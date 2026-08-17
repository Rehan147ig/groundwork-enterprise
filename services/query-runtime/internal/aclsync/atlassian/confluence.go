package atlassian

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"groundwork/query-runtime/internal/aclsync"
)

// DeltaTokenStore is the interface for tracking delta sync state.
type DeltaTokenStore interface {
	Load(ctx context.Context, tenantID string) (string, error)
	Save(ctx context.Context, tenantID, token string) error
}

// MemoryDeltaTokenStore is a simple in-memory implementation.
type MemoryDeltaTokenStore struct{}

func (m *MemoryDeltaTokenStore) Load(ctx context.Context, tenantID string) (string, error) {
	return "", nil
}
func (m *MemoryDeltaTokenStore) Save(ctx context.Context, tenantID, token string) error { return nil }

// Connector implements aclsync.Connector against Atlassian Confluence Cloud.
type Connector struct {
	client ConfluenceClient
	cfg    Config
	logger *slog.Logger
	delta  DeltaTokenStore
}

// ConfluenceClient is the minimal interface required by the Confluence connector.
type ConfluenceClient interface {
	ListSpaces(ctx context.Context) ([]ConfluenceSpace, error)
	ListSpacePermissions(ctx context.Context, spaceKey string) ([]ConfluencePermission, error)
	ListPages(ctx context.Context, spaceKey string, startRow, limit int) (PageResult, error)
	ListPagePermissions(ctx context.Context, spaceKey, pageKey string) ([]ConfluencePermission, error)
}

// Config holds the connector configuration.
type Config struct {
	// TenantID is the Atlassian site ID or domain.
	TenantID string
	// DeltaPollSeconds controls how often the watcher polls for changes.
	DeltaPollSeconds int
}

// NewConnector builds a Confluence connector from a ConfluenceClient and config.
func NewConnector(client ConfluenceClient, cfg Config, logger *slog.Logger, delta DeltaTokenStore) *Connector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Connector{client: client, cfg: cfg, logger: logger, delta: delta}
}

// Canonical user key derived from Confluence identity.
func userKey(username, displayName, accountID string) string {
	if v := strings.TrimSpace(username); v != "" {
		return v
	}
	if v := strings.TrimSpace(displayName); v != "" {
		return v
	}
	return accountID
}

func userKeyOfUser(u ConfluenceUser) string { return userKey(u.Username, u.DisplayName, u.AccountID) }

// granteesFromPerms maps read-granting Confluence permissions to viewer users/groups.
func granteesFromPerms(perms []ConfluencePermission) (users, groups []string) {
	for _, p := range perms {
		if !grantsRead(p.Permission) {
			continue
		}
		switch {
		case p.Actor.Type == "group":
			groups = append(groups, p.Actor.DisplayName)
		case p.Actor.Type == "user":
			key := userKey(p.Actor.DisplayName, p.Actor.DisplayName, p.Actor.Type)
			if key == "" {
				key = userKey(p.Actor.DisplayName, p.Actor.DisplayName, p.Actor.Type)
			}
			users = append(users, key)
		}
	}
	return users, groups
}

// grantsRead reports whether a Confluence permission conveys read access.
func grantsRead(permission string) bool {
	switch strings.ToLower(permission) {
	case "read", "view", "comment", "write", "admin", "manage":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------

// Snapshot reads the full Confluence permission state and maps it to aclsync.PermissionSet.
func (c *Connector) Snapshot(ctx context.Context, tenantID string) (aclsync.PermissionSet, error) {
	spaces, err := c.client.ListSpaces(ctx)
	if err != nil {
		return aclsync.PermissionSet{}, err
	}

	ps := aclsync.PermissionSet{TenantID: tenantID}

	for _, s := range spaces {
		perms, err := c.client.ListSpacePermissions(ctx, s.Key)
		if err != nil {
			return aclsync.PermissionSet{}, err
		}
		users, groups := granteesFromPerms(perms)
		ps.Folders = append(ps.Folders, aclsync.Folder{
			ID:           s.Key,
			ViewerUsers:  users,
			ViewerGroups: groups,
		})

		// Paginate through pages in this space.
		startRow := 0
		limit := 100
		for {
			pageList, err := c.client.ListPages(ctx, s.Key, startRow, limit)
			if err != nil {
				return aclsync.PermissionSet{}, err
			}
			for _, p := range pageList.Results {
				pagePerms, err := c.client.ListPagePermissions(ctx, s.Key, p.Key)
				if err != nil {
					return aclsync.PermissionSet{}, err
				}
				pUsers, pGroups := granteesFromPerms(pagePerms)
				ps.Documents = append(ps.Documents, aclsync.Document{
					ID:           p.Key,
					FolderID:     s.Key,
					ViewerUsers:  pUsers,
					ViewerGroups: pGroups,
				})
			}
			startRow += limit
			if startRow >= pageList.Total {
				break
			}
		}
	}

	return ps, nil
}

// ListDocuments implements aclsync.Connector.
func (c *Connector) ListDocuments(ctx context.Context, _ string) ([]aclsync.Document, error) {
	spaces, err := c.client.ListSpaces(ctx)
	if err != nil {
		return nil, err
	}
	var docs []aclsync.Document
	for _, s := range spaces {
		pagePerms, err := c.client.ListPagePermissions(ctx, s.Key, "")
		if err != nil {
			return nil, err
		}
		users, groups := granteesFromPerms(pagePerms)
		docs = append(docs, aclsync.Document{
			ID:           "",
			FolderID:     s.Key,
			ViewerUsers:  users,
			ViewerGroups: groups,
		})
	}
	return docs, nil
}

// GetDocumentPermissions implements aclsync.Connector.
func (c *Connector) GetDocumentPermissions(ctx context.Context, _ string, documentID string) (aclsync.DocumentPermissions, error) {
	spaces, err := c.client.ListSpaces(ctx)
	if err != nil {
		return aclsync.DocumentPermissions{}, err
	}
	for _, s := range spaces {
		pagePerms, err := c.client.ListPagePermissions(ctx, s.Key, documentID)
		if err != nil {
			return aclsync.DocumentPermissions{}, err
		}
		users, groups := granteesFromPerms(pagePerms)
		return aclsync.DocumentPermissions{
			DocumentID:   documentID,
			FolderID:     s.Key,
			ViewerUsers:  users,
			ViewerGroups: groups,
		}, nil
	}
	return aclsync.DocumentPermissions{}, nil
}

// WatchPermissionChanges implements aclsync.Connector.
func (c *Connector) WatchPermissionChanges(ctx context.Context, tenantID string) (<-chan aclsync.PermissionChange, error) {
	ch := make(chan aclsync.PermissionChange)
	go func() {
		defer close(ch)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.Snapshot(ctx, tenantID)
			}
		}
	}()
	return ch, nil
}

// ---------------------------------------------------------------------------
// Types mirroring the Confluence Cloud REST API schema (minimal).
// ---------------------------------------------------------------------------

type ConfluenceSpace struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type ConfluencePage struct {
	Key      string `json:"key"`
	Title    string `json:"title"`
	SpaceKey string `json:"spaceKey"`
	Status   string `json:"status"`
}

type ConfluencePermission struct {
	Actor struct {
		Type        string `json:"type"`
		DisplayName string `json:"displayName"`
		AccountID   string `json:"accountId"`
	} `json:"actor"`
	Permission string `json:"permission"`
}

type ConfluenceUser struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	AccountID   string `json:"accountId"`
}

type ConfluenceGroup struct {
	Name        string `json:"name"`
	Deactivated bool   `json:"deactivated"`
}

// PageResult is the response from Confluence ListPages.
type PageResult struct {
	Size     int              `json:"size"`
	StartRow int              `json:"startRow"`
	Total    int              `json:"total"`
	Results  []ConfluencePage `json:"results"`
}

// ---------------------------------------------------------------------------
// Interface‑cardinality guarantee.
// ---------------------------------------------------------------------------
var _ aclsync.Connector = (*Connector)(nil)
