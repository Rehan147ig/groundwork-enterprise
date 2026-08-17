package notion

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"groundwork/query-runtime/internal/aclsync"
)

// Connector implements aclsync.Connector against Notion.
type Connector struct {
	client NotionClient
	cfg    Config
	logger *slog.Logger
	delta  deltaTokenStore
}

// NotionClient is the minimal interface required by the Notion connector.
type NotionClient interface {
	ListPages(ctx context.Context, databaseID string) ([]NotionPage, error)
	ListPagePermissions(ctx context.Context, pageID string) ([]NotionPermission, error)
	ListBlocks(ctx context.Context, pageID string) ([]NotionBlock, error)
	ListBlockPermissions(ctx context.Context, blockID string) ([]NotionPermission, error)
}

// Config holds the connector configuration.
type Config struct {
	// DatabaseID is the Notion database ID to sync (pages in the database).
	DatabaseID string
	// DeltaPollSeconds controls how often the watcher polls for changes.
	DeltaPollSeconds int
}

type deltaTokenStore interface {
	Load(ctx context.Context, tenantID string) (string, error)
	Save(ctx context.Context, tenantID, token string) error
}

type memoryDeltaTokenStore struct{}

func (m *memoryDeltaTokenStore) Load(ctx context.Context, tenantID string) (string, error) {
	return "", nil
}
func (m *memoryDeltaTokenStore) Save(ctx context.Context, tenantID, token string) error { return nil }

// NewConnector builds a Notion connector from a NotionClient and config.
func NewConnector(client NotionClient, cfg Config, logger *slog.Logger, delta deltaTokenStore) *Connector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Connector{client: client, cfg: cfg, logger: logger, delta: delta}
}

// Snapshot reads the full Notion permission state and maps it to aclsync.PermissionSet.
func (c *Connector) Snapshot(ctx context.Context, tenantID string) (aclsync.PermissionSet, error) {
	pages, err := c.client.ListPages(ctx, c.cfg.DatabaseID)
	if err != nil {
		return aclsync.PermissionSet{}, err
	}

	ps := aclsync.PermissionSet{TenantID: tenantID}

	for _, page := range pages {
		perms, err := c.client.ListPagePermissions(ctx, page.ID)
		if err != nil {
			return aclsync.PermissionSet{}, err
		}
		users, groups := granteesFromPerms(perms)
		ps.Folders = append(ps.Folders, aclsync.Folder{
			ID:           page.ID,
			ViewerUsers:  users,
			ViewerGroups: groups,
		})

		// List blocks within this page.
		blocks, err := c.client.ListBlocks(ctx, page.ID)
		if err != nil {
			return aclsync.PermissionSet{}, err
		}
		for _, block := range blocks {
			blockPerms, err := c.client.ListBlockPermissions(ctx, block.ID)
			if err != nil {
				return aclsync.PermissionSet{}, err
			}
			bUsers, bGroups := granteesFromPerms(blockPerms)
			ps.Documents = append(ps.Documents, aclsync.Document{
				ID:           block.ID,
				FolderID:     page.ID,
				ViewerUsers:  bUsers,
				ViewerGroups: bGroups,
			})
		}
	}

	return ps, nil
}

// ListDocuments implements aclsync.Connector.
func (c *Connector) ListDocuments(ctx context.Context, tenantID string) ([]aclsync.Document, error) {
	pages, err := c.client.ListPages(ctx, c.cfg.DatabaseID)
	if err != nil {
		return nil, err
	}

	var docs []aclsync.Document
	for _, page := range pages {
		pagePerms, err := c.client.ListPagePermissions(ctx, page.ID)
		if err != nil {
			return nil, err
		}
		users, groups := granteesFromPerms(pagePerms)
		docs = append(docs, aclsync.Document{
			ID:           page.ID,
			FolderID:     "",
			ViewerUsers:  users,
			ViewerGroups: groups,
		})

		// List blocks within this page.
		blocks, err := c.client.ListBlocks(ctx, page.ID)
		if err != nil {
			return nil, err
		}
		for _, block := range blocks {
			blockPerms, err := c.client.ListBlockPermissions(ctx, block.ID)
			if err != nil {
				return nil, err
			}
			bUsers, bGroups := granteesFromPerms(blockPerms)
			docs = append(docs, aclsync.Document{
				ID:           block.ID,
				FolderID:     page.ID,
				ViewerUsers:  bUsers,
				ViewerGroups: bGroups,
			})
		}
	}
	return docs, nil
}

// GetDocumentPermissions implements aclsync.Connector.
func (c *Connector) GetDocumentPermissions(ctx context.Context, tenantID, documentID string) (aclsync.DocumentPermissions, error) {
	// Try as a page first.
	perms, err := c.client.ListPagePermissions(ctx, documentID)
	if err == nil {
		users, groups := granteesFromPerms(perms)
		return aclsync.DocumentPermissions{
			DocumentID:   documentID,
			FolderID:     "",
			ViewerUsers:  users,
			ViewerGroups: groups,
		}, nil
	}

	// Try as a block.
	blockPerms, err := c.client.ListBlockPermissions(ctx, documentID)
	if err == nil {
		users, groups := granteesFromPerms(blockPerms)
		return aclsync.DocumentPermissions{
			DocumentID:   documentID,
			FolderID:     "",
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
		ticker := time.NewTicker(time.Duration(c.cfg.DeltaPollSeconds) * time.Second)
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
// Types mirroring the minimal Notion API schema (block/page hierarchy).
// ---------------------------------------------------------------------------

type NotionPage struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Parent    string `json:"parent"`
	UpdatedAt string `json:"updated_at"`
}

type NotionBlock struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Title     string `json:"title"`
	PageID    string `json:"page_id"`
	UpdatedAt string `json:"updated_at"`
}

type NotionPermission struct {
	Actor struct {
		Type     string `json:"type"`
		Username string `json:"username"`
		ID       string `json:"id"`
	} `json:"actor"`
	Permission string `json:"permission"`
}

// granteesFromPerms maps read-granting Notion permissions to viewer users/groups.
func granteesFromPerms(perms []NotionPermission) (users, groups []string) {
	for _, p := range perms {
		if !grantsRead(p.Permission) {
			continue
		}
		switch {
		case p.Actor.Type == "user":
			key := userKey(p.Actor.Username, "", "")
			if key == "" {
				key = userKey(p.Actor.Username, "", "")
			}
			users = append(users, key)
		case p.Actor.Type == "group":
			groups = append(groups, strings.TrimSpace(p.Actor.Username))
		}
	}
	return users, groups
}

// userKey is the canonical Groundwork user identifier derived from Notion identity.
func userKey(mail, altMail, id string) string {
	if v := strings.TrimSpace(mail); v != "" {
		return v
	}
	if v := strings.TrimSpace(altMail); v != "" {
		return v
	}
	return id
}

// grantsRead reports whether a Notion permission conveys read access.
func grantsRead(permission string) bool {
	switch strings.ToLower(permission) {
	case "read", "comment":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Interface‑cardinality guarantee.
// ---------------------------------------------------------------------------
var _ aclsync.Connector = (*Connector)(nil)
