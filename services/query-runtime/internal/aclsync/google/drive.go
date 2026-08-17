package google

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

// Connector implements aclsync.Connector against Google Workspace (Drive).
type Connector struct {
	client DriveClient
	cfg    Config
	logger *slog.Logger
	delta  DeltaTokenStore
}

// DriveClient is the minimal interface required by the Google Drive connector.
type DriveClient interface {
	ListFiles(ctx context.Context) ([]DriveFile, error)
	ListFilePermissions(ctx context.Context, fileID string) ([]DrivePermission, error)
}

// Config holds the connector configuration.
type Config struct {
	// TenantID is the Google Workspace domain or enterprise ID.
	TenantID string
	// DeltaPollSeconds controls how often the watcher polls for changes.
	DeltaPollSeconds int
}

// NewConnector builds a Google Drive connector from a DriveClient and config.
func NewConnector(client DriveClient, cfg Config, logger *slog.Logger, delta DeltaTokenStore) *Connector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Connector{client: client, cfg: cfg, logger: logger, delta: delta}
}

// userKey is the canonical Groundwork user identifier derived from Google identity.
func userKey(mail, altMail, id string) string {
	if v := strings.TrimSpace(mail); v != "" {
		return v
	}
	if v := strings.TrimSpace(altMail); v != "" {
		return v
	}
	return id
}

func userKeyOfUser(u DriveUser) string { return userKey(u.Email, u.AlternateEmail, u.ID) }

// granteesFromPerms maps read-granting Drive permissions to viewer users/groups.
func granteesFromPerms(perms []DrivePermission) (users, groups []string) {
	for _, p := range perms {
		if !grantsRead(p.Role) {
			continue
		}
		switch {
		case p.Grantee.GroupID != "":
			groups = append(groups, p.Grantee.GroupID)
		case p.Grantee.Email != "":
			key := userKey(p.Grantee.Email, "", "")
			if key == "" {
				key = userKey(p.Grantee.Email, "", "")
			}
			users = append(users, key)
		}
	}
	return users, groups
}

// grantsRead reports whether a Drive permission's role confers at least read access.
func grantsRead(role string) bool {
	switch strings.ToLower(role) {
	case "reader", "commenter", "writer", "fileOrganizer", "owner", "full":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------

// Snapshot reads the full Drive permission state and maps it to aclsync.PermissionSet.
func (c *Connector) Snapshot(ctx context.Context, tenantID string) (aclsync.PermissionSet, error) {
	files, err := c.client.ListFiles(ctx)
	if err != nil {
		return aclsync.PermissionSet{}, err
	}

	ps := aclsync.PermissionSet{TenantID: tenantID}

	for _, f := range files {
		perms, err := c.client.ListFilePermissions(ctx, f.ID)
		if err != nil {
			return aclsync.PermissionSet{}, err
		}
		users, groups := granteesFromPerms(perms)
		if strings.HasSuffix(f.MimeType, "/gfolder") {
			ps.Folders = append(ps.Folders, aclsync.Folder{
				ID:           f.ID,
				ViewerUsers:  users,
				ViewerGroups: groups,
			})
		} else {
			ps.Documents = append(ps.Documents, aclsync.Document{
				ID:           f.ID,
				FolderID:     f.Parents[0],
				ViewerUsers:  users,
				ViewerGroups: groups,
			})
		}
	}

	return ps, nil
}

// ListDocuments implements aclsync.Connector.
func (c *Connector) ListDocuments(ctx context.Context, _ string) ([]aclsync.Document, error) {
	files, err := c.client.ListFiles(ctx)
	if err != nil {
		return nil, err
	}
	var docs []aclsync.Document
	for _, f := range files {
		if strings.HasSuffix(f.MimeType, "/gfolder") {
			continue
		}
		perms, err := c.client.ListFilePermissions(ctx, f.ID)
		if err != nil {
			return nil, err
		}
		users, groups := granteesFromPerms(perms)
		docs = append(docs, aclsync.Document{
			ID:           f.ID,
			FolderID:     f.Parents[0],
			ViewerUsers:  users,
			ViewerGroups: groups,
		})
	}
	return docs, nil
}

// GetDocumentPermissions implements aclsync.Connector.
func (c *Connector) GetDocumentPermissions(ctx context.Context, _ string, documentID string) (aclsync.DocumentPermissions, error) {
	files, err := c.client.ListFiles(ctx)
	if err != nil {
		return aclsync.DocumentPermissions{}, err
	}
	for _, f := range files {
		if f.ID == documentID && !strings.HasSuffix(f.MimeType, "/gfolder") {
			perms, err := c.client.ListFilePermissions(ctx, f.ID)
			if err != nil {
				return aclsync.DocumentPermissions{}, err
			}
			users, groups := granteesFromPerms(perms)
			return aclsync.DocumentPermissions{
				DocumentID:   f.ID,
				FolderID:     f.Parents[0],
				ViewerUsers:  users,
				ViewerGroups: groups,
			}, nil
		}
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
// Types mirroring the Google Drive API schema (minimal).
// ---------------------------------------------------------------------------

type DriveFile struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	MimeType string   `json:"mimeType"`
	Parents  []string `json:"parents"`
	Trashed  bool     `json:"trashed"`
}

type DriveUser struct {
	Email          string `json:"email"`
	AlternateEmail string `json:"alternateEmail"`
	ID             string `json:"id"`
	IsAdmin        bool   `json:"isAdmin"`
}

type DrivePermission struct {
	Role         string `json:"role"`
	EmailAddress string `json:"emailAddress"`
	Sender       bool   `json:"sender"`
	Grantee      struct {
		Email   string `json:"email"`
		GroupID string `json:"groupId"`
	} `json:"grantee"`
}

// ---------------------------------------------------------------------------
// Interface‑cardinality guarantee.
// ---------------------------------------------------------------------------
var _ aclsync.Connector = (*Connector)(nil)
