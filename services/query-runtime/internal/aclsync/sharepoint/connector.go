package sharepoint

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"groundwork/query-runtime/internal/aclsync"
)

// Connector implements aclsync.Connector against Microsoft SharePoint/OneDrive.
type Connector struct {
	client SharePointClient
	cfg    Config
	logger *slog.Logger
	delta  deltaTokenStore
}

// SharePointClient is the minimal interface required by the SharePoint connector.
type SharePointClient interface {
	ListSites(ctx context.Context) ([]SharePointSite, error)
	ListLibraryFolders(ctx context.Context, siteID, library string) ([]SharePointFolder, error)
	ListFolderItems(ctx context.Context, siteID, library, folderPath string) ([]SharePointItem, error)
	ListItemPermissions(ctx context.Context, siteID, library, itemID string) ([]SharePointPermission, error)
}

// Config holds the connector configuration.
type Config struct {
	// SiteURL is the SharePoint site URL (e.g., https://contoso.sharepoint.com/sites/dev).
	SiteURL string
	// LibraryName is the document library name (e.g., "Documents").
	LibraryName string
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

// NewConnector builds a SharePoint connector from a SharePointClient and config.
func NewConnector(client SharePointClient, cfg Config, logger *slog.Logger, delta deltaTokenStore) *Connector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Connector{client: client, cfg: cfg, logger: logger, delta: delta}
}

// Snapshot reads the full SharePoint permission state and maps it to aclsync.PermissionSet.
func (c *Connector) Snapshot(ctx context.Context, tenantID string) (aclsync.PermissionSet, error) {
	sites, err := c.client.ListSites(ctx)
	if err != nil {
		return aclsync.PermissionSet{}, err
	}

	ps := aclsync.PermissionSet{TenantID: tenantID}

	for _, site := range sites {
		if site.ID != c.cfg.SiteURL {
			continue
		}
		folders, err := c.client.ListLibraryFolders(ctx, site.ID, c.cfg.LibraryName)
		if err != nil {
			return aclsync.PermissionSet{}, err
		}
		for _, folder := range folders {
			perms, err := c.client.ListItemPermissions(ctx, site.ID, c.cfg.LibraryName, folder.ID)
			if err != nil {
				return aclsync.PermissionSet{}, err
			}
			users, groups := granteesFromPerms(perms)
			ps.Folders = append(ps.Folders, aclsync.Folder{
				ID:           folder.ID,
				ViewerUsers:  users,
				ViewerGroups: groups,
			})
		}

		// Also list root-level items (files at the library level).
		items, err := c.client.ListFolderItems(ctx, site.ID, c.cfg.LibraryName, "")
		if err != nil {
			return aclsync.PermissionSet{}, err
		}
		for _, item := range items {
			if item.IsFolder {
				perms, err := c.client.ListItemPermissions(ctx, site.ID, c.cfg.LibraryName, item.ID)
				if err != nil {
					return aclsync.PermissionSet{}, err
				}
				users, groups := granteesFromPerms(perms)
				ps.Folders = append(ps.Folders, aclsync.Folder{
					ID:           item.ID,
					ViewerUsers:  users,
					ViewerGroups: groups,
				})
			} else {
				perms, err := c.client.ListItemPermissions(ctx, site.ID, c.cfg.LibraryName, item.ID)
				if err != nil {
					return aclsync.PermissionSet{}, err
				}
				users, groups := granteesFromPerms(perms)
				ps.Documents = append(ps.Documents, aclsync.Document{
					ID:           item.ID,
					FolderID:     c.cfg.LibraryName,
					ViewerUsers:  users,
					ViewerGroups: groups,
				})
			}
		}
	}

	return ps, nil
}

// ListDocuments implements aclsync.Connector.
func (c *Connector) ListDocuments(ctx context.Context, tenantID string) ([]aclsync.Document, error) {
	sites, err := c.client.ListSites(ctx)
	if err != nil {
		return nil, err
	}

	var docs []aclsync.Document
	for _, site := range sites {
		if site.ID != c.cfg.SiteURL {
			continue
		}
		folders, err := c.client.ListLibraryFolders(ctx, site.ID, c.cfg.LibraryName)
		if err != nil {
			return nil, err
		}
		for _, folder := range folders {
			perms, err := c.client.ListItemPermissions(ctx, site.ID, c.cfg.LibraryName, folder.ID)
			if err != nil {
				return nil, err
			}
			users, groups := granteesFromPerms(perms)
			docs = append(docs, aclsync.Document{
				ID:           folder.ID,
				FolderID:     c.cfg.LibraryName,
				ViewerUsers:  users,
				ViewerGroups: groups,
			})
		}

		// List root-level items.
		items, err := c.client.ListFolderItems(ctx, site.ID, c.cfg.LibraryName, "")
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if !item.IsFolder {
				perms, err := c.client.ListItemPermissions(ctx, site.ID, c.cfg.LibraryName, item.ID)
				if err != nil {
					return nil, err
				}
				users, groups := granteesFromPerms(perms)
				docs = append(docs, aclsync.Document{
					ID:           item.ID,
					FolderID:     c.cfg.LibraryName,
					ViewerUsers:  users,
					ViewerGroups: groups,
				})
			}
		}
	}
	return docs, nil
}

// GetDocumentPermissions implements aclsync.Connector.
func (c *Connector) GetDocumentPermissions(ctx context.Context, tenantID, documentID string) (aclsync.DocumentPermissions, error) {
	sites, err := c.client.ListSites(ctx)
	if err != nil {
		return aclsync.DocumentPermissions{}, err
	}
	for _, site := range sites {
		if site.ID != c.cfg.SiteURL {
			continue
		}
		perms, err := c.client.ListItemPermissions(ctx, site.ID, c.cfg.LibraryName, documentID)
		if err != nil {
			return aclsync.DocumentPermissions{}, err
		}
		users, groups := granteesFromPerms(perms)
		return aclsync.DocumentPermissions{
			DocumentID:   documentID,
			FolderID:     c.cfg.LibraryName,
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
// Types mirroring the minimal SharePoint/OneDrive API schema.
// ---------------------------------------------------------------------------

type SharePointSite struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type SharePointFolder struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	IsFolder bool   `json:"isFolder"`
}

type SharePointItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	IsFolder bool   `json:"isFolder"`
	Folder   string `json:"folder"`
	File     string `json:"file"`
}

type SharePointPermission struct {
	Role      string `json:"role"`
	Email     string `json:"email"`
	GroupID   string `json:"groupId"`
	LoginName string `json:"loginName"`
}

// granteesFromPerms maps read-granting SharePoint permissions to viewer users/groups.
func granteesFromPerms(perms []SharePointPermission) (users, groups []string) {
	for _, p := range perms {
		if !grantsRead(p.Role) {
			continue
		}
		switch {
		case p.GroupID != "":
			groups = append(groups, strings.TrimSpace(p.GroupID))
		case p.Email != "":
			key := userKey(p.Email, "", "")
			if key == "" {
				key = userKey(p.Email, "", "")
			}
			users = append(users, key)
		}
	}
	return users, groups
}

// userKey is the canonical Groundwork user identifier derived from SharePoint identity.
func userKey(mail, altMail, id string) string {
	if v := strings.TrimSpace(mail); v != "" {
		return v
	}
	if v := strings.TrimSpace(altMail); v != "" {
		return v
	}
	return id
}

// grantsRead reports whether a SharePoint permission conveys read access.
func grantsRead(role string) bool {
	switch strings.ToLower(role) {
	case "read", "contribute", "edit", "full":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Interface‑cardinality guarantee.
// ---------------------------------------------------------------------------
var _ aclsync.Connector = (*Connector)(nil)
