package gcs

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"groundwork/query-runtime/internal/aclsync"
)

// Connector implements aclsync.Connector against Google Cloud Storage (GCS).
type Connector struct {
	client GCClient
	cfg    Config
	logger *slog.Logger
	delta  deltaTokenStore
}

// GCClient is the minimal interface required by the GCS connector.
type GCClient interface {
	ListBuckets(ctx context.Context) ([]GCBucket, error)
	ListObjectNames(ctx context.Context, bucket string) ([]GCObjectName, error)
	ListObjectAcls(ctx context.Context, bucket, object string) ([]GCPermission, error)
}

// Config holds the connector configuration.
type Config struct {
	// ProjectID is the GCP project ID where the bucket resides.
	ProjectID string
	// BucketName is the GCS bucket to sync.
	BucketName string
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

// NewConnector builds a GCS connector from a GCClient and config.
func NewConnector(client GCClient, cfg Config, logger *slog.Logger, delta deltaTokenStore) *Connector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Connector{client: client, cfg: cfg, logger: logger, delta: delta}
}

// Snapshot reads the full GCS permission state and maps it to aclsync.PermissionSet.
func (c *Connector) Snapshot(ctx context.Context, tenantID string) (aclsync.PermissionSet, error) {
	buckets, err := c.client.ListBuckets(ctx)
	if err != nil {
		return aclsync.PermissionSet{}, err
	}

	ps := aclsync.PermissionSet{TenantID: tenantID}

	for _, b := range buckets {
		if b.Name != c.cfg.BucketName {
			continue
		}
		names, err := c.client.ListObjectNames(ctx, b.Name)
		if err != nil {
			return aclsync.PermissionSet{}, err
		}
		for _, n := range names {
			acls, err := c.client.ListObjectAcls(ctx, b.Name, n.Name)
			if err != nil {
				return aclsync.PermissionSet{}, err
			}
			users, groups := granteesFromPerms(acls)
			ps.Documents = append(ps.Documents, aclsync.Document{
				ID:           n.Name,
				FolderID:     b.Name,
				ViewerUsers:  users,
				ViewerGroups: groups,
			})
		}
	}

	return ps, nil
}

// ListDocuments implements aclsync.Connector.
func (c *Connector) ListDocuments(ctx context.Context, tenantID string) ([]aclsync.Document, error) {
	buckets, err := c.client.ListBuckets(ctx)
	if err != nil {
		return nil, err
	}

	var docs []aclsync.Document
	for _, b := range buckets {
		if b.Name != c.cfg.BucketName {
			continue
		}
		names, err := c.client.ListObjectNames(ctx, b.Name)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			acls, err := c.client.ListObjectAcls(ctx, b.Name, n.Name)
			if err != nil {
				return nil, err
			}
			users, groups := granteesFromPerms(acls)
			docs = append(docs, aclsync.Document{
				ID:           n.Name,
				FolderID:     b.Name,
				ViewerUsers:  users,
				ViewerGroups: groups,
			})
		}
	}
	return docs, nil
}

// GetDocumentPermissions implements aclsync.Connector.
func (c *Connector) GetDocumentPermissions(ctx context.Context, tenantID, documentID string) (aclsync.DocumentPermissions, error) {
	buckets, err := c.client.ListBuckets(ctx)
	if err != nil {
		return aclsync.DocumentPermissions{}, err
	}
	for _, b := range buckets {
		if b.Name != c.cfg.BucketName {
			continue
		}
		acls, err := c.client.ListObjectAcls(ctx, b.Name, documentID)
		if err != nil {
			return aclsync.DocumentPermissions{}, err
		}
		users, groups := granteesFromPerms(acls)
		return aclsync.DocumentPermissions{
			DocumentID:   documentID,
			FolderID:     b.Name,
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
// Types mirroring the minimal GCS API schema (JSON/REST-like).
// ---------------------------------------------------------------------------

type GCBucket struct {
	Name string `json:"name"`
}

type GCObjectName struct {
	Name string `json:"name"`
}

type GCPermission struct {
	Role   string `json:"role"`
	Entity string `json:"entity"`
	Owner  bool   `json:"owner"`
	Domain string `json:"domain"`
	Group  bool   `json:"group"`
}

// granteesFromPerms maps read-granting GCS permissions to viewer users/groups.
func granteesFromPerms(perms []GCPermission) (users, groups []string) {
	for _, p := range perms {
		if !grantsRead(p.Role) {
			continue
		}
		switch {
		case p.Entity[:1] == "u": // user-XXX@domain format
			key := userKey(strings.TrimPrefix(p.Entity, "user-"), "", "")
			if key == "" {
				key = userKey(p.Entity, "", "")
			}
			users = append(users, key)
		case p.Entity[:1] == "g": // group-XXX@domain format
			groups = append(groups, strings.TrimPrefix(p.Entity, "group-"))
		}
	}
	return users, groups
}

// userKey is the canonical Groundwork user identifier derived from GCS identity.
func userKey(mail, altMail, id string) string {
	if v := strings.TrimSpace(mail); v != "" {
		return v
	}
	if v := strings.TrimSpace(altMail); v != "" {
		return v
	}
	return id
}

// grantsRead reports whether a GCS permission's role confers at least read access.
func grantsRead(role string) bool {
	switch strings.ToLower(role) {
	case "readers", "readers/payload", "OWNER":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Interface‑cardinality guarantee.
// ---------------------------------------------------------------------------
var _ aclsync.Connector = (*Connector)(nil)
