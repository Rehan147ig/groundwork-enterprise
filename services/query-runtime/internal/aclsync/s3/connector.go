package s3

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"groundwork/query-runtime/internal/aclsync"
)

// Connector implements aclsync.Connector against Amazon S3.
type Connector struct {
	client S3Client
	cfg    Config
	logger *slog.Logger
	delta  deltaTokenStore
}

// S3Client is the minimal interface required by the S3 connector.
type S3Client interface {
	ListBuckets(ctx context.Context) ([]S3Bucket, error)
	ListObjectKeys(ctx context.Context, bucket string) ([]S3ObjectKey, error)
	ListObjectPermissions(ctx context.Context, bucket, key string) ([]S3Permission, error)
}

// Config holds the connector configuration.
type Config struct {
	// Region is the AWS region where the bucket resides.
	Region string
	// BucketName is the S3 bucket to sync.
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

// NewConnector builds an S3 connector from an S3Client and config.
func NewConnector(client S3Client, cfg Config, logger *slog.Logger, delta deltaTokenStore) *Connector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Connector{client: client, cfg: cfg, logger: logger, delta: delta}
}

// Snapshot reads the full S3 permission state and maps it to aclsync.PermissionSet.
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
		keys, err := c.client.ListObjectKeys(ctx, b.Name)
		if err != nil {
			return aclsync.PermissionSet{}, err
		}
		for _, k := range keys {
			perms, err := c.client.ListObjectPermissions(ctx, b.Name, k.Key)
			if err != nil {
				return aclsync.PermissionSet{}, err
			}
			users, groups := granteesFromPerms(perms)
			ps.Documents = append(ps.Documents, aclsync.Document{
				ID:           k.Key,
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
		keys, err := c.client.ListObjectKeys(ctx, b.Name)
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			perms, err := c.client.ListObjectPermissions(ctx, b.Name, k.Key)
			if err != nil {
				return nil, err
			}
			users, groups := granteesFromPerms(perms)
			docs = append(docs, aclsync.Document{
				ID:           k.Key,
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
		perms, err := c.client.ListObjectPermissions(ctx, b.Name, documentID)
		if err != nil {
			return aclsync.DocumentPermissions{}, err
		}
		users, groups := granteesFromPerms(perms)
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
// Types mirroring the minimal S3 API schema.
// ---------------------------------------------------------------------------

type S3Bucket struct {
	Name string `json:"name"`
}

type S3ObjectKey struct {
	Key   string `json:"key"`
	ETag  string `json:"etag"`
	Owner string `json:"owner"`
	Size  int64  `json:"size"`
}

type S3Permission struct {
	Role    string `json:"role"`
	Grantee struct {
		Email   string `json:"email"`
		GroupID string `json:"groupId"`
	} `json:"grantee"`
}

// granteesFromPerms maps read-granting S3 permissions to viewer users/groups.
func granteesFromPerms(perms []S3Permission) (users, groups []string) {
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

// userKey is the canonical Groundwork user identifier derived from S3 identity.
func userKey(mail, altMail, id string) string {
	if v := strings.TrimSpace(mail); v != "" {
		return v
	}
	if v := strings.TrimSpace(altMail); v != "" {
		return v
	}
	return id
}

// grantsRead reports whether an S3 permission's role confers at least read access.
func grantsRead(role string) bool {
	switch strings.ToLower(role) {
	case "read", "read/write", "full":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Interface‑cardinality guarantee.
// ---------------------------------------------------------------------------
var _ aclsync.Connector = (*Connector)(nil)
