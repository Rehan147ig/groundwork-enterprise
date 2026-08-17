package snowflake

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"time"

	"groundwork/query-runtime/internal/aclsync"
)

// Connector implements aclsync.Connector against Snowflake.
type Connector struct {
	db     *sql.DB
	cfg    Config
	logger *slog.Logger
	delta  deltaTokenStore
}

// Config holds the connector configuration.
type Config struct {
	// ConnectionString is the Snowflake connection URL.
	ConnectionString string
	// Warehouse is the Snowflake warehouse to use.
	Warehouse string
	// Role is the Snowflake role to query grants for.
	Role string
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

// NewConnector builds a Snowflake connector from a sql.DB and config.
func NewConnector(db *sql.DB, cfg Config, logger *slog.Logger, delta deltaTokenStore) *Connector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Connector{db: db, cfg: cfg, logger: logger, delta: delta}
}

// Snapshot reads the full Snowflake permission state and maps it to aclsync.PermissionSet.
func (c *Connector) Snapshot(ctx context.Context, tenantID string) (aclsync.PermissionSet, error) {
	// Query all grants for the specified role.
	// Snowflake grants come in two forms:
	//   - GRANT <privilege> ON <object> TO <role>
	//   - GRANT <role> TO <role> (role hierarchy)
	qs := `SELECT grantee, privilege, object_type, object_name
	       FROM information_schema.role_grants
	       WHERE grantee = $1`
	rows, err := c.db.QueryContext(ctx, qs, c.cfg.Role)
	if err != nil {
		return aclsync.PermissionSet{}, err
	}
	defer rows.Close()

	ps := aclsync.PermissionSet{TenantID: tenantID}

	for rows.Next() {
		var grantee string
		var privilege string
		var objectType string
		var objectName sql.NullString
		if err := rows.Scan(&grantee, &privilege, &objectType, &objectName); err != nil {
			return aclsync.PermissionSet{}, err
		}

		// Map Snowflake privileges to Groundwork viewer grants.
		if !grantsRead(privilege) {
			continue
		}

		// Grant a viewer relationship: user:grantee -> group:objectName
		// or group:grantee -> group:objectName depending on grantee type.
		var viewers []string
		if strings.HasPrefix(grantee, "U") {
			// User grantee
			key := userKey(strings.TrimPrefix(grantee, "U"), "", "")
			if key != "" {
				viewers = append(viewers, key)
			}
		} else {
			// Role/group grantee
			viewers = append(viewers, strings.TrimSpace(grantee))
		}

		if objectName.Valid && objectName.String != "" {
			ps.Documents = append(ps.Documents, aclsync.Document{
				ID:           objectName.String,
				FolderID:     "",
				ViewerUsers:  viewers,
				ViewerGroups: []string{},
			})
		}
	}

	return ps, nil
}

// ListDocuments implements aclsync.Connector.
func (c *Connector) ListDocuments(ctx context.Context, tenantID string) ([]aclsync.Document, error) {
	qs := `SELECT object_name FROM information_schema.role_grants WHERE grantee = $1`
	rows, err := c.db.QueryContext(ctx, qs, c.cfg.Role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var docs []aclsync.Document
	for rows.Next() {
		var objectName string
		if err := rows.Scan(&objectName); err != nil {
			return nil, err
		}
		docs = append(docs, aclsync.Document{
			ID:           objectName,
			FolderID:     "",
			ViewerUsers:  []string{},
			ViewerGroups: []string{},
		})
	}
	return docs, nil
}

// GetDocumentPermissions implements aclsync.Connector.
func (c *Connector) GetDocumentPermissions(ctx context.Context, tenantID, documentID string) (aclsync.DocumentPermissions, error) {
	// Grant viewer access to the specific object.
	qs := `SELECT grantee FROM information_schema.role_grants WHERE object_name = $1`
	rows, err := c.db.QueryContext(ctx, qs, documentID)
	if err != nil {
		return aclsync.DocumentPermissions{}, err
	}
	defer rows.Close()

	var viewers []string
	for rows.Next() {
		var grantee string
		if err := rows.Scan(&grantee); err != nil {
			return aclsync.DocumentPermissions{}, err
		}
		if !grantsRead("SELECT") {
			continue
		}
		if strings.HasPrefix(grantee, "U") {
			key := userKey(strings.TrimPrefix(grantee, "U"), "", "")
			if key != "" {
				viewers = append(viewers, key)
			}
		} else {
			viewers = append(viewers, strings.TrimSpace(grantee))
		}
	}

	return aclsync.DocumentPermissions{
		DocumentID:   documentID,
		FolderID:     "",
		ViewerUsers:  viewers,
		ViewerGroups: []string{},
	}, nil
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
// Types mirroring the Snowflake information_schema schema.
// ---------------------------------------------------------------------------

type snowflakeGrant struct {
	Grantee    string
	Privilege  string
	ObjectType string
	ObjectName string
}

// userKey is the canonical Groundwork user identifier derived from Snowflake identity.
func userKey(mail, altMail, id string) string {
	if v := strings.TrimSpace(mail); v != "" {
		return v
	}
	if v := strings.TrimSpace(altMail); v != "" {
		return v
	}
	return id
}

// grantsRead reports whether a Snowflake privilege confers at least read access.
func grantsRead(privilege string) bool {
	switch strings.ToUpper(strings.TrimSpace(privilege)) {
	case "SELECT", "USAGE", "MONITOR", "EXECUTE":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Interface‑cardinality guarantee.
// ---------------------------------------------------------------------------
var _ aclsync.Connector = (*Connector)(nil)
