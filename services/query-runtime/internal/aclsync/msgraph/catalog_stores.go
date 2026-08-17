package msgraph

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// PostgresDeltaTokenStore persists the Graph delta token in
// connector_installations.delta_cursor (migration 032) so the connector
// resumes exactly where it left off across restarts — even when the
// token changes mid-cursor. Keying by tenant_id + provider='msgraph'
// keeps one durable cursor per installation.
type PostgresDeltaTokenStore struct {
	db *sql.DB
}

// NewPostgresDeltaTokenStore wraps an *sql.DB with migration 032 applied.
func NewPostgresDeltaTokenStore(db *sql.DB) *PostgresDeltaTokenStore {
	return &PostgresDeltaTokenStore{db: db}
}

// Load implements DeltaTokenStore. Missing installation -> empty token
// (fresh start), never an error.
func (s *PostgresDeltaTokenStore) Load(ctx context.Context, key string) (string, error) {
	var cursor sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT delta_cursor FROM connector_installations WHERE tenant_id = $1 AND provider = 'msgraph'`,
		key,
	).Scan(&cursor)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return cursor.String, nil
}

// Save implements DeltaTokenStore. The installation row is created if it
// does not exist yet (pending status).
func (s *PostgresDeltaTokenStore) Save(ctx context.Context, key, token string) error {
	const q = `
INSERT INTO connector_installations (tenant_id, provider, status, delta_cursor)
VALUES ($1, 'msgraph', 'pending', $2)
ON CONFLICT (tenant_id, provider) DO UPDATE SET
    delta_cursor = EXCLUDED.delta_cursor,
    updated_at   = NOW()`
	_, err := s.db.ExecContext(ctx, q, key, token)
	return err
}

// --- permission snapshots (delta diffing) ---

// SnapshotGrantee is one recorded read grant in a permission snapshot.
// A zero-value Type means the grant was to a group.
type SnapshotGrantee struct {
	Type string `json:"type,omitempty"` // "user" | "" (group)
	ID   string `json:"id"`
}

// ItemSnapshot is the last-known permission state of one drive item.
type ItemSnapshot struct {
	TenantID string
	ItemID   string
	IsFolder bool
	ParentID string
	Grantees []SnapshotGrantee
	Updated  time.Time
}

// PermissionSnapshotStore persists last-known item permission state so
// delta polls can diff current Graph permissions against the previous
// state and emit concrete revoke events. Production uses
// PostgresPermissionSnapshotStore (msgraph.permission_snapshots).
type PermissionSnapshotStore interface {
	Load(ctx context.Context, tenantID, itemID string) (ItemSnapshot, error)
	Save(ctx context.Context, snap ItemSnapshot) error
	Delete(ctx context.Context, tenantID, itemID string) error
}

// PostgresPermissionSnapshotStore stores snapshots in
// msgraph.permission_snapshots (migration 032).
type PostgresPermissionSnapshotStore struct {
	db *sql.DB
}

// NewPostgresPermissionSnapshotStore wraps an *sql.DB with migration 032
// applied.
func NewPostgresPermissionSnapshotStore(db *sql.DB) *PostgresPermissionSnapshotStore {
	return &PostgresPermissionSnapshotStore{db: db}
}

// Load implements PermissionSnapshotStore. Missing snapshot -> empty
// grantees (no prior state), never an error.
func (s *PostgresPermissionSnapshotStore) Load(ctx context.Context, tenantID, itemID string) (ItemSnapshot, error) {
	var snap ItemSnapshot
	var grantees []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT tenant_id, item_id, is_folder, parent_id, grantees, updated_at
		   FROM msgraph.permission_snapshots
		  WHERE tenant_id = $1 AND item_id = $2`,
		tenantID, itemID,
	).Scan(&snap.TenantID, &snap.ItemID, &snap.IsFolder, &snap.ParentID, &grantees, &snap.Updated)
	if err != nil {
		if err == sql.ErrNoRows {
			return ItemSnapshot{TenantID: tenantID, ItemID: itemID}, nil
		}
		return ItemSnapshot{}, err
	}
	if len(grantees) > 0 {
		if err := json.Unmarshal(grantees, &snap.Grantees); err != nil {
			return ItemSnapshot{}, err
		}
	}
	return snap, nil
}

// Save implements PermissionSnapshotStore.
func (s *PostgresPermissionSnapshotStore) Save(ctx context.Context, snap ItemSnapshot) error {
	raw, err := json.Marshal(snap.Grantees)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO msgraph.permission_snapshots (tenant_id, item_id, is_folder, parent_id, grantees, updated_at)
VALUES ($1, $2, $3, $4, $5, NOW())
ON CONFLICT (tenant_id, item_id) DO UPDATE SET
    is_folder  = EXCLUDED.is_folder,
    parent_id  = EXCLUDED.parent_id,
    grantees   = EXCLUDED.grantees,
    updated_at = NOW()`
	_, err = s.db.ExecContext(ctx, q, snap.TenantID, snap.ItemID, snap.IsFolder, snap.ParentID, raw)
	return err
}

// Delete implements PermissionSnapshotStore.
func (s *PostgresPermissionSnapshotStore) Delete(ctx context.Context, tenantID, itemID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM msgraph.permission_snapshots WHERE tenant_id = $1 AND item_id = $2`,
		tenantID, itemID,
	)
	return err
}

// MemoryPermissionSnapshotStore is the dev/test snapshot store.
type MemoryPermissionSnapshotStore struct {
	m map[string]ItemSnapshot
}

// NewMemoryPermissionSnapshotStore builds an empty memory store.
func NewMemoryPermissionSnapshotStore() *MemoryPermissionSnapshotStore {
	return &MemoryPermissionSnapshotStore{m: map[string]ItemSnapshot{}}
}

// Load implements PermissionSnapshotStore.
func (s *MemoryPermissionSnapshotStore) Load(_ context.Context, tenantID, itemID string) (ItemSnapshot, error) {
	snap, ok := s.m[tenantID+"/"+itemID]
	if !ok {
		return ItemSnapshot{TenantID: tenantID, ItemID: itemID}, nil
	}
	return snap, nil
}

// Save implements PermissionSnapshotStore.
func (s *MemoryPermissionSnapshotStore) Save(_ context.Context, snap ItemSnapshot) error {
	snap.Updated = time.Now().UTC()
	s.m[snap.TenantID+"/"+snap.ItemID] = snap
	return nil
}

// Delete implements PermissionSnapshotStore.
func (s *MemoryPermissionSnapshotStore) Delete(_ context.Context, tenantID, itemID string) error {
	delete(s.m, tenantID+"/"+itemID)
	return nil
}

var _ DeltaTokenStore = (*PostgresDeltaTokenStore)(nil)
var _ PermissionSnapshotStore = (*PostgresPermissionSnapshotStore)(nil)
var _ PermissionSnapshotStore = (*MemoryPermissionSnapshotStore)(nil)
