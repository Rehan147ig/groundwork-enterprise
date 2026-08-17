package aclsync

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Sentinel errors for the installation store.
var (
	// ErrInstallationNotFound means no installation record exists for
	// the (tenant, provider) pair.
	ErrInstallationNotFound = errors.New("acl_sync: connector installation not found")
	// ErrInvalidInstallationStatus means a status outside the closed set
	// was supplied to UpdateHealth.
	ErrInvalidInstallationStatus = errors.New("acl_sync: invalid connector installation status")
)

// InstallationStatus enumerates connector installation lifecycle states
// (must match the CHECK constraint in migration 032).
type InstallationStatus string

const (
	InstallationPending  InstallationStatus = "pending"
	InstallationActive   InstallationStatus = "active"
	InstallationDegraded InstallationStatus = "degraded"
	InstallationFailed   InstallationStatus = "failed"
	InstallationDisabled InstallationStatus = "disabled"
)

// IsValidInstallationStatus reports whether s is a legal state.
func IsValidInstallationStatus(s InstallationStatus) bool {
	switch s {
	case InstallationPending, InstallationActive, InstallationDegraded, InstallationFailed, InstallationDisabled:
		return true
	}
	return false
}

// Installation is the tenant-bound connector installation record
// (migration 032). Credential material is NEVER stored here — only the
// reference (keyring:// or an approved secret-manager ref) and an
// encrypted metadata blob sealed with the connector purpose key.
type Installation struct {
	TenantID       string
	Provider       string
	Status         InstallationStatus
	CredentialRef  string    // keyring://… or secret-manager ref; never the secret itself
	CredentialTTL  time.Time // credential expiry; zero = no expiry configured
	DeltaCursor    string    // durable provider delta cursor/checkpoint
	LastSuccessAt  time.Time // last fully successful sync
	LastAttemptAt  time.Time // last sync attempt (success or failure)
	SyncLagSeconds int64     // observed source-change lag at last sync
	DriftItems     int       // permission-drift items at last drift check
	LastError      string    // most recent failure message (no secrets allowed)
	Region         string    // tenant region at installation time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// HealthUpdate carries the mutable health surface of an installation.
type HealthUpdate struct {
	Status         InstallationStatus
	CredentialRef  string
	CredentialTTL  time.Time
	DeltaCursor    string
	LastSuccessAt  time.Time
	LastAttemptAt  time.Time
	SyncLagSeconds int64
	DriftItems     int
	LastError      string
}

// InstallationStore persists connector installation records. Production
// uses PostgresInstallationStore (migration 032); tests use the memory
// store. Callers must treat any non-nil error as fail-closed.
type InstallationStore interface {
	Get(ctx context.Context, tenantID, provider string) (Installation, error)
	Upsert(ctx context.Context, inst Installation) error
	UpdateHealth(ctx context.Context, tenantID, provider string, h HealthUpdate) error
	List(ctx context.Context, provider string) ([]Installation, error)
}

// IsKeyringRef reports whether ref is a keyring:// or approved
// secret-manager reference (production requirement; plaintext env values
// are a deployment violation).
func IsKeyringRef(ref string) bool {
	r := strings.TrimSpace(ref)
	return strings.HasPrefix(r, "keyring://") ||
		strings.HasPrefix(r, "secretsmanager://") ||
		strings.HasPrefix(r, "aws:secretsmanager:") ||
		strings.HasPrefix(r, "gcp:secretmanager:") ||
		strings.HasPrefix(r, "vault://")
}

// MemoryInstallationStore is the in-memory/dev installation store. Not
// durable; used by tests and single-process demos.
type MemoryInstallationStore struct {
	m map[string]Installation
}

// NewMemoryInstallationStore builds an empty memory store.
func NewMemoryInstallationStore() *MemoryInstallationStore {
	return &MemoryInstallationStore{m: map[string]Installation{}}
}

func installationKey(tenantID, provider string) string { return tenantID + "/" + provider }

// Get implements InstallationStore.
func (s *MemoryInstallationStore) Get(_ context.Context, tenantID, provider string) (Installation, error) {
	inst, ok := s.m[installationKey(tenantID, provider)]
	if !ok {
		return Installation{}, ErrInstallationNotFound
	}
	return inst, nil
}

// Upsert implements InstallationStore.
func (s *MemoryInstallationStore) Upsert(_ context.Context, inst Installation) error {
	if !IsValidInstallationStatus(inst.Status) {
		inst.Status = InstallationPending
	}
	if inst.CreatedAt.IsZero() {
		inst.CreatedAt = time.Now().UTC()
	}
	inst.UpdatedAt = time.Now().UTC()
	s.m[installationKey(inst.TenantID, inst.Provider)] = inst
	return nil
}

// UpdateHealth implements InstallationStore.
func (s *MemoryInstallationStore) UpdateHealth(_ context.Context, tenantID, provider string, h HealthUpdate) error {
	inst, ok := s.m[installationKey(tenantID, provider)]
	if !ok {
		return ErrInstallationNotFound
	}
	if h.Status != "" && IsValidInstallationStatus(h.Status) {
		inst.Status = h.Status
	}
	if h.CredentialRef != "" {
		inst.CredentialRef = h.CredentialRef
	}
	if !h.CredentialTTL.IsZero() {
		inst.CredentialTTL = h.CredentialTTL
	}
	if h.DeltaCursor != "" {
		inst.DeltaCursor = h.DeltaCursor
	}
	if !h.LastSuccessAt.IsZero() {
		inst.LastSuccessAt = h.LastSuccessAt
	}
	if !h.LastAttemptAt.IsZero() {
		inst.LastAttemptAt = h.LastAttemptAt
	}
	inst.SyncLagSeconds = h.SyncLagSeconds
	inst.DriftItems = h.DriftItems
	inst.LastError = h.LastError
	inst.UpdatedAt = time.Now().UTC()
	s.m[installationKey(tenantID, provider)] = inst
	return nil
}

// List implements InstallationStore.
func (s *MemoryInstallationStore) List(_ context.Context, provider string) ([]Installation, error) {
	var out []Installation
	for _, inst := range s.m {
		if provider == "" || inst.Provider == provider {
			out = append(out, inst)
		}
	}
	return out, nil
}

// PostgresInstallationStore persists installations in
// connector_installations (migration 032).
type PostgresInstallationStore struct {
	db *sql.DB
}

// NewPostgresInstallationStore wraps an *sql.DB with migration 032
// applied.
func NewPostgresInstallationStore(db *sql.DB) *PostgresInstallationStore {
	return &PostgresInstallationStore{db: db}
}

const installationColumns = `tenant_id, provider, status, credential_ref, credential_expires_at,
	delta_cursor, last_success_at, last_attempt_at, sync_lag_seconds,
	drift_items, last_error, region, created_at, updated_at`

// scanInstallation reads one row from the installationColumns layout.
func scanInstallation(scanner interface{ Scan(dest ...any) error }) (Installation, error) {
	var inst Installation
	var credentialTTL, lastSuccess, lastAttempt, createdAt, updatedAt sql.NullTime
	err := scanner.Scan(
		&inst.TenantID, &inst.Provider, &inst.Status, &inst.CredentialRef,
		&credentialTTL, &inst.DeltaCursor, &lastSuccess, &lastAttempt,
		&inst.SyncLagSeconds, &inst.DriftItems, &inst.LastError, &inst.Region,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return Installation{}, err
	}
	inst.CredentialTTL = credentialTTL.Time
	inst.LastSuccessAt = lastSuccess.Time
	inst.LastAttemptAt = lastAttempt.Time
	inst.CreatedAt = createdAt.Time
	inst.UpdatedAt = updatedAt.Time
	return inst, nil
}

// Get implements InstallationStore.
func (s *PostgresInstallationStore) Get(ctx context.Context, tenantID, provider string) (Installation, error) {
	const q = `SELECT ` + installationColumns + `
FROM connector_installations
WHERE tenant_id = $1 AND provider = $2`
	row := s.db.QueryRowContext(ctx, q, tenantID, provider)
	inst, err := scanInstallation(row)
	if err != nil {
		return Installation{}, err
	}
	return inst, nil
}

// Upsert implements InstallationStore.
func (s *PostgresInstallationStore) Upsert(ctx context.Context, inst Installation) error {
	const q = `
INSERT INTO connector_installations (
    tenant_id, provider, status, credential_ref,
    credential_expires_at, delta_cursor, last_success_at, last_attempt_at,
    sync_lag_seconds, drift_items, last_error, region
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (tenant_id, provider) DO UPDATE SET
    status                = EXCLUDED.status,
    credential_ref        = EXCLUDED.credential_ref,
    credential_expires_at = EXCLUDED.credential_expires_at,
    delta_cursor          = EXCLUDED.delta_cursor,
    last_success_at       = EXCLUDED.last_success_at,
    last_attempt_at       = EXCLUDED.last_attempt_at,
    sync_lag_seconds      = EXCLUDED.sync_lag_seconds,
    drift_items           = EXCLUDED.drift_items,
    last_error            = EXCLUDED.last_error,
    region                = EXCLUDED.region,
    updated_at            = NOW()`
	if !IsValidInstallationStatus(inst.Status) {
		inst.Status = InstallationPending
	}
	_, err := s.db.ExecContext(ctx, q,
		inst.TenantID, inst.Provider, string(inst.Status), inst.CredentialRef,
		nullTime(inst.CredentialTTL), inst.DeltaCursor,
		nullTime(inst.LastSuccessAt), nullTime(inst.LastAttemptAt),
		inst.SyncLagSeconds, inst.DriftItems, inst.LastError, inst.Region,
	)
	return err
}

// UpdateHealth implements InstallationStore.
func (s *PostgresInstallationStore) UpdateHealth(ctx context.Context, tenantID, provider string, h HealthUpdate) error {
	const q = `
UPDATE connector_installations SET
    status                = COALESCE(NULLIF($3, ''), status),
    credential_ref        = COALESCE(NULLIF($4, ''), credential_ref),
    credential_expires_at = COALESCE($5, credential_expires_at),
    delta_cursor          = COALESCE(NULLIF($6, ''), delta_cursor),
    last_success_at       = COALESCE($7, last_success_at),
    last_attempt_at       = COALESCE($8, last_attempt_at),
    sync_lag_seconds      = $9,
    drift_items           = $10,
    last_error            = $11,
    updated_at            = NOW()
WHERE tenant_id = $1 AND provider = $2`
	if h.Status != "" && !IsValidInstallationStatus(h.Status) {
		return ErrInvalidInstallationStatus
	}
	_, err := s.db.ExecContext(ctx, q,
		tenantID, provider, string(h.Status), h.CredentialRef,
		nullTime(h.CredentialTTL), h.DeltaCursor,
		nullTime(h.LastSuccessAt), nullTime(h.LastAttemptAt),
		h.SyncLagSeconds, h.DriftItems, h.LastError,
	)
	return err
}

// List implements InstallationStore.
func (s *PostgresInstallationStore) List(ctx context.Context, provider string) ([]Installation, error) {
	const q = `SELECT ` + installationColumns + `
FROM connector_installations
WHERE ($1 = '' OR provider = $1)
ORDER BY tenant_id`
	rows, err := s.db.QueryContext(ctx, q, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Installation
	for rows.Next() {
		inst, err := scanInstallation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inst)
	}
	return out, rows.Err()
}

// nullTime converts a zero time.Time to sql NULL for timestamptz
// parameters.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
