package tenancy

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"groundwork/query-runtime/internal/deployment"
	"groundwork/query-runtime/internal/runtime"
)

// Postgres store (production). Requires migration 027
// (027_create_tenancy.up.sql). Tenant status transitions and their
// hash-chained evidence events run inside one transaction serialized per
// tenant (pg_advisory_xact_lock), so the chain cannot fork under
// concurrency.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore returns the Postgres-backed tenant directory store.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (p *PostgresStore) Transact(ctx context.Context, lockKey string, fn func(tx TxStore) error) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		return err
	}
	ptx := &postgresTx{db: tx}
	if err := fn(ptx); err != nil {
		return err
	}
	return tx.Commit()
}

type postgresTx struct {
	db *sql.Tx
}

const tenantColumns = `tenant_id, region, status, COALESCE(capacity_tier, 'standard'), created_by, reason, created_at, updated_at, deprovisioned_at`

func scanTenant(row interface{ Scan(...any) error }) (runtime.Tenant, error) {
	var t runtime.Tenant
	var deprovisionedAt sql.NullTime
	err := row.Scan(&t.TenantID, &t.Region, &t.Status, &t.Tier, &t.CreatedBy, &t.Reason,
		&t.CreatedAt, &t.UpdatedAt, &deprovisionedAt)
	if deprovisionedAt.Valid {
		t.DeprovisionedAt = deprovisionedAt.Time
	}
	return t, err
}

func (p *postgresTx) GetTenant(ctx context.Context, tenantID string) (runtime.Tenant, error) {
	t, err := scanTenant(p.db.QueryRowContext(ctx, `
		SELECT `+tenantColumns+` FROM tenants
		WHERE tenant_id = $1
	`, tenantID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.Tenant{}, runtime.ErrTenantNotFound
	}
	return t, err
}

func (p *postgresTx) ListTenants(ctx context.Context) ([]runtime.Tenant, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT `+tenantColumns+` FROM tenants
		ORDER BY tenant_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.Tenant, 0)
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

const eventColumns = `id::text, tenant_id, event_type, actor, reason, region, immutable_digest, previous_hash, created_at`

func scanEvent(row interface{ Scan(...any) error }) (runtime.TenantEvent, error) {
	var e runtime.TenantEvent
	err := row.Scan(&e.ID, &e.TenantID, &e.EventType, &e.Actor, &e.Reason, &e.Region,
		&e.ImmutableDigest, &e.PreviousHash, &e.CreatedAt)
	return e, err
}

func (p *postgresTx) ListEvents(ctx context.Context, tenantID string) ([]runtime.TenantEvent, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT `+eventColumns+` FROM tenant_events
		WHERE tenant_id = $1
		ORDER BY created_at, id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.TenantEvent, 0)
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *postgresTx) UpsertTenant(ctx context.Context, t runtime.Tenant) (runtime.Tenant, error) {
	if t.Tier == "" {
		t.Tier = runtime.CapacityTierStandard
	}
	row := p.db.QueryRowContext(ctx, `
		INSERT INTO tenants (tenant_id, region, status, capacity_tier, created_by, reason, created_at, updated_at, deprovisioned_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id) DO UPDATE
		SET region = EXCLUDED.region,
		    status = EXCLUDED.status,
		    capacity_tier = EXCLUDED.capacity_tier,
		    created_by = EXCLUDED.created_by,
		    reason = EXCLUDED.reason,
		    updated_at = EXCLUDED.updated_at,
		    deprovisioned_at = EXCLUDED.deprovisioned_at
		RETURNING `+tenantColumns,
		t.TenantID, t.Region, t.Status, t.Tier, t.CreatedBy, t.Reason, t.CreatedAt, t.UpdatedAt,
		nullTime(t.DeprovisionedAt))
	tenant, err := scanTenant(row)
	if err != nil {
		return runtime.Tenant{}, err
	}
	// Keep the Phase 4 tenant_regions metadata (migration 017) in sync
	// so exports and operators see one region mapping. The provisioning
	// directory is the authoritative lifecycle source; this mirror is a
	// best-effort consistency write inside the same transaction.
	_, _ = p.db.ExecContext(ctx, `
		INSERT INTO tenant_regions (tenant_id, region, jurisdiction, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (tenant_id) DO UPDATE
		SET region = EXCLUDED.region,
		    jurisdiction = EXCLUDED.jurisdiction,
		    updated_at = now()
	`, t.TenantID, t.Region, deployment.Region(t.Region).Jurisdiction())
	return tenant, nil
}

func (p *postgresTx) SetTenantStatus(ctx context.Context, tenantID, status, actor, reason string, now time.Time) (runtime.Tenant, error) {
	row := p.db.QueryRowContext(ctx, `
		UPDATE tenants
		SET status = $1,
		    reason = $2,
		    updated_at = $3,
		    deprovisioned_at = CASE WHEN $1 = 'deprovisioned' THEN $3 ELSE deprovisioned_at END
		WHERE tenant_id = $4
		RETURNING `+tenantColumns,
		status, reason, now, tenantID)
	tenant, err := scanTenant(row)
	if err != nil {
		return runtime.Tenant{}, err
	}
	_, _ = p.db.ExecContext(ctx, `
		INSERT INTO tenant_regions (tenant_id, region, jurisdiction, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (tenant_id) DO UPDATE
		SET region = EXCLUDED.region,
		    jurisdiction = EXCLUDED.jurisdiction,
		    updated_at = now()
	`, tenant.TenantID, tenant.Region, deployment.Region(tenant.Region).Jurisdiction())
	return tenant, nil
}

func (p *postgresTx) AppendEvent(ctx context.Context, e runtime.TenantEvent) (runtime.TenantEvent, error) {
	var prev string
	if err := p.db.QueryRowContext(ctx, `
		SELECT immutable_digest FROM tenant_events
		WHERE tenant_id = $1
		ORDER BY created_at DESC, id DESC LIMIT 1
	`, e.TenantID).Scan(&prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return runtime.TenantEvent{}, err
	}
	e.ImmutableDigest = ComputeTenantEventDigest(e, prev)
	row := p.db.QueryRowContext(ctx, `
		INSERT INTO tenant_events
			(tenant_id, event_type, actor, reason, region, immutable_digest, previous_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+eventColumns,
		e.TenantID, e.EventType, e.Actor, e.Reason, e.Region, e.ImmutableDigest, prev)
	return scanEvent(row)
}

func (p *PostgresStore) GetTenant(ctx context.Context, tenantID string) (runtime.Tenant, error) {
	t, err := scanTenant(p.db.QueryRowContext(ctx, `
		SELECT `+tenantColumns+` FROM tenants
		WHERE tenant_id = $1
	`, tenantID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.Tenant{}, runtime.ErrTenantNotFound
	}
	return t, err
}

func (p *PostgresStore) ListTenants(ctx context.Context) ([]runtime.Tenant, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT `+tenantColumns+` FROM tenants
		ORDER BY tenant_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.Tenant, 0)
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (p *PostgresStore) ListEvents(ctx context.Context, tenantID string) ([]runtime.TenantEvent, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT `+eventColumns+` FROM tenant_events
		WHERE tenant_id = $1
		ORDER BY created_at, id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.TenantEvent, 0)
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// nullTime converts a time.Time to a nullable SQL value (zero time => NULL).
func nullTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}
}

var _ Store = (*PostgresStore)(nil)
