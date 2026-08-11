package breakglass

import (
	"context"
	"database/sql"
	"errors"

	"groundwork/query-runtime/internal/runtime"
)

// Postgres store (production). Requires migration 026
// (026_create_break_glass.up.sql). Grant creation/revocation and their
// hash-chained evidence events run inside one transaction serialized per
// tenant (pg_advisory_xact_lock), so the chain cannot fork under
// concurrency.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore returns the Postgres-backed break-glass store.
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

const grantColumns = `id::text, tenant_id, operator_principal_id, reason, duration_minutes, key_id, key_prefix, status, expires_at, requested_at, revoked_at, revoked_by, revocation_reason, immutable_digest, created_at`

func scanGrant(row interface{ Scan(...any) error }) (runtime.BreakGlassGrant, error) {
	var g runtime.BreakGlassGrant
	err := row.Scan(&g.ID, &g.TenantID, &g.OperatorPrincipalID, &g.Reason, &g.DurationMinutes,
		&g.KeyID, &g.KeyPrefix, &g.Status, &g.ExpiresAt, &g.RequestedAt,
		&g.RevokedAt, &g.RevokedBy, &g.RevocationReason, &g.ImmutableDigest, &g.CreatedAt)
	return g, err
}

func (p *postgresTx) GetGrant(ctx context.Context, tenantID, grantID string) (runtime.BreakGlassGrant, error) {
	g, err := scanGrant(p.db.QueryRowContext(ctx, `
		SELECT `+grantColumns+` FROM break_glass_grants
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, grantID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.BreakGlassGrant{}, runtime.ErrBreakGlassNotFound
	}
	return g, err
}

func (p *postgresTx) ListGrants(ctx context.Context, tenantID string) ([]runtime.BreakGlassGrant, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT `+grantColumns+` FROM break_glass_grants
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.BreakGlassGrant, 0)
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (p *postgresTx) ListEvents(ctx context.Context, tenantID, grantID string) ([]runtime.BreakGlassEvent, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT `+eventColumns+` FROM break_glass_events
		WHERE tenant_id = $1 AND grant_id = $2
		ORDER BY created_at, id
	`, tenantID, grantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.BreakGlassEvent, 0)
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *postgresTx) CreateGrant(ctx context.Context, g runtime.BreakGlassGrant) (runtime.BreakGlassGrant, error) {
	row := p.db.QueryRowContext(ctx, `
		INSERT INTO break_glass_grants
			(tenant_id, operator_principal_id, reason, duration_minutes, key_id, key_prefix, status, expires_at, requested_at, immutable_digest)
		VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $8, $9)
		RETURNING `+grantColumns,
		g.TenantID, g.OperatorPrincipalID, g.Reason, g.DurationMinutes, g.KeyID, g.KeyPrefix,
		g.ExpiresAt, g.RequestedAt, g.ImmutableDigest)
	return scanGrant(row)
}

const eventColumns = `id::text, tenant_id, grant_id, event_type, actor_principal_id, reason, duration_minutes, key_id, expires_at, immutable_digest, previous_hash, created_at`

func scanEvent(row interface{ Scan(...any) error }) (runtime.BreakGlassEvent, error) {
	var e runtime.BreakGlassEvent
	err := row.Scan(&e.ID, &e.TenantID, &e.GrantID, &e.EventType, &e.ActorPrincipalID,
		&e.Reason, &e.DurationMinutes, &e.KeyID, &e.ExpiresAt,
		&e.ImmutableDigest, &e.PreviousHash, &e.CreatedAt)
	return e, err
}

func (p *postgresTx) AppendEvent(ctx context.Context, e runtime.BreakGlassEvent) (runtime.BreakGlassEvent, error) {
	var prev string
	if err := p.db.QueryRowContext(ctx, `
		SELECT immutable_digest FROM break_glass_events
		WHERE tenant_id = $1
		ORDER BY created_at DESC, id DESC LIMIT 1
	`, e.TenantID).Scan(&prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return runtime.BreakGlassEvent{}, err
	}
	e.ImmutableDigest = ComputeBreakGlassEventDigest(e, prev)
	row := p.db.QueryRowContext(ctx, `
		INSERT INTO break_glass_events
			(tenant_id, grant_id, event_type, actor_principal_id, reason, duration_minutes, key_id, expires_at, immutable_digest, previous_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING `+eventColumns,
		e.TenantID, e.GrantID, e.EventType, e.ActorPrincipalID, e.Reason,
		e.DurationMinutes, e.KeyID, e.ExpiresAt, e.ImmutableDigest, prev)
	return scanEvent(row)
}

func (p *postgresTx) SetGrantStatus(ctx context.Context, tenantID, grantID, status, revokedBy, revocationReason string) (runtime.BreakGlassGrant, error) {
	row := p.db.QueryRowContext(ctx, `
		UPDATE break_glass_grants
		SET status = $1,
		    revoked_by = CASE WHEN $1 = 'revoked' THEN $4 ELSE '' END,
		    revocation_reason = CASE WHEN $1 = 'revoked' THEN $5 ELSE '' END,
		    revoked_at = CASE WHEN $1 = 'revoked' THEN now() ELSE revoked_at END
		WHERE tenant_id = $2 AND id = $3
		RETURNING `+grantColumns,
		status, tenantID, grantID, revokedBy, revocationReason)
	return scanGrant(row)
}

func (p *PostgresStore) GetGrant(ctx context.Context, tenantID, grantID string) (runtime.BreakGlassGrant, error) {
	g, err := scanGrant(p.db.QueryRowContext(ctx, `
		SELECT `+grantColumns+` FROM break_glass_grants
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, grantID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.BreakGlassGrant{}, runtime.ErrBreakGlassNotFound
	}
	return g, err
}

func (p *PostgresStore) ListGrants(ctx context.Context, tenantID string) ([]runtime.BreakGlassGrant, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT `+grantColumns+` FROM break_glass_grants
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.BreakGlassGrant, 0)
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (p *PostgresStore) ListEvents(ctx context.Context, tenantID, grantID string) ([]runtime.BreakGlassEvent, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT `+eventColumns+` FROM break_glass_events
		WHERE tenant_id = $1 AND grant_id = $2
		ORDER BY created_at, id
	`, tenantID, grantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.BreakGlassEvent, 0)
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

var _ Store = (*PostgresStore)(nil)
