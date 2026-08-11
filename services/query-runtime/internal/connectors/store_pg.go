package connectors

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"groundwork/query-runtime/internal/runtime"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresStore is the production registry. Lifecycle transitions are
// serialized per connector with an advisory lock so the hash chain
// cannot fork under concurrency (mirrors the agent registry pattern).
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore wraps a live *sql.DB.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

const connectorColumns = `id::text, tenant_id, name, connector_type, lifecycle, base_url, region,
	COALESCE(tool_id::text, ''), owner_principal_id, manifest_digest, timeout_ms, retry_max,
	retry_idempotent_only, max_response_bytes, allowed_content_types, redaction_fields,
	secret_ref, tls_verify, client_cert_ref, created_at, updated_at`

func scanConnector(row interface{ Scan(...any) error }) (runtime.Connector, error) {
	var c runtime.Connector
	var allowed, redact []byte
	if err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.Type, &c.Lifecycle, &c.BaseURL, &c.Region,
		&c.ToolID, &c.OwnerPrincipalID, &c.ManifestDigest, &c.TimeoutMS, &c.RetryMax,
		&c.RetryIdempotentOnly, &c.MaxResponseBytes, &allowed, &redact,
		&c.SecretRef, &c.TLSVerify, &c.ClientCertRef, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return c, err
	}
	_ = json.Unmarshal(allowed, &c.AllowedContentTypes)
	_ = json.Unmarshal(redact, &c.RedactionFields)
	return c, nil
}

func (p *PostgresStore) CreateConnector(ctx context.Context, c runtime.Connector, v runtime.ConnectorVersion, actions []runtime.ConnectorActionManifest, ev runtime.ConnectorLifecycleEvent) error {
	allowed, _ := json.Marshal(c.AllowedContentTypes)
	redact, _ := json.Marshal(c.RedactionFields)
	return withTx(ctx, p.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO connectors (id, tenant_id, name, connector_type, lifecycle, base_url, region,
				tool_id, owner_principal_id, manifest_digest, timeout_ms, retry_max,
				retry_idempotent_only, max_response_bytes, allowed_content_types, redaction_fields,
				secret_ref, tls_verify, client_cert_ref)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
			c.ID, c.TenantID, c.Name, c.Type, c.Lifecycle, c.BaseURL, c.Region, nullUUID(c.ToolID),
			c.OwnerPrincipalID, c.ManifestDigest, c.TimeoutMS, c.RetryMax, c.RetryIdempotentOnly,
			c.MaxResponseBytes, allowed, redact, c.SecretRef, c.TLSVerify, c.ClientCertRef); err != nil {
			return mapInsertErr(err)
		}
		if err := insertVersionTx(ctx, tx, c.ID, c.TenantID, v); err != nil {
			return err
		}
		for _, a := range SortedActions(actions) {
			if err := insertActionTx(ctx, tx, c.TenantID, c.ID, v.ID, a); err != nil {
				return err
			}
		}
		// The store is the single authoritative chaining point: the
		// create event is the chain root (previous digest "").
		ev.ImmutableDigest = ConnectorLifecycleDigest(ev.TenantID, ev.ConnectorID, ev.ActionType,
			ev.FromState, ev.ToState, ev.ActorPrincipalID, ev.Reason, "")
		return insertLifecycleTx(ctx, tx, ev)
	})
}

func (p *PostgresStore) ListConnectors(ctx context.Context, tenantID string) ([]runtime.Connector, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT `+connectorColumns+` FROM connectors WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.Connector
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListAllConnectors spans tenants for the credential-expiry monitor.
func (p *PostgresStore) ListAllConnectors(ctx context.Context) ([]runtime.Connector, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT `+connectorColumns+` FROM connectors ORDER BY tenant_id, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.Connector
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *PostgresStore) GetConnector(ctx context.Context, tenantID, connectorID string) (runtime.Connector, error) {
	c, err := scanConnector(p.db.QueryRowContext(ctx, `
		SELECT `+connectorColumns+` FROM connectors
		WHERE tenant_id = $1 AND id::text = $2`, tenantID, connectorID))
	if errors.Is(err, sql.ErrNoRows) {
		return runtime.Connector{}, runtime.ErrConnectorNotFound
	}
	return c, err
}

func (p *PostgresStore) GetConnectorByName(ctx context.Context, tenantID, name string) (runtime.Connector, error) {
	c, err := scanConnector(p.db.QueryRowContext(ctx, `
		SELECT `+connectorColumns+` FROM connectors
		WHERE tenant_id = $1 AND name = $2`, tenantID, name))
	if errors.Is(err, sql.ErrNoRows) {
		return runtime.Connector{}, runtime.ErrConnectorNotFound
	}
	return c, err
}

func (p *PostgresStore) TransitionConnector(ctx context.Context, tenantID, connectorID, from, to, actor, reason string) (runtime.Connector, error) {
	var c runtime.Connector
	err := withTx(ctx, p.db, func(tx *sql.Tx) error {
		// Serialize per connector: the chain cannot fork under concurrency.
		if _, err := tx.ExecContext(ctx,
			`SELECT pg_advisory_xact_lock(hashtext($1))`, connectorID); err != nil {
			return err
		}
		cur, err := scanConnector(tx.QueryRowContext(ctx, `
			SELECT `+connectorColumns+` FROM connectors
			WHERE tenant_id = $1 AND id::text = $2 FOR UPDATE`, tenantID, connectorID))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return runtime.ErrConnectorNotFound
			}
			return err
		}
		if cur.Lifecycle != from {
			return runtime.ErrConnectorInvalidState
		}
		if !isValidTransition(from, to) {
			return runtime.ErrConnectorInvalidState
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE connectors SET lifecycle = $1, updated_at = now() WHERE id = $2`,
			to, cur.ID); err != nil {
			return err
		}
		c = cur
		c.Lifecycle = to
		c.UpdatedAt = time.Now().UTC()
		return insertLifecycleTx(ctx, tx, makeLifecycleEvent(c, lifecycleActionType(from, to), from, to, actor, reason, time.Now().UTC(), lastDigestInTx(ctx, tx, tenantID, connectorID)))
	})
	return c, err
}

func (p *PostgresStore) UpdateVersion(ctx context.Context, c runtime.Connector, v runtime.ConnectorVersion, actions []runtime.ConnectorActionManifest, ev runtime.ConnectorLifecycleEvent) error {
	return withTx(ctx, p.db, func(tx *sql.Tx) error {
		allowed, _ := json.Marshal(c.AllowedContentTypes)
		redact, _ := json.Marshal(c.RedactionFields)
		if _, err := tx.ExecContext(ctx, `
			UPDATE connectors SET base_url=$1, timeout_ms=$2, retry_max=$3,
				retry_idempotent_only=$4, max_response_bytes=$5, allowed_content_types=$6,
				redaction_fields=$7, secret_ref=$8, tls_verify=$9, client_cert_ref=$10,
				manifest_digest=$11, current_version_id=$12, updated_at=now()
			WHERE tenant_id=$13 AND id=$14 AND lifecycle IN ('draft','suspended')`,
			c.BaseURL, c.TimeoutMS, c.RetryMax, c.RetryIdempotentOnly, c.MaxResponseBytes,
			allowed, redact, c.SecretRef, c.TLSVerify, c.ClientCertRef, v.ManifestDigest,
			v.ID, c.TenantID, c.ID); err != nil {
			return err
		}
		// Config updates only on draft/suspended connectors: active
		// connectors must not change surface under traffic.
		var n int
		if err := tx.QueryRowContext(ctx,
			`SELECT count(*) FROM connectors WHERE tenant_id=$1 AND id=$2`,
			c.TenantID, c.ID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return runtime.ErrConnectorNotFound
		}
		if err := insertVersionTx(ctx, tx, c.ID, c.TenantID, v); err != nil {
			return err
		}
		for _, a := range SortedActions(actions) {
			if err := insertActionTx(ctx, tx, c.TenantID, c.ID, v.ID, a); err != nil {
				return err
			}
		}
		// Chain off the previous event's digest inside the same tx
		// (the store is the single authoritative chaining point).
		ev.ImmutableDigest = ConnectorLifecycleDigest(ev.TenantID, ev.ConnectorID, ev.ActionType,
			ev.FromState, ev.ToState, ev.ActorPrincipalID, ev.Reason, lastDigestInTx(ctx, tx, c.TenantID, c.ID))
		return insertLifecycleTx(ctx, tx, ev)
	})
}

func (p *PostgresStore) GetCurrentVersion(ctx context.Context, tenantID, connectorID string) (runtime.ConnectorVersion, error) {
	var v runtime.ConnectorVersion
	var config []byte
	err := p.db.QueryRowContext(ctx, `
		SELECT id::text, connector_id::text, tenant_id, version_number, config::text,
			manifest_digest, created_by, created_at
		FROM connector_versions
		WHERE tenant_id = $1 AND connector_id = $2
		ORDER BY version_number DESC LIMIT 1`, tenantID, connectorID).Scan(
		&v.ID, &v.ConnectorID, &v.TenantID, &v.VersionNumber, &config, &v.ManifestDigest, &v.CreatedBy, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return runtime.ConnectorVersion{}, runtime.ErrConnectorNoManifest
	}
	if err != nil {
		return runtime.ConnectorVersion{}, err
	}
	if err := json.Unmarshal(config, &v.Config); err != nil {
		return runtime.ConnectorVersion{}, err
	}
	return v, nil
}

func (p *PostgresStore) GetActions(ctx context.Context, tenantID, connectorID, versionID string) ([]runtime.ConnectorActionManifest, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT name, transport_method, path_template, resource_type, risk, read_only,
			requires_approval, max_request_bytes, max_response_bytes,
			allowed_agent_version_ids, args
		FROM connector_actions
		WHERE tenant_id=$1 AND connector_id=$2 AND version_id=$3
		ORDER BY name`, tenantID, connectorID, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.ConnectorActionManifest
	for rows.Next() {
		var a runtime.ConnectorActionManifest
		var versions, args []byte
		if err := rows.Scan(&a.Name, &a.TransportMethod, &a.PathTemplate, &a.ResourceType,
			&a.Risk, &a.ReadOnly, &a.RequiresApproval, &a.MaxRequestBytes, &a.MaxResponseBytes,
			&versions, &args); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(versions, &a.AllowedVersions)
		_ = json.Unmarshal(args, &a.Args)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *PostgresStore) ListLifecycleEvents(ctx context.Context, tenantID, connectorID string) ([]runtime.ConnectorLifecycleEvent, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id::text, tenant_id, connector_id::text, action_type, from_state, to_state,
			actor_principal_id, reason, immutable_digest, created_at
		FROM connector_lifecycle_events
		WHERE tenant_id=$1 AND connector_id=$2 ORDER BY created_at, id`, tenantID, connectorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.ConnectorLifecycleEvent
	for rows.Next() {
		var e runtime.ConnectorLifecycleEvent
		if err := rows.Scan(&e.ID, &e.TenantID, &e.ConnectorID, &e.ActionType, &e.FromState,
			&e.ToState, &e.ActorPrincipalID, &e.Reason, &e.ImmutableDigest, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- tx helpers ---

// withTx runs fn inside one transaction and commits on success.
func withTx(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func insertVersionTx(ctx context.Context, tx *sql.Tx, connectorID, tenantID string, v runtime.ConnectorVersion) error {
	config, err := json.Marshal(v.Config)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO connector_versions (id, connector_id, tenant_id, version_number, config, manifest_digest, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		v.ID, connectorID, tenantID, v.VersionNumber, config, v.ManifestDigest, v.CreatedBy)
	return mapInsertErr(err)
}

func insertActionTx(ctx context.Context, tx *sql.Tx, tenantID, connectorID, versionID string, a runtime.ConnectorActionManifest) error {
	versions, err := json.Marshal(a.AllowedVersions)
	if err != nil {
		return err
	}
	args, err := json.Marshal(a.Args)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO connector_actions (tenant_id, connector_id, version_id, name, transport_method,
			path_template, resource_type, risk, read_only, requires_approval,
			max_request_bytes, max_response_bytes, allowed_agent_version_ids, args)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		tenantID, connectorID, versionID, a.Name, a.TransportMethod, a.PathTemplate,
		a.ResourceType, a.Risk, a.ReadOnly, a.RequiresApproval, a.MaxRequestBytes,
		a.MaxResponseBytes, versions, args)
	return mapInsertErr(err)
}

func insertLifecycleTx(ctx context.Context, tx *sql.Tx, ev runtime.ConnectorLifecycleEvent) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO connector_lifecycle_events (tenant_id, connector_id, action_type,
			from_state, to_state, actor_principal_id, reason, immutable_digest)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		ev.TenantID, ev.ConnectorID, ev.ActionType, ev.FromState, ev.ToState,
		ev.ActorPrincipalID, ev.Reason, ev.ImmutableDigest)
	return err
}

func lastDigestInTx(ctx context.Context, tx *sql.Tx, tenantID, connectorID string) string {
	var d string
	_ = tx.QueryRowContext(ctx, `
		SELECT immutable_digest FROM connector_lifecycle_events
		WHERE tenant_id=$1 AND connector_id=$2 ORDER BY created_at DESC, id DESC LIMIT 1`,
		tenantID, connectorID).Scan(&d)
	return d
}

func mapInsertErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("connector store: %w", err)
}

// nullUUID returns nil for an empty string so pgx encodes SQL NULL.
func nullUUID(s string) any {
	if s == "" {
		return nil
	}
	return s
}
