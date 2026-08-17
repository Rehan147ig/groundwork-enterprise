-- Migration 032: Connector installation registry + permission snapshots.
--
-- Production-grade connector lifecycle (Milestone 3):
--   - connector_installations is the tenant-bound installation record: one
--     row per (tenant_id, provider). It carries the credential reference
--     (keyring:// or secret-manager ref — never the secret itself), the
--     encrypted credential metadata, the durable delta cursor, and the
--     health surface (last success, lag, drift, credential expiry).
--   - msgraph.permission_snapshots stores the last-known read-granting
--     permissions per drive item so delta polls can diff against the
--     previous state and emit concrete revoke events.
--
-- Guarantees:
--   - Credential secrets never appear in plaintext here: credential_ref
--     names the keyring entry; credential_metadata is AES-GCM encrypted
--     with the connector purpose key (keyring.PurposeConnector).
--   - Installation is tenant-bound: tenant_id is required and the
--     runtime/connector never derives it from payloads.
--   - Status transitions are CHECK-constrained: pending -> active /
--     degraded / failed / disabled.

CREATE TABLE connector_installations (
    tenant_id             TEXT NOT NULL,
    provider              TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','active','degraded','failed','disabled')),
    credential_ref        TEXT NOT NULL DEFAULT '',
    credential_metadata   BYTEA,
    credential_expires_at TIMESTAMPTZ,
    delta_cursor          TEXT NOT NULL DEFAULT '',
    last_success_at       TIMESTAMPTZ,
    last_attempt_at       TIMESTAMPTZ,
    sync_lag_seconds      BIGINT NOT NULL DEFAULT 0,
    drift_items           INTEGER NOT NULL DEFAULT 0,
    last_error            TEXT NOT NULL DEFAULT '',
    region                TEXT NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, provider)
);
CREATE INDEX idx_connector_installations_status
    ON connector_installations (status, last_success_at DESC);

-- Last-known read-granting permissions per drive item. The delta poll
-- diffs the current Graph permissions against this snapshot to emit
-- concrete PermissionChange revoke events; tombstones (deleted items)
-- revoke every grantee recorded here.
CREATE TABLE msgraph.permission_snapshots (
    tenant_id    TEXT NOT NULL,
    item_id      TEXT NOT NULL,
    is_folder    BOOLEAN NOT NULL DEFAULT FALSE,
    parent_id    TEXT NOT NULL DEFAULT '',
    grantees     JSONB NOT NULL DEFAULT '[]',
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, item_id)
);