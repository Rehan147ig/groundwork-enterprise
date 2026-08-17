-- Migration 035: Create api_keys table (previously resolver-managed).
--
-- The API-key resolver historically created and altered api_keys at
-- runtime (internal/runtime/auth.go bootstrap()). That left schema truth
-- split between migrations and application DDL. This migration owns the
-- canonical schema; the resolver now inserts-only when the table exists
-- and otherwise fails with "run migrations first".
--
-- Security invariants:
--   - key_hash is a SHA-256 digest of the raw key (never the key itself);
--   - key_prefix stores only the short public prefix for enumeration
--     resistance and lookup;
--   - scopes are comma-joined; the auth layer parses them into the
--     trusted TenantContext.Scopes set;
--   - active + revoked_at + expires_at let revocation and expiry fail
--     closed at Resolve.

CREATE TABLE IF NOT EXISTS api_keys (
    id BIGSERIAL PRIMARY KEY,
    key_hash TEXT UNIQUE NOT NULL,
    key_prefix TEXT,
    tenant_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT 'default',
    scopes TEXT NOT NULL DEFAULT 'query',
    rate_limit_rpm INTEGER NOT NULL DEFAULT 60,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS api_keys_key_prefix_idx ON api_keys (key_prefix);
CREATE INDEX IF NOT EXISTS api_keys_tenant_active_idx ON api_keys (tenant_id, active);
