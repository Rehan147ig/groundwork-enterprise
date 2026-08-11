-- Break-glass operator access (Phase 8.4 Security Operations).
--
-- Time-bounded, reason-mandatory emergency admin access for operators.
-- A break-glass grant is opened by a verified operator, mints a
-- short-lived admin-scoped API key (api_keys.expires_at — added by the
-- API-key resolver bootstrap, since api_keys is resolver-managed, not
-- migration-managed), and records hash-chained write-once evidence.
--
-- Security invariants:
--   - every grant carries a mandatory reason and a bounded duration
--     (1..1440 minutes, service-capped by BREAK_GLASS_MAX_MINUTES);
--   - an expired or revoked grant's API key is unresolvable, so access
--     fails closed at the auth layer on the next request;
--   - every lifecycle transition (opened / expired / revoked) appends a
--     hash-chained evidence event (actor, reason, duration, key);
--   - events are write-once at the schema level (no UPDATE/DELETE);
--   - grants are tenant-scoped; tenant_id comes only from the verified
--     API-key context, never from the body.

CREATE TABLE break_glass_grants (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            TEXT NOT NULL,
    operator_principal_id TEXT NOT NULL,
    reason               TEXT NOT NULL,
    duration_minutes     INTEGER NOT NULL
                         CHECK (duration_minutes BETWEEN 1 AND 1440),
    key_id               BIGINT NOT NULL,
    key_prefix           TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL DEFAULT 'active'
                         CHECK (status IN ('active','expired','revoked')),
    expires_at           TIMESTAMPTZ NOT NULL,
    requested_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at           TIMESTAMPTZ,
    revoked_by           TEXT NOT NULL DEFAULT '',
    revocation_reason    TEXT NOT NULL DEFAULT '',
    immutable_digest     TEXT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_break_glass_grants_tenant ON break_glass_grants (tenant_id, status, expires_at);
CREATE INDEX idx_break_glass_grants_key ON break_glass_grants (key_id);

-- Immutable evidence of every break-glass lifecycle transition.
-- Hash-chained per tenant (each row digests its predecessor), write-once
-- at the schema level.
CREATE TABLE break_glass_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           TEXT NOT NULL,
    grant_id            UUID NOT NULL,
    event_type          TEXT NOT NULL
                        CHECK (event_type IN ('opened','expired','revoked')),
    actor_principal_id  TEXT NOT NULL,
    reason              TEXT NOT NULL DEFAULT '',
    duration_minutes    INTEGER NOT NULL DEFAULT 0,
    key_id              BIGINT NOT NULL DEFAULT 0,
    expires_at          TIMESTAMPTZ,
    immutable_digest    TEXT NOT NULL,
    previous_hash       TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_break_glass_events_tenant_time ON break_glass_events (tenant_id, created_at);
CREATE INDEX idx_break_glass_events_grant ON break_glass_events (grant_id, created_at);

-- Write-once: break-glass events are immutable evidence.
CREATE RULE no_update_break_glass_events AS ON UPDATE TO break_glass_events DO INSTEAD NOTHING;
CREATE RULE no_delete_break_glass_events AS ON DELETE TO break_glass_events DO INSTEAD NOTHING;
