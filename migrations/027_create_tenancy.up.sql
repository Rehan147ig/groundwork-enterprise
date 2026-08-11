-- Tenant provisioning directory (Phase 8.1 Multi-tenancy and isolation).
--
-- The tenant directory is the operator-managed source of truth for
-- tenant lifecycle: who is provisioned, in which region, and in what
-- lifecycle state. It complements (never replaces) the environment-based
-- GROUNDWORK_TENANT_REGIONS configuration: config tenants are seeded
-- into the directory at startup, and tenants provisioned through the
-- admin API are resolvable by the auth layer from the directory.
--
-- Lifecycle invariants:
--   - status is one of active / disabled / deprovisioned;
--   - there is NO destructive delete — deprovisioning is the terminal
--     state and every transition writes hash-chained evidence;
--   - a disabled or deprovisioned tenant fails closed at the auth layer
--     on the next request (TenantDirectory check in authenticate);
--   - every lifecycle transition (provisioned / disabled / enabled /
--     deprovisioned) appends a write-once, hash-chained event row;
--   - events are write-once at the schema level (no UPDATE/DELETE);
--   - tenant region always comes from the directory or trusted config,
--     never from request bodies.
--
-- Relationship to tenant_regions (migration 017): the provisioning
-- directory supersedes that dormant Phase 4 metadata table as the
-- authoritative tenant source; the tenancy store keeps tenant_regions
-- in sync (same transaction) so existing exports keep a single region
-- mapping.

CREATE TABLE tenants (
    tenant_id         TEXT PRIMARY KEY,
    region            TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active','disabled','deprovisioned')),
    created_by        TEXT NOT NULL DEFAULT '',
    reason            TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    deprovisioned_at  TIMESTAMPTZ
);
CREATE INDEX idx_tenants_status_region ON tenants (status, region);

-- Immutable hash-chained evidence of every tenant lifecycle transition.
-- Chained per tenant (each row digests its predecessor).
CREATE TABLE tenant_events (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        TEXT NOT NULL,
    event_type       TEXT NOT NULL
                     CHECK (event_type IN ('provisioned','disabled','enabled','deprovisioned')),
    actor            TEXT NOT NULL,
    reason           TEXT NOT NULL DEFAULT '',
    region           TEXT NOT NULL DEFAULT '',
    immutable_digest TEXT NOT NULL,
    previous_hash    TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_tenant_events_tenant_time ON tenant_events (tenant_id, created_at);

-- Write-once: tenant lifecycle events are immutable evidence.
CREATE RULE no_update_tenant_events AS ON UPDATE TO tenant_events DO INSTEAD NOTHING;
CREATE RULE no_delete_tenant_events AS ON DELETE TO tenant_events DO INSTEAD NOTHING;
