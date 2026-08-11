-- Sovereign Multi-Region Deployment Metadata (Phase 4).
--
-- Builds on the Phase 3 Evidence/Outbox (016). Adds two metadata
-- registries backing the Phase 4 customer-managed key and sovereign
-- region story:
--
--   - key_material_registry: an audit trail of which purpose key is
--     provisioned, from which source, and when it was (re)provisioned
--     or rotated. Actual key material never leaves the provider
--     (env / external key store); only metadata is recorded here so
--     rotation history is auditable and restarts can detect drift.
--
--   - tenant_regions: the tenant -> region/jurisdiction mapping for a
--     sovereign deployment. Env-driven today (GROUNDWORK_TENANT_*_REGION)
--     but persisted so operators and exports have a single source of
--     truth for where a tenant's data resides.
--
-- Tenancy: tenant_regions is keyed by tenant_id; the key registry is
-- deployment-global (purposes are not per-tenant).
CREATE TABLE key_material_registry (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purpose        TEXT NOT NULL
                   CHECK (purpose IN ('identity','delegation','webhook','audit_digest','database','backup')),
    key_id         TEXT NOT NULL,
    material_kind  TEXT NOT NULL CHECK (material_kind IN ('hmac','rsa_private','key_id_reference','unknown')),
    source         TEXT NOT NULL DEFAULT '',
    rotated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (purpose)
);
CREATE INDEX idx_key_registry_rotated ON key_material_registry (purpose, rotated_at DESC);

CREATE TABLE tenant_regions (
    tenant_id     TEXT PRIMARY KEY,
    region        TEXT NOT NULL,
    jurisdiction  TEXT NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_tenant_regions_region ON tenant_regions (region);
