-- Agent Registry & Lifecycle (Phase 1: Agent Trust and Control Plane).
--
-- Every AI agent becomes a first-class, tenant-scoped identity with an
-- accountable owner, declared purpose, lifecycle state, version history,
-- and a tamper-evident audit trail of every lifecycle change.
--
-- Tenant scoping: tenant_id is present on every table and every store
-- query filters by it. It is sourced exclusively from the authenticated
-- API-key context -- never from request bodies, URLs, or query params.
--
-- Fail-closed creation: agents always start in 'draft'. There is no way
-- to create an agent in any other lifecycle state, and no auto-activation
-- (activated_at is only ever set by the explicit activate transition).

CREATE TABLE agents (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          TEXT NOT NULL,
    name               TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    owner_principal_id TEXT NOT NULL,
    business_purpose   TEXT NOT NULL DEFAULT '',
    risk_tier          TEXT NOT NULL CHECK (risk_tier IN ('low','medium','high','critical')),
    lifecycle_state    TEXT NOT NULL DEFAULT 'draft'
                       CHECK (lifecycle_state IN ('draft','pending_approval','active','suspended','revoked','retired')),
    environment        TEXT NOT NULL DEFAULT 'development'
                       CHECK (environment IN ('development','staging','production')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at       TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    UNIQUE (tenant_id, name)
);
CREATE INDEX idx_agents_tenant_state ON agents (tenant_id, lifecycle_state);
CREATE INDEX idx_agents_tenant_owner ON agents (tenant_id, owner_principal_id);

CREATE TABLE agent_versions (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id              UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    version               TEXT NOT NULL,
    model_provider        TEXT NOT NULL DEFAULT '',
    model_name            TEXT NOT NULL DEFAULT '',
    prompt_digest         TEXT NOT NULL DEFAULT '',
    tool_manifest_digest  TEXT NOT NULL DEFAULT '',
    policy_bundle_version TEXT NOT NULL DEFAULT '',
    artifact_digest       TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL DEFAULT 'draft'
                          CHECK (status IN ('draft','approved','active','superseded','revoked')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at           TIMESTAMPTZ,
    UNIQUE (agent_id, version)
);
CREATE INDEX idx_agent_versions_agent ON agent_versions (agent_id, created_at);

-- One row per lifecycle change. Append-only: the write-once rules below
-- (same pattern as audit_log) make the event stream tamper-evident at the
-- schema level; immutable_digest additionally hash-chains each event to
-- its predecessor so reordering, deletion, or field edits are detectable.
CREATE TABLE agent_lifecycle_events (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          TEXT NOT NULL,
    agent_id           UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    agent_version_id   UUID REFERENCES agent_versions(id) ON DELETE SET NULL,
    actor_principal_id TEXT NOT NULL,
    event_type         TEXT NOT NULL,
    previous_state     TEXT NOT NULL DEFAULT '',
    new_state          TEXT NOT NULL DEFAULT '',
    reason             TEXT NOT NULL DEFAULT '',
    immutable_digest   TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_agent_events_tenant_agent ON agent_lifecycle_events (tenant_id, agent_id, created_at);
CREATE INDEX idx_agent_events_tenant_version ON agent_lifecycle_events (tenant_id, agent_version_id);

-- Write-once rules: lifecycle events are immutable evidence.
CREATE RULE no_update_agent_events AS ON UPDATE TO agent_lifecycle_events DO INSTEAD NOTHING;
CREATE RULE no_delete_agent_events AS ON DELETE TO agent_lifecycle_events DO INSTEAD NOTHING;
