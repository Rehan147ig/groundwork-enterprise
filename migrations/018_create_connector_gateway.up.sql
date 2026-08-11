-- Production Connector Gateway (Phase 5).
--
-- Builds on the Phase 3 Evidence/Outbox (016) and Phase 4 Deployment
-- Registry (017). Adds the governed outbound-connector surface: no
-- registered tool call may reach an external system unless Groundwork
-- authorizes that exact agent action first.
--
-- Model:
--   - connectors:  one per governed tool (tool_id FK). Five lifecycle
--     states: draft (no traffic) / active / suspended (next action
--     denied, reversible) / revoked (irreversible) / retired (terminal).
--     Suspending or revoking a connector ALSO suspends/revokes its tool
--     so the shared evaluator's emergency-control checks deny the next
--     action; the gateway re-checks lifecycle + region immediately
--     before opening any outbound connection (fail closed).
--   - connector_versions: append-only immutable configuration versions.
--     A config change creates a new version + manifest digest; the
--     connector points at its current version.
--   - connector_actions: the manifest surface (method / resource type /
--     risk / approval / size limits / allowed agent versions / argument
--     allowlist). The agent can never supply URL, host, port, method,
--     or unlisted arguments — those come only from the manifest and
--     the connector configuration.
--   - connector_invocations: immutable outcome evidence (success /
--     failure / timeout / response_blocked) keyed 1:1 by decision_id;
--     surfaced on the evidence chain (kind 'connector_invocation').
--   - connector_lifecycle_events: hash-chained, write-once lifecycle
--     audit trail (mirrors agent_lifecycle_events; chain evidence
--     kind 'connector_lifecycle').
--
-- Tenancy: every table carries tenant_id; all queries filter by it.
-- Region: connectors are registered in the tenant's region and the
-- gateway rejects any invocation where the call region differs.

-- One connector per governed tool, one row per tenant/name.
CREATE TABLE connectors (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            TEXT NOT NULL,
    name                 TEXT NOT NULL,
    connector_type       TEXT NOT NULL CHECK (connector_type IN ('rest','mcp')),
    lifecycle            TEXT NOT NULL DEFAULT 'draft'
                         CHECK (lifecycle IN ('draft','active','suspended','revoked','retired')),
    base_url             TEXT NOT NULL,
    region               TEXT NOT NULL,
    tool_id              UUID NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
    timeout_ms           INTEGER NOT NULL DEFAULT 15000
                         CHECK (timeout_ms BETWEEN 100 AND 120000),
    retry_max            INTEGER NOT NULL DEFAULT 0
                         CHECK (retry_max BETWEEN 0 AND 5),
    retry_idempotent_only BOOLEAN NOT NULL DEFAULT TRUE,
    max_response_bytes   INTEGER NOT NULL DEFAULT 262144
                         CHECK (max_response_bytes BETWEEN 1024 AND 67108864),
    allowed_content_types JSONB NOT NULL DEFAULT '["application/json"]',
    redaction_fields     JSONB NOT NULL DEFAULT '["token","secret","authorization","password","api_key","cookie"]',
    secret_ref           TEXT NOT NULL DEFAULT '',
    tls_verify           BOOLEAN NOT NULL DEFAULT TRUE,
    client_cert_ref      TEXT NOT NULL DEFAULT '',
    owner_principal_id   TEXT NOT NULL,
    manifest_digest      TEXT NOT NULL DEFAULT '',
    current_version_id   UUID,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX idx_connectors_tenant_lifecycle ON connectors (tenant_id, lifecycle);
CREATE INDEX idx_connectors_tenant_tool ON connectors (tenant_id, tool_id);

-- Append-only configuration versions. Config changes are immutable:
-- a new version supersedes, never edits, the previous one.
CREATE TABLE connector_versions (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connector_id     UUID NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    tenant_id        TEXT NOT NULL,
    version_number   INTEGER NOT NULL,
    config           JSONB NOT NULL,
    manifest_digest  TEXT NOT NULL,
    created_by       TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (connector_id, version_number)
);
CREATE INDEX idx_connector_versions_tenant ON connector_versions (tenant_id, connector_id, version_number DESC);
CREATE RULE no_update_connector_versions AS ON UPDATE TO connector_versions DO INSTEAD NOTHING;
CREATE RULE no_delete_connector_versions AS ON DELETE TO connector_versions DO INSTEAD NOTHING;

-- Manifest actions. name matches the governed tool action name; the
-- tool action carries the risk/read-only/approval flags the evaluator
-- enforces; this row carries the transport-level controls.
CREATE TABLE connector_actions (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                 TEXT NOT NULL,
    connector_id              UUID NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    version_id                UUID NOT NULL REFERENCES connector_versions(id) ON DELETE CASCADE,
    name                      TEXT NOT NULL,
    transport_method          TEXT NOT NULL,   -- HTTP method (rest) or MCP tool name (mcp)
    path_template             TEXT NOT NULL DEFAULT '',  -- REST only: /path/{arg} — never raw agent URLs
    resource_type             TEXT NOT NULL DEFAULT '',
    risk                      TEXT NOT NULL CHECK (risk IN ('low','medium','high','critical')),
    read_only                 BOOLEAN NOT NULL DEFAULT TRUE,
    requires_approval         BOOLEAN NOT NULL DEFAULT FALSE,
    max_request_bytes         INTEGER NOT NULL DEFAULT 65536,
    max_response_bytes        INTEGER NOT NULL DEFAULT 262144,
    allowed_agent_version_ids JSONB NOT NULL DEFAULT '[]',  -- [] = any active version
    args                      JSONB NOT NULL DEFAULT '{}',  -- allowlisted argument names
    UNIQUE (connector_id, version_id, name)
);
CREATE INDEX idx_connector_actions_tenant ON connector_actions (tenant_id, connector_id, version_id);

-- Immutable invocation outcomes. One row per decision_id (or per
-- health-check probe). Write-once at the schema level.
CREATE TABLE connector_invocations (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         TEXT NOT NULL,
    connector_id      UUID NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    tool_id           UUID REFERENCES tools(id) ON DELETE SET NULL,
    tool_action_id    UUID REFERENCES tool_actions(id) ON DELETE SET NULL,
    run_id            UUID REFERENCES agent_runs(id) ON DELETE SET NULL,
    decision_id       TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('agent_action','health_check')),
    outcome           TEXT NOT NULL CHECK (outcome IN ('success','failure','timeout','response_blocked')),
    status_code       INTEGER NOT NULL DEFAULT 0,
    error_code        TEXT NOT NULL DEFAULT '',
    duration_ms       INTEGER NOT NULL DEFAULT 0,
    response_bytes    INTEGER NOT NULL DEFAULT 0,
    region            TEXT NOT NULL,
    trace_id          TEXT NOT NULL DEFAULT '',
    occurred_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, decision_id)
);
CREATE INDEX idx_connector_invocations_tenant ON connector_invocations (tenant_id, occurred_at DESC);
CREATE INDEX idx_connector_invocations_connector ON connector_invocations (tenant_id, connector_id, occurred_at DESC);
CREATE RULE no_update_connector_invocations AS ON UPDATE TO connector_invocations DO INSTEAD NOTHING;
CREATE RULE no_delete_connector_invocations AS ON DELETE TO connector_invocations DO INSTEAD NOTHING;

-- Hash-chained lifecycle audit trail (write-once; digest chains to the
-- previous event so tampering breaks every subsequent digest).
CREATE TABLE connector_lifecycle_events (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        TEXT NOT NULL,
    connector_id     UUID NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    action_type      TEXT NOT NULL
                     CHECK (action_type IN ('create','activate','suspend','revoke','retire','config_update')),
    from_state       TEXT NOT NULL,
    to_state         TEXT NOT NULL,
    actor_principal_id TEXT NOT NULL,
    reason           TEXT NOT NULL DEFAULT '',
    immutable_digest TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_connector_lifecycle_tenant ON connector_lifecycle_events (tenant_id, connector_id, created_at);
CREATE RULE no_update_connector_lifecycle_events AS ON UPDATE TO connector_lifecycle_events DO INSTEAD NOTHING;
CREATE RULE no_delete_connector_lifecycle_events AS ON DELETE TO connector_lifecycle_events DO INSTEAD NOTHING;
