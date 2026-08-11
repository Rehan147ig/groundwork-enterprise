-- Delegated Authority & Governed Agent Execution (Phase 2).
--
-- Builds on the Phase 1 Agent Registry (014): an agent receives a
-- short-lived, tightly bound delegation to run on behalf of a verified
-- human principal, and every tool/retrieval action it takes is gated by
-- a single evaluator whose decision is recorded as tamper-evident
-- evidence.
--
-- Tenancy: every table carries tenant_id and every query filters by it.
-- It is sourced exclusively from the authenticated API-key context —
-- never from bodies, URLs, or headers.
--
-- Invariant (enforced by the governance service, not just the schema):
--   a tool or retrieval action is allowed only when
--     active agent version
--   + verified delegated principal (subject_principal_id)
--   + valid live delegation (signed token + unrevoked, unexpired grant)
--   + registered allowed tool/action
--   + SpiceDB resource permission (checked on the verified subject)
--   + valid region/purpose constraints
--   + required one-time human approval
--   Everything else fails closed and produces evidence.

-- Registered tools: the governed capabilities an agent may invoke.
CREATE TABLE tools (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           TEXT NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    transport           TEXT NOT NULL DEFAULT 'internal'
                        CHECK (transport IN ('http','mcp','builtin','internal')),
    endpoint_or_server  TEXT NOT NULL DEFAULT '',
    owner_principal_id  TEXT NOT NULL,
    region              TEXT NOT NULL,
    manifest_digest     TEXT NOT NULL DEFAULT '',
    lifecycle           TEXT NOT NULL DEFAULT 'draft'
                        CHECK (lifecycle IN ('draft','active','suspended','revoked')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX idx_tools_tenant_lifecycle ON tools (tenant_id, lifecycle);

-- Actions a tool exposes. resource_type names what the action operates
-- on (document, repository, channel, ...); risk_level drives whether
-- human approval is required for the action regardless of the grant.
CREATE TABLE tool_actions (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                TEXT NOT NULL,
    tool_id                  UUID NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
    action                   TEXT NOT NULL,
    resource_type            TEXT NOT NULL,
    risk_level               TEXT NOT NULL DEFAULT 'low'
                             CHECK (risk_level IN ('low','medium','high','critical')),
    read_only                BOOLEAN NOT NULL DEFAULT TRUE,
    requires_human_approval  BOOLEAN NOT NULL DEFAULT FALSE,
    status                   TEXT NOT NULL DEFAULT 'active'
                             CHECK (status IN ('active','retired')),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tool_id, action)
);
CREATE INDEX idx_tool_actions_tool ON tool_actions (tool_id);
CREATE INDEX idx_tool_actions_tenant ON tool_actions (tenant_id);

-- Grants: which agent version may invoke which tool action, over which
-- resource scope, within which region, up to how many calls per run,
-- and whether human approval is required for this grant.
CREATE TABLE agent_tool_grants (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            TEXT NOT NULL,
    agent_id             UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    version_id           UUID NOT NULL REFERENCES agent_versions(id) ON DELETE CASCADE,
    tool_id              UUID NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
    action_id            UUID NOT NULL REFERENCES tool_actions(id) ON DELETE CASCADE,
    resource_scope       TEXT NOT NULL DEFAULT '*',
    region_constraint    TEXT NOT NULL DEFAULT '*',
    call_limit_per_run   INTEGER NOT NULL DEFAULT 0,
    requires_approval    BOOLEAN NOT NULL DEFAULT FALSE,
    granted_by           TEXT NOT NULL,
    granted_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at           TIMESTAMPTZ,
    UNIQUE (agent_id, version_id, tool_id, action_id, resource_scope)
);
CREATE INDEX idx_agent_tool_grants_agent ON agent_tool_grants (agent_id, version_id);
CREATE INDEX idx_agent_tool_grants_tool ON agent_tool_grants (tool_id, action_id);
CREATE INDEX idx_agent_tool_grants_tenant ON agent_tool_grants (tenant_id);

-- One delegation: a short-lived authority minted for an active agent on
-- behalf of a verified subject principal. The raw token is NEVER stored
-- here — only its jti plus safe metadata. token_jti is consumed exactly
-- once (used_at/run_id are set atomically by the first run creation);
-- actions inside that run remain valid until expiry/revocation.
-- immutable_digest covers all immutable binding fields so a reorder or
-- edit of the bindings is detectable. used_at/run_id/revoked_at are
-- lifecycle fields and are not covered by the digest.
CREATE TABLE delegated_authority_grants (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                 TEXT NOT NULL,
    agent_id                  UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    agent_version_id          UUID NOT NULL REFERENCES agent_versions(id) ON DELETE CASCADE,
    token_jti                 TEXT NOT NULL UNIQUE,
    delegator_principal_id    TEXT NOT NULL,
    subject_principal_id      TEXT NOT NULL,
    purpose                   TEXT NOT NULL,
    region                    TEXT NOT NULL,
    permitted_actions_digest  TEXT NOT NULL,
    issued_at                 TIMESTAMPTZ NOT NULL,
    expires_at                TIMESTAMPTZ NOT NULL,
    used_at                   TIMESTAMPTZ,
    run_id                    UUID,
    revoked_at                TIMESTAMPTZ,
    idempotency_key           TEXT,
    immutable_digest          TEXT NOT NULL,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (expires_at > issued_at)
);
CREATE INDEX idx_delegated_grants_agent ON delegated_authority_grants (agent_id, expires_at);
CREATE INDEX idx_delegated_grants_tenant ON delegated_authority_grants (tenant_id, issued_at);
CREATE INDEX idx_delegated_grants_jti_used ON delegated_authority_grants (token_jti, used_at);
CREATE UNIQUE INDEX idx_delegated_grants_idem
    ON delegated_authority_grants (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- One governed run. run_id is ALWAYS server-generated (the token binds a
-- grant, never a run). status starts pending and moves to running at
-- first action evaluation; terminal states mark the run's outcome.
CREATE TABLE agent_runs (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            TEXT NOT NULL,
    agent_id             UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    delegation_grant_id  UUID NOT NULL REFERENCES delegated_authority_grants(id) ON DELETE CASCADE,
    idempotency_key      TEXT,
    user_id              TEXT NOT NULL,
    purpose              TEXT NOT NULL DEFAULT '',
    region               TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending','running','completed','denied','failed','revoked')),
    trace_id             TEXT NOT NULL DEFAULT '',
    started_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at         TIMESTAMPTZ,
    error_code           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_agent_runs_tenant_status ON agent_runs (tenant_id, status, started_at DESC);
CREATE INDEX idx_agent_runs_grant ON agent_runs (delegation_grant_id);
CREATE UNIQUE INDEX idx_agent_runs_idem
    ON agent_runs (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Every evaluator outcome, including denials and fail-closed results.
-- Append-only: the write-once rules make this tamper-evident at the
-- schema level; immutable_digest hash-chains each decision to its
-- predecessor so reordering, deletion, or field edits are detectable.
CREATE TABLE agent_action_decisions (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              TEXT NOT NULL,
    agent_id               UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    run_id                 UUID NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    delegation_grant_id    UUID NOT NULL REFERENCES delegated_authority_grants(id) ON DELETE CASCADE,
    tool_id                UUID REFERENCES tools(id) ON DELETE SET NULL,
    action_id              UUID REFERENCES tool_actions(id) ON DELETE SET NULL,
    resource_ref           TEXT NOT NULL DEFAULT '',
    decision               TEXT NOT NULL
                           CHECK (decision IN ('allowed','denied','approval_required','fail_closed')),
    reason                 TEXT NOT NULL DEFAULT '',
    policy_version         TEXT NOT NULL DEFAULT '',
    immutable_digest       TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_decisions_tenant_run ON agent_action_decisions (tenant_id, run_id, created_at);
CREATE INDEX idx_decisions_tenant_agent ON agent_action_decisions (tenant_id, agent_id, created_at);

-- One-time human approval evidence. An approval response alone is not
-- sufficient evidence — this row records WHO approved, WHAT (run, tool
-- action, resource reference), until WHEN, and whether it was consumed
-- (consumed_at is set atomically by the first evaluation that uses it).
CREATE TABLE agent_action_approvals (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                TEXT NOT NULL,
    run_id                   UUID NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    tool_id                  UUID NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
    action_id                UUID NOT NULL REFERENCES tool_actions(id) ON DELETE CASCADE,
    resource_ref             TEXT NOT NULL,
    approving_principal_id   TEXT NOT NULL,
    decision                 TEXT NOT NULL
                             CHECK (decision IN ('approved','denied')),
    expires_at               TIMESTAMPTZ NOT NULL,
    consumed_at              TIMESTAMPTZ,
    idempotency_key          TEXT,
    immutable_digest         TEXT NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at)
);
CREATE INDEX idx_approvals_tenant_run ON agent_action_approvals (tenant_id, run_id, tool_id, action_id, resource_ref);
CREATE UNIQUE INDEX idx_approvals_idem
    ON agent_action_approvals (tenant_id, run_id, tool_id, action_id, resource_ref, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Write-once rules: decisions are immutable evidence; approvals are
-- immutable except for the single one-time consumption transition
-- (consumed_at NULL -> set, everything else byte-identical). The
-- conditional rule below blocks every other UPDATE while permitting
-- exactly that transition, so the service's atomic consume
-- (UPDATE ... SET consumed_at = now() WHERE consumed_at IS NULL) is the
-- only way an approval can change after it is recorded.
CREATE RULE no_update_action_decisions AS ON UPDATE TO agent_action_decisions DO INSTEAD NOTHING;
CREATE RULE no_delete_action_decisions AS ON DELETE TO agent_action_decisions DO INSTEAD NOTHING;
CREATE RULE no_update_action_approvals AS ON UPDATE TO agent_action_approvals
    WHERE OLD.consumed_at IS NOT NULL
       OR NEW.consumed_at IS NULL
       OR OLD.decision <> NEW.decision
       OR OLD.tenant_id <> NEW.tenant_id
       OR OLD.run_id <> NEW.run_id
       OR OLD.tool_id <> NEW.tool_id
       OR OLD.action_id <> NEW.action_id
       OR OLD.resource_ref <> NEW.resource_ref
       OR OLD.approving_principal_id <> NEW.approving_principal_id
       OR OLD.expires_at <> NEW.expires_at
       OR OLD.immutable_digest <> NEW.immutable_digest
    DO INSTEAD NOTHING;
CREATE RULE no_delete_action_approvals AS ON DELETE TO agent_action_approvals DO INSTEAD NOTHING;
