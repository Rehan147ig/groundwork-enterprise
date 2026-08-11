-- Monitoring, Emergency Revocation & Evidence Operations (Phase 3).
--
-- Builds on the Phase 1 Agent Registry (014) and Phase 2 Delegated
-- Authority (015). Adds: emergency controls with immutable evidence,
-- deterministic per-run action budgets with transaction-safe counters,
-- an evidence checkpoint ledger, and a transactional event outbox for
-- signed webhook delivery to a SIEM/console (no external queue).
--
-- Tenancy: every table carries tenant_id and every query filters by it,
-- sourced exclusively from the authenticated API-key context.
--
-- Security invariants (enforced by the governance service, not just the
-- schema):
--   - emergency controls are checked BEFORE every governed action and
--     before delegation minting / run creation; a kill switch denies
--     the very next action and terminates active runs;
--   - kill switch is reversible (resume) for agents, versions, and
--     tools; revocation (delegations) and termination (runs) are
--     irreversible;
--   - every control mutation records a hash-chained evidence action
--     (actor, reason, scope, previous state, new state, timestamp);
--   - budget counters are upserted atomically (INSERT ... ON CONFLICT
--     DO UPDATE count = count + 1 RETURNING count) inside the same
--     transaction as the decision evidence, so concurrent actions can
--     never exceed a budget;
--   - outbox payloads carry safe fields only — never tokens, secrets,
--     raw user assertions, or document text.

-- One control state per entity (agent, agent_version, tool,
-- agent_tool_grant, delegation_grant, run). Absence of a row means
-- 'active'. kill_switched and suspended are reversible via resume;
-- revoked is terminal.
CREATE TABLE emergency_controls (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           TEXT NOT NULL,
    entity_type         TEXT NOT NULL
                        CHECK (entity_type IN ('agent','agent_version','tool','agent_tool_grant','delegation_grant','run')),
    entity_id           TEXT NOT NULL,
    control_state       TEXT NOT NULL DEFAULT 'active'
                        CHECK (control_state IN ('active','suspended','revoked','kill_switched')),
    reason              TEXT NOT NULL DEFAULT '',
    scope               TEXT NOT NULL DEFAULT '',
    actor_principal_id  TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, entity_type, entity_id)
);
CREATE INDEX idx_emergency_controls_tenant_state ON emergency_controls (tenant_id, control_state, entity_type);

-- Immutable evidence of every control action. Hash-chained per tenant
-- (each row digests its predecessor), write-once at the schema level.
CREATE TABLE emergency_control_actions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           TEXT NOT NULL,
    entity_type         TEXT NOT NULL,
    entity_id           TEXT NOT NULL,
    action_type         TEXT NOT NULL
                        CHECK (action_type IN ('kill_switch','resume','revoke','terminate')),
    actor_principal_id  TEXT NOT NULL,
    reason              TEXT NOT NULL DEFAULT '',
    scope               TEXT NOT NULL DEFAULT '',
    previous_state      TEXT NOT NULL,
    new_state           TEXT NOT NULL,
    immutable_digest    TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_emergency_actions_tenant_entity ON emergency_control_actions (tenant_id, entity_type, entity_id, created_at);
CREATE INDEX idx_emergency_actions_tenant_time ON emergency_control_actions (tenant_id, created_at);

-- Write-once: control actions are immutable evidence.
CREATE RULE no_update_emergency_control_actions AS ON UPDATE TO emergency_control_actions DO INSTEAD NOTHING;
CREATE RULE no_delete_emergency_control_actions AS ON DELETE TO emergency_control_actions DO INSTEAD NOTHING;

-- Budget policies at three scopes: tenant default, agent version, and
-- agent-tool grant. The narrowest applicable policy wins (grant >
-- agent_version > tenant). A 0 value means "no limit from this scope".
-- Phase 2 grant.call_limit_per_run remains authoritative and is honored
-- in addition to (min of) these budgets.
CREATE TABLE agent_action_budgets (
    id                              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                       TEXT NOT NULL,
    scope_type                      TEXT NOT NULL
                                    CHECK (scope_type IN ('tenant','agent_version','grant')),
    agent_version_id                UUID REFERENCES agent_versions(id) ON DELETE CASCADE,
    grant_id                        UUID REFERENCES agent_tool_grants(id) ON DELETE CASCADE,
    max_actions_per_run             INTEGER NOT NULL DEFAULT 0,
    max_denied_per_run              INTEGER NOT NULL DEFAULT 0,
    max_approval_required_per_run   INTEGER NOT NULL DEFAULT 0,
    max_tool_calls_per_action_per_run INTEGER NOT NULL DEFAULT 0,
    max_run_duration_seconds        INTEGER NOT NULL DEFAULT 0,
    max_citations_per_query         INTEGER NOT NULL DEFAULT 0,
    created_by                      TEXT NOT NULL,
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_budgets_tenant_scope
    ON agent_action_budgets (tenant_id, scope_type)
    WHERE scope_type = 'tenant';
CREATE UNIQUE INDEX idx_budgets_version_scope
    ON agent_action_budgets (tenant_id, scope_type, agent_version_id)
    WHERE scope_type = 'agent_version';
CREATE UNIQUE INDEX idx_budgets_grant_scope
    ON agent_action_budgets (tenant_id, scope_type, grant_id)
    WHERE scope_type = 'grant';
CREATE INDEX idx_budgets_tenant ON agent_action_budgets (tenant_id);

-- Transaction-safe budget counters. Every governed action increments
-- the applicable counters inside the SAME transaction that appends the
-- decision evidence; the pre-check reads the committed counter, so
-- concurrent actions cannot exceed a budget. action_id is NULL for
-- run-level counters (actions/denied/approval_required/citations) and
-- set for the per-tool-action counter (tool_calls).
CREATE TABLE agent_run_budget_usage (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      TEXT NOT NULL,
    run_id         UUID NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    action_id      UUID REFERENCES tool_actions(id) ON DELETE CASCADE,
    counter_type   TEXT NOT NULL
                   CHECK (counter_type IN ('actions','denied','approval_required','tool_calls','citations')),
    count          INTEGER NOT NULL DEFAULT 0,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_budget_usage_run_type
    ON agent_run_budget_usage (run_id, counter_type)
    WHERE action_id IS NULL;
CREATE UNIQUE INDEX idx_budget_usage_run_action_type
    ON agent_run_budget_usage (run_id, action_id, counter_type)
    WHERE action_id IS NOT NULL;
CREATE INDEX idx_budget_usage_tenant ON agent_run_budget_usage (tenant_id, run_id);

-- Chain checkpoints: a verified digest of the evidence stream up to a
-- point in time, so long histories can be verified incrementally.
CREATE TABLE evidence_checkpoints (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          TEXT NOT NULL,
    last_event_id      TEXT NOT NULL,
    last_verified_at   TIMESTAMPTZ NOT NULL,
    events_checked     INTEGER NOT NULL,
    chain_digest       TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_evidence_checkpoints_tenant ON evidence_checkpoints (tenant_id, last_verified_at DESC);

-- Transactional event outbox for security-relevant events. Events are
-- written in the same transaction as their business + evidence records;
-- a worker delivers them to a configured webhook endpoint (signed,
-- idempotent by event_id, exponential backoff, dead-letter state). The
-- payload is a JSONB blob of safe fields ONLY.
CREATE TABLE outbox_events (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        TEXT NOT NULL,
    event_id         TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    schema_version   INTEGER NOT NULL DEFAULT 1,
    occurred_at      TIMESTAMPTZ NOT NULL,
    payload          JSONB NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','delivering','delivered','dead_letter')),
    attempts         INTEGER NOT NULL DEFAULT 0,
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error       TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at     TIMESTAMPTZ,
    UNIQUE (tenant_id, event_id)
);
CREATE INDEX idx_outbox_delivery ON outbox_events (status, next_attempt_at);
CREATE INDEX idx_outbox_tenant_time ON outbox_events (tenant_id, occurred_at DESC);

-- Auditable reason codes for policy denials (budget exhaustion,
-- emergency controls, run termination) so evidence and SIEM queries can
-- filter by machine-readable cause. Human-readable detail stays in
-- agent_action_decisions.reason.
ALTER TABLE agent_action_decisions ADD COLUMN reason_code TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_decisions_tenant_reason ON agent_action_decisions (tenant_id, reason_code);
