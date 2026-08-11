-- Multi-Agent Delegation & External-Agent Trust (Phase 6).
--
-- Central rule: a child agent may never receive more authority than its
-- parent agent possesses. Delegation chains (human or service principal
-- -> parent agent -> child agent -> tool/action/resource) are bounded,
-- attenuated, auditable, and revocable end to end.
--
-- Invariants (enforced by the governance service, not just the schema):
--   trust is never implicit from shared tenant membership
--   + cross-tenant delegation is denied by default
--   + cross-region delegation requires an explicit transfer policy
--   + a revoked parent immediately invalidates every descendant
--   + a child cannot delegate unless its authority permits it
--   + external agents are untrusted by default (no data/tool access)
--   + external identities are validated against issuer/audience/JWKS/jti
--   + customer consent is required where configured
--   + every trust/chain/external transition records hash-chained evidence
--   + no raw token is ever stored — only jti and digests

-- ---------------------------------------------------------------------
-- Chain bindings on delegated authority grants (root grants keep zeros)
-- ---------------------------------------------------------------------
ALTER TABLE delegated_authority_grants
    ADD COLUMN parent_grant_id        UUID REFERENCES delegated_authority_grants(id),
    ADD COLUMN root_grant_id          UUID,
    ADD COLUMN delegator_agent_id     UUID REFERENCES agents(id) ON DELETE SET NULL,
    ADD COLUMN delegatee_agent_id     UUID REFERENCES agents(id) ON DELETE SET NULL,
    ADD COLUMN delegation_depth       INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN authority_scope_digest TEXT NOT NULL DEFAULT '',
    ADD COLUMN parent_scope_digest    TEXT NOT NULL DEFAULT '',
    ADD COLUMN attenuation_digest     TEXT NOT NULL DEFAULT '',
    ADD COLUMN trust_relationship_id  UUID,
    ADD COLUMN revoked_source         TEXT NOT NULL DEFAULT '',
    ADD COLUMN is_agent_delegation    BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT chk_delegation_depth CHECK (delegation_depth >= 0);
CREATE INDEX idx_delegated_grants_parent ON delegated_authority_grants (tenant_id, parent_grant_id);
CREATE INDEX idx_delegated_grants_root ON delegated_authority_grants (tenant_id, root_grant_id);

-- Chain + external binding on runs (empty for root runs).
ALTER TABLE agent_runs
    ADD COLUMN root_grant_id          UUID,
    ADD COLUMN parent_grant_id        UUID,
    ADD COLUMN delegation_depth       INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN external_agent_id      TEXT NOT NULL DEFAULT '',
    ADD COLUMN organization_id        TEXT NOT NULL DEFAULT '',
    ADD COLUMN customer_principal_id  TEXT NOT NULL DEFAULT '',
    ADD COLUMN consent_id             TEXT NOT NULL DEFAULT '',
    ADD CONSTRAINT chk_run_delegation_depth CHECK (delegation_depth >= 0);

-- Chain context on decisions so evidence timelines carry it even after
-- the grant row changes (append-only; the digest still covers the
-- original binding fields).
ALTER TABLE agent_action_decisions
    ADD COLUMN delegation_depth INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN chain_verified   TEXT NOT NULL DEFAULT ''; -- verified | broken | unchecked

-- ---------------------------------------------------------------------
-- External agents (1:1 with an agent-registry identity in `agents`)
-- Created BEFORE agent_trust_relationships: that table's FK references
-- external_agents, so declaration order matters for fresh applies.
-- ---------------------------------------------------------------------
CREATE TABLE external_agents (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_agent_id     TEXT NOT NULL,
    agent_id              UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    organization_id       TEXT NOT NULL,
    tenant_id             TEXT NOT NULL,
    owner_principal_id    TEXT NOT NULL,
    verified_issuer       TEXT NOT NULL,
    allowed_audiences     TEXT[] NOT NULL DEFAULT '{}',
    auth_method           TEXT NOT NULL
                          CHECK (auth_method IN ('oidc','jwt_jwks','mtls','internal_demo')),
    trust_tier            TEXT NOT NULL DEFAULT 'untrusted'
                          CHECK (trust_tier IN ('untrusted','verified','partner','customer')),
    region                TEXT NOT NULL,
    allowed_tools_actions TEXT[] NOT NULL DEFAULT '{}',
    public_key_jwks_ref   TEXT NOT NULL DEFAULT '',
    manifest_digest       TEXT NOT NULL DEFAULT '',
    security_contact      TEXT NOT NULL DEFAULT '',
    lifecycle_state       TEXT NOT NULL DEFAULT 'pending'
                          CHECK (lifecycle_state IN ('pending','active','suspended','revoked','expired')),
    expires_at            TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_external_agents_tenant_id
    ON external_agents (tenant_id, external_agent_id);
CREATE UNIQUE INDEX idx_external_agents_agent
    ON external_agents (agent_id);
CREATE INDEX idx_external_agents_issuer ON external_agents (tenant_id, verified_issuer);

-- ---------------------------------------------------------------------
-- Agent trust relationships
-- ---------------------------------------------------------------------
CREATE TABLE agent_trust_relationships (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              TEXT NOT NULL,
    parent_agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    child_agent_id         UUID REFERENCES agents(id) ON DELETE CASCADE,
    external_agent_id      UUID REFERENCES external_agents(id) ON DELETE CASCADE,
    trust_domain           TEXT NOT NULL,
    owner_principal_id     TEXT NOT NULL,
    purpose                TEXT NOT NULL,
    max_delegation_depth   INTEGER NOT NULL DEFAULT 1
                           CHECK (max_delegation_depth BETWEEN 1 AND 10),
    allowed_tools_actions  TEXT[] NOT NULL DEFAULT '{}',
    region                 TEXT NOT NULL,
    expires_at             TIMESTAMPTZ NOT NULL,
    status                 TEXT NOT NULL DEFAULT 'requested'
                           CHECK (status IN ('requested','approved','active','suspended','revoked','expired')),
    approval_required      BOOLEAN NOT NULL DEFAULT FALSE,
    reason                 TEXT NOT NULL DEFAULT '',
    immutable_digest       TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (child_agent_id IS NOT NULL OR external_agent_id IS NOT NULL),
    CHECK (NOT (child_agent_id IS NOT NULL AND external_agent_id IS NOT NULL))
);
CREATE UNIQUE INDEX idx_trust_pair
    ON agent_trust_relationships (tenant_id, parent_agent_id, child_agent_id)
    WHERE child_agent_id IS NOT NULL;
CREATE UNIQUE INDEX idx_trust_external
    ON agent_trust_relationships (tenant_id, parent_agent_id, external_agent_id)
    WHERE external_agent_id IS NOT NULL;
CREATE INDEX idx_trust_tenant ON agent_trust_relationships (tenant_id, status);

-- One-time use of an external identity jti (replay protection).
CREATE TABLE external_token_nonces (
    tenant_id         TEXT NOT NULL,
    external_agent_id UUID NOT NULL REFERENCES external_agents(id) ON DELETE CASCADE,
    jti               TEXT NOT NULL,
    used_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, external_agent_id, jti)
);

-- ---------------------------------------------------------------------
-- Explicit cross-region transfer policies
-- ---------------------------------------------------------------------
CREATE TABLE trust_transfer_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    source_region   TEXT NOT NULL,
    target_region   TEXT NOT NULL,
    purpose_pattern TEXT NOT NULL DEFAULT '*',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, source_region, target_region, purpose_pattern)
);

-- ---------------------------------------------------------------------
-- Customer consent records
-- ---------------------------------------------------------------------
CREATE TABLE consent_records (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             TEXT NOT NULL,
    organization_id       TEXT NOT NULL,
    external_agent_id     UUID NOT NULL REFERENCES external_agents(id) ON DELETE CASCADE,
    customer_principal_id TEXT NOT NULL,
    purpose               TEXT NOT NULL,
    resource_ref_pattern  TEXT NOT NULL DEFAULT '*',
    status                TEXT NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active','revoked')),
    granted_by            TEXT NOT NULL,
    granted_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at            TIMESTAMPTZ NOT NULL,
    immutable_digest      TEXT NOT NULL
);
CREATE INDEX idx_consent_tenant_org ON consent_records (tenant_id, organization_id);
CREATE INDEX idx_consent_customer ON consent_records (tenant_id, customer_principal_id);

-- ---------------------------------------------------------------------
-- External-agent budgets (customer > organization > external_agent)
-- ---------------------------------------------------------------------
CREATE TABLE external_agent_budgets (
    id                             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                      TEXT NOT NULL,
    scope_type                     TEXT NOT NULL
                                   CHECK (scope_type IN ('external_agent','external_organization','customer')),
    external_agent_id              UUID REFERENCES external_agents(id) ON DELETE CASCADE,
    organization_id                TEXT NOT NULL DEFAULT '',
    customer_principal_id          TEXT NOT NULL DEFAULT '',
    max_total_actions              INTEGER NOT NULL DEFAULT 0,
    max_actions_per_run            INTEGER NOT NULL DEFAULT 0,
    max_denied_per_run             INTEGER NOT NULL DEFAULT 0,
    max_approval_required_per_run  INTEGER NOT NULL DEFAULT 0,
    max_tool_calls_per_action_per_run INTEGER NOT NULL DEFAULT 0,
    actions_count                  INTEGER NOT NULL DEFAULT 0,
    denied_count                   INTEGER NOT NULL DEFAULT 0,
    approval_required_count        INTEGER NOT NULL DEFAULT 0,
    tool_calls_count               INTEGER NOT NULL DEFAULT 0,
    created_by                     TEXT NOT NULL,
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, scope_type, external_agent_id, organization_id, customer_principal_id)
);

-- ---------------------------------------------------------------------
-- Hash-chained trust / chain / external evidence
-- ---------------------------------------------------------------------
CREATE TABLE agent_trust_events (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            TEXT NOT NULL,
    event_type           TEXT NOT NULL
                         CHECK (event_type IN (
                            'trust.requested','trust.approved','trust.activated',
                            'trust.suspended','trust.resumed','trust.revoked',
                            'delegation.child_minted','chain.revoked','chain.suspended',
                            'chain.resumed','chain.verified','external.agent',
                            'consent.granted')),
    entity_type          TEXT NOT NULL
                         CHECK (entity_type IN ('relationship','grant','external_agent','consent')),
    entity_id            TEXT NOT NULL,
    actor_principal_id   TEXT NOT NULL,
    previous_state       TEXT NOT NULL DEFAULT '',
    new_state            TEXT NOT NULL DEFAULT '',
    reason               TEXT NOT NULL DEFAULT '',
    grant_id             TEXT NOT NULL DEFAULT '',
    parent_grant_id      TEXT NOT NULL DEFAULT '',
    root_grant_id        TEXT NOT NULL DEFAULT '',
    delegation_depth     INTEGER NOT NULL DEFAULT 0,
    subject_principal_id TEXT NOT NULL DEFAULT '',
    trust_domain         TEXT NOT NULL DEFAULT '',
    organization_id      TEXT NOT NULL DEFAULT '',
    scope_digest         TEXT NOT NULL DEFAULT '',
    attenuation_digest   TEXT NOT NULL DEFAULT '',
    revocation_source    TEXT NOT NULL DEFAULT '',
    immutable_digest     TEXT NOT NULL,
    previous_event_id    TEXT NOT NULL DEFAULT '',
    occurred_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_trust_events_tenant ON agent_trust_events (tenant_id, occurred_at DESC);
CREATE INDEX idx_trust_events_entity ON agent_trust_events (tenant_id, entity_type, entity_id);

-- Append-only: trust events are immutable evidence.
CREATE RULE no_update_agent_trust_events AS ON UPDATE TO agent_trust_events DO INSTEAD NOTHING;
CREATE RULE no_delete_agent_trust_events AS ON DELETE TO agent_trust_events DO INSTEAD NOTHING;
