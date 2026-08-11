-- Phase 6 schema corrections (applied after 019).
--
-- The governance store binds external identities by their TEXT
-- external_agent_id (the value an identity token's `sub` carries), not
-- by the row UUID. 019 declared several FK UUID columns; this migration
-- converts them to TEXT so onboarding/verification round-trips exactly,
-- and aligns table/column names with the store implementation.

-- delegated_authority_grants: persist the permitted-actions list (for
-- semantic attenuation verification of child scopes) plus the external
-- binding and mint path.
ALTER TABLE delegated_authority_grants
    ADD COLUMN permitted_actions  TEXT NOT NULL DEFAULT '',
    ADD COLUMN external_agent_id  TEXT NOT NULL DEFAULT '',
    ADD COLUMN issued_via         TEXT NOT NULL DEFAULT ''; -- root | agent | external

-- agent_runs: chain verification outcome stamped at run creation.
ALTER TABLE agent_runs
    ADD COLUMN chain_verified TEXT NOT NULL DEFAULT ''; -- verified | broken | unchecked

-- Trust relationships bind the external agent by its TEXT identifier.
ALTER TABLE agent_trust_relationships
    DROP CONSTRAINT IF EXISTS agent_trust_relationships_external_agent_id_fkey,
    ALTER COLUMN external_agent_id DROP NOT NULL,
    ALTER COLUMN external_agent_id TYPE TEXT USING external_agent_id::text;

-- External identity nonces: agent reference by TEXT identifier.
ALTER TABLE external_token_nonces
    DROP CONSTRAINT IF EXISTS external_token_nonces_external_agent_id_fkey,
    ALTER COLUMN external_agent_id TYPE TEXT USING external_agent_id::text;

-- Consent records and external budgets: agent reference by TEXT identifier.
ALTER TABLE consent_records
    DROP CONSTRAINT IF EXISTS consent_records_external_agent_id_fkey,
    ALTER COLUMN external_agent_id TYPE TEXT USING external_agent_id::text;

ALTER TABLE external_agent_budgets
    DROP CONSTRAINT IF EXISTS external_agent_budgets_external_agent_id_fkey,
    ALTER COLUMN external_agent_id TYPE TEXT USING external_agent_id::text;

-- Array columns are stored as comma-joined TEXT by the store (digest
-- canonicalization keeps them deterministic). The cast is a no-op when
-- the column is already TEXT, so re-applying the migration is safe.
ALTER TABLE agent_trust_relationships
    ALTER COLUMN allowed_tools_actions TYPE TEXT USING allowed_tools_actions::text;
ALTER TABLE external_agents
    ALTER COLUMN allowed_audiences TYPE TEXT USING allowed_audiences::text,
    ALTER COLUMN allowed_tools_actions TYPE TEXT USING allowed_tools_actions::text;

-- Trust events also cover transfer-policy and external-budget activity.
ALTER TABLE agent_trust_events DROP CONSTRAINT IF EXISTS agent_trust_events_entity_type_check;
ALTER TABLE agent_trust_events
    ADD CONSTRAINT agent_trust_events_entity_type_check
    CHECK (entity_type IN (
        'relationship','grant','external_agent','consent',
        'transfer_policy','external_budget'));

-- The transfer-policy table name matches the store.
ALTER TABLE trust_transfer_policies RENAME TO transfer_policies;
ALTER TABLE external_agent_budgets RENAME TO external_budget_policies;
ALTER TABLE agent_trust_events RENAME TO trust_events;
ALTER TABLE external_token_nonces RENAME TO external_nonces;
