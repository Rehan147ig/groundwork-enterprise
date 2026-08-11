-- Phase 6 schema corrections rollback (only relevant if 020 was applied
-- on top of 019; pure additive columns are simply dropped, type/text
-- conversions restore the 019 shapes).

ALTER TABLE delegated_authority_grants
    DROP COLUMN permitted_actions,
    DROP COLUMN external_agent_id,
    DROP COLUMN issued_via;

ALTER TABLE agent_runs
    DROP COLUMN chain_verified;

ALTER TABLE trust_events RENAME TO agent_trust_events;
ALTER TABLE transfer_policies RENAME TO trust_transfer_policies;
ALTER TABLE external_budget_policies RENAME TO external_agent_budgets;
ALTER TABLE external_nonces RENAME TO external_token_nonces;

ALTER TABLE agent_trust_relationships
    ALTER COLUMN external_agent_id TYPE UUID USING NULL,
    ADD CONSTRAINT agent_trust_relationships_external_agent_id_fkey
        FOREIGN KEY (external_agent_id) REFERENCES external_agents(id) ON DELETE CASCADE;

ALTER TABLE external_token_nonces
    ALTER COLUMN external_agent_id TYPE UUID USING NULL,
    ADD CONSTRAINT external_token_nonces_external_agent_id_fkey
        FOREIGN KEY (external_agent_id) REFERENCES external_agents(id) ON DELETE CASCADE;

ALTER TABLE consent_records
    ALTER COLUMN external_agent_id TYPE UUID USING NULL,
    ADD CONSTRAINT consent_records_external_agent_id_fkey
        FOREIGN KEY (external_agent_id) REFERENCES external_agents(id) ON DELETE CASCADE;

ALTER TABLE external_agent_budgets
    ALTER COLUMN external_agent_id TYPE UUID USING NULL,
    ADD CONSTRAINT external_agent_budgets_external_agent_id_fkey
        FOREIGN KEY (external_agent_id) REFERENCES external_agents(id) ON DELETE CASCADE;

ALTER TABLE agent_trust_relationships
    ALTER COLUMN allowed_tools_actions TYPE TEXT[] USING string_to_array(allowed_tools_actions, ',');
ALTER TABLE external_agents
    ALTER COLUMN allowed_audiences TYPE TEXT[] USING string_to_array(allowed_audiences, ','),
    ALTER COLUMN allowed_tools_actions TYPE TEXT[] USING string_to_array(allowed_tools_actions, ',');

ALTER TABLE agent_trust_events DROP CONSTRAINT agent_trust_events_entity_type_check;
ALTER TABLE agent_trust_events
    ADD CONSTRAINT agent_trust_events_entity_type_check
    CHECK (entity_type IN (
        'trust.requested','trust.approved','trust.activated',
        'trust.suspended','trust.resumed','trust.revoked',
        'delegation.child_minted','chain.revoked','chain.suspended',
        'chain.resumed','chain.verified','external.agent',
        'consent.granted'));
