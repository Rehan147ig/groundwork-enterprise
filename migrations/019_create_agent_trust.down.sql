-- Multi-Agent Delegation & External-Agent Trust (Phase 6) — rollback.

DROP RULE no_delete_agent_trust_events ON agent_trust_events;
DROP RULE no_update_agent_trust_events ON agent_trust_events;
DROP TABLE agent_trust_events;
DROP TABLE external_agent_budgets;
DROP TABLE consent_records;
DROP TABLE trust_transfer_policies;
DROP TABLE external_token_nonces;
DROP TABLE external_agents;
DROP TABLE agent_trust_relationships;

ALTER TABLE agent_action_decisions
    DROP COLUMN delegation_depth,
    DROP COLUMN chain_verified;

ALTER TABLE agent_runs
    DROP COLUMN consent_id,
    DROP COLUMN customer_principal_id,
    DROP COLUMN organization_id,
    DROP COLUMN external_agent_id,
    DROP COLUMN delegation_depth,
    DROP COLUMN parent_grant_id,
    DROP COLUMN root_grant_id;

DROP INDEX IF EXISTS idx_delegated_grants_root;
DROP INDEX IF EXISTS idx_delegated_grants_parent;
ALTER TABLE delegated_authority_grants
    DROP COLUMN is_agent_delegation,
    DROP COLUMN revoked_source,
    DROP COLUMN trust_relationship_id,
    DROP COLUMN attenuation_digest,
    DROP COLUMN parent_scope_digest,
    DROP COLUMN authority_scope_digest,
    DROP COLUMN delegation_depth,
    DROP COLUMN delegatee_agent_id,
    DROP COLUMN delegator_agent_id,
    DROP COLUMN root_grant_id,
    DROP COLUMN parent_grant_id;
