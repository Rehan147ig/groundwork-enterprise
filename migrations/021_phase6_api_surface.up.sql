-- Phase 6 API surface: consent revocation + transfer-policy lifecycle
-- evidence, and single-active-consent uniqueness.

-- Consent revocation and transfer-policy transitions are recorded as
-- hash-chained trust events, so the event_type domain is widened.
ALTER TABLE trust_events DROP CONSTRAINT IF EXISTS agent_trust_events_event_type_check;
ALTER TABLE trust_events
    ADD CONSTRAINT agent_trust_events_event_type_check
    CHECK (event_type IN (
        'trust.requested','trust.approved','trust.activated',
        'trust.suspended','trust.resumed','trust.revoked',
        'delegation.child_minted','chain.revoked','chain.suspended',
        'chain.resumed','chain.verified','external.agent',
        'consent.granted','consent.revoked','transfer_policy.updated'));

-- At most one ACTIVE consent per (tenant, organization, external agent,
-- customer principal, purpose): a re-grant after revocation creates a
-- fresh row, while a replay of an active grant fails closed (conflict).
CREATE UNIQUE INDEX idx_consent_active_unique
    ON consent_records (tenant_id, organization_id, external_agent_id, customer_principal_id, purpose)
    WHERE status = 'active';
