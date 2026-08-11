-- Phase 6 API surface rollback.
DROP INDEX IF EXISTS idx_consent_active_unique;

ALTER TABLE trust_events DROP CONSTRAINT agent_trust_events_event_type_check;
ALTER TABLE trust_events
    ADD CONSTRAINT agent_trust_events_event_type_check
    CHECK (event_type IN (
        'trust.requested','trust.approved','trust.activated',
        'trust.suspended','trust.resumed','trust.revoked',
        'delegation.child_minted','chain.revoked','chain.suspended',
        'chain.resumed','chain.verified','external.agent',
        'consent.granted'));
