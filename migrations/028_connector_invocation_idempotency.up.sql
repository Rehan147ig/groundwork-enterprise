-- Connector dispatch idempotency (Phase 8.2 "Idempotency for every
-- external mutation").
--
-- A client retry (same run, tool, action, resource, arguments) mints a
-- NEW decision id, so decision_id uniqueness alone cannot stop the
-- upstream from executing twice. idempotency_key is the semantic hash
-- of the logical mutation (tenant | run | tool | action | resource |
-- canonical args); the service replays the recorded success before
-- ever calling the connector again.
--
-- Guarantees:
--   - at most ONE success row per (tenant_id, idempotency_key): the
--     partial unique index fails closed on any second success;
--   - failed attempts do not consume the key (a retry after a failure
--     is a legitimate new attempt) — hence the WHERE outcome =
--     'success' predicate;
--   - old rows carry NULL (empty key) and are untouched.
--
-- The key is correlation metadata like root_grant_id and is NOT part
-- of ConnectorInvocationDigest: adding it to the hash would break
-- verification of every existing row, and write-once evidence already
-- pins the outcome fields.

ALTER TABLE connector_invocations
    ADD COLUMN idempotency_key TEXT;

-- Fast lookup for the replay check (service reads by key before call).
CREATE INDEX idx_connector_invocations_idempotency_key
    ON connector_invocations (tenant_id, idempotency_key);

-- One success per logical mutation; failures stay retryable.
CREATE UNIQUE INDEX uq_connector_invocations_success_key
    ON connector_invocations (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL AND outcome = 'success';
