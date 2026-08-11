DROP INDEX IF EXISTS uq_connector_invocations_success_key;
DROP INDEX IF EXISTS idx_connector_invocations_idempotency_key;
ALTER TABLE connector_invocations DROP COLUMN IF EXISTS idempotency_key;
