-- Connector invocation immutable evidence digest (Phase 5 live fix).
--
-- connector_invocations is write-once at the schema level (no_update /
-- no_delete rules), but the evidence union surfaced invocation rows
-- with an EMPTY immutable_digest, so investigation chains could not
-- verify an invocation outcome the way every other evidence kind can.
-- This adds a digest column computed at append time over the
-- security-relevant fields (the same field set the connectors package
-- hashes in ConnectorInvocationDigest).

ALTER TABLE connector_invocations
    ADD COLUMN immutable_digest TEXT NOT NULL DEFAULT '';
