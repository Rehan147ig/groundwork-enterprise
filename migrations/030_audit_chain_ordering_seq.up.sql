-- Guarantee a monotonic per-insert ordering for the audit hash chain.
--
-- The chain's linkage (previous_hash) is decided at write time under the
-- per-tenant advisory lock, so the read-back order MUST match insertion
-- order. ORDER BY (timestamp_utc, id) violated that: id is a random
-- UUID (migration 003) and Postgres timestamps have microsecond
-- precision, so two concurrent same-tenant writes within one microsecond
-- could read back in the wrong relative order and VerifyChain would flag
-- broken_link on innocent rows.
--
-- seq is a BIGINT identity: strictly monotonic, assigned at INSERT time,
-- and immune to timestamp ties. The writer's previous-hash lookup and
-- LoadAuditChain both order by it (per tenant).

ALTER TABLE audit_log ADD COLUMN seq BIGINT GENERATED ALWAYS AS IDENTITY;

CREATE INDEX idx_audit_log_tenant_seq ON audit_log (tenant_id, seq);