ALTER TABLE audit_log DROP COLUMN IF EXISTS seq;
DROP INDEX IF EXISTS idx_audit_log_tenant_seq;