-- Migration 035 down: Drop api_keys table
DROP INDEX IF EXISTS api_keys_tenant_active_idx;
DROP INDEX IF EXISTS api_keys_key_prefix_idx;
DROP TABLE IF EXISTS api_keys;
