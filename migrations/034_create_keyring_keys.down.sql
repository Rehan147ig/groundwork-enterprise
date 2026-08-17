-- Migration 034 down: Drop keyring_keys table
DROP INDEX IF EXISTS idx_keyring_keys_namespace;
DROP INDEX IF EXISTS idx_keyring_keys_purpose;
DROP TABLE IF EXISTS keyring_keys;