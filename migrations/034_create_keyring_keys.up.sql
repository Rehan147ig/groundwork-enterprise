-- Migration 034: Create keyring_keys table for DB-backed keyring
--
-- This table stores envelope-encrypted key material per namespace,
-- enabling per-tenant, per-connector secret isolation in production.
-- The envelope uses AES-GCM via cryptosvc with a KEK from the
-- cryptosvc KEK resolver chain (env://, file://, or external KMS).
--
-- Namespace examples:
--   purpose:connector                    (default, single key per purpose)
--   tenants/acme/connectors/msgraph      (per-tenant, per-connector)

CREATE TABLE IF NOT EXISTS keyring_keys (
    namespace TEXT NOT NULL,
    purpose   TEXT NOT NULL,
    key_id    TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    provisioned TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (namespace, purpose, key_id)
);

CREATE INDEX IF NOT EXISTS idx_keyring_keys_purpose
    ON keyring_keys (purpose);

CREATE INDEX IF NOT EXISTS idx_keyring_keys_namespace
    ON keyring_keys (namespace);