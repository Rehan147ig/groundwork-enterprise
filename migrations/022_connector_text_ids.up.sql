-- Connector registry ID alignment with the store (Phase 5 live fix).
--
-- The connector store generates TEXT identifiers (conn-*, cver-*) so
-- memory and Postgres modes behave identically, but 018 declared UUID
-- columns and FKs. The very first live insert therefore fails
-- (SQLSTATE 22P02). Convert the identifier columns to TEXT — the same
-- treatment 020 gave the Phase 6 external-agent columns — and restore
-- referential integrity on the TEXT values.
--
-- No legacy data exists to migrate: a row could never be inserted into
-- a UUID column from the store, so the USING id::text casts are safe.

-- Drop every FK whose referenced column is about to change type.
ALTER TABLE connector_versions
    DROP CONSTRAINT IF EXISTS connector_versions_connector_id_fkey;
ALTER TABLE connector_actions
    DROP CONSTRAINT IF EXISTS connector_actions_connector_id_fkey,
    DROP CONSTRAINT IF EXISTS connector_actions_version_id_fkey;
ALTER TABLE connector_invocations
    DROP CONSTRAINT IF EXISTS connector_invocations_connector_id_fkey;
ALTER TABLE connector_lifecycle_events
    DROP CONSTRAINT IF EXISTS connector_lifecycle_events_connector_id_fkey;

-- Convert identifiers to TEXT. (connectors.current_version_id declared
-- no FK in 018; connector_actions.id / connector_invocations.id /
-- connector_lifecycle_events.id stay UUID — the store never writes them.)
ALTER TABLE connectors
    ALTER COLUMN id TYPE TEXT USING id::text,
    ALTER COLUMN current_version_id TYPE TEXT USING current_version_id::text;

-- tool_id is optional: the gateway registers connectors without a
-- governed tool binding (the store keeps ToolID "" in memory mode),
-- so the column must accept NULL and the FK stays for bound ones.
ALTER TABLE connectors
    ALTER COLUMN tool_id DROP NOT NULL;

ALTER TABLE connector_versions
    ALTER COLUMN id TYPE TEXT USING id::text,
    ALTER COLUMN connector_id TYPE TEXT USING connector_id::text;

ALTER TABLE connector_actions
    ALTER COLUMN connector_id TYPE TEXT USING connector_id::text,
    ALTER COLUMN version_id TYPE TEXT USING version_id::text;

ALTER TABLE connector_invocations
    ALTER COLUMN connector_id TYPE TEXT USING connector_id::text;

ALTER TABLE connector_lifecycle_events
    ALTER COLUMN connector_id TYPE TEXT USING connector_id::text;

-- Restore referential integrity on the TEXT identifiers.
ALTER TABLE connector_versions
    ADD CONSTRAINT connector_versions_connector_id_fkey
        FOREIGN KEY (connector_id) REFERENCES connectors(id) ON DELETE CASCADE;
ALTER TABLE connector_actions
    ADD CONSTRAINT connector_actions_connector_id_fkey
        FOREIGN KEY (connector_id) REFERENCES connectors(id) ON DELETE CASCADE,
    ADD CONSTRAINT connector_actions_version_id_fkey
        FOREIGN KEY (version_id) REFERENCES connector_versions(id) ON DELETE CASCADE;
ALTER TABLE connector_invocations
    ADD CONSTRAINT connector_invocations_connector_id_fkey
        FOREIGN KEY (connector_id) REFERENCES connectors(id) ON DELETE CASCADE;
ALTER TABLE connector_lifecycle_events
    ADD CONSTRAINT connector_lifecycle_events_connector_id_fkey
        FOREIGN KEY (connector_id) REFERENCES connectors(id) ON DELETE CASCADE;
