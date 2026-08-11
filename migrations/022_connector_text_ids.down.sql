-- Connector ID alignment rollback: identifiers return to UUID.
-- TEXT rows (conn-*/cver-*) cannot be coerced to UUID, so reference
-- columns are NULLed and id columns are regenerated (same convention
-- as 020's rollback). Rollback is a dev-only operation; production
-- evidence rows should be archived before reverting.

ALTER TABLE connector_versions
    DROP CONSTRAINT connector_versions_connector_id_fkey;
ALTER TABLE connector_actions
    DROP CONSTRAINT connector_actions_connector_id_fkey,
    DROP CONSTRAINT connector_actions_version_id_fkey;
ALTER TABLE connector_invocations
    DROP CONSTRAINT connector_invocations_connector_id_fkey;
ALTER TABLE connector_lifecycle_events
    DROP CONSTRAINT connector_lifecycle_events_connector_id_fkey;

ALTER TABLE connectors
    ALTER COLUMN id TYPE UUID USING gen_random_uuid(),
    ALTER COLUMN current_version_id TYPE UUID USING NULL;

ALTER TABLE connectors
    ALTER COLUMN tool_id SET NOT NULL;

ALTER TABLE connector_versions
    ALTER COLUMN id TYPE UUID USING gen_random_uuid(),
    ALTER COLUMN connector_id TYPE UUID USING NULL;

ALTER TABLE connector_actions
    ALTER COLUMN connector_id TYPE UUID USING NULL,
    ALTER COLUMN version_id TYPE UUID USING NULL;

ALTER TABLE connector_invocations
    ALTER COLUMN connector_id TYPE UUID USING NULL;

ALTER TABLE connector_lifecycle_events
    ALTER COLUMN connector_id TYPE UUID USING NULL;

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
