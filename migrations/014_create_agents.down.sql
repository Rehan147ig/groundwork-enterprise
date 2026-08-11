DROP RULE IF EXISTS no_delete_agent_events ON agent_lifecycle_events;
DROP RULE IF EXISTS no_update_agent_events ON agent_lifecycle_events;
DROP TABLE IF EXISTS agent_lifecycle_events;
DROP TABLE IF EXISTS agent_versions;
DROP TABLE IF EXISTS agents;
