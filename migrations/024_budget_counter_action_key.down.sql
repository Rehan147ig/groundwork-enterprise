-- Revert the per-tool-action budget counter key to a UUID FK.

DROP INDEX IF EXISTS idx_budget_usage_run_type;
DROP INDEX IF EXISTS idx_budget_usage_run_action_type;

DELETE FROM agent_run_budget_usage
WHERE action_id IS NOT NULL AND action_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

ALTER TABLE agent_run_budget_usage
    ALTER COLUMN action_id TYPE UUID USING action_id::uuid,
    ADD CONSTRAINT agent_run_budget_usage_action_id_fkey
        FOREIGN KEY (action_id) REFERENCES tool_actions(id) ON DELETE CASCADE;

CREATE UNIQUE INDEX idx_budget_usage_run_type
    ON agent_run_budget_usage (run_id, counter_type)
    WHERE action_id IS NULL;
CREATE UNIQUE INDEX idx_budget_usage_run_action_type
    ON agent_run_budget_usage (run_id, action_id, counter_type)
    WHERE action_id IS NOT NULL;
