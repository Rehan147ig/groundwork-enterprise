-- Per-tool-action budget counters are keyed by an opaque composite
-- ("<tool_id>|<action_id>") in the memory store, and the same key must
-- round-trip through Postgres. Widen action_id to TEXT so the composite
-- key can be stored as-is (a UUID column can never hold it).

ALTER TABLE agent_run_budget_usage
    DROP CONSTRAINT IF EXISTS agent_run_budget_usage_action_id_fkey,
    ALTER COLUMN action_id TYPE TEXT;

DROP INDEX IF EXISTS idx_budget_usage_run_type;
DROP INDEX IF EXISTS idx_budget_usage_run_action_type;

CREATE UNIQUE INDEX idx_budget_usage_run_type
    ON agent_run_budget_usage (run_id, counter_type)
    WHERE action_id IS NULL;
CREATE UNIQUE INDEX idx_budget_usage_run_action_type
    ON agent_run_budget_usage (run_id, action_id, counter_type)
    WHERE action_id IS NOT NULL;
