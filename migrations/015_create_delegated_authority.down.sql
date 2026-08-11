-- Drop Phase 2 delegated authority objects in reverse order.
DROP RULE IF EXISTS no_delete_action_approvals ON agent_action_approvals;
DROP RULE IF EXISTS no_update_action_approvals ON agent_action_approvals;
DROP RULE IF EXISTS no_delete_action_decisions ON agent_action_decisions;
DROP RULE IF EXISTS no_update_action_decisions ON agent_action_decisions;
DROP TABLE IF EXISTS agent_action_approvals;
DROP TABLE IF EXISTS agent_action_decisions;
DROP TABLE IF EXISTS agent_runs;
DROP TABLE IF EXISTS delegated_authority_grants;
DROP TABLE IF EXISTS agent_tool_grants;
DROP TABLE IF EXISTS tool_actions;
DROP TABLE IF EXISTS tools;
