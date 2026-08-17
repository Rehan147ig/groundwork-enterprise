resource "groundwork_budget" "support_run_budget" {
  # Scope: tenant, agent_version, or grant.
  scope_type                        = "tenant"
  max_actions_per_run               = 25
  max_denied_per_run                = 5
  max_approval_required_per_run     = 3
  max_tool_calls_per_action_per_run = 5
  max_run_duration_seconds          = 1800
  max_citations_per_query           = 20
}