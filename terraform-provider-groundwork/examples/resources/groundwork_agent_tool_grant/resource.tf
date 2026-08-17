resource "groundwork_agent" "support" {
  name        = "support-agent"
  risk_tier   = "medium"
  environment = "production"
  version {
    version = "v1.0.0"
  }
}

resource "groundwork_agent_tool_grant" "support_slack" {
  agent_id          = groundwork_agent.support.id
  version_id        = groundwork_agent.support.version.version
  tool_id           = "slack"
  action_id         = "send_message"
  resource_scope    = "slack://C1234567890"
  region_constraint = "US"
  call_limit_per_run = 10
  requires_approval = true
}