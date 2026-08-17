---
page_title: "groundwork_agent_tool_grant Resource - groundwork"
subcategory: ""
description: |-
  A governance tool grant binding an agent version to a tool action. Delete revokes (non-destructive).
---

# groundwork_agent_tool_grant (Resource)

A governance tool grant binding an agent version to a tool action.
Delete **revokes** the grant (non-destructive): the grant record and
its evidence chain remain for audit replay.

## Example Usage

```terraform
resource "groundwork_agent_tool_grant" "support_slack" {
  agent_id           = groundwork_agent.support.id
  version_id         = groundwork_agent.support.version.version
  tool_id            = "slack"
  action_id          = "send_message"
  resource_scope     = "slack://C1234567890"
  region_constraint  = "US"
  call_limit_per_run = 10
  requires_approval  = true
}
```

## Schema

### Required

- `action_id` (String) Tool action the grant covers.
- `agent_id` (String) Agent that receives the grant.
- `tool_id` (String) Tool the grant covers.
- `version_id` (String) Agent version scoped to the grant.

### Optional

- `call_limit_per_run` (Number) Maximum calls of this action per run.
  `0` means unlimited.
- `region_constraint` (String) Region the grant is constrained to.
- `requires_approval` (Boolean) Whether every call requires human
  approval.
- `resource_scope` (String) Resource scope the grant applies to, e.g.
  `acme-docs://*`.

### Read-Only

- `id` (String) Grant ID.

## Import

Grants can be imported using their grant ID:

```
terraform import groundwork_agent_tool_grant.support_slack <grant-id>
```

## Update Semantics

Grants are immutable server-side. Updating any grant field revokes the
superseded grant and mints a replacement under a fresh grant ID.