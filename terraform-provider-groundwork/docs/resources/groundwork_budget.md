---
page_title: "groundwork_budget Resource - groundwork"
subcategory: ""
description: |-
  A run-level budget policy. Delete zeroes the policy (non-destructive; all-zero limits fail closed).
---

# groundwork_budget (Resource)

A run-level budget policy scoped to a tenant, an agent version, or a
grant. Delete **zeroes** the budget — the runtime has no destructive
budget endpoint, so Terraform delete deprovisions the policy to its
least-privileged state: all-zero limits fail closed on every budget
check.

## Example Usage

```terraform
resource "groundwork_budget" "support_run_budget" {
  scope_type                        = "tenant"
  max_actions_per_run               = 25
  max_denied_per_run                = 5
  max_approval_required_per_run     = 3
  max_tool_calls_per_action_per_run = 5
  max_run_duration_seconds          = 1800
  max_citations_per_query           = 20
}
```

## Schema

### Required

- `scope_type` (String) Scope: `tenant`, `agent_version`, or `grant`.

### Optional

- `agent_version_id` (String) Agent version ID when `scope_type` is
  `agent_version`.
- `grant_id` (String) Grant ID when `scope_type` is `grant`.
- `max_actions_per_run` (Number) Maximum evaluated actions per run.
- `max_approval_required_per_run` (Number) Maximum approval-required
  actions per run.
- `max_citations_per_query` (Number) Maximum citations per query.
- `max_denied_per_run` (Number) Maximum denied actions per run.
- `max_run_duration_seconds` (Number) Maximum run duration in seconds.
- `max_tool_calls_per_action_per_run` (Number) Maximum tool calls per
  action per run.

### Read-Only

- `id` (String) Budget policy ID.

## Import

Budgets can be imported using their policy ID:

```
terraform import groundwork_budget.support_run_budget <budget-id>
```

## Delete Semantics

Delete upserts the policy with all limits zeroed — a non-destructive
deprovision. The policy row and its evidence remain; every budget check
fails closed under the zeroed limits.