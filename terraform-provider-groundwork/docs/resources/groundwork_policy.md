---
page_title: "groundwork_policy Resource - groundwork"
subcategory: ""
description: |-
  A data-transfer policy allowlisting purpose-scoped transfers between regions. Delete revokes (non-destructive).
---

# groundwork_policy (Resource)

A data-transfer policy allowlisting purpose-scoped transfers between
regions. Delete **revokes** the policy (non-destructive): the policy
and its evidence chain remain for audit replay.

## Example Usage

```terraform
resource "groundwork_policy" "us_to_eu_sync" {
  source_region   = "US"
  target_region   = "EU"
  purpose_pattern = "*"
  enabled         = true
}
```

## Schema

### Required

- `purpose_pattern` (String) Purpose allowlist pattern: `*` (any) or an
  exact purpose.
- `source_region` (String) Source region, e.g. `US`.
- `target_region` (String) Target region, e.g. `EU`.

### Optional

- `enabled` (Boolean) Whether the policy is currently enforced.

### Read-Only

- `id` (String) Policy ID.

## Import

Policies can be imported using their policy ID:

```
terraform import groundwork_policy.us_to_eu_sync <policy-id>
```

## Delete Semantics

Delete issues the **revoke** transition. The policy row and its
evidence chain are never destroyed.