---
page_title: "groundwork_tenant Resource - groundwork"
subcategory: ""
description: |-
  A Groundwork tenant. Delete deprovisions (non-destructive): the tenant record and its evidence chain are retained.
---

# groundwork_tenant (Resource)

A Groundwork tenant. Delete **deprovisions** (non-destructive): the
tenant record and its hash-chained lifecycle evidence are retained and
remain queryable for compliance replay.

## Example Usage

```terraform
resource "groundwork_tenant" "acme" {
  tenant_id     = "acme-prod"
  region        = "US"
  capacity_tier = "enterprise"
  reason        = "managed by terraform"
}
```

## Schema

### Required

- `region` (String) Region the tenant is provisioned in (e.g. US, EU).
  Region is immutable after provisioning; a change fails closed
  server-side (`region_conflict`).
- `tenant_id` (String) Tenant identifier, e.g. `acme-prod`.

### Optional

- `capacity_tier` (String) Capacity model tier: `standard`, `plus`, or
  `enterprise`. Empty defaults to `standard`.
- `reason` (String) Auditable reason attached to every provisioning
  transition. Defaults to a terraform-generated reason.

### Read-Only

- `id` (String) Tenant ID (equals `tenant_id`).
- `status` (String) Tenant lifecycle status (`active`, `disabled`,
  `deprovisioned`).

## Import

Tenants can be imported using their `tenant_id`:

```
terraform import groundwork_tenant.acme acme-prod
```

## Delete Semantics

Delete issues the **deprovision** transition. The tenant directory
record, event chain, and audit trail are never destroyed.