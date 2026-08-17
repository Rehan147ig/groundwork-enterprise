---
page_title: "groundwork_agent Resource - groundwork"
subcategory: ""
description: |-
  An agent in the Groundwork registry. Delete revokes (non-destructive).
---

# groundwork_agent (Resource)

An agent in the Groundwork registry. Delete **revokes** the agent
(non-destructive): the registry record, versions, lifecycle events, and
evidence remain intact.

## Example Usage

```terraform
resource "groundwork_agent" "support" {
  name               = "support-agent"
  description        = "Customer support triage agent"
  owner_principal_id = "team-support"
  business_purpose   = "triage support tickets and draft replies"
  risk_tier          = "medium"
  environment        = "production"

  version {
    version              = "v1.0.0"
    model_provider       = "anthropic"
    model_name           = "claude-sonnet-4-5"
    prompt_digest        = "sha256:4b5e..."
    tool_manifest_digest = "sha256:9c1d..."
    artifact_digest      = "sha256:7f2e..."
  }
}
```

## Schema

### Required

- `name` (String) Agent name.
- `risk_tier` (String) Risk tier: `low`, `medium`, `high`, or
  `critical`.

### Optional

- `business_purpose` (String) Declared business purpose (used by policy
  evaluation).
- `description` (String) Human-readable description.
- `environment` (String) Deployment environment, e.g. `production`.
- `owner_principal_id` (String) Principal ID of the agent owner.
- `version` (Block, Optional) Version to publish at create/update time.
  Publishing a new version string on update deploys it as the new
  active version.
  - `version` (String, Required) Version string, e.g. `v1.0.0`.
  - `artifact_digest` (String, Optional) SHA-256 digest of the deployed
    artifact.
  - `model_name` (String, Optional) Model name, e.g.
    `claude-sonnet-4-5`.
  - `model_provider` (String, Optional) Model provider, e.g. `anthropic`.
  - `policy_bundle_version` (String, Optional) Policy bundle version the
    agent runs against.
  - `prompt_digest` (String, Optional) SHA-256 digest of the agent prompt.
  - `tool_manifest_digest` (String, Optional) SHA-256 digest of the tool
    manifest.

### Read-Only

- `active_version` (String) Currently active version string.
- `id` (String) Agent ID.
- `state` (String) Lifecycle state (`active`, `suspended`, `revoked`,
  `retired`).

## Import

Agents can be imported using their agent ID:

```
terraform import groundwork_agent.support <agent-id>
```

## Delete Semantics

Delete issues the **revoke** transition. The agent, its versions, and
its evidence chain are never destroyed.