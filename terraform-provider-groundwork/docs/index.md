# Groundwork Provider

The Groundwork provider manages the Groundwork runtime authorization
and evidence layer for enterprise AI agents: tenants, agents, tool
grants, connectors, transfer policies, and run budgets.

All mutations are **non-destructive by design**. Terraform delete maps
to the least-privileged terminal transition of the underlying resource
(deprovision, revoke, or zero) — records, hash-chained evidence, and
audit trails always remain intact for compliance replay.

## Example Usage

```terraform
terraform {
  required_providers {
    groundwork = {
      source  = "groundwork/groundwork"
      version = "~> 0.1"
    }
  }
}

provider "groundwork" {
  api_base_url = "https://gw.example.com"
  api_key      = var.groundwork_api_key
  region       = "US"
}
```

## Provider Configuration

- `api_base_url` (string, required) — Base URL of the Groundwork API.
  HTTPS is mandatory except for loopback hosts (local development).
- `api_key` (string, required, sensitive) — Groundwork API key with
  administrator scope. Use a secret reference; never commit the raw key.
- `region` (string, optional) — Default region for tenant-level
  operations (e.g. `US`, `EU`).
- `timeout_seconds` (number, optional) — Per-call API timeout in
  seconds. Defaults to `30`.

## Resources

- [groundwork_tenant](resources/groundwork_tenant.md) — tenants;
  delete deprovisions (non-destructive).
- [groundwork_agent](resources/groundwork_agent.md) — agent registry;
  delete revokes (non-destructive).
- [groundwork_agent_tool_grant](resources/groundwork_agent_tool_grant.md) —
  governance tool grants; delete revokes (non-destructive).
- [groundwork_connector](resources/groundwork_connector.md) — REST/MCP
  connectors; delete revokes (non-destructive). Secrets are references
  only (`secret_ref`), never raw credentials.
- [groundwork_policy](resources/groundwork_policy.md) — data-transfer
  policies; delete revokes (non-destructive).
- [groundwork_budget](resources/groundwork_budget.md) — run budget
  policies; delete zeroes (non-destructive deprovision).

## Development

```
go build ./...      # build
go test ./...       # unit tests (no external dependencies)
go vet ./...        # vet
gofmt -l .          # formatting
```

Acceptance tests run against a disposable Groundwork stack:

```
TF_ACC=1 GW_API_BASE_URL=https://... GW_API_KEY=... go test ./internal/provider/
```