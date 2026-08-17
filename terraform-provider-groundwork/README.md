# Terraform Provider Groundwork

The Groundwork Terraform provider manages the Groundwork runtime
authorization and evidence layer for enterprise AI agents.

Built on the current [Terraform Plugin
Framework](https://developer.hashicorp.com/terraform/plugin/framework)
(plugin protocol 6).

## Resources

| Resource | Delete semantics |
|---|---|
| `groundwork_tenant` | **Deprovisions** (non-destructive) |
| `groundwork_agent` | **Revokes** (non-destructive) |
| `groundwork_agent_tool_grant` | **Revokes** (non-destructive) |
| `groundwork_connector` | **Revokes** (non-destructive) |
| `groundwork_policy` | **Revokes** (non-destructive) |
| `groundwork_budget` | **Zeroes** limits (non-destructive; fail closed) |

Every Terraform delete honors Groundwork's non-destructive lifecycle:
records, hash-chained evidence, and audit trails always remain intact.

Secrets are **references only** (`secret_ref`, `client_cert_ref`) — raw
credentials never enter Terraform state.

## Usage

```terraform
provider "groundwork" {
  api_base_url = "https://gw.example.com"
  api_key      = var.groundwork_api_key
  region       = "US"
}
```

See [`examples/`](examples/) and [`docs/`](docs/) for full resource
examples and schema reference.

## Development

```sh
go build ./...    # build
go test ./...     # unit tests (no external dependencies)
go vet ./...      # vet
gofmt -l .        # formatting
```

Acceptance tests run against a disposable Groundwork stack:

```sh
TF_ACC=1 GW_API_BASE_URL=https://... GW_API_KEY=... go test ./internal/provider/
```