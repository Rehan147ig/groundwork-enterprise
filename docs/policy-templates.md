# Starter policy templates

The `groundwork` CLI ships validated starter governance policies for
common regulated use cases. Templates are embedded in
`services/query-runtime/cmd/groundwork/templates/*.json` and map 1:1
onto the governance API contract (`RegisterToolRequest`,
`RegisterToolActionRequest`, `GrantToolRequest`, `BudgetPolicyRequest`).

## List

| Template | Region | Surface |
|---|---|---|
| `read-only-research` | us | One built-in search tool, one grant. The safest starter. |
| `internal-knowledge` | uk | Read-only knowledge search + retrieve. No connectors. |
| `customer-support` | eu | Read-only ticket lookup + knowledge search. |
| `developer-agent` | us | Read-only code search + repo browsing. No write tools. |
| `finance-agent` | uk | Read-only ledger/statement lookup (high risk-level action). |
| `healthcare-assistant` | eu | Read-only patient record lookup; **every** action requires human approval. |

All templates are **read-only**: every action has `read_only: true`, so
a bad starter cannot silently mint a write-capable policy. The template
validator rejects any read-only template containing a write action, a
grant referencing an unknown tool/action, a region constraint that
diverges from the template region, or non-positive budget limits.

## Use

```powershell
# Scaffold a deployment directory with generated secrets + key pair.
go run ./cmd/groundwork init --template finance-agent --dir ./deploy/uk

# List templates.
go run ./cmd/groundwork templates

# Validate a deployment (fail-closed in production mode).
go run ./cmd/groundwork doctor --env-file ./deploy/uk/groundwork.env
```

`init` writes:

- `groundwork.env` — runtime configuration with generated HS secrets and
  the RSA delegation key wired in (`GROUNDWORK_DELEGATION_RS_PRIVATE_KEY_FILE`).
- `delegation-rs256.pem` / `.pub` — generated RSA-2048 key pair (RS256 preferred).
- `policy.json` — the validated starter policy.
- `README.md` — next steps.

## Applying policy.json

The document is the operator's intent; applying it is a sequence of
governance API calls after the runtime is up:

1. `POST /v1/agents` — register each `grants[].agent_label` as a real
   agent (the template's `agent_label` is a placeholder).
2. `POST /v1/agents/{agent_id}/versions` then `/activate` — the version
   the grants bind to.
3. `POST /v1/governance/tools` + `/actions` — register each `tools[]`
   entry (replace the grant placeholder references with returned ids).
4. `POST /v1/governance/grants` — one `GrantToolRequest` per
   `grants[].tools[]` entry.
5. `POST /v1/governance/budgets` — apply `budget_policy`.

Region constraints and consent rules are enforced before any connector
executes; see `docs/governance.md` (Phase 6) and
`docs/production-scale-roadmap.md`.
