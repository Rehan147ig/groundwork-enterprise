# Connector Gateway (Phase 5)

The Connector Gateway is the only path out of Groundwork. No registered
tool call may reach an external system unless Groundwork authorizes that
exact agent action first — and every missing, unavailable, inconsistent,
expired, or revoked dependency fails closed *before* the outbound
connection opens.

## The central rule

The gateway is invoked by `governance.Service.DispatchAction` **only
after** the shared evaluator has recorded an **allowed** decision on the
evidence chain. The gateway then re-validates, with a fresh read:

1. the connector is registered and **active** (not draft/suspended/revoked/retired);
2. the run's **region** matches the connector's region and is provisioned;
3. the **action** is in the current manifest (agent can never supply URL, host, port, or method);
4. the agent version is permitted by the manifest (`allowed_agent_version_ids`);
5. secrets resolve (missing secret ⇒ fail closed).

Only then does a transport open a connection. Anything else — nil
dispatcher, unknown connector, region mismatch, suspension, revocation
— produces `connector_failed` dispatch evidence and **no** external call.

## Architecture

```
agent action → governance evaluator → allowed decision (evidence) →
DispatchAction → Connector Gateway (fresh preflight, fail closed) →
   REST transport (GET/HEAD/POST against manifest path template)   → redact → size-limit → evidence
   MCP transport  (initialize + tools/call over JSON-RPC 2.0 HTTP)  → redact → size-limit → evidence
```

- `internal/runtime/connectors.go` — DTOs, sentinel errors, `ConnectorService` + `ConnectorDispatcher` interfaces.
- `internal/connectors/` — implementation: `gateway.go` (lifecycle + preflight), `restconnector.go`, `mcpconnector.go`, `contract.go` (config/manifest validation), `redact.go`, `secrets.go` (env/keyring resolvers), `store.go`, `store_pg.go`, `store_phase3.go` (Postgres + memory registry).
- `internal/runtime/connectors_api.go` — HTTP surface under `/v1/governance/connectors*`.
- `internal/deployment/validate.go` — deployment-time egress/TLS validation for connector base URLs.
- `migrations/018_connectors.up.sql` — registry, versions, actions, lifecycle events, invocation evidence.

## Lifecycle

`draft → active → suspended → revoked → retired` (revoked/retired are
terminal). Connectors are created in **draft** and never dispatch until
explicitly activated. Every transition and config change is a hash-
chained `connector_lifecycle_event`; config changes are only allowed on
draft/suspended connectors, and each change creates an **immutable new
version** with its own manifest digest.

## REST connectors

| Config field | Meaning |
|---|---|
| `base_url` | Operator-supplied endpoint. **Never** derived from agent input. Credentials in the URL are rejected. |
| `region` | Connector region; dispatch requires an exact match with the run's region. |
| `timeout_ms` | Per-call timeout (default 5s). |
| `retry_max` / `retry_idempotent_only` | Retries only on network-level errors, and only for idempotent GET/HEAD when `retry_idempotent_only` is set. |
| `max_response_bytes` | Response body cap (default 256 KiB); larger responses are blocked and recorded as `response_blocked`. |
| `allowed_content_types` | Response Content-Type allowlist; anything else is blocked. |
| `redaction_fields` | Case-insensitive field names redacted in responses and logs. |
| `secret_ref` / `client_cert_ref` | Secret / mTLS client certificate references (see Secrets). |
| `tls_verify` | TLS certificate verification; `false` is a deployment violation in production. |

Manifest actions define `path_template` (e.g. `/v1/balance/{account}` —
templates with `..` are rejected outright), `transport_method` (HTTP
method), `args` (allowlisted argument names; everything else is
filtered out before the request), `max_request_bytes`,
`max_response_bytes`, `risk`, `read_only`, `requires_approval`, and
`allowed_agent_version_ids`.

Enforcement rules:

- Redirects are **rejected** (single-hop, no following).
- No Authorization/cookie values are ever logged; responses are redacted with the configured fields before they reach the agent or evidence.
- Retry policy above; write requests are never retried.
- Health probes are credential-free `GET` on the base URL and are side-effect-free.

## MCP connectors

The gateway is an MCP **client** speaking JSON-RPC 2.0 over HTTP(S) to
the configured server: `initialize` → `notifications/initialized` →
`tools/list` → `tools/call`. The manifest `transport_method` is the
remote tool name; the remote tool list is hash-digested
(`ManifestDigestOfTools`) and compared against the manifest digest, so
remote tool drift is detectable. Same fail-closed preflight, redaction,
size limits, and content-type checks as REST. Health probes run
`initialize` + `ping` and are credential-free.

## Secrets

`secret_ref` and `client_cert_ref` support two reference forms, never
raw values:

- `env://<NAME>` — resolved from process environment at dispatch time;
- `keyring://<purpose>` — resolved from the customer-managed keyring.

Resolved material is used verbatim as a bearer token (or `Bearer
<material>` if it already carries a `Bearer ` prefix). Material never
leaves the gateway layer and never appears in logs, evidence, or
responses. Health probes never send credentials.

## Evidence

Every authorized call produces a `connector_invocation` evidence record
(decision id unique per tenant — duplicates are idempotency conflicts)
with outcome (`success`/`failure`/`timeout`/`response_blocked`), status
code, error code, duration, response bytes, region, and trace id.
Health checks are recorded as `health_check` invocations. Lifecycle
transitions produce `connector_lifecycle` records. Both join the
governance evidence **union** (`QueryEvidence`), so a tenant's
tamper-evident chain covers the full path from decision to outbound
call and back.

## HTTP API

All endpoints under the governance scope; mutations additionally
require a verified identity.

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/governance/connectors` | Register (creates draft + governed tool/actions) |
| GET | `/v1/governance/connectors` | List connectors |
| GET | `/v1/governance/connectors/{id}` | Detail: config + manifest + lifecycle + recent invocations |
| GET | `/v1/governance/connectors/{id}/manifest` | Current immutable version + manifest actions |
| POST | `/v1/governance/connectors/{id}/activate` | Activate (enables dispatch) |
| POST | `/v1/governance/connectors/{id}/suspend` | Suspend (fails closed) |
| POST | `/v1/governance/connectors/{id}/revoke` | Revoke (terminal, requires a reason) |
| POST | `/v1/governance/connectors/{id}/config` | New immutable version (draft/suspended only) |
| GET | `/v1/governance/connectors/{id}/health` | Audited, credential-free health probe |

Error mapping: unknown connector/manifest → 404; name conflict or
invalid transition → 409; unavailable/not-active/revoked/region/
unregistered → 503; invalid config or disabled TLS → 400.

## Deployment validation

`internal/deployment/validate.go` fails deployment when connector
configuration bypasses the safety model:

- `connector_egress_unregistered` — a `GROUNDWORK_CONNECTOR_<NAME>_BASE_URL` host is not in `GROUNDWORK_CONNECTOR_EGRESS_ALLOWLIST` (falls back to `GROUNDWORK_EGRESS_ALLOWLIST`) and `ApprovedEgressOnly` is set;
- `connector_plaintext_endpoint` — public connector endpoint uses `http://`;
- `connector_tls_verify_disabled` — `GROUNDWORK_CONNECTOR_<NAME>_TLS_VERIFY=false` or global `GROUNDWORK_CONNECTOR_TLS_VERIFY=false` in production;
- `connector_endpoint_invalid` — malformed base URL.

## Operator quick start

```
# 1. register (draft)
curl -X POST localhost:8080/v1/governance/connectors \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"name":"payments","type":"rest",
       "config":{"base_url":"https://api.example.com","region":"uk",
                 "tls_verify":true,"allowed_content_types":["application/json"],
                 "redaction_fields":["token"]},
       "actions":[{"name":"get_balance","transport_method":"GET",
                   "path_template":"/v1/balance/{account}",
                   "risk":"low","read_only":true,"args":["account"]}]}'

# 2. activate
curl -X POST localhost:8080/v1/governance/connectors/$ID/activate \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"reason":"go live"}'

# 3. probe, then inspect evidence
curl localhost:8080/v1/governance/connectors/$ID/health  -H "X-API-Key: $KEY"
curl "localhost:8080/v1/governance/evidence?kinds=connector_invocation" -H "X-API-Key: $KEY"
```

The Console (Governance → Connector Gateway) covers registration,
activation/suspend/revoke, config updates, recent invocations, and
health probes. The integration suite (`test/integration/connectors_test.go`,
live stack only) drives the full cycle through the real Postgres store
and live HTTP upstreams.

## Limitations

- One connector pairs with exactly one governed tool; multi-tool connectors are not supported yet.
- mTLS client certificates are resolved through the same secret resolver (`client_cert_ref`); PKCS#12/passphrase-protected keys are not supported.
- Health probes use the base URL only; custom health paths are not configurable.
- The egress allowlist applies at deployment validation time, not per-request DNS resolution.
