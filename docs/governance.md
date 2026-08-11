# Delegated Authority & Governed Agent Execution (Phase 2)

Phase 2 lets a verified human delegate **bounded, short-lived authority**
to an agent: which tools it may use, which actions it may take, and
under which run. Every decision — allowed, denied, approval-required, or
fail-closed — is recorded on an immutable, hash-chained evidence stream
that survives the run and can be verified offline.

The security anchor is the **delegation token**: a signed JWT whose
claims bind the tenant, agent, agent version, delegator, subject
principal, region, purpose, permitted actions, and TTL. The token is
returned exactly once at mint time and never persisted server-side —
only its `jti` is stored.

| | |
|---|---|
| Schema | `migrations/015_create_delegated_authority.{up,down}.sql` |
| Implementation | `services/query-runtime/internal/governance` (store + service + tokens + digest) |
| Contract/DTOs | `services/query-runtime/internal/runtime/governance.go` |
| HTTP surface | `services/query-runtime/internal/runtime/governance_api.go` + routes in `server.go` |
| Enforcement points | `/v1/query` delegation gate (`server.go`), MCP `groundwork_search` (stdio + `/mcp`) |
| Console | `apps/console/app/console/page.tsx` ("Governance" view) + `app/api/governance/*` proxy routes |

## Endpoints

All endpoints require the `governance` API-key scope (the existing
`admin` override grants access too). `tenant_id` **and** `region` come
only from the verified API-key context — never from bodies or URLs.
Reads need no identity; mutations require a verified end-user assertion.
Minting delegations and recording human approvals additionally **reject
demo identities** — a demo actor can never mint a delegation or approve
an action.

| Method | Path | Identity | Notes |
|---|---|---|---|
| `POST` | `/v1/governance/tools` | verified | Register a tool |
| `GET` | `/v1/governance/tools` | — | List tools |
| `GET` | `/v1/governance/tools/{tool_id}` | — | Detail + actions |
| `POST` | `/v1/governance/tools/{tool_id}/actions` | verified | Register an action |
| `GET` | `/v1/governance/tools/{tool_id}/actions` | — | List actions |
| `POST` | `/v1/governance/tools/{tool_id}/lifecycle` | verified | `draft → active` (and back) |
| `POST` | `/v1/governance/grants` | verified | Grant tool access to agent+version |
| `POST` | `/v1/governance/grants/{grant_id}/revoke` | verified | Revoke (irreversible) |
| `GET` | `/v1/governance/agents/{agent_id}/grants` | — | List grants |
| `POST` | `/v1/governance/delegations` | **verified only** | Mint — token returned ONCE |
| `POST` | `/v1/governance/runs` | — | Create run (token in body) |
| `GET` | `/v1/governance/runs` | — | List runs |
| `GET` | `/v1/governance/runs/{run_id}` | — | Run detail + decisions |
| `POST` | `/v1/governance/runs/{run_id}/evaluate` | — | Evaluate one action |
| `POST` | `/v1/governance/runs/{run_id}/approve/{action_id}` | **verified only** | Human approval |
| `POST` | `/v1/governance/runs/{run_id}/deny/{action_id}` | **verified only** | Human denial |
| `POST` | `/v1/governance/dispatch` | — | Evaluate + dispatch |
| `POST` | `/v1/governance/simulate` | — | **Read-only policy simulation** with per-gate explanations |

Errors use a stable `{"error": "<code>"}` envelope; codes are the
sentinels in `internal/runtime/governance.go` mapped to HTTP statuses in
`writeGovernanceServiceError` (400 invalid request, 401 delegation
invalid/expired, 403 every forbidden outcome, 404 not found, 409
conflicts, 503 governance unavailable, 500 generic with no internals).

## The delegation flow

```
1. Register tool + action, activate tool          (admin + verified identity)
2. Grant tool access to agent/version             (admin + verified identity)
   ── grant carries resource_scope, region_constraint, call_limit_per_run,
      requires_approval
3. POST /v1/governance/delegations                (VERIFIED identity only)
   ── returns { grant, token } — the raw token is single-delivery
4. POST /v1/governance/runs  {"delegation_token", "actions": [...]}
   ── server-generated run; every action is evaluated immediately;
      the run_id is stamped into the grant row (not the token)
5. approval_required decisions → human approve/deny  (VERIFIED identity only)
6. Agent executes governed work:
   • POST /v1/governance/runs/{run}/evaluate       (action-level gate)
   • POST /v1/governance/dispatch                  (gate + dispatch)
   • POST /v1/query + X-Groundwork-Delegation-Token (retrieval gate —
     runs as the delegation's subject principal)
   • MCP groundwork_search with delegation_token + run_id
     (or X-Groundwork-Delegation-Token header on POST /mcp)
```

### Enforcement order (single shared evaluator)

Every path — REST action evaluation, the `/v1/query` gate, and MCP —
runs through the same `evaluateInTx` inside one transaction:

1. **Token** live, signed, issuer/audience valid, not expired.
2. **Run bound** — the grant's `run_id` matches; tenant + region match.
3. **Agent + version** active (from the Phase 1 registry).
4. **Permitted digest** — the action must be in the signed permitted
   list (digest compared against the grant row).
5. **Tool + action** active.
6. **Grant** unrevoked, resource scope prefix matches, region constraint
   satisfied, per-run call limit not exceeded.
7. **SpiceDB** on the verified subject principal:
   `(user:<subject_principal_id>, use, tool:<tool_id>)` for read-only,
   `(user:<subject_principal_id>, execute, tool_action:<tool_id>:<action>)`
   for write. The subject is ALWAYS the delegation's subject — never a
   body/header-controlled identifier. Unavailable SpiceDB fails closed.
8. **Human approval** — `approval_required` actions need a fresh,
   unconsumed approval; consumption is one-time.

Every outcome appends an `agent_action_decisions` row whose
`immutable_digest` chains to the previous decision — tampering with any
historical decision breaks every subsequent digest.

## Policy simulator (Phase 7)

`POST /v1/governance/simulate` answers "would this action be allowed?"
against current state — WITHOUT minting a token, creating a run, or
writing anything (no evidence, no budget counters, no approval
consumption, no outbox events). It is an analysis endpoint, not a second
authorization path: the authoritative runtime decision always remains
`EvaluateAction`. The simulator walks the **same gate pipeline in the
same order** (`simulateGates` mirrors `evaluateInTx`), so the response
is an honest per-gate explanation, never a guessed result.

Request (`tenant_id` and `region` still come only from the API-key
context):

```json
{
  "agent_id": "agent-1",
  "version_id": "version-1",      // optional: defaults to active version
  "tool_name": "groundwork_search",
  "action": "search",
  "resource_ref": "doc:reports/q3",
  "principal_id": "principal:bob" // optional: enables the SpiceDB gate
}
```

Response:

```json
{
  "simulation": {
    "decision": "allowed",            // allowed | denied | approval_required | fail_closed
    "allowed": true,
    "reason": "allowed",
    "checks": [
      { "gate": "emergency_controls", "name": "agent control", "status": "passed", "detail": "no emergency control on agent" },
      { "gate": "delegation", "name": "live delegation", "status": "skipped", "detail": "runtime evaluation requires a live delegation token; simulation assumes the matching grant is the authority" },
      { "gate": "agent", "name": "agent lifecycle", "status": "passed", "detail": "agent active" },
      { "gate": "grant", "name": "grant coverage", "status": "passed", "detail": "covered by grant <id> (scope *, region *)" },
      { "gate": "spicedb", "name": "relationship permission", "status": "skipped", "detail": "no principal_id supplied" }
    ],
    "simulated": true,
    "simulated_at": "2026-08-08T10:25:13Z"
  }
}
```

Simulation semantics — read these before trusting a result:

- **No delegation token is accepted.** Run/delegation emergency-control
  rows do not exist in a simulation; those gates are reported as
  `skipped`, and the grant gate becomes the authority that the
  delegation gates would enforce at runtime. A would-allow simulation is
  NOT a guarantee the action would pass runtime evaluation — a real
  delegation must still be minted.
- **Gates stop at the first blocking failure.** The decision is the
  first `failed`/`unavailable`/`required` gate; later gates are still
  evaluated and reported in the allowed case so the operator sees the
  full picture.
- **SpiceDB is opt-in** via `principal_id`. Without it the gate is
  `skipped`. With it, an unavailable permission backend fails closed
  (`fail_closed`) — the simulator never guesses.
- **Approval** is reported as `required` when the grant or the tool
  action declares `requires_human_approval`; it does not consume or
  create any approval record.
- **Budgets** are read for transparency; counter dimensions
  (`max_actions_per_run`, ...) apply per run and are reported as
  `skipped` because no run exists.
- **Call limits** similarly read the grant but never increment.
- `simulated: true` is always set so no client can mistake the output
  for an authoritative decision.

The HTTP layer mirrors the evaluate handler (governance scope, no
identity required, 5s timeout); errors use the same `{"error": ...}`
envelope. Unit + HTTP tests assert the no-write invariant and that the
gate pipeline matches `evaluateInTx`.

## Security model

1. **Dedicated delegation authority** — delegation tokens use their own
   signing key, never `GROUNDWORK_JWT_HS_SECRET`. RS256 preferred
   (`GROUNDWORK_DELEGATION_RS_PRIVATE_KEY(_FILE)`), else a dedicated
   HS256 secret (`GROUNDWORK_DELEGATION_HS_SECRET`, ≥ 32 chars).
   Rotation via `GROUNDWORK_DELEGATION_HS_SECRET_PREVIOUS` /
   `GROUNDWORK_DELEGATION_RS_PUBLIC_KEY_PREVIOUS` (verification only).
   A runtime serving governed flows **fails to start** without a key.
   Issuer/audience are pinned (`GROUNDWORK_DELEGATION_ISSUER`,
   `GROUNDWORK_DELEGATION_AUDIENCE`); TTL is capped at 15 minutes.
2. **Bindings, not bodies** — tenant/region/agent/version/delegator/
   subject/purpose come from the minted token and grant row; `run_id`
   is stamped into the grant at run creation. Nothing in a request body
   or header can change the effective principal.
3. **Fail-closed everywhere** — missing governance service, unreachable
   SpiceDB, revoked grant, region mismatch, expired token, consumed
   approval, terminal run: all produce a recorded denial and no work.
4. **Demo can never mint or approve** — the HTTP layer rejects demo
   identities with `verified_identity_required_for_delegation` /
   `verified_identity_required_for_approval`.
5. **Single delivery** — the raw token is returned once at mint. An
   idempotent replay (same `Idempotency-Key`) returns the existing
   grant with `token_already_issued: true` and no token. Tokens are
   never logged, echoed in errors, or stored.
6. **Tamper-evident evidence** — grants, decisions, and approvals all
   carry hash-chained digests; write-once RULEs on the schema make
   direct SQL `UPDATE`/`DELETE` no-ops. Chain verification helpers
   (`VerifyDecisionChain` / `VerifyApprovalChain`) return a list of
   `ChainProblem`s.
7. **Idempotency** — mint, run creation, and approvals honor
   `Idempotency-Key`; conflicts map to 409.

## Query & MCP gates

- **`/v1/query`** — when `X-Groundwork-Delegation-Token` is present, the
  end-user assertion middleware is bypassed: the token authenticates the
  request, `run_id` comes from the body, and the builtin
  `groundwork_search:search` action is evaluated. On allow, the engine
  runs as `grant.subject_principal_id` and the run's evidence records
  the decision. No token → behavior is unchanged (verified identity or
  demo mode).
- **MCP `groundwork_search`** — accepts optional `delegation_token` +
  `run_id` arguments (stdio) or the `X-Groundwork-Delegation-Token`
  header (`POST /mcp`). A delegation token supersedes `user_token` /
  `user_id` entirely. Without a governance service wired, a delegation
  token fails closed with no documents.

## Storage

- **Postgres** (production): `governance.NewPostgresStore(db)`. Requires
  migration 015: `tools`, `tool_actions`, `agent_tool_grants`,
  `delegated_authority_grants`, `agent_runs`, `agent_action_decisions`,
  `agent_action_approvals` with CHECK-constrained enums, write-once
  RULEs, and advisory-lock serialized transitions.
- **In-memory** (dev/demo): `governance.NewMemoryStore()`. Ephemeral;
  used automatically when `DATABASE_URL` is unset. When governance is
  not wired at all, `/v1/governance*` returns 503 `governance_unavailable`
  and a delegation token on `/v1/query` fails closed.

`cmd/query-runtime/main.go` builds one `governance.Service` shared by
the REST server and the MCP server (stdio and `/mcp`), backed by the
Phase 1 agent registry (`AgentReader`) and the relationship
authorization backend (`internal/relationship` `Authorizer` — SpiceDB
today via the adapter in `internal/relationship/spicedb`, SpiceDB
later).

## Verification

```sh
cd services/query-runtime
go test ./internal/governance/... ./internal/runtime/... ./internal/mcp/...   # unit + HTTP + MCP
go test -tags integration ./test/integration/...              # Postgres lifecycle, isolation, write-once, chain
python ../scripts/check_migrations.py                         # migration gate (003..015)
```

The governance suite (`internal/governance/service_test.go`, 51 tests)
covers the authority (roundtrip, tamper, expiry, rotation), minting
(owner-or-admin, single delivery, TTL cap), runs (reuse rejection,
all-denied), the evaluator (17 cases incl. the exact SpiceDB contract
shapes), approvals (consume-once, expiry, deny blocks), the delegated
query gate, dispatch modes, and digest-chain tamper detection. The HTTP
surface (`internal/runtime/governance_api_test.go`) covers scope/auth
enforcement, demo rejection for mint + approval, token single delivery,
the approval lifecycle over HTTP, and the `/v1/query` delegation gate
including region mismatch and unknown-run fail-closed. MCP parity is
covered in `internal/mcp/delegation_test.go` (stdio + `/mcp` header).

---

# Phase 3 — Emergency Revocation, Evidence Operations & Event Delivery

Phase 3 adds the incident-response and assurance layer on top of Phase
2: transactional emergency controls (kill-switch / resume / revoke /
terminate), run budget policies with fail-closed enforcement, a
tamper-evident evidence read model with offline verification and
checkpoints, a transactional webhook outbox for security events, and
W3C traceparent telemetry with Prometheus metrics.

| | |
|---|---|
| Schema | `migrations/016_create_emergency_evidence_outbox.{up,down}.sql` |
| Implementation | `services/query-runtime/internal/governance` (`service_phase3.go`, `store_phase3.go`) |
| Delivery worker | `services/query-runtime/internal/outbox/worker.go` |
| Telemetry | `services/query-runtime/internal/telemetry/trace.go` (dependency-free W3C traceparent) |
| Metrics | `services/query-runtime/internal/metrics/metrics_phase3.go` (`RegisterPhase3`) |
| HTTP surface | `internal/runtime/governance_api.go` + routes in `server.go` |
| Console | `apps/console/app/console/page.tsx` ("Incident Response" view) |

## Endpoints

Same auth rules as Phase 2: `governance` API-key scope (admin override
included), tenant/region from the key context only, reads identity-free,
mutations requiring a verified end-user assertion.

| Method | Path | Identity | Notes |
|---|---|---|---|
| `POST` | `/v1/governance/agents/{agent_id}/kill-switch` | verified | Kill-switch an agent (fail-closed for all tools) |
| `POST` | `/v1/governance/agents/{agent_id}/resume` | verified | Resume a kill-switched agent |
| `POST` | `/v1/governance/agent-versions/{version_id}/kill-switch` | verified | Kill-switch one agent version |
| `POST` | `/v1/governance/agent-versions/{version_id}/resume` | verified | Resume the version |
| `POST` | `/v1/governance/tools/{tool_id}/kill-switch` | verified | Kill-switch a tool |
| `POST` | `/v1/governance/tools/{tool_id}/resume` | verified | Resume the tool |
| `POST` | `/v1/governance/delegations/{grant_id}/revoke` | verified | Revoke a delegation grant (irreversible) |
| `POST` | `/v1/governance/runs/{run_id}/terminate` | verified | Terminate a run (irreversible) |
| `GET` | `/v1/governance/emergency-controls` | — | List current control state per entity |
| `POST` | `/v1/governance/budgets` | verified | Upsert a budget policy (tenant / agent_version / grant scope) |
| `GET` | `/v1/governance/budgets/effective?agent_version_id=&grant_id=` | — | Effective policy (narrowest applicable) |
| `GET` | `/v1/governance/budgets` | — | List budget policies |
| `GET` | `/v1/governance/evidence` | — | Evidence read model: `from/to/agent_id/agent_version_id/owner_principal/user_id/tool_id/action_id/run_status/decision/reason_code/trace_id/kinds/cursor/limit` |
| `GET` | `/v1/governance/evidence/{evidence_id}` | — | Single evidence event |
| `GET` | `/v1/governance/runs/{run_id}/timeline` | — | Evidence scoped to one run |
| `GET` | `/v1/governance/agents/{agent_id}/activity` | — | Evidence scoped to one agent |
| `GET` | `/v1/governance/audit/verify?create_checkpoint=&checkpoint_id=` | — | Re-verify hash chains; optionally checkpoint |
| `GET` | `/v1/governance/audit/checkpoints` | — | List checkpoints |
| `GET` | `/v1/governance/outbox?status=&limit=&cursor=` | — | List outbox events |
| `POST` | `/v1/governance/outbox/{event_id}/retry` | verified | Re-queue a pending/dead-lettered event |

## Security & behavior notes

1. **Control mutations are audit events.** Every mutation records an
   `emergency_control` evidence event with actor, reason, scope,
   previous and new state. The same-state mutation is an idempotent
   200 no-op; illegal transitions (`revoke` on revoked, `resume` on
   active) are 409.
2. **Kill-switched entities fail closed.** Minting a delegation for a
   kill-switched agent/version returns 409; evaluating any action
   against a kill-switched tool/agent/version is a recorded denial.
3. **Terminated runs deny, not error.** `evaluate` on a terminated run
   returns 200 with `decision: denied`, reason code `run:terminated` —
   the decision is part of the evidence stream.
4. **Budgets enforce transactionally.** The effective policy is the
   narrowest applicable (grant > agent_version > tenant); Phase 2
   `call_limit_per_run` is honored in addition. Exhaustion returns
   `budget_exhausted:<counter>` denials, and `/v1/query` delegation
   charges `max_citations_per_query` (headers `X-Groundwork-Citation-Budget:
   exhausted` on exhaustion).
5. **Evidence read model never leaks secrets** — identifiers, digests,
   and safe metadata only; never tokens, assertions, or content.
6. **Outbox events are signed webhooks.** `POST` to
   `GROUNDWORK_OUTBOX_WEBHOOK_URL` with
   `X-Groundwork-Signature: v1=<HMAC-SHA256("v1:<ts>:<event_id>:<body>")>`
   using `GROUNDWORK_OUTBOX_WEBHOOK_SECRET`. Receivers verify with
   `outbox.VerifySignature`. Delivery: exponential backoff (base 1s,
   cap 5m), `MaxAttempts` (default 8) then `dead_letter`. The worker
   runs only when the webhook URL is set AND the store implements
   `OutboxDeliveryStore`; events are also surfaced via
   `GET /v1/governance/outbox` with manual `retry`.
7. **Agent lifecycle events feed the outbox** — create/version/
   transition events are enqueued in the same transaction as the state
   and evidence writes.
8. **Telemetry & metrics** — the HTTP server parses/emits W3C
   `traceparent` (`internal/telemetry`) and logs
   `trace <id> <method> <path> (<duration>)`; `RegisterPhase3()` adds
   `groundwork_control_events_total`, `groundwork_budget_exhaustions_total`,
   `groundwork_audit_verify_total`, `groundwork_evidence_events_total`,
   `groundwork_outbox_delivered_total`, `groundwork_outbox_dead_letter_total`,
   and the `groundwork_outbox_pending` gauge on `/metrics`.

## Verification

```sh
cd services/query-runtime
go test ./internal/governance/... ./internal/runtime/... ./internal/outbox/... ./internal/telemetry/...
python ../scripts/check_migrations.py    # migration gate (003..016)
cd apps/console && npm run build         # console (Incident Response view)
```

`internal/runtime/governance_api_phase3_test.go` covers the HTTP
surface: control idempotency and fail-closed minting, run termination
denials, budget exhaustion cascades, evidence filtering + checkpointed
verification, and outbox list/retry with tenant isolation.

---

# Phase 4 — Sovereign Multi-Region Deployment (Regions, OIDC, Keyring, Exports)

Phase 4 turns the governed-runtime story into a **sovereign
multi-region enterprise deployment**: tenants are pinned to regions with
enforced data-jurisdiction rules, end-user identity comes from an
enterprise OIDC provider (with its own signing keys, never the demo
JWT), customer-managed key material is registered and audited through a
purpose-scoped keyring, and the evidence ledger can be assembled into
regulatory **framework exports** (EU AI Act, GDPR, DORA, ISO/IEC 42001,
NIST AI RMF, UK/US customer policy).

| | |
|---|---|
| Region model | `services/query-runtime/internal/deployment` (`region.go`, `validate.go`, `tenants.go`, `env.go`) |
| Identity | `internal/runtime/oidc.go` (OIDC verifier) + `internal/runtime/identity.go` (`BuildIdentityVerifier`, `Provisioner`) |
| Keyring | `services/query-runtime/internal/keyring` |
| Exports | `services/query-runtime/internal/exports` + `internal/runtime/governance_exports.go` |
| Sovereign compose | `deploy/sovereign/` (`docker-compose.sovereign.yml`, `.env.{eu,uk,us}.example`, `nginx/nginx.sovereign.conf`) |
| Schema | `migrations/017_create_deployment_registry.{up,down}.sql` |
| Console | `apps/console/app/console/page.tsx` ("Incident Response" → Evidence Exports card) |

## Region & jurisdiction model

- `GROUNDWORK_DEPLOYMENT_REGION` selects the deployment's home region
  (`eu-central-1` / `uk-south-1` / `us-west-2`); `GROUNDWORK_JURISDICTION`
  its law. Per-service regions (`GROUNDWORK_POSTGRES_REGION`,
  `GROUNDWORK_SPICEDB_REGION`, `GROUNDWORK_QDRANT_REGION`,
  `GROUNDWORK_ELASTICSEARCH_REGION`, `GROUNDWORK_BACKUP_REGION`,
  `GROUNDWORK_TELEMETRY_REGION`, `GROUNDWORK_KMS_REGION`,
  `GROUNDWORK_MODEL_ENDPOINT_REGION`) let each component stay inside the
  tenant's jurisdiction.
- Tenants are pinned via `GROUNDWORK_TENANT_<name>_REGION`; a tenant may
  only act in its own region. `GROUNDWORK_JURISDICTION` must be one of
  `eu` / `uk` / `us` and the region must belong to it.
- **Transfer policies** (`GROUNDWORK_TRANSFER_POLICIES`:
  `from_region=region,to_region=region,policy=allowed|blocked|requires_approval,reason=...`)
  gate cross-region data flows; without an explicit `allowed` entry the
  transfer is blocked. `GROUNDWORK_EGRESS_ALLOWLIST` restricts outbound
  egress.
- Startup validation (`deployment.Validate` with `Production: true,
  StrictKeys: true, ApprovedEgressOnly: true`) runs only when
  `GROUNDWORK_DEPLOYMENT_REGION` is set — any problem is a fatal error.
- Deployment metadata is persisted by migration 017 (`tenant_regions`,
  `key_material_registry`) as the operator-facing source of truth.

## OIDC enterprise identity

When `GROUNDWORK_OIDC_ISSUER` (+ `GROUNDWORK_OIDC_AUDIENCE`,
`GROUNDWORK_OIDC_CLIENT_ID`, `GROUNDWORK_OIDC_ADMIN_ROLES`) is set,
`BuildIdentityVerifier()` builds an OIDC verifier **before** falling
back to the shared JWT/HS keys — OIDC takes priority.

- Startup discovery + JWKS fetch; an unreachable or inconsistent issuer
  prevents startup. Tokens must carry `kid` and `alg` in the JOSE
  header, be signed with an allowed algorithm (RS256/ES256/RS384/ES384),
  match issuer/audience, and be unexpired with a sane `nbf`.
- The **canonical principal** is `preferred_username` (else `sub`);
  tenancy comes only from the API-key context. OIDC issuers must be
  HTTPS, OIDC auto-discovery must exist, and a token must be `id_token`
  or bearer-token typed.
- `Provisioner`/`NoopProvisioner` abstract principal provisioning
  (SCIM planned); the noop returns "principal provisioning is not
  configured (SCIM not enabled)" so identity works without a provisioner.
- `scripts/validate-non-bypassable.{sh,ps1}` verifies the runtime is
  never started in demo identity mode with a deployment region set.

## Customer-managed keyring

`internal/keyring` registers key material per **purpose**:
`identity`, `delegation`, `webhook`, `audit_digest`, `database`,
`backup` (env map in `keyring.NewEnvProvider()`: OIDC issuer **or**
HS secret for identity; delegation RS key or HS secret; outbox webhook
secret; audit digest key; `GROUNDWORK_DATABASE_KEY_ID` /
`GROUNDWORK_BACKUP_KEY_ID` as `key_id_reference`).

- Missing required purposes fail closed: in a sovereign deployment the
  runtime refuses to start; otherwise it logs and runs in demo mode.
- `Keyring.Rotate` records an in-memory `Rotation` ledger (audit trail
  only — material stays in the provider); env providers return
  `ErrRotationUnsupported`. `ExternalProvider` adapts external KMS-style
  stores and fails closed on any error.
- Migration 017's `key_material_registry` persists purpose/key-id/source
  metadata so rotation history survives restarts.

## Framework evidence exports

`GET /v1/governance/exports/{framework}` (governance scope, read-only)
assembles the evidence ledger into a framework report:

- Frameworks: `eu_ai_act`, `gdpr`, `dora`, `iso_42001`, `nist_ai_rmf`,
  `uk_customer_policy`, `us_customer_policy`. Region/jurisdiction come
  only from the TenantContext; `from`/`to` are RFC3339 window bounds
  (default trailing 90 days; `to` is exclusive).
- Controls report `satisfied` / `partially_met` / `no_evidence` /
  `chain_unverified` status per control with evidence refs and
  `chain_verification` of the underlying hash chains; unknown framework
  → 400 `unknown_framework`.
- Console: the **Evidence Exports** card in the Incident Response view
  (framework selector, status badges, evidence rows, limitations).
  Without a live runtime the proxy serves a curated demo export (never
  fabricated control claims); mutations are never demo-faked.

## Verification

```sh
cd services/query-runtime
gofmt -l internal cmd && go build ./... && go vet ./...
go test ./...                                  # incl. runtime, deployment, keyring, exports, governance
cd ../.. && python scripts/check_migrations.py # migration gate (003..017)
bash scripts/validate-non-bypassable.sh -EnvFile deploy/sovereign/.env.eu.example
docker compose -f deploy/sovereign/docker-compose.sovereign.yml --env-file deploy/sovereign/.env.eu.example config -q
cd apps/console && npm run build               # console (Incident Response → Evidence Exports)
```

Phase 4 test coverage: OIDC verifier 14 cases (happy path, canonical
claim, tenant allowlist, tampered/expired/wrong-issuer/wrong-audience,
kid/alg validation, unreachable issuer, admin-role gating),
deployment env parsing (13), keyring (10), exports profiles (6), and
the exports HTTP surface (4).

---

# Multi-Agent Delegation & External-Agent Trust (Phase 6)

Phase 6 extends the delegated-authority model to **multi-agent trust**:
explicit trust edges between agents, agent-to-agent delegation chains
(attenuated, bounded, revocable end-to-end), external (partner /
customer) agent onboarding with verified identity, customer consent,
cross-region transfer policies, external budgets, and evidence
provenance.

Central rules (all fail closed):

- A child agent never receives more authority than its parent; child
  expiry never exceeds parent expiry; parent revocation invalidates
  every descendant.
- Cross-tenant and cross-region delegation are denied by default.
  Cross-region requires an explicit, enabled transfer policy.
- External agents are untrusted by default. Every run requires a
  validated identity (issuer, audience, signature, jti) plus an active
  trust relationship plus customer consent.
- Tenant, region, external-agent identity, and customer principal come
  ONLY from verified authentication context — never from request bodies.

| | |
|---|---|
| Schema | `migrations/019_create_agent_trust`, `020_phase6_trust_schema_fix`, `021_phase6_api_surface` |
| Service | `internal/governance/service_trust.go` (+ store_trust.go) |
| DTOs | `internal/runtime/trust.go` |
| HTTP surface | `internal/runtime/governance_api_phase6.go` + routes in `server.go` |
| MCP surface | `internal/mcp/governance_tools.go` (governance_* tools) |
| Console | `apps/console` "Multi-Agent Trust" view + `/api/governance/*` proxy |

## REST endpoints

All require the `governance` API-key scope; reads need no identity,
mutations require a verified end-user assertion, and every mutation
requires an `Idempotency-Key` header.

```text
Trust relationships
  POST /v1/governance/trust-relationships
  GET  /v1/governance/trust-relationships
  GET  /v1/governance/trust-relationships/{relationship_id}
  POST /v1/governance/trust-relationships/{id}/{approve|activate|suspend|resume|revoke}

Delegation chains
  GET  /v1/governance/delegations
  GET  /v1/governance/delegations/{grant_id}/chain
  POST /v1/governance/delegations/{grant_id}/chain/{revoke|suspend|resume}
  GET  /v1/governance/runs/{run_id}/delegation-chain
  GET  /v1/governance/evidence/{evidence_id}/provenance

External agents
  POST /v1/governance/external-agents
  GET  /v1/governance/external-agents
  GET  /v1/governance/external-agents/{external_agent_id}
  GET  /v1/governance/external-agents/{external_agent_id}/health
  POST /v1/governance/external-agents/{external_agent_id}/{activate|suspend|revoke}

External runs (authenticated by the external identity token)
  POST /v1/governance/external-runs
  GET  /v1/governance/external-runs
  GET  /v1/governance/external-runs/{run_id}
  POST /v1/governance/external-runs/{run_id}/terminate

Consent
  POST /v1/governance/consents
  GET  /v1/governance/consents
  GET  /v1/governance/consents/{consent_id}
  POST /v1/governance/consents/{consent_id}/revoke

Transfer policies
  POST /v1/governance/transfer-policies
  GET  /v1/governance/transfer-policies
  POST /v1/governance/transfer-policies/{policy_id}/{activate|suspend|revoke}

External budgets
  GET  /v1/governance/external-budgets
  PUT  /v1/governance/external-budgets/{external_agent_id}
```

## MCP surface

The MCP server (`internal/mcp/governance_tools.go`) exposes the same
Phase 6 operations as `governance_*` tools over both stdio and `/mcp`:

- `governance_trust_relationship_list/get/create/transition`
- `governance_delegation_chain` / `governance_delegation_chain_control`
- `governance_external_agent_list/get/onboard/transition`
- `governance_consent_list/create/revoke`
- `governance_transfer_policy_list/upsert/transition`
- `governance_external_budget_list/upsert`
- `governance_evidence_provenance`

Security model matches REST: tenant/region come from the transport
context, mutations require a verified `user_token` (fail closed
otherwise), the actor is the canonicalized token subject, and the admin
flag comes from the verified identity's configured admin role — never
from tool arguments.

## Console

The **Multi-Agent Trust** view (`apps/console/app/console/page.tsx`)
shows trust edges, external agents, consent records, transfer
policies, external budgets, delegation chains, and evidence
provenance. Reads fall back to curated demo data when the runtime is
unreachable; mutations never demo-fake and require a live runtime.

## Verification

```sh
cd services/query-runtime
gofmt -l internal cmd && go build ./... && go vet ./...
go test ./...   # includes governance + runtime + mcp Phase 6 tests
cd ../.. && python scripts/check_migrations.py   # gate 003..021
cd apps/console && npm run build                 # Multi-Agent Trust view
```

