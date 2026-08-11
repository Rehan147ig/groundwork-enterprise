# Groundwork Production Scale Roadmap and Knowledge Transfer

## Purpose of This Document

This document is the implementation handoff for coding agents working on Groundwork after Phase 6.

It explains:

- what Groundwork is and why it exists;
- what is already implemented through Phase 6;
- what is required to make the product usable by SMEs, mid-market customers, and enterprises;
- what to build from Phase 7 onward, with Phase 8 as the production-scale milestone;
- how multi-agent systems must be modeled in real enterprises;
- which security invariants may never be weakened;
- how to prioritize integrations, reliability, developer experience, and commercial readiness.

Read this document and `KT.md` before editing the repository.

## Product Definition

Groundwork is the runtime trust, authorization, and evidence layer for enterprise AI agents.

Before an agent retrieves private data or invokes a tool, Groundwork decides whether the action is allowed using trusted tenant, identity, agent, run, delegation, policy, resource, region, purpose, approval, and budget context. It blocks actions that cannot be proven authorized and writes tamper-evident evidence for every decision.

The product is not:

- a chatbot;
- a RAG framework;
- an LLM provider;
- an IAM replacement;
- a GRC documentation-only product;
- a prompt-injection-only product.

The product is the security boundary between agents and enterprise data/tools.

```text
Agent / workflow / MCP client
        |
        v
Groundwork authorization and connector gateway
        |
        +--> trusted identity and tenant resolution
        +--> agent/run/delegation validation
        +--> relationship authorization (SpiceDB)
        +--> contextual policy, region, approval, budget checks
        +--> controlled data retrieval or tool invocation
        +--> redaction and response controls
        +--> immutable evidence and operational telemetry
        v
Permitted result only
```

## Why Customers Need Groundwork

Enterprise agents can retrieve confidential information, call APIs, modify records, send messages, deploy code, approve transactions, or delegate work to other agents. Standard identity systems and static permissions are not enough because the final decision depends on runtime context.

Groundwork addresses these questions:

```text
Can this verified principal, through this exact agent version,
in this run, with this delegated authority, use this action,
against this resource, in this region, for this purpose, now?
```

Without Groundwork, companies face:

- overly broad agent permissions;
- stale access after role or employment changes;
- direct backend bypasses;
- unbounded tool use;
- no auditable approval chain;
- no reliable multi-agent provenance;
- inability to prove why an action was allowed;
- blocked AI deployments due to security, privacy, and risk concerns.

Groundwork allows organizations to deploy agents without trusting the agent framework or model to enforce enterprise permissions correctly.

## Customer Segments and Product Requirements

### SME and startup teams

Typical profile:

- 1 to 10 agents;
- small engineering/security team;
- uses hosted model providers and SaaS tools;
- needs secure adoption without operating SpiceDB, PostgreSQL, Kubernetes, or policy infrastructure.

What they need:

- hosted Groundwork Cloud;
- 15-minute quick start;
- SDK wrappers and copy-paste examples;
- one-command Docker local demo;
- default-safe read-only policies;
- simple agent/tool registration;
- GitHub, Slack, Google Drive, and generic MCP/REST integration;
- basic activity and deny feed;
- one-click revoke/suspend;
- usage-based limits and clear pricing;
- no policy-language knowledge required.

SME product promise:

> Add Groundwork to an agent in minutes and prevent it from accessing data or tools outside its approved scope.

### Mid-market

Typical profile:

- several teams running agents;
- sensitive customer or employee data;
- Entra, Okta, or Google Workspace identity;
- security team but limited platform engineering capacity.

What they need:

- SSO and team-based administration;
- dev/staging/production separation;
- policy templates and shadow mode;
- approval workflows;
- agent inventory and ownership;
- core connector catalogue;
- Slack/Jira/PagerDuty notifications;
- evidence exports;
- budget/rate controls;
- managed deployment and support;
- migration path from basic to advanced controls.

Mid-market product promise:

> Move agents from observation to controlled production without rebuilding the existing AI stack.

### Enterprise and regulated organizations

Typical profile:

- many internal, customer-facing, vendor, and workflow agents;
- multiple business units and regions;
- regulated data and consequential tools;
- formal security, compliance, procurement, and audit functions.

What they need:

- SaaS, dedicated tenant, BYOC, private cloud, and self-hosted options;
- EU, UK, and US regional deployment;
- private networking, default-deny egress, and non-bypassable topology;
- BYOK/HYOK, KMS/HSM, key rotation, and secret lifecycle controls;
- SSO, SCIM, service accounts, workload identity, and administrative separation;
- HA, backup/restore, disaster recovery, capacity planning, and SLOs;
- policy-as-code, policy review, simulation, CI tests, and rollback;
- SIEM/SOC/ITSM integration;
- custom connectors and connector SDK;
- audit evidence exports and immutable archive options;
- multi-agent graph, external-agent trust, partner/customer boundaries, consent, and data-transfer controls;
- professional services, security documentation, and support.

Enterprise product promise:

> Let the enterprise deploy agents into sensitive systems while retaining live control, sovereignty, revocation, and provable evidence.

## Current Product State

### Completed through Phase 6

- Agent registry, agent versions, ownership, lifecycle, and audit history.
- Delegated authority, run binding, approval gates, replay protection, and agent-tool grants.
- Shared REST/MCP/query/connector authorization evaluator.
- SpiceDB live relationship checks with fail-closed behavior.
- Emergency controls, kill switches, budgets, evidence explorer, audit verification, checkpoints, and transactional outbox.
- Region/jurisdiction model, OIDC/JWKS direction, key material registry, deployment registry, and evidence exports.
- Generic REST and MCP connector gateway, connector lifecycle, egress allow-listing, response redaction, and invocation evidence.
- Phase 6 trust/external-agent persistence and REST/MCP/console API work.

### Phase 6 completion caveat

Phase 6 now passes a live integration run against the real
PostgreSQL/SpiceDB stack: the full integration suite
(`test/integration/`) is green (14/14), including the trust/external-agent
lifecycle, delegation chains, consent, transfer-policy, budget, and
external-run flows. The caveat below is resolved; run the suite before
declaring any governance change complete:

```powershell
go test -tags integration ./test/integration/...
```

### Existing core stack

- Go runtime and governance services
- PostgreSQL
- SpiceDB
- Qdrant
- Elasticsearch
- Next.js console
- Python ingestion service
- REST and MCP gateways
- Generic REST and external MCP connectors
- OpenTelemetry-compatible metrics/traces
- transactional Postgres outbox

## Non-Negotiable Security Invariants

1. Fail closed on missing, invalid, stale, unavailable, revoked, timed-out, or conflicting authorization state.
2. Tenant and region are trusted runtime context, never body fields.
3. Identity must come from verified OIDC/JWKS, mTLS, trusted API key context, or explicitly gated demo mode.
4. Every protected query, REST call, MCP call, and connector invocation uses the same shared evaluator.
5. SpiceDB remains the relationship authorization source of truth.
6. No public direct path to protected Qdrant, SpiceDB, PostgreSQL, Elasticsearch, or connector backends in production.
7. A revoked parent agent/grant must invalidate descendants on the next action.
8. No raw JWT, delegation token, secret, user assertion, or unauthorized source data appears in logs, evidence, webhook payloads, API responses, or console data.
9. Every lifecycle change, decision, denial, approval, revocation, connector invocation, transfer decision, and security failure produces immutable evidence.
10. Read-only demo fallback is acceptable only for unavailable development/demo backend reads. Mutations must never fabricate state.
11. Do not create a second authorization path in handlers or connectors. Services and the shared evaluator are authoritative.

## End-State Product Architecture

```text
                    Groundwork Control Plane
  ----------------------------------------------------------------
  Tenant, identity, agent registry, policy, trust graph, evidence,
  connector catalog, deployment config, billing, support, analytics
  ----------------------------------------------------------------
                               |
                               v
                    Groundwork Regional Data Plane
  ----------------------------------------------------------------
  API/MCP gateway -> evaluator -> SpiceDB/context policy -> connectors
  query runtime -> retrieval filtering -> audit/evidence/outbox/telemetry
  ----------------------------------------------------------------
                               |
                               v
  Agents, workflow engines, external agents, MCP clients, data/tools
```

Design principle:

- The control plane can be centrally managed.
- The data plane must be region-aware and deployable per customer jurisdiction.
- Sensitive resource retrieval and tool invocation occur through the regional data plane.
- Evidence and telemetry must follow tenant/jurisdiction policy.

## Multi-Agent Model: Beyond Parent and Child

Enterprise workflows are not only a single parent agent delegating to a single sub-agent.

Real patterns include:

```text
Human -> coordinator -> research agent
                    -> finance agent
                    -> compliance agent

Workflow engine -> planner -> multiple specialist agents
                           -> tool agents

Partner agent -> customer tenant agent -> internal workflow agent

Supervisor agent -> retry/recovery agent -> restricted remediation tool
```

Groundwork must model a directed, auditable authority graph, not only a tree.

### Required graph concepts

- Agent identity and version
- Agent owner
- Organization and tenant
- Trust domain
- Run/session
- Root authority grant
- Delegation edge
- Parent grant and child grant
- Scope attenuation
- Resource and tool authority
- Purpose
- Region
- Consent
- Approval
- Budget
- Lifecycle state
- Evidence/provenance event

### Required graph rules

1. Every action has one root authority source: human principal, service principal, or explicitly authorized system policy.
2. Every delegation edge must be explicit, time-bounded, and auditable.
3. A child can receive only a subset of the parent scope.
4. Delegation depth is bounded by policy.
5. Cycles are forbidden. An agent cannot indirectly delegate authority back to itself.
6. Fan-out is permitted only when parent policy allows it and budgets are split or inherited safely.
7. Fan-in requires a new evaluated decision; two agents cannot combine permissions to create broader authority.
8. A downstream agent cannot use another agent's grant.
9. Parent suspension/revocation invalidates all descendants.
10. A run may include multiple related agents, but every tool action must identify the acting agent and exact delegation edge.
11. Cross-tenant, cross-organization, and cross-region edges are denied by default.
12. Cross-organization workflows require explicit trust, transfer, consent, and contract/purpose context.

### Future graph capabilities

- Visual trust graph and run graph
- Blast-radius preview before agent activation
- "Who can reach this tool/resource?" reverse authorization query
- Orphan-agent and orphan-delegation detection
- Privilege-escalation path detection
- Policy simulation across a workflow graph
- Revocation impact preview
- Multi-agent budget allocation
- Agent reputation/risk posture based on deterministic evidence signals

Do not use AI-generated risk scores as authorization truth. Deterministic policy remains authoritative.

## Phase 7: Developer Experience and Adoption

Phase 7 should be completed before broad scale work. It makes the existing system adoptable.

### Goal

Protect a first agent in less than 15 minutes while keeping enterprise-grade paths available.

### Required work

- `groundwork init` CLI that creates a local configuration and safe starter policy.
- `groundwork doctor` CLI that verifies identity, region, network, keys, SpiceDB, audit, and connector configuration.
- One-command Docker Compose demo.
- Hosted quick-start flow.
- SDKs: TypeScript, Python, Go first; Java and .NET next.
- OpenAPI specification and generated client strategy.
- MCP client/server quick starts.
- Agent-framework recipes: generic HTTP/MCP first, then LangGraph, Semantic Kernel, OpenAI Agents SDK, LlamaIndex, CrewAI, AutoGen, and cloud agent platforms only after demand validation.
- Agent and connector registration wizard.
- Read-only-safe starter policy templates.
- Shadow mode onboarding with explainable "would allow/would deny" results.
- Policy simulator and decision explainer.
- Local sample applications: internal assistant, customer support agent, multi-agent workflow.
- Usage metering and tenant usage limits.
- Starter docs, API reference, architecture guide, troubleshooting guide, and migration guide.

### Completed (first dev-experience bundle)

- `groundwork init` CLI — scaffolds `groundwork.env` (generated HS
  secrets), an RSA-2048 delegation key pair, a validated starter policy
  (`policy.json`), and a README
  (`services/query-runtime/cmd/groundwork`).
- `groundwork doctor` CLI — checks deployment rules (fail-closed
  `deployment.Validate`), identity keys, delegation authority, tenancy,
  database (ping + schema tables), SpiceDB, Qdrant, Elasticsearch, the
  outbox webhook, and shadow mode; supports `--env-file` and `--json`;
  exits non-zero on any failure (CI/rollout gate).
- Six read-only-safe starter policy templates (internal knowledge,
  customer support, developer agent, finance agent, healthcare
  assistant, read-only research) — see `docs/policy-templates.md`.
- OpenAPI specification covering the full registered route surface
  (health, query, admin, audit, agents, governance, connectors, trust)
  at `docs/openapi/groundwork.yaml`.
- TypeScript SDK (`packages/typescript`, `@groundwork/sdk`): zero-dep
  typed client for the full API surface, HS256 assertion helper,
  `GroundworkError` envelope semantics, 8 unit tests + 33-check live
  smoke suite — see `docs/client-strategy.md`.
- Python SDK (`packages/python`, `groundwork-sdk`): stdlib-only mirror of
  the TypeScript surface — same envelopes, error semantics, HS256
  assertion helper, injectable transport; 8 unit tests + 33-check live
  smoke suite.
- Go SDK (`packages/go`, `groundwork/sdk`): stdlib-only mirror of the
  TypeScript surface — typed request/response structs with snake_case
  JSON tags, `GroundworkError` semantics, `MintUserAssertion`; 8 unit
  tests + 33-check live smoke suite (`TestLiveSmoke`, gated on
  `GW_BASE_URL`).
- Policy simulator and decision explainer: read-only
  `POST /v1/governance/simulate` walks the shared evaluator's gate
  pipeline and explains every gate (would-allow/would-deny/
  approval-required/fail-closed) without writing anything — 13 unit
  tests + 3 HTTP tests incl. the no-write invariant, SDK
  `simulateAction()` client, OpenAPI path + schemas, docs in
  `docs/governance.md`.
- Local sample applications: `examples/bank-demo/` (synthetic banking
  corpus, personas, SpiceDB permissions, Java + SDK clients, one-command
  compose demo) and `examples/github-demo/` (repo analysis workflow).
- Usage metering and tenant usage limits: per-tenant quota enforcement
  across agents, runs, decisions, connector calls, exports, outbox
  delivery, and storage bytes with monthly/lifetime counters, atomic
  check-and-increment recording (fail-closed at agents create, query,
  run/evaluate/dispatch/exports), a usage API
  (`GET /v1/usage`, `GET/PUT /v1/usage/limits`), memory + Postgres
  stores (migration 025), SDK methods in all three clients, OpenAPI
  paths, and docs in `docs/usage-metering.md`.
- Per-tenant rate and concurrency limits: fixed-window RPM limiter
  (429 `rate_limit_exceeded` + `Retry-After`) and a non-blocking
  concurrency cap (503 `concurrency_limit_exceeded`), configurable via
  `LIMIT_RPM_PER_TENANT` / `LIMIT_CONCURRENCY_PER_TENANT`, enforced at
  the HTTP layer before execution, health endpoints exempt, memory-only
  per-instance implementation, unit + HTTP + real-stack integration
  tests, OpenAPI 429/503 responses, and docs in
  `docs/rate-and-concurrency-limits.md`.
- KT.md and this roadmap copied into the repository
  (`docs/KT.md`, `docs/production-scale-roadmap.md`).

Still open from the Phase 7 list: hosted quick-start flow, MCP
client/server quick starts, agent-framework recipes, agent/connector
registration wizard, and the API reference rendered from the OpenAPI
spec.

### Success criteria

- A developer protects a demo agent in under 15 minutes.
- A customer connects an IdP and one connector in under one day.
- An operator can explain any allow/deny result without reading source code.
- A user can switch from shadow to enforce mode through an approval workflow.

## Phase 8: Production Scale and Reliability

### Goal

Operate Groundwork as a reliable authorization and evidence platform for many tenants, many agents, and high-consequence workloads.

### 8.1 Multi-tenancy and isolation

- Define explicit tenant partition strategy for PostgreSQL, SpiceDB stores/models, Qdrant collections, Elasticsearch indexes, audit partitions, object storage, and telemetry.
- Support shared multi-tenant, dedicated tenant, BYOC, and self-hosted deployment tiers.
- Add tenant provisioning/deprovisioning workflows with audit evidence.
  [implemented — operator-managed tenant directory (`docs/tenant-provisioning.md`):
  `POST /v1/admin/tenants` provision (optional one-time admin key),
  disable/enable, non-destructive deprovision (no delete route), list/get/
  events; hash-chained write-once lifecycle evidence (migration 027); the
  auth layer fails closed for disabled/deprovisioned tenants via the
  TenantDirectory check; GROUNDWORK_TENANT_REGIONS tenants are seeded at
  startup and the dormant tenant_regions table (migration 017) is kept in
  sync]
- Add per-tenant quotas for agents, runs, decisions, connector calls,
  storage, exports, and outbox delivery.
  [implemented — `docs/usage-metering.md`; atomic check-and-increment
  counters deny 403 quota_exceeded:<metric>. connector_calls is
  enforced inside DispatchAction BEFORE any outbound connection (the
  denial is recorded as invocation evidence); outbox_deliveries via the
  worker's PreDeliver gate (over-quota events stay pending, no attempt
  consumed); storage_bytes fail-closed at export time (payload fully
  materialized before streaming); the dispatch response volume remains
  metered best-effort because it is unknowable before the outbound call]
- Add noisy-neighbor protections, connection pools, rate limits, and concurrency limits.
  [implemented — rate + concurrency limits: `docs/rate-and-concurrency-limits.md`;
  connection pools + overload protection: `docs/backpressure-and-overload.md`]
- Verify tenant deletion/retention workflow only after legal and customer requirements are defined; do not add destructive delete by default.
  [implemented — no delete path exists; deprovisioning is the terminal,
  non-destructive lifecycle state, and only re-provisioning can revive a
  tenant]

### 8.2 Availability and performance

Build and test:

- High-availability PostgreSQL deployment model.
- Persistent, high-availability SpiceDB deployment model.
- Qdrant backup/recovery and re-index behavior.
- Elasticsearch recovery where it remains on the query path.
- Connection pool configuration and overload protection.
  [implemented — `docs/backpressure-and-overload.md`: shared HTTP pool
  (GROUNDWORK_HTTP_POOL_*) for SpiceDB/connector/webhook clients,
  instance-wide overload cap (OVERLOAD_MAX_CONCURRENT_REQUESTS → 503
  overload_exceeded), outbox high-water mark (OUTBOX_BACKPRESSURE_MAX_PENDING
  → 503 outbox_backpressure at every evidence boundary)]
- Circuit breakers and bounded retries.
  [implemented — bounded retries: connector `RetryMax` (idempotent-only),
  outbox worker exponential backoff then dead-letter; circuits:
  retrieval/ACL/audit/SpiceDB breakers (Phase 3/PR #22), plus the
  Phase 8.2 dispatch circuits (`docs/dispatch-circuit-breakers.md`):
  per-connector fail-fast on the outbound call (connector_breaker_open
  evidence, only transport errors/5xx trip it) and a per-tenant
  outbox-delivery circuit (events stay pending, no attempt consumed,
  probe closes on recovery)]
- Request deadlines for every external dependency.
- Backpressure when audit/outbox dependencies are constrained.
  [implemented — `docs/backpressure-and-overload.md`: outbox high-water
  gate refuses new work fail-closed (503 outbox_backpressure) at audit
  writes, evaluate, dispatch, and delegated query; fail-closed by
  default, off until configured]
- Idempotency for every external mutation.
  [implemented — `docs/dispatch-idempotency.md`: every connector-backed
  dispatch carries a semantic key (tenant|run|tool|action|resource|canonical
  args); a client retry of an already-executed mutation is answered from
  immutable evidence (`DispatchMode: "replayed"` — no quota consumed, no
  connector call, no second invocation row) instead of re-calling the
  upstream. The key is forwarded as the `Idempotency-Key` header (REST)
  and the migration 028 partial unique index closes the multi-instance
  race; failed attempts stay retryable]
- Load test suites for query, tool dispatch, delegation, connector, and evidence paths.
  [implemented — `cmd/loadtest` drives all five paths concurrently (`-paths=`), with per-path
  p50/p95/p99/max, fail-closed rate, and repeatable JSON reports;
  `docs/load-testing-and-canary.md`]
- Capacity model per tenant and per deployment tier.
  [implemented — `docs/capacity-model.md`: every tenant carries a
  capacity tier (standard|plus|enterprise) in the tenant directory
  (migration 029); the auth middleware derives the per-tenant in-flight
  cap from the tier (`CapacityModel.ConcurrencyFor`, per-call
  `AcquireWithLimit`), tenants outside the directory use the model
  default, and over-cap requests fail closed with 503
  concurrency_limit_exceeded + Retry-After, counted per tenant
  (`groundwork_tenant_capacity_rejections_total`, warning
  `GroundworkTenantCapacityRefusals`). Caps: LIMIT_CONCURRENCY_PER_TENANT
  (standard/default), CAPACITY_CONCURRENCY_PLUS, CAPACITY_CONCURRENCY_ENTERPRISE]

Initial operating targets to validate, not market before measurement:

```text
Authorization overhead: target p99 < 100 ms for a normal decision path
Revocation: deny on the next action
Availability: 99.9% initial managed target, higher only after proof
Audit: no silent loss; integrity-verifiable chain
```

Never compromise authorization correctness for cache hit rate. Cache only after measuring, with safe invalidation/versioning and fail-closed fallback.

### 8.3 Data durability and recovery

- Backup policy for PostgreSQL, SpiceDB datastore, Qdrant, Elasticsearch, object storage, and key metadata.
- Restore drills with evidence-chain verification after restore.
- Defined RPO and RTO by plan/deployment tier.
- Disaster-recovery runbooks and tested regional recovery process.
- Immutable/WORM archive interface for audit exports and long-term retention.
  [implemented — `docs/worm-archive.md`: content-addressed write-once
  archive (`internal/archive` `WORMStore` interface + filesystem
  backend; blobs created O_EXCL, no delete/update path), append-only
  per-tenant manifest chain with prev/chain digests, fail-closed
  Verify/Open (payload edits, manifest edits, deletion, reordering all
  detected), idempotent re-seal, tenant-scoped; `cmd/archive`
  seal/list/verify/restore CLI with restore-through-verify for restore
  drills, anchorable to governance audit checkpoints
  (source_chain_digest) for evidence continuity]
- Audit-chain checkpoints and cross-store integrity verification.
- Migration compatibility and zero-downtime migration policy.

### 8.4 Security operations

- Vulnerability scanning and dependency update process.
- SBOM generation.
- Signed container images and build provenance.
- Secrets scanning.
- Security incident workflow.
- Penetration-test plan.
- Threat model updates for each new connector and identity mode.
- Break-glass operator access with mandatory reason, expiration, and evidence.
  Implemented (Phase 8.4): `POST /v1/security/break-glass/grants`,
  `GET /v1/security/break-glass/grants`, `GET .../{id}`, and
  `POST .../{id}/revoke` — time-bounded admin keys with hash-chained,
  write-once evidence (migration 026, `internal/breakglass`,
  `docs/break-glass.md`).
- Administrative separation of duties.
  [implemented — `docs/separation-of-duties.md`: the platform operator
  surface is split into distinct API-key roles — `provision` (tenant
  lifecycle), `key_admin` (API-key management), `break_glass` (emergency
  grants) — enforced per route with fail-closed 403 insufficient_scope;
  the legacy `admin` scope still satisfies every role, keys default to
  query-only, and the audit scope stays read-only]
- Customer-facing security and architecture package.

### 8.5 Observability and supportability

- Per-tenant safe metrics, traces, and logs.
  [implemented — the SLO counter surface (below) is tenant-labeled and
  bounded; traces/logs stay secret-free by construction]
- SLO dashboards and alerting.
  [implemented — `groundwork_slo_decisions_total{tenant_id,outcome}`,
  `groundwork_http_requests_total{tenant_id,method,code_class}`,
  `groundwork_connector_errors_total{tenant_id,connector_id,error_code}`;
  `deploy/prometheus/alerting-rules.yml` (fail-closed SLO, denial spike,
  5xx, outbox staleness/dead letters, audit verify failure, key expiry,
  connectors, circuit breakers, SpiceDB, budgets); Grafana dashboard at
  `deploy/grafana/groundwork-overview.json`; all previously-dead Phase 3
  counters (control events, budget exhaustions, audit verify, evidence
  events, outbox delivered/dead-letter/pending) are now emitted]
- Decision latency decomposition: identity, SpiceDB, policy, connector, audit, response.
  [implemented — `groundwork_decision_gate_duration_seconds{tenant_id,gate}`
  histogram with the closed gate set
  controls/grant_binding/agent/permitted/tool/grant/budget/spicedb/approval
  in `internal/governance/service.go` `evaluateInTx`; the timeline endpoint
  already decomposed identity/SpiceDB/connector/audit at the evidence layer]
- Outbox age and delivery health.
  [implemented — worker publishes
  `groundwork_outbox_pending_age_seconds{tenant_id}` and
  `groundwork_outbox_dead_letter_pending{tenant_id}` each cycle via the
  optional `OutboxPendingStats` store capability (memory + Postgres);
  `internal/outbox/worker.go`, `internal/metrics/metrics_phase8.go`]
- Connector health and credential expiry monitoring.
  [implemented — connector health:
  `groundwork_connector_health{tenant_id,connector_id}` set by the
  health probe at `internal/runtime/connectors_api.go`; failed
  dispatches and unhealthy probes also increment
  `groundwork_connector_errors_total{tenant_id,connector_id,error_code}`.
  Credential expiry: `groundwork_connector_credential_expiry_timestamp_seconds`
  and `groundwork_connector_credential_days_until_expiry{tenant_id,connector_id,secret_ref}`
  refreshed on a one-minute cadence by the `CredentialExpiryScanner`
  (`internal/connectors/credential_expiry.go`), dating
  `keyring://<purpose>` references from the keyring (env:// references
  carry no metadata → 0); `GroundworkConnectorCredentialExpiringSoon`
  (warn <30d) and `GroundworkConnectorCredentialExpired` (page) alerts —
  see `docs/credential-expiry-monitoring.md`]
- Key/certificate expiry monitoring.
  [implemented — `groundwork_key_expiry_timestamp_seconds{purpose}` and
  `groundwork_key_days_until_expiry{purpose}` refreshed on a one-minute
  cadence by `cmd/query-runtime` from `Keyring.Expiries`; env providers
  may declare expiries via `GROUNDWORK_<PURPOSE>_KEY_EXPIRY` (RFC3339)]
- Audit-chain verification alerts.
  [implemented — `groundwork_audit_verify_total{tenant_id,outcome}`
  (`verified`/`failed`) emitted by `VerifyAuditChain`
  (`internal/governance/service_phase3.go`); `GroundworkAuditVerifyFailure`
  pages in `deploy/prometheus/alerting-rules.yml`]
- Support bundle export with strict secret and data redaction.
  [implemented — `GET /v1/security/support-bundle` streams a zip
  (manifest/status/keys/outbox/connectors) under admin scope + verified
  identity; expiries only — never key material. Nil-safe 503 when unwired]
- Correlation IDs spanning agent run, connector call, evidence, and support case.
  [implemented — `X-Groundwork-Correlation-Id` accepted (with
  `X-Correlation-Id` fallback), generated, echoed, and stamped as the
  engine trace id so the audit row and logs share the client-visible id]

### Phase 8 acceptance criteria

- Live integration suite passes against real PostgreSQL and SpiceDB.
- Load tests exist and produce repeatable reports.
  [implemented — `cmd/loadtest` (`-mode=seed|setup|load`) covers the query, delegation,
  dispatch, connector, and evidence paths and writes versioned JSON reports
  (`loadtest-report-<timestamp>.json`, `schema_version: 1`); the harness has unit tests
  against an in-process fake runtime (seed idempotency, setup idempotency, all-paths load)]
- Restore drill verifies evidence continuity.
- A disabled SpiceDB, audit store, or key provider denies protected actions safely.
- A noisy tenant cannot exhaust shared runtime capacity.
- Production deployment validation proves protected backends are non-bypassable.
- SLO dashboard shows decision rate, denial rate, fail-closed rate, latency, errors, and outbox health.
  [implemented — decision rate `groundwork_slo_decisions_total`, denial rate
  `{outcome="denied"}`, fail-closed rate `{outcome="fail_closed"}` (5% SLO),
  latency `groundwork_query_latency_seconds` + `groundwork_decision_gate_duration_seconds`,
  errors `groundwork_http_requests_total{code_class="5xx"}` +
  `groundwork_connector_errors_total` + `groundwork_spicedb_unreachable_total`,
  outbox health `groundwork_outbox_pending`/`_pending_age_seconds`/`_dead_letter_pending`;
  see `deploy/grafana/groundwork-overview.json` and `docs/observability.md`]

## Phase 9: Enterprise Integrations and Policy Operations

### Identity integrations

Priority order:

1. Microsoft Entra ID
2. Okta
3. Google Workspace
4. Ping Identity
5. Generic OIDC
6. SCIM provisioning
7. Service accounts and workload identity
8. SPIFFE/SPIRE only when Kubernetes/cross-cluster customer demand justifies it

### Data and tool integrations

Build an SDK and connector certification process first, then own the integrations that customers repeatedly request.

Initial high-value connectors:

1. Microsoft SharePoint and OneDrive
2. Google Drive
3. Slack
4. GitHub and GitLab
5. ServiceNow
6. Salesforce
7. Jira and Confluence
8. PostgreSQL
9. Snowflake, BigQuery, or Databricks based on validated demand
10. AWS, Azure, and GCP administration APIs with strict read/write/destructive separation

Every connector requires:

- least-privilege scopes;
- versioned manifest;
- read/write/destructive risk classification;
- region and data classification metadata;
- resource mapping contract;
- safe retries;
- response limits and redaction;
- health checks;
- secret/KMS integration;
- lifecycle controls;
- audit and evidence coverage;
- connector test suite;
- documented data-flow diagram.

### Policy operations

- Visual policy editor backed by versioned declarative policy.
- Policy templates: internal knowledge assistant, customer support, developer agent, finance agent, healthcare assistant, and read-only research agent.
- Policy simulator before enforcement.
- Shadow mode and comparison view.
- Policy diff, approval workflow, rollback, and scheduled activation.
- Policy-as-code repository support.
- CI policy tests.
- Explainable authorization decisions.
- Reverse queries: which agents can reach this resource/tool?
- Import/export of policy bundles.

SpiceDB manages relationships. Add only one contextual engine, such as OPA or Cedar, when real requirements exceed current evaluator capabilities. Do not run multiple conflicting policy decision engines.

## Phase 10: Agent Discovery, Posture, and Governance

### Goal

Help customers discover and govern agents they did not register manually.

### Required capabilities

- Agent discovery from MCP traffic, API gateway logs, cloud logs, repositories, CI/CD, and known agent frameworks.
- Tool and model/provider discovery.
- Shadow/unmanaged agent detection.
- Agent owner assignment workflow.
- Agent risk classification.
- Agent inventory completeness score.
- Over-privileged agent detection.
- Dormant agent detection.
- Unused connector detection.
- Unowned resource/tool relationship detection.
- Policy drift detection.
- Deployment change detection.
- Compliance evidence completeness score.

Important rule:

- Discovery can create findings and draft records.
- Discovery must never auto-activate an agent or grant authority.

## Phase 11: External Ecosystem and Federated Trust

### Goal

Support customer-facing, partner, vendor, and cross-company agents without weakening tenant boundaries.

### Required capabilities

- External-agent onboarding.
- External organization registry.
- Verified issuer/JWKS/mTLS trust configuration.
- Partner trust agreements and lifecycle.
- Customer consent and purpose records.
- Cross-organization data-transfer policies.
- Tenant-isolated external sessions.
- External-agent rate, budget, and response controls.
- Data-minimization templates.
- Contractually required evidence export.
- Federation standards evaluation, including token exchange only after a clear threat model.

No implicit trust across companies. Every external relationship is default deny.

## Phase 12: Advanced Multi-Agent Controls

### Goal

Make multi-agent systems safe, inspectable, and operationally controllable at enterprise scale.

### Required capabilities

- Directed authorization graph storage and query APIs.
- Delegation cycle detection.
- Fan-out budget allocation.
- Fan-in privilege-escalation prevention.
- Workflow-level risk and budget controls.
- Root-authority trace for every action.
- Multi-agent simulation before deployment.
- Revocation blast-radius preview.
- Workflow kill switch.
- Agent-to-agent protocol enforcement.
- Shared-state access policy.
- Cross-agent data provenance.
- Multi-agent incident timeline.
- Policy constraints for retries, recovery agents, and hand-offs.

Do not permit agents to combine separate grants to synthesize wider authority. Each action must independently satisfy an evaluated policy decision.

## Commercial Product Requirements

### Packaging

Developer:

- local runtime and examples;
- limited connectors/runs;
- basic audit history;
- community support.

Team:

- hosted control plane;
- SSO;
- policy templates;
- common connectors;
- managed evidence;
- alerts;
- support.

Enterprise:

- private/dedicated/BYOC/self-hosted options;
- sovereign region choices;
- private networking;
- BYOK/HYOK;
- SCIM;
- advanced policy operations;
- SIEM/ITSM integrations;
- custom connectors;
- SLO/support;
- compliance exports;
- professional services.

### Sales readiness

Build these non-code deliverables alongside the product:

- security architecture overview;
- data-flow diagrams;
- threat model;
- deployment guide;
- shared-responsibility model;
- vendor security questionnaire package;
- incident-response policy;
- backup/recovery statement;
- privacy and data-processing documentation;
- customer ROI calculator;
- two live demos: internal bank-style agent and external/customer-facing agent;
- competitive positioning by category, not unsupported claims about individual competitors.

## What Not To Build

Do not expand Groundwork into:

- a foundation model;
- a general-purpose chatbot product;
- a general RAG framework;
- a replacement for enterprise IAM;
- a replacement for SIEM/SOC tools;
- a documentation-only GRC platform;
- a custom vector database;
- a custom authorization database;
- a prompt-security product that claims to solve authorization;
- an unbounded connector marketplace before the connector SDK is mature.

Groundwork should integrate with these categories while remaining the runtime authorization and evidence layer.

## Prioritization Framework

Build a feature only when it improves one of three pillars:

| Pillar | Definition | Examples |
| --- | --- | --- |
| Trust | Who/what may act | identity, registry, delegation, external trust, lifecycle |
| Control | What action is allowed | SpiceDB, policy, connector gateway, approval, budgets, revocation |
| Proof | Why it can be trusted | evidence, audit, telemetry, exports, investigation |

For every proposed feature, answer:

1. Which customer segment needs it?
2. Which pillar does it strengthen?
3. Does it improve adoption, security, or commercial viability?
4. Can it be enforced at runtime?
5. Can it be audited?
6. Can it fail closed?
7. Does it increase operational complexity more than customer value?

If the feature does not have a clear answer, defer it.

## Required Engineering Process

Before editing:

1. Read `KT.md`, this file, affected docs, migrations, services, and tests.
2. Inspect existing patterns before designing a new abstraction.
3. Preserve all existing user changes and do not rewrite applied migrations.
4. Write a concise implementation plan.
5. Identify tenant, identity, region, audit, and failure behavior before coding.

While implementing:

- Keep HTTP/MCP handlers thin.
- Keep service layer authoritative.
- Reuse the shared evaluator.
- Use transactions/advisory locks where existing conventions require them.
- Add migrations rather than modifying historical migrations.
- Add focused unit, HTTP/MCP, and live integration tests.
- Maintain redaction and write-once evidence rules.

Before declaring completion:

```powershell
gofmt -l .
go build ./...
go vet ./...
go test ./...
go test -tags integration ./test/integration/...
python scripts/check_migrations.py
```

Then run the console build:

```powershell
cd apps/console
npm run build
```

Also run feature-specific live smoke tests and verify evidence-chain integrity.

## Final Product Vision

Groundwork should become the system of record for enterprise agent trust:

```text
Discover -> Register -> Verify -> Authorize -> Execute
         -> Monitor -> Revoke -> Audit -> Prove
```

The durable differentiator is not a single database or dashboard. It is the combination of live enforcement, delegation-aware multi-agent control, sovereign deployment, high-quality integrations, and evidence that makes agent use safe enough for real enterprise systems.
