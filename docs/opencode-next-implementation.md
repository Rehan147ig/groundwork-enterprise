# Groundwork: Next Implementation Handoff for OpenCode

## Purpose

This is the current implementation brief for the next coding agent. Read this
document, `docs/KT.md`, `docs/production-scale-roadmap.md`, and the code paths
named below before editing.

Groundwork is a runtime authorization and evidence layer for enterprise AI
agents. It must decide whether an exact retrieval or tool invocation is
authorized now. It is not a generic RAG product, IAM replacement, or GRC
product. Its non-negotiable behavior is fail closed: if identity,
authorization, tenancy, region, policy, connector, or durable evidence cannot
be verified, the data or action must not proceed.

## Current Repository State

Repository root:

```text
C:\Users\SHAIK MOHAMMAD REHAN\Downloads\groundwork-master
```

The working tree has substantial uncommitted work. Preserve it. Do not reset,
checkout, revert, or replace existing changes. Inspect `git status --short`
and `git diff` before changing any touched file.

Current authorization backend:

- SpiceDB is the sole active relationship authorization backend.
- The schema source of truth is
  `services/query-runtime/internal/relationship/schema/groundwork.zed`.
- Do not reintroduce OpenFGA. Legacy OpenFGA names in historical migrations or
  documentation are not a reason to add it back.

Core runtime entry point:

```text
services/query-runtime/cmd/query-runtime/main.go
```

Core enforcement sequence:

```text
trusted API key / tenant context
  -> verified end-user or workload identity
  -> tenant and region validation
  -> agent, version, run, and delegation validation
  -> SpiceDB relationship permission check
  -> policy, approval, consent, and budget checks
  -> retrieval or governed connector dispatch
  -> context firewall / redaction
  -> tamper-evident audit evidence
```

Never weaken this sequence. Client-provided tenant IDs, regions, user IDs,
roles, agent IDs, grants, or policy outcomes are untrusted unless verified and
bound by the runtime.

## What Is Implemented

### Identity and console SSO

- Console generic OIDC login: `apps/console/lib/auth.ts`.
- Console role presentation and server-action checks: `apps/console/lib/rbac.ts`
  and `apps/console/app/actions.ts`.
- Runtime JWT/OIDC/JWKS verification: `internal/runtime/identity.go` and
  `internal/runtime/oidc.go`.
- OIDC configuration is documented in `.env.example`.
- Demo identity and in-memory API keys are prohibited outside local/dev.

This is OIDC SSO, not completed SAML or SCIM support.

### Existing production-oriented source path

- Microsoft Entra / Microsoft Graph ACL sync is the most mature real source
  integration. Start from `internal/aclsync/msgraph/`,
  `cmd/msgraph-connector/`, and `docs/microsoft-graph-connector.md`.
- GitHub ACL sync also exists.

### New connector adapters

New packages exist under `internal/aclsync/`:

```text
s3/
gcs/
sharepoint/
notion/
atlassian/       # Confluence
snowflake/
```

They currently map provider-specific permissions into the common
`aclsync.Connector` contract. They are not yet complete production
integrations.

### Other product foundations already present

- Agent registry and lifecycle.
- Governance, grants, delegations, external-agent trust, budgets, and
  provenance.
- REST and MCP interfaces.
- Governed REST/MCP connector gateway.
- Hash-chained audit/evidence, WORM archive, evidence exports, and break-glass.
- Tenant provisioning, quotas, rate limits, concurrency tiers, backpressure,
  circuit breakers, and usage metering.
- Context firewall, hybrid retrieval, and envelope encryption.

## Do Not Claim These Are Complete Yet

The following are scaffolds or incomplete and must not be marketed as
production-ready until their acceptance criteria below pass.

### New source connectors

The new S3, GCS, SharePoint, Notion, Confluence, and Snowflake packages use
injected client interfaces. Most do not yet have real provider HTTP/SDK
clients, OAuth/workload credential setup, persistent cursor state, worker
wiring, or integration tests.

Their `WatchPermissionChanges` implementations currently poll `Snapshot()` and
discard the result. They do not calculate and emit actual
`aclsync.PermissionChange` events. A revoked permission could remain in
SpiceDB until a full reconciliation is explicitly applied.

### SSO and provisioning

- Generic OIDC is implemented.
- SAML is not implemented.
- SCIM is not implemented. `runtime.NoopProvisioner` explicitly confirms this.
- Customer-specific IdP group-to-Groundwork-role mapping is not a finished
  administration feature.
- Workload/service identity onboarding needs a documented customer flow.

### Notifications

`internal/notifications/slack.go` has basic webhook delivery. The break-glass
handler currently uses a placeholder URL, so no customer notification is
actually configured. There are no Slack/Teams interactive approval actions.

### Terraform

`terraform-provider-groundwork/` is only a scaffold. Resource CRUD methods are
TODOs. Do not publish or advertise it until it has a working provider client,
resource CRUD, import, diagnostics, examples, and acceptance tests.

## Delivery Order

Implement in this order. Do not start broad connector expansion before the
first complete connector and identity path are proven.

### Milestone 1: Stabilize the current working tree

1. Run formatting, build, unit tests, console typecheck/build, migration gate,
   security checks, and integration tests where the real stack is available.
2. Fix compilation, race, test, lint, and migration failures introduced by the
   active uncommitted work.
3. Commit coherent changes in small, reviewable units. Do not combine SSO,
   connector work, Terraform, and unrelated UI work in one commit.
4. Keep production Compose persistent: SpiceDB must not use an in-memory
   datastore in any deployment described as production.

Required checks:

```powershell
Set-Location services/query-runtime
gofmt -l .
go build ./...
go vet ./...
go test ./...
go test -race ./...

Set-Location ../..
python scripts/check_migrations.py
npm --prefix apps/console run typecheck
npm --prefix apps/console run build
```

Run live integration and non-bypassable deployment checks only against an
explicit test environment with Postgres, SpiceDB, Qdrant, and Elasticsearch.

### Milestone 2: Complete OIDC SSO as an enterprise feature

Goal: a customer can configure Entra ID or Okta, sign in to the console, and
the runtime enforces the same verified identity and tenant boundaries.

Required work:

1. Add configuration validation for OIDC issuer, client ID, audience, tenant
   claim, allowed tenant values, roles claim, and admin-role mapping.
2. Provide exact Entra and Okta setup guides: redirect URI, scopes, claims,
   group/role mapping, token lifetime, and key rotation behavior.
3. Verify the browser session does not expose raw provider tokens to client
   JavaScript. Only server route handlers may forward the IdP token to the
   runtime.
4. Ensure runtime privileged operations require both an appropriately scoped
   Groundwork API key and a verified identity with the appropriate ownership or
   admin rule. Console hiding is not authorization.
5. Add end-to-end tests using a local OIDC/JWKS test issuer for: valid login,
   invalid signature, expired token, wrong issuer, wrong audience, tenant
   mismatch, missing role, and admin role.
6. Keep demo mode impossible outside `GROUNDWORK_ENV=local` or `dev`.

Deferred, separate milestones:

- SAML support.
- SCIM 2.0 Users and Groups provisioning.
- IdP group-to-console/runtime role administration UI.

SCIM implementation requirements when started:

- Use a dedicated `/scim/v2` surface protected by tenant-scoped bearer tokens.
- Implement Users and Groups CRUD, PATCH, pagination, filtering, deactivation,
  idempotency, and audit events.
- Never let a SCIM payload set Groundwork tenant membership without trusted
  tenant binding from the provisioning token/configuration.
- Deactivation must revoke or disable effective access promptly.

### Milestone 3: Make one connector production-grade

Choose Microsoft Graph/SharePoint first unless a signed design partner requires
S3 or GCS. The Graph connector has the best starting point in this repository.

For a connector to be called production-ready, implement all of these:

1. Real provider client with documented least-privilege OAuth or workload
   identity permissions.
2. Credentials stored only as `keyring://` or approved secret-manager
   references. No access token, refresh token, client secret, or connection
   string may be written to logs, API responses, audit payloads, or the
   connector registry.
3. Tenant-bound installation record and encrypted credential metadata.
4. Full initial inventory and permission snapshot.
5. Persistent delta cursor/checkpoint in Postgres.
6. Incremental changes that generate concrete permission grants and revokes,
   reconcile them into SpiceDB, and record evidence.
7. Full reconciliation job to repair missed webhooks/deltas.
8. Provider rate-limit behavior, bounded retries, timeout, paging, resumable
   sync, and dead-letter/alert handling.
9. Connector health, last-success, lag, permission-drift, and credential-expiry
   metrics and console status.
10. Integration tests against a provider sandbox or reliable fake HTTP server,
    including permission revocation followed by a live Groundwork deny.
11. Customer setup guide and `groundwork doctor` checks.

Do not call polling a real-time sync unless the connector computes the delta,
applies it, and proves revocations take effect within the stated SLO.

### Milestone 4: Connector SDK and adapter contract

Before adding more provider-specific code, create a stable connector SDK or
internal contract.

The contract must cover:

- Authentication method and secret references.
- Installation and tenant binding.
- Content inventory and stable source/resource IDs.
- Source ACL/group/user mapping to canonical Groundwork principals.
- Snapshot and delta cursor semantics.
- Permission grant/revoke events.
- Content deletion/tombstones.
- Region/residency metadata.
- Rate-limit, retry, timeout, and pagination semantics.
- Health, sync lag, credential expiry, and error taxonomy.
- Evidence event schema.
- Contract tests every connector must pass.

Use the existing `internal/aclsync` interface as the starting point, but extend
it only with explicit versioned contracts. Do not duplicate security behavior
inside every provider package.

Provider-specific warnings:

- S3 and GCS object ACLs alone do not model effective IAM. Bucket policies,
  IAM roles, access points, inherited grants, and encryption access must be
  accounted for or the connector must document its strict supported subset and
  fail closed outside it.
- SharePoint/OneDrive needs inherited, sharing-link, site, library, folder, and
  item permission semantics plus Graph delta handling.
- Notion permissions are integration-scoped and may not expose each end-user's
  effective permission. Do not claim per-user authorization unless the provider
  data can prove it.
- Snowflake must model role inheritance and actual effective grants. Validate
  queries against a real Snowflake account before relying on them.

### Milestone 5: Notification and approval delivery

1. Move Slack webhook configuration out of code into a tenant-scoped secret
   reference. Remove placeholder URLs.
2. Use the shared hardened HTTP client, explicit deadlines, retry policy, and
   allowlisted endpoints. Do not use `http.DefaultClient` for security events.
3. Add signed Slack interactive actions for approve/reject/revoke with replay
   protection and server-side role checks.
4. Add Microsoft Teams through its supported workflow/action mechanism.
5. Notification failure must create operational evidence and an alert; it must
   not make a correctly authorized emergency action silently succeed without
   visibility.

### Milestone 6: Terraform provider

> **Status: complete.** Implemented in `terraform-provider-groundwork/`
> with `terraform-plugin-framework` v1.19 (plugin protocol 6): provider
> config (`api_base_url`, `api_key` sensitive, `region`, `timeout_seconds`),
> all six resources (`groundwork_tenant`, `groundwork_agent`,
> `groundwork_agent_tool_grant`, `groundwork_connector`,
> `groundwork_policy`, `groundwork_budget`) with Create/Read/Update/
> Delete/ImportState, diagnostics, sensitive state (`secret_ref`,
> `client_cert_ref` are references only), and deterministic
> `Idempotency-Key` headers derived from resource config. Terraform
> delete is non-destructive everywhere: tenant → deprovision, agent →
> revoke, grant → revoke, connector → revoke, policy → revoke, budget →
> zero (all-zero limits fail closed). Unit tests run without a Terraform
> binary against an in-process fake runtime; acceptance tests are
> TF_ACC-gated (`GW_API_BASE_URL`/`GW_API_KEY`) for a disposable stack;
> examples and registry-format docs included; CI workflow
> `.github/workflows/terraform-provider.yml`.

Only begin after the REST API resource lifecycle contracts are stable.

Implement these first:

```text
groundwork_tenant
groundwork_agent
groundwork_agent_tool_grant
groundwork_connector
groundwork_policy
groundwork_budget
```

Requirements:

- Use the current Terraform Plugin Framework, not a partial legacy schema
  scaffold.
- Add provider configuration for base URL, API key, and optional region.
- Implement Create, Read, Update, Delete, ImportState, diagnostics, sensitive
  state handling, and idempotency keys.
- A Terraform delete must honor Groundwork's non-destructive tenant lifecycle:
  deprovision instead of destructive deletion.
- Add unit tests, acceptance tests against a disposable Groundwork stack,
  examples, generated docs, and CI.
- Do not store connector secrets in Terraform state. Support secret references
  only.

## Security Rules for Every Change

1. Deny on dependency, parsing, permission, identity, or evidence failure.
2. Never trust request-body identity, tenant, region, role, or permission data.
3. Enforce tenant isolation in IDs, database queries, SpiceDB tuple handling,
   vector/lexical retrieval, audit queries, and connector state.
4. Keep the runtime and connector path non-bypassable in production network
   deployments.
5. Store secret references, never raw secrets.
6. Verify every mutation has idempotency, actor identity, tenant scope, and
   immutable evidence where appropriate.
7. Do not log tokens, credentials, raw sensitive content, or full webhook
   payloads.
8. Preserve administrative separation: an auditor can inspect evidence but must
   not be able to grant access or open break-glass.

## Definition of Done

A feature is done only when all apply:

- Its threat model and failure mode are documented.
- It is tenant-, region-, and identity-bound.
- It fails closed on uncertainty.
- It has unit, HTTP/API, and appropriate integration tests.
- It has operational metrics, alerts, and a runbook.
- It is documented in the API reference and customer setup guide.
- Its console UI cannot be the sole authorization barrier.
- It passes the repository build, test, formatting, migration, and security
  gates.

## Product Scope Guardrail

Keep Groundwork focused on runtime authorization and evidence for AI agent
actions. Integrate with IAM, GRC, SIEM, ticketing, and cloud platforms; do not
try to replace all of them. The next commercial proof should be one managed
deployment, one real IdP, one production-quality source connector, one agent,
and one demonstrated live revocation path.
