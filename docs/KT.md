# Groundwork Knowledge Transfer

## 1. Product

Groundwork is a runtime trust, authorization, and evidence layer for enterprise AI agents.

Its core job is to decide, before an agent retrieves data or invokes a tool, whether that exact action is authorized. Unauthorized data and actions are blocked immediately. Every decision is recorded in a tamper-evident audit trail.

Groundwork is not a chatbot, RAG application, IAM replacement, GRC replacement, or model provider. It sits between AI agents and enterprise data/tools.

Core decision context:

```text
tenant + region + verified principal + agent + agent version + run
+ delegation + tool + action + resource + purpose + approval + policy
```

The product supports internal employee agents, customer-facing agents, partner agents, and future multi-agent systems.

## 2. Product Positioning

Recommended positioning:

> Groundwork is a sovereign runtime control plane that governs what enterprise AI agents may access and do, and proves every decision afterward.

Initial market focus:

- EU and UK banks, insurers, and regulated fintechs
- US regulated enterprises after regional deployment is proven
- Healthcare, NHS trusts, government, defense contractors, utilities, and large enterprises as expansion markets

Primary buyers:

- CISO
- CTO
- Head of AI Platform
- Chief Risk Officer
- Head of Operational Resilience

Daily users:

- Security engineers
- Platform engineers
- Agent developers
- AI governance teams
- Compliance and internal audit teams
- SOC and incident-response teams

Groundwork supports evidence views for EU AI Act, DORA, GDPR, ISO/IEC 42001, NIST AI RMF, UK requirements, and US customer policies. These are evidence mappings, not legal certification.

## 3. Repository Location

The Groundwork repository is expected at:

```text
C:\Users\SHAIK MOHAMMAD REHAN\Downloads\groundwork-master
```

Open the `groundwork-master` folder as the repository root. The current Codex workspace may be different from the repository root.

Important paths:

```text
services\query-runtime\       Go runtime
apps\console\                 Next.js console
migrations\                    SQL migrations
internal\agentregistry\       Agent registry implementation
internal\governance\          Governance implementation
test\integration\              Live integration tests
docs\                           Architecture and product documentation
examples\                       Bank, GitHub, MCP, and SDK demos
```

## 4. Architecture

### Runtime flow

```text
AI agent / REST / MCP
        |
        v
Groundwork gateway and query runtime
        |
        +--> identity and tenant resolution
        +--> agent/delegation/run validation
        +--> tool/action policy evaluation
        +--> SpiceDB relationship check
        +--> region and residency check
        +--> approval and budget check
        +--> connector invocation or retrieval
        +--> response filtering/redaction
        +--> immutable evidence and audit
        v
Only permitted data or tool result reaches the agent
```

### Core components

- Go query runtime and governance runtime
- PostgreSQL for tenant metadata, registry state, runs, grants, evidence, and audit metadata
- SpiceDB for live relationship-based authorization
- Qdrant for semantic retrieval
- Elasticsearch for lexical/compliance search paths
- Next.js console for CISO and platform operations
- Python ingestion service for chunking and embeddings
- REST and MCP gateway paths
- REST and MCP connector gateway
- OpenTelemetry-compatible metrics/traces
- Postgres transactional outbox for security events

### SpiceDB role

SpiceDB is the relationship authorization engine, not the entire policy engine.

Use SpiceDB for relationships such as:

- user is member of group
- group can view folder
- folder contains document
- agent may use tool
- principal may access resource

Keep contextual decisions in Groundwork's shared evaluator: region, purpose, risk, expiry, approval, budgets, delegation attenuation, lifecycle, and emergency controls.

Do not replace SpiceDB with custom authorization. SpiceDB is a possible future backend, but no migration is planned. If a future backend is needed, hide SpiceDB behind a `RelationshipAuthorizer` interface and use contract tests.

## 5. Non-Negotiable Security Rules

1. Fail closed. Missing, stale, revoked, conflicting, unavailable, or timed-out security state denies the action.
2. Tenant and region come only from trusted authentication/runtime context, never request-body fields.
3. Every external tool call must pass through the shared evaluator and connector gateway.
4. No public direct access to Qdrant, SpiceDB, PostgreSQL, Elasticsearch, MinIO, or internal runtime services in production.
5. A revoked agent, version, grant, delegation, tool, connector, or run must deny the next action.
6. Never log or return raw JWTs, delegation tokens, API keys, secrets, user assertions, or unauthorized document content.
7. SpiceDB remains the relationship source of truth.
8. Every lifecycle change, authorization decision, connector invocation, approval, revocation, and security failure must produce evidence.
9. Write-once evidence and audit chain behavior must remain intact.
10. Demo identity is explicitly gated and must never enable production delegation or external-agent access.

## 6. Completed Phases

### Phase 1: Agent Registry and Lifecycle

Delivered:

- `migrations/014_create_agents.{up,down}.sql`
- Agent, agent-version, and lifecycle-event persistence
- Write-once database rules
- `internal/agentregistry/`
- Digest/hash-chain implementation
- Memory and PostgreSQL stores
- Advisory-lock protected state transitions
- Agent lifecycle state machine
- Runtime agent APIs and eight routes
- Console Agents view and proxy routes
- `docs/agents.md`

Verified:

- Agent create, version, activation, suspension, revocation, retirement
- Tenant isolation
- Write-once database behavior
- Digest-chain verification
- Migration validation through migration 014
- Go build, vet, formatting, unit tests, and Postgres integration tests

Known cosmetic issue:

- `time.Time` values may render as `0001-01-01T00:00:00Z` instead of being omitted. Fixing requires pointer time fields and is wire-format cosmetic only.

### Phase 2: Delegated Authority and Governed Execution

Delivered:

- `migrations/015_delegated_authority.{up,down}.sql`
- Tools and tool actions
- Agent-tool grants
- Delegated authority grants
- Agent runs
- Action decisions
- Human approval flow
- Shared governance evaluator
- Delegation token minting and validation
- JTI replay protection
- Query and MCP governance gates
- REST/MCP decision parity
- Console Governance view
- `docs/governance.md` Phase 2 section

Important behavior:

- Delegation is bound to agent, active agent version, principal, run, region, purpose, scope, and expiry.
- Child authority cannot exceed parent authority.
- Tool calls are default deny.
- Write/destructive actions can require one-time human approval.
- Use a dedicated delegation signing key, not the ordinary user JWT key, in production.

Verified:

- Go build/vet/formatting
- Unit tests for evaluator and state transitions
- HTTP governance tests
- MCP delegation tests
- Postgres integration tests
- Console build
- Migration validation through 015

### Phase 3: Monitoring, Emergency Controls, and Evidence Operations

Delivered:

- Emergency controls and kill switches
- Budgets and action limits
- Evidence explorer and investigation APIs
- Audit-chain verification and checkpoints
- Transactional Postgres outbox
- Webhook delivery and retry behavior
- Operational telemetry
- Incident Response console view
- Demo GET fallbacks for read-only unavailable backend routes
- Pass-through-only mutations
- `docs/governance.md` Phase 3 section

Verified:

- Go formatting, build, vet, and full tests
- Outbox tests
- Migration validation through 016
- Console TypeScript build

Important behavior:

- Demo fallbacks are allowed only for read operations.
- Mutations must never fake state.
- Telemetry failure must not permit an unauthorized action.

### Phase 4: Sovereign Multi-Region Enterprise Deployment

Delivered:

- Region/jurisdiction model
- EU, UK, and US deployment concepts
- OIDC and JWKS validation
- Key-material registry
- Tenant region registry
- Purpose-scoped key metadata
- Production topology validation
- Sovereign deployment documentation
- Evidence export profiles
- Console Evidence Exports card
- `migrations/017_create_deployment_registry.{up,down}.sql`
- `docs/governance.md` Phase 4 section

Supported evidence profiles include:

- EU AI Act
- DORA
- GDPR
- ISO/IEC 42001
- NIST AI RMF
- UK customer policy profile
- US customer policy profile

Important positioning:

- Groundwork supplies controls and evidence mappings.
- Groundwork does not independently certify legal compliance.
- EU, UK, and US deployments must isolate runtime, data, audit, telemetry, backups, and keys by approved jurisdiction.

### Phase 5: Production Connector Gateway

Delivered:

- Generic REST connector
- External MCP connector
- Connector registration and lifecycle
- Connector action manifests
- Connector health checks
- Egress allow-listing
- Credential-free health probes
- Request/response redaction
- Connector invocation evidence
- Connector lifecycle evidence
- REST/MCP connector dispatch
- Revocation and suspension fail-closed behavior
- Evidence union for connector events
- Idempotency conflict handling
- `docs/connectors.md`
- Migration validation through 018

Verified:

- Live-stack connector integration tests
- REST lifecycle: register, activate, dispatch, redact, revoke, fail closed
- MCP JSON-RPC dispatch
- Credential-free health probe
- Suspension fail-closed behavior
- Evidence union and chain behavior
- Go formatting, build, vet, full tests
- Console build

## 7. Current Database Migrations

The migration sequence is expected to be contiguous and reversible:

```text
003 ... 024
```

Phase 6 schema work introduced:

```text
019 ... Phase 6 trust schema
020 ... Phase 6 schema compatibility fix
021 ... Phase 6 API surface
022 ... Phase 6 external run/evidence bindings
023 ... Phase 6 consent/transfer/budget bindings
024 ... budget counter action key (TEXT, uuid cast fix)
```

`python scripts/check_migrations.py` reports the full sequence through 024 and must stay green before any change is declared complete.

Migration 020 corrected Phase 6 store/schema mismatches:

- External agent identity columns converted to TEXT
- TEXT arrays converted to store-compatible TEXT representation
- Missing grant and run bindings added
- Trust event entity types widened
- Tables renamed to match store code
- Postgres bindings aligned with memory-store behavior

Do not edit old migrations casually. Add a new migration for any correction.

## 8. Verification Commands

Run from the repository root:

```powershell
gofmt -l .
go build ./...
go vet ./...
go test ./...
go test -tags integration ./test/integration/...
python scripts/check_migrations.py
```

Console:

```powershell
cd apps/console
npm run build
```

Use the real PostgreSQL/SpiceDB integration environment for live tests. A package compiling under an integration tag is not the same as a successful live-stack test.

## 9. Phase 6 Status

Phase 6 is **not started as a new implementation phase**.

The Phase 6 schema and persistence compatibility fix has been completed, including:

- Trust relationships
- External agents
- External nonces
- Consent records
- External budgets
- Transfer policies
- Delegation-chain bindings
- External run bindings
- Evidence chain flags

Phase 6 API completion **is done**. The existing Phase 6 GovernanceService
methods are exposed through REST, MCP, and the console and verified
against the live PostgreSQL/SpiceDB stack (integration suite 14/14).

## 10. Completed: Phase 6 API Completion

All of the following were implemented and are covered by unit, HTTP,
MCP, and live Postgres/SpiceDB integration tests:

- Trust relationship REST handlers
- External-agent registration and lifecycle handlers
- Delegation-chain and provenance endpoints
- External-run handlers
- Consent endpoints
- Transfer-policy endpoints
- External-budget endpoints
- Production external-agent authentication
- REST/MCP parity
- Console Multi-Agent Trust view
- HTTP, MCP, Postgres, tenant-isolation, replay, and redaction tests

Required safety rules:

- External agent identity must come from verified OIDC/JWKS or mTLS context.
- Never trust `tenant_id`, `region`, `organization_id`, `external_agent_id`, or `customer_principal_id` from the request body.
- Parent delegation scope must strictly contain child scope.
- Child expiry cannot exceed parent expiry.
- Parent revocation invalidates descendants.
- Cross-tenant and cross-region delegation is denied by default.
- Consent and transfer policy requirements must be evaluated before connector execution.
- External run and multi-agent provenance must appear in evidence.

Recommended API areas:

```text
POST/GET /v1/governance/trust-relationships
POST /v1/governance/trust-relationships/{id}/approve
POST /v1/governance/trust-relationships/{id}/suspend
POST /v1/governance/trust-relationships/{id}/revoke

POST/GET /v1/governance/external-agents
GET /v1/governance/external-agents/{id}
POST /v1/governance/external-agents/{id}/activate
POST /v1/governance/external-agents/{id}/suspend
POST /v1/governance/external-agents/{id}/revoke

GET /v1/governance/delegations/{id}/chain
GET /v1/governance/runs/{id}/delegation-chain
GET /v1/governance/evidence/{id}/provenance

POST/GET /v1/governance/consents
POST /v1/governance/consents/{id}/revoke

POST/GET /v1/governance/transfer-policies
POST/GET /v1/governance/external-budgets
```

Before editing Phase 6 code, inspect the actual method names and DTOs. Do not duplicate service logic in HTTP handlers.

## 11. Future Product Direction

After Phase 6 API completion, likely product expansions are:

- Multi-agent trust graph
- Parent/child authority attenuation
- External partner-agent onboarding
- Customer-agent isolation
- Consent and purpose binding
- Cross-company federation
- Agent policy simulation
- Risk scoring and policy recommendations
- More enterprise connectors
- SIEM integrations
- Customer-managed deployment automation
- Compliance evidence packs

Keep the product focused on runtime trust and enforcement. Do not become a generic chatbot framework or documentation-only GRC product.

## 12. Product Moat

The moat is the combined enforcement system, not the choice of SpiceDB or another authorization database:

- Agent/user/run/tool/resource authorization model
- Live revocation
- Fail-closed runtime behavior
- Connector and MCP interception
- Sovereign regional deployment
- Immutable evidence and provenance
- Enterprise identity and key integration
- Security policy and connector integrations
- Production reliability under dependency failures

## 13. Engineering Rules for Future Work

- Read existing code and migrations before editing.
- Preserve user changes and unrelated work.
- Use existing repository patterns before adding abstractions.
- Use `apply_patch` for manual edits.
- Add focused tests for every security-sensitive branch.
- Add a migration for schema changes; do not rewrite applied migrations.
- Keep handlers thin and services authoritative.
- Keep one shared authorization evaluator for REST, MCP, query, and connectors.
- Make every security decision auditable.
- Never weaken fail-closed behavior for demos or convenience.
- Run formatting, build, vet, tests, migration validation, console build, and relevant live integration tests before declaring work complete.
