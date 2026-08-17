# Groundwork Developer Reference

**Zero-Trust AI Context Firewall** for agentic AI: a runtime data access control plane that sits between AI applications and private data. Every retrieval is checked against **live permissions**, scrubbed by a **context firewall**, and written to an **immutable, verifiable audit chain** — before any data reaches a model.

- **Not a RAG tool** — not a chatbot. It is infrastructure: the enforcement point your AI traffic already has to pass through.
- **Fail-closed by design** — if the authorizer, backend, or engine is unavailable, callers get *zero chunks* and the decision lands in the audit log. No fallback to open.
- **Revocation is immediate** — no permission caching; every query re-checks against SpiceDB at query time.
- **Every decision is evidence** — allowed, denied, and fail-closed decisions are hash-chained and can be independently verified.

---

## Quickstart (2 minutes)

### 1. Start the stack

```bash
docker compose -f infra/docker-compose.quickstart.yml up -d
```

This brings up Postgres, SpiceDB, the query-runtime (HTTP on `localhost:8080`), and the CISO console (on `localhost:3000`), seeded with a GitHub-org permission demo. The stack mints one fixed demo key:

```bash
export GROUNDWORK_API_KEY=gw_local_acme_key
```

### 2. Install the Python SDK

```bash
pip install -e sdks/python          # + optional LangChain extra: pip install -e "sdks/python[langchain]"
```

### 3. Make your first query

```python
from groundwork import GroundworkClient

client = GroundworkClient(
    base_url="http://localhost:8080",
    api_key="gw_local_acme_key",     # fixed demo key from the quickstart stack
)

resp = client.query(
    question="What shipped in the last sprint?",
    user_id="alice@corp.com",        # demo identity (ALLOW_DEMO_IDENTITY)
)
print(resp.answer, round(resp.confidence, 2))
print(len(resp.citations), "permitted chunks cited")
print(resp.trace.immutable_digest)     # root of the audit chain for this query
```

Or plug straight into a LangChain pipeline:

```python
from langchain_core.documents import Document  # noqa: F401  (documents are returned, not emitted)
from groundwork import GroundworkClient
from groundwork.integrations.langchain import GroundworkRetriever

client = GroundworkClient(base_url="http://localhost:8080", api_key="gw_local_acme_key")
retriever = GroundworkRetriever(client=client, top_k=5)
docs = retriever.invoke("What are the Q3 regulatory filings?")
for doc in docs:
    print(doc.metadata["document_id"], doc.metadata["score"], doc.metadata["chunk_hash"])
```

**That's it** — your first query was permission-checked against live ACLs, firewall-scrubbed, watermarked, and written to the immutable audit log.

---

## Authentication

Every request needs an API key. Send it as `X-Groundwork-API-Key` (or `Authorization: Bearer <key>`).

Keys are **scoped**. Each endpoint requires a specific scope; a key with `admin` satisfies any scope:

| Scope | Grants access to |
|---|---|
| `query` | `POST /v1/query` |
| `audit` | `GET /v1/leak-report`, `GET /v1/audit/verify` |
| `usage` | `GET /v1/usage` |
| `break_glass` | Open/revoke break-glass grants (also requires a verified operator identity) |

Tenant, region, and identity never come from the body or URL — they are resolved from the key and from signed headers (`X-Groundwork-User-Assertion` JWT, or `X-Groundwork-Delegation-Token` for agent runs).

Errors use a stable envelope so clients can branch without string-matching prose:

```json
{ "error": "insufficient_scope" }
```

---

## Endpoints

### `POST /v1/query` — permission-checked retrieval

The core surface. Retrieves candidates, evaluates **every chunk against live permissions**, applies the zero-trust context firewall (PII redaction, indirect prompt-injection blocking, provenance watermarks), and answers with citations plus an immutable trace.

```bash
curl -sS http://localhost:8080/v1/query \
  -H "X-Groundwork-API-Key: gw_local_acme_key" \
  -H "X-Groundwork-User-Assertion: <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"alice@corp.com","question":"What shipped last sprint?"}'
```

Response highlights: `answer`, `confidence`, `citations[]` (each with `chunk_hash` and `watermark` for provenance), and `trace` (every decision + `immutable_digest` rooted in the audit chain).

### `GET /v1/leak-report` — compliance scan

Read-only scan over connected external indexes (e.g. GitHub org) for documents that should have been restricted: files pushed before onboarding, excluded paths that got indexed, tightened permissions not yet reflected in search.

```bash
curl -sS http://localhost:8080/v1/leak-report -H "X-Groundwork-API-Key: <audit-scoped key>"
```

Returns `{ "findings": [ { "kind", "severity", "title", "detail" } ] }`.

### `POST /v1/security/break-glass/grants` — time-bounded emergency admin

Opens an emergency grant that mints a **short-lived, admin-scoped API key**; reason is mandatory and every lifecycle transition is hash-chained evidence. Requires `break_glass` scope **and** a verified operator identity.

```bash
curl -sS -X POST http://localhost:8080/v1/security/break-glass/grants \
  -H "X-Groundwork-API-Key: <break_glass-scoped key>" \
  -H "X-Groundwork-User-Assertion: <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"reason":"Prod incident - on-call override","duration_minutes":30}'
```

`201` returns `{ "grant": {...}, "key": "gw_bgk_..." }`. The key is **shown once and never persisted** — store it securely or open a new grant. Grants auto-expire (`expires_at`) and can be revoked early:

```bash
curl -sS -X POST http://localhost:8080/v1/security/break-glass/grants/grant-1/revoke \
  -H "X-Groundwork-API-Key: <break_glass-scoped key>" \
  -H "X-Groundwork-User-Assertion: <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"reason":"Incident resolved"}'
```

### `GET /v1/audit/verify` — prove the chain is untampered

Recomputes the tenant's append-only SHA-256 hash chain. Every row digests its predecessor (ordered by the immutable `seq` identity, stable under concurrent writes). A rewritten, deleted, or reordered row produces a per-entry `problems[]` entry.

```bash
curl -sS http://localhost:8080/v1/audit/verify -H "X-Groundwork-API-Key: <audit-scoped key>"
```

```json
{ "verified": true, "entries_checked": 1284 }
```

`413 chain_too_large` when the chain exceeds the server cap — archive before re-verifying.

### `GET /v1/usage` — metered consumption

Current counts per metric against the tenant's configured limits (`remaining = -1` when unlimited). When a limited metric would be exceeded, the governing endpoint fails closed before doing the work.

```bash
curl -sS http://localhost:8080/v1/usage -H "X-Groundwork-API-Key: <usage-scoped key>"
```

---

## Common error codes

| Code | Status | Meaning |
|---|---|---|
| `missing_api_key` / `invalid_api_key` / `api_key_expired` | 401 | Key absent, unknown, or past its expiry |
| `invalid_identity_assertion` / `verified_identity_required` | 401 / 403 | Identity JWT invalid or missing where required |
| `insufficient_scope` | 403 | Key valid but lacks the endpoint's scope |
| `identity_unresolved` | 403 | User principal could not be resolved — fails closed |
| `rate_limit_exceeded` | 429 | Per-key RPM cap hit; back off |
| `engine_unavailable` | 503 | Fail-closed path: zero chunks, decision audited |
| `break_glass_unavailable` / `audit_unavailable` / `connector_unavailable` | 503 | Backing service not wired |
| `break_glass_grant_not_found` / `break_glass_grant_not_active` | 404 / 409 | Grant id unknown or inactive |
| `chain_too_large` | 413 | Audit chain exceeds verify cap; archive first |

## Reliability

- **Retry with backoff** on `429` and `503`-class errors (the SDK retries 429/502/503/504 and transport errors automatically).
- **Idempotence**: pass your own `X-Groundwork-Correlation-Id`; it becomes the audit `trace_id` so retries share one evidence record.
- **Fail closed**: treat 5xx as "no access granted", never as "retry can bypass".

## More

- [OpenAPI 3.0 spec](openapi/v1.json)
- [Architecture](../docs/architecture.md) · [Governance & zero-trust model](../docs/governance.md) · [Break-glass design](../docs/break-glass.md)
- [Query runtime source](../services/query-runtime)
- [Python SDK source](../sdks/python)