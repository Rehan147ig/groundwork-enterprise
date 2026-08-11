# Rate and Concurrency Limits

Per-tenant rate limiting and concurrent-request limits for the
Groundwork query runtime. Both are **fail-closed**: a tenant over its
rate or concurrency budget is denied at the HTTP layer **before** any
execution happens (before the engine, before usage recording, before
audit writes).

These are per-instance, in-memory protections (see the caveat below) —
they protect a single runtime process from noisy neighbors, complementing
the durable per-tenant usage quotas in `docs/usage-metering.md`.

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `LIMIT_RPM_PER_TENANT` | `0` (unlimited) | Max requests per tenant per fixed 60-second window |
| `LIMIT_CONCURRENCY_PER_TENANT` | `0` (unlimited) | Max in-flight requests per tenant at any instant |

Both are read once at startup; `0` disables the corresponding limiter.

## Enforcement semantics

- **Rate limit** (fixed window): each tenant gets `LIMIT_RPM_PER_TENANT`
  requests per UTC-aligned 60-second window. When the budget is
  exhausted, the request is rejected with HTTP `429` and error code
  `rate_limit_exceeded`, plus a `Retry-After` header (seconds until the
  window resets). The rejected request consumes nothing — it never
  reaches the engine or the usage counters.
- **Concurrency limit**: when `LIMIT_CONCURRENCY_PER_TENANT` requests
  are already in flight for a tenant, further requests are rejected
  immediately (non-blocking) with HTTP `503` and error code
  `concurrency_limit_exceeded`. No queueing: clients are expected to
  back off and retry. The slot is released when the request completes,
  including failed and rejected requests.
- Both limiters key on the **tenant id from the verified API key**, so
  every key and end-user under a tenant shares one budget.
- Health endpoints (`/health`, `/healthz`, `/livez`, `/readyz`) and
  `/metrics` are **exempt** — they never consume budget and are never
  rejected.
- The existing per-key `rate_limit_rpm` (configured per API key) still
  applies first; the tenant-level checks run after it. A request must
  pass all three checks (per-key rate, tenant rate, tenant concurrency)
  to execute.
- Limiter state is **in-memory and per-instance**: a multi-instance
  deployment must treat these limits as approximate per process, not a
  global budget. Connection pooling and other noisy-neighbor controls
  remain open work (Roadmap 8.1).

## Error responses

| Status | Code | Headers | Meaning |
|---|---|---|---|
| `429` | `rate_limit_exceeded` | `Retry-After: <seconds>` | Tenant hit its fixed-window request budget |
| `503` | `concurrency_limit_exceeded` | — | Tenant's concurrent-request budget is saturated |

Both use the standard `{"error": "<code>"}` envelope.

## Verification

```sh
cd services/query-runtime
go test ./internal/runtime/...            # unit (limiters) + HTTP (429/503, isolation, healthz exempt)
go test -tags integration ./test/integration/...   # real stack: 429 on POST /v1/query, healthz exempt
```

The integration test (`test/integration/limits_test.go`) proves the
tenant rate limiter against real Qdrant + SpiceDB + Postgres: the first
query returns the authorized document, the second is rejected with 429
before execution, and `/healthz` stays up.
