# Usage Metering and Tenant Limits

Per-tenant quota enforcement for the Groundwork query runtime. Every
supported metric is counted per tenant per UTC calendar month, limits can
be set per metric and period, and enforcement is **fail-closed**: a tenant
over its quota is denied at the HTTP layer before the operation happens.

## Metrics and periods

| Metric | `metric` value | Recorded at |
|---|---|---|
| Agents | `agents` | `POST /v1/agents` |
| Query runs | `runs` | `POST /v1/query`, `POST /v1/governance/runs` (internal and external) |
| Policy decisions | `decisions` | `POST /v1/governance/evaluate`, `POST /v1/governance/dispatch`, and the delegated-agent query gate |
| Connector calls | `connector_calls` | `POST /v1/governance/dispatch` — fail-closed preflight inside `DispatchAction`, immediately before the outbound call |
| Exports | `exports` | `GET /v1/governance/exports/{framework}` |
| Outbox deliveries | `outbox_deliveries` | outbox worker `PreDeliver` gate, before each delivery attempt |
| Storage bytes | `storage_bytes` | export payload size at export time (fail-closed); dispatch response volume (best-effort) |

Periods:

- `monthly` — counter keyed by the UTC calendar month (`YYYY-MM`); a new
  month starts at zero.
- `lifetime` — the sum of all monthly counters for the metric.

A limit of **0 or less means unlimited** (the limit row is deleted). When
a metric is unlimited, `GET /v1/usage` reports `limit: 0` and
`remaining: -1`.

## Enforcement semantics

- **Fail-closed metrics** (agents, runs, decisions, exports,
  connector_calls, storage_bytes, outbox_deliveries): `Record` is an
  atomic check-and-increment. If the increment would exceed the limit,
  the transaction rolls back — the denied attempt never consumes quota —
  and the operation is denied with HTTP `403` and error code
  `quota_exceeded:<metric>`. Other recording errors are logged and never
  block the request.
  - **connector_calls** is enforced inside the governed dispatch
    pipeline, *before any outbound connection opens*: an over-quota
    tenant never reaches the connector gateway. The denial is recorded
    in the immutable evidence chain as a failed connector invocation
    with error code `quota_exceeded:connector_calls`, and the dispatch
    endpoint reports it as `403`. The counter reflects dispatch
    attempts (an attempt that is then denied by policy or fails at the
    gateway still consumed its unit).
  - **outbox_deliveries** is enforced by the worker's `PreDeliver` gate
    before each delivery attempt. An over-quota tenant's events are
    **skipped without being claimed**: they stay `pending`, consume no
    attempt, and are retried on the next cycle — delivery resumes
    automatically once the quota is raised or the month rolls over. A
    delivery that is *started* but fails (webhook error) still consumes
    its unit, because counters are never decremented.
  - **storage_bytes** is enforced fail-closed at **export** time: the
    export payload is fully materialized before anything is streamed, so
    an over-quota tenant receives `403` and no bytes leave the service.
    The *dispatch* response volume remains metered best-effort: it is
    unknowable before the outbound connector call, so it cannot be
    denied ahead of the side effect.
- If usage metering is not configured, the usage endpoints return
  `503 usage_unavailable` and recording is a no-op.
- Counters are never decremented. The monthly rollover is automatic; to
  free a tenant mid-month an operator raises or clears the limit.
- There is no per-attempt event log (intentionally): only aggregate
  counters are stored, so a monthly counter is *not* an audit trail.
  Attempt-level detail stays in the audit/evidence chain.

## API

All usage endpoints require the `usage` API-key scope (or `admin`).
`tenant_id` always comes from the verified key, never the body.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/v1/usage` | Snapshot: `{tenant_id, period: "YYYY-MM", usage: [{metric, period, count, limit, remaining}]}` — every metric × every period |
| `GET` | `/v1/usage/limits` | `{tenant_id, limits: [{metric, period, limit}]}` |
| `PUT` | `/v1/usage/limits` | Body `{limits: [{metric, period, limit}]}`; requires a verified user assertion + `Idempotency-Key`. `limit <= 0` clears the limit. Invalid metric/period → `400` |

Setting a limit is never retroactive: a tenant already over a newly set
limit is denied immediately and must be raised/cleared by an operator.

## Storage

- **Postgres** (production, when `DATABASE_URL` is set):
  `internal/usage/postgresStore` — migration `025_usage_metering`:
  `usage_counters (tenant_id, metric, period, count, updated_at)` and
  `usage_limits (tenant_id, metric, period, limit_value, updated_at)`.
  `Record` runs in a single transaction: upsert the monthly counter, then
  check both monthly and lifetime limits against the new value, rolling
  back on over-limit.
- **In-memory** (dev/demo): `internal/usage/memoryStore`, mutex-guarded,
  used when no `DATABASE_URL` is set.

The service (`internal/usage/service.go`) is storage-agnostic; main.go
selects the store and hands the service to the HTTP layer via
`server.SetUsageMeter(...)`.

## SDKs

All three first-party clients expose the usage surface:

- TypeScript: `getUsage()`, `getUsageLimits()`, `putUsageLimits(body, idempotencyKey)`.
- Python: `usage()`, `usage_limits()`, `set_usage_limits(body, idempotency_key)`.
- Go: `GetUsage(ctx)`, `GetUsageLimits(ctx)`, `PutUsageLimits(ctx, body, idempotencyKey)`.

## Verification

```sh
cd services/query-runtime
go test ./internal/usage/... ./internal/governance/ ./internal/outbox/ ./internal/runtime/...   # unit + HTTP
go test -tags integration ./test/integration/...      # Postgres record/limits/tenant isolation
python scripts/check_migrations.py                    # migration gate (003..025)
```

The HTTP tests cover scope enforcement, `usage_unavailable`, the limits
lifecycle, idempotency on `PUT /v1/usage/limits`, agents quota fail-closed
behavior (denied create leaves the count unchanged), query-run metering,
the connector_calls fail-closed preflight (403 before any outbound call,
denial recorded as invocation evidence), the outbox `PreDeliver` skip
(over-quota events stay pending with zero attempts), and the export
storage_bytes denial (403 before any bytes stream). Integration tests
cover atomic recording, limit enforcement with rollback, and tenant
isolation at the SQL layer.
