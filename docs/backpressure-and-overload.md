# Backpressure and Overload Protection

Phase 8.2 protections for the two failure modes that a noisy tenant (or
a slow dependency) can cause: a saturating request stream, and an
evidence pipeline that cannot drain. Both are **fail-closed and
non-queuing**: when capacity is exhausted, the request is refused with
an immediate HTTP 503 — nothing is buffered, nothing is retried inside
the runtime.

| | |
|---|---|
| HTTP pool | `services/query-runtime/internal/httpclient/pool.go` |
| Overload limiter | `services/query-runtime/internal/runtime/overload.go` |
| Outbox backpressure | `services/query-runtime/internal/outbox/backpressure.go` |
| Enforcement | `internal/runtime/server.go`, `internal/engine/engine.go`, `internal/governance/service.go` |
| Env wiring | `cmd/query-runtime/main.go` |

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `GROUNDWORK_HTTP_POOL_MAX_IDLE` | `100` | Max idle connections across all outbound HTTP clients (SpiceDB, connector gateway, webhook delivery) |
| `GROUNDWORK_HTTP_POOL_PER_HOST` | `20` | Max idle connections to any single host |
| `GROUNDWORK_HTTP_POOL_IDLE_MS` | `90000` | Idle connection lifetime before reuse |
| `OVERLOAD_MAX_CONCURRENT_REQUESTS` | `0` (unlimited) | Instance-wide in-flight request cap |
| `OUTBOX_BACKPRESSURE_MAX_PENDING` | `0` (disabled) | Per-tenant pending-outbox high-water mark |

All are read once at startup. `0`/unset disables the corresponding
protection, so a partially configured deployment never throttles itself.

## Layer 1: connection pooling

Every outbound HTTP dependency (SpiceDB via the ACL sink, connector
dispatch via the backend client, outbox webhook delivery) uses a shared
`http.Transport` built from the pool env vars. A slow dependency cannot
multiply connections unboundedly: idle connections are capped and
expired, and connection attempts are serialized per pool instead of
stacking new TCP dials per request.

## Layer 2: instance-wide overload limit

`OVERLOAD_MAX_CONCURRENT_REQUESTS` caps in-flight requests for the whole
process — the case where the sum of tenants saturates the runtime (pool
exhaustion, slow dependencies). It sits after the per-key scope check in
the auth middleware:

- New requests when the cap is reached are refused **immediately** (no
  queueing, non-blocking) with HTTP `503`, error code
  `overload_exceeded`, and a `Retry-After: 1` header.
- The slot is released when the request completes, including failed and
  rejected requests.
- Health endpoints and `/metrics` are exempt, as with the per-tenant
  limiters.

This is per-instance and in-memory, like the rate/concurrency limiters
(`docs/rate-and-concurrency-limits.md`).

## Layer 3: outbox backpressure (evidence pipeline)

The outbox table is the bounded buffer between governed decisions and
webhook delivery. When the delivery endpoint is slow or down, pending
events accumulate without limit — and every subsequent decision adds to
the backlog.

`OUTBOX_BACKPRESSURE_MAX_PENDING` turns the unmeasured backlog into an
explicit fail-closed refusal. The gate checks the tenant's pending
outbox count **before** new evidence is created, at every boundary:

| Boundary | Where | Result |
|---|---|---|
| Query audit write | `engine.writeAudit` (every query, allowed or denied) | Fail-closed, trace `error_code: outbox_backpressure`, zero citations |
| Governed evaluate | `governance.EvaluateAction` | `403`-class denial mapped to HTTP `503 outbox_backpressure` |
| Dispatch | `governance.DispatchAction` (via `EvaluateAction`) | HTTP `503 outbox_backpressure` |
| Delegated query | `governance.EvaluateDelegatedQuery` | HTTP `503 outbox_backpressure` |

Semantics:

- The mark is **per tenant**: one tenant's backlog never refuses another
  tenant's work.
- `Allow` is checked above the mark (`pending >= mark` refuses).
- Store errors **propagate** (fail-closed): if the pending count cannot
  be read, the request is refused rather than allowed blind.
- The count comes from the active store: `SELECT COUNT(*) ... WHERE
  status='pending'` on Postgres, an in-memory scan in dev.
- When the gate is not wired (default), the pipeline is unconstrained —
  existing behavior unchanged.

## Error responses

| Status | Code | Headers | Where |
|---|---|---|---|
| `503` | `overload_exceeded` | `Retry-After: 1` | Auth middleware, instance cap reached |
| `503` | `outbox_backpressure` | — | Audit write / evaluate / dispatch / delegated query above mark |
| `503` | `concurrency_limit_exceeded` | — | Per-tenant concurrency cap (Phase 8.1) |

All use the standard `{"error": "<code>"}` envelope. The engine's
fail-closed trace distinguishes `outbox_backpressure` (pipeline backed
up) from `audit_write_failed` (store broken) in the audit log itself.

## Alerting

`deploy/prometheus/alerting-rules.yml` adds:

- `GroundworkOverloadRefusals` (page) — any overload refusals in 15m.
- `GroundworkOutboxBackpressureRefusals` (warning) — any backpressure
  refusals in 15m; inspect webhook delivery and the outbox worker, not
  the writers.

Both fire on `increase(... > 0)` over 15m because every refusal is
already an anomaly — the fail-closed design intentionally trades
availability for bounded queues.

When the webhook is the root cause, the delivery circuit opens first and
pauses POSTs (see `docs/dispatch-circuit-breakers.md`); the pending
backlog then trips backpressure. Read the two docs together when
troubleshooting a webhook outage.

## Verification

```sh
cd services/query-runtime
go build ./... && go vet ./...
go test ./internal/httpclient/ ./internal/outbox/ \
  ./internal/engine/ -run Backpressure -count=1
go test ./internal/runtime/ -run Overload -count=1
go test ./...
cd ../.. && python scripts/check_migrations.py
```

No migrations were added for this phase: the outbox pending count is a
read over the existing `outbox_events` table.
