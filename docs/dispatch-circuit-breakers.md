# Dispatch Circuit Breakers

Phase 8.2 reliability: the two outbound delivery paths — connector tool
calls and outbox webhook delivery — fail fast on dead dependencies
instead of burning their timeout + retry budget on every attempt. This
completes the breaker story that Phase 3 (retrieval/ACL) and PR #22
(audit write) started.

| | |
|---|---|
| Breaker primitive | `internal/runtime/circuit_breaker.go` (+ `BreakerRegistry`) |
| Connector dispatch | `internal/connectors/gateway.go` (`dispatch`, `reportDispatch`) |
| Outbox delivery | `internal/outbox/worker.go` (`deliver`) |
| Metrics | `internal/metrics/metrics_phase8.go` |

## Why two more circuits

- **Connector dispatch**: a dead connector endpoint currently costs the
  full `TimeoutMS` + the connector's `RetryMax` retries **on every
  dispatch**. A noisy agent would keep paying that price forever, and
  each attempt is an evidence record saying the endpoint is down. The
  circuit collapses three consecutive failures into a fast
  `connector_breaker_open` refusal until a probe succeeds.
- **Outbox delivery**: the worker already backs off exponentially, but
  a dead webhook means every poll cycle re-attempts every pending event
  (up to `BatchSize`), growing attempts without any new information. The
  per-tenant circuit stops POSTing entirely — events stay pending with
  **no attempt consumed** — until a probe succeeds.

## Behavior

Both circuits use the shared breaker semantics: `FailureLimit` (default
3) consecutive failures open the circuit; after `OpenTimeout` (default
30s) a single half-open probe passes; success closes, failure reopens.

### Connector dispatch

- Keyed per `(tenant_id, connector_id)` — one dead connector never
  blackouts another tenant's or another connector's traffic.
- The breaker guards **only the outbound call**. The preflight (fresh
  read, lifecycle, region, manifest, secret resolution) runs first and
  is never gated — a revoked/suspended connector still fails closed with
  its own lifecycle error while the circuit is open.
- Only **transport errors and 5xx responses** trip the circuit. 4xx
  responses (per-request client problems) and blocked responses
  (response-size/content-type defense) never blackout a connector.
- Open-circuit dispatches return outcome `failure`, error code
  `connector_breaker_open`, mapped to HTTP 503 — and are recorded as
  invocation evidence like any other dispatch (the evidence contract is
  unchanged).
- Health probes (`DispatchHealth`) are **not** circuit-gated: they are
  credential-free and cheap, and stay usable during an outage.

### Outbox delivery

- Keyed per `tenant_id` — one tenant's dead webhook never pauses
  another tenant's deliveries.
- While open, `deliver` returns before the claim: the event stays
  pending, `Attempts` is untouched, and no webhook POST happens. The
  worker simply retries next cycle, which is when the half-open probe
  goes through.
- **Any** delivery failure trips the circuit. Delivery payloads are
  system-generated, so a 4xx from the webhook means the receiver is
  rejecting deliveries — pausing is correct (and the pending backlog
  then trips outbox backpressure, `docs/backpressure-and-overload.md`,
  which refuses new evidence writes rather than growing the backlog).
- The circuit settings can be tuned per worker via
  `Config.BreakerFailureLimit` / `Config.BreakerOpenTimeout`.

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `groundwork_connector_breaker_state{tenant_id,connector_id}` | gauge | 0 closed, 1 half_open, 2 open |
| `groundwork_connector_breaker_trips_total{tenant_id,connector_id}` | counter | Transitions to open |
| `groundwork_outbox_delivery_breaker_state{tenant_id}` | gauge | 0 closed, 1 half_open, 2 open |
| `groundwork_outbox_delivery_breaker_trips_total{tenant_id}` | counter | Transitions to open |
| `groundwork_outbox_delivery_breaker_skips_total{tenant_id}` | counter | Delivery attempts skipped while open |

`deploy/prometheus/alerting-rules.yml` pages/warns when either circuit
is open for 10 minutes (`GroundworkConnectorBreakerOpen`,
`GroundworkOutboxDeliveryBreakerOpen`).

## Verification

```sh
cd services/query-runtime
go build ./... && go vet ./...
go test ./internal/runtime/ -run Breaker -count=1
go test ./internal/connectors/ -run Breaker -count=1
go test ./internal/outbox/ -run Breaker -count=1
go test ./...
```

No migrations were added: breaker state is in-memory and per-instance,
like the rate/concurrency limiters.
