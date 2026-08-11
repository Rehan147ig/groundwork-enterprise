# Observability and Supportability (Phase 8.5)

Operational surface for escalation and monitoring: decision-latency
decomposition, outbox delivery health, connector and key-expiry
monitoring, correlation IDs, and a tenant-scoped support bundle with
strict redaction. Metrics are registered via `metrics.RegisterPhase8()`
(automatically by `cmd/query-runtime`; also see Phase 3's
`RegisterPhase3`).

## Metrics

All metrics are tenant-labeled only — no run, event, key, or connector
ids — so cardinality stays bounded. Served at `GET /metrics`.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `groundwork_decision_gate_duration_seconds` | histogram | `tenant_id`, `gate` | One governed decision gate's duration. Closed gate set: `controls`, `grant_binding`, `agent`, `permitted`, `tool`, `grant`, `budget`, `spicedb`, `approval`. Recorded for short-circuited gates too, so every path is attributable. |
| `groundwork_outbox_pending_age_seconds` | gauge | `tenant_id` | Age of the tenant's oldest pending outbox event (0 = none). |
| `groundwork_outbox_dead_letter_pending` | gauge | `tenant_id` | Dead-lettered outbox events awaiting manual inspection. |
| `groundwork_connector_health` | gauge | `tenant_id`, `connector_id` | Last health-probe result (1 healthy / 0 unhealthy). Set by `GET /v1/governance/connectors/{id}/health`. |
| `groundwork_key_expiry_timestamp_seconds` | gauge | `purpose` | Key expiry as a Unix timestamp (0 = no expiry configured). |
| `groundwork_key_days_until_expiry` | gauge | `purpose` | Days until key expiry (negative = expired, 0 = none). Refreshed on a one-minute cadence by `cmd/query-runtime` from `Keyring.Expiries`. |

### SLO counters

The Phase 8 acceptance SLO surface (decision rate, denial rate,
fail-closed rate, error rate) is emitted by the service layer and the
HTTP layer:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `groundwork_slo_decisions_total` | counter | `tenant_id`, `outcome` | Every governed decision outcome (`allowed`, `denied`, `fail_closed`, `approval_required`). Emitted from `enqueueDecision`, so every decision write funnels through it. |
| `groundwork_http_requests_total` | counter | `tenant_id`, `method`, `code_class` | Every authenticated API response by status class (`2xx`/`3xx`/`4xx`/`5xx`), including early 403/429/503s. Requests that fail before the API key resolves record with an empty `tenant_id`. |
| `groundwork_connector_errors_total` | counter | `tenant_id`, `connector_id`, `error_code` | Failed connector dispatches (preflight + transport) and unhealthy health probes. |

Supporting counters that were previously defined but unwired are now
emitted:

| Metric | Type | Labels | Emitted from |
|---|---|---|---|
| `groundwork_control_events_total` | counter | `tenant_id`, `entity`, `action` | Every applied emergency control (`setControl`). |
| `groundwork_budget_exhaustions_total` | counter | `tenant_id`, `reason` | Every budget denial (evaluator budget gate + citation gate). |
| `groundwork_audit_verify_total` | counter | `tenant_id`, `outcome` | Every `VerifyAuditChain` run (`verified`/`failed`) — the alerting signal for audit-chain tampering. |
| `groundwork_evidence_events_total` | counter | `tenant_id`, `kind` | Decisions, approvals, delegation mints, and emergency controls recorded as evidence. |
| `groundwork_outbox_delivered_total` / `groundwork_outbox_dead_letter_total` | counter | `event_type` | Outbox worker deliveries and dead letters. |
| `groundwork_outbox_pending` | gauge | `tenant_id` | Pending event count per tenant (published with the pending-age gauge). |

The SLO counter table is what the acceptance criterion asks for:
decision rate (`slo_decisions_total`), denial rate
(`slo_decisions_total{outcome="denied"}`), fail-closed rate
(`{outcome="fail_closed"}`), latency (`query_latency_seconds`,
`decision_gate_duration_seconds`), errors (`http_requests_total`
5xx + `connector_errors_total` + `spicedb_unreachable`), and outbox
health (`outbox_pending`, `outbox_pending_age_seconds`,
`outbox_dead_letter_pending`).

### Key expiries

`keyring.Key` gained `ExpiresAt`. The env provider reads an optional
RFC3339 `GROUNDWORK_<PURPOSE>_KEY_EXPIRY` (e.g.
`GROUNDWORK_WEBHOOK_KEY_EXPIRY=2027-01-01T00:00:00Z`); KMS-backed
`ExternalProvider` implementations set it in `GetFn`. `Keyring.Expiries`
never errors and never surfaces key material.

### Outbox health

The delivery worker publishes the pending-age and dead-letter gauges on
every cycle when the store implements the optional
`OutboxPendingStats` capability (memory + Postgres stores do). Stores
without the capability simply skip the gauges — the delivery cycle is
never failed by stats.

## Correlation IDs

Every response carries `X-Groundwork-Correlation-Id`. The middleware
accepts an incoming `X-Groundwork-Correlation-Id` (fallback:
`X-Correlation-Id`), generates one when absent, echoes it, and stamps it
on the request context. `POST /v1/query` maps it to the engine trace id,
so the audit row (`/v1/audit/{trace_id}`), request logs, and support
case share one identifier. The id is never accepted from the request
body.

## Support bundle

`GET /v1/security/support-bundle` streams a tenant-scoped diagnostics
zip. Requires the `admin` API-key scope **and** a verified operator
identity (`X-Groundwork-User-Assertion` JWT) — the same bar as
break-glass Open/Revoke. Errors: `support_bundle_unavailable` (503,
source not wired), `support_bundle_failed` (503, source error),
`verified_identity_required` (403).

Archive layout (`application/zip`):

| Entry | Contents |
|---|---|
| `manifest.json` | generated_at, tenant_id, section list |
| `status.json` | service, tenant, region, API-key wiring, readiness-probe results |
| `keys.json` | per-purpose key expiries (never material) |
| `outbox.json` | per-tenant pending age + dead-letter counts (when the store supports stats) |
| `connectors.json` | registered connectors (registry holds no raw secrets) |

The source is assembled in `cmd/query-runtime`
(`supportBundleSource`): key expiries via `Keyring.Expiries`, outbox
stats via `runtime.OutboxStatsSource`, connector registry via
`connectors.Gateway.List`. Section failures degrade to missing sections
rather than failing the archive, so a dead dependency never blocks an
escalation. Redaction is by construction: no secrets, tokens,
assertions, or document text are ever included.

## Alerting and dashboards (SLO)

- `deploy/prometheus/alerting-rules.yml` — Prometheus rules covering
  the SLO surface: fail-closed rate > 5% (page), denial-rate spike,
  HTTP 5xx rate, stale outbox (> 10 min), dead-letter backlog,
  **audit-chain verify failures (page — tamper-evidence event)**,
  key expiry (warn at 30 days, page when expired), unhealthy
  connectors, open circuit breakers, SpiceDB unreachable, and budget
  exhaustion spikes.
- `deploy/grafana/groundwork-overview.json` — a Grafana dashboard
  (UID `groundwork-slo-overview`) with panels for decision rate by
  outcome, denial and fail-closed rates (with the 5% SLO threshold),
  API traffic by status class, p95/p99 latency, outbox age and dead
  letters, connector health, days-to-key-expiry, audit verification
  outcomes, and budget exhaustions. Import it with a Prometheus
  datasource UID `DS_PROMETHEUS`.
