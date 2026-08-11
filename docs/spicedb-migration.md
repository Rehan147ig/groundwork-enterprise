# OpenFGA → SpiceDB migration (Phase C) — COMPLETE

> **Status: DONE.** SpiceDB is the sole authorization backend. OpenFGA has
> been decommissioned: the OpenFGA adapter, the `fga-to-spicedb` tool, the
> dual-write overlay, OpenFGA services/envs in every compose/Fly/Render
> deployment, and the OpenFGA metrics/alerts are all gone. This document
> records the decision, the target architecture, and what the completed
> cutover left behind.

## Decision

Authorization for query-runtime moved from OpenFGA to [SpiceDB](https://authzed.com/spicedb)
(Google Zanzibar-compliant, horizontal scaling, snapshot consistency, no
open-source licensing constraints). SpiceDB is the sole authorization
backend.

## Why

- **Consistency**: SpiceDB provides `at_least_as_fresh` (token-tracked) and
  `fully_consistent` reads; OpenFGA local mode is eventually consistent with
  no per-request freshness control.
- **Scale**: SpiceDB partitions/shards and scales horizontally; OpenFGA local
  is single-node.
- **Operations**: SpiceDB has a first-class TLS/CA story, a pre-shared-key
  auth model, and a stable `authzed-go` client.

## Schema

Single source of truth: `services/query-runtime/internal/relationship/schema/groundwork.zed`
(embedded via `//go:embed`). The runtime fails closed (`ErrModelMissing`)
if the deployed SpiceDB schema ever drifts from it.

```zed
definition user {}

definition group {
  relation member: user | group#member
}

definition folder {
  relation viewer: user | group#member
  permission view = viewer
}

definition document {
  relation parent: folder
  relation viewer: user | group#member
  permission view = viewer + parent->view
}

definition tool {
  relation use: user | group#member
}

definition tool_action {
  relation execute: user | group#member
}
```

### Mapping (OpenFGA → SpiceDB)

| Groundwork semantic | OpenFGA | SpiceDB |
|---|---|---|
| can view folder/document | `viewer` relation + folder inheritance | `view` **permission** (computed; SpiceDB cannot compute relations) |
| can use tool | `use` relation | `use` relation |
| can execute tool action | `execute` relation | `execute` relation |
| identity | `user:<id>` | `user:<tenant>:<escaped-id>` (see below) |
| groups | `group:<id>#member` | `group:<tenant>:<escaped-id>#member` |

SpiceDB can compute *permissions* from relations but cannot compute
*relations* from other relations, so folder inheritance lives in the
computed permission `view = viewer + parent->view` instead of a materialized
`viewer` relation. **The adapter's permission name is identity**: checks use
`view`, `use`, `execute` exactly as written; do not map `view` → `viewer` on
the wire.

### Tenancy

OpenFGA was a *shared store* (tenant id is not sent on the wire; isolation
was enforced by caller guards). SpiceDB keeps one namespaced copy per
tenant: every object/user id is escaped (`EscapeID`) and prefixed
`<tenant-id>:` (e.g. `user:acme:rehan`, `document:acme:doc-1`). Checks and
writes are scoped to the tenant id passed by the runtime, and the caller
guard remains the outer enforcement boundary. The cutover's
`fga-to-spicedb` tool replicated the full source set under each tenant
scope (source tuple `user:rehan viewer document:doc-1` became
`user:acme:rehan viewer document:acme:doc-1`).

## Runtime wiring

- `SPICEDB_ENDPOINT` set → SpiceDB is the **primary** authorizer.
- Neither `SPICEDB_ENDPOINT` nor a connector configured → in-memory
  `MemoryFGA` demo mode (local/dev only; no external permission store).
- `SHADOW_AUTHORIZER=spicedb` → shadow mode: a sampled fraction of checks
  (FNV-32a-deterministic, `SPICEDB_SHADOW_SAMPLE_RATE`) are mirrored to a
  second SpiceDB endpoint; its answer never affects the response
  (best-effort 50 ms fallback on primary error). Use this to validate a new
  SpiceDB endpoint *before* promoting it.

### Consistency (`SPICEDB_CONSISTENCY`)

| Value | Read semantics |
|---|---|
| `minimize_latency` (default) | any replica |
| `at_least_as_fresh` | token-tracked: every write refreshes the token; reads are never stale relative to the last observed write |
| `fully_consistent` | strongest |

### Resilience

- Circuit breaker per backend (settings via `SPICEDB_CIRCUIT_*`); only
  classified transport errors trip it, denied responses count as success.
  Trips are exported as `spicedb_circuit_trips_total`.
- Readiness: SpiceDB is ready only when health check, bootstrap, schema read
  **and** `IsUpToDate()` all pass — otherwise `/readyz` fails and the
  container is not scheduled traffic. Deep readiness provisions the schema
  on first boot (no warm-up ordering needed).

## Deploy

- `deploy/fly/spicedb/fly.toml` — internal-only SpiceDB app on Fly
  (Postgres datastore on Supabase, preshared key via secrets).
- `services/query-runtime/Dockerfile.allinone` + `render-entrypoint.sh` —
  free-hosting all-in-one image that runs SpiceDB on localhost.
- `infra/docker-compose*.yml`, `deploy/sovereign/docker-compose.sovereign.yml`
  — `spicedb` service (memory datastore in dev, Postgres in sovereign).
- `.env.*.example` — `SPICEDB_PRESHARED_KEY`, `SPICEDB_CONSISTENCY`.

## Metrics

- `groundwork_relationship_backend_unreachable_total` — fail-closed denials
  from an unreachable relationship backend.
- `groundwork_relationship_shadow_fallbacks_total{tenant_id}` (shadow mode)
- `groundwork_relationship_shadow_errors_total{tenant_id}` (shadow backend failures)
- `groundwork_relationship_shadow_mismatches_total{tenant_id,category}`
  — decision-parity mismatches: `allow_deny_mismatch` or `error_mismatch`.
  Observe-only; the primary decision is authoritative.
- `groundwork_spicedb_circuit_trips_total`
- `groundwork_acl_sync_conflicts_total{tenant_id,sink}` (secondary sink
  write/delete failures during dual-write)
