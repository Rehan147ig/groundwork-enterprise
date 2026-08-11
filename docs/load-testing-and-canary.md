# Load testing & production canary

Two operator tools under `services/query-runtime/cmd/`. Both talk to the stack over HTTP, so
they run from any machine against a local or deployed Groundwork.

## `loadtest` — seed a realistic dataset + measure performance

Turns "I worry it's slow" into numbers: p50/p95/p99 latency, throughput, and the fail-closed
rate under concurrency. Three modes: **seed**, **setup**, **load**.

**Seed** a bank-shaped dataset (run the runtime once first so it provisions the SpiceDB store):
```bash
go run ./cmd/loadtest -mode=seed \
  -qdrant=http://localhost:6333 -spicedb=http://localhost:8081 \
  -spicedb-store=groundwork_local -tenant=acme -region=uk \
  -users=500 -docs=2000
```
This upserts `-docs` documents into Qdrant (deterministic vectors, so re-seeds converge) and
grants each of `-users` users access to one document (deterministically: user *i* → doc
*i mod docs*), so the load run hits a realistic mix of authorized and fail-closed queries.

**Setup** the governed plane once (idempotent — safe to re-run):
```bash
go run ./cmd/loadtest -mode=setup \
  -runtime=http://localhost:8080 -apikey=$GROUNDWORK_API_KEY \
  -jwt-secret=$GROUNDWORK_JWT_HS_SECRET -spicedb=http://localhost:8081 \
  -tenant=acme -region=us-east-1
```
Creates (or finds) the `loadtest-agent` with an active version, the governed builtin tool
`loadtest_search` with a `search` action and grant, and the SpiceDB `use` tuple for the
delegated subject. Required once before `-mode=load` for the governed paths.

**Load** the runtime:
```bash
go run ./cmd/loadtest -mode=load \
  -runtime=http://localhost:8080 -apikey=$GROUNDWORK_API_KEY \
  -jwt-secret=$GROUNDWORK_JWT_HS_SECRET -tenant=acme \
  -users=500 -concurrency=50 -duration=30s
```

Five paths, enabled with `-paths=query,delegation,dispatch,connector,evidence` (each gets
`-concurrency` workers; at least one worker per enabled path):

| Path | What it drives | "Allowed" | "Fail-closed" |
|---|---|---|---|
| `query` | `POST /v1/query` as a random user | 200 with citations | 200 with zero citations |
| `delegation` | mint → run → `evaluate` on `loadtest_search:search` | allowed | denied |
| `dispatch` | mint → run → `dispatch` on the builtin tool | dispatched | denied |
| `connector` | mint → run → `dispatch` on a nonce `http` connector aimed at an internal stub (auto-registered per run, grant + tuple included) | dispatched | denied |
| `evidence` | `GET /v1/governance/evidence` | 200 | — |

Each request mints a signed end-user JWT, and the tool reports per path: requests, req/s,
allowed vs fail-closed counts, **fail-closed rate**, 429s, errors, and latency
**p50/p95/p99/max**. (Run the **audit-timeout fix** + rate-limit PRs first, or you'll be
load-testing those gaps rather than the system.)

**Reports** — every run also writes `loadtest-report-<timestamp>.json` (override with
`-report=path.json`, stdout-only with `-report=-`). The schema is stable (`schema_version:
1`): per-path requests/req-per-sec/allowed/fail-closed/throttled/errors and
latency_p50/p95/p99/max plus the run parameters, so reports from different builds can be
diffed as a canary.

## `canary` — production smoke test

A scheduled safety net: verifies the live deployment and **exits non-zero** if a guarantee
breaks, so cron / CI / a scheduled agent can alert.
```bash
go run ./cmd/canary -runtime=https://gw.example.com \
  -apikey=$GROUNDWORK_API_KEY -jwt-secret=$GROUNDWORK_JWT_HS_SECRET \
  -authorized-user=alice@corp.test
```
Checks: `/healthz`; **fail-closed** (an unauthorized user must receive **zero** documents — a
leak fails the canary loudly); and, if `-authorized-user` is given, that the authorized path
returns documents. Wire it to a 5–15 min schedule and alert on a non-zero exit.

## Related: backend auth for non-bypassable deployment

To make "every retrieval goes through Groundwork" literally true, set these on the runtime so
the datastores **require** the runtime's secret (and firewall them to the runtime's network):

| Variable | Effect |
|---|---|
| `QDRANT_API_KEY` | runtime sends Qdrant's `api-key` header |
| `ELASTICSEARCH_API_KEY` | runtime sends `Authorization: ApiKey` |
| `SPICEDB_TOKEN` | runtime sends SpiceDB's `Authorization: Bearer` pre-shared key |

All optional; unset = current behavior.
