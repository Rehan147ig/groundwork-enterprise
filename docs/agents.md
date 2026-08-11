# Agent Registry — Agent Trust and Control Plane (Phase 1)

Groundwork's agent registry turns every AI agent into a first-class,
tenant-scoped identity with an accountable owner, a declared purpose, a
lifecycle state, a version history, and a tamper-evident audit trail of
every lifecycle change.

| | |
|---|---|
| Schema | `migrations/014_create_agents.{up,down}.sql` |
| Implementation | `services/query-runtime/internal/agentregistry` (store + service + digest) |
| HTTP surface | `services/query-runtime/internal/runtime/agents_api.go` |
| Console | `apps/console/app/console/page.tsx` ("Agents" view) + `app/api/agents/*` proxy routes |

> **Phase 2 (Delegated Authority & Governed Agent Execution)** is
> documented in `docs/governance.md`.

## Endpoints

All endpoints require the `agents` API-key scope (or the existing
`admin` override). `tenant_id` always comes from the verified API key —
never from bodies, query strings, or URLs.

| Method | Path | Identity required | Notes |
|---|---|---|---|
| `POST` | `/v1/agents` | verified | Create — always lands in `draft` |
| `GET` | `/v1/agents?state=` | — | List, newest-first, `state` filter optional |
| `GET` | `/v1/agents/{agent_id}` | — | Detail + versions + lifecycle events |
| `POST` | `/v1/agents/{agent_id}/versions` | verified | Register a draft version |
| `POST` | `/v1/agents/{agent_id}/activate` | verified | `draft \| pending_approval \| suspended` → `active` |
| `POST` | `/v1/agents/{agent_id}/suspend` | verified | `active` → `suspended` |
| `POST` | `/v1/agents/{agent_id}/revoke` | verified | Any non-terminal → `revoked` (IRREVERSIBLE) |
| `POST` | `/v1/agents/{agent_id}/retire` | verified | Any non-terminal → `retired` (terminal) |

Mutations also require that the caller is the **agent owner** (the
principal recorded as `owner_principal_id`) or uses an **admin-scoped
key** — enforced by the service, not the HTTP layer. Errors use a stable
`{"error": "<code>"}` envelope; codes are the sentinel errors in
`internal/runtime/agents.go` (`agent_not_found`, `agent_name_conflict`,
`agent_operation_not_authorized`, `invalid_agent_state_transition`,
`agent_version_conflict`, `invalid_agent_request`,
`agent_registry_unavailable`).

## Lifecycle model

```
                    ┌────────────┐
        create ───▶ │   draft    │ ──activate──▶ ┌──────────┐ ──suspend──▶ ┌───────────┐
                    └────────────┘               │  active   │              │ suspended │
                       │  ▲                      └──────────┘ ◀──activate─── └───────────┘
                       │  │                           │  │
                version │  │ version                  │  │
              registered│  │ approved/                ▼  ▼
                       │  └──────────┐      ┌─────────────┐
                       │             │      │  revoked    │  terminal
                       └─────────────┼─────▶│ (irreversible)│
                    pending_approval │      └─────────────┘
                                     └─────▶ ┌─────────────┐
                                            │  retired    │  terminal
                                            └─────────────┘
```

Rules:

- **Never auto-activates.** Creation always lands in `draft`; a version
  must be registered and explicitly activated.
- **Exactly one active version.** Activation promotes the newest usable
  (non-revoked, non-superseded) version `draft → approved → active` and
  supersedes all others. Adding a version to an *active* agent
  immediately supersedes the current active version.
- **Resume keeps the version.** `suspended → active` reactivates the
  existing active version.
- **Revocation is irreversible.** `revoked` agents and every version
  freeze permanently: no activation, no suspension, no retirement, no
  new versions, no un-revocation.
- **Versions are frozen on terminal agents.** No new versions on
  `revoked` or `retired` agents.
- **Name uniqueness per tenant.** `UNIQUE (tenant_id, name)` and
  `UNIQUE (agent_id, version)` are enforced at the schema level; the
  service maps conflicts to 409.

## Security model

1. **Tenant scoping** — every query filters by `tenant_id` from the
   verified API-key context; cross-tenant lookups return 404 (no
   existence leak). Verified in unit and Postgres integration tests.
2. **Fail-closed identity** — mutations require a verified end-user
   assertion (`X-Groundwork-User-Assertion`). No assertion, invalid
   signature, or expired token → 401. Demo identity
   (`ALLOW_DEMO_IDENTITY=true`, dev only) resolves to the synthetic
   `demo_actor`.
3. **Owner-or-admin authorization** — transitions require the recorded
   owner principal or an admin-scoped key. The body can *declare* an
   owner label at creation (defaults to the caller), but the caller is
   then not implicitly the owner.
4. **Tamper-evident events** — every lifecycle change appends a row to
   `agent_lifecycle_events`. Each row carries `immutable_digest` = SHA-256
   over all security-relevant fields **plus the previous event's
   digest**, so edits, deletion, reordering, or insertion break the
   chain. The schema's write-once rules (`no_update_agent_events`,
   `no_delete_agent_events`) make direct SQL tampering a no-op.
5. **Atomic transitions** — multi-step transitions (read → validate →
   version side-effects → agent state → event append) run inside one
   transaction serialized per agent with
   `pg_advisory_xact_lock(hashtext(agent_id))`, so the chain cannot fork
   under concurrency.

## Storage

- **Postgres** (production): `agentregistry.NewPostgresStore(db)`.
  Requires migration 014. `agents` / `agent_versions` /
  `agent_lifecycle_events` with CHECK-constrained enums, write-once
  rules, and lookup indexes.
- **In-memory** (dev/demo): `agentregistry.NewMemoryStore()`. Ephemeral;
  used automatically when `DATABASE_URL` is unset. When the registry is
  not wired at all, `/v1/agents*` returns 503 `agent_registry_unavailable`.

`cmd/query-runtime/main.go` wires Postgres when `DATABASE_URL` is set,
in-memory otherwise.

## Console

The console's **Agents** view (sidebar → Agents) lists the registry with
state badges, risk tier, environment, active version, and per-agent
detail: versions, the hash-chained event stream, and lifecycle actions
(activate / suspend / retire / revoke / add version). The proxy routes
under `app/api/agents/*` mint a short-lived `console-admin` JWT
(HS256, `GROUNDWORK_JWT_HS_SECRET`) and attach the server-side API key —
neither the key nor the secret reaches the browser. Without a configured
runtime the view falls back to curated demo data; mutations are never
faked (they surface the runtime's error).

## Verification

```sh
cd services/query-runtime
go test ./internal/agentregistry/... ./internal/runtime/...   # unit + HTTP
go test -tags integration ./test/integration/...              # Postgres lifecycle, isolation, write-once, chain
python ../scripts/check_migrations.py                         # migration gate (003..015)
```

The integration suite (`test/integration/agents_test.go`) covers the
full lifecycle against real Postgres, tenant isolation at the SQL layer,
and the write-once rules (direct `UPDATE`/`DELETE` on the event table
must be no-ops while the chain still verifies).
