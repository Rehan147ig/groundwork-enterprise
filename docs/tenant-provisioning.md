# Tenant Provisioning

The operator-managed **tenant directory** (Phase 8.1 Multi-tenancy and
isolation). Tenants are provisioned through the admin API, each with a
trusted region, a lifecycle status, and **hash-chained, write-once
evidence** of every transition. A disabled or deprovisioned tenant
**fails closed at the auth layer** on its next request — no handler or
service-layer check is needed.

There is deliberately **no delete route**: deprovisioning is the
terminal, non-destructive lifecycle state (per the roadmap, "do not add
destructive delete by default"). A deprovisioned tenant can only be
revived by re-provisioning.

## API

All endpoints require the `provision` API-key scope (the `admin` scope
inherits via the existing override). Mutations additionally require a
**verified operator identity** (`X-Groundwork-User-Assertion` JWT);
demo identities are always rejected for provisioning.

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/admin/tenants` | Body `{tenant_id, region, reason, mint_admin_key?}`. `reason` mandatory. Provisioning an existing active tenant with the same region is idempotent; a different region on an active tenant → `409 tenant_region_conflict` (deprovision first); a disabled tenant → `409 tenant_not_active`. `mint_admin_key: true` returns a one-time `gw_live_...` admin+query key (`key` in the response; never persisted — losing it means re-provisioning). |
| `GET` | `/v1/admin/tenants` | Full directory (config-seeded + provisioned), sorted by tenant id. |
| `GET` | `/v1/admin/tenants/{tenant_id}` | One entry: `{tenant_id, region, status, created_by, reason, created_at, updated_at, deprovisioned_at?}`. |
| `GET` | `/v1/admin/tenants/{tenant_id}/events` | The tenant's full hash-chained lifecycle evidence (oldest first). |
| `POST` | `/v1/admin/tenants/{tenant_id}/disable` | Body `{reason}` (mandatory). `active → disabled`; idempotent when already disabled. The tenant's keys fail closed on the next request. |
| `POST` | `/v1/admin/tenants/{tenant_id}/enable` | Body `{reason}` (mandatory). `disabled → active`. A deprovisioned tenant cannot be enabled (re-provision instead) → `409 tenant_not_active`. |
| `POST` | `/v1/admin/tenants/{tenant_id}/deprovision` | Body `{reason}` (mandatory). `active|disabled → deprovisioned`; terminal. |

Error codes: `tenant_management_unavailable` (503, service not wired),
`reason_required` / `tenant_id_required` / `region_required` (400),
`tenant_not_found` (404), `tenant_region_conflict` / `tenant_not_active`
(409), `tenant is not active` / `tenant region does not match deployment
region` (403 — the auth-layer directory checks, returned to the
tenant's own keys).

## Lifecycle

```
                 ┌──────────┐  disable   ┌───────────┐
   provision ───▶│  active   │ ──────────▶│ disabled  │ ─┐
                 └──────────┘ ◀────────── └───────────┘  │ deprovision
                 │          ▲    enable                   │
                 │          └─────────────────────────────▼─┐
                 │                                     ┌──────────────┐
                 └──────────── re-provision ──────────▶│ deprovisioned │ (terminal; no delete)
                                                       └──────────────┘
```

## Security invariants

1. **Fail-closed directory at the auth layer.** After key resolution,
   `authenticate` consults the directory (`TenantDirectory`): a tenant
   with status `disabled` or `deprovisioned` is rejected with
   `403 tenant is not active`; a tenant whose key region differs from
   its directory region fails closed with `403 tenant region does not
   match deployment region`. Tenants absent from the directory are
   unaffected (governed only by the trusted region resolver, if wired).
2. **No destructive delete.** `deprovisioned` is the terminal state;
   there is no `DELETE` route and the store has no delete path.
   Re-provisioning a deprovisioned tenant reactivates it (region may
   change; the original `created_at` is preserved).
3. **Mandatory reasons and verified actors.** Every provisioning
   transition requires a non-empty reason and a verified operator
   principal (demo identities rejected).
4. **Tamper-evident evidence.** Every transition appends a
   `tenant_events` row digesting all security-relevant fields plus the
   previous event's digest (chain is per-tenant, so it cannot fork). The
   schema's write-once rules make direct `UPDATE`/`DELETE` no-ops.
5. **Atomic transitions.** Status change + evidence append run inside
   one transaction serialized per tenant (`pg_advisory_xact_lock`) — the
   chain cannot fork under concurrency.
6. **One-time key disclosure.** `mint_admin_key` returns the raw key
   once in the provision response; the store records only the key
   metadata via the API-key resolver, never the secret. If the directory
   write fails after minting, the key is revoked best-effort.
7. **Config + directory reconciliation.** `GROUNDWORK_TENANT_REGIONS`
   tenants are seeded into the directory at startup (idempotent; seeding
   never overrides directory state — an operator can disable an
   env-configured tenant via the API). The dormant `tenant_regions`
   table (migration 017) is kept in sync in the same transaction so
   Phase 4 exports keep a single region mapping.

## Storage

- **Postgres** (production): `tenancy.NewPostgresStore(db)`.
  Requires migration 027 (`tenants`, `tenant_events` with CHECK-
  constrained enums and write-once rules). Used when `DATABASE_URL` is
  set.
- **In-memory** (dev/demo): `tenancy.NewMemoryStore()` — ephemeral.

`cmd/query-runtime/main.go` wires the store, passes the API-key resolver
as the `KeyMinter`, seeds `GROUNDWORK_TENANT_REGIONS` tenants, wires the
env resolver as the auth-layer region resolver, and calls
`server.SetTenantService(...)`. When the service is not wired at all,
the endpoints return `503 tenant_management_unavailable` and no
directory check runs.

## Verification

```sh
cd services/query-runtime
go test ./internal/tenancy/ -v                    # lifecycle, evidence chain, seed, lookup
go test ./internal/runtime/ -run TestTenant -v    # HTTP surface + auth fail-closed
go vet ./internal/tenancy/... ./internal/runtime/...
python ../scripts/check_migrations.py             # migration gate (003..027)
```
