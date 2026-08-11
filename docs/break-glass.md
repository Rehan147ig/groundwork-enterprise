# Break-Glass Operator Access

Time-bounded, reason-mandatory emergency admin access for operators.
A verified operator opens a grant, which mints a **short-lived
admin-scoped API key**; every lifecycle transition (opened / expired /
revoked) appends **hash-chained, write-once evidence**. Expired and
revoked grants fail closed at the API-key auth layer on the very next
request.

## API

All endpoints require the `break_glass` API-key scope (Phase 8.4
separation of duties — the legacy `admin` scope still satisfies it).
`Open` and `Revoke` additionally require a **verified operator identity**
(`X-Groundwork-User-Assertion` JWT). `tenant_id` always comes from the
verified key, never the body. A `break_glass` operator must not hold
`key_admin` or `provision`: opening a grant is the emergency path, not
routine key or tenant management.

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/security/break-glass/grants` | Body `{reason, duration_minutes}`. `reason` is mandatory; `duration_minutes` is capped by `BREAK_GLASS_MAX_MINUTES` (default `60`). Returns `{grant, key}` — the **minted admin key is returned exactly once and never persisted**; losing it requires opening a new grant. |
| `GET` | `/v1/security/break-glass/grants` | Tenant's grants, newest first. Grants past `expires_at` are lazily flipped to `expired` (evidence appended). |
| `GET` | `/v1/security/break-glass/grants/{id}` | One grant + its full hash-chained event log. |
| `POST` | `/v1/security/break-glass/grants/{id}/revoke` | Body `{reason}` (mandatory). Revokes the bound API key immediately, records `revoked` evidence. Already revoked/expired → `409 break_glass_grant_not_active`. |

Error codes: `break_glass_unavailable` (503, service not wired),
`reason_required` (400), `break_glass_grant_not_found` (404),
`break_glass_grant_not_active` (409), `api_key_expired` (401 — a
break-glass key past its expiry is rejected before any handler runs).

## Security invariants

1. **Fail-closed expiry at the auth layer.** Grants mint keys with
   `api_keys.expires_at`; `Resolve` rejects expired keys with
   `ErrAPIKeyExpired` → HTTP `401 api_key_expired`. No handler, policy,
   or service layer check is needed — access stops the moment the window
   closes, even if the operator holds a copy of the key.
2. **Fail-closed revocation.** Revoking a grant deletes the key from the
   resolver immediately; the next use is `401 invalid_api_key`.
3. **Mandatory reasons and bounded durations.** `Open`/`Revoke` reject
   empty reasons; durations are capped by the service configuration
   (never silently shortened).
4. **Tamper-evident evidence.** Every transition appends a
   `break_glass_events` row digesting all security-relevant fields plus
   the previous event's digest (chain is per-tenant, so it cannot fork).
   The schema's write-once rules make direct `UPDATE`/`DELETE` no-ops.
5. **Atomic lifecycle.** Grant creation + evidence, and revocation +
   evidence, run inside one transaction serialized per tenant
   (`pg_advisory_xact_lock`) — the chain cannot fork under concurrency.
6. **One-time key disclosure.** The minted raw key appears only in the
   `Open` response; the store records just `key_id`/`key_prefix`, never
   the secret.

## Storage

- **Postgres** (production): `breakglass.NewPostgresStore(db)`.
  Requires migration 026 (`break_glass_grants`,
  `break_glass_events` with CHECK-constrained enums and write-once
  rules). Used when `DATABASE_URL` is set.
- **In-memory** (dev/demo): `breakglass.NewMemoryStore()` — ephemeral.

`cmd/query-runtime/main.go` wires the store and passes the API-key
resolver as the `KeyMinter` (`BREAK_GLASS_MAX_MINUTES` configures the
duration cap). When the service is not wired at all, the endpoints
return `503 break_glass_unavailable`.

## Verification

```sh
cd services/query-runtime
go test ./internal/runtime/ -run BreakGlass -v   # HTTP surface + fail-closed expiry/revocation
go vet ./internal/runtime/... ./internal/breakglass/...
python ../scripts/check_migrations.py             # migration gate
```
