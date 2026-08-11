# Administrative Separation of Duties

Phase 8.4: the platform operator surface is split into **distinct
API-key roles**, so no single operator key can perform every privileged
action. A key-manager operator cannot open break-glass grants or
provision tenants; a break-glass operator cannot mint keys; a tenant
operator cannot do either. The legacy `admin` scope still satisfies
every check (backward compatible), and every mutation beyond scope
checks keeps requiring a verified operator identity.

## Operator roles

| Role | Scope | Endpoints |
|---|---|---|
| Tenant operator | `provision` | `POST /v1/admin/tenants`, `GET .../{tenant_id}`, `.../events`, `.../disable`, `.../enable`, `.../deprovision` |
| Key operator | `key_admin` | `POST /v1/admin/api-keys`, `POST .../{id}/rotate`, `DELETE .../{id}` |
| Break-glass operator | `break_glass` | `POST /v1/security/break-glass/grants`, `GET .../grants`, `GET .../grants/{id}`, `POST .../{id}/revoke` |
| Auditor | `audit` | Read-only audit, chain verify, leak report (unchanged) |
| Legacy | `admin` | Satisfies **every** operator role via `hasScope`'s override — existing keys keep working unchanged |

Everything else (agents, governance, connectors, usage) is a
**tenant-scoped** duty with its own dedicated scope and is out of scope
for the platform-operator split.

## Enforcement

- **Per-route gates.** Each surface's routes are registered with its
  role scope (`server.go` `Routes`, `breakGlassScope`, `keyAdminScope`,
  `tenantProvisionScope`); `hasScope` (`auth.go`) accepts the role scope
  or the legacy `admin` override. No route uses the mega-scope alone for
  platform duties.
- **Fail-closed.** A key without the required role scope gets
  `403 {"error":"insufficient_scope"}` before any handler runs.
- **No scope registry.** Scope strings are free-form (deduplicated at
  key creation); roles are enforced only by the route gates, so there is
  no single place a typo silently grants more.
- **Keys default to `query` only.** Key creation with no scopes yields a
  query-only key (`normalizeCreateAPIKeyRequest`) — never an implicit
  admin.

## Not included (deliberately)

- **Two-person rule / approval tickets** for destructive operations:
  explicitly out of this build's scope; a follow-up can add
  single-use, expiring approval tickets with hash-chained evidence.
- **Privileged-ops ledger** beyond what each surface already records
  (tenant lifecycle events, break-glass grant events, API-key
  expiry/rotation are observable via the audit API).
- **Read-only operator roles** (e.g. read-only key listing): the read
  endpoints above require the same role as the mutations; a read-only
  split can ride on the audit scope in a later build.

## Verification

```sh
cd services/query-runtime
go test ./internal/runtime/ -run "TestKeyAdminRole|TestBreakGlassRole|TestProvisionRole|TestLegacyAdmin|TestQueryOnly" -v
go test ./internal/runtime/ -run BreakGlass -count=1   # existing surface still green
python ../scripts/check_migrations.py                  # migration gate unchanged
```
