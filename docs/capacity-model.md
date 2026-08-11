# Per-Tenant Capacity Model

Phase 8.2: every tenant carries a **capacity tier** (`standard`,
`plus`, `enterprise`) in the tenant directory, and the runtime derives
its per-tenant in-flight cap from that tier. A tenant pinned at its cap
is refused immediately (fail-closed HTTP 503, never queued) and the
refusals are counted per tenant so capacity planning is observable. This
builds on the Phase 8.1 per-tenant concurrency limiter and sits inside
the same overload-protection stack.

| | |
|---|---|
| Tier column | `tenants.capacity_tier` (migration 029, CHECK-constrained, default `standard`) |
| Tier model | `internal/runtime/tenancy.go` (`CapacityTierStandard/Plus/Enterprise`, `IsCapacityTier`) |
| Capacity model | `internal/runtime/capacity_model.go` (`CapacityModel`, `ConcurrencyFor`) |
| Enforcement | `internal/runtime/server.go` auth middleware (tier lookup → per-call cap) |
| Limiter | `internal/runtime/ratelimit_tenant.go` (`AcquireWithLimit`) |
| Metrics | `internal/metrics/metrics_phase8.go` (`groundwork_tenant_capacity_rejections_total`) |
| Alerts | `GroundworkTenantCapacityRefusals` (warning) |

## Tier semantics

- **Tier is a directory fact.** Provisioned tenants carry a tier
  (`standard` unless the operator requests another); tenants **not** in
  the directory (unprovisioned) fall back to the model **default**.
- **Closed set.** `standard | plus | enterprise` only. Provisioning with
  an unknown tier is rejected; a blank tier normalizes to `standard`, so
  callers that predate tiers keep working.
- **Per-call cap.** The middleware calls
  `AcquireWithLimit(tenantID, model.ConcurrencyFor(tier))` on every
  request; without a model, the limiter's own default applies. The
  effective cap for a tenant is fixed by the first acquire of its slot
  channel, so a tier upgrade takes effect once the tenant's in-flight
  work drains.

## Configuration

| Env var | Meaning | Default |
|---|---|---|
| `LIMIT_CONCURRENCY_PER_TENANT` | `standard` tier cap **and** the model default (unprovisioned tenants) | `0` (unlimited) |
| `CAPACITY_CONCURRENCY_PLUS` | `plus` tier cap | falls back to the standard cap |
| `CAPACITY_CONCURRENCY_ENTERPRISE` | `enterprise` tier cap | falls back to the standard cap |
| `LIMIT_RPM_PER_TENANT` | Phase 8.1 per-tenant rate limit (unrelated, listed for the stack) | `0` (unlimited) |

A non-positive cap means unlimited (the limiter is a no-op), so
deployments that do not configure tiers are never throttled.

```
LIMIT_CONCURRENCY_PER_TENANT=4
CAPACITY_CONCURRENCY_ENTERPRISE=16
```

## Where it sits in the protection stack

Each request passes these gates in order (auth middleware,
`internal/runtime/server.go`):

1. **Instance overload** (`OVERLOAD_MAX_CONCURRENT_REQUESTS`) — whole
   process saturated → 503 `overload_exceeded` (page).
2. **Per-key rate limit** (`LIMIT_RPM_PER_KEY`) → 429 `rate_limit_exceeded`.
3. **Per-tenant rate limit** (`LIMIT_RPM_PER_TENANT`) → 429 `rate_limit_exceeded`.
4. **Per-tenant capacity tier** (this build) → 503 `concurrency_limit_exceeded`
   with `Retry-After: 1`, counted in `groundwork_tenant_capacity_rejections_total{tenant_id}`.

Denials at every gate are fail-closed and never queued; no gate buffers
work for the tenant behind it.

## Metrics

```
groundwork_tenant_capacity_rejections_total{tenant_id}
```

Refusals are a **planning signal**: the tenant's traffic exceeds its
tier, so the operator raises the tier or tunes the caps. Sustained
refusals trip `GroundworkTenantCapacityRefusals` (warning, slo
`api_availability`), which is deliberately *not* a page — a tenant at
its cap is the model working as designed, not a cluster crisis.

## Verification

```sh
cd services/query-runtime
go test ./internal/runtime/ -run "CapacityModel|ConcurrencyLimiter|Tier"   # model + limiter + middleware
go test ./internal/tenancy/ -run "Tier"                                    # directory tier semantics
python ../scripts/check_migrations.py                                      # migration gate (003..029)
```
