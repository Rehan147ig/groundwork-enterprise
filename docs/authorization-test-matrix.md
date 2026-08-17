# Authorization & Fail-Closed Test Matrix

> Source of truth for what Groundwork must enforce across identity modes,
> resources, backends, and transports. Every cell's expected result is
> contract-tested: the `integration` build-tag suite exercises the live
> engine against real Postgres + SpiceDB + Qdrant (`scripts/integration-test.sh`),
> and the unit suite pins the in-memory equivalents.

## Legend

| Outcome | Meaning |
|---|---|
| `ALLOW` | Permitted chunk(s) returned, evidence row written |
| `DENY` | Zero citations, decision recorded, no data reaches the model |
| `FAIL_CLOSED` | Zero citations, `FailureStage` + `ErrorCode` set, evidence written where the stage permits |

The three are distinct in the audit ledger (`acl_decision`): `allowed`,
`denied`, and `fail_closed`. A `DENY` is a correct authorization decision;
a `FAIL_CLOSED` is a safety decision when a dependency is unavailable.

## Matrix

### Identity modes × resources (SpiceDB healthy)

| Identity mode | Permitted resource | Denied resource | Wrong tenant | Wrong region | No relationship |
|---|---|---|---|---|---|
| API key (trusted tenant/region) | `ALLOW` | `DENY` | `DENY` | `DENY` | `DENY` |
| JWT HS256 (verified subject) | `ALLOW` | `DENY` | `DENY` | `DENY` | `DENY` |
| OIDC / JWKS (verified issuer) | `ALLOW` | `DENY` | `DENY` | `DENY` | `DENY` |
| Canonical principal (resolved) | `ALLOW` | `DENY` | `DENY` | `DENY` | `DENY` |
| Demo identity (local only) | `ALLOW` | `DENY` | `DENY` | `DENY` | `DENY` |

### Backends × transports

| Backend state | REST `/v1/query` | MCP | Cloud MCP `/mcp` |
|---|---|---|---|
| SpiceDB healthy | `ALLOW`/`DENY` by policy | same | same |
| SpiceDB down | `FAIL_CLOSED` | `FAIL_CLOSED` | `FAIL_CLOSED` |
| SpiceDB slow (timeout) | `FAIL_CLOSED` | `FAIL_CLOSED` | `FAIL_CLOSED` |
| Qdrant down | `FAIL_CLOSED` | `FAIL_CLOSED` | `FAIL_CLOSED` |
| Audit Postgres down | `FAIL_CLOSED` | `FAIL_CLOSED` | `FAIL_CLOSED` |
| Audit breaker open | `FAIL_CLOSED` | `FAIL_CLOSED` | `FAIL_CLOSED` |
| Outbox high-water | `FAIL_CLOSED` (`outbox_backpressure`) | same | same |

### The non-negotiable invariant

```text
For every "down / degraded" cell above, the only acceptable result is
0 citations + an evidence row. There is no fallback to an open state.
```

## Where each cell is proven

- **Engine unit tests** — `internal/engine/*_test.go`: per-chunk ACL deny,
  region/tenant isolation, audit-write failure, circuit breaker, backpressure.
- **Runtime unit tests** — `internal/runtime/*_test.go`: identity
  verification precedence, canonical principal, auth bearer/JWT, OIDC.
- **Integration suite** — `test/integration/` (build tag `integration`):
  `TestFailClosedOnUnauthorizedUser`, `TestFailClosedWhenSpiceDBDown`,
  `TestFailClosedWrongRegionAndTenant`, `TestFailClosedWhenAuditWriteFails`,
  `TestAuditChainWritesToPostgres`.

## Adding a new transport or backend

1. Add the row/column here.
2. Add an `integration` test using the existing harness
   (`newSpiceDBChecker`, `deadGRPCEndpoint`, `postgresAuditor`,
   `errorAuditor`).
3. Verify every "down" cell resolves to `FAIL_CLOSED`, never `ALLOW`.

## Chaos drills (nightly, real stack)

`scripts/integration-test.sh` runs the integration suite. Add these
fail-closed drills to the nightly job:

1. Stop SpiceDB mid-traffic → 100% `FAIL_CLOSED`, breaker opens, recovery
   on restart (assert zero partial data).
2. Stop Postgres (audit) mid-traffic → audit circuit path, zero citations,
   pod readiness degrades (`/readyz` fails).
3. Saturate the outbox → `503 outbox_backpressure` before unbounded
   backlog.
4. Restore drill → `cmd/archive` restore-through-verify, then
   `/v1/audit/verify` returns `verified`.
