# Client Strategy

How Groundwork's first-party client SDKs are built, versioned, and kept in
sync with the query runtime — and how the console will migrate to them.

## Status

- **TypeScript** (`@groundwork/sdk`): shipped as `packages/typescript`,
  hand-written, zero runtime dependencies. 8 unit tests + a 33-check live
  smoke test against the running runtime. Published for internal workspace
  use; not yet on a registry.
- **Python** (`groundwork-sdk`): shipped as `packages/python`, hand-written,
  stdlib only (urllib transport). 8 unit tests + a 33-check live smoke test
  (`python test/smoke.py`) mirroring the TypeScript smoke. Ready for local
  install (`pip install -e packages/python`); not yet on a registry.
- **Go** (`groundwork/sdk`): shipped as `packages/go`, hand-written, stdlib
  only. 8 unit tests (httptest) + a 33-check live smoke test
  (`go test -run TestLiveSmoke`) gated on `GW_BASE_URL`. Importable via a
  `replace` directive from the workspace; not yet published.

## Why hand-written instead of codegen

Codegen (openapi-typescript, openapi-generator, etc.) was rejected for v1:

1. **The OpenAPI spec is not authoritative yet.** It has drifted from the
   runtime (auth header naming, `count` envelopes, connector register
   shape — all fixed during SDK delivery). Generating from a drifting spec
   exports wrong types; generating from code exports a second source of
   truth. Hand-written types keep one canonical source: the Go DTOs.
2. **The API is small and stable enough** (~95 paths) that a hand-written
   client is ~700 lines, fully typed, with no toolchain risk.
3. **Richer error semantics**: the runtime error envelope is
   `{"error": code, "detail"}`; a generated client would swallow it into
   generic exceptions. `GroundworkError` preserves `status`, `code`, and
   `detail`.
4. **Auth is bespoke**: `X-Groundwork-API-Key` + `X-Groundwork-User-Assertion`
   + `Idempotency-Key` on Phase 6 mutations. Codegen handles standard
   schemes only.

**When to reconsider codegen:** once the OpenAPI spec passes a full
contract test against the runtime (every endpoint exercised, diff-gated in
CI). The contract test is the prerequisite, not the codegen tool.

## Single source of truth

- The **Go structs** in `services/query-runtime/internal/runtime` are
  canonical. `packages/typescript/src/types.ts` mirrors them (snake_case
  JSON) and `docs/openapi/groundwork.yaml` describes them.
- Response **envelopes** were verified against the handlers' `writeJSON`
  calls, not guessed: lists carry `count`, single-entity mutations wrap
  (`{agent}`, `{tool}`, `{grant}`, `{detail}`, `{relationship}`, ...).
- **Rule:** every SDK change ships with a live smoke check. The smoke test
  (`packages/typescript/test/smoke.mjs`) runs against a demo-mode runtime
  and exercises each envelope shape. If a shape diverges, the smoke test
  fails first.

## Auth model

| Header | Value | Notes |
|---|---|---|
| `X-Groundwork-API-Key` | API key (`Authorization: Bearer` also accepted) | Key scopes gate endpoint groups; `tenant_id` comes from the key, never the body |
| `X-Groundwork-User-Assertion` | Short-lived HS256 JWT (console-minted) or OIDC token | Required for mutations; omitted entirely for key-scoped reads |
| `Idempotency-Key` | Client-generated UUID | Required for Phase 6 mutations (trust relationships, external agents, consents, transfer policies, external budgets, delegation minting) |

The SDK accepts `assertion` as a static string or a provider function
(cleanly plumbed to OIDC token refresh). `mintUserAssertion()` exists for
local dev and first-party console flows only — production assertions come
from the enterprise IdP.

## Versioning

- `@groundwork/sdk` is semver'd independently (`0.1.0`). The console pins
  the workspace version; the runtime does not consume the SDK.
- Breaking API changes bump the SDK minor/major independently of runtime
  versions. The `/healthz` `version` field is the runtime contract anchor.
- Until `1.0.0`, expect frequent 0.x bumps; the smoke test gate keeps
  churn honest.

## Console migration

`apps/console/lib/*Proxy.ts` currently hand-rolls fetch calls and response
types with a demo-fallback `source` field. Migration plan (next dev pass):

1. Replace proxy internals with `GroundworkClient` calls (keep the
   server-side JWT minting; wire it as `assertion` provider).
2. Keep the `source` demo-fallback at the API route layer, not in the SDK —
   the SDK speaks only runtime shapes.
3. Delete the proxy-local type unions in favor of `@groundwork/sdk` types.
4. Keep `QUERY_RUNTIME_URL`/`GROUNDWORK_API_KEY` env wiring as the client
   options source.

## Roadmap

- [ ] Contract test: drive every OpenAPI path against the runtime in CI
- [x] Python SDK (`groundwork-sdk`): stdlib-only, same envelope/error
      semantics, 7 unit + 29 live-smoke checks (all green)
- [x] Go SDK (`groundwork/sdk`): reuses the wire surface mirrored from
      `internal/runtime` DTOs, 7 unit + 29 live-smoke checks (all green)
- [ ] Publish TS SDK to a registry (private or public) once console
      migration lands
- [ ] MCP transport support in the TS SDK (`POST /mcp` JSON-RPC)
