# @groundwork/sdk

TypeScript client for the Groundwork query runtime API. Zero runtime
dependencies (global `fetch`, Node >= 18 or any browser).

## Usage

```ts
import { GroundworkClient } from '@groundwork/sdk';

const client = new GroundworkClient({
  baseUrl: process.env.QUERY_RUNTIME_URL!,   // e.g. http://localhost:8080
  apiKey: process.env.GROUNDWORK_API_KEY!,
  // assertion: () => mintToken(),           // required for mutations
});

const { agent } = await client.createAgent({
  name: 'research-agent',
  business_purpose: 'read-only research',
  risk_tier: 'low',
});

const { tools, count } = await client.listTools();
```

Mutations require a verified user assertion (`X-Groundwork-User-Assertion`),
provided as a static string or a provider function. Phase 6 mutations
(trust relationships, external agents, consents, transfer policies,
external budgets, delegation minting) additionally require an
`Idempotency-Key` — pass it as the last argument to those methods.

Errors are thrown as `GroundworkError` with `status`, `code` (the runtime's
`{"error": ...}` code), and optional `detail`.

## Development

```
npm run build          # tsc -> dist/ (ESM + .d.ts)
npm test               # build + node:test unit tests (no framework deps)
node test/smoke.mjs    # live checks against a running demo-mode runtime
```

## Design

- Hand-written, typed per endpoint group; mirror the runtime DTOs
  (snake_case JSON). See `docs/client-strategy.md` for why no codegen.
- Canonical source of truth: `services/query-runtime/internal/runtime`
  Go structs + `docs/openapi/groundwork.yaml`.
- List responses carry `count`; single-entity mutations wrap
  (`{agent}`, `{tool}`, `{detail}`, ...) — matching the real envelopes.
