# Groundwork Threat Model

This document is the security analysis for the Groundwork platform. It answers the
three questions every deployment must be able to answer — *what happens if the
console is compromised*, *what happens if the runtime is compromised*, and *what
happens if SpiceDB is compromised* — and records the status of every finding from
the security review (2026-08).

## Trust boundaries

```
 Browser
   │  same-origin fetch (no cookies; header auth)
   ▼
 Console (Next.js, server-side)
   │  GROUNDWORK_API_KEY (server-held) + RS256/HS256 user assertion (10m TTL)
   ▼
 Query Runtime (Go)
   │  API key → tenant/region/scope   ·  assertion → end-user identity
   ├── Postgres (api_keys, agents, governance, audit chain)
   ├── SpiceDB (relationships — the authorization source of truth)
   ├── Qdrant / Elasticsearch (embeddings / evidence index)
   └── Connectors (outbound, manifest-allowlisted, redacted)
```

- Tenant identity, region, and scopes come **only** from the API key.
- End-user identity comes **only** from a signed assertion (`X-Groundwork-User-Assertion`).
- Nothing identity-bearing is ever accepted from bodies, URLs, or plain headers.

## Compromise scenarios

### What happens if the console is compromised?

The console holds the runtime API key and the identity signing private key
(RS256) or shared secret (HS256).

- An attacker with the console's **runtime API key + signing key** can mint
  assertions as any persona and query the runtime as that user. They cannot mint
  a **different tenant's** keys (tenants come from the API key, not the
  assertion), cannot grant new scopes, and cannot mutate the relationship store
  unless the API key itself is admin-scoped.
- **Blast-radius reduction**: the console's key should be a dedicated key with
  the narrowest scope the console needs (e.g. `query` + `agents` read), never
  the bootstrap key. The `key_admin`/break-glass scopes are deliberately
  separate.
- **Recommendation**: prefer RS256 so the runtime never holds signing material.
  Rotate the console's API key on any suspected compromise (see `Key rotation`
  below); assertion TTL is 10 minutes, so revoked identities stop being mintable
  within the rotation window.
- CSRF is **not applicable** to the console's API routes: authentication is
  header-based (`X-Groundwork-API-Key` + assertion), no cookies are set or read,
  and every state-changing call requires both. If cookie-based sessions are ever
  introduced, SameSite=Strict + a CSRF token must be added (see `Open items`).

### What happens if the runtime is compromised?

The runtime holds the SpiceDB token, database credentials, and (with HS256) the
identity shared secret.

- **With RS256**: a compromised runtime still cannot mint user assertions
  (only the console holds the private key) — it can only act within the scopes
  of the API keys it already holds.
- With HS256 the shared secret lets the attacker mint assertions directly. This
  is why production deployments should use RS256 (or OIDC).
- A compromised runtime can read everything its keys can read — including the
  full audit chain and any relationship data. It **cannot** tamper with the
  audit chain undetectably (hash-chained, salt-bound), and it cannot overwrite
  sealed WORM artifacts (`O_EXCL` + fsync + content addressing).
- **Recommendation**: run the runtime with the principle of least privilege on
  its service credentials, separate SpiceDB token per service, and turn on
  SpiceDB TLS (`SPICEDB_INSECURE_PLAINTEXT=false` + CA file) in any deployment
  where the network is not fully trusted.

### What happens if SpiceDB is compromised?

SpiceDB holds the full relationship graph.

- A read compromise leaks who-can-access-what (the authorization model itself,
  not content).
- A write compromise can add/remove relationships — this is why the runtime
  never trusts SpiceDB health alone: every decision still goes through the
  engine's fail-closed path, and the governance decision gate records evidence
  per decision.
- The ACL sync reconciler detects drift: unauthorized relationships are
  reverted on the next sync cycle, and the `acl-sync` drift checks surface them
  as `BackendExtraNotInSource`.
- **Recommendation**: firewall SpiceDB to the runtime only (it has no public
  ports in the compose stacks), enable TLS, and back it with an immutable
  snapshot for forensics.

## Review findings — status

| ID | Finding | Status |
|----|---------|--------|
| C-001 | Stored/Reflected XSS via `dangerouslySetInnerHTML` (`page.tsx`) | **Fixed** — `lib/sanitize.ts` allowlist sanitizer applied at the API boundary (`leak-report` route) *and* at render; only `<code>` survives. |
| C-002 | `math/rand` in security-sensitive contexts | **Fixed** — retry/backoff jitter and load-test selection now draw from `crypto/rand` (`retry.go`, `aclsync/jitter.go`, `msgraph`, `loadtest`). |
| C-003 | Auth bypass via demo-mode fallback | **Fixed** — console demo fallback requires explicit `GROUNDWORK_DEMO_MODE=true`; runtime fails startup with `ALLOW_DEMO_IDENTITY=true` (or `ALLOW_MEMORY_API_KEYS=true`) unless `GROUNDWORK_ENV` is local/dev. |
| H-001 | Path traversal in `FileWORMStore` | **Fixed** — root absolutized/validated at construction, every path containment-checked, artifact IDs validated as 64-hex content addresses. |
| H-002 | Client-supplied API key | **Fixed** — `/api/query` ignores `payload.api_key`; only server-side `GROUNDWORK_API_KEY` is used. |
| H-003 | Missing CSRF protection | **Not applicable / documented** — all console auth is header-based, no cookies; CSRF requires ambient credentials. Documented here and in `SECURITY.md`. |
| H-004 | JWT HS256 shared secret, no rotation path | **Fixed** — console mints RS256 assertions (`GROUNDWORK_JWT_RS_PRIVATE_KEY[_FILE]`); runtime verifies with `GROUNDWORK_JWT_RS_PUBLIC_KEY[_FILE]` (already supported). Rotation procedure below. |
| H-005 | Secret exposure via connector errors | **Already mitigated** — `internal/connectors/redact.go` (`redactError`, `RedactJSON/Text`, `RedactHeader`) applied to REST + MCP transports; responses are size-limited and redacted before leaving the gateway. |
| M-001 | Plaintext inter-service HTTP | **Documented risk** — internal Docker network only; SpiceDB has no published ports and `SPICEDB_INSECURE_PLAINTEXT=true` is explicit in compose. Production hardening path: mTLS/network policies + `SPICEDB_INSECURE_PLAINTEXT=false` with a CA. |
| M-002 | Race in `MemoryAPIKeyResolver` | **Fixed** — key-ID counter is now `atomic.Int64`. |
| M-003 | Dynamic SQL surface | **Already mitigated** — production queries are parameterized `$N`; `fmt.Sprintf` SQL exists only in tests. Added a grep-based CI lint: `docs/ci.md` documents the ban. |
| M-004 | Missing rate limiting | **Already mitigated** — per-key (`RateLimiter`, enforces `rate_limit_rpm`) and per-tenant (`TenantRateLimiter`) limits wired at `server.go`; 429 with Retry-After; health endpoints exempt. |
| M-005 | CORS misconfiguration | **Not applicable** — the Go runtime sets no CORS headers (same-origin/BFF model); any future CORS must be an explicit allowlist, never `*` with credentials. |
| M-006 | Sensitive headers in logs | **Already mitigated** — no request-logging middleware exists; nothing logs `Authorization`/`X-Groundwork-API-Key`/assertion headers. New middleware must use the redaction helpers. |
| L-001 | Health endpoints exposed | **By design / documented** — `/healthz`/`livez`/`readyz` are unauthenticated for orchestration probes; `readyz` is tested to never leak raw dependency errors (server_test.go). Restrict the listener to the internal network in production. |
| L-002 | Timing oracle in API-key lookup | **Fixed** — the prefix miss path now runs one bcrypt verification (`dummyBcryptHash`), equalizing latency between absent-prefix and wrong-secret keys. |
| L-003 | Supply-chain verification | **Fixed** — `govulncheck` in `go-ci.yml`; `npm audit --omit=dev --audit-level=high` in `console-ci.yml`; Next.js bumped 16.2.4 → 16.3.0 (7 high advisories), sharp 0.34.5 → 0.35.3; `npm audit` now reports 0 vulnerabilities. |
| L-004 | Static audit salt (`IMMUTABLE_AUDIT_SALT=change-me`) | **Fixed** — the salt is now bound into every audit digest on the write and verify paths (`engine.ComputeDigestWithSalt`, `PostgresAuditWriter.SetSalt`, `PostgresAuditReader.SetSalt`); predictable values (incl. the old `change-me`) are refused at startup (`validateAuditSalt`); an empty salt keeps the original v1 formula so pre-salt chains still verify. |

## Security headers

- Console (`next.config.ts`): CSP (`frame-ancestors 'none'`, `base-uri 'self'`),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy`, `Permissions-Policy`, HSTS (production builds),
  `Cache-Control: no-store`.
- Runtime (`server.go` `securityHeaders` middleware): `nosniff`, `DENY`
  framing, `no-referrer`, `Cache-Control: no-store` on all `/v1/*`.

## Key rotation

1. Generate a new RSA key pair (PKCS#8):
   `openssl genrsa -out console-signing-key.pem 3072 && openssl rsa -in console-signing-key.pem -pubout -out console-verify-key.pub`
2. Publish the **public** key to the runtime (`GROUNDWORK_JWT_RS_PUBLIC_KEY` or
   `_FILE`) and roll the pod — the runtime accepts tokens signed by the new key.
3. Replace the console's `GROUNDWORK_JWT_RS_PRIVATE_KEY` (or `_FILE`).
4. Since assertions are short-lived (10m), both steps can be done in either
   order; the maximum window where an old token is still valid is 10 minutes.
5. For API keys: `POST /v1/admin/api-keys/{id}/rotate` (requires `key_admin`
   scope) — old keys are invalidated immediately.

## Open items

- Cookie-based console sessions (if ever added) require SameSite=Strict + CSRF
  tokens before they ship.
- mTLS for inter-service traffic (M-001) — track deployment-level network
  policies; enable SpiceDB TLS for external deployments.
- CSP nonce support for the Next.js App Router to drop `'unsafe-inline'`
  script-src (requires a nonce middleware; next-plugin-csp is an option).

See also: [SECURITY.md](../SECURITY.md) (reporting), [ci.md](ci.md)
(security gates), [spicedb-migration.md](spicedb-migration.md).
