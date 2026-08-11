# Security Policy

Groundwork is an authorization and audit infrastructure product: security is the product. We take every report seriously and respond promptly.

## Supported Versions

| Version | Supported |
|---|---|
| `main` (development) | ✅ |
| Tagged releases | ✅ (latest stable) |

## Reporting a Vulnerability

**Do not open a public GitHub issue for a vulnerability.**

Instead, report privately:

- **Email:** [security@groundwork.dev](mailto:security@groundwork.dev) *(placeholder — replace with the maintainer's address)*
- **GitHub private advisory:** use the *Security → Report a vulnerability* flow on the repository.

Include as much of the following as possible:

1. Affected component and version (`query-runtime`, `ingestion`, `console`, `infra`, `migrations`).
2. A minimal reproduction: environment, configuration, and the smallest payload/request that triggers the issue.
3. Impact — what an attacker can do, and whether authorization or audit guarantees are affected.
4. Suggested fix, if you have one.

### Response timeline

| Step | Timeframe |
|---|---|
| Acknowledgment | Within 48 hours |
| Triage / severity assessment | Within 5 business days |
| Fix target | Commensurate with severity (CVSS) |
| Public disclosure | After a fix ships, coordinated with the reporter |

## Scope

The following are always in scope:

- Authorization bypass: any path that returns data without a live, allowed permission check.
- Fail-open conditions: any path that returns data when the authorization backend is unavailable, slow, or misconfigured.
- Audit integrity: any way to rewrite, delete, or forge audit records.
- Cross-tenant leakage: identity, tenancy, namespace, or store isolation failures.
- Secrets handling: tokens, keys, or credentials leaked via logs, APIs, or artifacts.
- Supply chain: compromised dependencies with a demonstrated exploit path.

Out of scope:

- LLM prompt injection via document content (documented as partially mitigated — [README](README.md)).
- Social engineering of end users.
- Issues in third-party infrastructure (SpiceDB, Qdrant, Elasticsearch, PostgreSQL) unless Groundwork's integration introduces the flaw.

## Security Posture (in brief)

- **Fail-closed enforcement:** any timeout, circuit trip, or backend error returns zero citations and is recorded in the audit log. See [docs/governance.md](docs/governance.md).
- **Immutable audit:** append-only traces with SHA-256 digests and a `/v1/audit/verify` endpoint. See [docs/worm-archive.md](docs/worm-archive.md).
- **Live permission checks:** SpiceDB evaluated at query time — no permission caching. See [docs/spicedb-migration.md](docs/spicedb-migration.md).
- **Secrets scanning** in CI on every push: `.github/workflows/secret-scan.yml`.
- **Supply-chain scanning:** `govulncheck` (Go) and `npm audit --audit-level=high` (production deps) are required CI checks.
- **Non-bypassable deployment:** only Groundwork ingress is exposed; internal backends are network-isolated. See [docs/non-bypassable-deployment.md](docs/non-bypassable-deployment.md).
- **Full threat model:** trust boundaries, compromise scenarios, finding status, and key-rotation procedures live in [docs/threat-model.md](docs/threat-model.md). Notable posture decisions:
  - Console API routes use **header-based auth only** (no cookies) — CSRF does not apply. If cookie sessions are ever added, SameSite=Strict + CSRF tokens are required first.
  - Demo mode (`ALLOW_DEMO_IDENTITY`, `ALLOW_MEMORY_API_KEYS`, `GROUNDWORK_DEMO_MODE`) is **fail-closed by default**: the runtime refuses to start with those flags outside local/dev `GROUNDWORK_ENV`, and the console serves synthetic data only with an explicit opt-in.
  - Identity assertions from the console use **RS256** (private key at the console, public key at the runtime) when configured; HS256 remains a local/dev fallback.
  - Leak-report details are sanitized at the API boundary and at render time (only `<code>` is permitted); client-supplied API keys are rejected.

## Attribution

We will credit reporters who wish to be named in the advisory. We do not offer bug bounties at this time.
