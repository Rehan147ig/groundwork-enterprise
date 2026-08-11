# Changelog

All notable changes to Groundwork are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial open-source release of the Groundwork platform monorepo.
- Monorepo formalized as a Turborepo: npm workspaces (`apps/console`, `packages/typescript`)
  with `turbo run build|lint|typecheck|test` task orchestration; Go and Python services
  remain fully isolated layers (`services/query-runtime`, `services/ingestion`).
- Enterprise documentation set: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, Apache-2.0 `LICENSE`.
- CI workflows for Go, Python, console, compose validation, migration checks,
  secret scanning, and security checks (`.github/workflows/`).
- Security hardening review (2026-08), see `docs/threat-model.md`:
  - `docs/threat-model.md` — trust boundaries, compromise scenarios, finding status, key rotation.
  - Console: allowlist HTML sanitizer for leak-report details (`lib/sanitize.ts`),
    RS256 assertion minting (`lib/jwt.ts`), security headers in `next.config.ts`
    (CSP, HSTS, framing/sniffing/referrer protection, no-store).
  - Runtime: security-headers + `no-store` middleware on `/v1/*`; startup guards
    refuse `ALLOW_DEMO_IDENTITY=true` / `ALLOW_MEMORY_API_KEYS=true` unless
    `GROUNDWORK_ENV` is local/dev.
  - `crypto/rand` jitter for retry/backoff (runtime, aclsync, msgraph, loadtest);
    atomic key-ID counter; bcrypt timing equalization in API-key lookup;
    `FileWORMStore` root containment + artifact-ID validation.
  - Supply chain: `govulncheck` in `go-ci.yml`; `npm audit --omit=dev --audit-level=high`
    in `console-ci.yml`; Next.js 16.2.4 → 16.3.0 (7 high advisories), sharp 0.35.3;
    grpc v1.82.1, pgx v5.9.2, golang-jwt v5.2.2, x/text v0.39.0; Go toolchain
    go1.26.5 (stdlib crypto/tls, crypto/x509, net/textproto advisories);
    `npm audit` and `govulncheck` now report 0 vulnerabilities.

### Changed

- Authorization backend fully migrated from OpenFGA to SpiceDB:
  - SpiceDB gRPC adapter with tenant-scoped relationship encoding.
  - `internal/relationship` codec, circuit breaker, memory reference implementation,
    and schema in `internal/relationship/schema/groundwork.zed`.
  - Runtime configuration via `SPICEDB_ENDPOINT` / `SPICEDB_TOKEN` /
    `SPICEDB_INSECURE_PLAINTEXT` / `SPICEDB_CA_FILE` / `SPICEDB_CONSISTENCY`.
  - Deep-readiness provisions the authorization model at boot; seeders write
    relationships only.
  - Legacy OpenFGA adapter, `fga-to-spicedb` tool, dual-write overlay, and OpenFGA
    services/envs removed from all compose, Fly, and Render deployments.
  - Historical audit column `openfga_latency_ms` / API field `OpenFGALatencyMs`
    retained for backward compatibility of the immutable audit wire format.
- `cmd/msgraph-connector` now requires `MSGRAPH_TENANT_ID`, `MSGRAPH_CLIENT_ID`,
  `MSGRAPH_CLIENT_SECRET`, and `DATABASE_URL` (or `POSTGRES_URL`).
- Governance decision gate renamed from `openfga` to `relationship`.

### Fixed

- Dockerfile no longer builds the decommissioned `cmd/fga-to-spicedb`.
- Non-bypassable validation scripts check SpiceDB gRPC (50051) and HTTP (8443)
  instead of the removed OpenFGA port (8081).

### Security

- Fail-closed behavior verified end-to-end: backend unavailability, timeouts, and
  circuit trips return zero citations and write evidence to the audit log.
- Secrets scanning enforced in CI.

---

**Previous iterations of this project (pre-monorepo) are not part of this
changelog.** See the repository history and `docs/` for the migration record.
