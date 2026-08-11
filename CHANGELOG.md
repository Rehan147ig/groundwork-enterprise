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
