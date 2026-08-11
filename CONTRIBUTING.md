# Contributing to Groundwork

Thank you for contributing. Groundwork enforces permissions for real organizations — please treat every change with the care the security posture demands.

## Table of Contents

- [Development environment](#development-environment)
- [Repository layout & build isolation](#repository-layout--build-isolation)
- [Branching & workflow](#branching--workflow)
- [Commit conventions](#commit-conventions)
- [Code standards by layer](#code-standards-by-layer)
- [Testing](#testing)
- [Pull request process](#pull-request-process)
- [Security-sensitive changes](#security-sensitive-changes)

## Development environment

Prerequisites:

| Tool | Version | Purpose |
|---|---|---|
| Go | 1.23+ | `services/query-runtime`, `services/msgraph-connector` |
| Python | 3.11+ | `services/ingestion`, `packages/python` |
| Node.js | 18.17+ | `apps/console`, `packages/typescript` |
| Docker | latest | `infra/docker-compose*.yml`, integration testing |
| Docker Compose | v2 | local stack |
| `gh` CLI | 2.x | GitHub workflows (optional) |

Install JavaScript workspaces (includes Turbo):

```bash
npm install
```

## Repository layout & build isolation

Groundwork is a monorepo with three independent layers:

- **Go services** (`services/`) — own module, own builds, own tests.
- **Python services** (`services/ingestion`, `packages/python`) — own environment, own tests.
- **TypeScript workspaces** (`apps/console`, `packages/typescript`) — managed by npm workspaces + Turborepo.

Each layer must build and test **in isolation**. A change in the Go runtime must never require a Python environment, and vice versa. Turbo is only the orchestrator for the TypeScript tasks:

```bash
npm run typecheck   # turbo run typecheck (both TS workspaces)
npm run build       # turbo run build
npm run test        # turbo run test
npm run test:runtime  # go test ./... (query-runtime)
npm run test:ingestion # python -m unittest discover services/ingestion/tests
```

Never introduce a cross-layer build-time dependency (e.g., Go code calling into `node_modules`).

## Branching & workflow

Trunk-based development with short-lived branches:

1. Create a branch from `main`: `git checkout -b feat/your-feature` or `fix/...`.
2. Keep branches small and focused (one logical change per PR).
3. Open a pull request against `main`.
4. Squash-and-merge with the Conventional Commit title (see below).

Branch naming:

| Prefix | Purpose |
|---|---|
| `feat/` | New capability |
| `fix/` | Bug fix |
| `refactor/` | Code restructuring with no behavior change |
| `docs/` | Documentation only |
| `chore/` | Tooling, CI, housekeeping |
| `security/` | Security fix — use this for anything touching authorization |

## Commit conventions

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>
```

Examples:

- `feat(runtime): add spicedb consistency mode to ACL checks`
- `fix(ingestion): handle empty document bodies in chunker`
- `docs(security): document fail-closed guarantees`
- `chore(ci): parallelize go test across packages`

Scopes include: `runtime`, `ingestion`, `console`, `connector`, `spicedb`, `audit`, `identity`, `governance`, `infra`, `ci`, `docs`, `deps`.

**Never commit secrets, `.env` files, build artifacts, or `node_modules`.**

## Code standards by layer

### Go (`services/query-runtime`, `services/msgraph-connector`)

- `go vet ./...` and `go test ./...` must pass.
- Errors are propagated or handled — no swallowed errors.
- All authorization paths fail closed; never log credentials or tokens.
- Public types used across packages are documented.

### Python (`services/ingestion`)

- `python -m unittest discover tests` must pass.
- `python -m py_compile` on every module.
- Embedding/chunking functions return clean errors on edge cases (empty input, oversized payloads).

### TypeScript (`apps/console`, `packages/typescript`)

- `npm run typecheck` (via `turbo run typecheck`) must pass with zero errors.
- Console API routes keep server-side keys out of the browser bundle.
- SDK packages build to `dist/` via `tsc` and are consumed via workspace exports.

### SQL migrations (`migrations/`)

- Migrations are **append-only** — never edit an applied migration.
- `.up.sql` and `.down.sql` pairs are required and must be reversible.
- New migrations are numbered after the highest existing one.

## Testing

Run the full gate locally before pushing:

```bash
# Go
cd services/query-runtime && go vet ./... && go test ./...

# Python
cd services/ingestion && python -m unittest discover tests

# TypeScript
npm run typecheck && npm run build

# Infra
docker compose -f infra/docker-compose.yml config --quiet
```

CI runs these on every push (`.github/workflows/`): `go-ci`, `python-ci`, `console-ci`, `compose-validate`, `migration-check`, `secret-scan`, `security-ci`.

## Pull request process

1. Title follows Conventional Commits (it becomes the merge commit message).
2. Description states the problem, the change, and how it was verified.
3. At least one approving review before merge (enabled via branch protection on `main`).
4. Squash-merge only.
5. Verify the PR checks are green — including `secret-scan` and `security-ci`.

## Security-sensitive changes

Anything touching authorization, identity, audit, or fail-closed behavior is security-sensitive:

- Call out the change explicitly in the PR description (label `security`).
- Add or update tests proving the **deny** and **fail-closed** paths, not just the allow path.
- Never weaken a fail-closed path without an explicit, documented decision.
- Secrets, keys, and tokens must never appear in code, logs, or the audit trail.
- For vulnerabilities, follow [SECURITY.md](SECURITY.md) — do not open a public issue.

---

Questions? Open an issue or reach out through the repository's discussion space.
