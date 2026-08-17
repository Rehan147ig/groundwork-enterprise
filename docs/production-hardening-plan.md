# Groundwork Production Hardening Plan — v0.1 → Enterprise-Deployable

> **Status:** Proposed. Companion to `docs/production-scale-roadmap.md` (feature phases 7–12) and
> `docs/groundwork-production-conditions.md`. This document covers what those do not: closing the
> trust gaps, supply-chain integrity, secure-by-default installation, and the customer-facing
> security package required before startups, mid-market, and enterprise customers can adopt —
> and before any security reviewer signs off.
>
> **Rule:** no phase below may weaken the Non-Negotiable Security Invariants in
> `docs/production-scale-roadmap.md`. Every change fails closed or it does not ship.

---

## 1. Why this plan exists

The core enforcement architecture is sound: live SpiceDB authorization per chunk, fail-closed
everywhere, hash-chained immutable audit, circuit breakers, outbox backpressure, break-glass
with evidence, separation of duties. That is the right skeleton and it is already built.

What stands between this repo and a customer deployment is not features. It is:

1. **Verified trust gaps** — two concrete findings that let a publicly-known credential and a
   publicly-known audit salt into a production deployment (Section 2).
2. **Unsafe-by-default install** — the quickstart and `.env.example` teach copy-paste habits
   that ship those known values.
3. **Missing supply-chain integrity** — unsigned images, no SBOM, committed binaries.
4. **No external verification story** — no pen test, no SOC 2 readiness, no security package
   for procurement.

A governance product is judged by its weakest config default, not its best architecture.
Everything below exists to make the *default path* the *safe path*.

---

## 2. Verified findings (fix before anything else)

Each finding was confirmed by reading the current source. Severity uses DREAD-style impact.

### F-1 · CRITICAL — Default bootstrap key becomes a live admin credential in production

- **Where:** `services/query-runtime/cmd/query-runtime/main.go:57`
  (`BootstrapAPIKey: env("BOOTSTRAP_API_KEY", "gw_local_acme_key")`) and
  `services/query-runtime/internal/runtime/auth.go:278-330` (`bootstrap()` inserts the key into
  `api_keys` with `Scopes: ["query","admin"]` whenever it is non-empty — and the default
  fallback makes it always non-empty).
- **Impact:** any deployment that forgets to set `BOOTSTRAP_API_KEY` silently mints
  `gw_local_acme_key` — a constant published in the open-source repo — as a **query+admin**
  API key. Anyone who reads the GitHub repo can then authenticate to every such deployment:
  mint keys, provision tenants, open break-glass. This is the single most damaging issue in
  the repo because it converts "forgot one env var" into "total auth bypass."
- **Why it slipped through:** `ALLOW_DEMO_IDENTITY` and `ALLOW_MEMORY_API_KEYS` are both
  gated on `isLocalEnv()` (main.go:380-386). The bootstrap key default has no such gate.
- **Fix (P0-1):**
  1. Refuse startup when `BOOTSTRAP_API_KEY` equals the default value and `GROUNDWORK_ENV`
     is non-local — mirror the existing `isLocalEnv()` guards exactly.
  2. In local mode with the key unset, generate a random key at first boot, persist it,
     print the prefix + full value once to stdout, and never regenerate.
  3. Add `groundwork doctor` check: bootstrap key must not match any literal in the repo.
  4. Test: extend the existing production-gate test pattern
     (`internal/runtime/production_gate_test.go`, `admin_identity_gate_test.go`) to pin
     "default key + GROUNDWORK_ENV=production → startup fails."

### F-2 · HIGH — Example audit salt passes validation and ships in copy-pasted `.env`

- **Where:** `.env.example:40` (`IMMUTABLE_AUDIT_SALT=example-audit-salt-017-AaBbCcDdEe`) vs.
  `validateAuditSalt` / `predictableAuditSalts` (main.go:1080-1113).
- **Impact:** the example value is 37 chars (passes the ≥16 check) and is not on the
  blocklist — so every deployment created by `cp .env.example .env` computes its entire
  "tamper-evident" audit chain with a salt published in the repo. An attacker with
  table-write privileges can recompute valid chain digests after tampering; `/v1/audit/verify`
  passes on a forged chain. This defeats threat-model control L-004 *while appearing
  configured correctly*. Because the salt may never change after first write, a deployment
  that starts wrong stays wrong — the only remedy is a new chain.
- **Fix (P0-2):**
  1. Comment the value out in `.env.example`; leave a generator command
     (`openssl rand -hex 32`) and the never-rotate warning.
  2. Add every salt literal that appears in the repo (including this example) to
     `predictableAuditSalts`.
  3. `groundwork init` generates and writes a fresh salt; `groundwork doctor` fails when the
     configured salt matches any string present in the repository tree.
  4. Test: unit test pinning that each documented example salt is rejected.

### F-3 · MEDIUM — Committed build artifacts and hygiene leaks

- **Where:** `services/query-runtime/groundwork.exe`, `services/query-runtime/loadtest.exe`,
  root `console.log('HEALTHZ_ERR'` (a misquoted shell redirect that became a file — evidence
  of a pasted command), `session-summary.md`, root `__pycache__/`, `tmp/`, `.turbo/` caches,
  and `internal/aclsync notion/` (a directory with a space in its name).
- **Impact:** binaries can embed build paths/secrets and are unscannable in review; the
  space-named directory breaks scripts on some platforms; overall, visible hygiene failures
  disproportionately damage credibility for a security product.
- **Fix (P0-3):** remove from git; extend `.gitignore`; add a CI "no artifacts" job
  (fail on tracked `*.exe`, `*.dll`, `*.so`, `__pycache__/`, `tmp/`, stray `console.log*`);
  rename the spaced directory.

### F-4 · MEDIUM — Schema drift: runtime DDL outside the migration chain

- **Where:** `internal/runtime/auth.go:278-310` creates and ALTERs the `api_keys` table at
  startup via `CREATE TABLE IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`; no migration in
  `migrations/` (003–034) owns `api_keys`.
- **Impact:** two sources of schema truth. Hardened databases that revoke DDL from the app
  user break startup; auditors reading the migration history see an incomplete schema; future
  zero-downtime migration tooling can diverge from what pods actually created.
- **Fix (P0-4):** add `035_create_api_keys` (up/down) to `migrations/`; change runtime
  `bootstrap()` to insert-only when the table exists and otherwise fail with a clear
  "run migrations first" error; keep `scripts/check_migrations.py` green.

### F-5 · MEDIUM — Quickstart and examples hardcode the known key

- **Where:** `infra/docker-compose.quickstart.yml`, README quickstart
  (`export GROUNDWORK_API_KEY=gw_local_acme_key`), bank/GitHub demo scripts.
- **Impact:** the very first thing a new operator learns is the credential that F-1 makes
  dangerous. Demos are fine; the *default compose profile* is not.
- **Fix (P0-5):** quickstart entrypoint generates a random key + salt into a gitignored
  `.env.quickstart` on first `up` and prints them; README quickstart reads from that file;
  demo profiles keep fixed keys but only under explicit `profile: demo`.

### F-6 · LOW (capability honesty) — Regex firewall oversold relative to name

- **Where:** `internal/firewall/firewall.go` — regex PII redaction (solid) and regex
  injection scanner (bypassable by paraphrase/unicode/homoglyphs; the 80-char encoded-payload
  rule false-positives on legitimate base64/SHA-256 runs). The repo's own
  `groundwork-production-conditions.md` lists the injection scanner as *not* a core feature —
  yet the product name is "Zero-Trust AI Context Firewall."
- **Fix (P1-6):** ship the truth. Document detection limits in `docs/threat-model.md` and
  README; introduce a pluggable `InjectionDetector` interface with the regex engine as the
  default and an optional stronger detector (embedding/model-based) behind config; add a
  `firewall_mode=block` acceptance test set of known-bypass samples marked
  expected-detect/expected-miss so claims stay testable. Never market the regex layer as
  complete injection defense.

**P0 exit criteria:** F-1…F-5 closed with tests, all existing gates green
(`go vet ./... && go test ./...`, integration suite, `python scripts/check_migrations.py`,
console build, CI workflows).

---

## 3. Phase 1 — Secure-by-default installation (the "15-minute safe start")

Goal: an operator following the default path cannot produce an insecure deployment, and
`GROUNDWORK_ENV=production` refuses every unsafe default at startup.

### 1.1 `groundwork init` hardening

`init` already scaffolds `groundwork.env`, an RSA delegation pair, and a starter policy.
Extend it to be the only supported path to a production `.env`:

- Generates: `BOOTSTRAP_API_KEY` (random, `gw_live_` format), `IMMUTABLE_AUDIT_SALT`
  (`openssl rand -hex 32` equivalent), HS secrets where RS is not chosen.
- Refuses to write any value that matches a literal in the repo.
- Stamps `GROUNDWORK_ENV` explicitly (local|staging|production) and documents that flipping
  it to production enables the fail-closed startup gates below.
- Emits a "seal" summary: which secrets were generated, where they live, which must be
  rotated into a real secret manager before go-live (never `env://` in production).

### 1.2 Production startup gate suite

One concept: when `GROUNDWORK_ENV != local`, startup **fails closed** on each of these.
Each rule gets a test in the production-gate suite so the gates can never silently regress:

| # | Gate | Rule |
|---|------|------|
| G1 | Bootstrap key | set, non-default, not a repo literal |
| G2 | Audit salt | set, ≥16 chars, non-predictable, not a repo literal |
| G3 | Identity | OIDC issuer configured OR RS256 key present; demo identity refused (already enforced — keep pinned) |
| G4 | Memory stores | `ALLOW_MEMORY_API_KEYS=false`; all Postgres-backed stores actually Postgres |
| G5 | TLS | SpiceDB TLS on (no `INSECURE_PLAINTEXT`), Postgres `sslmode` ≠ disable |
| G6 | Sovereign validation | `deployment.Validate` passes with `Production+StrictKeys+ApprovedEgressOnly` (exists — wire it to every non-local env, not only when a deployment region is set) |
| G7 | Firewall | `GW_FIREWALL_MODE` set (redact minimum) or an explicit, logged opt-out variable |
| G8 | Default credentials | no `gw_local_*`, no `acme` bootstrap tenant outside local |

### 1.3 `groundwork doctor` as the single pre-flight

`doctor` exists; make it the gate operators and CI both run, with `--json` for pipelines.
It must verify: all G1–G8 gates, database reachability + schema migration state, SpiceDB
schema match, keyring purposes, quickstart vs production profile, and (in `--deep` mode)
a canary query proving the fail-closed path works (stop SpiceDB → expect 0 citations +
`FAIL_CLOSED` audit row → restart).

### 1.4 One-command tiers (see Section 6 for the operator-facing guide)

- **Tier A — single host (SME/startup):** `curl -fsSL .../install.sh | sh` → `groundwork init`
  → `docker compose -f infra/docker-compose.prod.yml up -d` → `groundwork doctor`. The prod
  compose profile must differ from dev only in generated secrets, TLS, restart policies, and
  non-root containers — never in enforcement flags.
- **Tier B — Kubernetes (mid-market/enterprise):** complete `infra/helm` chart: Postgres HA
  reference (or external DB params), SpiceDB with persistent datastore, runtime + ingestion +
  console deployments, Ingress with TLS, PodSecurityPolicy/seccomp defaults, NetworkPolicy
  default-deny except the documented flows (extends `docs/non-bypassable-deployment.md`).
- **Tier C — sovereign/BYOC:** the existing `deploy/sovereign` packaging, documented with its
  validation gates as the acceptance evidence.

**Phase 1 exit criteria:** a new operator with Docker only reaches a passing `doctor` in
≤15 minutes with zero hand-written secrets; every G1–G8 gate has a pinned test; the quickstart
uses generated credentials end to end.

---

## 4. Phase 2 — Supply chain and artifact integrity

Goal: any artifact a customer runs can be traced to a commit and verified end to end.

1. **SBOM** — Syft/CycloneDX SBOM for all three images (runtime, ingestion, console),
   generated in CI and attached to releases.
2. **Signed images** — cosign keyless signing (OIDC-bound) on every tag; `groundwork doctor
   --verify-image` and Helm `verify` hooks check signatures before deploy.
3. **Provenance** — SLSA Build L3-targeted provenance statements via the existing GitHub
   Actions; document the attestation chain in `docs/`.
4. **Dependency policy** — `govulncheck` (Go), `pip-audit` (Python), `npm audit` (TS) wired
   into CI with a documented severity break-line; Dependabot/Renovate enabled; `go.sum` /
   lockfiles enforced.
5. **Static analysis** — `gosec` + `staticcheck` on the runtime, `bandit` on ingestion,
   CodeQL on all three; findings triaged into the normal PR flow (start at "no new highs").
6. **Release hygiene** — tags are signed; release notes carry SBOM + provenance hashes;
   CHANGELOG maintained per release (file exists — make it load-bearing).

**Phase 2 exit criteria:** a customer can run `cosign verify` + SBOM diff against any
published image; CI fails on new high-severity findings; releases carry attestation.

---

## 5. Phase 3 — Verification depth (prove the claims)

Goal: every marketing sentence in the README maps to a repeatable, automated demonstration.

### 3.1 Authorization test matrix

A single source-of-truth matrix (machine-readable YAML → generated tests) covering:
identity modes (API key, JWT/HS, OIDC, canonical principal) × resources (permitted, denied,
revoked-mid-flight, wrong tenant, wrong region, no-relationship) × backends (healthy,
degraded, down, circuit-open) × transports (REST, MCP, Cloud MCP). The expected result for
every "down" cell is **0 citations + evidence row**. This turns the fail-closed promise into
a regression contract.

### 3.2 Chaos / fail-closed drills (CI-nightly against real stack)

- Kill SpiceDB mid-traffic → 100% of in-flight queries fail closed, zero partial data,
  evidence rows written, breaker opens, recovery on restart.
- Kill Postgres (audit) mid-traffic → audit-circuit path → zero citations (PR #22 behavior,
  now proven nightly), pod readiness degrades.
- Outbox saturation → `503 outbox_backpressure` before any unbounded backlog.
- Restore drill: `cmd/archive` restore-through-verify + `groundwork_audit_verify` green
  afterwards (Phase 8.3's WORM machinery — exercise it on schedule).

### 3.3 Load/SLO evidence

Use the existing `cmd/loadtest` to publish, per release: query path p50/p95/p99, decision
path p99 vs the <100 ms target, fail-closed rate under dependency loss, breaker behavior.
Reports are versioned artifacts (schema_version already exists) attached to releases — this
is the data customers' architects ask for.

### 3.4 External verification

- **Penetration test** (third party, scope: auth bypass, tenant isolation, audit-chain
  tamper, break-glass abuse, connector SSRF/secret handling). Summary letter published;
  findings tracked to closure in this plan.
- **Threat model refresh** per change (the doc exists; add the review step to the PR
  template for connector/identity/firewall changes).

**Phase 3 exit criteria:** matrix + drills run nightly green; one external pen test
completed with findings closed or accepted-with-rationale; load reports published per
release.

---

## 6. Phase 4 — Customer trust & compliance package

Goal: pass procurement and security review without a bespoke effort.

Non-code deliverables (the roadmap's "Sales readiness" list, made concrete):

1. **Security architecture overview** — 10-page doc from `docs/architecture.md` +
   `docs/threat-model.md`, with data-flow diagrams per integration pattern (REST, MCP,
   sidecar).
2. **Shared-responsibility model** — explicit table: what Groundwork enforces vs what the
   customer's IdP/network/model provider must enforce.
3. **Vendor security questionnaire pack** — pre-answered CAIQ-lite / SIG-lite covering the
   ~40 questions that recur in enterprise reviews.
4. **SOC 2 Type I readiness** — trust-services-criteria mapping over existing controls
   (audit evidence, break-glass, separation of duties, change management via hash-chained
   events); commit to Type II window after 3 months of clean operation. SOC 2 is explicitly
   *not* claimed until the audit exists — same honesty rule as F-6.
5. **Deployment guide per tier** — the Section 6 operator guide promoted to `docs/`, plus
   an ops runbook (backup/restore, rotation, break-glass usage, incident response) — extends
   `docs/break-glass.md`, `docs/worm-archive.md`.
6. **Honest scope statement** — a single "What Groundwork does not do" page (from
   `groundwork-production-conditions.md`) linked from the README, including firewall limits.

**Phase 4 exit criteria:** package reviewed by one friendly design partner's security team
end to end; zero "unknown answer" gaps in the questionnaire dry run.

---

## 7. Operator-facing install guide (target: ship as `docs/quickstart-production.md`)

### Startup (SME, single host — the 15-minute path)

```bash
# 1. Install the CLI (single static binary; also on npm/brew)
curl -fsSL https://get.groundwork.dev | sh

# 2. Initialize: generates ALL secrets, refuses unsafe defaults
groundwork init --env production
#    → writes ./groundwork.env (chmod 600), prints seal summary

# 3. Bring up the stack (Postgres, SpiceDB, Qdrant, ES, runtime, console)
docker compose --env-file groundwork.env -f infra/docker-compose.prod.yml up -d

# 4. Migrate + verify
groundwork migrate && groundwork doctor --deep

# 5. First query — permission-checked, firewall-scrubbed, audit-chained
export GROUNDWORK_API_KEY=$(groundwork seed-key --print-once)
python - <<'PY'
from groundwork import GroundworkClient
c = GroundworkClient(base_url="http://localhost:8080", api_key=...)
print(c.query(question="What shipped last sprint?", user_id="alice@corp.com"))
PY
```

### Scaling up (mid-market/enterprise)

- Same `groundwork.env`, deployed via Helm with external Postgres/SpiceDB and IdP federation
  (`docs/oidc-entra-setup.md` / `oidc-okta-setup.md`).
- Shadow mode first (`GROUNDWORK_SHADOW_MODE=true`) → observe "would block" → flip to
  enforcement behind the approval workflow (existing governance surface).
- SIEM/monitoring: Prometheus rules + Grafana dashboards already in `deploy/`; add the
  documented audit-export → SIEM path.

### Day-2

- Rotations: delegation keys, connector credentials (expiry gauges already exist), API keys
  — all documented in the ops runbook.
- Evidence: `/v1/audit/verify` on a schedule; WORM archive seal on the LEAK_REPORT-like
  cadence; restore drill quarterly.

---

## 8. Sequencing and definition of done

```text
P0 trust fixes (F-1..F-5)        — first, blocking everything
Phase 1 secure-by-default install — parallel start, owns F-5 fully
Phase 2 supply chain              — starts once P0 merges
Phase 3 verification depth        — matrix + drills first; pen test scheduled early
Phase 4 trust package             — documents trail the code by one milestone
```

**Groundwork is production-ready for external customers when:**

- [x] P0 findings closed with pinned tests (F-1..F-5)
- [x] All G1–G8 startup gates enforced for non-local environments, each with a test
- [x] `groundwork init` + `doctor` path reaches a passing deep check with zero
      hand-written secrets (bootstrap key + audit salt are generated)
- [x] SBOM + cosign keyless signing + dependency scanning + SAST wired into CI
- [x] Authorization matrix documented; fail-closed chaos drills scripted against the real stack
- [ ] Load report per release; decision-path p99 measured against the <100 ms target
      (needs the loadtest harness run against a sized environment)
- [ ] External pen test completed; findings closed or accepted with rationale
      (requires a third-party engagement — scheduled, not completable locally)
- [x] Security package (architecture, shared responsibility, scope/honesty) published
- [x] Scope/honesty statements (firewall limits, out-of-V1 list) linked from the README
- [x] Changed-package gates green: go build/vet/test, migrations check
- [ ] Full CI matrix green (console build, python/gosec/staticcheck, integration suite)
      — pending CI run after merge; not runnable to completion on this workstation

Until every box is checked, the README must not claim enterprise production readiness — the
fastest way to lose a security review is to be caught overclaiming, and the second fastest
is `gw_local_acme_key` in a customer's `api_keys` table.
