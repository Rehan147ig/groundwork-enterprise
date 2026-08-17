# Production Quickstart

The safe install path. Follow this to stand up a Groundwork deployment
with **zero hand-written secrets** and a `groundwork doctor` pass that
proves the fail-closed production gates are satisfied.

## What you need

- Docker + Docker Compose v2
- `groundwork` CLI (build from source: `cd services/query-runtime && go build -o groundwork ./cmd/groundwork`)
- A Postgres database reachable from the runtime (managed, or the included
  compose profile)

## 1. Initialize (generates every secret)

```bash
groundwork init --env production --dir ./.groundwork
```

This writes `groundwork.env` (mode `0600`) containing generated
`BOOTSTRAP_API_KEY`, `IMMUTABLE_AUDIT_SALT`, JWT/delegation/webhook
secrets, and an RSA-2048 delegation key pair. It refuses any value that
matches a repo-published literal.

## 2. Point it at real infrastructure

Edit `.groundwork/groundwork.env`:

- `DATABASE_URL` — Postgres with TLS (`sslmode=require`)
- `SPICEDB_ENDPOINT` + `SPICEDB_TOKEN` — TLS on (no `INSECURE_PLAINTEXT`)
- `GROUNDWORK_OIDC_ISSUER` (or keep the generated HS secret for initial)
- `GROUNDWORK_TENANT_REGIONS` and `GROUNDWORK_DEPLOYMENT_REGION` for
  sovereign/multi-region

## 3. Bring the stack up

```bash
docker compose --env-file .groundwork/groundwork.env \
  -f infra/docker-compose.prod.yml up -d
```

## 4. Migrate and verify

```bash
docker compose --env-file .groundwork/groundwork.env \
  -f infra/docker-compose.prod.yml run --rm db-migrate up
groundwork doctor --env-file .groundwork/groundwork.env --json
```

A passing `doctor` means every production gate (G1–G8) is satisfied: no
default bootstrap key, a strong unique audit salt, verified identity,
Postgres-backed stores, TLS on the relationship and database transports,
and the firewall enabled (or an explicit, logged opt-out).

## 5. First query

```bash
export GROUNDWORK_API_KEY="$(grep '^BOOTSTRAP_API_KEY=' .groundwork/groundwork.env | cut -d= -f2-)"
python - <<'PY'
from groundwork import GroundworkClient
c = GroundworkClient(base_url="http://localhost:8080", api_key=...)
print(c.query(question="What shipped last sprint?", user_id="alice@corp.com"))
PY
```

The response was permission-checked against live ACLs, firewall-scrubbed,
and written to the immutable audit chain.

## Day-2

- Rotate delegation/connector keys on the documented cadence (expiry
  gauges already emit warnings).
- Run `GET /v1/audit/verify` on a schedule to prove the chain is
  untampered.
- Seal the WORM archive and run a quarterly restore-through-verify drill
  (`cmd/archive`).
- Monitor the SLO dashboards in `deploy/grafana/` and alert on
  `GroundworkAuditVerifyFailure`, fail-closed SLO breach, and outbox
  staleness.

## What this is not

Groundwork is the runtime authorization + evidence boundary. It does not
replace your IdP, model provider, or SIEM. See
`docs/groundwork-production-conditions.md` for the explicit out-of-scope
list and the firewall's detection limits.
