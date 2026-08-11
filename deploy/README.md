# Groundwork — Live Demo Deployment

Stand up a public, working Groundwork demo for the YC / Antler application. Three
tiers, each a superset of the one before. Start at Tier 0 today for an instant
link; add Tier 1 for the live product core; add Tier 2 for live RAG retrieval.

| Tier | What's live | Needs | Time |
|------|-------------|-------|------|
| **0** | Full Acme UX from curated data (identical to live output) | Vercel | ~5 min |
| **1** | Connect, Leak Report, Audit timeline + verify, ACL enforcement — **100% computed live** | + Supabase, Fly | ~30–45 min |
| **2** | Everything above **+ live RAG retrieval** (Try-It strips the real `gh:finance-budget` leak) | + Qdrant, Elasticsearch, embedder | +30–60 min |

> The product's whole thesis — runtime authorization + tamper-evident audit —
> is fully live at **Tier 1**. Retrieval (Qdrant) is the Tier 2 layer. Don't let
> Tier 2 block your link going out.

---

## Hosting — free vs. paid (pick the runtime's home)

The console (Vercel), Postgres (Supabase), and vectors (Qdrant Cloud) are all free
and **card-free**. The only piece that needs a compute host is the backend.

| Host | Free? | Card? | Fit |
|------|-------|-------|-----|
| **Render** | yes (750 hrs/mo) | **no card** | ✅ Recommended free path — Docker-native |
| Koyeb | yes | no card | ⚠️ only 1 free service/org |
| Northflank | yes (always-on) | **card required** | ❌ |
| Fly.io | trial | **card required** | paid path (configs in `deploy/fly/`, `services/query-runtime/fly.toml`) |

### Recommended FREE path — Render, no credit card

One **self-bootstrapping container** runs the whole backend: it applies the DB
migrations to Supabase, starts SpiceDB on localhost (Supabase datastore, never
public), then starts the runtime. One free service, no manual migration step.

1. Push the repo to GitHub.
2. Render → **New → Blueprint** → select the repo. Render reads
   `deploy/render/render.yaml` and provisions the service from
   `services/query-runtime/Dockerfile.allinone`.
3. When prompted, fill the secrets (stored by Render, never in git):
   - `DATABASE_URL` — Supabase **session pooler** URI (`:5432`), `?sslmode=require`
   - `SPICEDB_PRESHARED_KEY` — `openssl rand -hex 32` (used by both SpiceDB and the runtime)
   - `GROUNDWORK_JWT_HS_SECRET` — `openssl rand -hex 32` (use the SAME value on Vercel)
   - `BOOTSTRAP_API_KEY` — `gw_live_<random>` (= `GROUNDWORK_API_KEY` on Vercel)
   - `IMMUTABLE_AUDIT_SALT` — `openssl rand -hex 32` (set once, never change)
4. Deploy. First boot runs migrations + SpiceDB bootstrap (~30–60s), then health
   goes green at `/healthz`. Your runtime URL is `https://groundwork-runtime.onrender.com`.
5. Point Vercel at it (Tier 1, step 5 below) and **Connect** (step 6).

You skip the separate SpiceDB Fly app and all the `fly …` commands — the container
handles them. Then continue at **Tier 1, step 5**.

**Cold start:** free services sleep after ~15 min idle and wake in ~30–60s. The Vercel
link always works (it shows demo data while the backend wakes). Before a live
walkthrough, open `…onrender.com/healthz` once to warm it — or keep it warm with a
free no-card cron (e.g. cron-job.org) hitting `/healthz` every ~10 min; one always-on
service fits the 750 hrs/month budget.

**Qdrant on free hosting:** Tier 2 (live retrieval) needs Elasticsearch + an embedder,
which are RAM-heavy and don't fit a 512 MB free instance — that step waits until you
have a small paid box. Your Qdrant cluster isn't wasted; it's the Tier 2 vector store.
The free Render path delivers Tier 1 (authz + audit + leak report fully live).

---

## Secrets — set once, never commit, never paste in chat

| Secret | Where it lives | Shape / notes |
|--------|----------------|---------------|
| `DATABASE_URL` | Fly (runtime) | Supabase **session pooler** (`:5432`) or direct conn, `?sslmode=require` |
| `SPICEDB_DATASTORE_CONN_URI` | Fly (spicedb) | Same Supabase DB, same session-pooler rule |
| `SPICEDB_PRESHARED_KEY` / `SPICEDB_TOKEN` | Fly (spicedb) / Fly (runtime) | The SAME random value in both apps |
| `GROUNDWORK_JWT_HS_SECRET` | Fly (runtime) **and** Vercel | 32+ random bytes, **identical in both** |
| `BOOTSTRAP_API_KEY` | Fly (runtime) = `GROUNDWORK_API_KEY` on Vercel | e.g. `gw_live_<random>` |
| `IMMUTABLE_AUDIT_SALT` | Fly (runtime) | random; **set once and never change** (audit digest input) |
| `QDRANT_API_KEY` | Fly (runtime), Tier 2 | from Qdrant Cloud |
| `GITHUB_TOKEN` | Fly (runtime), optional | omit → offline Acme MockClient (recommended for the demo) |

Generate a good random value: `openssl rand -hex 32`.

---

## Tier 0 — instant public link (no backend)

1. Push the repo to GitHub (private is fine).
2. In Vercel: **Add New → Project → Import** the repo.
3. Set **Root Directory = `apps/console`**. Leave all env vars empty.
4. **Deploy.**

You get `https://<project>.vercel.app` with the complete Acme story — Connect
graph, Leak Report, Audit timeline, Try-It allow/deny — served from the curated
fallbacks in `apps/console/app/api/*`. This is your application link. Upgrade the
same project to live data by adding the Tier 1 env vars later (no re-import).

---

## Tier 1 — live product core (Supabase + SpiceDB + runtime)

> **No credit card?** Use the **Recommended FREE path (Render)** above — it replaces
> steps 2–4 here (migrations, SpiceDB, runtime) with one Blueprint deploy, then rejoin
> at step 5. The Fly steps below are the paid alternative.

Prereqs (Fly path): a [Fly.io](https://fly.io) account + `flyctl`, and your Supabase project.

### 1. Get your Supabase connection string
Supabase → Project Settings → Database → **Connection string → Session pooler**.
Append `?sslmode=require`. Use this same value for both `DATABASE_URL` (runtime)
and `SPICEDB_DATASTORE_CONN_URI` (spicedb).

### 2. Apply the app migrations (003–013)
```bash
export DATABASE_URL='postgresql://postgres.<ref>:<pw>@aws-0-<region>.pooler.supabase.com:5432/postgres?sslmode=require'
bash deploy/migrate.sh
```
Creates `audit_log`, `audit_log_decisions`, `principal_aliases`, and the demo
schema. (Migration 013 builds indexes `CONCURRENTLY` — that's why a session/direct
connection is required, not the transaction pooler.)

### 3. Deploy SpiceDB (internal-only, Supabase datastore)
```bash
fly launch --no-deploy --copy-config --config deploy/fly/spicedb/fly.toml \
  --name groundwork-spicedb --region iad         # pick a region near Supabase

export SPICEDB_PRESHARED_KEY="$(openssl rand -hex 32)"   # SAVE THIS — the runtime needs it too
fly secrets set -a groundwork-spicedb \
  SPICEDB_DATASTORE_CONN_URI="$DATABASE_URL" \
  SPICEDB_PRESHARED_KEY="$SPICEDB_PRESHARED_KEY"

# one-shot: create SpiceDB's datastore tables in Supabase, then exit
fly machine run authzed/spicedb:latest migrate head --rm -a groundwork-spicedb

fly deploy --config deploy/fly/spicedb/fly.toml
```

### 4. Deploy the runtime
```bash
cd services/query-runtime
fly launch --no-deploy --copy-config --name groundwork-runtime --region iad   # SAME region as spicedb

fly secrets set -a groundwork-runtime \
  DATABASE_URL="$DATABASE_URL" \
  SPICEDB_TOKEN="$SPICEDB_PRESHARED_KEY" \
  GROUNDWORK_JWT_HS_SECRET="$(openssl rand -hex 32)" \
  BOOTSTRAP_API_KEY="gw_live_$(openssl rand -hex 12)" \
  IMMUTABLE_AUDIT_SALT="$(openssl rand -hex 32)"

fly deploy
cd ../..
```
Save the JWT secret and API key — Vercel needs the exact same values. Confirm
health: `curl https://groundwork-runtime.fly.dev/healthz` → `ok`.

### 5. Point the console at the runtime
In your Vercel project, set (Production):
```
QUERY_RUNTIME_URL=https://groundwork-runtime.fly.dev
GROUNDWORK_API_KEY=<the BOOTSTRAP_API_KEY from step 4>
GROUNDWORK_JWT_HS_SECRET=<the JWT secret from step 4>
NEXT_PUBLIC_APP_NAME=Groundwork
```
Redeploy the Vercel project.

### 6. Connect
The runtime's deep readiness provisions the SpiceDB schema on boot, so **Connect
works immediately** — no warm-up ordering needed. Click **Connect** in the
console: it writes the Acme org's relationships (including the planted
engineering → finance-budget leak). **Leak Report** and the **Audit** timeline
are now fully live and computed.

### Tier 1 verification checklist
- `GET /healthz` → `ok`; `GET /readyz` → `ok` (Postgres + SpiceDB reachable).
- Console **Connect** returns the 5 teams / 5 documents / relationship count from live SpiceDB.
- **Leak Report** shows `cross_department_access` (high) for engineering → finance-budget.
- **Audit** timeline lists real rows; **Verify** returns chain-intact.
- In Supabase, `select count(*) from audit_log;` grows as you run Try-It.

---

## Tier 2 — live RAG retrieval (Qdrant + Elasticsearch + embedder)

The engine fuses **Qdrant** (vector) and **Elasticsearch** (BM25) and embeds
queries via the **embedder** (`services/ingestion`). All three are required for
live retrieval — `main.go` only activates the HTTP backend when both
`QDRANT_URL` and `ELASTICSEARCH_URL` are set.

1. **Embedder** → deploy `services/ingestion` to Fly (internal-only, exposes `:8000`).
2. **Elasticsearch** → Elastic Cloud free trial, or a Fly ES app (internal `:9200`).
3. Add to the runtime and redeploy:
   ```bash
   fly secrets set -a groundwork-runtime QDRANT_API_KEY='<qdrant-cloud-key>'
   # then uncomment the Tier 2 [env] block in services/query-runtime/fly.toml:
   #   QDRANT_URL, QDRANT_COLLECTION, ELASTICSEARCH_URL, ELASTICSEARCH_INDEX, EMBEDDING_URL
   fly deploy -c services/query-runtime/fly.toml
   ```
4. **Seed** the Acme corpus (real embeddings → Qdrant, relationships → SpiceDB):
   ```bash
   fly proxy 50051:50051 -a groundwork-spicedb &    # tunnel to internal SpiceDB
   fly proxy 8000:8000 -a groundwork-embedder &    # tunnel to internal embedder
   export QDRANT_URL='https://<cluster>.<region>.aws.cloud.qdrant.io:6333'
   export QDRANT_API_KEY='<qdrant-cloud-key>'
   export SPICEDB_ENDPOINT='localhost:50051'
   export SPICEDB_TOKEN="$SPICEDB_PRESHARED_KEY"
   export SPICEDB_INSECURE_PLAINTEXT=true
   export EMBEDDING_URL='http://localhost:8000'
   bash deploy/seed-acme.sh
   ```
5. In the console, ask the **engineering** user for the Q4 finance budget — the
   `gh:finance-budget` chunk is retrieved by Qdrant but **stripped live by GW**,
   and the denial appears in the audit trail. That's the money demo.

---

## Troubleshooting

- **Console shows demo data after wiring Tier 1** — `GROUNDWORK_API_KEY` /
  `GROUNDWORK_JWT_HS_SECRET` on Vercel don't match the runtime, or
  `QUERY_RUNTIME_URL` is wrong. The console silently falls back to demo on auth
  failure by design.
- **Migration 013 fails / "CREATE INDEX CONCURRENTLY cannot run in a transaction"**
  — you're on the Supabase transaction pooler (`:6543`). Use the session pooler
  (`:5432`) or direct connection.
- **Everyone sees zero documents after a SpiceDB restart** — SpiceDB is on the
  `memory` datastore. Confirm `SPICEDB_DATASTORE_ENGINE=postgres` and that the
  `migrate head` one-shot ran.
- **Runtime can't reach SpiceDB** — both Fly apps must be in the same org/region;
  the runtime uses `groundwork-spicedb.internal:50051` (Fly private net).
- **"spicedb schema drifted" / schema write failed at boot** — the embedded
  `groundwork.zed` schema and the live store disagree; the runtime fails closed
  rather than serve against a stale schema. Check for a version skew between
  the deployed runtime and the SpiceDB store.

## Recommended hardening (offered)
- **Make SpiceDB fully private** — already internal-only here; keep it that way in
  prod (never give the SpiceDB app a public service).
