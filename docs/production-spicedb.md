# Production SpiceDB (persistent datastore)

> **Status: REQUIRED for production.** SpiceDB is the sole authorization
> backend (see `docs/spicedb-migration.md`). The relationship datastore
> is authoritative tenant state: it must survive container restarts and
> host reboots. In `infra/docker-compose.prod.yml` SpiceDB therefore
> runs against its **own PostgreSQL database** — never
> `--datastore-engine memory`.

## Why persistent

`--datastore-engine memory` loses every relationship (every `view`,
`use`, `execute` grant and folder inheritance edge) on container
restart. The runtime fails closed on missing schema or missing
relationships, so a memory-backed SpiceDB in production silently
becomes an outage the moment the container restarts — while the rest of
the stack (Postgres, Qdrant, Elasticsearch, MinIO) already persists.

The datastore lives in a dedicated `spicedb` database on the same
PostgreSQL instance as the application data, so SpiceDB's schema
migrations can never collide with Groundwork's own migrations.

## Architecture and startup ordering

Three services replace the single in-memory service:

| Service | Image | Role |
|---|---|---|
| `spicedb-db-init` | `postgres:16` | One-shot: waits for Postgres, creates the `spicedb` database if absent (idempotent) |
| `spicedb-migrate` | `authzed/spicedb:v1.56.0` | One-shot: applies SpiceDB schema migrations (`migrate head`) to the Postgres datastore |
| `spicedb` | `authzed/spicedb:v1.56.0` | The server (`serve`), Postgres datastore, gRPC TLS, preshared key |

Ordering is enforced with `depends_on` conditions:

```
postgres (healthy) → spicedb-db-init (completed_successfully)
                   → spicedb-migrate (completed_successfully) → spicedb (started)
```

`serve` refuses to start against an unmigrated datastore, so the
migration gate is structural, not a best-effort flag. Consumers
(`query-runtime`, `ingestion`) keep `depends_on: service_started` and
rely on `query-runtime`'s `readyz` probe for readiness.

The connection uses TLS with the internal CA and the shared mTLS client
certificate, matching the posture of every other Postgres client in the
stack:

```
postgres://groundwork:<password>@postgres:5432/spicedb?sslmode=require&sslcert=/certs/client.crt&sslkey=/certs/client.key&sslrootcert=/certs/ca.crt
```

## Health checks

The pinned SpiceDB image is a minimal Chainguard base with **no
shell**, so a `CMD-SHELL` healthcheck cannot run inside it. Instead:

1. **`query-runtime`'s `readyz`** probes SpiceDB at startup and
   continuously; it is the authoritative readiness signal for the
   application path.
2. **`--grpc-healthcheck`** is enabled on `serve`, exposing the
   standard gRPC health service for external monitors.
3. **Operator probe** (using the official debug image, which contains
   `grpc_health_probe`):

```sh
docker run --rm --network groundwork_default --entrypoint grpc_health_probe \
  authzed/spicedb:v1.56.0-debug \
  -addr=spicedb:50051 \
  -tls -tls-ca-cert=/certs/ca.crt \
  -tls-client-cert=/certs/client.crt -tls-client-key=/certs/client.key \
  -tls-server-name=spicedb
```

## First deploy (bootstrap)

```sh
# From the repo root
cp infra/certs.example.env .env   # or fill your own values
docker compose -f infra/docker-compose.prod.yml config --quiet   # validate
docker compose -f infra/docker-compose.prod.yml up -d            # db-init and migrate run first, then serve
docker compose -f infra/docker-compose.prod.yml ps                # spicedb-db-init / spicedb-migrate exit 0
```

The Groundwork runtime applies its application schema
(`groundwork.zed`) itself and fails closed (`ErrModelMissing`) if the
deployed SpiceDB schema drifts from it — so no separate schema upload
step exists.

## Restart-persistence verification

After any restart of the stack, confirm relationships survived:

1. Grant a relationship (e.g. via the agent registry / governance
   console), then:
   ```sh
   docker compose -f infra/docker-compose.prod.yml restart spicedb
   ```
2. Wait for `query-runtime` `readyz` to return healthy, then re-check
   the relationship (the check that returned "allowed" before the
   restart must still return "allowed").
3. Verify the datastore is the Postgres one, not memory:
   ```sh
   docker compose -f infra/docker-compose.prod.yml exec postgres \
     psql -U groundwork -d spicedb -c "\dt"    # relationship tables present
   ```
4. A `docker compose -f infra/docker-compose.prod.yml up -d` from a
   cold start (containers removed) must reproduce the same results —
   the data lives in the `postgres-data` volume.

## Backup and restore

Back up the `spicedb` database with the rest of Postgres:

```sh
# Backup (hot, consistent)
docker compose -f infra/docker-compose.prod.yml exec postgres \
  pg_dump -U groundwork -d spicedb -Fc -f /tmp/spicedb.dump
docker compose -f infra/docker-compose.prod.yml cp \
  postgres:/tmp/spicedb.dump ./spicedb-$(date +%F).dump
```

```sh
# Restore (into a fresh deployment)
docker compose -f infra/docker-compose.prod.yml exec -T postgres \
  pg_restore -U groundwork -d spicedb -Fc --clean --if-exists < ./spicedb-YYYY-MM-DD.dump
```

Restore order matters: restore the `spicedb` database **before** the
application data (or at least before `query-runtime` starts checking
relationships), and bring the stack up normally afterwards — the
`spicedb-migrate` one-shot is a no-op when the schema is already at
head.

## mTLS enforcement (True mutual TLS)

Production SpiceDB now **requires** verified client certificates:

```yaml
spicedb:
  command: [serve, ..., "--grpc-tls-client-ca-path", "/certs/ca.crt"]
```

This flag tells SpiceDB to **reject any gRPC connection that does not present a valid client certificate** signed by the internal CA. Combined with the query-runtime's mTLS client config (`SPICEDB_TLS_CERT`, `SPICEDB_TLS_KEY`, `SPICEDB_TLS_CA`), this achieves true mutual TLS:

- Server validates client → client must present `/certs/client.crt` + key, signed by `/certs/ca.crt`
- Client validates server → server presents `/certs/spicedb.crt` + key, signed by `/certs/ca.crt`

**Generate the internal PKI** (once per deployment):
```sh
# From repo root
mkdir -p infra/certs
# CA
openssl req -x509 -newkey rsa:4096 -sha256 -days 730 -nodes \
  -keyout infra/certs/ca.key -out infra/certs/ca.crt \
  -subj "/CN=groundwork-internal-ca"
# SpiceDB server cert
openssl req -newkey rsa:2048 -nodes -keyout infra/certs/spicedb.key \
  -out infra/certs/spicedb.csr -subj "/CN=spicedb"
openssl x509 -req -in infra/certs/spicedb.csr -CA infra/certs/ca.crt \
  -CAkey infra/certs/ca.key -CAcreateserial -out infra/certs/spicedb.crt \
  -days 365 -sha256 -extfile <(echo "subjectAltName=DNS:spicedb,IP:127.0.0.1")
# mTLS client cert (used by query-runtime, ingestion, spicedb-migrate)
openssl req -newkey rsa:2048 -nodes -keyout infra/certs/client.key \
  -out infra/certs/client.csr -subj "/CN=groundwork-client"
openssl x509 -req -in infra/certs/client.csr -CA infra/certs/ca.crt \
  -CAkey infra/certs/ca.key -CAcreateserial -out infra/certs/client.crt \
  -days 365 -sha256
# Postgres TLS certs (same CA)
openssl req -newkey rsa:2048 -nodes -keyout infra/certs/postgres.key \
  -out infra/certs/postgres.csr -subj "/CN=postgres"
openssl x509 -req -in infra/certs/postgres.csr -CA infra/certs/ca.crt \
  -CAkey infra/certs/ca.key -CAcreateserial -out infra/certs/postgres.crt \
  -days 365 -sha256
```

All certs are signed by the same internal CA (`ca.crt`), which is the trust anchor for both SpiceDB's `--grpc-tls-client-ca-path` and the query-runtime's `SPICEDB_TLS_CA`. The certs are mounted read-only at `/certs` in the compose file.

**Bootstrap verification** (after `docker compose up`):
```sh
# SpiceDB gRPC health with mTLS
docker run --rm --network groundwork_default --entrypoint grpc_health_probe \
  authzed/spicedb:v1.56.0-debug \
  -addr=spicedb:50051 \
  -tls -tls-ca-cert=/certs/ca.crt \
  -tls-client-cert=/certs/client.crt -tls-client-key=/certs/client.key \
  -tls-server-name=spicedb
```

If mTLS is misconfigured, the probe fails and `query-runtime`'s `readyz` will not pass.

## Upgrades

- Pin SpiceDB to the same version across `spicedb-migrate` and
  `spicedb` — they must be the same image tag.
- Upgrade order: run `spicedb-migrate` once against the new version
  (`docker compose -f infra/docker-compose.prod.yml up -d spicedb-migrate`),
  then update the `spicedb` image. Never skip the migration step; the
  server refuses to run on an unmigrated datastore by design.