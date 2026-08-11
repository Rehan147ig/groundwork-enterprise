#!/bin/sh
# All-in-one entrypoint for free single-service hosting.
# Idempotent — safe to run on every boot (including free-tier cold starts):
#   1. apply the app DB migrations to Supabase
#   2. apply SpiceDB's datastore migrations, then start SpiceDB on 127.0.0.1:50051
#   3. start the query-runtime on the host-assigned $PORT
set -eu

: "${DATABASE_URL:?set DATABASE_URL to your Supabase SESSION-pooler URI (port 5432, sslmode=require)}"

# SpiceDB shares the same Supabase database unless you override it.
SPICEDB_DATASTORE_CONN_URI="${SPICEDB_DATASTORE_CONN_URI:-$DATABASE_URL}"
SPICEDB_PRESHARED_KEY="${SPICEDB_PRESHARED_KEY:-groundwork-local}"
export SPICEDB_DATASTORE_ENGINE=postgres SPICEDB_DATASTORE_CONN_URI SPICEDB_PRESHARED_KEY
export SPICEDB_LOG_FORMAT=json SPICEDB_GRPC_NO_TLS=true

echo "[entrypoint] applying app migrations…"
migrate -path /migrations -database "$DATABASE_URL" up || {
  echo "[entrypoint] app migrate failed — DATABASE_URL must be the SESSION pooler (:5432) or direct connection, NOT the transaction pooler (:6543)"
  exit 1
}

echo "[entrypoint] applying spicedb datastore migrations…"
spicedb migrate head

echo "[entrypoint] starting spicedb on 127.0.0.1:50051…"
SPICEDB_GRPC_ADDR=127.0.0.1:50051 \
SPICEDB_HTTP_ADDR=127.0.0.1:8443 \
SPICEDB_GRPC_PRESHARED_KEY="$SPICEDB_PRESHARED_KEY" \
  spicedb serve &
sdb_pid=$!

echo "[entrypoint] waiting for spicedb grpc port…"
i=0
while ! nc -z 127.0.0.1 50051 >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -gt 60 ] && { echo "[entrypoint] spicedb did not come up in 60s"; exit 1; }
  kill -0 "$sdb_pid" 2>/dev/null || { echo "[entrypoint] spicedb exited early"; exit 1; }
  sleep 1
done
echo "[entrypoint] spicedb listening."

# query-runtime talks to SpiceDB over localhost; listens on the public $PORT.
# The runtime's deep readiness provisions the SpiceDB schema on first boot.
export SPICEDB_ENDPOINT="127.0.0.1:50051"
export SPICEDB_TOKEN="$SPICEDB_PRESHARED_KEY"
export SPICEDB_INSECURE_PLAINTEXT="true"
export QUERY_RUNTIME_ADDR=":${PORT:-8080}"
echo "[entrypoint] starting query-runtime on ${QUERY_RUNTIME_ADDR} (SPICEDB_ENDPOINT=${SPICEDB_ENDPOINT})…"
exec query-runtime
