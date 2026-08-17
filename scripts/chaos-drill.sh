#!/usr/bin/env bash
#
# Fail-closed chaos drills — prove Groundwork never falls open when a
# backend dies mid-flight. Brings up the integration stack, runs the
# authorization + fail-closed integration suite, then stops each critical
# dependency in turn and asserts the observable result is FAIL_CLOSED
# (zero citations) — never partial data.
#
# These are NIGHTLY drills, not a fast PR gate. They need Docker and Go.
# Usage:  scripts/chaos-drill.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/services/query-runtime/test/integration/docker-compose.yml"
PROJECT="gw-chaos"

compose() { docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }

cleanup() {
  echo "==> Tearing down chaos stack"
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

export GROUNDWORK_TEST_DATABASE_URL="postgres://groundwork:groundwork@localhost:${GW_INTEGRATION_POSTGRES_PORT:-5433}/groundwork?sslmode=disable"
export GROUNDWORK_TEST_SPICEDB_ENDPOINT="localhost:50051"
export GROUNDWORK_TEST_SPICEDB_TOKEN="groundwork"
export GROUNDWORK_TEST_SPICEDB_INSECURE="true"
export GROUNDWORK_TEST_QDRANT_URL="http://localhost:6333"
export GROUNDWORK_TEST_MIGRATIONS_DIR="$REPO_ROOT/migrations"

echo "==> Starting integration stack"
compose up -d

echo "==> Drill 1: baseline authorization + fail-closed suite"
cd "$REPO_ROOT/services/query-runtime"
go test -tags integration -count=1 -run 'TestFailClosed|TestAuditChain' ./test/integration/...

echo "==> Drill 2: stop SpiceDB -> engine fail-closed (suite asserts zero citations)"
compose stop spicedb
go test -tags integration -count=1 -run 'TestFailClosedWhenSpiceDBDown' ./test/integration/...

echo "==> Drill 3: restart SpiceDB -> recovery (deep readiness passes)"
compose start spicedb
go test -tags integration -count=1 -run 'TestFailClosedOnUnauthorizedUser' ./test/integration/...

echo "==> Drill 4: stop Postgres -> audit evidence boundary fail-closed"
compose stop postgres
go test -tags integration -count=1 -run 'TestFailClosedWhenAuditWriteFails' ./test/integration/...

echo "==> Drill 5: restart Postgres -> audit chain verifies"
compose start postgres
go test -tags integration -count=1 -run 'TestAuditChainWritesToPostgres' ./test/integration/...

echo "==> All chaos drills passed: fail-closed under dependency loss, recovery clean"
