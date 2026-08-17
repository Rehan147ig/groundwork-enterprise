#!/bin/sh
# Groundwork quickstart seed — runs once inside the `seed` compose
# service. Populates the Acme demo org (5 document ACLs, 5 teams,
# users) into SpiceDB and makes /v1/leak-report return live findings so
# the console opens already pre-seeded.
#
# Uses only the runtime's public API and the bootstrap API key:
#   1. wait for /healthz
#   2. force /readyz — deep readiness writes the embedded
#      groundwork.zed schema onto SpiceDB (idempotent)
#   3. POST /v1/connect/github — the mock Acme org re-syncs, mapping
#      teams->groups, repos->documents and writing tuples to SpiceDB
#   4. GET /v1/leak-report — exposure analysis over the seeded snapshot
#
# Demo org (canonical Acme, not fabricated):
#   repos   finance-budget, payroll-system, engineering-platform,
#           security-audit, executive-strategy      (5 document ACLs)
#   teams   finance, engineering, hr, security, executive
#   users   alice(finance), bob(engineering), carol(hr), dave(security),
#           eve(executive)
#   leak    engineering-team can view finance-budget (owned by
#           finance-team) — a real cross-department exposure.

set -e

RUNTIME="${QUICKSTART_RUNTIME_URL:-http://query-runtime:8080}"
API_KEY="${QUICKSTART_API_KEY:-gw_local_acme_key}"

echo "[seed] waiting for query-runtime at $RUNTIME ..."
i=0
until curl -fsS "$RUNTIME/healthz" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 90 ]; then
    echo "[seed] ERROR: query-runtime never became healthy after 90s" >&2
    exit 1
  fi
  sleep 1
done
echo "[seed] query-runtime healthy"

echo "[seed] forcing SpiceDB deep readiness (writes embedded groundwork.zed schema)"
i=0
until curl -fsS "$RUNTIME/readyz" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -ge 30 ]; then
    echo "[seed] ERROR: SpiceDB never became ready (schema bootstrap failed)" >&2
    exit 1
  fi
  sleep 1
done
echo "[seed] SpiceDB ready — schema matches embedded groundwork.zed"

echo "[seed] syncing Acme demo org (5 repos -> 5 document ACLs, 5 teams, users alice/bob/carol/dave/eve)"
curl -fsS -X POST "$RUNTIME/v1/connect/github" \
  -H "X-Groundwork-API-Key: $API_KEY"
echo ""

echo "[seed] generating leak report over the seeded snapshot"
REPORT="$(curl -fsS "$RUNTIME/v1/leak-report" -H "X-Groundwork-API-Key: $API_KEY")"
echo "$REPORT" | grep -q '"findings"' || {
  echo "[seed] ERROR: leak report response has no findings" >&2
  exit 1
}

FINDINGS="$(echo "$REPORT" | grep -o '"kind"' | wc -l | tr -d ' ')"
echo "[seed] leak report ready: $FINDINGS finding(s) (engineering-team -> finance-budget included)"
echo "[seed] done — console at http://localhost:3000 (view: Leak Report)"