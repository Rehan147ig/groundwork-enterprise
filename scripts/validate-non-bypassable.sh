#!/usr/bin/env bash
#
# Validates the Groundwork non-bypassable deployment profile:
#   - query-runtime is reachable through the gateway
#   - /mcp is reachable (and requires an API key)
#   - Qdrant / SpiceDB / PostgreSQL / Elasticsearch are NOT reachable on host ports
#   - (optional) an authenticated query still works through /mcp
#   - (sovereign, Phase 4) when GROUNDWORK_DEPLOYMENT_REGION is set, the
#     region/tenant/identity/key/audit environment is sound and demo
#     identity is off
#
# Usage:
#   GW_URL=http://localhost ./scripts/validate-non-bypassable.sh
#   GW_API_KEY=gw_live_xxx GW_URL=http://localhost ./scripts/validate-non-bypassable.sh
#   GW_ENV_FILE=deploy/sovereign/.env GW_URL=http://localhost ./scripts/validate-non-bypassable.sh
#
# Exit code 0 = only Groundwork ingress is exposed; non-zero = a check failed.

set -u

GW_URL="${GW_URL:-http://localhost}"
API_KEY="${GW_API_KEY:-}"
ENV_FILE="${GW_ENV_FILE:-}"
fail=0

pass() { echo "PASS: $1"; }
bad()  { echo "FAIL: $1"; fail=1; }

http_code() { curl -s -o /dev/null -m 5 -w '%{http_code}' "$@" 2>/dev/null; }

echo "== Groundwork non-bypassable validation =="
echo "gateway: $GW_URL"
echo

# 1. query-runtime reachable through the gateway.
c=$(http_code "$GW_URL/healthz")
[ "$c" = "200" ] && pass "query-runtime /healthz reachable (200)" || bad "/healthz expected 200, got '$c'"

# 2. /mcp reachable AND auth-protected (401 without an API key).
c=$(http_code -X POST "$GW_URL/mcp" -H 'Content-Type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
[ "$c" = "401" ] && pass "/mcp reachable and requires API key (401)" || bad "/mcp expected 401 without key, got '$c'"

# 3-6. Backend host ports MUST be closed (connection refused).
check_closed() { # <port> <name>
  if timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null; then
    bad "$2 ($1) is reachable from the host — it must be internal-only"
  else
    pass "$2 ($1) not reachable from the host"
  fi
}
check_closed 6333 "Qdrant"
check_closed 50051 "SpiceDB gRPC"
check_closed 8443 "SpiceDB HTTP"
check_closed 5432 "PostgreSQL"
check_closed 9200 "Elasticsearch"

# 7. Optional: a real authenticated query still works through /mcp.
if [ -n "$API_KEY" ]; then
  body=$(curl -s -m 8 -X POST "$GW_URL/mcp" -H "X-Groundwork-API-Key: $API_KEY" \
          --data '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' 2>/dev/null)
  if echo "$body" | grep -q "groundwork_search"; then
    pass "authenticated /mcp tools/list works (Groundwork query path is live)"
  else
    bad "authenticated /mcp tools/list failed: $body"
  fi
else
  echo "INFO: set GW_API_KEY to also verify an authenticated query through /mcp"
fi

# 8-13. Sovereign deployment env checks (Phase 4). Only active when the
# deployment region is configured (or an env file was supplied).
env_val() {
  if [ -n "$ENV_FILE" ] && grep -q "^$1=" "$ENV_FILE" 2>/dev/null; then
    grep "^$1=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2-
  else
    eval "printf '%s' \"\${$1:-}\""
  fi
}

REGION=$(env_val GROUNDWORK_DEPLOYMENT_REGION)
if [ -n "$REGION" ]; then
  echo
  echo "== Sovereign deployment env validation (region: $REGION) =="

  TENANTS=$(env_val GROUNDWORK_TENANT_REGIONS)
  if echo "$TENANTS" | grep -qi ":${REGION}" ; then
    pass "tenant region map covers this deployment region"
  else
    bad "GROUNDWORK_TENANT_REGIONS='$TENANTS' does not assign any tenant to region $REGION"
  fi

  BOOTSTRAP_REGION=$(env_val BOOTSTRAP_TENANT_REGION)
  if [ "$BOOTSTRAP_REGION" = "$REGION" ]; then
    pass "BOOTSTRAP_TENANT_REGION matches the deployment region"
  else
    bad "BOOTSTRAP_TENANT_REGION='$BOOTSTRAP_REGION' must equal the deployment region '$REGION'"
  fi

  if [ -n "$(env_val GROUNDWORK_OIDC_ISSUER)" ] || [ -n "$(env_val GROUNDWORK_JWT_HS_SECRET)" ]; then
    pass "identity material configured (OIDC issuer or JWT secret)"
  else
    bad "no identity material: set GROUNDWORK_OIDC_ISSUER or GROUNDWORK_JWT_HS_SECRET"
  fi

  if [ -n "$(env_val GROUNDWORK_DELEGATION_RS_PRIVATE_KEY)" ] || [ -n "$(env_val GROUNDWORK_DELEGATION_HS_SECRET)" ]; then
    pass "delegation key material present (RS private key or HS secret)"
  else
    bad "no delegation key material: set GROUNDWORK_DELEGATION_RS_PRIVATE_KEY or GROUNDWORK_DELEGATION_HS_SECRET"
  fi

  [ -n "$(env_val GROUNDWORK_OUTBOX_WEBHOOK_SECRET)" ] && pass "GROUNDWORK_OUTBOX_WEBHOOK_SECRET present" || bad "GROUNDWORK_OUTBOX_WEBHOOK_SECRET missing — purpose webhook has no key material"
  [ -n "$(env_val GROUNDWORK_AUDIT_DIGEST_KEY)" ] && pass "GROUNDWORK_AUDIT_DIGEST_KEY present" || bad "GROUNDWORK_AUDIT_DIGEST_KEY missing — purpose audit_digest has no key material"

  if [ -n "$(env_val DATABASE_URL)" ] || [ -n "$(env_val POSTGRES_PASSWORD)" ]; then
    pass "DATABASE_URL set (or compose-managed postgres) — immutable audit ledger configured"
  else
    bad "DATABASE_URL missing — audit storage is not configured"
  fi

  if [ "$(env_val ALLOW_DEMO_IDENTITY)" = "true" ]; then
    bad "ALLOW_DEMO_IDENTITY=true is forbidden in production"
  else
    pass "ALLOW_DEMO_IDENTITY is off"
  fi

  for key in GROUNDWORK_POSTGRES_EXPOSED GROUNDWORK_SPICEDB_EXPOSED GROUNDWORK_QDRANT_EXPOSED GROUNDWORK_ES_EXPOSED GROUNDWORK_MINIO_EXPOSED; do
    if [ -n "$(env_val "$key")" ]; then
      bad "$key is set — a backend is published on the host interface"
    fi
  done
else
  echo "INFO: GROUNDWORK_DEPLOYMENT_REGION unset — skipping sovereign env checks (pass GW_ENV_FILE=deploy/sovereign/.env)"
fi

echo
if [ "$fail" = "0" ]; then
  echo "ALL CHECKS PASSED — only Groundwork ingress is exposed."
  exit 0
else
  echo "CHECKS FAILED — a backend is exposed or Groundwork ingress is broken."
  exit 1
fi
