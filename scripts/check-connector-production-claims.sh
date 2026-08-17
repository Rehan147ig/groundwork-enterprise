#!/usr/bin/env bash
# Fails when a connector declares production status without a verified
# production review. Connectors are self-describing (contract
# ProviderDescriptor.Status); this gate audits the claim so an
# unreviewed connector can never quietly claim production readiness.
#
# Rules:
#   - Only providers on the PRODUCTION_ALLOWLIST may declare
#     Status: "production".
#   - Every allowlisted provider must actually declare it (prevents
#     the flag from silently regressing).
#
# A connector is "declaring production" when its Go source contains
# Status: "production" in a ProviderDescriptor literal.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QUERY_RUNTIME="$REPO_ROOT/services/query-runtime"

# Connectors with a verified production review. Add here only after the
# production hardening review is done for that connector.
PRODUCTION_ALLOWLIST="msgraph"

# 1. Collect the providers that declare production status, pairing
#    provider+status within the same file (each connector's descriptor
#    lives in its own file).
declare -A declared=()
while IFS= read -r file; do
  [ -n "$file" ] || continue
  provider=$(grep -hoE 'Provider:[[:space:]]*"[a-z0-9_]+"' "$file" | sed -E 's/.*"([a-z0-9_]+)"/\1/' | head -n1)
  if [ -n "$provider" ]; then
    declared["$provider"]=1
  fi
done < <(grep -rlE 'Status:[[:space:]]*"production"' "$QUERY_RUNTIME" --include='*.go' || true)

# 2. Any production declaration must be allowlisted.
for provider in "${!declared[@]}"; do
  case " $PRODUCTION_ALLOWLIST " in
    *" $provider "*)
      ;;
    *)
      echo "FAIL: connector '$provider' declares production status but is not on the production allowlist ($PRODUCTION_ALLOWLIST)" >&2
      echo "      It must declare Status: \"experimental\" until its production hardening review is done." >&2
      exit 1
      ;;
  esac
done

# 3. Every allowlisted provider must actually declare production.
for provider in $PRODUCTION_ALLOWLIST; do
  if [ -z "${declared[$provider]+_}" ]; then
    echo "FAIL: allowlisted connector '$provider' no longer declares production status" >&2
    exit 1
  fi
done

echo "production connector claims verified: $(printf '%s ' "${!declared[@]}" | sed 's/ *$//')"