# Connector Credential Expiry Monitoring

Phase 8.5 observability: every connector's secret reference is dated on
a one-minute cadence and published as days-until-expiry gauges, so a
stale credential pages before (not after) dispatches start failing.
This completes the key/certificate hygiene story that Phase 8.5 started
for the runtime's own keys.

| | |
|---|---|
| Scanner | `internal/connectors/credential_expiry.go` (`CredentialExpiryScanner`) |
| Expiry source | `SecretResolver.Expiry` (`internal/connectors/secrets.go`) |
| Registry view | `Store.ListAllConnectors` (memory + Postgres, monitor-only) |
| Metrics | `internal/metrics/metrics_phase8.go` |
| Cadence | `cmd/query-runtime` one-minute ticker (alongside key expiry) |
| Alerts | `GroundworkConnectorCredentialExpiringSoon` (warn < 30d), `GroundworkConnectorCredentialExpired` (page) |

## What gets dated

- **`keyring://<purpose>`** — dated from the keyring's own expiry
  metadata (`Keyring.Expiries`, the same source as the runtime key
  gauges). Rotating the purpose key updates the connector gauge on the
  next scan.
- **`env://<NAME>`** — environment-provided material carries no expiry
  metadata, so the gauges report **0** (no expiry configured), matching
  the key-expiry metric semantics.
- **No `secret_ref`** — the connector is skipped (nothing to date).
- **Unknown/malformed references** — report 0; the scan never fails,
  never fails closed, and never touches material (the gateway's
  `Resolve` remains the authoritative fail-closed check at dispatch).

## Metrics

```
groundwork_connector_credential_expiry_timestamp_seconds{tenant_id, connector_id, secret_ref}
groundwork_connector_credential_days_until_expiry{tenant_id, connector_id, secret_ref}
```

- `> 0` — days until expiry (fractional).
- `0` — no expiry metadata (env-provided or never-expiring).
- `< 0` — already expired; `GroundworkConnectorCredentialExpired` pages.

`secret_ref` is the *reference* (`keyring://<purpose>`), never material —
consistent with invariant 8 (no secrets in telemetry).

## Why a scanner instead of dispatch-time checks

Dispatch already fails closed on a missing/invalid credential
(`secret_resolution_failed`), but that only detects problems when an
agent calls the connector. The scanner turns expiry into a **lead-time
signal**: the operator rotates before agents start failing, and the
`GroundworkConnectorCredentialExpiringSoon` warning fires at 30 days —
the same threshold as the runtime's own key-expiry warning.

## Verification

```sh
cd services/query-runtime
go test ./internal/connectors/ -run CredentialExpiry   # scanner + cross-tenant list
python ../scripts/check_migrations.py                  # migration gate unchanged
```
