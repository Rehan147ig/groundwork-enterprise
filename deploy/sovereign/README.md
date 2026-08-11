# Groundwork — Sovereign Multi-Region Deployment (Phase 4)

One runtime per region. A regional deployment serves **only the tenants assigned
to it**, keeps every data plane component inside the region, and **fails closed**
on any configuration that would allow data to leave the region without an
explicit, auditable policy.

## Region model

| Region | Jurisdiction | Framework evidence profiles (Phase 4e) |
|--------|-------------|----------------------------------------|
| `EU`   | `eu` | EU AI Act, DORA, GDPR, ISO/IEC 42001, NIST AI RMF |
| `UK`   | `uk` | UK customer policy, ISO/IEC 42001, NIST AI RMF |
| `US`   | `us` | US customer policy, NIST AI RMF, ISO/IEC 42001 |
| custom (e.g. `eu-central-1`) | region id | none by default — customer-defined |

The chain is enforced end to end:

```
tenant jurisdiction → regional runtime → regional DBs/vector stores →
regional audit → regional telemetry → regional encryption keys
```

- **Tenant region is trusted config only.** `GROUNDWORK_TENANT_REGIONS=tenant:REGION`
  is the only authority; a request body can never move a tenant. A request for a
  tenant whose region differs from this deployment gets `403 region_mismatch`;
  an unprovisioned tenant gets `403 region_unprovisioned`.
- **Components are co-located by default.** Postgres, SpiceDB, Qdrant,
  Elasticsearch, telemetry, KMS, backups, model endpoints all resolve to the
  deployment region. A component region override must match the deployment
  region or be covered by a transfer policy — otherwise **startup fails**.
- **Cross-region flow needs an explicit policy.** `GROUNDWORK_TRANSFER_POLICIES`
  takes `kind:from:to` entries. Kinds are a closed set: `telemetry`, `backup`,
  `model`, `audit`. A policy only grants its exact kind + direction
  (`telemetry:EU:uk` does NOT allow `uk:EU` or `model:EU:uk`).

## Starting a regional stack

```bash
cp deploy/sovereign/.env.eu.example .env        # or .uk / .us
# edit .env: real secrets, OIDC issuer, tenant regions
docker compose -f deploy/sovereign/docker-compose.sovereign.yml --env-file .env up --build
```

The runtime's `deployment.Validate` gate runs at startup whenever
`GROUNDWORK_DEPLOYMENT_REGION` is set. It refuses to start on any of:

- `region_missing` — no/invalid deployment region
- `jurisdiction_mismatch` — configured jurisdiction conflicts with the region
- `region_mismatch` — a component outside the region without a transfer policy
- `backend_port_public` — any non-gateway service published on the host
- `unapproved_external_endpoint` — public service outside the region, or an
  unapproved model endpoint
- `production_key_missing` — a key purpose (identity, delegation, webhook,
  audit_digest, database, backup) has no material
- `audit_storage_not_configured` — no `DATABASE_URL` (immutable audit ledger)
- `telemetry_jurisdiction` — telemetry leaves the jurisdiction without a policy
- `demo_identity_in_production` — `ALLOW_DEMO_IDENTITY=true`

## Identity (Phase 4c)

Enterprise OIDC is configured with `GROUNDWORK_OIDC_ISSUER` (+
`GROUNDWORK_OIDC_CLIENT_ID`); it takes priority over the JWT HMAC secret.
The verifier performs issuer discovery and JWKS fetch **at startup** — an
unreachable or inconsistent issuer kills the container. Verification is strict:

- algorithms allow-list (default `RS256,PS256,ES256`; `none`/`HS*` rejected)
- issuer, audience, expiration (10s leeway) all required
- `kid` required; unknown kid fails closed; JWKS cached 30 min with
  stale-while-error only for a known kid
- tenant from the `tid` claim (+ optional `GROUNDWORK_OIDC_TENANT_ALLOWLIST`)
- admin **only** from `GROUNDWORK_OIDC_ADMIN_ROLES` values on the roles claim

See `services/query-runtime/internal/runtime/oidc.go` for the full env contract.

## Keys

Every key purpose must be provisioned in production: identity (OIDC issuer or
JWT secret), delegation (`GROUNDWORK_DELEGATION_RS_PRIVATE_KEY`), webhook
signing (`GROUNDWORK_OUTBOX_WEBHOOK_SECRET`), audit digest
(`GROUNDWORK_AUDIT_DIGEST_KEY`), database encryption and backup encryption
(KMS key IDs). Phase 4d adds the customer-managed key provider layer
(`internal/keyring`) with rotation and historical verification.

## Verification

```bash
# only Groundwork ingress reachable + region/identity/audit settings sound
GW_URL=http://localhost GW_API_KEY=gw_live_xxx bash scripts/validate-non-bypassable.sh
```
