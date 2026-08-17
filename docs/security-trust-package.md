# Security, Trust, and Shared Responsibility

Groundwork's product is the runtime authorization + evidence boundary
between agents and enterprise data/tools. This document is the
customer-facing statement of what Groundwork enforces, what it depends on,
and what is honestly not yet proven.

## Security model (enforced, not aspirational)

- **Live authorization.** Every retrieval and connector invocation is
  checked against SpiceDB at decision time. Revocation is immediate; there
  is no permission cache without safe, webhook-triggered invalidation.
- **Fail closed.** A missing, stale, timed-out, revoked, or unavailable
  authorization state returns zero data/tool output and writes an evidence
  record. There is no open fallback.
- **Tenant + region isolation.** These are trusted runtime context derived
  from the verified API key, never request-body fields. A candidate
  outside the tenant or region is dropped before ACL.
- **Immutable audit.** Every decision is hash-chained in Postgres with
  `IMMUTABLE_AUDIT_SALT` bound into the digest. `/v1/audit/verify` proves
  the chain; the WORM archive seals long-term retention.
- **Zero-trust context firewall.** Permitted chunks pass PII/secret
  redaction, an injection scan, and a provenance watermark before reaching
  the model.

## Production gates (G1–G8)

`groundwork doctor` and runtime startup both enforce, for any non-local
environment:

1. Bootstrap key set, non-default, not a repo literal
2. Audit salt set, strong, unique
3. Verified identity (OIDC or signing key)
4. Postgres-backed stores (no in-memory keys)
5. TLS on SpiceDB and Postgres
6. Sovereign deployment validation passes
7. Firewall enabled or explicitly opted out
8. No `gw_local_*` / `acme` demo credentials

## Shared responsibility

| Layer | Groundwork | Customer |
|---|---|---|
| Identity source of truth | Verifies OIDC/JWKS/API key | Operates the IdP, mints scoped keys |
| Relationship data | Enforces SpiceDB tuples | Provisions teams/roles via connector or API |
| Data residency | Enforces region boundaries | Configures `GROUNDWORK_TENANT_REGIONS` |
| Model provider | Watermarks + scrubs context | Secures the model endpoint + its own output guardrails |
| Secrets | Validates keyring/KMS refs | Owns the KMS/HSM + rotation |
| Evidence | Writes + verifies the chain | Operates backup/restore + retention |

Groundwork is **not** a replacement for enterprise IAM, a SIEM/SOC, or a
prompt-injection-only product. It integrates with those categories while
remaining the runtime enforcement point.

## Honest scope statement

- The context firewall's PII/secret redaction is regex-based and strong
  for well-formed SSNs, cards (Luhn-verified), phones, emails, and API
  keys. It is **not** a substitute for format-specific DLP.
- The injection scanner is a conservative regex first line of defense. It
  is bypassable by paraphrase, unicode/homoglyph tricks, and novel
  payloads; a stronger detector is pluggable. Groundwork does not claim
  complete injection defense.
- Groundwork does not synthesize model answers; the query path returns
  permitted chunks + citations for the customer's model to assemble.

## Verification status

| Area | Status |
|---|---|
| Fail-closed under SpiceDB/Postgres/Qdrant loss | Contract-tested (integration suite + chaos drills) |
| Cross-tenant / region isolation | Contract-tested |
| Immutable audit chain | Contract-tested (`/v1/audit/verify`) |
| Supply chain (SBOM, cosign, SAST, vuln scan) | CI wired; iterate toward SLSA L3 |
| External penetration test | **Not yet completed** — schedule before enterprise go-live |
| SOC 2 Type I / II | **Not yet audited** — readiness controls are in place, audit is outstanding |
| HIPAA BAA / FedRAMP | Out of scope for current release |

Groundwork must not be marketed as SOC 2 or pen-test certified until those
audits exist. The fastest way to lose a security review is overclaiming;
the second fastest is a default credential.
