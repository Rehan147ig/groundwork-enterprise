# Groundwork Documentation

Index of the Groundwork platform documentation.

## Architecture & Design

- [Architecture](architecture.md) — system overview, components, request flows.
- [Repository structure](repository-structure.md) — monorepo layout and conventions.
- [Capacity model](capacity-model.md) — sizing, latency budget, scaling.
- [Production-scale roadmap](production-scale-roadmap.md) — growth plan.

## Security & Governance

- [Governance](governance.md) — decision gates, delegation, fail-closed guarantees.
- [SpiceDB migration](spicedb-migration.md) — authorization backend cutover record (COMPLETE).
- [ACL sync framework](acl-sync-framework.md) — relationship sync, drift detection, revocation.
- [Identity resolution](identity-resolution.md) — principal aliases, canonical identity.
- [Separation of duties](separation-of-duties.md) — admin vs operator vs auditor roles.
- [Break glass](break-glass.md) — emergency access procedures.
- [Non-bypassable deployment](non-bypassable-deployment.md) — production hardening.
- [WORM archive](worm-archive.md) — immutable audit log design.
- [Credential expiry monitoring](credential-expiry-monitoring.md) — key lifecycle.
- [Policy templates](policy-templates.md) — reusable authorization policies.

## Operations

- [Observability](observability.md) — metrics, logs, traces, dashboards.
- [Rate & concurrency limits](rate-and-concurrency-limits.md) — throttling design.
- [Backpressure & overload](backpressure-and-overload.md) — load shedding.
- [Circuit breakers](dispatch-circuit-breakers.md) — dependency failure isolation.
- [Dispatch idempotency](dispatch-idempotency.md) — exactly-once delivery.
- [Load testing & canary](load-testing-and-canary.md) — perf gates.
- [Tenant provisioning](tenant-provisioning.md) — onboarding a tenant.
- [Usage metering](usage-metering.md) — billing-grade counters.
- [Groundwork production conditions](groundwork-production-conditions.md) — readiness checklist.

## Connectors & Integrations

- [Connectors](connectors.md) — connector architecture.
- [Microsoft Graph connector](microsoft-graph-connector.md) — Entra/SharePoint sync.
- [Cloud / MCP / HTTP](cloud-mcp-http.md) — transport patterns.

## Demos & Testing

- [MCP live demo](mcp-live-demo.md) — end-to-end demo walkthrough.
- [Hyperagent MCP demo](hyperagent-mcp-demo.md) — multi-agent demo.
- [Integration testing](integration-testing.md) — integration test harness.
- [CI](ci.md) — continuous integration pipelines.
- [Client strategy](client-strategy.md) — SDK design.

## Business & Archive

- [Business materials](business/) — pitch and investor-facing material.
- [Archive](archive/) — historical planning artifacts (read-only).

## Onboarding

- [KT / onboarding](KT.md) — knowledge transfer notes.
