import { NextRequest, NextResponse } from "next/server";
import {
  DEMO_BUDGETS,
  DEMO_CHECKPOINTS,
  DEMO_CONSENTS,
  DEMO_CONNECTORS,
  DEMO_CONTROLS,
  DEMO_DELEGATIONS,
  DEMO_EVIDENCE,
  DEMO_EXTERNAL_AGENTS,
  DEMO_EXTERNAL_BUDGETS,
  DEMO_GRANTS,
  DEMO_OUTBOX,
  DEMO_RUNS,
  DEMO_TOOLS,
  DEMO_TRANSFER_POLICIES,
  DEMO_TRUST_RELS,
  GovBudgetsResp,
  GovCheckpointsResp,
  GovConnectorDetailResp,
  GovConnectorHealthResp,
  GovConnectorsResp,
  GovConsentsResp,
  GovControlsResp,
  GovDelegationsResp,
  GovEvidenceResp,
  GovExternalAgentsResp,
  GovExternalBudgetsResp,
  GovGrantsResp,
  GovOutboxResp,
  GovRunsResp,
  GovToolsResp,
  GovTransferPoliciesResp,
  GovTrustRelsResp,
  GovVerifyResp,
  demoConnectorDetail,
  demoConnectorHealth,
  demoDelegationChain,
  demoExport,
  demoProvenance,
  demoRunDetail,
  demoToolDetail,
  govFetch,
} from "@/lib/governanceProxy";
import { agentError } from "@/lib/agentProxy";

// Catch-all proxy for the runtime's delegated-authority surface
// (/v1/governance/*). Reads (GET tools / grants / runs / details /
// Phase 3 controls / budgets / evidence / verify / checkpoints /
// outbox / Phase 4e framework exports) fall back to curated demo data
// when the runtime is unreachable or the governance service is not
// wired (503) — the console must look alive in a pitch even with a
// cold backend. Mutations NEVER demo-fake: they either succeed against
// the runtime or fail loudly (502).

type GovRouteParams = { params: Promise<{ path: string[] }> };

function notFound(path: string[]): NextResponse {
  return agentError(404, `Unknown governance route: /v1/governance/${path.join("/")}`);
}

export async function GET(request: NextRequest, { params }: GovRouteParams) {
  const { path } = await params;
  const p = path.join("/");
  const res = await govFetch("GET", path);
  const data = await res.json().catch(() => ({}));

  if (res.status === 503 || res.status === 502) {
    // Runtime unreachable or governance not wired: demo fallback.
    if (p === "tools") {
      const body: GovToolsResp = { source: "demo", tools: DEMO_TOOLS, count: DEMO_TOOLS.length };
      return NextResponse.json(body);
    }
    if (p === "runs") {
      const body: GovRunsResp = { source: "demo", runs: DEMO_RUNS, count: DEMO_RUNS.length };
      return NextResponse.json(body);
    }
    if (p === "emergency-controls") {
      const body: GovControlsResp = { source: "demo", controls: DEMO_CONTROLS, count: DEMO_CONTROLS.length };
      return NextResponse.json(body);
    }
    if (p === "budgets") {
      const body: GovBudgetsResp = { source: "demo", budgets: DEMO_BUDGETS, count: DEMO_BUDGETS.length };
      return NextResponse.json(body);
    }
    if (p === "evidence") {
      const body: GovEvidenceResp = { source: "demo", events: DEMO_EVIDENCE, count: DEMO_EVIDENCE.length };
      return NextResponse.json(body);
    }
    if (p === "audit/checkpoints") {
      const body: GovCheckpointsResp = { source: "demo", checkpoints: DEMO_CHECKPOINTS, count: DEMO_CHECKPOINTS.length };
      return NextResponse.json(body);
    }
    if (p === "outbox") {
      const body: GovOutboxResp = { source: "demo", events: DEMO_OUTBOX, count: DEMO_OUTBOX.length };
      return NextResponse.json(body);
    }
    if (p === "connectors") {
      const body: GovConnectorsResp = { source: "demo", connectors: DEMO_CONNECTORS, count: DEMO_CONNECTORS.length };
      return NextResponse.json(body);
    }
    // Phase 6: multi-agent trust (read-only demo fallbacks).
    if (p === "trust-relationships") {
      const body: GovTrustRelsResp = { source: "demo", relationships: DEMO_TRUST_RELS, count: DEMO_TRUST_RELS.length };
      return NextResponse.json(body);
    }
    if (p === "external-agents") {
      const body: GovExternalAgentsResp = { source: "demo", agents: DEMO_EXTERNAL_AGENTS, count: DEMO_EXTERNAL_AGENTS.length };
      return NextResponse.json(body);
    }
    if (p === "consents") {
      const body: GovConsentsResp = { source: "demo", consents: DEMO_CONSENTS, count: DEMO_CONSENTS.length };
      return NextResponse.json(body);
    }
    if (p === "transfer-policies") {
      const body: GovTransferPoliciesResp = { source: "demo", policies: DEMO_TRANSFER_POLICIES, count: DEMO_TRANSFER_POLICIES.length };
      return NextResponse.json(body);
    }
    if (p === "external-budgets") {
      const body: GovExternalBudgetsResp = { source: "demo", budgets: DEMO_EXTERNAL_BUDGETS, count: DEMO_EXTERNAL_BUDGETS.length };
      return NextResponse.json(body);
    }
    if (p === "delegations") {
      const body: GovDelegationsResp = { source: "demo", grants: DEMO_DELEGATIONS, count: DEMO_DELEGATIONS.length };
      return NextResponse.json(body);
    }
    if (p === "audit/verify") {
      const body: GovVerifyResp = {
        source: "demo",
        verified: true,
        chains_checked: 4,
        events_checked: 4,
        from_checkpoint: false,
        checked_at: new Date().toISOString(),
      };
      return NextResponse.json(body);
    }
    const parts = path;
    // Phase 4e: framework evidence exports (read-only; demo fallback).
    if (parts.length === 2 && parts[0] === "exports") {
      const d = demoExport(parts[1]);
      return d ? NextResponse.json(d) : notFound(path);
    }
    if (parts.length === 2 && parts[0] === "tools") {
      const d = demoToolDetail(parts[1]);
      return d ? NextResponse.json(d) : notFound(path);
    }
    if (parts.length === 2 && parts[0] === "runs") {
      const d = demoRunDetail(parts[1]);
      return d ? NextResponse.json(d) : notFound(path);
    }
    if (parts.length === 3 && parts[0] === "agents" && parts[2] === "grants") {
      const grants = DEMO_GRANTS.filter((g) => g.agent_id === parts[1]);
      const body: GovGrantsResp = { source: "demo", grants, count: grants.length };
      return NextResponse.json(body);
    }
    // Phase 5: connector registry (read-only demo fallback).
    if (parts.length === 2 && parts[0] === "connectors") {
      const d = demoConnectorDetail(parts[1]);
      return d ? NextResponse.json(d) : notFound(path);
    }
    if (parts.length === 3 && parts[0] === "connectors" && parts[2] === "health") {
      const d = demoConnectorHealth(parts[1]);
      return d ? NextResponse.json(d) : notFound(path);
    }
    // Phase 6: delegation chain + provenance detail (read-only demo).
    if (parts.length === 3 && parts[0] === "delegations" && parts[2] === "chain") {
      const d = demoDelegationChain(parts[1]);
      return d ? NextResponse.json(d) : notFound(path);
    }
    if (parts.length === 3 && parts[0] === "evidence" && parts[2] === "provenance") {
      const d = demoProvenance(parts[1]);
      return d ? NextResponse.json(d) : notFound(path);
    }
  }

  if (!res.ok) {
    return agentError(res.status, data.error ?? `governance_${p.replace(/\//g, "_")}_failed (${res.status})`);
  }
  return NextResponse.json({ ...data, source: "live" });
}

export async function POST(request: NextRequest, { params }: GovRouteParams) {
  const { path } = await params;
  const body = await request.json().catch(() => null);
  const res = await govFetch("POST", path, body ?? {});
  const data = await res.json().catch(() => ({}));
  if (res.status === 503 || res.status === 502) {
    // Mutations never demo-fake: fail loudly with a clear reason.
    return agentError(
      502,
      "Query runtime unreachable or governance not wired — mutations require a live runtime.",
    );
  }
  if (!res.ok) {
    return agentError(res.status, data.error ?? `governance_mutation_failed (${res.status})`);
  }
  return NextResponse.json({ ...data, source: "live" });
}
