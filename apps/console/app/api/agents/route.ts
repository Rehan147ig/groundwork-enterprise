import { NextRequest, NextResponse } from "next/server";
import {
  Agent,
  agentError,
  agentHeaders,
  agentRuntimeEnv,
} from "@/lib/agentProxy";
import { requireConsolePermission } from "@/lib/consoleAuth";

// Proxies the runtime's Agent Registry (GET /v1/agents list, POST
// /v1/agents create) using a server-side API key + console-admin
// assertion. Falls back to curated demo data ONLY when the console is
// explicitly running in demo mode (GROUNDWORK_DEMO_MODE=true) AND the
// runtime is unreachable or the registry is not wired (503) — in any
// other deployment a missing backend is a hard error, never silent
// synthetic data. `source` tells the UI which path it got.

const DEMO_AGENTS: Agent[] = [
  {
    id: "ag_demo_1",
    tenant_id: "tenant_demo",
    name: "treasury-reconcile",
    description: "Reconciles daily treasury positions against the ledger.",
    owner_principal_id: "principal:alice",
    business_purpose: "Daily cash reconciliation with sign-off trail",
    risk_tier: "critical",
    lifecycle_state: "active",
    environment: "production",
    created_at: "2026-05-02T09:00:00Z",
    updated_at: "2026-06-11T08:12:00Z",
    activated_at: "2026-05-09T15:20:00Z",
    active_version_id: "agv_demo_1_2",
    active_version: "2.1.0",
    version_count: 2,
  },
  {
    id: "ag_demo_2",
    tenant_id: "tenant_demo",
    name: "hr-benefits-helper",
    description: "Answers benefits questions from HR policy docs.",
    owner_principal_id: "principal:carol",
    business_purpose: "Employee self-service for benefits",
    risk_tier: "medium",
    lifecycle_state: "suspended",
    environment: "staging",
    created_at: "2026-04-18T10:00:00Z",
    updated_at: "2026-06-08T17:45:00Z",
    activated_at: "2026-05-01T09:30:00Z",
    active_version_id: "agv_demo_2_1",
    active_version: "1.3.0",
    version_count: 3,
  },
  {
    id: "ag_demo_3",
    tenant_id: "tenant_demo",
    name: "vendor-pay-review",
    description: "Drafts vendor payment review memos.",
    owner_principal_id: "principal:bob",
    business_purpose: "AP review pre-approval drafts",
    risk_tier: "high",
    lifecycle_state: "pending_approval",
    environment: "production",
    created_at: "2026-06-05T11:00:00Z",
    updated_at: "2026-06-10T14:02:00Z",
    version_count: 1,
  },
  {
    id: "ag_demo_4",
    tenant_id: "tenant_demo",
    name: "legacy-pii-scan",
    description: "Scanned legacy shares for PII exposure.",
    owner_principal_id: "principal:dave",
    business_purpose: "One-off exposure sweep",
    risk_tier: "critical",
    lifecycle_state: "revoked",
    environment: "staging",
    created_at: "2026-03-12T08:00:00Z",
    updated_at: "2026-06-02T16:30:00Z",
    revoked_at: "2026-06-02T16:30:00Z",
    version_count: 3,
  },
  {
    id: "ag_demo_5",
    tenant_id: "tenant_demo",
    name: "mkdocs-writer",
    description: "Proposed docs summarizer — not yet reviewed.",
    owner_principal_id: "principal:alice",
    business_purpose: "Internal documentation summaries",
    risk_tier: "low",
    lifecycle_state: "draft",
    environment: "development",
    created_at: "2026-06-09T09:00:00Z",
    updated_at: "2026-06-09T09:00:00Z",
    version_count: 0,
  },
];

export async function GET(request: NextRequest) {
  const denied = await requireConsolePermission("agents-read");
  if (denied) return denied;
  const { runtimeUrl, apiKey } = agentRuntimeEnv();
  const state = request.nextUrl.searchParams.get("state") ?? "";
  if (runtimeUrl && apiKey) {
    try {
      const res = await fetch(
        `${runtimeUrl}/v1/agents${state ? `?state=${encodeURIComponent(state)}` : ""}`,
        { headers: { "X-Groundwork-API-Key": apiKey }, cache: "no-store" },
      );
      if (res.ok) {
        const data = await res.json();
        return NextResponse.json({ source: "live", agents: data.agents ?? [], count: data.count ?? 0 });
      }
      // 503 = registry not wired (in-memory/local mode): fall through to demo.
      if (res.status !== 503) {
        return NextResponse.json({ source: "error", error: `agents_list_failed (${res.status})` }, { status: res.status });
      }
    } catch {
      /* runtime unreachable: demo */
    }
  }
  return demoData({ source: "demo", agents: DEMO_AGENTS, count: DEMO_AGENTS.length });
}

// demoData is the fail-closed gate for curated demo responses: only
// GROUNDWORK_DEMO_MODE=true opts the console into serving synthetic
// data in place of a live backend. Production should never send DEMO_*
// payloads (they leak internal data shapes); with the flag off these
// routes return 503 instead of fabricating data.
function demoData<T>(data: T): NextResponse {
  if (process.env.GROUNDWORK_DEMO_MODE !== "true") {
    return NextResponse.json(
      { source: "error", error: "agent_registry_unavailable" },
      { status: 503 },
    );
  }
  return NextResponse.json(data);
}

export async function POST(request: NextRequest) {
  const denied = await requireConsolePermission("agents-manage");
  if (denied) return denied;
  const { runtimeUrl, apiKey, secret } = agentRuntimeEnv();
  const payload = (await request.json().catch(() => null)) as Record<string, unknown> | null;
  if (!payload || typeof payload.name !== "string" || !payload.name.trim()) {
    return agentError(400, "A name is required.");
  }
  if (!runtimeUrl || !apiKey) {
    return agentError(400, "No API key. Set GROUNDWORK_API_KEY or pass api_key.");
  }

  const body: Record<string, unknown> = {};
  for (const k of ["name", "description", "owner_principal_id", "business_purpose", "risk_tier", "environment"] as const) {
    if (payload[k] !== undefined) body[k] = payload[k];
  }

  try {
    const res = await fetch(`${runtimeUrl}/v1/agents`, {
      method: "POST",
      headers: await agentHeaders(secret, apiKey),
      body: JSON.stringify(body),
      cache: "no-store",
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      return NextResponse.json({ source: "live", agent: data.agent });
    }
    return NextResponse.json(data, { status: res.status });
  } catch (error: unknown) {
    return agentError(502, error instanceof Error ? error.message : "Query runtime unavailable");
  }
}
