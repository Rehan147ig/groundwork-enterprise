import { NextResponse } from "next/server";
import { agentRuntimeEnv, LifecycleEvent, Agent, AgentVersion } from "@/lib/agentProxy";
import { requireConsolePermission } from "@/lib/consoleAuth";

// GET /api/agents/[agentId] — proxies the runtime's tenant-scoped agent
// detail (agent + versions + tamper-evident lifecycle events). Demo
// fallback mirrors the list route.

const DEMO_VERSIONS: AgentVersion[] = [
  { id: "agv_demo_1_1", agent_id: "ag_demo_1", version: "1.0.0", model_provider: "anthropic", model_name: "claude-4", status: "superseded", created_at: "2026-05-03T10:00:00Z", approved_at: "2026-05-09T15:19:00Z" },
  { id: "agv_demo_1_2", agent_id: "ag_demo_1", version: "2.1.0", model_provider: "anthropic", model_name: "claude-4", status: "active", created_at: "2026-06-01T09:00:00Z", approved_at: "2026-06-01T09:10:00Z" },
];

const DEMO_EVENTS: LifecycleEvent[] = [
  { id: "ev_demo_1", tenant_id: "tenant_demo", agent_id: "ag_demo_1", actor_principal_id: "principal:alice", event_type: "created", previous_state: "", new_state: "draft", reason: "", immutable_digest: "9f1c…e4a2", created_at: "2026-05-02T09:00:00Z" },
  { id: "ev_demo_2", tenant_id: "tenant_demo", agent_id: "ag_demo_1", agent_version_id: "agv_demo_1_1", actor_principal_id: "principal:alice", event_type: "version_created", previous_state: "", new_state: "draft", reason: "", immutable_digest: "7c21…90bd", created_at: "2026-05-03T10:00:00Z" },
  { id: "ev_demo_3", tenant_id: "tenant_demo", agent_id: "ag_demo_1", agent_version_id: "agv_demo_1_1", actor_principal_id: "principal:alice", event_type: "version_approved", previous_state: "draft", new_state: "approved", reason: "risk sign-off", immutable_digest: "4a10…c8f1", created_at: "2026-05-09T15:19:00Z" },
  { id: "ev_demo_4", tenant_id: "tenant_demo", agent_id: "ag_demo_1", agent_version_id: "agv_demo_1_1", actor_principal_id: "principal:alice", event_type: "version_activated", previous_state: "approved", new_state: "active", reason: "", immutable_digest: "d3ee…55ab", created_at: "2026-05-09T15:20:00Z" },
  { id: "ev_demo_5", tenant_id: "tenant_demo", agent_id: "ag_demo_1", actor_principal_id: "principal:alice", event_type: "activated", previous_state: "draft", new_state: "active", reason: "approved by risk", immutable_digest: "6b7c…1d9e", created_at: "2026-05-09T15:20:00Z" },
  { id: "ev_demo_6", tenant_id: "tenant_demo", agent_id: "ag_demo_1", agent_version_id: "agv_demo_1_2", actor_principal_id: "principal:alice", event_type: "version_created", previous_state: "active", new_state: "draft", reason: "version roll", immutable_digest: "e0f2…33cc", created_at: "2026-06-01T09:00:00Z" },
  { id: "ev_demo_7", tenant_id: "tenant_demo", agent_id: "ag_demo_1", agent_version_id: "agv_demo_1_1", actor_principal_id: "principal:alice", event_type: "version_superseded", previous_state: "active", new_state: "superseded", reason: "v2.1.0 shipped", immutable_digest: "aa51…7749", created_at: "2026-06-01T09:00:00Z" },
  { id: "ev_demo_8", tenant_id: "tenant_demo", agent_id: "ag_demo_1", agent_version_id: "agv_demo_1_2", actor_principal_id: "principal:alice", event_type: "version_approved", previous_state: "draft", new_state: "approved", reason: "", immutable_digest: "12f8…9c30", created_at: "2026-06-01T09:10:00Z" },
  { id: "ev_demo_9", tenant_id: "tenant_demo", agent_id: "ag_demo_1", agent_version_id: "agv_demo_1_2", actor_principal_id: "principal:alice", event_type: "version_activated", previous_state: "approved", new_state: "active", reason: "", immutable_digest: "8d2b…6e17", created_at: "2026-06-01T09:10:00Z" },
];

export async function GET(_: Request, { params }: { params: Promise<{ agentId: string }> }) {
  const denied = await requireConsolePermission("agents-read");
  if (denied) return denied;
  const { agentId } = await params;
  const { runtimeUrl, apiKey } = agentRuntimeEnv();

  if (runtimeUrl && apiKey) {
    try {
      const res = await fetch(`${runtimeUrl}/v1/agents/${encodeURIComponent(agentId)}`, {
        headers: { "X-Groundwork-API-Key": apiKey },
        cache: "no-store",
      });
      if (res.ok) {
        const data = await res.json();
        return NextResponse.json({
          source: "live",
          agent: data.agent,
          versions: data.versions ?? [],
          lifecycle_events: data.lifecycle_events ?? [],
        });
      }
      if (res.status === 404) {
        return NextResponse.json({ error: "agent_not_found" }, { status: 404 });
      }
      if (res.status !== 503) {
        return NextResponse.json({ error: `agents_query_failed (${res.status})` }, { status: res.status });
      }
    } catch {
      /* runtime unreachable: demo */
    }
  }

  const demoAgent: Agent = {
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
  };
  return NextResponse.json({
    source: "demo",
    agent: demoAgent,
    versions: DEMO_VERSIONS,
    lifecycle_events: DEMO_EVENTS,
  });
}
