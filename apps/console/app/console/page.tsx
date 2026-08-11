"use client";

import { useCallback, useEffect, useState } from "react";
import "./console.css";
import {
  ActionDecision,
  AgentToolGrant,
  AgentRun,
  AgentTrustRelationship,
  BudgetPolicy,
  Connector,
  ConnectorDetail,
  ConnectorHealth,
  ConsentRecord,
  DelegationChain,
  DelegationGrant,
  EmergencyControl,
  EvidenceCheckpoint,
  EvidenceEvent,
  EvidenceVerifyResult,
  ExternalAgent,
  ExternalBudgetPolicy,
  FrameworkExport,
  GovRunDetailResp,
  GovToolDetailResp,
  OutboxEvent,
  ProvenanceView,
  Tool,
  ToolAction,
  TransferPolicy,
} from "@/lib/governanceProxy";
import { sanitizeRichText } from "@/lib/sanitize";

// ----- types (mirror the /api proxy responses) -----
type Decision = { document_id: string; allowed: boolean; reason: string };
type AuditEntry = {
  trace_id: string;
  timestamp_utc: string;
  user_id: string;
  agent_key_name?: string;
  acl_decision: string;
  reason: string;
  fail_closed: boolean;
  total_latency_ms: number;
  decisions?: Decision[];
};
type AuditResp = { source: string; entries: AuditEntry[]; verify: { verified: boolean; entries_checked: number } };
type Finding = { kind: string; severity: "high" | "medium" | "low"; title: string; detail: string };
type Graph = { teams: string[]; documents: string[]; tuples: number };
type Agent = {
  id: string;
  name: string;
  description?: string;
  owner_principal_id: string;
  business_purpose?: string;
  risk_tier: string;
  lifecycle_state: string;
  environment: string;
  created_at: string;
  activated_at?: string;
  revoked_at?: string;
  active_version?: string;
  version_count: number;
};
type AgentVersion = { id: string; version: string; model_provider?: string; model_name?: string; status: string; created_at: string; approved_at?: string };
type LifecycleEvent = { id: string; agent_version_id?: string; actor_principal_id: string; event_type: string; previous_state: string; new_state: string; reason: string; immutable_digest: string; created_at: string };
type AgentDetail = { source: string; agent: Agent; versions: AgentVersion[]; lifecycle_events: LifecycleEvent[] };
type AgentsResp = { source: string; agents: Agent[]; count: number };
type BreakGlassGrant = {
  id: string;
  tenant_id: string;
  operator_principal_id: string;
  reason: string;
  duration_minutes: number;
  key_id: number;
  key_prefix: string;
  status: "active" | "expired" | "revoked";
  expires_at: string;
  requested_at: string;
  revoked_at?: string;
  revoked_by?: string;
  revocation_reason?: string;
  immutable_digest: string;
  created_at: string;
};
type BreakGlassResp = { source: string; grants: BreakGlassGrant[] } | { source: string; error: string };

const VIEWS = ["overview", "connect", "agent", "agents", "governance", "trust", "controls", "break", "audit", "leak"] as const;
type View = (typeof VIEWS)[number];
const META: Record<View, [string, string]> = {
  overview: ["Overview", "Runtime governance at a glance"],
  connect: ["Connect", "Source systems"],
  agent: ["Connect Agent", "Put Groundwork in the path"],
  agents: ["Agents", "Registry · lifecycle · tamper-evident events"],
  governance: ["Delegated Authority", "Tools · grants · runs · one-time approvals"],
  trust: ["Multi-Agent Trust", "Trust edges · external agents · consent · budgets"],
  controls: ["Incident Response", "Emergency controls · budgets · evidence · outbox"],
  break: ["Break Glass", "Time-bounded emergency admin access"],
  audit: ["Audit Timeline", "Tamper-evident decision log"],
  leak: ["Leak Report", "Pre-emptive exposure scan"],
};

const RISK_TIERS = ["low", "medium", "high", "critical"];
const ENVIRONMENTS = ["development", "staging", "production"];

function stateBadge(state: string): string {
  switch (state) {
    case "active": return "allow";
    case "revoked":
    case "retired": return "deny";
    default: return "medium";
  }
}

function runBadge(status: string): string {
  switch (status) {
    case "completed": return "allow";
    case "denied":
    case "failed":
    case "revoked": return "deny";
    default: return "medium";
  }
}

function decisionBadge(d: string): string {
  switch (d) {
    case "allowed": return "allow";
    case "denied": return "deny";
    default: return "medium";
  }
}

const PERSONAS = [
  { id: "eve", label: "Eve · Executive" },
  { id: "bob", label: "Bob · Engineering" },
  { id: "alice", label: "Alice · Finance" },
  { id: "carol", label: "Carol · HR" },
  { id: "dave", label: "Dave · Security" },
];

const MCP_CONFIG = `"mcpServers": {
  "groundwork": {
    "url": "https://acme.groundwork.app/mcp",
    "headers": {
      "X-Groundwork-API-Key": "gw_live_••••••",
      "X-Groundwork-User-Assertion": "<SSO-signed JWT>"
    }
  }
}`;

function Mark({ size = 30 }: { size?: number }) {
  return (
    <span className="logo">
      <svg width={size} height={size} viewBox="0 0 32 32" fill="none">
        <rect x="2" y="2" width="28" height="28" rx="8" fill="url(#gwg)" />
        <path d="M9 19.5l7-4 7 4M9 14l7-4 7 4M16 23.5v-8" stroke="#fff" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
        <defs>
          <linearGradient id="gwg" x1="2" y1="2" x2="30" y2="30">
            <stop stopColor="#6366f1" />
            <stop offset="1" stopColor="#2dd4bf" />
          </linearGradient>
        </defs>
      </svg>
      <span className="wm">
        <b>Groundwork</b>
      </span>
    </span>
  );
}

export default function ConsolePage() {
  const [signedIn, setSignedIn] = useState(false);
  const [view, setView] = useState<View>("overview");
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [audit, setAudit] = useState<AuditResp | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [pat, setPat] = useState("");
  const [copied, setCopied] = useState(false);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [agentsSource, setAgentsSource] = useState("demo");
  const [detail, setDetail] = useState<Record<string, AgentDetail | null>>({});
  const [agentsError, setAgentsError] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [newAgent, setNewAgent] = useState({ name: "", risk_tier: "medium", environment: "development" });
  const [versionInputs, setVersionInputs] = useState<Record<string, string>>({});
  const [actionBusy, setActionBusy] = useState<string>("");
  // live "try it"
  const [persona, setPersona] = useState("bob");
  const [question, setQuestion] = useState("summarize the executive strategy");
  const [tryResult, setTryResult] = useState<string>("");

  // ---- Phase 8.4: break-glass operator access ----
  const [bgGrants, setBgGrants] = useState<BreakGlassGrant[]>([]);
  const [bgSource, setBgSource] = useState("offline");
  const [bgError, setBgError] = useState("");
  const [bgBusy, setBgBusy] = useState<string>("");
  const [bgReason, setBgReason] = useState("");
  const [bgDuration, setBgDuration] = useState(60);
  const [bgMinted, setBgMinted] = useState<{ key?: string; grant?: BreakGlassGrant } | null>(null);

  const load = useCallback(async () => {
    try {
      const [a, l, ag] = await Promise.all([
        fetch("/api/audit").then((r) => r.json()),
        fetch("/api/leak-report").then((r) => r.json()),
        fetch("/api/agents").then((r) => r.json()),
      ]);
      setAudit(a);
      setFindings(l.findings ?? []);
      setAgents(ag.agents ?? []);
      setAgentsSource(ag.source ?? "demo");
      if ((ag.agents ?? []).length > 0) loadGrants((ag.agents ?? [])[0].id);
      loadGovernance();
      loadControls();
      loadBudgets();
      loadEvidence();
      loadCheckpoints();
      loadOutbox();
      loadExport("eu_ai_act");
      loadConnectors();
      loadTrust();
      loadBreakGlass();
    } catch {
      /* routes always return demo data; ignore */
    }
  }, []);

  async function loadAgentDetail(agentId: string) {
    const d = await fetch(`/api/agents/${agentId}`).then((r) => r.json());
    setDetail((prev) => ({ ...prev, [agentId]: d }));
  }

  async function createAgent() {
    setAgentsError("");
    const name = newAgent.name.trim();
    if (!name) return;
    const r = await fetch("/api/agents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(newAgent),
    });
    const data = await r.json();
    if (!r.ok) {
      setAgentsError(data.error ?? `Create failed (${r.status})`);
      return;
    }
    setNewAgent({ name: "", risk_tier: "medium", environment: "development" });
    setCreateOpen(false);
    setAgents((prev) => [data.agent, ...prev]);
  }

  async function agentAction(agentId: string, action: string, extra?: string) {
    setActionBusy(`${agentId}:${action}`);
    setAgentsError("");
    try {
      const body: Record<string, unknown> = {};
      if (action === "versions") {
        const v = (versionInputs[agentId] ?? "").trim();
        if (!v) return;
        body.version = v;
      } else if (extra) {
        body.reason = extra;
      }
      const r = await fetch(`/api/agents/${agentId}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await r.json();
      if (!r.ok) {
        setAgentsError(`${action}: ${data.error ?? r.status}`);
        return;
      }
      if (action === "versions") {
        setVersionInputs((prev) => ({ ...prev, [agentId]: "" }));
      }
      await load(); // refresh the registry
      const d = await fetch(`/api/agents/${agentId}`).then((x) => x.json());
      setDetail((prev) => ({ ...prev, [agentId]: d }));
    } finally {
      setActionBusy("");
    }
  }

  // ---- delegated authority (governance) ----
  const [govTools, setGovTools] = useState<Tool[]>([]);
  const [govToolsSource, setGovToolsSource] = useState("demo");
  const [govToolDetail, setGovToolDetail] = useState<Record<string, GovToolDetailResp | null>>({});
  const [govRuns, setGovRuns] = useState<AgentRun[]>([]);
  const [govRunsSource, setGovRunsSource] = useState("demo");
  const [govRunDetail, setGovRunDetail] = useState<Record<string, GovRunDetailResp | null>>({});
  const [govGrants, setGovGrants] = useState<AgentToolGrant[]>([]);
  const [govGrantsAgent, setGovGrantsAgent] = useState("");
  const [govError, setGovError] = useState("");
  const [govBusy, setGovBusy] = useState("");
  const [govMint, setGovMint] = useState<{ token?: string; grant?: DelegationGrant; already?: boolean; error?: string } | null>(null);
  const [registerOpen, setRegisterOpen] = useState(false);
  const [mintOpen, setMintOpen] = useState(false);
  const [newTool, setNewTool] = useState({ name: "", description: "", transport: "builtin", owner_principal_id: "principal:alice", region: "us-east-1" });
  const [grantForm, setGrantForm] = useState({ agent_id: "", version_id: "", tool_id: "", action_id: "", resource_scope: "", region_constraint: "us-east-1", call_limit_per_run: 10, requires_approval: false });
  const [mintForm, setMintForm] = useState({ agent_id: "", subject_principal_id: "principal:bob", purpose: "", permitted_actions: "", ttl_seconds: 300 });
  const [tokenCopied, setTokenCopied] = useState(false);

  // ---- Phase 3: incident response (controls · budgets · evidence · outbox) ----
  const [controls, setControls] = useState<EmergencyControl[]>([]);
  const [controlsSource, setControlsSource] = useState("demo");
  const [budgets, setBudgets] = useState<BudgetPolicy[]>([]);
  const [budgetsSource, setBudgetsSource] = useState("demo");
  const [effectiveBudget, setEffectiveBudget] = useState<BudgetPolicy | null>(null);
  const [evidence, setEvidence] = useState<EvidenceEvent[]>([]);
  const [evidenceSource, setEvidenceSource] = useState("demo");
  const [verify, setVerify] = useState<EvidenceVerifyResult | null>(null);
  const [checkpoints, setCheckpoints] = useState<EvidenceCheckpoint[]>([]);
  const [outbox, setOutbox] = useState<OutboxEvent[]>([]);
  const [outboxSource, setOutboxSource] = useState("demo");
  const [outboxStatus, setOutboxStatus] = useState("");
  const [p3Error, setP3Error] = useState("");
  const [p3Busy, setP3Busy] = useState("");
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [controlReason, setControlReason] = useState("console incident response");
  const [budgetOpen, setBudgetOpen] = useState(false);
  const [budgetForm, setBudgetForm] = useState({
    scope_type: "tenant", agent_version_id: "", grant_id: "",
    max_actions_per_run: 0, max_denied_per_run: 0, max_run_duration_seconds: 0, max_citations_per_query: 0,
  });

  // ---- Phase 4e: framework evidence exports ----
  const [exportFramework, setExportFramework] = useState("eu_ai_act");
  const [exportReport, setExportReport] = useState<FrameworkExport | null>(null);
  const [exportSource, setExportSource] = useState("demo");

  // ---- Phase 5: connector gateway ----
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [connectorSource, setConnectorSource] = useState("demo");
  const [connectorDetail, setConnectorDetail] = useState<ConnectorDetail | null>(null);
  const [connectorHealth, setConnectorHealth] = useState<Record<string, ConnectorHealth>>({});
  const [connectorBusy, setConnectorBusy] = useState("");

  // ---- Phase 6: multi-agent trust ----
  const [trustRels, setTrustRels] = useState<AgentTrustRelationship[]>([]);
  const [trustSource, setTrustSource] = useState("demo");
  const [extAgents, setExtAgents] = useState<ExternalAgent[]>([]);
  const [extAgentSource, setExtAgentSource] = useState("demo");
  const [consents, setConsents] = useState<ConsentRecord[]>([]);
  const [consentSource, setConsentSource] = useState("demo");
  const [transferPolicies, setTransferPolicies] = useState<TransferPolicy[]>([]);
  const [tpSource, setTpSource] = useState("demo");
  const [extBudgets, setExtBudgets] = useState<ExternalBudgetPolicy[]>([]);
  const [extBudgetSource, setExtBudgetSource] = useState("demo");
  const [delegations, setDelegations] = useState<DelegationGrant[]>([]);
  const [delegationChain, setDelegationChain] = useState<DelegationChain | null>(null);
  const [chainFor, setChainFor] = useState("");
  const [provenance, setProvenance] = useState<ProvenanceView | null>(null);
  const [provFor, setProvFor] = useState("");
  const [trustError, setTrustError] = useState("");
  const [trustBusy, setTrustBusy] = useState("");
  const [relReason, setRelReason] = useState("console trust review");

  useEffect(() => {
    if (signedIn) load();
  }, [signedIn, load]);

  async function loadGovernance() {
    try {
      const [t, r] = await Promise.all([
        fetch("/api/governance/tools").then((x) => x.json()),
        fetch("/api/governance/runs").then((x) => x.json()),
      ]);
      setGovTools(t.tools ?? []);
      setGovToolsSource(t.source ?? "demo");
      setGovRuns(r.runs ?? []);
      setGovRunsSource(r.source ?? "demo");
    } catch {
      /* demo fallback from the proxy */
    }
    if (govGrantsAgent) loadGrants(govGrantsAgent);
  }

  async function loadGrants(agentId: string) {
    setGovGrantsAgent(agentId);
    const g = await fetch(`/api/governance/agents/${agentId}/grants`).then((x) => x.json());
    setGovGrants(g.grants ?? []);
  }

  // ---- Phase 3 loaders ----
  async function loadControls() {
    try {
      const r = await fetch("/api/governance/emergency-controls").then((x) => x.json());
      setControls(r.controls ?? []);
      setControlsSource(r.source ?? "demo");
    } catch { /* demo fallback from the proxy */ }
  }

  async function loadBudgets() {
    try {
      const r = await fetch("/api/governance/budgets").then((x) => x.json());
      setBudgets(r.budgets ?? []);
      setBudgetsSource(r.source ?? "demo");
    } catch { /* demo fallback from the proxy */ }
  }

  async function loadEvidence() {
    try {
      const r = await fetch("/api/governance/evidence?limit=25").then((x) => x.json());
      setEvidence(r.events ?? []);
      setEvidenceSource(r.source ?? "demo");
    } catch { /* demo fallback from the proxy */ }
  }

  async function loadCheckpoints() {
    try {
      const r = await fetch("/api/governance/audit/checkpoints").then((x) => x.json());
      setCheckpoints(r.checkpoints ?? []);
    } catch { /* demo fallback from the proxy */ }
  }

  async function loadOutbox(status = "") {
    try {
      const q = status ? `?status=${encodeURIComponent(status)}` : "";
      const r = await fetch(`/api/governance/outbox${q}`).then((x) => x.json());
      setOutbox(r.events ?? []);
      setOutboxSource(r.source ?? "demo");
    } catch { /* demo fallback from the proxy */ }
  }

  // ---- Phase 4e: framework evidence exports ----
  async function loadExport(framework: string) {
    setExportFramework(framework);
    try {
      const r = await fetch(`/api/governance/exports/${framework}`).then((x) => x.json());
      if (r.error) { setExportReport(null); return; }
      setExportReport(r.framework ? r : null);
      setExportSource(r.source ?? "demo");
    } catch { setExportReport(null); }
  }

  // ---- Phase 5 loaders ----
  async function loadConnectors() {
    try {
      const r = await fetch("/api/governance/connectors").then((x) => x.json());
      setConnectors(r.connectors ?? []);
      setConnectorSource(r.source ?? "demo");
    } catch { /* demo fallback from the proxy */ }
  }

  async function loadConnectorDetail(id: string) {
    setConnectorDetail(null);
    try {
      const r = await fetch(`/api/governance/connectors/${id}`).then((x) => x.json());
      if (r.error) return;
      setConnectorDetail(r.detail ?? null);
    } catch { /* demo fallback from the proxy */ }
  }

  async function probeConnector(id: string) {
    setConnectorBusy(`probe:${id}`);
    try {
      const r = await fetch(`/api/governance/connectors/${id}/health`).then((x) => x.json());
      if (r.error) { setP3Error(r.error); return; }
      setConnectorHealth((h) => ({ ...h, [id]: r.health }));
      if (connectorDetail?.connector.id === id) {
        setConnectorDetail({ ...connectorDetail, connector: connectorDetail.connector });
      }
    } finally {
      setConnectorBusy("");
    }
  }

  // ---- Phase 6: multi-agent trust loaders ----
  async function loadTrust() {
    try {
      const [r, e, c, tp, eb, dg] = await Promise.all([
        fetch("/api/governance/trust-relationships").then((x) => x.json()),
        fetch("/api/governance/external-agents").then((x) => x.json()),
        fetch("/api/governance/consents").then((x) => x.json()),
        fetch("/api/governance/transfer-policies").then((x) => x.json()),
        fetch("/api/governance/external-budgets").then((x) => x.json()),
        fetch("/api/governance/delegations").then((x) => x.json()),
      ]);
      setTrustRels(r.relationships ?? []);
      setTrustSource(r.source ?? "demo");
      setExtAgents(e.agents ?? []);
      setExtAgentSource(e.source ?? "demo");
      setConsents(c.consents ?? []);
      setConsentSource(c.source ?? "demo");
      setTransferPolicies(tp.policies ?? []);
      setTpSource(tp.source ?? "demo");
      setExtBudgets(eb.budgets ?? []);
      setExtBudgetSource(eb.source ?? "demo");
      setDelegations(dg.grants ?? []);
    } catch { /* demo fallback from the proxy */ }
  }

  // ---- Phase 8.4: break-glass loaders ----
  async function loadBreakGlass() {
    setBgError("");
    try {
      const r = await fetch("/api/break-glass").then((x) => x.json());
      if (r.error) { setBgGrants([]); setBgSource("offline"); return; }
      setBgGrants(r.grants ?? []);
      setBgSource(r.source ?? "demo");
    } catch { /* runtime unreachable — described in the view */ }
  }

  async function openBreakGlass() {
    setBgError("");
    if (bgReason.trim().length < 10) { setBgError("Justification must be at least 10 characters."); return; }
    setBgBusy("open");
    try {
      const r = await fetch("/api/break-glass", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: bgReason.trim(), duration_minutes: bgDuration }),
      });
      const data = await r.json();
      if (!r.ok) { setBgError(data.error ?? `open failed (${r.status})`); return; }
      setBgMinted({ key: data.key, grant: data.grant });
      setBgReason("");
      await loadBreakGlass();
    } finally { setBgBusy(""); }
  }

  async function revokeBreakGlass(grantId: string) {
    setBgError("");
    setBgBusy(`revoke:${grantId}`);
    try {
      const r = await fetch(`/api/break-glass/${grantId}/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: bgReason.trim() || "console break-glass revocation" }),
      });
      const data = await r.json();
      if (!r.ok) { setBgError(data.error ?? `revoke failed (${r.status})`); return; }
      setBgMinted(null);
      await loadBreakGlass();
    } finally { setBgBusy(""); }
  }

  async function loadChain(grantId: string) {
    setChainFor(grantId);
    setTrustError("");
    try {
      const r = await fetch(`/api/governance/delegations/${grantId}/chain`).then((x) => x.json());
      if (r.error) { setDelegationChain(null); setTrustError(r.error); return; }
      setDelegationChain(r.chain ?? null);
    } catch { setDelegationChain(null); }
  }

  async function loadProvenance(eventId: string) {
    setProvFor(eventId);
    setTrustError("");
    try {
      const r = await fetch(`/api/governance/evidence/${eventId}/provenance`).then((x) => x.json());
      if (r.error) { setProvenance(null); setTrustError(r.error); return; }
      setProvenance(r.provenance ?? null);
    } catch { setProvenance(null); }
  }

  async function trustAction(relId: string, action: string) {
    setTrustError("");
    setTrustBusy(`${relId}:${action}`);
    try {
      const r = await fetch(`/api/governance/trust-relationships/${relId}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: relReason.trim() || "console trust review" }),
      });
      const data = await r.json();
      if (!r.ok) { setTrustError(data.error ?? `${action} failed (${r.status})`); return; }
      await loadTrust();
    } finally { setTrustBusy(""); }
  }

  async function extAgentAction(extId: string, action: string) {
    setTrustError("");
    setTrustBusy(`ext:${extId}:${action}`);
    try {
      const r = await fetch(`/api/governance/external-agents/${extId}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: relReason.trim() || "console trust review" }),
      });
      const data = await r.json();
      if (!r.ok) { setTrustError(data.error ?? `${action} failed (${r.status})`); return; }
      await loadTrust();
    } finally { setTrustBusy(""); }
  }

  async function revokeConsent(consentId: string) {
    setTrustError("");
    setTrustBusy(`consent:${consentId}`);
    try {
      const r = await fetch(`/api/governance/consents/${consentId}/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: relReason.trim() || "console consent review" }),
      });
      const data = await r.json();
      if (!r.ok) { setTrustError(data.error ?? `revoke failed (${r.status})`); return; }
      await loadTrust();
    } finally { setTrustBusy(""); }
  }

  async function transferPolicyAction(policyId: string, action: string) {
    setTrustError("");
    setTrustBusy(`tp:${policyId}:${action}`);
    try {
      const r = await fetch(`/api/governance/transfer-policies/${policyId}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: relReason.trim() || "console transfer review" }),
      });
      const data = await r.json();
      if (!r.ok) { setTrustError(data.error ?? `${action} failed (${r.status})`); return; }
      await loadTrust();
    } finally { setTrustBusy(""); }
  }

  async function govControl(target: string, id: string, action: string, irreversible = false) {
    setP3Error("");
    if (irreversible && !window.confirm(`Irreversibly ${action} ${target} ${id}?`)) return;
    setP3Busy(`${action}:${id}`);
    try {
      const r = await fetch(`/api/governance/${target}/${id}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: controlReason.trim() || "console incident response" }),
      });
      const data = await r.json();
      if (!r.ok) { setP3Error(data.error ?? `${action} failed (${r.status})`); return; }
      await loadControls();
      if (target === "runs") loadGovernance();
    } finally { setP3Busy(""); }
  }

  async function govVerify(createCheckpoint: boolean, checkpointId = "") {
    setP3Error("");
    setVerifyBusy(true);
    try {
      const q = new URLSearchParams();
      if (createCheckpoint) q.set("create_checkpoint", "true");
      if (checkpointId) q.set("checkpoint_id", checkpointId);
      const s = q.toString();
      const r = await fetch(`/api/governance/audit/verify${s ? `?${s}` : ""}`).then((x) => x.json());
      if (r.error) { setP3Error(r.error); setVerify(null); return; }
      setVerify(r);
      if (createCheckpoint) loadCheckpoints();
    } finally { setVerifyBusy(false); }
  }

  async function govUpsertBudget() {
    setP3Error("");
    setP3Busy("budget");
    try {
      const r = await fetch("/api/governance/budgets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(budgetForm),
      });
      const data = await r.json();
      if (!r.ok) { setP3Error(data.error ?? `budget failed (${r.status})`); return; }
      setBudgetOpen(false);
      setBudgetForm((f) => ({ ...f, max_actions_per_run: 0, max_denied_per_run: 0, max_run_duration_seconds: 0, max_citations_per_query: 0 }));
      loadBudgets();
    } finally { setP3Busy(""); }
  }

  async function govEffectiveBudget() {
    setP3Error("");
    try {
      const r = await fetch("/api/governance/budgets/effective").then((x) => x.json());
      if (r.error) { setP3Error(r.error); setEffectiveBudget(null); return; }
      setEffectiveBudget(r.budget ?? null);
    } catch { setEffectiveBudget(null); }
  }

  async function loadToolDetail(toolId: string) {
    const d = await fetch(`/api/governance/tools/${toolId}`).then((x) => x.json());
    setGovToolDetail((prev) => ({ ...prev, [toolId]: d }));
    if (!d.tool) return;
    if (grantForm.tool_id === toolId && !grantForm.action_id && (d.actions ?? []).length > 0) {
      setGrantForm((f) => ({ ...f, action_id: d.actions[0].id }));
    }
  }

  async function loadRunDetail(runId: string) {
    const d = await fetch(`/api/governance/runs/${runId}`).then((x) => x.json());
    setGovRunDetail((prev) => ({ ...prev, [runId]: d }));
  }

  async function govRegisterTool() {
    setGovError("");
    if (!newTool.name.trim()) return;
    setGovBusy("register-tool");
    try {
      const r = await fetch("/api/governance/tools", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newTool),
      });
      const data = await r.json();
      if (!r.ok) { setGovError(data.error ?? `register failed (${r.status})`); return; }
      setNewTool({ name: "", description: "", transport: "builtin", owner_principal_id: "principal:alice", region: "us-east-1" });
      setRegisterOpen(false);
      setGovTools((prev) => [data.tool, ...prev]);
    } finally { setGovBusy(""); }
  }

  async function govToolLifecycle(toolId: string, lifecycle: string) {
    setGovError("");
    setGovBusy(`tool:${toolId}:${lifecycle}`);
    try {
      const r = await fetch(`/api/governance/tools/${toolId}/lifecycle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lifecycle, reason: `console ${lifecycle}` }),
      });
      const data = await r.json();
      if (!r.ok) { setGovError(data.error ?? `lifecycle failed (${r.status})`); return; }
      setGovTools((prev) => prev.map((t) => (t.id === toolId ? data.tool : t)));
      await loadToolDetail(toolId);
    } finally { setGovBusy(""); }
  }

  async function govGrant() {
    setGovError("");
    const f = grantForm;
    if (!f.agent_id || !f.version_id || !f.tool_id || !f.action_id || !f.resource_scope.trim()) {
      setGovError("Grant needs agent, version, tool, action and resource_scope.");
      return;
    }
    setGovBusy("grant");
    try {
      const r = await fetch("/api/governance/grants", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(f),
      });
      const data = await r.json();
      if (!r.ok) { setGovError(data.error ?? `grant failed (${r.status})`); return; }
      setGovGrants((prev) => [data.grant, ...prev]);
      setGrantForm((p) => ({ ...p, resource_scope: "", call_limit_per_run: 10, requires_approval: false }));
    } finally { setGovBusy(""); }
  }

  async function govRevokeGrant(grantId: string) {
    setGovError("");
    setGovBusy(`revoke:${grantId}`);
    try {
      const r = await fetch(`/api/governance/grants/${grantId}/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: "console revocation" }),
      });
      const data = await r.json();
      if (!r.ok) { setGovError(data.error ?? `revoke failed (${r.status})`); return; }
      loadGrants(govGrantsAgent);
    } finally { setGovBusy(""); }
  }

  async function govMintDelegation(body: Record<string, unknown>) {
    setGovError("");
    setGovBusy("mint");
    try {
      const r = await fetch("/api/governance/delegations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await r.json();
      if (!r.ok) { setGovMint({ error: data.error ?? `mint failed (${r.status})` }); return; }
      setGovMint({ token: data.token, grant: data.grant, already: data.token_already_issued });
    } finally { setGovBusy(""); }
  }

  async function govDecision(runId: string, actionId: string, approve: boolean) {
    setGovError("");
    setGovBusy(`decision:${runId}:${actionId}`);
    try {
      const r = await fetch(`/api/governance/runs/${runId}/${approve ? "approve" : "deny"}/${actionId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ resource_ref: "*" }),
      });
      const data = await r.json();
      if (!r.ok) { setGovError(data.error ?? `${approve ? "approve" : "deny"} failed (${r.status})`); return; }
      await loadRunDetail(runId);
      loadGovernance();
    } finally { setGovBusy(""); }
  }

  async function connect() {
    const r = await fetch("/api/connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pat, org: "acme-financial" }),
    }).then((x) => x.json());
    if (r.graph) setGraph(r.graph);
  }

  async function runQuery() {
    setTryResult("Running…");
    try {
      const r = await fetch("/api/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ persona, question }),
      });
      const data = await r.json();
      if (!r.ok) {
        setTryResult(`Runtime not connected — showing demo behavior. (${data.error ?? r.status})`);
        return;
      }
      const n = (data.citations ?? []).length;
      setTryResult(n > 0 ? `ALLOWED — ${n} grounded citation(s) returned` : "BLOCKED — fail-closed, zero content returned");
    } catch {
      setTryResult("Runtime not connected — wire QUERY_RUNTIME_URL to run live.");
    }
  }

  if (!signedIn) {
    return (
      <div id="gw">
        <div className="signin">
          <div className="si-card">
            <Mark size={34} />
            <h1>Runtime authorization for enterprise AI</h1>
            <p>Govern which agent sees what, on whose behalf — with tamper-evident proof.</p>
            <button className="gbtn" onClick={() => setSignedIn(true)}>
              <svg width="17" height="17" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.5 12.2c0-.8-.1-1.5-.2-2.2H12v4.3h5.9a5 5 0 0 1-2.2 3.3v2.8h3.6c2.1-2 3.2-4.9 3.2-8.2z" />
                <path fill="#34A853" d="M12 23c2.9 0 5.4-1 7.2-2.6l-3.6-2.8c-1 .7-2.3 1.1-3.6 1.1-2.8 0-5.1-1.9-6-4.4H2.3v2.9A11 11 0 0 0 12 23z" />
                <path fill="#FBBC05" d="M6 14.3a6.6 6.6 0 0 1 0-4.2V7.2H2.3a11 11 0 0 0 0 9.9L6 14.3z" />
                <path fill="#EA4335" d="M12 5.4c1.6 0 3 .5 4.1 1.6l3.1-3.1A11 11 0 0 0 2.3 7.2L6 10.1c.9-2.5 3.2-4.4 6-4.4z" />
              </svg>
              Continue with Google
            </button>
            <div className="si-foot">
              <span className="dot" /> SOC 2 controls in progress · fail-closed by design
            </div>
          </div>
        </div>
      </div>
    );
  }

  const verified = audit?.verify?.verified ?? true;
  const checked = audit?.verify?.entries_checked ?? 0;
  const live = audit?.source === "live";

  return (
    <div id="gw">
      <div className="shell">
        <aside className="side">
          <Mark />
          {VIEWS.map((v) => (
            <button key={v} className={`nav${view === v ? " active" : ""}`} onClick={() => setView(v)}>
              {META[v][0]}
            </button>
          ))}
          <div className="side-foot">
            Tenant <b>acme-financial</b>
            <br />
            Mode <b>ENFORCE · fail-closed</b>
          </div>
        </aside>

        <div>
          <div className="topbar">
            <div>
              <h2>{META[view][0]}</h2>
              <div className="sub">{META[view][1]}</div>
            </div>
            <div className={`pill${live ? "" : " warn"}`}>
              <span className="dot" /> {live ? "Runtime connected · chain verified" : "Demo data · connect runtime for live"}
            </div>
          </div>

          <div className="content">
            {view === "overview" && (
              <div className="view">
                <div className="grid g3" style={{ marginBottom: 16 }}>
                  <div className="card">
                    <div className="label">Queries governed</div>
                    <div className="stat">{audit?.entries.length ?? 0}</div>
                    <p className="dim" style={{ marginTop: 6 }}>recent decisions</p>
                  </div>
                  <div className="card">
                    <div className="label">Blocked / fail-closed</div>
                    <div className="stat r">{audit?.entries.filter((e) => e.acl_decision !== "allowed").length ?? 0}</div>
                    <p className="dim" style={{ marginTop: 6 }}>leakage prevented</p>
                  </div>
                  <div className="card">
                    <div className="label">Chain integrity</div>
                    <div className="stat g">{verified ? "100%" : "FAIL"}</div>
                    <p className="dim" style={{ marginTop: 6 }}>{checked} entries verified</p>
                  </div>
                </div>
                <div className="card" style={{ marginBottom: 16 }}>
                  <p className="kicker">The loop</p>
                  <div className="flow">
                    <div className="flowcol"><div className="hd">Agent</div><div className="node">Claude Desktop<div className="n2">via MCP gateway</div></div></div>
                    <div className="arrowcol">→</div>
                    <div className="flowcol"><div className="hd">Groundwork</div><div className="node" style={{ borderColor: "var(--indigo-deep)" }}>Authorize · Audit · Verify<div className="n2">per-chunk, fail-closed</div></div></div>
                    <div className="arrowcol">→</div>
                    <div className="flowcol"><div className="hd">Enterprise</div><div className="node">GitHub · acme-financial<div className="n2">5 repos · 5 teams</div></div></div>
                  </div>
                </div>
                <div className="card">
                  <p className="kicker">Try it — live enforcement</p>
                  <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
                    <select value={persona} onChange={(e) => setPersona(e.target.value)} style={{ maxWidth: 220 }}>
                      {PERSONAS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                    </select>
                    <input value={question} onChange={(e) => setQuestion(e.target.value)} style={{ flex: 1, minWidth: 220 }} />
                    <button className="btn" onClick={runQuery}>Ask</button>
                  </div>
                  {tryResult && <p className="dim" style={{ marginTop: 12 }}>{tryResult}</p>}
                </div>
              </div>
            )}

            {view === "connect" && (
              <div className="view">
                <p className="lead">Connect a source system</p>
                <p className="dim" style={{ marginBottom: 22 }}>Read-only. Groundwork ingests entitlements + content; it never writes to your systems.</p>
                <div className="card" style={{ marginBottom: 16 }}>
                  <div className="label" style={{ marginBottom: 10 }}>GitHub organization — read-only PAT</div>
                  <div style={{ display: "flex", gap: 10 }}>
                    <input className="mono" placeholder="ghp_…" value={pat} onChange={(e) => setPat(e.target.value)} />
                    <button className="btn" onClick={connect}>Connect GitHub</button>
                  </div>
                  <p className="dim" style={{ marginTop: 10 }}>Scopes: read:org + repository read. We never request write access.</p>
                </div>
                {graph && (
                  <div className="card">
                    <div className="verify" style={{ background: "linear-gradient(92deg,rgba(99,102,241,.12),rgba(45,212,191,.04))", borderColor: "rgba(99,102,241,.3)" }}>
                      <div className="ic" style={{ background: "rgba(99,102,241,.16)", color: "var(--indigo)" }}>✓</div>
                      <div><b>Synced acme-financial</b> &nbsp;<span>{graph.teams.length} teams → groups · {graph.documents.length} repos → documents · {graph.tuples} relationships written to SpiceDB</span></div>
                    </div>
                    <div className="flow">
                      <div className="flowcol"><div className="hd">Teams → Groups</div>{graph.teams.map((t) => <div key={t} className="node">{t}</div>)}</div>
                      <div className="arrowcol">→</div>
                      <div className="flowcol"><div className="hd">Repos → Documents</div>{graph.documents.map((d) => <div key={d} className="node">{d}</div>)}</div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {view === "agent" && (
              <div className="view">
                <p className="lead">Put Groundwork in your agent&apos;s path</p>
                <p className="dim" style={{ marginBottom: 22 }}>Your agent calls Groundwork as its MCP server. Every retrieval is authorized and audited — without changing the agent.</p>
                <div className="grid g2">
                  <div className="card">
                    <div className="label" style={{ marginBottom: 12 }}>1 · Paste into Claude Desktop config</div>
                    <div className="code">
                      <button className="cp" onClick={() => { navigator.clipboard?.writeText(MCP_CONFIG); setCopied(true); setTimeout(() => setCopied(false), 1500); }}>{copied ? "Copied ✓" : "Copy"}</button>
                      {MCP_CONFIG}
                    </div>
                  </div>
                  <div className="card">
                    <div className="label" style={{ marginBottom: 12 }}>2 · How identity is proven</div>
                    <ol className="steps">
                      <li><b>Agent</b> = the API key Groundwork issued. A credential, never self-reported.</li>
                      <li><b>User</b> = a short-lived JWT signed by your IdP at SSO login.</li>
                      <li><b>Never</b> trusted: anything in the request body.</li>
                      <li>Both are bound into every audit entry, tamper-evidently.</li>
                    </ol>
                  </div>
                </div>
              </div>
            )}

            {view === "agents" && (
              <div className="view">
                <p className="lead">Agent Registry</p>
                <p className="dim" style={{ marginBottom: 18 }}>
                  Every agent is a tenant-scoped identity with an accountable owner, lifecycle state,
                  version history, and a tamper-evident chain of events. {agentsSource === "live" ? "Live registry." : "Demo registry — connect the runtime for live control."}
                </p>

                <div className="grid g3" style={{ marginBottom: 20 }}>
                  <div className="card"><div className="label">Agents</div><div className="stat">{agents.length}</div></div>
                  <div className="card"><div className="label">Active</div><div className="stat g">{agents.filter((a) => a.lifecycle_state === "active").length}</div></div>
                  <div className="card"><div className="label">Revoked / retired</div><div className="stat r">{agents.filter((a) => a.lifecycle_state === "revoked" || a.lifecycle_state === "retired").length}</div></div>
                </div>

                <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 18 }}>
                  <button className="btn" onClick={() => setCreateOpen((o) => !o)}>{createOpen ? "Cancel" : "+ Register agent"}</button>
                  {agentsError && <span style={{ color: "var(--red)", fontSize: 12.5 }}>{agentsError}</span>}
                </div>

                {createOpen && (
                  <div className="card" style={{ marginBottom: 18 }}>
                    <p className="kicker">Register a new agent — always lands in <b>draft</b>, never auto-activates</p>
                    <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                      <input placeholder="Name (unique per tenant)" value={newAgent.name} onChange={(e) => setNewAgent((n) => ({ ...n, name: e.target.value }))} style={{ flex: 2, minWidth: 220 }} />
                      <select value={newAgent.risk_tier} onChange={(e) => setNewAgent((n) => ({ ...n, risk_tier: e.target.value }))} style={{ flex: 1, minWidth: 130 }}>
                        {RISK_TIERS.map((t) => <option key={t} value={t}>{t}</option>)}
                      </select>
                      <select value={newAgent.environment} onChange={(e) => setNewAgent((n) => ({ ...n, environment: e.target.value }))} style={{ flex: 1, minWidth: 140 }}>
                        {ENVIRONMENTS.map((e) => <option key={e} value={e}>{e}</option>)}
                      </select>
                      <button className="btn" disabled={!newAgent.name.trim() || actionBusy !== ""} onClick={createAgent}>Create</button>
                    </div>
                  </div>
                )}

                {agents.map((a) => {
                  const isOpen = !!detail[a.id];
                  const d = detail[a.id] ?? null;
                  const busy = actionBusy.startsWith(a.id);
                  return (
                    <div key={a.id}>
                      <button
                        className={`row${isOpen ? " open" : ""}`}
                        onClick={() => (isOpen ? setDetail((prev) => ({ ...prev, [a.id]: null })) : loadAgentDetail(a.id))}
                      >
                        <span className={`badge ${stateBadge(a.lifecycle_state)}`}>{a.lifecycle_state.toUpperCase()}</span>
                        <div>
                          <div className="who">{a.name}</div>
                          <div className="meta">
                            <b>{a.risk_tier} risk</b> · {a.environment}
                            {a.active_version ? <> · <span style={{ color: "var(--green)" }}>v{a.active_version}</span></> : null}
                            {a.version_count > 0 ? <> · {a.version_count} version{a.version_count > 1 ? "s" : ""}</> : null}
                          </div>
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                          <div className="t">owner {a.owner_principal_id}<br />{new Date(a.created_at).toLocaleDateString()}</div>
                          <span className="chev">›</span>
                        </div>
                      </button>

                      {isOpen && d && (
                        <div className="decisions">
                          {d.agent.description && <div className="dec"><span className="doc">Purpose</span><span className="rsn">{d.agent.business_purpose ?? d.agent.description}</span></div>}
                          {d.source === "live" && d.agent.activated_at && <div className="dec"><span className="doc">Activated</span><span className="rsn">{new Date(d.agent.activated_at).toLocaleString()}</span></div>}
                          {d.agent.revoked_at && <div className="dec"><span className="doc">Revoked</span><span className="rsn">{new Date(d.agent.revoked_at).toLocaleString()}</span></div>}

                          {d.versions.length > 0 && (
                            <>
                              <div className="label" style={{ margin: "10px 0 6px" }}>Versions</div>
                              {d.versions.map((v) => (
                                <div className="dec" key={v.id}>
                                  <span className={`badge ${v.status === "active" ? "allow" : v.status === "revoked" ? "deny" : v.status === "superseded" ? "medium" : "low"}`}>{v.status}</span>
                                  <span className="doc">v{v.version}</span>
                                  <span className="rsn">{v.model_provider ? `${v.model_provider}${v.model_name ? "/" + v.model_name : ""}` : "—"} · {new Date(v.created_at).toLocaleDateString()}</span>
                                </div>
                              ))}
                            </>
                          )}

                          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", margin: "12px 0" }}>
                            {a.lifecycle_state === "draft" || a.lifecycle_state === "suspended" || a.lifecycle_state === "pending_approval" ? (
                              <button className="btn" disabled={busy} onClick={(e) => { e.stopPropagation(); agentAction(a.id, "activate", "console activation"); }}>Activate</button>
                            ) : null}
                            {a.lifecycle_state === "active" ? (
                              <button className="btn ghost" disabled={busy} onClick={(e) => { e.stopPropagation(); agentAction(a.id, "suspend", "console suspension"); }}>Suspend</button>
                            ) : null}
                            {a.lifecycle_state !== "revoked" && a.lifecycle_state !== "retired" ? (
                              <>
                                <button className="btn ghost" disabled={busy} onClick={(e) => { e.stopPropagation(); agentAction(a.id, "retire", "console retirement"); }}>Retire</button>
                                <button className="btn" style={{ background: "linear-gradient(92deg,#e11d48,#fb7185)" }} disabled={busy} onClick={(e) => { e.stopPropagation(); if (window.confirm(`Irreversibly revoke ${a.name} and all its versions?`)) agentAction(a.id, "revoke", "console revocation"); }}>Revoke</button>
                              </>
                            ) : null}
                            {a.lifecycle_state !== "revoked" && a.lifecycle_state !== "retired" ? (
                              <div style={{ display: "flex", gap: 8, marginLeft: "auto", alignItems: "center" }}>
                                <input className="mono" placeholder="version (e.g. 3.0.0)" value={versionInputs[a.id] ?? ""} onChange={(e) => setVersionInputs((prev) => ({ ...prev, [a.id]: e.target.value }))} style={{ width: 180 }} />
                                <button className="btn ghost" disabled={busy || !(versionInputs[a.id] ?? "").trim()} onClick={(e) => { e.stopPropagation(); agentAction(a.id, "versions"); }}>+ Version</button>
                              </div>
                            ) : null}
                          </div>

                          <div className="label" style={{ margin: "10px 0 6px" }}>Lifecycle events — hash-chained, write-once</div>
                          {d.lifecycle_events.map((ev, i) => (
                            <div className="dec" key={ev.id} style={{ alignItems: "flex-start" }}>
                              <span style={{ color: "var(--faint)", width: 22, flex: "none", textAlign: "right" }}>#{i + 1}</span>
                              <span className="doc" style={{ flex: "none", width: 170 }}>{ev.event_type}</span>
                              <span className="rsn" style={{ marginLeft: 0, marginRight: "auto", textAlign: "right" }}>
                                <span style={{ color: "var(--muted)" }}>{ev.previous_state || "—"} → {ev.new_state}</span>
                                {ev.reason ? <> · {ev.reason}</> : null}
                                <br />
                                <span style={{ fontSize: 10.5 }}>{ev.actor_principal_id} · {new Date(ev.created_at).toLocaleString()} · <span className="mono">{ev.immutable_digest}</span></span>
                              </span>
                            </div>
                          ))}
                          {d.lifecycle_events.length === 0 && <div className="dec"><span className="rsn">no lifecycle events recorded</span></div>}
                        </div>
                      )}
                    </div>
                  );
                })}
                {agents.length === 0 && <div className="card"><p className="dim">No agents registered yet.</p></div>}
              </div>
            )}

            {view === "governance" && (
              <div className="view">
                <p className="lead">Delegated Authority</p>
                <p className="dim" style={{ marginBottom: 18 }}>
                  Registered tools, agent grants, server-generated runs, and one-time human approvals —
                  every decision hash-chained into evidence.{" "}
                  {govToolsSource === "live" || govRunsSource === "live"
                    ? "Live governance."
                    : "Demo data — connect the runtime for live control (mutations require it)."}
                </p>

                <div className="grid g3" style={{ marginBottom: 20 }}>
                  <div className="card"><div className="label">Tools</div><div className="stat">{govTools.length}</div></div>
                  <div className="card"><div className="label">Active grants</div><div className="stat g">{govGrants.filter((gr) => !gr.revoked_at).length}</div></div>
                  <div className="card"><div className="label">Runs · pending approval</div><div className="stat a">{govRuns.filter((r) => r.status === "pending").length}</div></div>
                </div>

                {govError && <div className="card" style={{ marginBottom: 16, borderColor: "var(--red)", color: "var(--red)", fontSize: 12.5 }}>{govError}</div>}

                <div className="card" style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
                    <p className="kicker" style={{ margin: 0 }}>Tools</p>
                    <button className="btn" style={{ marginLeft: "auto" }} onClick={() => setRegisterOpen((o) => !o)} disabled={govBusy !== ""}>
                      {govBusy === "register-tool" ? "Registering…" : "+ Register tool"}
                    </button>
                  </div>
                  {registerOpen && (
                    <div className="card" style={{ marginBottom: 14 }}>
                      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                        <input placeholder="Name (unique per tenant)" value={newTool.name} onChange={(e) => setNewTool((n) => ({ ...n, name: e.target.value }))} style={{ flex: 2, minWidth: 180 }} />
                        <input placeholder="Description" value={newTool.description} onChange={(e) => setNewTool((n) => ({ ...n, description: e.target.value }))} style={{ flex: 3, minWidth: 220 }} />
                        <select value={newTool.transport} onChange={(e) => setNewTool((n) => ({ ...n, transport: e.target.value }))} style={{ flex: 1, minWidth: 110 }}>
                          {["builtin", "http", "mcp"].map((t) => <option key={t} value={t}>{t}</option>)}
                        </select>
                        <input placeholder="principal:alice" value={newTool.owner_principal_id} onChange={(e) => setNewTool((n) => ({ ...n, owner_principal_id: e.target.value }))} style={{ flex: 1, minWidth: 140 }} />
                        <input placeholder="us-east-1" value={newTool.region} onChange={(e) => setNewTool((n) => ({ ...n, region: e.target.value }))} style={{ flex: 1, minWidth: 110 }} />
                        <button className="btn" disabled={!newTool.name.trim() || govBusy !== ""} onClick={govRegisterTool}>Register</button>
                      </div>
                    </div>
                  )}
                  {govTools.map((t) => {
                    const isOpen = !!open[`gt:${t.id}`];
                    const d = govToolDetail[t.id] ?? null;
                    const busy = govBusy.startsWith(`tool:${t.id}`);
                    return (
                      <div key={t.id}>
                        <button className={`row${isOpen ? " open" : ""}`} onClick={() => (isOpen ? setOpen((o) => ({ ...o, [`gt:${t.id}`]: false })) : loadToolDetail(t.id))}>
                          <span className={`badge ${stateBadge(t.lifecycle)}`}>{t.lifecycle.toUpperCase()}</span>
                          <div>
                            <div className="who">{t.name}</div>
                            <div className="meta"><b>{t.transport}</b>{t.endpoint_or_server ? ` · ${t.endpoint_or_server}` : ""} · owner {t.owner_principal_id}</div>
                          </div>
                          <div className="t">{t.region}<br />{new Date(t.created_at).toLocaleDateString()}</div>
                          <span className="chev">›</span>
                        </button>
                        {isOpen && d && (
                          <div className="decisions">
                            {d.tool.description && <div className="dec"><span className="doc">Purpose</span><span className="rsn">{d.tool.description}</span></div>}
                            <div className="label" style={{ margin: "10px 0 6px" }}>Actions</div>
                            {(() => {
                              const actions: ToolAction[] = d.actions ?? [];
                              return actions.length > 0 ? (
                                actions.map((a) => (
                                  <div className="dec" key={a.id}>
                                    <span className={`badge ${a.requires_human_approval ? "medium" : a.read_only ? "allow" : "medium"}`}>{a.status}</span>
                                    <span className="doc">{a.action}</span>
                                    <span className="rsn">{a.resource_type} · {a.risk_level} risk{a.read_only ? " · read-only" : ""}{a.requires_human_approval ? " · needs approval" : ""}</span>
                                  </div>
                                ))
                              ) : (
                                <div className="dec"><span className="rsn">no actions registered yet</span></div>
                              );
                            })()}
                            {d.tool.lifecycle !== "active" ? (
                              <button className="btn" disabled={busy} onClick={() => govToolLifecycle(t.id, "activate")}>Activate</button>
                            ) : (
                              <>
                                <button className="btn ghost" disabled={busy} onClick={() => govToolLifecycle(t.id, "suspend")}>Suspend</button>
                                <button className="btn" style={{ background: "linear-gradient(92deg,#e11d48,#fb7185)" }} disabled={busy} onClick={() => { if (window.confirm(`Retire ${t.name}?`)) govToolLifecycle(t.id, "retire"); }}>Retire</button>
                              </>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                  {govTools.length === 0 && <p className="dim">No tools registered yet.</p>}
                </div>

                <div className="card" style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12, flexWrap: "wrap" }}>
                    <p className="kicker" style={{ margin: 0 }}>Grants — tool access for one agent version</p>
                    <select value={govGrantsAgent} onChange={(e) => loadGrants(e.target.value)} style={{ marginLeft: "auto", maxWidth: 240 }}>
                      {agents.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
                    </select>
                  </div>
                  {govGrants.map((gr) => (
                    <div className="dec" key={gr.id}>
                      <span className={`badge ${gr.revoked_at ? "deny" : "allow"}`}>{gr.revoked_at ? "REVOKED" : "ACTIVE"}</span>
                      <span className="doc" style={{ flex: "none" }}>{gr.tool_id}</span>
                      <span className="rsn">{gr.resource_scope} · {gr.region_constraint} · {gr.call_limit_per_run}/run{gr.requires_approval ? " · approval" : ""}</span>
                      {!gr.revoked_at && (
                        <button className="btn ghost" style={{ marginLeft: "auto", flex: "none" }} disabled={govBusy !== ""} onClick={() => { if (window.confirm("Revoke this grant?")) govRevokeGrant(gr.id); }}>Revoke</button>
                      )}
                    </div>
                  ))}
                  {govGrants.length === 0 && <p className="dim">No grants for this agent.</p>}

                  <div className="label" style={{ margin: "16px 0 8px" }}>New grant</div>
                  <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                    <select value={grantForm.agent_id} onChange={(e) => setGrantForm((f) => ({ ...f, agent_id: e.target.value }))} style={{ minWidth: 160 }}>
                      <option value="">agent…</option>
                      {agents.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
                    </select>
                    <input className="mono" placeholder="version id (e.g. agv_…)" value={grantForm.version_id} onChange={(e) => setGrantForm((f) => ({ ...f, version_id: e.target.value }))} style={{ width: 170 }} />
                    <select value={grantForm.tool_id} onChange={(e) => { setGrantForm((f) => ({ ...f, tool_id: e.target.value, action_id: "" })); if (e.target.value) loadToolDetail(e.target.value); }} style={{ minWidth: 160 }}>
                      <option value="">tool…</option>
                      {govTools.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                    </select>
                    <select value={grantForm.action_id} onChange={(e) => setGrantForm((f) => ({ ...f, action_id: e.target.value }))} style={{ minWidth: 140 }}>
                      <option value="">action…</option>
                      {(() => {
                        const d = govToolDetail[grantForm.tool_id];
                        return d ? d.actions.map((a) => <option key={a.id} value={a.id}>{a.action}</option>) : null;
                      })()}
                    </select>
                    <input className="mono" placeholder="resource_scope (e.g. doc://policies/*)" value={grantForm.resource_scope} onChange={(e) => setGrantForm((f) => ({ ...f, resource_scope: e.target.value }))} style={{ flex: 1, minWidth: 180 }} />
                    <input placeholder="region" value={grantForm.region_constraint} onChange={(e) => setGrantForm((f) => ({ ...f, region_constraint: e.target.value }))} style={{ width: 110 }} />
                    <input type="number" placeholder="calls/run" value={grantForm.call_limit_per_run} onChange={(e) => setGrantForm((f) => ({ ...f, call_limit_per_run: Number(e.target.value) }))} style={{ width: 100 }} />
                    <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12.5 }}>
                      <input type="checkbox" checked={grantForm.requires_approval} onChange={(e) => setGrantForm((f) => ({ ...f, requires_approval: e.target.checked }))} />
                      approval
                    </label>
                    <button className="btn" disabled={govBusy !== ""} onClick={govGrant}>Grant</button>
                  </div>
                </div>

                <div className="card" style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
                    <p className="kicker" style={{ margin: 0 }}>Mint delegation — short-lived, single-delivery token</p>
                    <button className="btn ghost" style={{ marginLeft: "auto" }} onClick={() => setMintOpen((o) => !o)}>{mintOpen ? "Hide" : "Mint"}</button>
                  </div>
                  {mintOpen && (
                    <>
                      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                        <select value={mintForm.agent_id} onChange={(e) => setMintForm((f) => ({ ...f, agent_id: e.target.value }))} style={{ minWidth: 180 }}>
                          <option value="">agent…</option>
                          {agents.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
                        </select>
                        <input placeholder="subject_principal_id" value={mintForm.subject_principal_id} onChange={(e) => setMintForm((f) => ({ ...f, subject_principal_id: e.target.value }))} style={{ flex: 1, minWidth: 160 }} />
                        <input placeholder="purpose" value={mintForm.purpose} onChange={(e) => setMintForm((f) => ({ ...f, purpose: e.target.value }))} style={{ flex: 2, minWidth: 200 }} />
                        <input className="mono" placeholder="permitted actions (comma)" value={mintForm.permitted_actions} onChange={(e) => setMintForm((f) => ({ ...f, permitted_actions: e.target.value }))} style={{ flex: 2, minWidth: 180 }} />
                        <input type="number" placeholder="ttl seconds" value={mintForm.ttl_seconds} onChange={(e) => setMintForm((f) => ({ ...f, ttl_seconds: Number(e.target.value) }))} style={{ width: 110 }} />
                        <button className="btn" disabled={govBusy !== "" || !mintForm.agent_id || !mintForm.purpose.trim()} onClick={() => govMintDelegation({
                          agent_id: mintForm.agent_id,
                          subject_principal_id: mintForm.subject_principal_id,
                          purpose: mintForm.purpose,
                          permitted_actions: mintForm.permitted_actions.split(",").map((s) => s.trim()).filter(Boolean),
                          ttl_seconds: mintForm.ttl_seconds,
                        })}>{govBusy === "mint" ? "Minting…" : "Mint"}</button>
                      </div>
                      {govMint && (
                        <div className="card" style={{ marginTop: 12, borderColor: govMint.error ? "var(--red)" : "var(--green)" }}>
                          {govMint.error ? (
                            <p style={{ color: "var(--red)", fontSize: 12.5 }}>{govMint.error} — minting requires the live runtime and a verified identity.</p>
                          ) : (
                            <>
                              <p className="dim" style={{ marginBottom: 8 }}>
                                {govMint.already ? "Idempotent replay — the raw token was already delivered once and is single-delivery." : "Token delivered exactly once — copy it now; it is never stored server-side."}
                              </p>
                              {(() => {
                                const tok = govMint.token;
                                return tok ? (
                                  <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10 }}>
                                    <code className="code" style={{ flex: 1 }}>{tok.slice(0, 90)}…</code>
                                    <button className="btn ghost" onClick={() => { navigator.clipboard.writeText(tok); setTokenCopied(true); }}>{tokenCopied ? "Copied" : "Copy"}</button>
                                  </div>
                                ) : null;
                              })()}
                              {govMint.grant && (
                                <p className="dim" style={{ fontSize: 12 }}>
                                  grant {govMint.grant.id} · subject <b>{govMint.grant.subject_principal_id}</b> · region {govMint.grant.region} · expires {new Date(govMint.grant.expires_at).toLocaleString()} · <span className="mono">{govMint.grant.token_jti}</span>
                                </p>
                              )}
                            </>
                          )}
                        </div>
                      )}
                    </>
                  )}
                </div>

                <div className="card">
                  <p className="kicker" style={{ marginBottom: 12 }}>Runs — server-generated, bound to one delegation</p>
                  {govRuns.map((r) => {
                    const isOpen = !!open[`gr:${r.id}`];
                    const d = govRunDetail[r.id] ?? null;
                    const busy = govBusy.startsWith(`decision:${r.id}`);
                    return (
                      <div key={r.id}>
                        <button className={`row${isOpen ? " open" : ""}`} onClick={() => (isOpen ? setOpen((o) => ({ ...o, [`gr:${r.id}`]: false })) : loadRunDetail(r.id))}>
                          <span className={`badge ${runBadge(r.status)}`}>{r.status.toUpperCase()}</span>
                          <div>
                            <div className="who">{r.purpose}</div>
                            <div className="meta">agent {r.agent_id} · as <b>{r.user_id}</b>{r.trace_id ? ` · ${r.trace_id}` : ""}</div>
                          </div>
                          <div className="t">{r.region}<br />{new Date(r.started_at).toLocaleTimeString()}</div>
                          <span className="chev">›</span>
                        </button>
                        {isOpen && d && (
                          <div className="decisions">
                            {(() => {
                              const decs: ActionDecision[] = d.decisions ?? [];
                              return decs.length > 0 ? (
                                decs.map((x) => (
                                  <div className="dec" key={x.id} style={{ alignItems: "flex-start" }}>
                                    <span className={`badge ${decisionBadge(x.decision)}`}>{x.decision.toUpperCase()}</span>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                      <div className="rsn" style={{ margin: 0 }}>{x.resource_ref} · {x.reason}</div>
                                      <div style={{ fontSize: 10.5, color: "var(--muted)", marginTop: 4 }} className="mono">{x.immutable_digest} · policy {x.policy_version}</div>
                                    </div>
                                    {x.decision === "approval_required" && (
                                      <div style={{ display: "flex", gap: 8, flex: "none" }}>
                                        <button className="btn" disabled={busy} onClick={() => govDecision(r.id, x.action_id ?? "", true)}>Approve</button>
                                        <button className="btn ghost" disabled={busy} onClick={() => govDecision(r.id, x.action_id ?? "", false)}>Deny</button>
                                      </div>
                                    )}
                                  </div>
                                ))
                              ) : (
                                <div className="dec"><span className="rsn">no decisions recorded for this run</span></div>
                              );
                            })()}
                          </div>
                        )}
                      </div>
                    );
                  })}
                  {govRuns.length === 0 && <p className="dim">No runs yet — runs are created when an agent presents a delegation token.</p>}
                </div>
              </div>
            )}

            {view === "trust" && (
              <div className="view">
                <p className="lead">Multi-Agent Trust</p>
                <p className="dim" style={{ marginBottom: 18 }}>
                  Explicit trust edges between agents, onboarded external (partner/customer) agents, customer
                  consent, cross-region transfer policies, external budgets, and delegation-chain provenance.{" "}
                  {trustSource === "live" || extAgentSource === "live" || consentSource === "live"
                    ? "Live trust graph."
                    : "Demo data — connect the runtime for live control (mutations require it)."}
                </p>

                <div className="grid g3" style={{ marginBottom: 20 }}>
                  <div className="card"><div className="label">Trust edges</div><div className="stat">{trustRels.length}</div></div>
                  <div className="card"><div className="label">External agents</div><div className="stat g">{extAgents.filter((a) => a.lifecycle_state === "active").length}</div></div>
                  <div className="card"><div className="label">Active consents</div><div className="stat a">{consents.filter((c) => c.status === "active").length}</div></div>
                </div>

                {trustError && <div className="card" style={{ marginBottom: 16, borderColor: "var(--red)", color: "var(--red)", fontSize: 12.5 }}>{trustError}</div>}

                <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 16 }}>
                  <input value={relReason} onChange={(e) => setRelReason(e.target.value)} placeholder="Reason for lifecycle actions" style={{ flex: 1, minWidth: 220 }} />
                  <button className="btn" onClick={loadTrust} disabled={trustBusy !== ""}>Refresh</button>
                </div>

                {/* Trust relationships */}
                <div className="card" style={{ marginBottom: 16 }}>
                  <p className="kicker" style={{ margin: 0, marginBottom: 10 }}>Trust relationships</p>
                  {trustRels.length === 0 && <p className="dim">No trust edges yet.</p>}
                  {trustRels.map((rel) => {
                    const target = rel.external_agent_id ?? rel.child_agent_id ?? "?";
                    return (
                      <div key={rel.id} className="card" style={{ marginBottom: 10 }}>
                        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                          <span className={`badge ${rel.status === "active" ? "allow" : rel.status === "revoked" ? "deny" : "medium"}`}>{rel.status.toUpperCase()}</span>
                          <div style={{ flex: 1 }}>
                            <div className="who">{rel.parent_agent_id} → {target}</div>
                            <div className="dec"><span className="rsn">domain {rel.trust_domain} · {rel.purpose} · depth {rel.max_delegation_depth} · {rel.region} · expires {rel.expires_at?.slice(0, 10)}</span></div>
                          </div>
                          <div style={{ display: "flex", gap: 6 }}>
                            {rel.status === "requested" && <button className="btn" disabled={trustBusy !== ""} onClick={() => trustAction(rel.id, "approve")}>Approve</button>}
                            {rel.status === "approved" && <button className="btn" disabled={trustBusy !== ""} onClick={() => trustAction(rel.id, "activate")}>Activate</button>}
                            {rel.status === "active" && <button className="btn" disabled={trustBusy !== ""} onClick={() => trustAction(rel.id, "suspend")}>Suspend</button>}
                            {rel.status === "suspended" && <button className="btn" disabled={trustBusy !== ""} onClick={() => trustAction(rel.id, "resume")}>Resume</button>}
                            {rel.status !== "revoked" && (
                              <button className="btn" style={{ borderColor: "var(--red)", color: "var(--red)" }} disabled={trustBusy !== ""} onClick={() => trustAction(rel.id, "revoke")}>Revoke</button>
                            )}
                          </div>
                        </div>
                        <div className="dec" style={{ marginTop: 6 }}><span className="rsn">digest {rel.immutable_digest}</span></div>
                      </div>
                    );
                  })}
                </div>

                {/* External agents */}
                <div className="card" style={{ marginBottom: 16 }}>
                  <p className="kicker" style={{ margin: 0, marginBottom: 10 }}>External agents</p>
                  {extAgents.length === 0 && <p className="dim">No external agents onboarded.</p>}
                  {extAgents.map((a) => (
                    <div key={a.id} className="card" style={{ marginBottom: 10 }}>
                        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                          <span className={`badge ${a.lifecycle_state === "active" ? "allow" : a.lifecycle_state === "revoked" ? "deny" : "medium"}`}>{a.lifecycle_state.toUpperCase()}</span>
                          <div style={{ flex: 1 }}>
                            <div className="who">{a.external_agent_id}</div>
                            <div className="dec">
                              <span className="rsn">
                                org {a.organization_id} · {a.trust_tier} tier · {a.auth_method} · paired {a.agent_id} · {a.region} · issuer {a.verified_issuer}
                              </span>
                            </div>
                          </div>
                          <div style={{ display: "flex", gap: 6 }}>
                            {a.lifecycle_state === "pending" || a.lifecycle_state === "suspended"
                              ? <button className="btn" disabled={trustBusy !== ""} onClick={() => extAgentAction(a.external_agent_id, "activate")}>Activate</button>
                              : null}
                            {a.lifecycle_state === "active" && <button className="btn" disabled={trustBusy !== ""} onClick={() => extAgentAction(a.external_agent_id, "suspend")}>Suspend</button>}
                            {a.lifecycle_state !== "revoked" && (
                              <button className="btn" style={{ borderColor: "var(--red)", color: "var(--red)" }} disabled={trustBusy !== ""} onClick={() => extAgentAction(a.external_agent_id, "revoke")}>Revoke</button>
                            )}
                          </div>
                        </div>
                      </div>
                  ))}
                </div>

                {/* Consents */}
                <div className="card" style={{ marginBottom: 16 }}>
                  <p className="kicker" style={{ margin: 0, marginBottom: 10 }}>Customer consent</p>
                  {consents.length === 0 && <p className="dim">No consent records.</p>}
                  {consents.map((c) => (
                    <div key={c.id} className="card" style={{ marginBottom: 10 }}>
                      <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                        <span className={`badge ${c.status === "active" ? "allow" : "deny"}`}>{c.status.toUpperCase()}</span>
                        <div style={{ flex: 1 }}>
                          <div className="who">{c.customer_principal_id}</div>
                          <div className="dec">
                            <span className="rsn">
                              {c.external_agent_id} · {c.organization_id} · purpose {c.purpose} · scope {c.resource_ref_pattern} · expires {c.expires_at?.slice(0, 10)}
                            </span>
                          </div>
                        </div>
                        {c.status === "active" && (
                          <button className="btn" style={{ borderColor: "var(--red)", color: "var(--red)" }} disabled={trustBusy !== ""} onClick={() => revokeConsent(c.id)}>Revoke</button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Transfer policies */}
                <div className="card" style={{ marginBottom: 16 }}>
                  <p className="kicker" style={{ margin: 0, marginBottom: 10 }}>Cross-region transfer policies</p>
                  {transferPolicies.length === 0 && <p className="dim">No transfer policies — cross-region delegation is denied by default.</p>}
                  {transferPolicies.map((p) => (
                    <div key={p.id} className="card" style={{ marginBottom: 10 }}>
                      <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                        <span className={`badge ${p.enabled ? "allow" : "medium"}`}>{p.enabled ? "ENABLED" : "DISABLED"}</span>
                        <div style={{ flex: 1 }}>
                          <div className="who">{p.source_region} → {p.target_region}</div>
                          <div className="dec"><span className="rsn">purpose {p.purpose_pattern} · created by {p.created_by}</span></div>
                        </div>
                        <div style={{ display: "flex", gap: 6 }}>
                          {p.enabled
                            ? <button className="btn" disabled={trustBusy !== ""} onClick={() => transferPolicyAction(p.id, "suspend")}>Suspend</button>
                            : <button className="btn" disabled={trustBusy !== ""} onClick={() => transferPolicyAction(p.id, "activate")}>Enable</button>}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                {/* External budgets */}
                <div className="card" style={{ marginBottom: 16 }}>
                  <p className="kicker" style={{ margin: 0, marginBottom: 10 }}>External budgets</p>
                  {extBudgets.length === 0 && <p className="dim">No external budgets configured.</p>}
                  {extBudgets.map((b) => (
                    <div key={b.id} className="card" style={{ marginBottom: 10 }}>
                      <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                        <span className="badge medium">{b.scope_type.toUpperCase()}</span>
                        <div style={{ flex: 1 }}>
                          <div className="who">{b.external_agent_id ?? b.organization_id ?? b.customer_principal_id}</div>
                          <div className="dec">
                            <span className="rsn">
                              max {b.max_total_actions} actions · {b.max_actions_per_run}/run · {b.max_denied_per_run} denied/run · used {b.actions_count}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Delegation chains + provenance */}
                <div className="grid g2">
                  <div className="card">
                    <p className="kicker" style={{ margin: 0, marginBottom: 10 }}>Delegation chains</p>
                    {delegations.length === 0 && <p className="dim">No delegation grants.</p>}
                    {delegations.map((g) => (
                      <div key={g.id} className="card" style={{ marginBottom: 8 }}>
                        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                          <div style={{ flex: 1 }}>
                            <div className="who">{g.id}{g.is_agent_delegation ? " (child)" : ""}</div>
                            <div className="dec"><span className="rsn">agent {g.agent_id} · {g.purpose} · depth {g.delegation_depth ?? 0} · {g.region}</span></div>
                          </div>
                          <button className="btn" disabled={trustBusy !== ""} onClick={() => loadChain(g.id)}>Chain</button>
                        </div>
                      </div>
                    ))}
                    {delegationChain && (
                      <div className="card" style={{ marginTop: 10, borderColor: "var(--green)" }}>
                        <p className="kicker" style={{ margin: 0, marginBottom: 8 }}>Chain · {chainFor} · {delegationChain.verified ? "VERIFIED" : "BROKEN"}</p>
                        {delegationChain.nodes.map((n, i) => (
                          <div key={i} className="dec" style={{ marginBottom: 4 }}>
                            <span className="rsn">
                              [{i}] {n.grant.id}{i < delegationChain.nodes.length - 1 ? " ↓" : ""} — {n.delegator_agent_id ?? "root"} → {n.delegatee_agent_id ?? "self"} · {n.verified ? "verified" : `BROKEN: ${n.problem}`}
                            </span>
                          </div>
                        ))}
                        {!delegationChain.verified && delegationChain.problem && (
                          <div className="dec" style={{ color: "var(--red)" }}>{delegationChain.problem}</div>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="card">
                    <p className="kicker" style={{ margin: 0, marginBottom: 10 }}>Evidence provenance</p>
                    <p className="dim" style={{ fontSize: 12 }}>Enter an evidence event id (e.g. ev_demo_2) to resolve who delegated, what scope was inherited, and the final outcome.</p>
                    <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
                      <input placeholder="evidence event id" value={provFor} onChange={(e) => setProvFor(e.target.value)} style={{ flex: 1 }} />
                      <button className="btn" disabled={!provFor.trim()} onClick={() => loadProvenance(provFor.trim())}>Resolve</button>
                    </div>
                    {provenance && (
                      <div className="card" style={{ borderColor: "var(--green)" }}>
                        <div className="who">{provenance.event_id}</div>
                        <div className="dec">
                          <span className="rsn">
                            {provenance.kind} · {provenance.final_decision ?? "n/a"} · chain {provenance.chain_verification ?? "unchecked"} · subject {provenance.subject_principal_id ?? "—"} · tool {provenance.tool_name ?? "—"} · region {provenance.region ?? "—"}
                          </span>
                        </div>
                        <div className="dec"><span className="rsn">root {provenance.root_grant_id ?? "—"} · digest {provenance.immutable_digest}</span></div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {view === "controls" && (
              <div className="view">
                <p className="lead">Incident Response</p>
                <p className="dim" style={{ marginBottom: 18 }}>
                  Kill-switches, delegation revocation, run termination, transactional budgets, tamper-evident
                  evidence, chain verification, regulatory evidence exports, and the webhook outbox.{" "}
                  {controlsSource === "live" || evidenceSource === "live" || outboxSource === "live" || exportSource === "live"
                    ? "Live governance."
                    : "Demo data — connect the runtime for live control (mutations require it)."}
                </p>

                <div className="grid g3" style={{ marginBottom: 20 }}>
                  <div className="card"><div className="label">Emergency controls</div><div className="stat">{controls.filter((c) => c.control_state === "kill_switched").length} <span style={{ fontSize: 12, color: "var(--dim)" }}>kill-switched</span></div></div>
                  <div className="card"><div className="label">Evidence events</div><div className="stat">{evidence.length}</div></div>
                  <div className="card"><div className="label">Outbox · pending</div><div className="stat a">{outbox.filter((e) => e.status === "pending").length}</div></div>
                </div>

                {p3Error && <div className="card" style={{ marginBottom: 16, borderColor: "var(--red)", color: "var(--red)", fontSize: 12.5 }}>{p3Error}</div>}

                <div className="card" style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 10 }}>
                    <p className="kicker" style={{ margin: 0 }}>Emergency Controls</p>
                    <span className="badge medium" style={{ marginLeft: "auto" }}>MUTATIONS REQUIRE LIVE RUNTIME</span>
                  </div>
                  <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 12 }}>
                    <label className="dim" style={{ fontSize: 12 }}>Reason</label>
                    <input value={controlReason} onChange={(e) => setControlReason(e.target.value)} placeholder="incident reason (recorded in evidence)" style={{ flex: 1, minWidth: 200 }} />
                  </div>
                  {controls.length === 0 && <p className="dim">No emergency controls recorded.</p>}
                  {controls.map((c) => {
                    const isAgent = c.entity_type === "agent";
                    const isGrant = c.entity_type === "delegation";
                    const isRun = c.entity_type === "run";
                    const targetPath = isAgent ? "agents" : isGrant ? "delegations" : isRun ? "runs" : "tools";
                    const busy = p3Busy === `resume:${c.entity_id}`;
                    const stateLabel = c.control_state.replace(/_/g, " ");
                    return (
                      <div className="row" key={c.id}>
                        <span className={`badge ${c.control_state === "active" ? "allow" : "medium"}`}>{stateLabel.toUpperCase()}</span>
                        <div style={{ flex: 1 }}>
                          <div className="who">{stateLabel} · {c.entity_type} <span className="mono">{c.entity_id.slice(0, 24)}</span></div>
                          <div className="meta">triggered by <b>{c.actor_principal_id}</b> · {c.reason}</div>
                        </div>
                        <div className="t">{new Date(c.created_at).toLocaleDateString()}<br /><span className="dim">{c.created_at.slice(11, 19)}</span></div>
                        {c.control_state === "kill_switched" && (
                          <button className="btn" disabled={busy || p3Busy !== ""} onClick={() => govControl(targetPath, c.entity_id, "resume")}>
                            {busy ? "…" : "Resume"}
                          </button>
                        )}
                      </div>
                    );
                  })}
                  {controls.length > 0 && (
                    <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 12 }}>
                      {controls.filter((c) => c.entity_type === "agent" && c.control_state !== "kill_switched").map((c) => (
                        <button key={c.entity_id} className="btn" disabled={p3Busy !== ""} onClick={() => govControl("agents", c.entity_id, "kill-switch", true)}>
                          Kill-switch agent {c.entity_id.slice(0, 8)}…
                        </button>
                      ))}
                      <button className="btn" disabled={p3Busy !== ""} onClick={() => govEffectiveBudget()}>
                        Load effective budget
                      </button>
                    </div>
                  )}
                </div>

                <div className="card" style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
                    <p className="kicker" style={{ margin: 0 }}>Budgets</p>
                    <button className="btn" style={{ marginLeft: "auto" }} onClick={() => setBudgetOpen((o) => !o)} disabled={p3Busy !== ""}>
                      {budgetOpen ? "Close" : "+ Upsert budget"}
                    </button>
                  </div>
                  {budgetOpen && (
                    <div className="card" style={{ marginBottom: 14 }}>
                      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 8 }}>
                        <select value={budgetForm.scope_type} onChange={(e) => setBudgetForm((f) => ({ ...f, scope_type: e.target.value }))} style={{ flex: 1, minWidth: 120 }}>
                          {["tenant", "agent_version", "grant"].map((s) => <option key={s} value={s}>{s}</option>)}
                        </select>
                        <input placeholder="agent_version_id (if scope)" value={budgetForm.agent_version_id} onChange={(e) => setBudgetForm((f) => ({ ...f, agent_version_id: e.target.value }))} style={{ flex: 1, minWidth: 150 }} />
                        <input placeholder="grant_id (if scope)" value={budgetForm.grant_id} onChange={(e) => setBudgetForm((f) => ({ ...f, grant_id: e.target.value }))} style={{ flex: 1, minWidth: 150 }} />
                      </div>
                      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                        <input type="number" placeholder="max actions / run" value={budgetForm.max_actions_per_run || ""} onChange={(e) => setBudgetForm((f) => ({ ...f, max_actions_per_run: Number(e.target.value) }))} style={{ flex: 1, minWidth: 110 }} />
                        <input type="number" placeholder="max denied / run" value={budgetForm.max_denied_per_run || ""} onChange={(e) => setBudgetForm((f) => ({ ...f, max_denied_per_run: Number(e.target.value) }))} style={{ flex: 1, minWidth: 110 }} />
                        <input type="number" placeholder="max run seconds" value={budgetForm.max_run_duration_seconds || ""} onChange={(e) => setBudgetForm((f) => ({ ...f, max_run_duration_seconds: Number(e.target.value) }))} style={{ flex: 1, minWidth: 110 }} />
                        <input type="number" placeholder="max citations / query" value={budgetForm.max_citations_per_query || ""} onChange={(e) => setBudgetForm((f) => ({ ...f, max_citations_per_query: Number(e.target.value) }))} style={{ flex: 1, minWidth: 110 }} />
                        <button className="btn" disabled={p3Busy !== ""} onClick={govUpsertBudget}>Save</button>
                      </div>
                    </div>
                  )}
                  {budgets.map((b) => (
                    <div className="row" key={b.id}>
                      <span className="badge allow">{b.scope_type.toUpperCase()}</span>
                      <div style={{ flex: 1 }}>
                        <div className="who">{b.max_actions_per_run} actions / run · {b.max_denied_per_run} denied / run</div>
                        <div className="meta">{b.scope_type === "tenant" ? "tenant-wide" : b.agent_version_id ?? b.grant_id} · {b.max_run_duration_seconds}s max run · {b.max_citations_per_query} citations/query · by {b.created_by}</div>
                      </div>
                      <div className="t">v{b.updated_at.slice(0, 10)}<br /><span className="dim">{b.scope_type === "grant" ? "grant scope" : b.scope_type === "agent_version" ? "version scope" : "fallback"}</span></div>
                    </div>
                  ))}
                  {effectiveBudget && (
                    <div className="dec" style={{ marginTop: 8 }}>
                      <span className="badge medium">EFFECTIVE</span>
                      <span className="rsn">{effectiveBudget.max_actions_per_run} actions · {effectiveBudget.max_denied_per_run} denied · {effectiveBudget.max_run_duration_seconds}s run · {effectiveBudget.max_citations_per_query} citations/query</span>
                    </div>
                  )}
                  {budgets.length === 0 && <p className="dim">No budget policies — defaults apply (no explicit caps).</p>}
                </div>

                <div className="card" style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 10 }}>
                    <p className="kicker" style={{ margin: 0 }}>Evidence</p>
                    <span className="dim" style={{ fontSize: 12 }}>hash-chained · every decision, run, and control</span>
                    <button className="btn" style={{ marginLeft: "auto" }} disabled={verifyBusy} onClick={() => govVerify(false)}>
                      {verifyBusy ? "Verifying…" : "Verify chain"}
                    </button>
                    <button className="btn" disabled={verifyBusy} onClick={() => govVerify(true)}>
                      {verifyBusy ? "…" : "Verify + checkpoint"}
                    </button>
                  </div>
                  {verify && (
                    <div className="dec">
                      <span className={`badge ${verify.verified ? "allow" : "medium"}`}>{verify.verified ? "VERIFIED" : "FAILED"}</span>
                      <span className="rsn">{verify.events_checked} events · {verify.chains_checked} chains{verify.from_checkpoint ? " · from checkpoint" : ""} · {new Date(verify.checked_at).toLocaleString()}</span>
                    </div>
                  )}
                  <div className="label" style={{ margin: "10px 0 6px" }}>Checkpoints</div>
                  {checkpoints.map((c) => (
                    <div className="dec" key={c.id}>
                      <span className="badge allow">CKPT</span>
                      <span className="doc">{c.chain_digest.slice(0, 24)}…</span>
                      <span className="rsn">{c.events_checked} events · {new Date(c.created_at).toLocaleString()}</span>
                      <button className="btn" disabled={verifyBusy} onClick={() => govVerify(false, c.id)} style={{ marginLeft: 8 }}>verify from</button>
                    </div>
                  ))}
                  {evidence.slice(0, 8).map((e) => (
                    <div className="dec" key={e.event_id}>
                      <span className={`badge ${e.kind === "run_start" ? "allow" : e.kind === "budget_exhaustion" || e.kind === "emergency_control" ? "medium" : "low"}`}>{e.kind.replace(/_/g, " ")}</span>
                      <span className="doc">{e.action_id ?? (e.run_id ? `run ${e.run_id.slice(0, 8)}…` : e.entity_id ?? e.delegation_grant_id ?? "")}</span>
                      <span className="rsn">{e.decision ? `${e.decision} · ${e.reason_code ?? "policy"}` : e.reason_code ?? "recorded"} · {new Date(e.occurred_at).toLocaleString()}</span>
                    </div>
                  ))}
                  {evidence.length === 0 && <p className="dim">No evidence yet — decisions are recorded as agents act.</p>}
                </div>

                <div className="card" style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 10, flexWrap: "wrap" }}>
                    <p className="kicker" style={{ margin: 0 }}>Evidence Exports</p>
                    <span className="dim" style={{ fontSize: 12 }}>regulatory snapshots from the evidence ledger</span>
                    <select
                      value={exportFramework}
                      onChange={(e) => { setExportFramework(e.target.value); loadExport(e.target.value); }}
                      style={{ marginLeft: "auto" }}
                    >
                      {[
                        ["eu_ai_act", "EU AI Act"],
                        ["gdpr", "GDPR"],
                        ["dora", "DORA"],
                        ["iso_42001", "ISO/IEC 42001"],
                        ["nist_ai_rmf", "NIST AI RMF"],
                        ["uk_customer_policy", "UK customer policy"],
                        ["us_customer_policy", "US customer policy"],
                      ].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                    </select>
                  </div>
                  {!exportReport && <p className="dim">No export available for this framework.</p>}
                  {exportReport && (
                    <>
                      <div className="dec" style={{ marginBottom: 10 }}>
                        <span className={`badge ${exportReport.chain_verification.verified ? "allow" : "medium"}`}>{exportReport.chain_verification.verified ? "CHAIN VERIFIED" : "CHAIN UNVERIFIED"}</span>
                        <span className="rsn">{exportReport.framework_name} · {exportReport.region} / {exportReport.jurisdiction} · tenant {exportReport.tenant_id} · {exportReport.controls.length} controls · generated {new Date(exportReport.generated_at).toLocaleString()}</span>
                      </div>
                      {exportReport.controls.map((c) => (
                        <div className="dec" key={c.control_id} style={{ alignItems: "flex-start" }}>
                          <span className={`badge ${c.status === "satisfied" ? "allow" : c.status === "partially_met" ? "low" : "medium"}`}>{c.status.replace(/_/g, " ")}</span>
                          <div style={{ flex: 1 }}>
                            <div className="who mono">{c.control_id}</div>
                            <div className="meta">{c.title}</div>
                            {c.evidence.length > 0 && (
                              <div style={{ marginTop: 6 }}>
                                {c.evidence.map((ev) => (
                                  <div className="meta" key={ev.event_id}>
                                    <span className="mono">{ev.event_id.slice(0, 12)}…</span> · {ev.kind.replace(/_/g, " ")}
                                    {ev.decision ? ` · ${ev.decision}${ev.reason_code ? ` · ${ev.reason_code}` : ""}` : ""} · {new Date(ev.occurred_at).toLocaleString()}
                                  </div>
                                ))}
                              </div>
                            )}
                            {c.evidence.length === 0 && <div className="meta dim">no matching evidence in window</div>}
                          </div>
                        </div>
                      ))}
                      <div className="label" style={{ margin: "10px 0 4px" }}>Limitations</div>
                      {exportReport.limitations.map((l, i) => <p className="dim" key={i} style={{ margin: "2px 0", fontSize: 12 }}>· {l}</p>)}
                    </>
                  )}
                </div>

                <div className="card" style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 10, flexWrap: "wrap" }}>
                    <p className="kicker" style={{ margin: 0 }}>Connector Gateway</p>
                    <span className="dim" style={{ fontSize: 12 }}>Phase 5 · registry, lifecycle, invocation evidence{connectorSource === "demo" ? " · demo" : ""}</span>
                    <button className="btn ghost" style={{ marginLeft: "auto" }} onClick={loadConnectors}>refresh</button>
                  </div>
                  {connectors.length === 0 && <p className="dim">No connectors registered.</p>}
                  {connectors.map((c) => {
                    const health = connectorHealth[c.id];
                    const expanded = connectorDetail?.connector.id === c.id;
                    return (
                      <div key={c.id} style={{ marginBottom: 10 }}>
                        <button
                          className={`row${expanded ? " open" : ""}`}
                          style={{ width: "100%", textAlign: "left" }}
                          onClick={() => loadConnectorDetail(c.id)}
                        >
                          <span className={`badge ${c.lifecycle === "active" ? "allow" : c.lifecycle === "suspended" ? "medium" : "deny"}`}>{c.lifecycle}</span>
                          <div style={{ flex: 1 }}>
                            <div className="who mono">{c.name}</div>
                            <div className="meta">{c.type.toUpperCase()} · {c.base_url} · {c.region} · v{c.version_number}</div>
                          </div>
                          {health && <span className={`badge ${health.healthy ? "allow" : "deny"}`}>{health.healthy ? "OK" : "DOWN"}</span>}
                        </button>
                        {expanded && connectorDetail && (
                          <div style={{ padding: "10px 12px", border: "1px solid var(--line)", borderTop: "none", borderRadius: "0 0 8px 8px" }}>
                            <div className="label" style={{ marginBottom: 6 }}>Actions · manifest digest <span className="mono">{connectorDetail.connector.manifest_digest}</span></div>
                            {connectorDetail.actions.map((a) => (
                              <div className="dec" key={a.name} style={{ alignItems: "flex-start" }}>
                                <span className={`badge ${a.risk === "low" || a.risk === "medium" ? "low" : a.risk === "high" ? "medium" : "deny"}`}>{a.risk}</span>
                                <div style={{ flex: 1 }}>
                                  <div className="who mono">{a.transport_method}{a.path_template ? ` ${a.path_template}` : ""} · {a.name}</div>
                                  <div className="meta">{a.read_only ? "read-only" : "mutating"}{a.requires_approval ? " · human approval" : ""} · args: {a.args?.length ? a.args.join(", ") : "none"}</div>
                                </div>
                              </div>
                            ))}
                            <div className="label" style={{ margin: "10px 0 6px" }}>Recent invocations (evidence)</div>
                            {connectorDetail.recent_invocations.length === 0 && <p className="dim" style={{ fontSize: 12 }}>No invocations recorded yet.</p>}
                            {connectorDetail.recent_invocations.map((i) => (
                              <div className="dec" key={i.id}>
                                <span className={`badge ${i.outcome === "success" ? "allow" : i.outcome === "response_blocked" ? "medium" : "deny"}`}>{i.outcome.replace(/_/g, " ")}</span>
                                <span className="doc">{i.kind.replace(/_/g, " ")} · {i.error_code || `http ${i.status_code}`}</span>
                                <span className="rsn">{i.duration_ms}ms · {i.response_bytes}B · {new Date(i.occurred_at).toLocaleString()}</span>
                              </div>
                            ))}
                            <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                              <button className="btn" disabled={connectorBusy === `probe:${c.id}`} onClick={() => probeConnector(c.id)}>
                                {connectorBusy === `probe:${c.id}` ? "probing…" : "Health probe"}
                              </button>
                              {health && (
                                <span className="dim" style={{ fontSize: 12, alignSelf: "center" }}>
                                  {health.healthy ? "healthy" : health.error_code} · {health.latency_ms}ms · {new Date(health.checked_at).toLocaleString()}
                                </span>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>

                <div className="card" style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 10 }}>
                    <p className="kicker" style={{ margin: 0 }}>Webhook Outbox</p>
                    <select value={outboxStatus} onChange={(e) => { setOutboxStatus(e.target.value); loadOutbox(e.target.value); }} style={{ marginLeft: "auto" }}>
                      <option value="">all</option>
                      {["pending", "delivered", "dead_letter"].map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                  {outbox.length === 0 && <p className="dim">Outbox empty.</p>}
                  {outbox.map((e) => (
                    <div className="dec" key={e.id}>
                      <span className={`badge ${e.status === "delivered" ? "allow" : e.status === "dead_letter" ? "medium" : "low"}`}>{e.status}</span>
                      <span className="doc">{e.event_type}</span>
                      <span className="rsn">{e.attempts} attempt(s){e.last_error ? ` · ${e.last_error}` : ""}{e.next_attempt_at ? ` · next ${new Date(e.next_attempt_at).toLocaleString()}` : ""}</span>
                      {e.status !== "delivered" && (
                        <button className="btn" disabled={p3Busy !== ""} onClick={async () => { setP3Busy(`retry:${e.id}`); const r = await fetch(`/api/governance/outbox/${e.id}/retry`, { method: "POST" }); const d = await r.json(); if (!r.ok) setP3Error(d.error ?? "retry failed"); setP3Busy(""); loadOutbox(outboxStatus); }}>
                          {p3Busy === `retry:${e.id}` ? "…" : "Retry"}
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {view === "break" && (
              <div className="view">
                <p className="lead">Break-glass operator access</p>
                <p className="dim" style={{ marginBottom: 18 }}>
                  Time-bounded emergency admin grants. Opening one mints a short-lived admin-scoped
                  API key; it is shown <b>exactly once</b> and is never persisted.{" "}
                  {bgSource === "live" ? "Live grants." : "Runtime offline — emergency controls require a live runtime and are never demo-faked."}
                </p>

                <div className="grid g3" style={{ marginBottom: 20 }}>
                  <div className="card"><div className="label">Active grants</div><div className="stat a">{bgGrants.filter((g) => g.status === "active").length}</div></div>
                  <div className="card"><div className="label">Revoked</div><div className="stat">{bgGrants.filter((g) => g.status === "revoked").length}</div></div>
                  <div className="card"><div className="label">Expired</div><div className="stat">{bgGrants.filter((g) => g.status === "expired").length}</div></div>
                </div>

                {bgError && <div className="card" style={{ marginBottom: 16, borderColor: "var(--red)", color: "var(--red)", fontSize: 12.5 }}>{bgError}</div>}

                <div className="card" style={{ marginBottom: 18, borderColor: "rgba(225,29,72,.45)" }}>
                  <p className="kicker" style={{ color: "var(--red)" }}>Open an emergency grant — irreversible exposure while active</p>
                  <textarea
                    className="mono"
                    rows={2}
                    placeholder="Justification (mandatory, ≥10 chars) — e.g. 'prod incident: root pipeline leaking to staging'"
                    value={bgReason}
                    onChange={(e) => setBgReason(e.target.value)}
                    style={{ width: "100%", marginBottom: 10 }}
                  />
                  <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
                    {[60, 240, 1440].map((m) => (
                      <label key={m} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <input type="radio" name="bg-duration" checked={bgDuration === m} onChange={() => setBgDuration(m)} />
                        {m === 60 ? "1 hour" : m === 240 ? "4 hours" : "24 hours"}
                      </label>
                    ))}
                    <button
                      className="btn"
                      style={{ background: "linear-gradient(92deg,#e11d48,#fb7185)", marginLeft: "auto" }}
                      disabled={bgBusy !== "" || bgReason.trim().length < 10}
                      onClick={() => { if (window.confirm("Open a time-bounded emergency admin grant? The minted key grants admin scope until it expires.")) openBreakGlass(); }}
                    >
                      {bgBusy === "open" ? "Opening…" : "Open grant"}
                    </button>
                  </div>
                  <p className="dim" style={{ marginTop: 10, fontSize: 12 }}>
                    Duration is capped by the runtime&apos;s <code>BREAK_GLASS_MAX_MINUTES</code> — requesting more fails, never silently shortens.
                  </p>
                </div>

                {bgMinted && bgMinted.key && (
                  <div className="card" style={{ marginBottom: 18, borderColor: "rgba(225,29,72,.6)", background: "rgba(225,29,72,.06)" }}>
                    <div className="label" style={{ color: "var(--red)", marginBottom: 8 }}>Minted admin key — displayed once, never again</div>
                    <div className="code">
                      <button className="cp" onClick={() => { navigator.clipboard?.writeText(bgMinted.key ?? ""); }}>Copy</button>
                      {bgMinted.key}
                    </div>
                    {bgMinted.grant && (
                      <p className="dim" style={{ marginTop: 8, fontSize: 12 }}>
                        Grant {bgMinted.grant.id} · expires {new Date(bgMinted.grant.expires_at).toLocaleString()} · revoke below when the incident is over.
                      </p>
                    )}
                  </div>
                )}

                {(bgGrants ?? []).map((g) => {
                  const active = g.status === "active";
                  const busy = bgBusy === `revoke:${g.id}`;
                  return (
                    <div key={g.id} className="row">
                      <span className={`badge ${active ? "medium" : g.status === "revoked" ? "deny" : "low"}`}>{g.status.toUpperCase()}</span>
                      <div>
                        <div className="who">{g.reason}</div>
                        <div className="meta">
                          <b>{g.duration_minutes} min</b> · key <span className="mono">{g.key_prefix}</span> · {g.operator_principal_id}
                          {g.revoked_by ? <> · revoked by {g.revoked_by}{g.revocation_reason ? ` — ${g.revocation_reason}` : ""}</> : null}
                        </div>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                        {active && (
                          <button
                            className="btn ghost"
                            disabled={busy}
                            onClick={(e) => { e.stopPropagation(); if (window.confirm("Revoke this grant now? The minted admin key is revoked immediately (fail-closed on its next use).")) revokeBreakGlass(g.id); }}
                          >
                            {busy ? "Revoking…" : "Revoke"}
                          </button>
                        )}
                        <div className="t">{new Date(g.requested_at).toLocaleString()}<br />{active ? <>expires {new Date(g.expires_at).toLocaleTimeString()}</> : <span style={{ color: "var(--faint)" }}>{g.revoked_at ? "revoked " + new Date(g.revoked_at).toLocaleString() : "expired"}</span>}</div>
                      </div>
                    </div>
                  );
                })}
                {bgGrants.length === 0 && bgSource === "live" && <div className="card"><p className="dim">No break-glass grants recorded for this tenant.</p></div>}
              </div>
            )}

            {view === "audit" && (
              <div className="view">
                <div className="verify">
                  <div className="ic">✓</div>
                  <div><b>{verified ? "Audit chain verified" : "Chain verification FAILED"}</b> &nbsp;<span>{checked} entries · SHA-256 hash-chained{live ? "" : " · demo data"}</span></div>
                  <button className="btn ghost" style={{ marginLeft: "auto" }} onClick={load}>Re-verify chain</button>
                </div>
                {(audit?.entries ?? []).map((r) => {
                  const isOpen = !!open[r.trace_id];
                  const allow = r.acl_decision === "allowed";
                  return (
                    <div key={r.trace_id}>
                      <button className={`row${isOpen ? " open" : ""}`} onClick={() => setOpen((o) => ({ ...o, [r.trace_id]: !o[r.trace_id] }))}>
                        <span className={`badge ${allow ? "allow" : "deny"}`}>{allow ? "ALLOW" : "DENY"}</span>
                        <div>
                          <div className="who">{r.user_id}</div>
                          <div className="meta"><b>agent</b> {r.agent_key_name ?? "—"} &nbsp;·&nbsp; {r.reason}</div>
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                          <div className="t">{new Date(r.timestamp_utc).toLocaleTimeString()}<br />{r.total_latency_ms}ms</div>
                          <span className="chev">›</span>
                        </div>
                      </button>
                      {isOpen && (
                        <div className="decisions">
                          {(r.decisions ?? []).map((d, i) => (
                            <div className="dec" key={i}>
                              <span className={`badge ${d.allowed ? "allow" : "deny"}`}>{d.allowed ? "ALLOW" : "DENY"}</span>
                              <span className="doc">{d.document_id}</span>
                              <span className="rsn">{d.reason}</span>
                            </div>
                          ))}
                          {(r.decisions ?? []).length === 0 && <div className="dec"><span className="rsn">no per-chunk detail recorded</span></div>}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {view === "leak" && (
              <div className="view">
                <p className="lead">Leak Report — acme-financial</p>
                <p className="dim" style={{ marginBottom: 18 }}>What&apos;s overexposed, before any agent even asks.</p>
                <div className="grid g3" style={{ marginBottom: 20 }}>
                  <div className="card"><div className="label">High severity</div><div className="stat r">{findings.filter((f) => f.severity === "high").length}</div></div>
                  <div className="card"><div className="label">Medium</div><div className="stat a">{findings.filter((f) => f.severity === "medium").length}</div></div>
                  <div className="card"><div className="label">Low</div><div className="stat" style={{ color: "var(--muted)" }}>{findings.filter((f) => f.severity === "low").length}</div></div>
                </div>
                {findings.map((f, i) => (
                  <div key={i} className={`finding ${f.severity}`}>
                    <div className="body">
                      <div className="ttl">{f.title}</div>
                      <div className="det" dangerouslySetInnerHTML={{ __html: sanitizeRichText(f.detail) }} />
                    </div>
                    <span className={`badge ${f.severity}`}>{f.severity.toUpperCase()}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
