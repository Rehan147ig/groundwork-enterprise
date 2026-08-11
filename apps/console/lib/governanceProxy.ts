import { NextResponse } from "next/server";
import { agentError, agentHeaders, agentRuntimeEnv } from "./agentProxy";

// Shared plumbing for the console's Delegated Authority (governance)
// surface. Mirrors the /api/agents proxy: the tenant API key and, for
// mutations, a short-lived console-admin JWT are minted server-side so
// neither the key nor the minting secret ever reaches the browser.
// Reads fall back to curated demo data when the runtime is unreachable;
// mutations never demo-fake — they either succeed against the runtime
// or fail loudly with a 502.

export type Tool = {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  transport: string;
  endpoint_or_server?: string;
  owner_principal_id: string;
  region: string;
  manifest_digest?: string;
  lifecycle: string;
  created_at: string;
  updated_at: string;
};

export type ToolAction = {
  id: string;
  tenant_id: string;
  tool_id: string;
  action: string;
  resource_type: string;
  risk_level: string;
  read_only: boolean;
  requires_human_approval: boolean;
  status: string;
  created_at: string;
};

export type AgentToolGrant = {
  id: string;
  tenant_id: string;
  agent_id: string;
  version_id: string;
  tool_id: string;
  action_id: string;
  resource_scope: string;
  region_constraint: string;
  call_limit_per_run: number;
  requires_approval: boolean;
  granted_by: string;
  granted_at: string;
  revoked_at?: string;
};

export type DelegationGrant = {
  id: string;
  tenant_id: string;
  agent_id: string;
  agent_version_id: string;
  token_jti: string;
  delegator_principal_id: string;
  subject_principal_id: string;
  purpose: string;
  region: string;
  permitted_actions?: string[];
  permitted_actions_digest: string;
  issued_at: string;
  expires_at: string;
  used_at?: string;
  run_id?: string;
  revoked_at?: string;
  immutable_digest: string;
  // Phase 6: agent-to-agent chain fields.
  is_agent_delegation?: boolean;
  parent_grant_id?: string;
  root_grant_id?: string;
  delegator_agent_id?: string;
  delegatee_agent_id?: string;
  delegation_depth?: number;
  authority_scope_digest?: string;
  parent_scope_digest?: string;
  attenuation_digest?: string;
  trust_relationship_id?: string;
  external_agent_id?: string;
  issued_via?: string;
};

export type AgentRun = {
  id: string;
  tenant_id: string;
  agent_id: string;
  delegation_grant_id: string;
  user_id: string;
  purpose: string;
  region: string;
  status: string;
  trace_id?: string;
  started_at: string;
  completed_at?: string;
  error_code?: string;
};

export type ActionDecision = {
  id: string;
  tenant_id: string;
  agent_id: string;
  run_id: string;
  delegation_grant_id: string;
  tool_id?: string;
  action_id?: string;
  resource_ref: string;
  decision: string;
  reason: string;
  policy_version: string;
  immutable_digest: string;
  created_at: string;
};

export type ActionApproval = {
  id: string;
  tenant_id: string;
  run_id: string;
  tool_id: string;
  action_id: string;
  resource_ref: string;
  approving_principal_id: string;
  decision: string;
  expires_at: string;
  consumed_at?: string;
  immutable_digest: string;
  created_at: string;
};

export type GovToolsResp = { source: string; tools: Tool[]; count: number };
export type GovToolDetailResp = { source: string; tool: Tool; actions: ToolAction[] };
export type GovGrantsResp = { source: string; grants: AgentToolGrant[]; count: number };
export type GovRunsResp = { source: string; runs: AgentRun[]; count: number };
export type GovRunDetailResp = { source: string; run: AgentRun; decisions: ActionDecision[] };
export type GovMintResp = {
  source: string;
  grant?: DelegationGrant;
  token?: string;
  token_already_issued?: boolean;
  error?: string;
};
export type GovActionResp = { source: string; decision: ActionDecision; allowed: boolean; error?: string };

// ---- Phase 3: emergency controls, budgets, evidence, outbox ----

export type EmergencyControl = {
  id: string;
  tenant_id: string;
  entity_type: string;
  entity_id: string;
  control_state: string;
  reason: string;
  scope?: string;
  actor_principal_id: string;
  created_at: string;
  updated_at: string;
};

export type BudgetPolicy = {
  id: string;
  tenant_id: string;
  scope_type: string;
  agent_version_id?: string;
  grant_id?: string;
  max_actions_per_run: number;
  max_denied_per_run: number;
  max_approval_required_per_run: number;
  max_tool_calls_per_action_per_run: number;
  max_run_duration_seconds: number;
  max_citations_per_query: number;
  created_by: string;
  created_at: string;
  updated_at: string;
};

export type EvidenceEvent = {
  event_id: string;
  kind: string;
  tenant_id: string;
  occurred_at: string;
  actor_principal_id?: string;
  agent_id?: string;
  agent_name?: string;
  agent_version_id?: string;
  delegation_grant_id?: string;
  user_id?: string;
  run_id?: string;
  run_status?: string;
  tool_id?: string;
  tool_name?: string;
  action_id?: string;
  resource_ref?: string;
  decision?: string;
  reason?: string;
  reason_code?: string;
  policy_version?: string;
  trace_id?: string;
  entity_type?: string;
  entity_id?: string;
  previous_state?: string;
  new_state?: string;
  immutable_digest: string;
};

export type EvidenceVerifyResult = {
  tenant_id: string;
  verified: boolean;
  chains_checked: number;
  events_checked: number;
  first_broken_kind?: string;
  first_broken_id?: string;
  first_broken_at?: string;
  first_broken_detail?: string;
  from_checkpoint?: boolean;
  checked_at: string;
};

export type EvidenceCheckpoint = {
  id: string;
  tenant_id: string;
  last_event_id: string;
  last_verified_at: string;
  events_checked: number;
  chain_digest: string;
  created_at: string;
};

export type OutboxEvent = {
  id: string;
  tenant_id: string;
  event_id: string;
  event_type: string;
  schema_version: number;
  occurred_at: string;
  payload?: unknown;
  status: string;
  attempts: number;
  next_attempt_at: string;
  last_error?: string;
  created_at: string;
  delivered_at?: string;
};

export type GovControlsResp = { source: string; controls: EmergencyControl[]; count: number };
export type GovBudgetsResp = { source: string; budgets: BudgetPolicy[]; count: number };
export type GovEvidenceResp = { source: string; events: EvidenceEvent[]; next_cursor?: string; count: number };
export type GovVerifyResp = { source: string; verified: boolean; chains_checked: number; events_checked: number; first_broken_kind?: string; first_broken_id?: string; first_broken_detail?: string; from_checkpoint?: boolean; checked_at: string };
export type GovCheckpointsResp = { source: string; checkpoints: EvidenceCheckpoint[]; count: number };
export type GovOutboxResp = { source: string; events: OutboxEvent[]; next_cursor?: string; count: number };

// ---- Phase 5: Production Connector Gateway ----

export type Connector = {
  id: string;
  tenant_id: string;
  name: string;
  type: string;
  lifecycle: string;
  base_url: string;
  region: string;
  tool_id: string;
  owner_principal_id: string;
  manifest_digest: string;
  version_number: number;
  timeout_ms: number;
  retry_max: number;
  retry_idempotent_only: boolean;
  max_response_bytes: number;
  allowed_content_types: string[];
  redaction_fields: string[];
  secret_ref?: string;
  tls_verify: boolean;
  created_at: string;
  updated_at: string;
};

export type ConnectorAction = {
  name: string;
  transport_method: string;
  path_template?: string;
  resource_type?: string;
  risk: string;
  read_only: boolean;
  requires_approval: boolean;
  max_request_bytes: number;
  max_response_bytes: number;
  allowed_agent_version_ids?: string[];
  args?: string[];
};

export type ConnectorInvocation = {
  id: string;
  tenant_id: string;
  connector_id: string;
  connector_name?: string;
  tool_id?: string;
  tool_action_id?: string;
  run_id?: string;
  decision_id: string;
  kind: string;
  outcome: string;
  status_code: number;
  error_code: string;
  duration_ms: number;
  response_bytes: number;
  region: string;
  trace_id: string;
  occurred_at: string;
};

export type ConnectorLifecycleEvent = {
  id: string;
  tenant_id: string;
  connector_id: string;
  action_type: string;
  from_state: string;
  to_state: string;
  actor_principal_id: string;
  reason: string;
  immutable_digest: string;
  created_at: string;
};

export type ConnectorDetail = {
  connector: Connector;
  config: {
    base_url: string;
    region: string;
    timeout_ms: number;
    retry_max: number;
    retry_idempotent_only: boolean;
    max_response_bytes: number;
    tls_verify: boolean;
    secret_ref?: string;
    allowed_content_types: string[];
    redaction_fields: string[];
  };
  actions: ConnectorAction[];
  lifecycle_events: ConnectorLifecycleEvent[];
  recent_invocations: ConnectorInvocation[];
};

export type ConnectorHealth = {
  connector_id: string;
  healthy: boolean;
  status_code: number;
  error_code: string;
  latency_ms: number;
  checked_at: string;
};

export type GovConnectorsResp = { source: string; connectors: Connector[]; count: number };
export type GovConnectorDetailResp = { source: string; detail: ConnectorDetail };
export type GovConnectorHealthResp = { source: string; health: ConnectorHealth };

// ---- Phase 6: Multi-Agent Trust (relationships, external agents,
// consents, transfer policies, external budgets, delegation chains) ----

export type AgentTrustRelationship = {
  id: string;
  tenant_id: string;
  parent_agent_id: string;
  child_agent_id?: string;
  external_agent_id?: string;
  trust_domain: string;
  owner_principal_id: string;
  purpose: string;
  max_delegation_depth: number;
  allowed_tools_actions?: string[];
  region: string;
  expires_at: string;
  status: string;
  approval_required: boolean;
  reason?: string;
  immutable_digest: string;
  created_at: string;
  updated_at: string;
};

export type ExternalAgent = {
  id: string;
  external_agent_id: string;
  agent_id: string;
  organization_id: string;
  tenant_id: string;
  owner_principal_id: string;
  verified_issuer: string;
  allowed_audiences: string[];
  auth_method: string;
  trust_tier: string;
  region: string;
  allowed_tools_actions?: string[];
  public_key_jwks_ref?: string;
  manifest_digest?: string;
  security_contact?: string;
  lifecycle_state: string;
  expires_at: string;
  created_at: string;
  updated_at: string;
};

export type ConsentRecord = {
  id: string;
  tenant_id: string;
  organization_id: string;
  external_agent_id: string;
  customer_principal_id: string;
  purpose: string;
  resource_ref_pattern: string;
  status: string;
  granted_by: string;
  granted_at: string;
  expires_at: string;
  immutable_digest: string;
};

export type TransferPolicy = {
  id: string;
  tenant_id: string;
  source_region: string;
  target_region: string;
  purpose_pattern: string;
  enabled: boolean;
  created_by: string;
  created_at: string;
};

export type ExternalBudgetPolicy = {
  id: string;
  tenant_id: string;
  scope_type: string;
  external_agent_id?: string;
  organization_id?: string;
  customer_principal_id?: string;
  max_total_actions: number;
  max_actions_per_run: number;
  max_denied_per_run: number;
  max_approval_required_per_run: number;
  max_tool_calls_per_action_per_run: number;
  actions_count: number;
  denied_count: number;
  approval_required_count: number;
  tool_calls_count: number;
  created_by: string;
  created_at: string;
  updated_at: string;
};

export type DelegationChainNode = {
  grant: DelegationGrant;
  delegator_agent_id?: string;
  delegatee_agent_id?: string;
  verified: boolean;
  problem?: string;
};

export type DelegationChain = {
  root_grant_id: string;
  leaf_grant_id: string;
  depth: number;
  verified: boolean;
  problem?: string;
  nodes: DelegationChainNode[];
};

export type ProvenanceView = {
  event_id: string;
  kind: string;
  tenant_id: string;
  occurred_at: string;
  root_grant_id?: string;
  parent_grant_id?: string;
  delegation_depth: number;
  delegator_agent_id?: string;
  delegatee_agent_id?: string;
  subject_principal_id?: string;
  trust_domain?: string;
  organization_id?: string;
  region?: string;
  final_decision?: string;
  chain_verification?: string;
  tool_name?: string;
  resource_ref?: string;
  reason?: string;
  immutable_digest: string;
};

export type GovTrustRelsResp = { source: string; relationships: AgentTrustRelationship[]; count: number };
export type GovExternalAgentsResp = { source: string; agents: ExternalAgent[]; count: number };
export type GovConsentsResp = { source: string; consents: ConsentRecord[]; count: number };
export type GovTransferPoliciesResp = { source: string; policies: TransferPolicy[]; count: number };
export type GovExternalBudgetsResp = { source: string; budgets: ExternalBudgetPolicy[]; count: number };
export type GovDelegationsResp = { source: string; grants: DelegationGrant[]; count: number };
export type GovDelegationChainResp = { source: string; chain: DelegationChain };
export type GovProvenanceResp = { source: string; provenance: ProvenanceView };

// Curated Phase 5 demo connectors: the payments connector bound to the
// same treasury-reconcile story as the rest of the console, plus a
// suspended one to show the lifecycle surface.
export const DEMO_CONNECTORS: Connector[] = [
  {
    id: "conn_demo_payments",
    tenant_id: "tenant_demo",
    name: "payments",
    type: "rest",
    lifecycle: "active",
    base_url: "https://payments.example.com",
    region: "eu-central-1",
    tool_id: "tool_demo_payments",
    owner_principal_id: "principal:finance-owner",
    manifest_digest: "sha256:5e8d…3c21",
    version_number: 2,
    timeout_ms: 5000,
    retry_max: 2,
    retry_idempotent_only: true,
    max_response_bytes: 262144,
    allowed_content_types: ["application/json"],
    redaction_fields: ["token", "secret", "authorization"],
    secret_ref: "env://PAYMENTS_TOKEN",
    tls_verify: true,
    created_at: "2026-06-01T09:00:00Z",
    updated_at: "2026-06-14T11:22:00Z",
  },
  {
    id: "conn_demo_crm",
    tenant_id: "tenant_demo",
    name: "crm-sync",
    type: "mcp",
    lifecycle: "suspended",
    base_url: "https://crm-mcp.example.com",
    region: "eu-central-1",
    tool_id: "tool_demo_crm",
    owner_principal_id: "principal:finance-owner",
    manifest_digest: "sha256:1ab2…9f77",
    version_number: 1,
    timeout_ms: 10000,
    retry_max: 0,
    retry_idempotent_only: false,
    max_response_bytes: 1048576,
    allowed_content_types: ["application/json"],
    redaction_fields: ["token"],
    tls_verify: true,
    created_at: "2026-06-05T14:00:00Z",
    updated_at: "2026-06-18T08:30:00Z",
  },
];

export function demoConnectorDetail(id: string): GovConnectorDetailResp | null {
  const c = DEMO_CONNECTORS.find((x) => x.id === id);
  if (!c) return null;
  const isPayments = c.id === "conn_demo_payments";
  const detail: ConnectorDetail = {
    connector: c,
    config: {
      base_url: c.base_url,
      region: c.region,
      timeout_ms: c.timeout_ms,
      retry_max: c.retry_max,
      retry_idempotent_only: c.retry_idempotent_only,
      max_response_bytes: c.max_response_bytes,
      tls_verify: c.tls_verify,
      secret_ref: c.secret_ref,
      allowed_content_types: c.allowed_content_types,
      redaction_fields: c.redaction_fields,
    },
    actions: isPayments
      ? [
          { name: "get_balance", transport_method: "GET", path_template: "/v1/balance", risk: "low", read_only: true, requires_approval: false, max_request_bytes: 0, max_response_bytes: 262144, args: [] },
          { name: "pay", transport_method: "POST", path_template: "/v1/pay", risk: "critical", read_only: false, requires_approval: true, max_request_bytes: 4096, max_response_bytes: 262144, args: ["amount", "currency"] },
        ]
      : [
          { name: "crm_sync_contacts", transport_method: "crm_sync_contacts", risk: "medium", read_only: false, requires_approval: false, max_request_bytes: 8192, max_response_bytes: 1048576, args: ["batch_id"] },
        ],
    lifecycle_events: [
      {
        id: "clev_demo_2",
        tenant_id: c.tenant_id,
        connector_id: c.id,
        action_type: "config_update",
        from_state: c.lifecycle,
        to_state: c.lifecycle,
        actor_principal_id: "principal:finance-owner",
        reason: "pinned agent versions",
        immutable_digest: "f3d2…aa91",
        created_at: c.updated_at,
      },
      {
        id: "clev_demo_1",
        tenant_id: c.tenant_id,
        connector_id: c.id,
        action_type: "activate",
        from_state: "draft",
        to_state: "active",
        actor_principal_id: "principal:finance-owner",
        reason: "go live",
        immutable_digest: "9c1e…77b2",
        created_at: "2026-06-03T10:00:00Z",
      },
    ],
    recent_invocations: isPayments
      ? [
          {
            id: "cinv_demo_2",
            tenant_id: c.tenant_id,
            connector_id: c.id,
            connector_name: c.name,
            tool_id: c.tool_id,
            tool_action_id: "action_pay",
            run_id: "run_demo_7",
            decision_id: "dec_demo_8",
            kind: "agent_action",
            outcome: "success",
            status_code: 200,
            error_code: "",
            duration_ms: 42,
            response_bytes: 180,
            region: c.region,
            trace_id: "trace_demo_2",
            occurred_at: "2026-06-18T09:12:00Z",
          },
          {
            id: "cinv_demo_1",
            tenant_id: c.tenant_id,
            connector_id: c.id,
            connector_name: c.name,
            tool_id: c.tool_id,
            tool_action_id: "action_get_balance",
            run_id: "run_demo_6",
            decision_id: "dec_demo_7",
            kind: "agent_action",
            outcome: "success",
            status_code: 200,
            error_code: "",
            duration_ms: 31,
            response_bytes: 92,
            region: c.region,
            trace_id: "trace_demo_1",
            occurred_at: "2026-06-18T08:55:00Z",
          },
        ]
      : [],
  };
  return { source: "demo", detail };
}

export function demoConnectorHealth(id: string): GovConnectorHealthResp | null {
  if (!DEMO_CONNECTORS.some((x) => x.id === id)) return null;
  return {
    source: "demo",
    health: {
      connector_id: id,
      healthy: true,
      status_code: 200,
      error_code: "",
      latency_ms: 23,
      checked_at: new Date().toISOString(),
    },
  };
}

// ---- Phase 6 demo data: the multi-agent trust story. Consistent with
// the tenant_demo treasury-reconcile world: finance-reviewer (agent-1)
// delegates to vendor-pay-review (agent-2) across an approved trust
// edge; a partner external agent (payroll-ops) acts on a customer's
// consent under an external budget; a cross-region transfer policy
// covers EU -> US. All ids are stable demo ids — never fabricated live
// state (mutations still fail loudly without a runtime).

export const DEMO_TRUST_RELS: AgentTrustRelationship[] = [
  {
    id: "rel_demo_1",
    tenant_id: "tenant_demo",
    parent_agent_id: "ag_demo_1",
    child_agent_id: "ag_demo_2",
    trust_domain: "finance",
    owner_principal_id: "principal:alice",
    purpose: "vendor reconciliation",
    max_delegation_depth: 2,
    allowed_tools_actions: ["groundwork_search:search"],
    region: "us-east-1",
    expires_at: "2026-12-31T23:59:59Z",
    status: "active",
    approval_required: false,
    immutable_digest: "0001tr…aa11",
    created_at: "2026-06-05T10:00:00Z",
    updated_at: "2026-06-05T10:00:00Z",
  },
  {
    id: "rel_demo_2",
    tenant_id: "tenant_demo",
    parent_agent_id: "ag_demo_1",
    external_agent_id: "ext_demo_payroll",
    trust_domain: "external",
    owner_principal_id: "principal:alice",
    purpose: "payroll operations",
    max_delegation_depth: 1,
    region: "eu-central-1",
    expires_at: "2026-09-30T23:59:59Z",
    status: "active",
    approval_required: true,
    immutable_digest: "0001tr…bb22",
    created_at: "2026-06-20T14:00:00Z",
    updated_at: "2026-06-21T09:00:00Z",
  },
  {
    id: "rel_demo_3",
    tenant_id: "tenant_demo",
    parent_agent_id: "ag_demo_1",
    child_agent_id: "ag_demo_3",
    trust_domain: "finance",
    owner_principal_id: "principal:alice",
    purpose: "draft review",
    max_delegation_depth: 1,
    region: "us-east-1",
    expires_at: "2026-07-01T00:00:00Z",
    status: "requested",
    approval_required: true,
    immutable_digest: "0001tr…cc33",
    created_at: "2026-06-25T08:30:00Z",
    updated_at: "2026-06-25T08:30:00Z",
  },
];

export const DEMO_EXTERNAL_AGENTS: ExternalAgent[] = [
  {
    id: "ext_row_1",
    external_agent_id: "ext_demo_payroll",
    agent_id: "ag_demo_1",
    organization_id: "org_payroll_provider",
    tenant_id: "tenant_demo",
    owner_principal_id: "principal:alice",
    verified_issuer: "https://id.payroll-provider.example",
    allowed_audiences: ["groundwork-api"],
    auth_method: "oidc",
    trust_tier: "partner",
    region: "eu-central-1",
    allowed_tools_actions: ["groundwork_search:search"],
    security_contact: "security@payroll-provider.example",
    manifest_digest: "sha256:9c1e…77b2",
    lifecycle_state: "active",
    expires_at: "2026-08-21T00:00:00Z",
    created_at: "2026-06-20T14:00:00Z",
    updated_at: "2026-06-20T14:00:00Z",
  },
  {
    id: "ext_row_2",
    external_agent_id: "ext_demo_auditor",
    agent_id: "ag_demo_1",
    organization_id: "org_audit_firm",
    tenant_id: "tenant_demo",
    owner_principal_id: "principal:bob",
    verified_issuer: "https://id.audit-firm.example",
    allowed_audiences: ["groundwork-api"],
    auth_method: "jwt_jwks",
    trust_tier: "verified",
    region: "us-east-1",
    lifecycle_state: "suspended",
    expires_at: "2026-07-15T00:00:00Z",
    created_at: "2026-05-30T11:00:00Z",
    updated_at: "2026-06-19T16:45:00Z",
  },
];

export const DEMO_CONSENTS: ConsentRecord[] = [
  {
    id: "consent_demo_1",
    tenant_id: "tenant_demo",
    organization_id: "org_payroll_provider",
    external_agent_id: "ext_demo_payroll",
    customer_principal_id: "principal:emma",
    purpose: "payroll operations",
    resource_ref_pattern: "doc://payroll/*",
    status: "active",
    granted_by: "principal:alice",
    granted_at: "2026-06-20T15:00:00Z",
    expires_at: "2026-12-20T15:00:00Z",
    immutable_digest: "0001co…aa11",
  },
  {
    id: "consent_demo_2",
    tenant_id: "tenant_demo",
    organization_id: "org_payroll_provider",
    external_agent_id: "ext_demo_payroll",
    customer_principal_id: "principal:james",
    purpose: "payroll operations",
    resource_ref_pattern: "*",
    status: "active",
    granted_by: "principal:alice",
    granted_at: "2026-06-22T09:15:00Z",
    expires_at: "2026-12-22T09:15:00Z",
    immutable_digest: "0001co…bb22",
  },
  {
    id: "consent_demo_3",
    tenant_id: "tenant_demo",
    organization_id: "org_audit_firm",
    external_agent_id: "ext_demo_auditor",
    customer_principal_id: "principal:emma",
    purpose: "annual audit",
    resource_ref_pattern: "doc://audit/*",
    status: "revoked",
    granted_by: "principal:bob",
    granted_at: "2026-05-30T12:00:00Z",
    expires_at: "2026-11-30T12:00:00Z",
    immutable_digest: "0001co…cc33",
  },
];

export const DEMO_TRANSFER_POLICIES: TransferPolicy[] = [
  {
    id: "tp_demo_1",
    tenant_id: "tenant_demo",
    source_region: "eu-central-1",
    target_region: "us-east-1",
    purpose_pattern: "payroll operations",
    enabled: true,
    created_by: "principal:alice",
    created_at: "2026-06-20T14:05:00Z",
  },
  {
    id: "tp_demo_2",
    tenant_id: "tenant_demo",
    source_region: "us-east-1",
    target_region: "eu-central-1",
    purpose_pattern: "*",
    enabled: false,
    created_by: "principal:bob",
    created_at: "2026-06-01T10:00:00Z",
  },
];

export const DEMO_EXTERNAL_BUDGETS: ExternalBudgetPolicy[] = [
  {
    id: "eb_demo_1",
    tenant_id: "tenant_demo",
    scope_type: "external_agent",
    external_agent_id: "ext_demo_payroll",
    max_total_actions: 500,
    max_actions_per_run: 25,
    max_denied_per_run: 5,
    max_approval_required_per_run: 3,
    max_tool_calls_per_action_per_run: 50,
    actions_count: 214,
    denied_count: 3,
    approval_required_count: 1,
    tool_calls_count: 512,
    created_by: "principal:alice",
    created_at: "2026-06-20T14:10:00Z",
    updated_at: "2026-07-02T09:00:00Z",
  },
  {
    id: "eb_demo_2",
    tenant_id: "tenant_demo",
    scope_type: "external_organization",
    external_agent_id: "ext_demo_auditor",
    organization_id: "org_audit_firm",
    max_total_actions: 100,
    max_actions_per_run: 10,
    max_denied_per_run: 2,
    max_approval_required_per_run: 1,
    max_tool_calls_per_action_per_run: 20,
    actions_count: 12,
    denied_count: 0,
    approval_required_count: 0,
    tool_calls_count: 15,
    created_by: "principal:bob",
    created_at: "2026-05-30T12:10:00Z",
    updated_at: "2026-05-30T12:10:00Z",
  },
];

export const DEMO_DELEGATIONS: DelegationGrant[] = [
  {
    id: "dg_demo_root",
    tenant_id: "tenant_demo",
    agent_id: "ag_demo_1",
    agent_version_id: "agv_demo_1_2",
    token_jti: "jti_demo_root",
    delegator_principal_id: "principal:alice",
    subject_principal_id: "principal:bob",
    purpose: "vendor reconciliation",
    region: "us-east-1",
    permitted_actions: ["groundwork_search:search"],
    permitted_actions_digest: "0001pd…",
    issued_at: "2026-06-05T10:00:00Z",
    expires_at: "2026-07-05T10:00:00Z",
    immutable_digest: "0001dg…aa",
  },
  {
    id: "dg_demo_child",
    tenant_id: "tenant_demo",
    agent_id: "ag_demo_2",
    agent_version_id: "agv_demo_2_1",
    token_jti: "jti_demo_child",
    delegator_principal_id: "principal:alice",
    subject_principal_id: "principal:bob",
    purpose: "child purpose",
    region: "us-east-1",
    permitted_actions: ["groundwork_search:search"],
    permitted_actions_digest: "0001pd…",
    issued_at: "2026-06-05T10:05:00Z",
    expires_at: "2026-07-05T10:05:00Z",
    is_agent_delegation: true,
    parent_grant_id: "dg_demo_root",
    root_grant_id: "dg_demo_root",
    delegator_agent_id: "ag_demo_1",
    delegatee_agent_id: "ag_demo_2",
    delegation_depth: 1,
    authority_scope_digest: "0001as…",
    parent_scope_digest: "0001ps…",
    attenuation_digest: "0001at…",
    trust_relationship_id: "rel_demo_1",
    immutable_digest: "0001dg…bb",
  },
];

export function demoDelegationChain(grantId: string): GovDelegationChainResp | null {
  const root = DEMO_DELEGATIONS.find((g) => g.id === "dg_demo_root");
  const child = DEMO_DELEGATIONS.find((g) => g.id === "dg_demo_child");
  if (!root) return null;
  if (grantId === "dg_demo_root" || grantId === root.id) {
    return {
      source: "demo",
      chain: {
        root_grant_id: root.id,
        leaf_grant_id: root.id,
        depth: 0,
        verified: true,
        nodes: [{ grant: root, delegator_agent_id: root.delegator_agent_id, delegatee_agent_id: root.delegatee_agent_id, verified: true }],
      },
    };
  }
  if (child && (grantId === child.id || grantId === "dg_demo_child")) {
    return {
      source: "demo",
      chain: {
        root_grant_id: root.id,
        leaf_grant_id: child.id,
        depth: 1,
        verified: true,
        nodes: [
          { grant: root, delegator_agent_id: root.delegator_agent_id, delegatee_agent_id: root.delegatee_agent_id, verified: true },
          { grant: child, delegator_agent_id: child.delegator_agent_id, delegatee_agent_id: child.delegatee_agent_id, verified: true },
        ],
      },
    };
  }
  return null;
}

export function demoProvenance(eventId: string): GovProvenanceResp | null {
  if (eventId !== "ev_demo_2") return null;
  return {
    source: "demo",
    provenance: {
      event_id: eventId,
      kind: "decision",
      tenant_id: "tenant_demo",
      occurred_at: "2026-06-11T19:02:03Z",
      root_grant_id: "dg_demo_root",
      parent_grant_id: "dg_demo_root",
      delegation_depth: 0,
      delegator_agent_id: "ag_demo_1",
      delegatee_agent_id: "ag_demo_1",
      subject_principal_id: "principal:bob",
      trust_domain: "finance",
      region: "us-east-1",
      final_decision: "allowed",
      chain_verification: "verified",
      tool_name: "groundwork_search",
      resource_ref: "doc://policies/treasury-ops",
      reason: "grant active · action within permitted digest",
      immutable_digest: "0001dec…bb22",
    },
  };
}

// ---- Phase 4e: framework evidence exports ----

export type ExportControlReport = {
  control_id: string;
  title: string;
  status: "satisfied" | "partially_met" | "no_evidence" | "chain_unverified";
  evidence: {
    event_id: string;
    kind: string;
    occurred_at: string;
    decision?: string;
    reason_code?: string;
    region?: string;
    jurisdiction?: string;
    immutable_digest: string;
  }[];
  limitations?: string[];
};

export type FrameworkExport = {
  framework: string;
  framework_name: string;
  region: string;
  jurisdiction: string;
  tenant_id: string;
  owner?: string;
  generated_at: string;
  window_from: string;
  window_to: string;
  controls: ExportControlReport[];
  chain_verification: { checked: number; problems: number; verified: boolean; detail?: string };
  limitations: string[];
};

// Curated Phase 4e demo export: derived from the demo evidence story
// (tenant_demo, EU jurisdiction) so the console shows a plausible EU AI
// Act report even with a cold backend. Other frameworks fall back to a
// honest all-no-evidence report — the export surface never fabricates.
export function demoExport(framework: string): FrameworkExport | null {
  const base = {
    region: "eu-central-1",
    jurisdiction: "eu",
    tenant_id: "tenant_demo",
    generated_at: new Date().toISOString(),
    window_from: "2026-05-20T00:00:00Z",
    window_to: new Date().toISOString(),
    chain_verification: { checked: 4, problems: 0, verified: true },
    limitations: [
      "demo export derived from the curated demo evidence story (not a live runtime)",
      "evidence status reflects matching evidence kinds; it is not a certification",
    ],
  };
  if (framework === "eu_ai_act") {
    return {
      ...base,
      framework,
      framework_name: "EU AI Act",
      controls: [
        {
          control_id: "art_9_risk_management",
          title: "Article 9 — Risk management system",
          status: "satisfied",
          evidence: [
            { event_id: "ev_demo_3", kind: "decision", occurred_at: "2026-06-11T19:03:00Z", decision: "denied", reason_code: "budget_exhausted:max_denied_per_run", region: "eu-central-1", jurisdiction: "eu", immutable_digest: "0001dec…cc33" },
            { event_id: "ev_demo_4", kind: "emergency_control", occurred_at: "2026-06-11T19:12:00Z", region: "eu-central-1", jurisdiction: "eu", immutable_digest: "0001ebc…dd44" },
          ],
        },
        {
          control_id: "art_12_logging",
          title: "Article 12 — Record-keeping / automatic logging",
          status: "satisfied",
          evidence: [
            { event_id: "ev_demo_1", kind: "run_start", occurred_at: "2026-06-11T19:02:00Z", region: "eu-central-1", jurisdiction: "eu", immutable_digest: "0001ebe…aa11" },
            { event_id: "ev_demo_2", kind: "decision", occurred_at: "2026-06-11T19:02:03Z", decision: "allowed", region: "eu-central-1", jurisdiction: "eu", immutable_digest: "0001dec…bb22" },
          ],
        },
        {
          control_id: "art_26_transparency",
          title: "Article 26 — Obligations of deployers (transparency)",
          status: "no_evidence",
          evidence: [],
        },
        {
          control_id: "art_27_registry",
          title: "Article 27 — Registration of high-risk AI systems",
          status: "no_evidence",
          evidence: [],
        },
      ],
    };
  }
  const names: Record<string, string> = {
    dora: "DORA (Digital Operational Resilience Act)",
    gdpr: "GDPR (General Data Protection Regulation)",
    iso_42001: "ISO/IEC 42001 — AI Management System",
    nist_ai_rmf: "NIST AI RMF (AI Risk Management Framework)",
    uk_customer_policy: "UK customer policy",
    us_customer_policy: "US customer policy",
  };
  return { ...base, framework, framework_name: names[framework] ?? framework, controls: [] };
}

// Curated Phase 3 demo story: the same tenant_demo treasury-reconcile
// agent from the registry/governance views, plus an incident response.
export const DEMO_CONTROLS: EmergencyControl[] = [
  {
    id: "ctrl_demo_1",
    tenant_id: "tenant_demo",
    entity_type: "tool",
    entity_id: "tool_demo_2",
    control_state: "kill_switched",
    reason: "SIEM alert: sharepoint publish attempted outside approved scope",
    actor_principal_id: "principal:alice",
    created_at: "2026-06-11T19:12:00Z",
    updated_at: "2026-06-11T19:12:00Z",
  },
  {
    id: "ctrl_demo_2",
    tenant_id: "tenant_demo",
    entity_type: "run",
    entity_id: "run_demo_3",
    control_state: "revoked",
    reason: "Run attempted denied-resource access three times in a row",
    actor_principal_id: "principal:alice",
    created_at: "2026-06-11T19:13:00Z",
    updated_at: "2026-06-11T19:13:00Z",
  },
  {
    id: "ctrl_demo_3",
    tenant_id: "tenant_demo",
    entity_type: "agent",
    entity_id: "ag_demo_3",
    control_state: "active",
    reason: "Suspension reviewed — agent released after policy update",
    actor_principal_id: "principal:alice",
    created_at: "2026-06-11T19:40:00Z",
    updated_at: "2026-06-11T19:40:00Z",
  },
];

export const DEMO_BUDGETS: BudgetPolicy[] = [
  {
    id: "budget_demo_tenant",
    tenant_id: "tenant_demo",
    scope_type: "tenant",
    max_actions_per_run: 20,
    max_denied_per_run: 3,
    max_approval_required_per_run: 2,
    max_tool_calls_per_action_per_run: 50,
    max_run_duration_seconds: 600,
    max_citations_per_query: 40,
    created_by: "principal:alice",
    created_at: "2026-05-20T08:00:00Z",
    updated_at: "2026-06-08T09:15:00Z",
  },
  {
    id: "budget_demo_grant",
    tenant_id: "tenant_demo",
    scope_type: "grant",
    grant_id: "grant_demo_2",
    max_actions_per_run: 3,
    max_denied_per_run: 1,
    max_approval_required_per_run: 1,
    max_tool_calls_per_action_per_run: 5,
    max_run_duration_seconds: 120,
    max_citations_per_query: 10,
    created_by: "principal:bob",
    created_at: "2026-06-05T11:12:00Z",
    updated_at: "2026-06-05T11:12:00Z",
  },
];

export const DEMO_EVIDENCE: EvidenceEvent[] = [
  {
    event_id: "ev_demo_1",
    kind: "run_start",
    tenant_id: "tenant_demo",
    occurred_at: "2026-06-11T19:02:00Z",
    agent_id: "ag_demo_1",
    delegation_grant_id: "dg_demo_1",
    user_id: "principal:bob",
    run_id: "run_demo_1",
    run_status: "running",
    immutable_digest: "0001ebe…aa11",
  },
  {
    event_id: "ev_demo_2",
    kind: "decision",
    tenant_id: "tenant_demo",
    occurred_at: "2026-06-11T19:02:03Z",
    agent_id: "ag_demo_1",
    delegation_grant_id: "dg_demo_1",
    user_id: "principal:bob",
    run_id: "run_demo_1",
    tool_id: "tool_demo_1",
    tool_name: "groundwork_search",
    action_id: "act_demo_search",
    resource_ref: "doc://policies/treasury-ops",
    decision: "allowed",
    reason: "grant active · action within permitted digest",
    policy_version: "v1",
    immutable_digest: "0001dec…bb22",
  },
  {
    event_id: "ev_demo_3",
    kind: "decision",
    tenant_id: "tenant_demo",
    occurred_at: "2026-06-11T19:03:00Z",
    agent_id: "ag_demo_1",
    delegation_grant_id: "dg_demo_1",
    user_id: "principal:bob",
    run_id: "run_demo_2",
    tool_id: "tool_demo_1",
    tool_name: "groundwork_search",
    action_id: "act_demo_search",
    resource_ref: "doc://hr/salaries",
    decision: "denied",
    reason_code: "budget_exhausted:max_denied_per_run",
    reason: "denial budget exhausted for this run",
    policy_version: "v1",
    immutable_digest: "0001dec…cc33",
  },
  {
    event_id: "ev_demo_4",
    kind: "emergency_control",
    tenant_id: "tenant_demo",
    occurred_at: "2026-06-11T19:12:00Z",
    actor_principal_id: "principal:alice",
    entity_type: "tool",
    entity_id: "tool_demo_2",
    previous_state: "active",
    new_state: "kill_switched",
    immutable_digest: "0001ebc…dd44",
  },
];

export const DEMO_CHECKPOINTS: EvidenceCheckpoint[] = [
  {
    id: "cp_demo_1",
    tenant_id: "tenant_demo",
    last_event_id: "ev_demo_4",
    last_verified_at: "2026-06-11T19:12:05Z",
    events_checked: 4,
    chain_digest: "0001cp0…88",
    created_at: "2026-06-11T19:12:05Z",
  },
];

export const DEMO_OUTBOX: OutboxEvent[] = [
  {
    id: "obx_demo_1",
    tenant_id: "tenant_demo",
    event_id: "ev_demo_1",
    event_type: "run.started",
    schema_version: 1,
    occurred_at: "2026-06-11T19:02:00Z",
    payload: { run_id: "run_demo_1", agent_id: "ag_demo_1" },
    status: "delivered",
    attempts: 1,
    next_attempt_at: "2026-06-11T19:02:00Z",
    delivered_at: "2026-06-11T19:02:01Z",
    created_at: "2026-06-11T19:02:00Z",
  },
  {
    id: "obx_demo_2",
    tenant_id: "tenant_demo",
    event_id: "ev_demo_4",
    event_type: "emergency.control",
    schema_version: 1,
    occurred_at: "2026-06-11T19:12:00Z",
    payload: { entity_type: "tool", entity_id: "tool_demo_2", action: "kill_switch" },
    status: "pending",
    attempts: 2,
    last_error: "webhook returned 500 Internal Server Error",
    next_attempt_at: "2026-06-11T19:12:04Z",
    created_at: "2026-06-11T19:12:00Z",
  },
];

const T0 = "2026-06-10T09:00:00Z";

// Curated demo dataset — consistent with the agent registry demo story
// (tenant_demo, treasury-reconcile / vendor-pay-review agents).
export const DEMO_TOOLS: Tool[] = [
  {
    id: "tool_demo_1",
    tenant_id: "tenant_demo",
    name: "groundwork_search",
    description: "Semantic + keyword retrieval over grounded, ACL-checked document chunks.",
    transport: "builtin",
    owner_principal_id: "principal:alice",
    region: "us-east-1",
    lifecycle: "active",
    created_at: "2026-04-02T10:00:00Z",
    updated_at: "2026-05-21T14:00:00Z",
  },
  {
    id: "tool_demo_2",
    tenant_id: "tenant_demo",
    name: "sharepoint-policy",
    description: "Policy document store — read, and human-approved publish.",
    transport: "http",
    endpoint_or_server: "https://sp.acme.example/sites/policy",
    owner_principal_id: "principal:bob",
    region: "us-east-1",
    lifecycle: "active",
    created_at: "2026-04-18T09:30:00Z",
    updated_at: "2026-06-02T11:00:00Z",
  },
];

export const DEMO_ACTIONS: ToolAction[] = [
  {
    id: "act_demo_search",
    tenant_id: "tenant_demo",
    tool_id: "tool_demo_1",
    action: "search",
    resource_type: "document",
    risk_level: "low",
    read_only: true,
    requires_human_approval: false,
    status: "active",
    created_at: "2026-04-02T10:05:00Z",
  },
  {
    id: "act_demo_sp_read",
    tenant_id: "tenant_demo",
    tool_id: "tool_demo_2",
    action: "read",
    resource_type: "document",
    risk_level: "medium",
    read_only: true,
    requires_human_approval: false,
    status: "active",
    created_at: "2026-04-18T09:35:00Z",
  },
  {
    id: "act_demo_sp_publish",
    tenant_id: "tenant_demo",
    tool_id: "tool_demo_2",
    action: "publish",
    resource_type: "document",
    risk_level: "high",
    read_only: false,
    requires_human_approval: true,
    status: "active",
    created_at: "2026-04-18T09:40:00Z",
  },
];

export const DEMO_GRANTS: AgentToolGrant[] = [
  {
    id: "grant_demo_1",
    tenant_id: "tenant_demo",
    agent_id: "ag_demo_1",
    version_id: "agv_demo_1_2",
    tool_id: "tool_demo_1",
    action_id: "act_demo_search",
    resource_scope: "doc://policies/*",
    region_constraint: "us-east-1",
    call_limit_per_run: 20,
    requires_approval: false,
    granted_by: "principal:alice",
    granted_at: "2026-05-09T15:30:00Z",
  },
  {
    id: "grant_demo_2",
    tenant_id: "tenant_demo",
    agent_id: "ag_demo_3",
    version_id: "agv_demo_3_1",
    tool_id: "tool_demo_2",
    action_id: "act_demo_sp_publish",
    resource_scope: "doc://policy-drafts/*",
    region_constraint: "us-east-1",
    call_limit_per_run: 3,
    requires_approval: true,
    granted_by: "principal:bob",
    granted_at: "2026-06-05T11:10:00Z",
  },
];

export const DEMO_RUNS: AgentRun[] = [
  {
    id: "run_demo_1",
    tenant_id: "tenant_demo",
    agent_id: "ag_demo_1",
    delegation_grant_id: "dg_demo_1",
    user_id: "principal:bob",
    purpose: "Evening reconciliation — retrieve sharepoint policy chunks",
    region: "us-east-1",
    status: "completed",
    trace_id: "tr_demo_0001",
    started_at: "2026-06-11T18:02:00Z",
    completed_at: "2026-06-11T18:02:04Z",
  },
  {
    id: "run_demo_2",
    tenant_id: "tenant_demo",
    agent_id: "ag_demo_1",
    delegation_grant_id: "dg_demo_1",
    user_id: "principal:bob",
    purpose: "Reconciliation — attempted access outside granted scope",
    region: "us-east-1",
    status: "denied",
    trace_id: "tr_demo_0002",
    started_at: "2026-06-11T18:03:00Z",
    completed_at: "2026-06-11T18:03:01Z",
    error_code: "resource_outside_grant_scope",
  },
  {
    id: "run_demo_3",
    tenant_id: "tenant_demo",
    agent_id: "ag_demo_3",
    delegation_grant_id: "dg_demo_2",
    user_id: "principal:bob",
    purpose: "Publish approved vendor-pay policy draft",
    region: "us-east-1",
    status: "pending",
    trace_id: "tr_demo_0003",
    started_at: "2026-06-11T19:00:00Z",
  },
];

export const DEMO_DECISIONS: ActionDecision[] = [
  {
    id: "dec_demo_1",
    tenant_id: "tenant_demo",
    agent_id: "ag_demo_1",
    run_id: "run_demo_1",
    delegation_grant_id: "dg_demo_1",
    tool_id: "tool_demo_1",
    action_id: "act_demo_search",
    resource_ref: "doc://policies/treasury-ops",
    decision: "allowed",
    reason: "subject has use tool:<id> relation · action within permitted digest · grant active",
    policy_version: "v1",
    immutable_digest: "0001dec0de…aaaa",
    created_at: "2026-06-11T18:02:03Z",
  },
  {
    id: "dec_demo_2",
    tenant_id: "tenant_demo",
    agent_id: "ag_demo_1",
    run_id: "run_demo_2",
    delegation_grant_id: "dg_demo_1",
    tool_id: "tool_demo_1",
    action_id: "act_demo_search",
    resource_ref: "doc://hr/salaries",
    decision: "denied",
    reason: "resource outside grant resource_scope",
    policy_version: "v1",
    immutable_digest: "0001dec0de…bbbb",
    created_at: "2026-06-11T18:03:00Z",
  },
  {
    id: "dec_demo_3",
    tenant_id: "tenant_demo",
    agent_id: "ag_demo_3",
    run_id: "run_demo_3",
    delegation_grant_id: "dg_demo_2",
    tool_id: "tool_demo_2",
    action_id: "act_demo_sp_publish",
    resource_ref: "doc://policy-drafts/vendor-pay-v3",
    decision: "approval_required",
    reason: "publish requires one-time human approval",
    policy_version: "v1",
    immutable_digest: "0001dec0de…cccc",
    created_at: "2026-06-11T19:00:02Z",
  },
];

export function demoToolDetail(toolId: string): GovToolDetailResp | null {
  const tool = DEMO_TOOLS.find((t) => t.id === toolId);
  if (!tool) return null;
  return { source: "demo", tool, actions: DEMO_ACTIONS.filter((a) => a.tool_id === toolId) };
}

export function demoRunDetail(runId: string): GovRunDetailResp | null {
  const run = DEMO_RUNS.find((r) => r.id === runId);
  if (!run) return null;
  return { source: "demo", run, decisions: DEMO_DECISIONS.filter((d) => d.run_id === runId) };
}

// Idempotency-Key derivation: deterministic per (method, path, body) so
// a network retry of the exact same mutation replays instead of double-
// executing, while distinct requests always get distinct keys.
export function idempotencyKey(method: string, path: string, body: string): string {
  let h = 2166136261;
  const s = `${method}\u0000${path}\u0000${body}`;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return `console-${(h >>> 0).toString(16).padStart(8, "0")}`;
}

export async function govFetch(
  method: string,
  path: string[],
  body?: unknown,
): Promise<NextResponse> {
  const { runtimeUrl, apiKey, secret } = agentRuntimeEnv();
  const url = `${runtimeUrl}/v1/governance/${path.join("/")}`;
  if (!runtimeUrl || !apiKey) {
    return agentError(502, "No API key. Set GROUNDWORK_API_KEY.");
  }
  const raw = body === undefined ? "" : JSON.stringify(body);
  const headers = await agentHeaders(secret, apiKey);
  if (method !== "GET") {
    headers["Idempotency-Key"] = idempotencyKey(method, path.join("/"), raw);
    headers["Content-Type"] = "application/json";
  }
  try {
    const res = await fetch(url, {
      method,
      headers,
      body: method === "GET" ? undefined : raw,
      cache: "no-store",
    });
    const data = await res.json().catch(() => ({}));
    // A 503 means governance isn't wired in this runtime build (in-memory
    // mode) — callers decide whether to fall back to demo data.
    return NextResponse.json(data, { status: res.status });
  } catch (error: unknown) {
    return agentError(502, error instanceof Error ? error.message : "Query runtime unavailable");
  }
}
