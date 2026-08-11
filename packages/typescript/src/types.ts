// Type definitions for the Groundwork query runtime API.
// Mirrors the runtime DTOs (snake_case JSON) and the OpenAPI spec at
// docs/openapi/groundwork.yaml. Keep in sync with the Go structs in
// services/query-runtime/internal/runtime.

export type LifecycleState =
  | 'draft'
  | 'reviewing'
  | 'active'
  | 'disabled'
  | 'revoked'
  | 'retired';

export interface Agent {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  owner_principal_id: string;
  business_purpose: string;
  risk_tier: string;
  lifecycle_state: LifecycleState;
  environment: string;
  created_at: string;
  updated_at: string;
  activated_at?: string | null;
  revoked_at?: string | null;
  active_version_id?: string | null;
  active_version?: string | null;
  version_count?: number;
}

export interface AgentVersion {
  id: string;
  agent_id: string;
  version: string;
  model_provider: string;
  model_name: string;
  prompt_digest: string;
  tool_manifest_digest: string;
  policy_bundle_version: string;
  artifact_digest: string;
  status: string;
  created_at: string;
  approved_at?: string | null;
}

export interface LifecycleEvent {
  id: string;
  agent_id: string;
  event_type: string;
  principal_id: string;
  from_state: string;
  to_state: string;
  reason?: string;
  created_at: string;
}

export interface AgentListResponse {
  agents: Agent[];
  count: number;
}

export interface AgentResponse {
  agent: Agent;
}

export interface AgentDetailResponse {
  agent: Agent;
  versions: AgentVersion[];
  lifecycle_events: LifecycleEvent[];
}

export interface AgentVersionResponse {
  version: AgentVersion;
}

export interface CreateAgentRequest {
  name: string;
  description?: string;
  business_purpose: string;
  risk_tier?: string;
  environment?: string;
}

export interface UpdateAgentRequest {
  name?: string;
  description?: string;
  business_purpose?: string;
  risk_tier?: string;
}

export interface AddAgentVersionRequest {
  version: string;
  model_provider: string;
  model_name: string;
  prompt_digest: string;
  tool_manifest_digest: string;
  policy_bundle_version: string;
  artifact_digest: string;
}

// ---------------------------------------------------------------------
// Governance: tools, actions, grants
// ---------------------------------------------------------------------

export interface Tool {
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
}

export interface ToolAction {
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
}

export interface AgentToolGrant {
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
  revoked_at?: string | null;
}

export interface RegisterToolRequest {
  name: string;
  description?: string;
  transport: string;
  endpoint_or_server?: string;
  owner_principal_id: string;
  region: string;
  manifest_digest?: string;
}

export interface RegisterToolActionRequest {
  action: string;
  resource_type: string;
  risk_level: string;
  read_only: boolean;
  requires_human_approval: boolean;
}

export interface TransitionToolRequest {
  lifecycle: string;
  reason?: string;
}

export interface GrantToolRequest {
  agent_id: string;
  version_id?: string;
  tool_id: string;
  action_id?: string;
  resource_scope?: string;
  region_constraint?: string;
  call_limit_per_run?: number;
  requires_approval?: boolean;
}

export interface ToolListResponse {
  tools: Tool[];
  count: number;
}

export interface ToolResponse {
  tool: Tool;
}

export interface ToolDetailResponse {
  tool: Tool;
  actions: ToolAction[];
}

export interface ToolActionListResponse {
  actions: ToolAction[];
  count: number;
}

export interface ToolActionResponse {
  action: ToolAction;
}

export interface GrantResponse {
  grant: AgentToolGrant;
}

export interface GrantListResponse {
  grants: AgentToolGrant[];
  count: number;
}

// ---------------------------------------------------------------------
// Governance: delegations, runs, evaluation
// ---------------------------------------------------------------------

export interface DelegationGrant {
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
  used_at?: string | null;
  run_id?: string;
  revoked_at?: string | null;
  immutable_digest: string;
  is_agent_delegation?: boolean;
  parent_grant_id?: string;
  root_grant_id?: string;
  delegator_agent_id?: string;
  delegatee_agent_id?: string;
  delegation_depth?: number;
  external_agent_id?: string;
  issued_via?: string;
}

export interface MintDelegationRequest {
  subject_principal_id: string;
  purpose: string;
  permitted_actions: string[];
  ttl_seconds?: number;
}

export interface MintDelegationResponse {
  grant: DelegationGrant;
  token?: string;
  token_already_issued?: boolean;
}

export type RunStatus = 'pending' | 'running' | 'completed' | 'denied' | 'failed' | 'revoked';

export interface AgentRun {
  id: string;
  tenant_id: string;
  agent_id: string;
  delegation_grant_id: string;
  user_id: string;
  purpose: string;
  region: string;
  status: RunStatus;
  trace_id?: string;
  started_at: string;
  completed_at?: string | null;
  error_code?: string | null;
  root_grant_id?: string;
  parent_grant_id?: string;
  delegation_depth?: number;
  chain_verification?: string;
  external_agent_id?: string;
  organization_id?: string;
  customer_principal_id?: string;
  consent_id?: string;
}

export interface ActionDecision {
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
  reason_code?: string;
  policy_version: string;
  immutable_digest: string;
  created_at: string;
  delegation_depth: number;
  chain_verification?: string;
}

export interface ActionApproval {
  id: string;
  tenant_id: string;
  run_id: string;
  tool_id: string;
  action_id: string;
  resource_ref: string;
  approving_principal_id: string;
  decision: string;
  expires_at: string;
  consumed_at?: string | null;
  immutable_digest: string;
  created_at: string;
}

export interface RunActionRequest {
  tool_name: string;
  action: string;
  resource_ref: string;
}

export interface CreateRunRequest {
  delegation_token: string;
  actions: RunActionRequest[];
}

export interface CreateRunResponse {
  run: AgentRun;
  decisions: ActionDecision[];
}

export interface RunListResponse {
  runs: AgentRun[];
  count: number;
}

export interface RunDetailResponse {
  run: AgentRun;
  decisions: ActionDecision[];
}

export interface EvaluateActionRequest {
  delegation_token: string;
  run_id: string;
  tool_name: string;
  action: string;
  resource_ref: string;
  arguments?: Record<string, unknown>;
  trace_id?: string;
}

export interface EvaluateActionResponse {
  decision: ActionDecision;
  allowed: boolean;
}

export interface GateCheck {
  gate: string;
  name: string;
  status: 'passed' | 'failed' | 'skipped' | 'unavailable' | 'required';
  detail: string;
  reason_code?: string;
}

export interface SimulateActionRequest {
  agent_id: string;
  version_id?: string;
  tool_name: string;
  action: string;
  resource_ref: string;
  principal_id?: string;
}

export interface SimulateActionResponse {
  decision: string;
  allowed: boolean;
  reason: string;
  reason_code?: string;
  checks: GateCheck[];
  simulated: boolean;
  simulated_at: string;
}

export interface GovernanceSimulateResponse {
  simulation: SimulateActionResponse;
}

export interface ApproveActionRequest {
  resource_ref: string;
}

export interface ApproveActionResponse {
  approval: ActionApproval;
  denied: boolean;
}

export interface DispatchResponse {
  decision: ActionDecision;
  allowed: boolean;
  dispatch_mode?: string;
  invocation?: unknown;
  response?: unknown;
}

export interface ControlRequest {
  reason: string;
  scope?: string;
}

// ---------------------------------------------------------------------
// Governance: emergency controls, budgets, evidence, outbox
// ---------------------------------------------------------------------

export interface EmergencyControl {
  id: string;
  tenant_id: string;
  entity_type: string;
  entity_id: string;
  control_state: string;
  reason: string;
  scope: string;
  actor_principal_id: string;
  created_at: string;
  updated_at: string;
}

export interface ControlResponse {
  control: EmergencyControl;
}

export interface ControlsResponse {
  controls: EmergencyControl[];
  count: number;
}

export type BudgetScopeType = 'tenant' | 'agent_version' | 'grant';

export interface BudgetPolicy {
  id: string;
  tenant_id: string;
  scope_type: BudgetScopeType;
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
}

export interface BudgetPolicyRequest {
  max_actions_per_run?: number;
  max_denied_per_run?: number;
  max_approval_required_per_run?: number;
  max_tool_calls_per_action_per_run?: number;
  max_run_duration_seconds?: number;
  max_citations_per_query?: number;
}

export interface BudgetUpsertRequest extends BudgetPolicyRequest {
  scope_type: BudgetScopeType;
  agent_version_id?: string;
  grant_id?: string;
}

export interface BudgetResponse {
  budget: BudgetPolicy;
}

export interface BudgetsResponse {
  budgets: BudgetPolicy[];
  count: number;
}

export interface EvidencePage {
  events: EvidenceEvent[];
  next_cursor?: string | null;
  count: number;
}

export interface EvidenceEvent {
  id: string;
  tenant_id: string;
  kind: string;
  entity_id: string;
  data: Record<string, unknown>;
  immutable_digest: string;
  previous_hash?: string;
  created_at: string;
}

export interface EvidenceEventResponse {
  event: EvidenceEvent;
}

export interface TimelineResponse {
  events: EvidenceEvent[];
  count: number;
}

export interface ActivityResponse {
  events: EvidenceEvent[];
  count: number;
}

export interface AuditVerifyResult {
  verified: boolean;
  problem?: string;
  events_checked: number;
  checkpoint?: string;
}

export interface Checkpoint {
  id: string;
  tenant_id: string;
  block_hash: string;
  events_count: number;
  created_at: string;
}

export interface CheckpointsResponse {
  checkpoints: Checkpoint[];
  count: number;
}

export interface OutboxEvent {
  id: string;
  event_type: string;
  entity_id: string;
  payload: Record<string, unknown>;
  status: string;
  attempts: number;
  last_error?: string | null;
  next_attempt_at?: string | null;
  created_at: string;
  updated_at?: string | null;
}

export interface OutboxResponse {
  events: OutboxEvent[];
  next_cursor?: string | null;
  count: number;
}

export interface OutboxEventResponse {
  event: OutboxEvent;
}

// ---------------------------------------------------------------------
// Governance: connectors (Phase 5)
// ---------------------------------------------------------------------

export type ConnectorType = 'rest' | 'mcp';

export interface Connector {
  id: string;
  name: string;
  type: ConnectorType;
  description?: string | null;
  config_digest: string;
  manifest_digest: string;
  status: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ConnectorConfig {
  base_url: string;
  region: string;
  timeout_ms?: number;
  retry_max?: number;
  retry_idempotent_only?: boolean;
  max_response_bytes?: number;
  tls_verify?: boolean;
  secret_ref?: string;
  client_cert_ref?: string;
  allowed_content_types?: string[];
  redaction_fields?: string[];
}

export interface ConnectorActionManifest {
  name: string;
  transport_method: string;
  path_template?: string;
  resource_type?: string;
  risk: string;
  read_only?: boolean;
  requires_approval?: boolean;
  max_request_bytes?: number;
  max_response_bytes?: number;
  allowed_agent_version_ids?: string[];
  args?: string[];
}

export interface ConnectorRegisterRequest {
  name: string;
  type: ConnectorType;
  config: ConnectorConfig;
  actions: ConnectorActionManifest[];
  description?: string;
}

export interface ConnectorDetail {
  id: string;
  name: string;
  type: ConnectorType;
  description?: string | null;
  config: ConnectorConfig;
  actions: ConnectorActionManifest[];
  config_digest: string;
  manifest_digest: string;
  status: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ConnectorManifest {
  actions: ConnectorActionManifest[];
  manifest_digest: string;
}

export interface ConnectorHealth {
  connector_id: string;
  healthy: boolean;
  status_code?: number | null;
  error_code?: string | null;
  latency_ms?: number | null;
  checked_at: string;
}

export interface ConnectorsResponse {
  connectors: Connector[];
  count: number;
}

export interface ConnectorDetailResponse {
  detail: ConnectorDetail;
}

export interface ConnectorManifestResponse {
  actions: ConnectorActionManifest[];
  manifest_digest: string;
}

export interface ConnectorHealthResponse {
  health: ConnectorHealth;
}

export interface ConnectorConfigUpdateRequest {
  timeout_ms?: number;
  retry_max?: number;
  retry_idempotent_only?: boolean;
  max_response_bytes?: number;
  tls_verify?: boolean;
  secret_ref?: string;
  client_cert_ref?: string;
  allowed_content_types?: string[];
  redaction_fields?: string[];
}

// ---------------------------------------------------------------------
// Governance: trust (Phase 6)
// ---------------------------------------------------------------------

export type TrustStatus = 'active' | 'expired' | 'revoked' | 'pending_approval' | 'suspended';

export interface AgentTrustRelationship {
  id: string;
  tenant_id: string;
  parent_agent_id: string;
  child_agent_id?: string | null;
  external_agent_id?: string | null;
  trust_domain: string;
  owner_principal_id: string;
  purpose: string;
  max_delegation_depth: number;
  allowed_tools_actions?: Record<string, string[]> | null;
  region: string;
  expires_at: string;
  status: TrustStatus;
  approval_required: boolean;
  reason?: string | null;
  immutable_digest: string;
  created_at: string;
  updated_at: string;
}

export interface CreateTrustRelationshipRequest {
  child_agent_id: string;
  trust_domain: string;
  purpose: string;
  max_delegation_depth: number;
  allowed_tools_actions?: Record<string, string[]>;
  region: string;
  expires_at: string;
  approval_required?: boolean;
}

export interface ExternalAgent {
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
  allowed_tools_actions?: Record<string, string[]> | null;
  public_key_jwks_ref: string;
  manifest_digest: string;
  security_contact?: string | null;
  lifecycle_state: LifecycleState;
  expires_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateExternalAgentRequest {
  external_agent_id: string;
  agent_id: string;
  organization_id: string;
  verified_issuer: string;
  allowed_audiences: string[];
  auth_method: string;
  trust_tier: string;
  region: string;
  allowed_tools_actions?: Record<string, string[]>;
  public_key_jwks_ref: string;
  manifest_digest?: string;
  security_contact?: string;
  ttl_seconds?: number;
}

export interface ConsentRecord {
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
  expires_at?: string | null;
  immutable_digest: string;
}

export interface CreateConsentRequest {
  organization_id: string;
  external_agent_id: string;
  customer_principal_id: string;
  purpose: string;
  resource_ref_pattern: string;
  ttl_seconds?: number;
}

export interface TransferPolicy {
  id: string;
  tenant_id: string;
  source_region: string;
  target_region: string;
  purpose_pattern: string;
  enabled: boolean;
  created_by: string;
  created_at: string;
}

export interface UpsertTransferPolicyRequest {
  source_region: string;
  target_region: string;
  purpose_pattern: string;
  enabled: boolean;
}

export interface DelegationChainNode {
  grant: DelegationGrant;
  delegator_agent_id?: string | null;
  delegator_agent_name?: string | null;
  delegatee_agent_id?: string | null;
  delegatee_agent_name?: string | null;
  trust_relationship_id: string;
  verified: boolean;
  problem?: string | null;
}

export interface DelegationChain {
  root_grant_id: string;
  leaf_grant_id: string;
  depth: number;
  verified: boolean;
  problem?: string | null;
  nodes: DelegationChainNode[];
}

export type ExternalBudgetScopeType = 'external_agent' | 'organization' | 'customer';

export interface TrustRelationshipResponse {
  relationship: AgentTrustRelationship;
}

export interface TrustRelationshipsResponse {
  relationships: AgentTrustRelationship[];
  count: number;
}

export interface DelegationChainResponse {
  chain: DelegationChain;
}

export interface ChainControlResponse {
  grants_changed: number;
}

export interface ExternalAgentResponse {
  agent: ExternalAgent;
}

export interface ExternalAgentsResponse {
  agents: ExternalAgent[];
  count: number;
}

export interface ExternalAgentHealthResponse {
  external_agent_id: string;
  lifecycle_state: string;
  trust_tier: string;
  region: string;
  expires_at: string;
  healthy: boolean;
  reason?: string;
}

export interface ConsentResponse {
  consent: ConsentRecord;
}

export interface ConsentsResponse {
  consents: ConsentRecord[];
  count: number;
}

export interface TransferPolicyResponse {
  policy: TransferPolicy;
}

export interface TransferPoliciesResponse {
  policies: TransferPolicy[];
  count: number;
}

export interface ExternalBudgetResponse {
  budget: ExternalBudgetPolicy;
}

export interface ExternalBudgetsResponse {
  budgets: ExternalBudgetPolicy[];
  count: number;
}

export interface ExternalBudgetPolicy {
  id: string;
  tenant_id: string;
  scope_type: ExternalBudgetScopeType;
  external_agent_id?: string | null;
  organization_id?: string | null;
  customer_principal_id?: string | null;
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
}

export interface UpsertExternalBudgetRequest {
  max_total_actions?: number;
  max_actions_per_run?: number;
  max_denied_per_run?: number;
  max_approval_required_per_run?: number;
  max_tool_calls_per_action_per_run?: number;
}

export type UsageMetricName =
  | 'agents'
  | 'runs'
  | 'decisions'
  | 'connector_calls'
  | 'exports'
  | 'outbox_deliveries'
  | 'storage_bytes';

export type UsagePeriod = 'monthly' | 'lifetime';

export interface UsageLimit {
  metric: UsageMetricName;
  period: UsagePeriod;
  limit: number;
}

export interface MetricUsage {
  metric: UsageMetricName;
  period: UsagePeriod;
  count: number;
  limit: number;
  remaining: number;
}

export interface UsageResponse {
  tenant_id: string;
  period: string;
  usage: MetricUsage[];
}

export interface UsageLimitsResponse {
  tenant_id: string;
  limits: UsageLimit[];
}

export interface PutUsageLimitsRequest {
  limits: UsageLimit[];
}

export interface ExternalRunAction {
  action: string;
  resource_ref: string;
  args: Record<string, string>;
}

export interface CreateExternalRunRequest {
  external_token: string;
  delegation_token: string;
  actions: ExternalRunAction[];
}

export interface ExternalRun {
  id: string;
  tenant_id: string;
  external_agent_id: string;
  organization_id: string;
  customer_principal_id?: string;
  consent_id: string;
  status: string;
  started_at: string;
  completed_at?: string | null;
  error_code?: string | null;
  trace_id?: string;
}

// ---------------------------------------------------------------------
// Audit, admin, health, query
// ---------------------------------------------------------------------

export type AuditDecisionMode = 'enforce' | 'shadow';

export interface AccessDecisionSummary {
  action: string;
  resource_ref?: string;
  decision: string;
  reason?: string;
}

export interface AuditEntryRead {
  trace_id: string;
  timestamp_utc: string;
  tenant_id: string;
  user_id?: string | null;
  region: string;
  agent_key_id: string;
  agent_key_name: string;
  decision_mode: AuditDecisionMode;
  acl_decision: string;
  reason: string;
  fail_closed: boolean;
  fail_stage?: string | null;
  error_code?: string | null;
  error_message?: string | null;
  candidates_retrieved: number;
  candidates_allowed: number;
  candidates_blocked: number;
  total_latency_ms: number;
  openfga_latency_ms: number;
  qdrant_latency_ms: number;
  circuit_breaker_state: string;
  identity_resolution: string;
  principal_id?: string | null;
  query_hash: string;
  immutable_digest: string;
  previous_hash: string;
  access_decisions?: AccessDecisionSummary[];
}

export interface AuditFilters {
  trace_id?: string;
  tenant_id?: string;
  agent_id?: string;
  decision?: string;
  reason?: string;
  from?: string;
  to?: string;
  limit?: number;
  cursor?: string;
}

export interface AuditListResponse {
  entries: AuditEntryRead[];
  next_cursor?: string | null;
}

export interface ApiKeySummary {
  id: string;
  key_prefix: string;
  name?: string | null;
  scopes: string[];
  created_at: string;
  last_used_at?: string | null;
  expires_at?: string | null;
  revoked: boolean;
}

export interface ApiKeyListResponse {
  api_keys: ApiKeySummary[];
  count: number;
}

export interface CreateApiKeyRequest {
  name?: string;
  scopes: string[];
  expires_at?: string;
}

export interface CreateApiKeyResponse {
  api_key: {
    id: string;
    name?: string | null;
    scopes: string[];
    created_at: string;
    expires_at?: string | null;
  };
  secret: string;
}

export interface HealthResponse {
  status: string;
  service: string;
}

export interface QueryResponse {
  answer: string;
  trace_id: string;
  query_hash?: string;
  sources?: string[];
  candidates?: number;
}

export interface QueryRequest {
  query: string;
  agent_id?: string;
  top_k?: number;
}

export interface ErrorResponse {
  error: string;
  detail?: string;
}
