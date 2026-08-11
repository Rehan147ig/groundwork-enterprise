"""Typed request/response shapes mirroring the TypeScript SDK.

Field names are the wire-level snake_case JSON keys. These TypedDicts
are documentation + type-checking aid; the client accepts and returns
plain dicts.
"""

from typing import Dict, List, Optional, TypedDict, Union


# ---------------------------------------------------------------------
# Agents (Phase 1)
# ---------------------------------------------------------------------

class Agent(TypedDict):
    id: str
    tenant_id: str
    name: str
    description: str
    owner_principal_id: str
    business_purpose: str
    risk_tier: str
    lifecycle_state: str
    environment: str
    created_at: str
    updated_at: str
    activated_at: Optional[str]
    revoked_at: Optional[str]
    active_version_id: Optional[str]
    active_version: Optional[str]
    version_count: Optional[int]


class AgentVersion(TypedDict):
    id: str
    agent_id: str
    version: str
    model_provider: str
    model_name: str
    prompt_digest: str
    tool_manifest_digest: str
    policy_bundle_version: str
    artifact_digest: str
    status: str
    created_at: str
    approved_at: Optional[str]


class LifecycleEvent(TypedDict):
    id: str
    agent_id: str
    event_type: str
    principal_id: str
    from_state: str
    to_state: str
    reason: Optional[str]
    created_at: str


class AgentListResponse(TypedDict):
    agents: List[Agent]
    count: int


class AgentResponse(TypedDict):
    agent: Agent


class AgentDetailResponse(TypedDict):
    agent: Agent
    versions: List[AgentVersion]
    lifecycle_events: List[LifecycleEvent]


class AgentVersionResponse(TypedDict):
    version: AgentVersion


class CreateAgentRequest(TypedDict):
    name: str
    description: Optional[str]
    business_purpose: str
    risk_tier: Optional[str]
    environment: Optional[str]


class UpdateAgentRequest(TypedDict):
    name: Optional[str]
    description: Optional[str]
    business_purpose: Optional[str]
    risk_tier: Optional[str]


class AddAgentVersionRequest(TypedDict):
    version: str
    model_provider: str
    model_name: str
    prompt_digest: str
    tool_manifest_digest: str
    policy_bundle_version: str
    artifact_digest: str


# ---------------------------------------------------------------------
# Governance: tools, actions, grants
# ---------------------------------------------------------------------

class Tool(TypedDict):
    id: str
    tenant_id: str
    name: str
    description: str
    transport: str
    endpoint_or_server: Optional[str]
    owner_principal_id: str
    region: str
    manifest_digest: Optional[str]
    lifecycle: str
    created_at: str
    updated_at: str


class ToolAction(TypedDict):
    id: str
    tenant_id: str
    tool_id: str
    action: str
    resource_type: str
    risk_level: str
    read_only: bool
    requires_human_approval: bool
    status: str
    created_at: str


class AgentToolGrant(TypedDict):
    id: str
    tenant_id: str
    agent_id: str
    version_id: str
    tool_id: str
    action_id: str
    resource_scope: str
    region_constraint: str
    call_limit_per_run: int
    requires_approval: bool
    granted_by: str
    granted_at: str
    revoked_at: Optional[str]


class RegisterToolRequest(TypedDict):
    name: str
    description: Optional[str]
    transport: str
    endpoint_or_server: Optional[str]
    owner_principal_id: str
    region: str
    manifest_digest: Optional[str]


class RegisterToolActionRequest(TypedDict):
    action: str
    resource_type: str
    risk_level: str
    read_only: bool
    requires_human_approval: bool


class TransitionToolRequest(TypedDict):
    lifecycle: str
    reason: Optional[str]


class GrantToolRequest(TypedDict):
    agent_id: str
    version_id: Optional[str]
    tool_id: str
    action_id: Optional[str]
    resource_scope: Optional[str]
    region_constraint: Optional[str]
    call_limit_per_run: Optional[int]
    requires_approval: Optional[bool]


class ToolListResponse(TypedDict):
    tools: List[Tool]
    count: int


class ToolResponse(TypedDict):
    tool: Tool


class ToolDetailResponse(TypedDict):
    tool: Tool
    actions: List[ToolAction]


class ToolActionListResponse(TypedDict):
    actions: List[ToolAction]
    count: int


class ToolActionResponse(TypedDict):
    action: ToolAction


class GrantResponse(TypedDict):
    grant: AgentToolGrant


class GrantListResponse(TypedDict):
    grants: List[AgentToolGrant]
    count: int


# ---------------------------------------------------------------------
# Governance: delegations, runs, evaluation, simulation
# ---------------------------------------------------------------------

class DelegationGrant(TypedDict):
    id: str
    tenant_id: str
    agent_id: str
    agent_version_id: str
    token_jti: str
    delegator_principal_id: str
    subject_principal_id: str
    purpose: str
    region: str
    permitted_actions: Optional[List[str]]
    permitted_actions_digest: str
    issued_at: str
    expires_at: str
    used_at: Optional[str]
    run_id: Optional[str]
    revoked_at: Optional[str]
    immutable_digest: str
    is_agent_delegation: Optional[bool]
    parent_grant_id: Optional[str]
    root_grant_id: Optional[str]
    delegator_agent_id: Optional[str]
    delegatee_agent_id: Optional[str]
    delegation_depth: Optional[int]
    external_agent_id: Optional[str]
    issued_via: Optional[str]


class MintDelegationRequest(TypedDict):
    subject_principal_id: str
    purpose: str
    permitted_actions: List[str]
    ttl_seconds: Optional[int]


class MintDelegationResponse(TypedDict):
    grant: DelegationGrant
    token: Optional[str]
    token_already_issued: Optional[bool]


class AgentRun(TypedDict):
    id: str
    tenant_id: str
    agent_id: str
    delegation_grant_id: str
    user_id: str
    purpose: str
    region: str
    status: str
    trace_id: Optional[str]
    started_at: str
    completed_at: Optional[str]
    error_code: Optional[str]
    root_grant_id: Optional[str]
    parent_grant_id: Optional[str]
    delegation_depth: Optional[int]
    chain_verification: Optional[str]
    external_agent_id: Optional[str]
    organization_id: Optional[str]
    customer_principal_id: Optional[str]
    consent_id: Optional[str]


class ActionDecision(TypedDict):
    id: str
    tenant_id: str
    agent_id: str
    run_id: str
    delegation_grant_id: str
    tool_id: Optional[str]
    action_id: Optional[str]
    resource_ref: str
    decision: str
    reason: str
    reason_code: Optional[str]
    policy_version: str
    immutable_digest: str
    created_at: str
    delegation_depth: int
    chain_verification: Optional[str]


class ActionApproval(TypedDict):
    id: str
    tenant_id: str
    run_id: str
    tool_id: str
    action_id: str
    resource_ref: str
    approving_principal_id: str
    decision: str
    expires_at: str
    consumed_at: Optional[str]
    immutable_digest: str
    created_at: str


class RunActionRequest(TypedDict):
    tool_name: str
    action: str
    resource_ref: str


class CreateRunRequest(TypedDict):
    delegation_token: str
    actions: List[RunActionRequest]


class CreateRunResponse(TypedDict):
    run: AgentRun
    decisions: List[ActionDecision]


class RunListResponse(TypedDict):
    runs: List[AgentRun]
    count: int


class RunDetailResponse(TypedDict):
    run: AgentRun
    decisions: List[ActionDecision]


class EvaluateActionRequest(TypedDict):
    delegation_token: str
    run_id: str
    tool_name: str
    action: str
    resource_ref: str
    arguments: Optional[Dict[str, object]]
    trace_id: Optional[str]


class EvaluateActionResponse(TypedDict):
    decision: ActionDecision
    allowed: bool


class GateCheck(TypedDict):
    gate: str
    name: str
    status: str  # passed | failed | skipped | unavailable | required
    detail: str
    reason_code: Optional[str]


class SimulateActionRequest(TypedDict):
    agent_id: str
    version_id: Optional[str]
    tool_name: str
    action: str
    resource_ref: str
    principal_id: Optional[str]


class SimulateActionResponse(TypedDict):
    decision: str  # allowed | denied | approval_required | fail_closed
    allowed: bool
    reason: str
    reason_code: Optional[str]
    checks: List[GateCheck]
    simulated: bool
    simulated_at: str


class GovernanceSimulateResponse(TypedDict):
    simulation: SimulateActionResponse


class ApproveActionRequest(TypedDict):
    resource_ref: str


class ApproveActionResponse(TypedDict):
    approval: ActionApproval
    denied: bool


class DispatchResponse(TypedDict):
    decision: ActionDecision
    allowed: bool
    dispatch_mode: Optional[str]
    invocation: Optional[object]
    response: Optional[object]


class ControlRequest(TypedDict):
    reason: str
    scope: Optional[str]


# ---------------------------------------------------------------------
# Governance: emergency controls, budgets, evidence, outbox
# ---------------------------------------------------------------------

class EmergencyControl(TypedDict):
    id: str
    tenant_id: str
    entity_type: str
    entity_id: str
    control_state: str
    reason: str
    scope: str
    actor_principal_id: str
    created_at: str
    updated_at: str


class ControlResponse(TypedDict):
    control: EmergencyControl


class ControlsResponse(TypedDict):
    controls: List[EmergencyControl]
    count: int


class BudgetPolicy(TypedDict):
    id: str
    tenant_id: str
    scope_type: str  # tenant | agent_version | grant
    agent_version_id: Optional[str]
    grant_id: Optional[str]
    max_actions_per_run: int
    max_denied_per_run: int
    max_approval_required_per_run: int
    max_tool_calls_per_action_per_run: int
    max_run_duration_seconds: int
    max_citations_per_query: int
    created_by: str
    created_at: str
    updated_at: str


class BudgetUpsertRequest(TypedDict):
    scope_type: str
    agent_version_id: Optional[str]
    grant_id: Optional[str]
    max_actions_per_run: Optional[int]
    max_denied_per_run: Optional[int]
    max_approval_required_per_run: Optional[int]
    max_tool_calls_per_action_per_run: Optional[int]
    max_run_duration_seconds: Optional[int]
    max_citations_per_query: Optional[int]


class BudgetResponse(TypedDict):
    budget: BudgetPolicy


class BudgetsResponse(TypedDict):
    budgets: List[BudgetPolicy]
    count: int


class EvidenceEvent(TypedDict):
    id: str
    tenant_id: str
    kind: str
    entity_id: str
    data: Dict[str, object]
    immutable_digest: str
    previous_hash: Optional[str]
    created_at: str


class EvidencePage(TypedDict):
    events: List[EvidenceEvent]
    next_cursor: Optional[str]
    count: int


class EvidenceEventResponse(TypedDict):
    event: EvidenceEvent


class TimelineResponse(TypedDict):
    events: List[EvidenceEvent]
    count: int


class ActivityResponse(TypedDict):
    events: List[EvidenceEvent]
    count: int


class Checkpoint(TypedDict):
    id: str
    tenant_id: str
    block_hash: str
    events_count: int
    created_at: str


class CheckpointsResponse(TypedDict):
    checkpoints: List[Checkpoint]
    count: int


class OutboxEvent(TypedDict):
    id: str
    event_type: str
    entity_id: str
    payload: Dict[str, object]
    status: str
    attempts: int
    last_error: Optional[str]
    next_attempt_at: Optional[str]
    created_at: str
    updated_at: Optional[str]


class OutboxResponse(TypedDict):
    events: List[OutboxEvent]
    next_cursor: Optional[str]
    count: int


class OutboxEventResponse(TypedDict):
    event: OutboxEvent


# ---------------------------------------------------------------------
# Governance: connectors (Phase 5)
# ---------------------------------------------------------------------

class ConnectorConfig(TypedDict):
    base_url: str
    region: str
    timeout_ms: Optional[int]
    retry_max: Optional[int]
    retry_idempotent_only: Optional[bool]
    max_response_bytes: Optional[int]
    tls_verify: Optional[bool]
    secret_ref: Optional[str]
    client_cert_ref: Optional[str]
    allowed_content_types: Optional[List[str]]
    redaction_fields: Optional[List[str]]


class ConnectorActionManifest(TypedDict):
    name: str
    transport_method: str
    path_template: Optional[str]
    resource_type: Optional[str]
    risk: str
    read_only: Optional[bool]
    requires_approval: Optional[bool]
    max_request_bytes: Optional[int]
    max_response_bytes: Optional[int]
    allowed_agent_version_ids: Optional[List[str]]
    args: Optional[List[str]]


class ConnectorRegisterRequest(TypedDict):
    name: str
    type: str  # rest | mcp
    config: ConnectorConfig
    actions: List[ConnectorActionManifest]
    description: Optional[str]


class ConnectorDetail(TypedDict):
    id: str
    name: str
    type: str
    description: Optional[str]
    config: ConnectorConfig
    actions: List[ConnectorActionManifest]
    config_digest: str
    manifest_digest: str
    status: str
    created_by: str
    created_at: str
    updated_at: str


class ConnectorManifest(TypedDict):
    actions: List[ConnectorActionManifest]
    manifest_digest: str


class ConnectorHealth(TypedDict):
    connector_id: str
    healthy: bool
    status_code: Optional[int]
    error_code: Optional[str]
    latency_ms: Optional[int]
    checked_at: str


class ConnectorsResponse(TypedDict):
    connectors: List[ConnectorDetail]
    count: int


class ConnectorDetailResponse(TypedDict):
    detail: ConnectorDetail


class ConnectorManifestResponse(TypedDict):
    actions: List[ConnectorActionManifest]
    manifest_digest: str


class ConnectorHealthResponse(TypedDict):
    health: ConnectorHealth


class ConnectorConfigUpdateRequest(TypedDict):
    timeout_ms: Optional[int]
    retry_max: Optional[int]
    retry_idempotent_only: Optional[bool]
    max_response_bytes: Optional[int]
    tls_verify: Optional[bool]
    secret_ref: Optional[str]
    client_cert_ref: Optional[str]
    allowed_content_types: Optional[List[str]]
    redaction_fields: Optional[List[str]]


# ---------------------------------------------------------------------
# Governance: trust, external agents, consents, transfers, budgets (Phase 6)
# ---------------------------------------------------------------------

class AgentTrustRelationship(TypedDict):
    id: str
    tenant_id: str
    parent_agent_id: str
    child_agent_id: Optional[str]
    external_agent_id: Optional[str]
    trust_domain: str
    owner_principal_id: str
    purpose: str
    max_delegation_depth: int
    allowed_tools_actions: Optional[Dict[str, List[str]]]
    region: str
    expires_at: str
    status: str
    approval_required: bool
    reason: Optional[str]
    immutable_digest: str
    created_at: str
    updated_at: str


class CreateTrustRelationshipRequest(TypedDict):
    child_agent_id: str
    trust_domain: str
    purpose: str
    max_delegation_depth: int
    allowed_tools_actions: Optional[Dict[str, List[str]]]
    region: str
    expires_at: str
    approval_required: Optional[bool]


class ExternalAgent(TypedDict):
    id: str
    external_agent_id: str
    agent_id: str
    organization_id: str
    tenant_id: str
    owner_principal_id: str
    verified_issuer: str
    allowed_audiences: List[str]
    auth_method: str
    trust_tier: str
    region: str
    allowed_tools_actions: Optional[Dict[str, List[str]]]
    public_key_jwks_ref: str
    manifest_digest: str
    security_contact: Optional[str]
    lifecycle_state: str
    expires_at: Optional[str]
    created_at: str
    updated_at: str


class CreateExternalAgentRequest(TypedDict):
    external_agent_id: str
    agent_id: str
    organization_id: str
    verified_issuer: str
    allowed_audiences: List[str]
    auth_method: str
    trust_tier: str
    region: str
    allowed_tools_actions: Optional[Dict[str, List[str]]]
    public_key_jwks_ref: str
    manifest_digest: Optional[str]
    security_contact: Optional[str]
    ttl_seconds: Optional[int]


class ConsentRecord(TypedDict):
    id: str
    tenant_id: str
    organization_id: str
    external_agent_id: str
    customer_principal_id: str
    purpose: str
    resource_ref_pattern: str
    status: str
    granted_by: str
    granted_at: str
    expires_at: Optional[str]
    immutable_digest: str


class CreateConsentRequest(TypedDict):
    organization_id: str
    external_agent_id: str
    customer_principal_id: str
    purpose: str
    resource_ref_pattern: str
    ttl_seconds: Optional[int]


class TransferPolicy(TypedDict):
    id: str
    tenant_id: str
    source_region: str
    target_region: str
    purpose_pattern: str
    enabled: bool
    created_by: str
    created_at: str


class UpsertTransferPolicyRequest(TypedDict):
    source_region: str
    target_region: str
    purpose_pattern: str
    enabled: bool


class DelegationChainNode(TypedDict):
    grant: DelegationGrant
    delegator_agent_id: Optional[str]
    delegator_agent_name: Optional[str]
    delegatee_agent_id: Optional[str]
    delegatee_agent_name: Optional[str]
    trust_relationship_id: str
    verified: bool
    problem: Optional[str]


class DelegationChain(TypedDict):
    root_grant_id: str
    leaf_grant_id: str
    depth: int
    verified: bool
    problem: Optional[str]
    nodes: List[DelegationChainNode]


class TrustRelationshipResponse(TypedDict):
    relationship: AgentTrustRelationship


class TrustRelationshipsResponse(TypedDict):
    relationships: List[AgentTrustRelationship]
    count: int


class DelegationChainResponse(TypedDict):
    chain: DelegationChain


class ChainControlResponse(TypedDict):
    grants_changed: int


class ExternalAgentResponse(TypedDict):
    agent: ExternalAgent


class ExternalAgentsResponse(TypedDict):
    agents: List[ExternalAgent]
    count: int


class ExternalAgentHealthResponse(TypedDict):
    external_agent_id: str
    lifecycle_state: str
    trust_tier: str
    region: str
    expires_at: str
    healthy: bool
    reason: Optional[str]


class ConsentResponse(TypedDict):
    consent: ConsentRecord


class ConsentsResponse(TypedDict):
    consents: List[ConsentRecord]
    count: int


class TransferPolicyResponse(TypedDict):
    policy: TransferPolicy


class TransferPoliciesResponse(TypedDict):
    policies: List[TransferPolicy]
    count: int


class ExternalBudgetPolicy(TypedDict):
    id: str
    tenant_id: str
    scope_type: str  # external_agent | organization | customer
    external_agent_id: Optional[str]
    organization_id: Optional[str]
    customer_principal_id: Optional[str]
    max_total_actions: int
    max_actions_per_run: int
    max_denied_per_run: int
    max_approval_required_per_run: int
    max_tool_calls_per_action_per_run: int
    actions_count: int
    denied_count: int
    approval_required_count: int
    tool_calls_count: int
    created_by: str
    created_at: str
    updated_at: str


class ExternalBudgetResponse(TypedDict):
    budget: ExternalBudgetPolicy


class ExternalBudgetsResponse(TypedDict):
    budgets: List[ExternalBudgetPolicy]
    count: int


class UpsertExternalBudgetRequest(TypedDict):
    max_total_actions: Optional[int]
    max_actions_per_run: Optional[int]
    max_denied_per_run: Optional[int]
    max_approval_required_per_run: Optional[int]
    max_tool_calls_per_action_per_run: Optional[int]


class UsageLimit(TypedDict):
    metric: str
    period: str
    limit: int


class MetricUsage(TypedDict):
    metric: str
    period: str
    count: int
    limit: int
    remaining: int


class UsageResponse(TypedDict):
    tenant_id: str
    period: str
    usage: List[MetricUsage]


class UsageLimitsResponse(TypedDict):
    tenant_id: str
    limits: List[UsageLimit]


class PutUsageLimitsRequest(TypedDict):
    limits: List[UsageLimit]


class ExternalRunAction(TypedDict):
    action: str
    resource_ref: str
    args: Dict[str, str]


class CreateExternalRunRequest(TypedDict):
    external_token: str
    delegation_token: str
    actions: List[ExternalRunAction]


class ExternalRun(TypedDict):
    id: str
    tenant_id: str
    external_agent_id: str
    organization_id: str
    customer_principal_id: Optional[str]
    consent_id: str
    status: str
    started_at: str
    completed_at: Optional[str]
    error_code: Optional[str]
    trace_id: Optional[str]


# ---------------------------------------------------------------------
# Audit, admin, health, query
# ---------------------------------------------------------------------

class AccessDecisionSummary(TypedDict):
    action: str
    resource_ref: Optional[str]
    decision: str
    reason: Optional[str]


class AuditEntryRead(TypedDict):
    trace_id: str
    timestamp_utc: str
    tenant_id: str
    user_id: Optional[str]
    region: str
    agent_key_id: str
    agent_key_name: str
    decision_mode: str
    acl_decision: str
    reason: str
    fail_closed: bool
    fail_stage: Optional[str]
    error_code: Optional[str]
    error_message: Optional[str]
    candidates_retrieved: int
    candidates_allowed: int
    candidates_blocked: int
    total_latency_ms: int
    openfga_latency_ms: int
    qdrant_latency_ms: int
    circuit_breaker_state: str
    identity_resolution: str
    principal_id: Optional[str]
    query_hash: str
    immutable_digest: str
    previous_hash: str
    access_decisions: Optional[List[AccessDecisionSummary]]


class AuditFilters(TypedDict, total=False):
    trace_id: str
    tenant_id: str
    agent_id: str
    decision: str
    reason: str
    from_: str
    to: str
    limit: int
    cursor: str


class AuditListResponse(TypedDict):
    entries: List[AuditEntryRead]
    next_cursor: Optional[str]


class ApiKeySummary(TypedDict):
    id: str
    key_prefix: str
    name: Optional[str]
    scopes: List[str]
    created_at: str
    last_used_at: Optional[str]
    expires_at: Optional[str]
    revoked: bool


class ApiKeyListResponse(TypedDict):
    api_keys: List[ApiKeySummary]
    count: int


class CreateApiKeyRequest(TypedDict):
    name: Optional[str]
    scopes: List[str]
    expires_at: Optional[str]


class CreateApiKeyResponse(TypedDict):
    api_key: Dict[str, object]
    secret: str


class HealthResponse(TypedDict):
    status: str
    service: str


class QueryResponse(TypedDict):
    answer: str
    trace_id: str
    query_hash: Optional[str]
    sources: Optional[List[str]]
    candidates: Optional[int]


class QueryRequest(TypedDict):
    query: str
    agent_id: Optional[str]
    top_k: Optional[int]


class ErrorResponse(TypedDict):
    error: str
    detail: Optional[str]


Json = Union[dict, list, str, int, float, bool, None]
