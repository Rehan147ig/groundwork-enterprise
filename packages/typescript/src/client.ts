import { GroundworkError, parseErrorResponse } from './errors.js';
import type {
  ActionApproval,
  ActionDecision,
  ActivityResponse,
  Agent,
  AgentDetailResponse,
  AgentListResponse,
  AgentResponse,
  AgentRun,
  AgentTrustRelationship,
  AgentVersionResponse,
  ApiKeyListResponse,
  ApproveActionResponse,
  AuditFilters,
  AuditListResponse,
  BudgetResponse,
  BudgetUpsertRequest,
  BudgetsResponse,
  CheckpointsResponse,
  ConnectorConfigUpdateRequest,
  ConnectorDetailResponse,
  ConnectorHealthResponse,
  ConnectorManifestResponse,
  ConnectorRegisterRequest,
  ConnectorsResponse,
  ConsentRecord,
  ControlResponse,
  ControlsResponse,
  CreateAgentRequest,
  CreateApiKeyRequest,
  CreateApiKeyResponse,
  CreateConsentRequest,
  CreateExternalAgentRequest,
  CreateExternalRunRequest,
  CreateRunRequest,
  CreateRunResponse,
  CreateTrustRelationshipRequest,
  ConsentResponse,
  ConsentsResponse,
  ChainControlResponse,
  DelegationChain,
  DelegationChainResponse,
  DelegationGrant,
  DispatchResponse,
  EvidenceEventResponse,
  EvidencePage,
  EvaluateActionRequest,
  EvaluateActionResponse,
  GateCheck,
  GovernanceSimulateResponse,
  SimulateActionRequest,
  SimulateActionResponse,
  ExternalAgentHealthResponse,
  ExternalAgentResponse,
  ExternalAgentsResponse,
  ExternalBudgetResponse,
  ExternalBudgetsResponse,
  ExternalRun,
  GrantListResponse,
  GrantResponse,
  GrantToolRequest,
  HealthResponse,
  MintDelegationRequest,
  MintDelegationResponse,
  OutboxEventResponse,
  OutboxResponse,
  QueryRequest,
  QueryResponse,
  RegisterToolActionRequest,
  RegisterToolRequest,
  AddAgentVersionRequest,
  RunDetailResponse,
  RunListResponse,
  Tool,
  ToolActionListResponse,
  ToolActionResponse,
  ToolDetailResponse,
  ToolListResponse,
  ToolResponse,
  TimelineResponse,
  TransferPoliciesResponse,
  TransferPolicyResponse,
  TransferPolicy,
  TransitionToolRequest,
  TrustRelationshipResponse,
  TrustRelationshipsResponse,
  UpdateAgentRequest,
  UpsertExternalBudgetRequest,
  UpsertTransferPolicyRequest,
  UsageLimit,
  UsageLimitsResponse,
  UsageResponse,
  PutUsageLimitsRequest,
} from './types.js';

export type AssertionProvider = () => string | Promise<string>;

export interface GroundworkClientOptions {
  baseUrl: string;
  apiKey: string;
  assertion?: string | AssertionProvider;
  timeoutMs?: number;
  fetch?: typeof globalThis.fetch;
}

interface RequestOptions {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  idempotencyKey?: string;
}

export class GroundworkClient {
  readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly assertion?: string | AssertionProvider;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof globalThis.fetch;

  constructor(options: GroundworkClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.apiKey = options.apiKey;
    this.assertion = options.assertion;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.fetchImpl = options.fetch ?? globalThis.fetch;

    if (typeof this.fetchImpl !== 'function') {
      throw new Error('No fetch implementation found: use Node >= 18 or pass a fetch polyfill');
    }
  }

  private async request<T>(options: RequestOptions): Promise<T> {
    const url = new URL(options.path, `${this.baseUrl}/`);
    if (options.query) {
      for (const [key, value] of Object.entries(options.query)) {
        if (value !== undefined) {
          url.searchParams.set(key, String(value));
        }
      }
    }

    const headers: Record<string, string> = {
      'X-Groundwork-API-Key': this.apiKey,
    };
    if (this.assertion !== undefined) {
      const assertion = typeof this.assertion === 'function' ? await this.assertion() : this.assertion;
      if (assertion) {
        headers['X-Groundwork-User-Assertion'] = assertion;
      }
    }
    if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    if (options.idempotencyKey) {
      headers['Idempotency-Key'] = options.idempotencyKey;
    }

    const signal = AbortSignal.timeout(this.timeoutMs);
    let res: Response;
    try {
      res = await this.fetchImpl(url.toString(), {
        method: options.method,
        headers,
        body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
        signal,
      });
    } catch (err) {
      if (err instanceof Error && err.name === 'TimeoutError') {
        throw new GroundworkError(`Groundwork API request timed out after ${this.timeoutMs}ms`, 0, 'timeout', null, new Headers());
      }
      throw new GroundworkError(`Groundwork API request failed: ${err instanceof Error ? err.message : String(err)}`, 0, 'network', null, new Headers());
    }

    if (!res.ok) {
      throw await parseErrorResponse(res);
    }
    if (res.status === 204) {
      return undefined as T;
    }
    return (await res.json()) as T;
  }

  // ---- health ----

  health(): Promise<HealthResponse> {
    return this.request<HealthResponse>({ method: 'GET', path: '/healthz' });
  }

  // ---- query ----

  query(body: QueryRequest): Promise<QueryResponse> {
    return this.request<QueryResponse>({ method: 'POST', path: '/v1/query', body });
  }

  // ---- audit ----

  audit(filters: AuditFilters = {}): Promise<AuditListResponse> {
    return this.request<AuditListResponse>({
      method: 'GET',
      path: '/v1/audit',
      query: {
        trace_id: filters.trace_id,
        tenant_id: filters.tenant_id,
        agent_id: filters.agent_id,
        decision: filters.decision,
        reason: filters.reason,
        from: filters.from,
        to: filters.to,
        limit: filters.limit,
        cursor: filters.cursor,
      },
    });
  }

  // ---- admin: api keys ----

  listApiKeys(): Promise<ApiKeyListResponse> {
    return this.request<ApiKeyListResponse>({ method: 'GET', path: '/v1/admin/api-keys' });
  }

  createApiKey(body: CreateApiKeyRequest): Promise<CreateApiKeyResponse> {
    return this.request<CreateApiKeyResponse>({ method: 'POST', path: '/v1/admin/api-keys', body });
  }

  revokeApiKey(keyId: string): Promise<void> {
    return this.request<void>({ method: 'POST', path: `/v1/admin/api-keys/${encodeURIComponent(keyId)}/revoke` });
  }

  // ---- agents ----

  listAgents(state?: string, environment?: string): Promise<AgentListResponse> {
    return this.request<AgentListResponse>({
      method: 'GET',
      path: '/v1/agents',
      query: { state, environment },
    });
  }

  createAgent(body: CreateAgentRequest): Promise<AgentResponse> {
    return this.request<AgentResponse>({ method: 'POST', path: '/v1/agents', body });
  }

  getAgent(agentId: string): Promise<AgentDetailResponse> {
    return this.request<AgentDetailResponse>({ method: 'GET', path: `/v1/agents/${encodeURIComponent(agentId)}` });
  }

  updateAgent(agentId: string, body: UpdateAgentRequest): Promise<AgentResponse> {
    return this.request<AgentResponse>({ method: 'PATCH', path: `/v1/agents/${encodeURIComponent(agentId)}`, body });
  }

  activateAgent(agentId: string, reason: string): Promise<AgentResponse> {
    return this.request<AgentResponse>({
      method: 'POST',
      path: `/v1/agents/${encodeURIComponent(agentId)}/activate`,
      body: { reason },
    });
  }

  suspendAgent(agentId: string, reason: string): Promise<AgentResponse> {
    return this.request<AgentResponse>({
      method: 'POST',
      path: `/v1/agents/${encodeURIComponent(agentId)}/suspend`,
      body: { reason },
    });
  }

  revokeAgent(agentId: string, reason: string): Promise<AgentResponse> {
    return this.request<AgentResponse>({
      method: 'POST',
      path: `/v1/agents/${encodeURIComponent(agentId)}/revoke`,
      body: { reason },
    });
  }

  retireAgent(agentId: string, reason: string): Promise<AgentResponse> {
    return this.request<AgentResponse>({
      method: 'POST',
      path: `/v1/agents/${encodeURIComponent(agentId)}/retire`,
      body: { reason },
    });
  }

  addAgentVersion(agentId: string, body: AddAgentVersionRequest): Promise<AgentVersionResponse> {
    return this.request<AgentVersionResponse>({ method: 'POST', path: `/v1/agents/${encodeURIComponent(agentId)}/versions`, body });
  }

  // ---- governance: tools ----

  listTools(): Promise<ToolListResponse> {
    return this.request<ToolListResponse>({ method: 'GET', path: '/v1/governance/tools' });
  }

  registerTool(body: RegisterToolRequest): Promise<ToolResponse> {
    return this.request<ToolResponse>({ method: 'POST', path: '/v1/governance/tools', body });
  }

  getTool(toolId: string): Promise<ToolDetailResponse> {
    return this.request<ToolDetailResponse>({ method: 'GET', path: `/v1/governance/tools/${encodeURIComponent(toolId)}` });
  }

  registerToolAction(toolId: string, body: RegisterToolActionRequest): Promise<ToolActionResponse> {
    return this.request<ToolActionResponse>({
      method: 'POST',
      path: `/v1/governance/tools/${encodeURIComponent(toolId)}/actions`,
      body,
    });
  }

  listToolActions(toolId: string): Promise<ToolActionListResponse> {
    return this.request<ToolActionListResponse>({ method: 'GET', path: `/v1/governance/tools/${encodeURIComponent(toolId)}/actions` });
  }

  toolLifecycle(toolId: string, body: TransitionToolRequest): Promise<ToolResponse> {
    return this.request<ToolResponse>({
      method: 'POST',
      path: `/v1/governance/tools/${encodeURIComponent(toolId)}/lifecycle`,
      body,
    });
  }

  killSwitchTool(toolId: string, reason: string, scope?: string): Promise<ControlResponse> {
    return this.controlMutation(`/v1/governance/tools/${encodeURIComponent(toolId)}/kill-switch`, reason, scope);
  }

  resumeTool(toolId: string, reason: string, scope?: string): Promise<ControlResponse> {
    return this.controlMutation(`/v1/governance/tools/${encodeURIComponent(toolId)}/resume`, reason, scope);
  }

  // ---- governance: grants ----

  grantTool(body: GrantToolRequest): Promise<GrantResponse> {
    return this.request<GrantResponse>({ method: 'POST', path: '/v1/governance/grants', body });
  }

  listAgentGrants(agentId: string): Promise<GrantListResponse> {
    return this.request<GrantListResponse>({ method: 'GET', path: `/v1/governance/agents/${encodeURIComponent(agentId)}/grants` });
  }

  revokeGrant(grantId: string, reason: string): Promise<GrantResponse> {
    return this.request<GrantResponse>({
      method: 'POST',
      path: `/v1/governance/grants/${encodeURIComponent(grantId)}/revoke`,
      body: { reason },
    });
  }

  // ---- governance: delegations ----

  mintDelegation(body: MintDelegationRequest, idempotencyKey: string): Promise<MintDelegationResponse> {
    return this.request<MintDelegationResponse>({ method: 'POST', path: '/v1/governance/delegations', body, idempotencyKey });
  }

  listDelegationGrants(): Promise<GrantListResponse> {
    return this.request<GrantListResponse>({ method: 'GET', path: '/v1/governance/delegations' });
  }

  getDelegationChain(grantId: string): Promise<DelegationChain> {
    return this.request<DelegationChain>({ method: 'GET', path: `/v1/governance/delegations/${encodeURIComponent(grantId)}/chain` });
  }

  revokeDelegation(grantId: string, reason: string, scope?: string): Promise<ControlResponse> {
    return this.controlMutation(`/v1/governance/delegations/${encodeURIComponent(grantId)}/chain/revoke`, reason, scope);
  }

  suspendDelegationChain(grantId: string, reason: string, scope?: string): Promise<ControlResponse> {
    return this.controlMutation(`/v1/governance/delegations/${encodeURIComponent(grantId)}/chain/suspend`, reason, scope);
  }

  resumeDelegationChain(grantId: string, reason: string, scope?: string): Promise<ControlResponse> {
    return this.controlMutation(`/v1/governance/delegations/${encodeURIComponent(grantId)}/chain/resume`, reason, scope);
  }

  getRunDelegationChain(runId: string): Promise<DelegationChain> {
    return this.request<DelegationChain>({ method: 'GET', path: `/v1/governance/runs/${encodeURIComponent(runId)}/delegation-chain` });
  }

  // ---- governance: runs ----

  createRun(body: CreateRunRequest, idempotencyKey?: string): Promise<CreateRunResponse> {
    return this.request<CreateRunResponse>({ method: 'POST', path: '/v1/governance/runs', body, idempotencyKey });
  }

  listRuns(query?: { agent_id?: string; status?: string; cursor?: string; limit?: number }): Promise<RunListResponse> {
    return this.request<RunListResponse>({
      method: 'GET',
      path: '/v1/governance/runs',
      query: { agent_id: query?.agent_id, status: query?.status, cursor: query?.cursor, limit: query?.limit },
    });
  }

  getRun(runId: string): Promise<RunDetailResponse> {
    return this.request<RunDetailResponse>({ method: 'GET', path: `/v1/governance/runs/${encodeURIComponent(runId)}` });
  }

  evaluateAction(body: EvaluateActionRequest): Promise<EvaluateActionResponse> {
    return this.request<EvaluateActionResponse>({ method: 'POST', path: `/v1/governance/runs/${encodeURIComponent(body.run_id)}/evaluate`, body });
  }

  simulateAction(body: SimulateActionRequest): Promise<GovernanceSimulateResponse> {
    return this.request<GovernanceSimulateResponse>({ method: 'POST', path: '/v1/governance/simulate', body });
  }

  approveAction(runId: string, actionId: string, resourceRef: string): Promise<ApproveActionResponse> {
    return this.request<ApproveActionResponse>({
      method: 'POST',
      path: `/v1/governance/runs/${encodeURIComponent(runId)}/approve/${encodeURIComponent(actionId)}`,
      body: { resource_ref: resourceRef },
    });
  }

  denyAction(runId: string, actionId: string, resourceRef: string): Promise<ApproveActionResponse> {
    return this.request<ApproveActionResponse>({
      method: 'POST',
      path: `/v1/governance/runs/${encodeURIComponent(runId)}/deny/${encodeURIComponent(actionId)}`,
      body: { resource_ref: resourceRef },
    });
  }

  dispatch(body: EvaluateActionRequest): Promise<DispatchResponse> {
    return this.request<DispatchResponse>({ method: 'POST', path: '/v1/governance/dispatch', body });
  }

  terminateRun(runId: string, reason: string, scope?: string): Promise<ControlResponse> {
    return this.controlMutation(`/v1/governance/runs/${encodeURIComponent(runId)}/terminate`, reason, scope);
  }

  killSwitchAgent(agentId: string, reason: string, scope?: string): Promise<ControlResponse> {
    return this.controlMutation(`/v1/governance/agents/${encodeURIComponent(agentId)}/kill-switch`, reason, scope);
  }

  resumeAgent(agentId: string, reason: string, scope?: string): Promise<ControlResponse> {
    return this.controlMutation(`/v1/governance/agents/${encodeURIComponent(agentId)}/resume`, reason, scope);
  }

  killSwitchAgentVersion(versionId: string, reason: string, scope?: string): Promise<ControlResponse> {
    return this.controlMutation(`/v1/governance/agent-versions/${encodeURIComponent(versionId)}/kill-switch`, reason, scope);
  }

  resumeAgentVersion(versionId: string, reason: string, scope?: string): Promise<ControlResponse> {
    return this.controlMutation(`/v1/governance/agent-versions/${encodeURIComponent(versionId)}/resume`, reason, scope);
  }

  listEmergencyControls(): Promise<ControlsResponse> {
    return this.request<ControlsResponse>({ method: 'GET', path: '/v1/governance/emergency-controls' });
  }

  private controlMutation(path: string, reason: string, scope?: string): Promise<ControlResponse> {
    return this.request<ControlResponse>({ method: 'POST', path, body: { reason, scope } });
  }

  // ---- governance: budgets ----

  upsertBudget(body: BudgetUpsertRequest): Promise<BudgetResponse> {
    return this.request<BudgetResponse>({ method: 'POST', path: '/v1/governance/budgets', body });
  }

  getEffectiveBudget(): Promise<BudgetResponse> {
    return this.request<BudgetResponse>({ method: 'GET', path: '/v1/governance/budgets/effective' });
  }

  listBudgets(): Promise<BudgetsResponse> {
    return this.request<BudgetsResponse>({ method: 'GET', path: '/v1/governance/budgets' });
  }

  // ---- governance: evidence ----

  queryEvidence(query?: { tenant_id?: string; kind?: string; entity_id?: string; from?: string; to?: string; cursor?: string; limit?: number }): Promise<EvidencePage> {
    return this.request<EvidencePage>({
      method: 'GET',
      path: '/v1/governance/evidence',
      query: {
        tenant_id: query?.tenant_id,
        kind: query?.kind,
        entity_id: query?.entity_id,
        from: query?.from,
        to: query?.to,
        cursor: query?.cursor,
        limit: query?.limit,
      },
    });
  }

  getEvidenceEvent(eventId: string): Promise<EvidenceEventResponse> {
    return this.request<EvidenceEventResponse>({ method: 'GET', path: `/v1/governance/evidence/${encodeURIComponent(eventId)}` });
  }

  getEvidenceProvenance(eventId: string): Promise<EvidenceEventResponse> {
    return this.request<EvidenceEventResponse>({
      method: 'GET',
      path: `/v1/governance/evidence/${encodeURIComponent(eventId)}/provenance`,
    });
  }

  getRunTimeline(runId: string): Promise<TimelineResponse> {
    return this.request<TimelineResponse>({ method: 'GET', path: `/v1/governance/runs/${encodeURIComponent(runId)}/timeline` });
  }

  getAgentActivity(agentId: string): Promise<ActivityResponse> {
    return this.request<ActivityResponse>({ method: 'GET', path: `/v1/governance/agents/${encodeURIComponent(agentId)}/activity` });
  }

  verifyAuditChain(): Promise<unknown> {
    return this.request<unknown>({ method: 'GET', path: '/v1/governance/audit/verify' });
  }

  listCheckpoints(): Promise<CheckpointsResponse> {
    return this.request<CheckpointsResponse>({ method: 'GET', path: '/v1/governance/audit/checkpoints' });
  }

  // ---- governance: outbox ----

  listOutbox(query?: { status?: string; cursor?: string; limit?: number }): Promise<OutboxResponse> {
    return this.request<OutboxResponse>({
      method: 'GET',
      path: '/v1/governance/outbox',
      query: { status: query?.status, cursor: query?.cursor, limit: query?.limit },
    });
  }

  retryOutboxEvent(eventId: string): Promise<OutboxEventResponse> {
    return this.request<OutboxEventResponse>({ method: 'POST', path: `/v1/governance/outbox/${encodeURIComponent(eventId)}/retry` });
  }

  getExport(framework: string): Promise<unknown> {
    return this.request<unknown>({ method: 'GET', path: `/v1/governance/exports/${encodeURIComponent(framework)}` });
  }

  // ---- governance: connectors ----

  listConnectors(): Promise<ConnectorsResponse> {
    return this.request<ConnectorsResponse>({ method: 'GET', path: '/v1/governance/connectors' });
  }

  registerConnector(body: ConnectorRegisterRequest): Promise<ConnectorDetailResponse> {
    return this.request<ConnectorDetailResponse>({ method: 'POST', path: '/v1/governance/connectors', body });
  }

  getConnector(connectorId: string): Promise<ConnectorDetailResponse> {
    return this.request<ConnectorDetailResponse>({ method: 'GET', path: `/v1/governance/connectors/${encodeURIComponent(connectorId)}` });
  }

  getConnectorManifest(connectorId: string): Promise<ConnectorManifestResponse> {
    return this.request<ConnectorManifestResponse>({
      method: 'GET',
      path: `/v1/governance/connectors/${encodeURIComponent(connectorId)}/manifest`,
    });
  }

  activateConnector(connectorId: string, reason: string): Promise<ConnectorDetailResponse> {
    return this.connectorTransition(connectorId, 'activate', reason);
  }

  suspendConnector(connectorId: string, reason: string): Promise<ConnectorDetailResponse> {
    return this.connectorTransition(connectorId, 'suspend', reason);
  }

  revokeConnector(connectorId: string, reason: string): Promise<ConnectorDetailResponse> {
    return this.connectorTransition(connectorId, 'revoke', reason);
  }

  updateConnectorConfig(connectorId: string, body: ConnectorConfigUpdateRequest): Promise<ConnectorDetailResponse> {
    return this.request<ConnectorDetailResponse>({
      method: 'POST',
      path: `/v1/governance/connectors/${encodeURIComponent(connectorId)}/config`,
      body,
    });
  }

  connectorHealth(connectorId: string): Promise<ConnectorHealthResponse> {
    return this.request<ConnectorHealthResponse>({
      method: 'GET',
      path: `/v1/governance/connectors/${encodeURIComponent(connectorId)}/health`,
    });
  }

  private connectorTransition(connectorId: string, transition: 'activate' | 'suspend' | 'revoke', reason: string): Promise<ConnectorDetailResponse> {
    return this.request<ConnectorDetailResponse>({
      method: 'POST',
      path: `/v1/governance/connectors/${encodeURIComponent(connectorId)}/${transition}`,
      body: { reason },
    });
  }

  // ---- governance: trust relationships ----

  createTrustRelationship(body: CreateTrustRelationshipRequest, idempotencyKey: string): Promise<TrustRelationshipResponse> {
    return this.request<TrustRelationshipResponse>({ method: 'POST', path: '/v1/governance/trust-relationships', body, idempotencyKey });
  }

  listTrustRelationships(): Promise<TrustRelationshipsResponse> {
    return this.request<TrustRelationshipsResponse>({ method: 'GET', path: '/v1/governance/trust-relationships' });
  }

  getTrustRelationship(relationshipId: string): Promise<TrustRelationshipResponse> {
    return this.request<TrustRelationshipResponse>({
      method: 'GET',
      path: `/v1/governance/trust-relationships/${encodeURIComponent(relationshipId)}`,
    });
  }

  trustRelationshipTransition(
    relationshipId: string,
    transition: 'approve' | 'activate' | 'suspend' | 'resume' | 'revoke',
    reason: string,
    idempotencyKey: string,
  ): Promise<TrustRelationshipResponse> {
    return this.request<TrustRelationshipResponse>({
      method: 'POST',
      path: `/v1/governance/trust-relationships/${encodeURIComponent(relationshipId)}/${transition}`,
      body: { reason },
      idempotencyKey,
    });
  }

  // ---- governance: external agents ----

  createExternalAgent(body: CreateExternalAgentRequest, idempotencyKey: string): Promise<ExternalAgentResponse> {
    return this.request<ExternalAgentResponse>({ method: 'POST', path: '/v1/governance/external-agents', body, idempotencyKey });
  }

  listExternalAgents(): Promise<ExternalAgentsResponse> {
    return this.request<ExternalAgentsResponse>({ method: 'GET', path: '/v1/governance/external-agents' });
  }

  getExternalAgent(externalAgentId: string): Promise<ExternalAgentResponse> {
    return this.request<ExternalAgentResponse>({
      method: 'GET',
      path: `/v1/governance/external-agents/${encodeURIComponent(externalAgentId)}`,
    });
  }

  externalAgentHealth(externalAgentId: string): Promise<ExternalAgentHealthResponse> {
    return this.request<ExternalAgentHealthResponse>({
      method: 'GET',
      path: `/v1/governance/external-agents/${encodeURIComponent(externalAgentId)}/health`,
    });
  }

  externalAgentTransition(
    externalAgentId: string,
    transition: 'activate' | 'suspend' | 'revoke',
    reason: string,
    idempotencyKey: string,
  ): Promise<ExternalAgentResponse> {
    return this.request<ExternalAgentResponse>({
      method: 'POST',
      path: `/v1/governance/external-agents/${encodeURIComponent(externalAgentId)}/${transition}`,
      body: { reason },
      idempotencyKey,
    });
  }

  // ---- governance: external runs ----

  createExternalRun(body: CreateExternalRunRequest, idempotencyKey?: string): Promise<ExternalRun> {
    return this.request<ExternalRun>({ method: 'POST', path: '/v1/governance/external-runs', body, idempotencyKey });
  }

  listExternalRuns(query?: { external_agent_id?: string; status?: string; cursor?: string; limit?: number }): Promise<ExternalRun[]> {
    return this.request<ExternalRun[]>({
      method: 'GET',
      path: '/v1/governance/external-runs',
      query: { external_agent_id: query?.external_agent_id, status: query?.status, cursor: query?.cursor, limit: query?.limit },
    });
  }

  getExternalRun(runId: string): Promise<ExternalRun> {
    return this.request<ExternalRun>({ method: 'GET', path: `/v1/governance/external-runs/${encodeURIComponent(runId)}` });
  }

  terminateExternalRun(runId: string, reason: string, idempotencyKey: string): Promise<ExternalRun> {
    return this.request<ExternalRun>({
      method: 'POST',
      path: `/v1/governance/external-runs/${encodeURIComponent(runId)}/terminate`,
      body: { reason },
      idempotencyKey,
    });
  }

  // ---- governance: consents ----

  createConsent(body: CreateConsentRequest, idempotencyKey: string): Promise<ConsentResponse> {
    return this.request<ConsentResponse>({ method: 'POST', path: '/v1/governance/consents', body, idempotencyKey });
  }

  listConsents(): Promise<ConsentsResponse> {
    return this.request<ConsentsResponse>({ method: 'GET', path: '/v1/governance/consents' });
  }

  getConsent(consentId: string): Promise<ConsentResponse> {
    return this.request<ConsentResponse>({ method: 'GET', path: `/v1/governance/consents/${encodeURIComponent(consentId)}` });
  }

  revokeConsent(consentId: string, reason: string, idempotencyKey: string): Promise<ConsentResponse> {
    return this.request<ConsentResponse>({
      method: 'POST',
      path: `/v1/governance/consents/${encodeURIComponent(consentId)}/revoke`,
      body: { reason },
      idempotencyKey,
    });
  }

  // ---- governance: transfer policies ----

  upsertTransferPolicy(body: UpsertTransferPolicyRequest, idempotencyKey: string): Promise<TransferPolicyResponse> {
    return this.request<TransferPolicyResponse>({ method: 'POST', path: '/v1/governance/transfer-policies', body, idempotencyKey });
  }

  listTransferPolicies(): Promise<TransferPoliciesResponse> {
    return this.request<TransferPoliciesResponse>({ method: 'GET', path: '/v1/governance/transfer-policies' });
  }

  transferPolicyTransition(
    policyId: string,
    transition: 'activate' | 'suspend' | 'revoke',
    reason: string,
    idempotencyKey: string,
  ): Promise<TransferPolicyResponse> {
    return this.request<TransferPolicyResponse>({
      method: 'POST',
      path: `/v1/governance/transfer-policies/${encodeURIComponent(policyId)}/${transition}`,
      body: { reason },
      idempotencyKey,
    });
  }

  // ---- governance: external budgets ----

  listExternalBudgets(): Promise<ExternalBudgetsResponse> {
    return this.request<ExternalBudgetsResponse>({ method: 'GET', path: '/v1/governance/external-budgets' });
  }

  upsertExternalBudget(externalAgentId: string, body: UpsertExternalBudgetRequest, idempotencyKey: string): Promise<ExternalBudgetResponse> {
    return this.request<ExternalBudgetResponse>({
      method: 'PUT',
      path: `/v1/governance/external-budgets/${encodeURIComponent(externalAgentId)}`,
      body,
      idempotencyKey,
    });
  }

  // ---- usage metering ----

  getUsage(): Promise<UsageResponse> {
    return this.request<UsageResponse>({ method: 'GET', path: '/v1/usage' });
  }

  getUsageLimits(): Promise<UsageLimitsResponse> {
    return this.request<UsageLimitsResponse>({ method: 'GET', path: '/v1/usage/limits' });
  }

  putUsageLimits(body: PutUsageLimitsRequest, idempotencyKey: string): Promise<UsageLimitsResponse> {
    return this.request<UsageLimitsResponse>({ method: 'PUT', path: '/v1/usage/limits', body, idempotencyKey });
  }
}

// Re-export used response types for convenience.
export type {
  ActionApproval,
  ActionDecision,
  AgentRun,
  AgentTrustRelationship,
  DelegationChain,
  DelegationGrant,
  MintDelegationResponse,
  Tool,
  TransferPolicy,
  UsageLimit,
  UsageResponse,
  UsageLimitsResponse,
};
