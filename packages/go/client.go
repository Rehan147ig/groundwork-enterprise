package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AssertionProvider resolves a user assertion at request time; may
// return an empty string to skip the header.
type AssertionProvider func() (string, error)

// ClientOptions configures a GroundworkClient.
type ClientOptions struct {
	BaseURL    string
	APIKey     string
	Assertion  string            // static assertion
	Provider   AssertionProvider // dynamic assertion (takes precedence when non-nil)
	Timeout    time.Duration     // per-request timeout (default 30s)
	HTTPClient *http.Client
}

// GroundworkClient is the zero-dependency typed client for the
// Groundwork query runtime API.
type GroundworkClient struct {
	baseURL   string
	apiKey    string
	assertion string
	provider  AssertionProvider
	timeout   time.Duration
	http      *http.Client
}

// NewClient builds a GroundworkClient. BaseURL trailing slashes are
// normalized; the API key is attached to every request.
func NewClient(opts ClientOptions) *GroundworkClient {
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &GroundworkClient{
		baseURL:   strings.TrimRight(opts.BaseURL, "/"),
		apiKey:    opts.APIKey,
		assertion: opts.Assertion,
		provider:  opts.Provider,
		timeout:   timeout,
		http:      httpClient,
	}
}

// request performs one typed API call. query values with zero values are
// omitted. body is JSON-encoded when non-nil.
func (c *GroundworkClient) request(ctx context.Context, method, path string, query map[string]any, body any, idempotencyKey string, out any) error {
	endpoint := c.baseURL + path
	if len(query) > 0 {
		params := url.Values{}
		for k, v := range query {
			if v == nil {
				continue
			}
			switch t := v.(type) {
			case string:
				if t != "" {
					params.Set(k, t)
				}
			case int:
				if t != 0 {
					params.Set(k, fmt.Sprintf("%d", t))
				}
			case bool:
				params.Set(k, fmt.Sprintf("%t", t))
			}
		}
		if len(params) > 0 {
			endpoint += "?" + params.Encode()
		}
	}

	headers := http.Header{}
	headers.Set("X-Groundwork-API-Key", c.apiKey)
	if c.provider != nil {
		if assertion, err := c.provider(); err == nil && assertion != "" {
			headers.Set("X-Groundwork-User-Assertion", assertion)
		}
	} else if c.assertion != "" {
		headers.Set("X-Groundwork-User-Assertion", c.assertion)
	}
	if idempotencyKey != "" {
		headers.Set("Idempotency-Key", idempotencyKey)
	}

	var bodyReader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		headers.Set("Content-Type", "application/json")
		bodyReader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return err
	}
	req.Header = headers

	client := c.http
	// Per-request timeout: wrap the context when the shared client has no
	// timeout of its own (avoids double timeouts on custom clients).
	if client.Timeout == 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
		req = req.WithContext(ctx)
	}

	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return &GroundworkError{Status: 0, Code: "timeout", Headers: http.Header{}}
		}
		return &GroundworkError{Status: 0, Code: "network", Headers: http.Header{}}
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return &GroundworkError{Status: 0, Code: "network", Headers: resp.Header}
	}
	if resp.StatusCode >= 400 {
		return parseErrorResponse(resp, respBody)
	}
	if resp.StatusCode == 204 || len(respBody) == 0 {
		return nil
	}
	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("sdk: decode %s: %w", resp.Status, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// health / query / audit / admin
// ---------------------------------------------------------------------

func (c *GroundworkClient) Health(ctx context.Context) (HealthResponse, error) {
	var out HealthResponse
	err := c.request(ctx, http.MethodGet, "/healthz", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) Query(ctx context.Context, body QueryRequest) (QueryResponse, error) {
	var out QueryResponse
	err := c.request(ctx, http.MethodPost, "/v1/query", nil, body, "", &out)
	return out, err
}

type AuditFilters struct {
	TraceID  string
	TenantID string
	AgentID  string
	Decision string
	Reason   string
	From     string
	To       string
	Limit    int
	Cursor   string
}

func (c *GroundworkClient) Audit(ctx context.Context, filters AuditFilters) (AuditListResponse, error) {
	var out AuditListResponse
	err := c.request(ctx, http.MethodGet, "/v1/audit", map[string]any{
		"trace_id": filters.TraceID, "tenant_id": filters.TenantID,
		"agent_id": filters.AgentID, "decision": filters.Decision,
		"reason": filters.Reason, "from": filters.From, "to": filters.To,
		"limit": filters.Limit, "cursor": filters.Cursor,
	}, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) ListAPIKeys(ctx context.Context) (ApiKeyListResponse, error) {
	var out ApiKeyListResponse
	err := c.request(ctx, http.MethodGet, "/v1/admin/api-keys", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) CreateAPIKey(ctx context.Context, body CreateApiKeyRequest) (CreateApiKeyResponse, error) {
	var out CreateApiKeyResponse
	err := c.request(ctx, http.MethodPost, "/v1/admin/api-keys", nil, body, "", &out)
	return out, err
}

func (c *GroundworkClient) RevokeAPIKey(ctx context.Context, keyID string) error {
	return c.request(ctx, http.MethodPost, "/v1/admin/api-keys/"+escape(keyID)+"/revoke", nil, nil, "", nil)
}

// ---------------------------------------------------------------------
// agents
// ---------------------------------------------------------------------

func (c *GroundworkClient) ListAgents(ctx context.Context, state, environment string) (AgentListResponse, error) {
	var out AgentListResponse
	err := c.request(ctx, http.MethodGet, "/v1/agents", map[string]any{
		"state": state, "environment": environment,
	}, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) CreateAgent(ctx context.Context, body CreateAgentRequest) (AgentResponse, error) {
	var out AgentResponse
	err := c.request(ctx, http.MethodPost, "/v1/agents", nil, body, "", &out)
	return out, err
}

func (c *GroundworkClient) GetAgent(ctx context.Context, agentID string) (AgentDetailResponse, error) {
	var out AgentDetailResponse
	err := c.request(ctx, http.MethodGet, "/v1/agents/"+escape(agentID), nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) UpdateAgent(ctx context.Context, agentID string, body UpdateAgentRequest) (AgentResponse, error) {
	var out AgentResponse
	err := c.request(ctx, http.MethodPatch, "/v1/agents/"+escape(agentID), nil, body, "", &out)
	return out, err
}

func (c *GroundworkClient) agentTransition(ctx context.Context, agentID, transition, reason string) (AgentResponse, error) {
	var out AgentResponse
	err := c.request(ctx, http.MethodPost, "/v1/agents/"+escape(agentID)+"/"+transition, nil, ControlRequest{Reason: reason}, "", &out)
	return out, err
}

func (c *GroundworkClient) ActivateAgent(ctx context.Context, agentID, reason string) (AgentResponse, error) {
	return c.agentTransition(ctx, agentID, "activate", reason)
}

func (c *GroundworkClient) SuspendAgent(ctx context.Context, agentID, reason string) (AgentResponse, error) {
	return c.agentTransition(ctx, agentID, "suspend", reason)
}

func (c *GroundworkClient) RevokeAgent(ctx context.Context, agentID, reason string) (AgentResponse, error) {
	return c.agentTransition(ctx, agentID, "revoke", reason)
}

func (c *GroundworkClient) RetireAgent(ctx context.Context, agentID, reason string) (AgentResponse, error) {
	return c.agentTransition(ctx, agentID, "retire", reason)
}

func (c *GroundworkClient) AddAgentVersion(ctx context.Context, agentID string, body AddAgentVersionRequest) (AgentVersionResponse, error) {
	var out AgentVersionResponse
	err := c.request(ctx, http.MethodPost, "/v1/agents/"+escape(agentID)+"/versions", nil, body, "", &out)
	return out, err
}

// ---------------------------------------------------------------------
// governance: tools
// ---------------------------------------------------------------------

func (c *GroundworkClient) ListTools(ctx context.Context) (ToolListResponse, error) {
	var out ToolListResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/tools", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) RegisterTool(ctx context.Context, body RegisterToolRequest) (ToolResponse, error) {
	var out ToolResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/tools", nil, body, "", &out)
	return out, err
}

func (c *GroundworkClient) GetTool(ctx context.Context, toolID string) (ToolDetailResponse, error) {
	var out ToolDetailResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/tools/"+escape(toolID), nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) RegisterToolAction(ctx context.Context, toolID string, body RegisterToolActionRequest) (ToolActionResponse, error) {
	var out ToolActionResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/tools/"+escape(toolID)+"/actions", nil, body, "", &out)
	return out, err
}

func (c *GroundworkClient) ListToolActions(ctx context.Context, toolID string) (ToolActionListResponse, error) {
	var out ToolActionListResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/tools/"+escape(toolID)+"/actions", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) ToolLifecycle(ctx context.Context, toolID string, body TransitionToolRequest) (ToolResponse, error) {
	var out ToolResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/tools/"+escape(toolID)+"/lifecycle", nil, body, "", &out)
	return out, err
}

func (c *GroundworkClient) KillSwitchTool(ctx context.Context, toolID, reason, scope string) (ControlResponse, error) {
	return c.controlMutation(ctx, "/v1/governance/tools/"+escape(toolID)+"/kill-switch", reason, scope)
}

func (c *GroundworkClient) ResumeTool(ctx context.Context, toolID, reason, scope string) (ControlResponse, error) {
	return c.controlMutation(ctx, "/v1/governance/tools/"+escape(toolID)+"/resume", reason, scope)
}

// ---------------------------------------------------------------------
// governance: grants
// ---------------------------------------------------------------------

func (c *GroundworkClient) GrantTool(ctx context.Context, body GrantToolRequest) (GrantResponse, error) {
	var out GrantResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/grants", nil, body, "", &out)
	return out, err
}

func (c *GroundworkClient) ListAgentGrants(ctx context.Context, agentID string) (GrantListResponse, error) {
	var out GrantListResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/agents/"+escape(agentID)+"/grants", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) RevokeGrant(ctx context.Context, grantID, reason string) (GrantResponse, error) {
	var out GrantResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/grants/"+escape(grantID)+"/revoke", nil, ControlRequest{Reason: reason}, "", &out)
	return out, err
}

// ---------------------------------------------------------------------
// governance: delegations
// ---------------------------------------------------------------------

func (c *GroundworkClient) MintDelegation(ctx context.Context, body MintDelegationRequest, idempotencyKey string) (MintDelegationResponse, error) {
	var out MintDelegationResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/delegations", nil, body, idempotencyKey, &out)
	return out, err
}

func (c *GroundworkClient) ListDelegationGrants(ctx context.Context) (GrantListResponse, error) {
	var out GrantListResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/delegations", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) GetDelegationChain(ctx context.Context, grantID string) (DelegationChain, error) {
	var out DelegationChain
	err := c.request(ctx, http.MethodGet, "/v1/governance/delegations/"+escape(grantID)+"/chain", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) RevokeDelegation(ctx context.Context, grantID, reason, scope string) (ControlResponse, error) {
	return c.controlMutation(ctx, "/v1/governance/delegations/"+escape(grantID)+"/chain/revoke", reason, scope)
}

func (c *GroundworkClient) SuspendDelegationChain(ctx context.Context, grantID, reason, scope string) (ControlResponse, error) {
	return c.controlMutation(ctx, "/v1/governance/delegations/"+escape(grantID)+"/chain/suspend", reason, scope)
}

func (c *GroundworkClient) ResumeDelegationChain(ctx context.Context, grantID, reason, scope string) (ControlResponse, error) {
	return c.controlMutation(ctx, "/v1/governance/delegations/"+escape(grantID)+"/chain/resume", reason, scope)
}

func (c *GroundworkClient) GetRunDelegationChain(ctx context.Context, runID string) (DelegationChain, error) {
	var out DelegationChain
	err := c.request(ctx, http.MethodGet, "/v1/governance/runs/"+escape(runID)+"/delegation-chain", nil, nil, "", &out)
	return out, err
}

// ---------------------------------------------------------------------
// governance: runs
// ---------------------------------------------------------------------

func (c *GroundworkClient) CreateRun(ctx context.Context, body CreateRunRequest, idempotencyKey string) (CreateRunResponse, error) {
	var out CreateRunResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/runs", nil, body, idempotencyKey, &out)
	return out, err
}

type RunListFilters struct {
	AgentID string
	Status  string
	Cursor  string
	Limit   int
}

func (c *GroundworkClient) ListRuns(ctx context.Context, filters RunListFilters) (RunListResponse, error) {
	var out RunListResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/runs", map[string]any{
		"agent_id": filters.AgentID, "status": filters.Status,
		"cursor": filters.Cursor, "limit": filters.Limit,
	}, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) GetRun(ctx context.Context, runID string) (RunDetailResponse, error) {
	var out RunDetailResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/runs/"+escape(runID), nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) EvaluateAction(ctx context.Context, body EvaluateActionRequest) (EvaluateActionResponse, error) {
	var out EvaluateActionResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/runs/"+escape(body.RunID)+"/evaluate", nil, body, "", &out)
	return out, err
}

func (c *GroundworkClient) SimulateAction(ctx context.Context, body SimulateActionRequest) (GovernanceSimulateResponse, error) {
	var out GovernanceSimulateResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/simulate", nil, body, "", &out)
	return out, err
}

func (c *GroundworkClient) ApproveAction(ctx context.Context, runID, actionID, resourceRef string) (ApproveActionResponse, error) {
	var out ApproveActionResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/runs/"+escape(runID)+"/approve/"+escape(actionID), nil, ApproveActionRequest{ResourceRef: resourceRef}, "", &out)
	return out, err
}

func (c *GroundworkClient) DenyAction(ctx context.Context, runID, actionID, resourceRef string) (ApproveActionResponse, error) {
	var out ApproveActionResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/runs/"+escape(runID)+"/deny/"+escape(actionID), nil, ApproveActionRequest{ResourceRef: resourceRef}, "", &out)
	return out, err
}

func (c *GroundworkClient) Dispatch(ctx context.Context, body EvaluateActionRequest) (DispatchResponse, error) {
	var out DispatchResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/dispatch", nil, body, "", &out)
	return out, err
}

func (c *GroundworkClient) TerminateRun(ctx context.Context, runID, reason, scope string) (ControlResponse, error) {
	return c.controlMutation(ctx, "/v1/governance/runs/"+escape(runID)+"/terminate", reason, scope)
}

func (c *GroundworkClient) KillSwitchAgent(ctx context.Context, agentID, reason, scope string) (ControlResponse, error) {
	return c.controlMutation(ctx, "/v1/governance/agents/"+escape(agentID)+"/kill-switch", reason, scope)
}

func (c *GroundworkClient) ResumeAgent(ctx context.Context, agentID, reason, scope string) (ControlResponse, error) {
	return c.controlMutation(ctx, "/v1/governance/agents/"+escape(agentID)+"/resume", reason, scope)
}

func (c *GroundworkClient) KillSwitchAgentVersion(ctx context.Context, versionID, reason, scope string) (ControlResponse, error) {
	return c.controlMutation(ctx, "/v1/governance/agent-versions/"+escape(versionID)+"/kill-switch", reason, scope)
}

func (c *GroundworkClient) ResumeAgentVersion(ctx context.Context, versionID, reason, scope string) (ControlResponse, error) {
	return c.controlMutation(ctx, "/v1/governance/agent-versions/"+escape(versionID)+"/resume", reason, scope)
}

func (c *GroundworkClient) ListEmergencyControls(ctx context.Context) (ControlsResponse, error) {
	var out ControlsResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/emergency-controls", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) controlMutation(ctx context.Context, path, reason, scope string) (ControlResponse, error) {
	var out ControlResponse
	body := ControlRequest{Reason: reason}
	if scope != "" {
		body.Scope = scope
	}
	err := c.request(ctx, http.MethodPost, path, nil, body, "", &out)
	return out, err
}

// ---------------------------------------------------------------------
// governance: budgets
// ---------------------------------------------------------------------

func (c *GroundworkClient) UpsertBudget(ctx context.Context, body BudgetUpsertRequest) (BudgetResponse, error) {
	var out BudgetResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/budgets", nil, body, "", &out)
	return out, err
}

func (c *GroundworkClient) GetEffectiveBudget(ctx context.Context) (BudgetResponse, error) {
	var out BudgetResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/budgets/effective", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) ListBudgets(ctx context.Context) (BudgetsResponse, error) {
	var out BudgetsResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/budgets", nil, nil, "", &out)
	return out, err
}

// ---------------------------------------------------------------------
// governance: evidence
// ---------------------------------------------------------------------

type EvidenceFilters struct {
	TenantID string
	Kind     string
	EntityID string
	From     string
	To       string
	Cursor   string
	Limit    int
}

func (c *GroundworkClient) QueryEvidence(ctx context.Context, filters EvidenceFilters) (EvidencePage, error) {
	var out EvidencePage
	err := c.request(ctx, http.MethodGet, "/v1/governance/evidence", map[string]any{
		"tenant_id": filters.TenantID, "kind": filters.Kind, "entity_id": filters.EntityID,
		"from": filters.From, "to": filters.To, "cursor": filters.Cursor, "limit": filters.Limit,
	}, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) GetEvidenceEvent(ctx context.Context, eventID string) (EvidenceEventResponse, error) {
	var out EvidenceEventResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/evidence/"+escape(eventID), nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) GetEvidenceProvenance(ctx context.Context, eventID string) (EvidenceEventResponse, error) {
	var out EvidenceEventResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/evidence/"+escape(eventID)+"/provenance", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) GetRunTimeline(ctx context.Context, runID string) (TimelineResponse, error) {
	var out TimelineResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/runs/"+escape(runID)+"/timeline", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) GetAgentActivity(ctx context.Context, agentID string) (ActivityResponse, error) {
	var out ActivityResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/agents/"+escape(agentID)+"/activity", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) VerifyAuditChain(ctx context.Context) (any, error) {
	var out any
	err := c.request(ctx, http.MethodGet, "/v1/governance/audit/verify", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) ListCheckpoints(ctx context.Context) (CheckpointsResponse, error) {
	var out CheckpointsResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/audit/checkpoints", nil, nil, "", &out)
	return out, err
}

// ---------------------------------------------------------------------
// governance: outbox
// ---------------------------------------------------------------------

type OutboxFilters struct {
	Status string
	Cursor string
	Limit  int
}

func (c *GroundworkClient) ListOutbox(ctx context.Context, filters OutboxFilters) (OutboxResponse, error) {
	var out OutboxResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/outbox", map[string]any{
		"status": filters.Status, "cursor": filters.Cursor, "limit": filters.Limit,
	}, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) RetryOutboxEvent(ctx context.Context, eventID string) (OutboxEventResponse, error) {
	var out OutboxEventResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/outbox/"+escape(eventID)+"/retry", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) GetExport(ctx context.Context, framework string) (any, error) {
	var out any
	err := c.request(ctx, http.MethodGet, "/v1/governance/exports/"+escape(framework), nil, nil, "", &out)
	return out, err
}

// ---------------------------------------------------------------------
// governance: connectors
// ---------------------------------------------------------------------

func (c *GroundworkClient) ListConnectors(ctx context.Context) (ConnectorsResponse, error) {
	var out ConnectorsResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/connectors", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) RegisterConnector(ctx context.Context, body ConnectorRegisterRequest) (ConnectorDetailResponse, error) {
	var out ConnectorDetailResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/connectors", nil, body, "", &out)
	return out, err
}

func (c *GroundworkClient) GetConnector(ctx context.Context, connectorID string) (ConnectorDetailResponse, error) {
	var out ConnectorDetailResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/connectors/"+escape(connectorID), nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) GetConnectorManifest(ctx context.Context, connectorID string) (ConnectorManifestResponse, error) {
	var out ConnectorManifestResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/connectors/"+escape(connectorID)+"/manifest", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) connectorTransition(ctx context.Context, connectorID, transition, reason string) (ConnectorDetailResponse, error) {
	var out ConnectorDetailResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/connectors/"+escape(connectorID)+"/"+transition, nil, ControlRequest{Reason: reason}, "", &out)
	return out, err
}

func (c *GroundworkClient) ActivateConnector(ctx context.Context, connectorID, reason string) (ConnectorDetailResponse, error) {
	return c.connectorTransition(ctx, connectorID, "activate", reason)
}

func (c *GroundworkClient) SuspendConnector(ctx context.Context, connectorID, reason string) (ConnectorDetailResponse, error) {
	return c.connectorTransition(ctx, connectorID, "suspend", reason)
}

func (c *GroundworkClient) RevokeConnector(ctx context.Context, connectorID, reason string) (ConnectorDetailResponse, error) {
	return c.connectorTransition(ctx, connectorID, "revoke", reason)
}

func (c *GroundworkClient) UpdateConnectorConfig(ctx context.Context, connectorID string, body ConnectorConfigUpdateRequest) (ConnectorDetailResponse, error) {
	var out ConnectorDetailResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/connectors/"+escape(connectorID)+"/config", nil, body, "", &out)
	return out, err
}

func (c *GroundworkClient) ConnectorHealth(ctx context.Context, connectorID string) (ConnectorHealthResponse, error) {
	var out ConnectorHealthResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/connectors/"+escape(connectorID)+"/health", nil, nil, "", &out)
	return out, err
}

// ---------------------------------------------------------------------
// governance: trust relationships (Phase 6)
// ---------------------------------------------------------------------

func (c *GroundworkClient) CreateTrustRelationship(ctx context.Context, body CreateTrustRelationshipRequest, idempotencyKey string) (TrustRelationshipResponse, error) {
	var out TrustRelationshipResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/trust-relationships", nil, body, idempotencyKey, &out)
	return out, err
}

func (c *GroundworkClient) ListTrustRelationships(ctx context.Context) (TrustRelationshipsResponse, error) {
	var out TrustRelationshipsResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/trust-relationships", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) GetTrustRelationship(ctx context.Context, relationshipID string) (TrustRelationshipResponse, error) {
	var out TrustRelationshipResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/trust-relationships/"+escape(relationshipID), nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) TrustRelationshipTransition(ctx context.Context, relationshipID, transition, reason, idempotencyKey string) (TrustRelationshipResponse, error) {
	var out TrustRelationshipResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/trust-relationships/"+escape(relationshipID)+"/"+transition, nil, ControlRequest{Reason: reason}, idempotencyKey, &out)
	return out, err
}

// ---------------------------------------------------------------------
// governance: external agents
// ---------------------------------------------------------------------

func (c *GroundworkClient) CreateExternalAgent(ctx context.Context, body CreateExternalAgentRequest, idempotencyKey string) (ExternalAgentResponse, error) {
	var out ExternalAgentResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/external-agents", nil, body, idempotencyKey, &out)
	return out, err
}

func (c *GroundworkClient) ListExternalAgents(ctx context.Context) (ExternalAgentsResponse, error) {
	var out ExternalAgentsResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/external-agents", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) GetExternalAgent(ctx context.Context, externalAgentID string) (ExternalAgentResponse, error) {
	var out ExternalAgentResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/external-agents/"+escape(externalAgentID), nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) ExternalAgentHealth(ctx context.Context, externalAgentID string) (ExternalAgentHealthResponse, error) {
	var out ExternalAgentHealthResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/external-agents/"+escape(externalAgentID)+"/health", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) ExternalAgentTransition(ctx context.Context, externalAgentID, transition, reason, idempotencyKey string) (ExternalAgentResponse, error) {
	var out ExternalAgentResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/external-agents/"+escape(externalAgentID)+"/"+transition, nil, ControlRequest{Reason: reason}, idempotencyKey, &out)
	return out, err
}

// ---------------------------------------------------------------------
// governance: external runs
// ---------------------------------------------------------------------

func (c *GroundworkClient) CreateExternalRun(ctx context.Context, body CreateExternalRunRequest, idempotencyKey string) (ExternalRun, error) {
	var out ExternalRun
	err := c.request(ctx, http.MethodPost, "/v1/governance/external-runs", nil, body, idempotencyKey, &out)
	return out, err
}

type ExternalRunFilters struct {
	ExternalAgentID string
	Status          string
	Cursor          string
	Limit           int
}

func (c *GroundworkClient) ListExternalRuns(ctx context.Context, filters ExternalRunFilters) ([]ExternalRun, error) {
	var out []ExternalRun
	err := c.request(ctx, http.MethodGet, "/v1/governance/external-runs", map[string]any{
		"external_agent_id": filters.ExternalAgentID, "status": filters.Status,
		"cursor": filters.Cursor, "limit": filters.Limit,
	}, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) GetExternalRun(ctx context.Context, runID string) (ExternalRun, error) {
	var out ExternalRun
	err := c.request(ctx, http.MethodGet, "/v1/governance/external-runs/"+escape(runID), nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) TerminateExternalRun(ctx context.Context, runID, reason, idempotencyKey string) (ExternalRun, error) {
	var out ExternalRun
	err := c.request(ctx, http.MethodPost, "/v1/governance/external-runs/"+escape(runID)+"/terminate", nil, ControlRequest{Reason: reason}, idempotencyKey, &out)
	return out, err
}

// ---------------------------------------------------------------------
// governance: consents
// ---------------------------------------------------------------------

func (c *GroundworkClient) CreateConsent(ctx context.Context, body CreateConsentRequest, idempotencyKey string) (ConsentResponse, error) {
	var out ConsentResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/consents", nil, body, idempotencyKey, &out)
	return out, err
}

func (c *GroundworkClient) ListConsents(ctx context.Context) (ConsentsResponse, error) {
	var out ConsentsResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/consents", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) GetConsent(ctx context.Context, consentID string) (ConsentResponse, error) {
	var out ConsentResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/consents/"+escape(consentID), nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) RevokeConsent(ctx context.Context, consentID, reason, idempotencyKey string) (ConsentResponse, error) {
	var out ConsentResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/consents/"+escape(consentID)+"/revoke", nil, ControlRequest{Reason: reason}, idempotencyKey, &out)
	return out, err
}

// ---------------------------------------------------------------------
// governance: transfer policies
// ---------------------------------------------------------------------

func (c *GroundworkClient) UpsertTransferPolicy(ctx context.Context, body UpsertTransferPolicyRequest, idempotencyKey string) (TransferPolicyResponse, error) {
	var out TransferPolicyResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/transfer-policies", nil, body, idempotencyKey, &out)
	return out, err
}

func (c *GroundworkClient) ListTransferPolicies(ctx context.Context) (TransferPoliciesResponse, error) {
	var out TransferPoliciesResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/transfer-policies", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) TransferPolicyTransition(ctx context.Context, policyID, transition, reason, idempotencyKey string) (TransferPolicyResponse, error) {
	var out TransferPolicyResponse
	err := c.request(ctx, http.MethodPost, "/v1/governance/transfer-policies/"+escape(policyID)+"/"+transition, nil, ControlRequest{Reason: reason}, idempotencyKey, &out)
	return out, err
}

// ---------------------------------------------------------------------
// governance: external budgets
// ---------------------------------------------------------------------

func (c *GroundworkClient) ListExternalBudgets(ctx context.Context) (ExternalBudgetsResponse, error) {
	var out ExternalBudgetsResponse
	err := c.request(ctx, http.MethodGet, "/v1/governance/external-budgets", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) UpsertExternalBudget(ctx context.Context, externalAgentID string, body UpsertExternalBudgetRequest, idempotencyKey string) (ExternalBudgetResponse, error) {
	var out ExternalBudgetResponse
	err := c.request(ctx, http.MethodPut, "/v1/governance/external-budgets/"+escape(externalAgentID), nil, body, idempotencyKey, &out)
	return out, err
}

// ---------------------------------------------------------------------
// usage metering
// ---------------------------------------------------------------------

func (c *GroundworkClient) GetUsage(ctx context.Context) (UsageResponse, error) {
	var out UsageResponse
	err := c.request(ctx, http.MethodGet, "/v1/usage", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) GetUsageLimits(ctx context.Context) (UsageLimitsResponse, error) {
	var out UsageLimitsResponse
	err := c.request(ctx, http.MethodGet, "/v1/usage/limits", nil, nil, "", &out)
	return out, err
}

func (c *GroundworkClient) PutUsageLimits(ctx context.Context, body PutUsageLimitsRequest, idempotencyKey string) (UsageLimitsResponse, error) {
	var out UsageLimitsResponse
	err := c.request(ctx, http.MethodPut, "/v1/usage/limits", nil, body, idempotencyKey, &out)
	return out, err
}

func escape(s string) string {
	return url.PathEscape(s)
}
