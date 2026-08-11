package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"groundwork/query-runtime/internal/usage"
)

// Governance HTTP surface (Phase 2: Delegated Authority & Governed Agent
// Execution). The GovernanceService interface and the JSON DTOs live
// here; the implementation (internal/governance) is wired via
// SetGovernanceService from cmd/query-runtime. When unset, the endpoints
// return 503 governance_unavailable.
//
// Endpoints:
//
//	POST /v1/governance/tools                            register tool (admin + identity)
//	GET  /v1/governance/tools                            list tools (governance scope)
//	GET  /v1/governance/tools/{tool_id}                  detail + actions
//	POST /v1/governance/tools/{tool_id}/actions          register action (admin + identity)
//	GET  /v1/governance/tools/{tool_id}/actions          list actions
//	POST /v1/governance/tools/{tool_id}/lifecycle        transition lifecycle (admin + identity)
//	POST /v1/governance/grants                           grant tool access (admin + identity)
//	POST /v1/governance/grants/{grant_id}/revoke         revoke grant (admin + identity)
//	GET  /v1/governance/agents/{agent_id}/grants         list grants
//	POST /v1/governance/delegations                      mint delegation (VERIFIED identity only)
//	POST /v1/governance/runs                             create run (token in body)
//	GET  /v1/governance/runs                             list runs
//	GET  /v1/governance/runs/{run_id}                    run detail + decisions
//	POST /v1/governance/runs/{run_id}/evaluate           evaluate one action
//	POST /v1/governance/runs/{run_id}/approve/{action_id} human approval (VERIFIED identity)
//	POST /v1/governance/runs/{run_id}/deny/{action_id}    human denial (VERIFIED identity)
//	POST /v1/governance/dispatch                         evaluate + dispatch
//
// Security model (mirrors /v1/agents):
//   - tenant_id and region come ONLY from the verified API-key context;
//   - reads require the "governance" scope (admin inherits);
//   - mutations require a verified end-user identity; minting and human
//     approvals additionally REJECT demo identities — a demo actor can
//     never mint a delegation or approve an action;
//   - delegation tokens are never echoed in errors or responses; only
//     the jti and safe metadata are persisted;
//   - every decision (allowed/denied/approval_required/fail_closed) is
//     appended to the write-once, hash-chained evidence.

// DelegationTokenHeader carries the delegation token on /v1/query. When
// present, the request runs as the verified delegated principal instead
// of requiring an end-user assertion.
const DelegationTokenHeader = "X-Groundwork-Delegation-Token"

// governanceScope is the API-key scope required for /v1/governance
// reads. hasScope's existing "admin" override grants access too.
const governanceScope = "governance"

// SetGovernanceService wires the Phase 2 governance implementation.
// Nil-safe: when unset, /v1/governance* returns 503 and a delegation
// token on /v1/query fails closed.
func (s *Server) SetGovernanceService(g GovernanceService) { s.governance = g }

// governanceActor resolves the actor principal for a governance
// mutation. verified is false for demo identities (ALLOW_DEMO_IDENTITY):
// minting delegations and recording human approvals REQUIRE a verified
// identity and reject demo actors.
func (s *Server) governanceActor(w http.ResponseWriter, r *http.Request) (actor string, verified bool, ok bool) {
	decision, ok := identityFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, ErrIdentityMissing)
		return "", false, false
	}
	tenant, _ := tenantFromContext(r.Context())
	if decision.identity.Verified {
		effective, _, err := CanonicalizeIdentity(r.Context(), s.resolver, s.canonicalIdentity, tenant.TenantID, decision.identity)
		if err != nil {
			writeGovernanceError(w, http.StatusForbidden, ErrIdentityUnresolved)
			return "", false, false
		}
		return effective, true, true
	}
	return "demo_actor", false, true
}

// idempotencyKey reads the Idempotency-Key header (optional). Mint,
// run creation, and approval decisions honor it for safe retries.
func idempotencyKey(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("Idempotency-Key"))
}

// ---------------------------------------------------------------------
// Tools & actions
// ---------------------------------------------------------------------

func (s *Server) createGovernanceTool(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	actor, _, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	var req RegisterToolRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tool, err := s.governance.RegisterTool(ctx, tenant.TenantID, actor, hasScope(tenant, "admin"), req)
	if err != nil {
		writeGovernanceServiceError(w, err, "tool_create_failed")
		return
	}
	writeJSON(w, http.StatusCreated, GovernanceToolResponse{Tool: tool})
}

func (s *Server) listGovernanceTools(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tools, err := s.governance.ListTools(ctx, tenant.TenantID)
	if err != nil {
		writeGovernanceServiceError(w, err, "tools_query_failed")
		return
	}
	if tools == nil {
		tools = []Tool{}
	}
	writeJSON(w, http.StatusOK, GovernanceToolListResponse{Tools: tools, Count: len(tools)})
}

func (s *Server) getGovernanceTool(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	toolID := strings.TrimSpace(r.PathValue("tool_id"))
	if toolID == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_tool_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tool, actions, err := s.governance.GetTool(ctx, tenant.TenantID, toolID)
	if err != nil {
		writeGovernanceServiceError(w, err, "tool_query_failed")
		return
	}
	if actions == nil {
		actions = []ToolAction{}
	}
	writeJSON(w, http.StatusOK, GovernanceToolDetailResponse{Tool: tool, Actions: actions})
}

func (s *Server) createGovernanceToolAction(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	actor, _, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	toolID := strings.TrimSpace(r.PathValue("tool_id"))
	if toolID == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_tool_id"))
		return
	}
	var req RegisterToolActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	action, err := s.governance.RegisterToolAction(ctx, tenant.TenantID, toolID, actor, hasScope(tenant, "admin"), req)
	if err != nil {
		writeGovernanceServiceError(w, err, "tool_action_create_failed")
		return
	}
	writeJSON(w, http.StatusCreated, GovernanceToolActionResponse{Action: action})
}

func (s *Server) listGovernanceToolActions(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	toolID := strings.TrimSpace(r.PathValue("tool_id"))
	if toolID == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_tool_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	actions, err := s.governance.ListToolActions(ctx, tenant.TenantID, toolID)
	if err != nil {
		writeGovernanceServiceError(w, err, "tool_actions_query_failed")
		return
	}
	if actions == nil {
		actions = []ToolAction{}
	}
	writeJSON(w, http.StatusOK, GovernanceToolActionsResponse{Actions: actions, Count: len(actions)})
}

func (s *Server) transitionGovernanceTool(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	actor, _, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	toolID := strings.TrimSpace(r.PathValue("tool_id"))
	if toolID == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_tool_id"))
		return
	}
	var req TransitionToolRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tool, err := s.governance.TransitionTool(ctx, tenant.TenantID, toolID, actor, hasScope(tenant, "admin"), req)
	if err != nil {
		writeGovernanceServiceError(w, err, "tool_transition_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceToolResponse{Tool: tool})
}

// ---------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------

func (s *Server) createGovernanceGrant(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	actor, _, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	var req GrantToolRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grant, err := s.governance.GrantToolAccess(ctx, tenant.TenantID, actor, hasScope(tenant, "admin"), req)
	if err != nil {
		writeGovernanceServiceError(w, err, "grant_create_failed")
		return
	}
	writeJSON(w, http.StatusCreated, GovernanceGrantResponse{Grant: grant})
}

func (s *Server) revokeGovernanceGrant(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	actor, _, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	grantID := strings.TrimSpace(r.PathValue("grant_id"))
	if grantID == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_grant_id"))
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grant, err := s.governance.RevokeToolGrant(ctx, tenant.TenantID, grantID, actor, hasScope(tenant, "admin"), req.Reason)
	if err != nil {
		writeGovernanceServiceError(w, err, "grant_revoke_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceGrantResponse{Grant: grant})
}

func (s *Server) listGovernanceGrants(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	agentID := strings.TrimSpace(r.PathValue("agent_id"))
	if agentID == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_agent_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grants, err := s.governance.ListToolGrants(ctx, tenant.TenantID, agentID)
	if err != nil {
		writeGovernanceServiceError(w, err, "grants_query_failed")
		return
	}
	if grants == nil {
		grants = []AgentToolGrant{}
	}
	writeJSON(w, http.StatusOK, GovernanceGrantListResponse{Grants: grants, Count: len(grants)})
}

// ---------------------------------------------------------------------
// Delegations (verified identity ONLY — demo can never mint)
// ---------------------------------------------------------------------

func (s *Server) mintGovernanceDelegation(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	actor, verified, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	if !verified {
		// A demo actor must never be able to mint a delegation: the
		// subject_principal_id on the grant is the security anchor of
		// every governed decision.
		writeGovernanceError(w, http.StatusForbidden, errors.New("verified_identity_required_for_delegation"))
		return
	}
	var body struct {
		AgentID string `json:"agent_id"`
		MintDelegationRequest
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	if strings.TrimSpace(body.AgentID) == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_agent_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	resp, err := s.governance.MintDelegation(ctx, tenant.TenantID, tenant.Region, strings.TrimSpace(body.AgentID), actor, hasScope(tenant, "admin"), idempotencyKey(r), body.MintDelegationRequest)
	if err != nil {
		writeGovernanceServiceError(w, err, "delegation_mint_failed")
		return
	}
	// The raw token is returned exactly once (single delivery); it is
	// never persisted server-side or echoed in logs.
	writeJSON(w, http.StatusCreated, GovernanceDelegationResponse{Grant: resp.Grant, Token: resp.Token, TokenAlreadyIssued: resp.TokenAlreadyIssued})
}

// ---------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------

func (s *Server) createGovernanceRun(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	var req CreateRunRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Phase 8.1: governed runs are metered (fail closed).
	if !s.recordUsage(w, tenant.TenantID, usage.MetricRuns, 1) {
		return
	}
	resp, err := s.governance.CreateRun(ctx, tenant.TenantID, tenant.Region, idempotencyKey(r), req)
	if err != nil {
		writeGovernanceServiceError(w, err, "run_create_failed")
		return
	}
	writeJSON(w, http.StatusCreated, GovernanceRunResponse{Run: resp.Run, Decisions: resp.Decisions})
}

func (s *Server) listGovernanceRuns(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	runs, err := s.governance.ListRuns(ctx, tenant.TenantID)
	if err != nil {
		writeGovernanceServiceError(w, err, "runs_query_failed")
		return
	}
	if runs == nil {
		runs = []AgentRun{}
	}
	writeJSON(w, http.StatusOK, GovernanceRunListResponse{Runs: runs, Count: len(runs)})
}

func (s *Server) getGovernanceRun(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_run_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	run, decisions, err := s.governance.GetRun(ctx, tenant.TenantID, runID)
	if err != nil {
		writeGovernanceServiceError(w, err, "run_query_failed")
		return
	}
	if decisions == nil {
		decisions = []ActionDecision{}
	}
	writeJSON(w, http.StatusOK, GovernanceRunDetailResponse{Run: run, Decisions: decisions})
}

func (s *Server) evaluateGovernanceAction(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_run_id"))
		return
	}
	var req EvaluateActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	req.RunID = runID
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Phase 8.1: each evaluation is a governed decision (fail closed).
	if !s.recordUsage(w, tenant.TenantID, usage.MetricDecisions, 1) {
		return
	}
	resp, err := s.governance.EvaluateAction(ctx, tenant.TenantID, tenant.Region, req)
	if err != nil {
		writeGovernanceServiceError(w, err, "action_evaluate_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceEvaluateResponse{Decision: resp.Decision, Allowed: resp.Allowed})
}

// simulateGovernanceAction is the Phase 7 policy simulator: read-only
// analysis (governance scope, no identity) that walks the SAME gate
// pipeline as evaluateGovernanceAction and explains each gate. It never
// writes evidence, counters, or approvals.
func (s *Server) simulateGovernanceAction(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	var req SimulateActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	resp, err := s.governance.SimulateAction(ctx, tenant.TenantID, tenant.Region, req)
	if err != nil {
		writeGovernanceServiceError(w, err, "action_simulate_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceSimulateResponse{Simulation: resp})
}

// ---------------------------------------------------------------------
// Human approval (VERIFIED identity only)
// ---------------------------------------------------------------------

func (s *Server) approveGovernanceAction(w http.ResponseWriter, r *http.Request) {
	s.recordGovernanceApproval(w, r, true)
}

func (s *Server) denyGovernanceAction(w http.ResponseWriter, r *http.Request) {
	s.recordGovernanceApproval(w, r, false)
}

func (s *Server) recordGovernanceApproval(w http.ResponseWriter, r *http.Request, approve bool) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	actor, verified, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	if !verified {
		// Approvals are recorded against the approving principal; a
		// demo actor must never be able to approve or deny governed
		// actions.
		writeGovernanceError(w, http.StatusForbidden, errors.New("verified_identity_required_for_approval"))
		return
	}
	runID := strings.TrimSpace(r.PathValue("run_id"))
	actionID := strings.TrimSpace(r.PathValue("action_id"))
	if runID == "" || actionID == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_run_or_action_id"))
		return
	}
	var req ApproveActionRequest
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var resp ApproveActionResponse
	var err error
	if approve {
		resp, err = s.governance.ApproveAction(ctx, tenant.TenantID, runID, actionID, actor, idempotencyKey(r), req)
	} else {
		resp, err = s.governance.DenyAction(ctx, tenant.TenantID, runID, actionID, actor, idempotencyKey(r), req)
	}
	if err != nil {
		writeGovernanceServiceError(w, err, "approval_record_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceApprovalResponse{Approval: resp.Approval, Denied: resp.Denied})
}

// ---------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------

func (s *Server) dispatchGovernanceAction(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	var req EvaluateActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Phase 8.1: dispatch is a governed decision (fail closed).
	if !s.recordUsage(w, tenant.TenantID, usage.MetricDecisions, 1) {
		return
	}
	resp, err := s.governance.DispatchAction(ctx, tenant.TenantID, tenant.Region, req)
	if err != nil {
		writeGovernanceServiceError(w, err, "action_dispatch_failed")
		return
	}
	// Phase 8.1: a connector_calls quota denial surfaces as a
	// fail-closed invocation (quota_exceeded:connector_calls) that was
	// recorded in the evidence chain before any outbound call; the
	// HTTP surface reports the quota error like every other quota
	// denial (403 quota_exceeded:<metric>).
	if resp.Invocation != nil && strings.HasPrefix(resp.Invocation.ErrorCode, "quota_exceeded:") {
		writeGovernanceError(w, http.StatusForbidden, errors.New(resp.Invocation.ErrorCode))
		return
	}
	// Phase 8.1: the redacted response volume meters storage_bytes.
	// Best-effort: the volume is unknowable before the outbound call,
	// so it cannot be enforced fail-closed at dispatch time (the
	// storage quota IS enforced fail-closed at export time, where the
	// payload is fully materialized before anything is streamed).
	if resp.Response != nil {
		if payload, err := json.Marshal(resp.Response); err == nil {
			s.recordUsageBestEffort(tenant.TenantID, usage.MetricStorageBytes, int64(len(payload)))
		}
	}
	writeJSON(w, http.StatusOK, GovernanceDispatchResponse{
		Decision: resp.Decision, Allowed: resp.Allowed, DispatchMode: resp.DispatchMode,
		Invocation: resp.Invocation, Response: resp.Response,
	})
}

// ---------------------------------------------------------------------
// Phase 3: emergency controls, budgets, evidence, verification, outbox
// ---------------------------------------------------------------------

// governanceControlMutation is the shared driver for emergency control
// mutations. The entity id comes from the route; identity and tenant
// come from the verified context; reason is required (the security
// operator's justification is part of the immutable evidence chain).
func (s *Server) governanceControlMutation(
	entityID string,
	call func(ctx context.Context, tenantID, entityID, actor string, admin bool, req ControlRequest) (EmergencyControl, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := tenantFromContext(r.Context())
		if !ok {
			writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
			return
		}
		if s.governance == nil {
			writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
			return
		}
		actor, _, ok := s.governanceActor(w, r)
		if !ok {
			return
		}
		id := strings.TrimSpace(r.PathValue(entityID))
		if id == "" {
			writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_entity_id"))
			return
		}
		var req ControlRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		control, err := call(ctx, tenant.TenantID, id, actor, hasScope(tenant, "admin"), req)
		if err != nil {
			writeGovernanceServiceError(w, err, "control_mutation_failed")
			return
		}
		writeJSON(w, http.StatusOK, GovernanceControlResponse{Control: control})
	}
}

func (s *Server) killSwitchGovernanceAgent(w http.ResponseWriter, r *http.Request) {
	s.governanceControlMutation("agent_id", s.governance.KillSwitchAgent)(w, r)
}

func (s *Server) resumeGovernanceAgent(w http.ResponseWriter, r *http.Request) {
	s.governanceControlMutation("agent_id", s.governance.ResumeAgent)(w, r)
}

func (s *Server) killSwitchGovernanceAgentVersion(w http.ResponseWriter, r *http.Request) {
	s.governanceControlMutation("version_id", s.governance.KillSwitchAgentVersion)(w, r)
}

func (s *Server) resumeGovernanceAgentVersion(w http.ResponseWriter, r *http.Request) {
	s.governanceControlMutation("version_id", s.governance.ResumeAgentVersion)(w, r)
}

func (s *Server) killSwitchGovernanceTool(w http.ResponseWriter, r *http.Request) {
	s.governanceControlMutation("tool_id", s.governance.KillSwitchTool)(w, r)
}

func (s *Server) resumeGovernanceTool(w http.ResponseWriter, r *http.Request) {
	s.governanceControlMutation("tool_id", s.governance.ResumeTool)(w, r)
}

func (s *Server) revokeGovernanceDelegation(w http.ResponseWriter, r *http.Request) {
	s.governanceControlMutation("grant_id", s.governance.RevokeDelegationGrant)(w, r)
}

func (s *Server) terminateGovernanceRun(w http.ResponseWriter, r *http.Request) {
	s.governanceControlMutation("run_id", s.governance.TerminateRun)(w, r)
}

func (s *Server) listGovernanceEmergencyControls(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	controls, err := s.governance.ListEmergencyControls(ctx, tenant.TenantID)
	if err != nil {
		writeGovernanceServiceError(w, err, "controls_query_failed")
		return
	}
	if controls == nil {
		controls = []EmergencyControl{}
	}
	writeJSON(w, http.StatusOK, GovernanceControlsResponse{Controls: controls, Count: len(controls)})
}

// Budgets

func (s *Server) upsertGovernanceBudget(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	actor, _, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	var req struct {
		ScopeType      string `json:"scope_type"`
		AgentVersionID string `json:"agent_version_id"`
		GrantID        string `json:"grant_id"`
		BudgetPolicyRequest
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	budget, err := s.governance.UpsertBudget(ctx, tenant.TenantID, actor, hasScope(tenant, "admin"), req.ScopeType, req.AgentVersionID, req.GrantID, req.BudgetPolicyRequest)
	if err != nil {
		writeGovernanceServiceError(w, err, "budget_upsert_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceBudgetResponse{Budget: budget})
}

func (s *Server) getGovernanceEffectiveBudget(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	budget, err := s.governance.GetEffectiveBudget(ctx, tenant.TenantID, strings.TrimSpace(r.URL.Query().Get("agent_version_id")), strings.TrimSpace(r.URL.Query().Get("grant_id")))
	if err != nil {
		writeGovernanceServiceError(w, err, "budget_query_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceBudgetResponse{Budget: budget})
}

func (s *Server) listGovernanceBudgets(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	budgets, err := s.governance.ListBudgets(ctx, tenant.TenantID)
	if err != nil {
		writeGovernanceServiceError(w, err, "budgets_query_failed")
		return
	}
	if budgets == nil {
		budgets = []BudgetPolicy{}
	}
	writeJSON(w, http.StatusOK, GovernanceBudgetsResponse{Budgets: budgets, Count: len(budgets)})
}

// Evidence read model

// evidenceFilterFromQuery parses the tenant-scoped evidence filter from
// query parameters. Unknown parameters are ignored; malformed numbers
// fail the request (no silent defaults).
func evidenceFilterFromQuery(w http.ResponseWriter, r *http.Request) (EvidenceFilter, bool) {
	q := r.URL.Query()
	f := EvidenceFilter{
		From: strings.TrimSpace(q.Get("from")), To: strings.TrimSpace(q.Get("to")),
		AgentID: strings.TrimSpace(q.Get("agent_id")), AgentVersionID: strings.TrimSpace(q.Get("agent_version_id")),
		OwnerPrincipal: strings.TrimSpace(q.Get("owner_principal")), UserID: strings.TrimSpace(q.Get("user_id")),
		ToolID: strings.TrimSpace(q.Get("tool_id")), ActionID: strings.TrimSpace(q.Get("action_id")),
		RunStatus: strings.TrimSpace(q.Get("run_status")), Decision: strings.TrimSpace(q.Get("decision")),
		ReasonCode: strings.TrimSpace(q.Get("reason_code")), TraceID: strings.TrimSpace(q.Get("trace_id")),
		Cursor: strings.TrimSpace(q.Get("cursor")),
	}
	if k := strings.TrimSpace(q.Get("kinds")); k != "" {
		for _, part := range strings.Split(k, ",") {
			if part = strings.TrimSpace(part); part != "" {
				f.Kinds = append(f.Kinds, part)
			}
		}
	}
	if l := strings.TrimSpace(q.Get("limit")); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n <= 0 {
			writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_limit"))
			return f, false
		}
		f.Limit = n
	}
	if f.Limit == 0 {
		f.Limit = 50
	}
	if f.Limit > 200 {
		f.Limit = 200
	}
	return f, true
}

func (s *Server) queryGovernanceEvidence(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	filter, ok := evidenceFilterFromQuery(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	page, err := s.governance.QueryEvidence(ctx, tenant.TenantID, filter)
	if err != nil {
		writeGovernanceServiceError(w, err, "evidence_query_failed")
		return
	}
	if page.Events == nil {
		page.Events = []EvidenceEvent{}
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) getGovernanceEvidenceEvent(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	eventID := strings.TrimSpace(r.PathValue("evidence_id"))
	if eventID == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_event_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	event, err := s.governance.GetEvidenceEvent(ctx, tenant.TenantID, eventID)
	if err != nil {
		writeGovernanceServiceError(w, err, "evidence_event_query_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceEvidenceEventResponse{Event: event})
}

func (s *Server) getGovernanceRunTimeline(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	runID := strings.TrimSpace(r.PathValue("run_id"))
	if runID == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_run_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	events, err := s.governance.GetRunTimeline(ctx, tenant.TenantID, runID)
	if err != nil {
		writeGovernanceServiceError(w, err, "run_timeline_failed")
		return
	}
	if events == nil {
		events = []EvidenceEvent{}
	}
	writeJSON(w, http.StatusOK, GovernanceTimelineResponse{Events: events, Count: len(events)})
}

func (s *Server) getGovernanceAgentActivity(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	agentID := strings.TrimSpace(r.PathValue("agent_id"))
	if agentID == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_agent_id"))
		return
	}
	filter, ok := evidenceFilterFromQuery(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	events, err := s.governance.GetAgentActivity(ctx, tenant.TenantID, agentID, filter)
	if err != nil {
		writeGovernanceServiceError(w, err, "agent_activity_failed")
		return
	}
	if events == nil {
		events = []EvidenceEvent{}
	}
	writeJSON(w, http.StatusOK, GovernanceActivityResponse{Events: events, Count: len(events)})
}

// Audit verification & checkpoints

func (s *Server) verifyGovernanceAuditChain(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	q := r.URL.Query()
	createCheckpoint := strings.TrimSpace(q.Get("create_checkpoint")) == "true"
	checkpointID := strings.TrimSpace(q.Get("checkpoint_id"))
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	result, err := s.governance.VerifyAuditChain(ctx, tenant.TenantID, checkpointID, createCheckpoint)
	if err != nil {
		writeGovernanceServiceError(w, err, "audit_verify_failed")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) listGovernanceCheckpoints(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	checkpoints, err := s.governance.ListCheckpoints(ctx, tenant.TenantID)
	if err != nil {
		writeGovernanceServiceError(w, err, "checkpoints_query_failed")
		return
	}
	if checkpoints == nil {
		checkpoints = []EvidenceCheckpoint{}
	}
	writeJSON(w, http.StatusOK, GovernanceCheckpointsResponse{Checkpoints: checkpoints, Count: len(checkpoints)})
}

// Outbox surface

func (s *Server) listGovernanceOutbox(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	q := r.URL.Query()
	limit := 50
	if l := strings.TrimSpace(q.Get("limit")); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n <= 0 {
			writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_limit"))
			return
		}
		limit = n
		if limit > 200 {
			limit = 200
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	events, nextCursor, err := s.governance.ListOutboxEvents(ctx, tenant.TenantID, strings.TrimSpace(q.Get("status")), limit, strings.TrimSpace(q.Get("cursor")))
	if err != nil {
		writeGovernanceServiceError(w, err, "outbox_query_failed")
		return
	}
	if events == nil {
		events = []OutboxEvent{}
	}
	writeJSON(w, http.StatusOK, GovernanceOutboxResponse{Events: events, NextCursor: nextCursor, Count: len(events)})
}

func (s *Server) retryGovernanceOutbox(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	eventID := strings.TrimSpace(r.PathValue("event_id"))
	if eventID == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_event_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	event, err := s.governance.RetryOutboxEvent(ctx, tenant.TenantID, eventID)
	if err != nil {
		writeGovernanceServiceError(w, err, "outbox_retry_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceOutboxEventResponse{Event: event})
}

// ---------------------------------------------------------------------
// Response envelopes
// ---------------------------------------------------------------------

type GovernanceToolResponse struct {
	Tool Tool `json:"tool"`
}

type GovernanceToolListResponse struct {
	Tools []Tool `json:"tools"`
	Count int    `json:"count"`
}

type GovernanceToolDetailResponse struct {
	Tool    Tool         `json:"tool"`
	Actions []ToolAction `json:"actions"`
}

type GovernanceToolActionResponse struct {
	Action ToolAction `json:"action"`
}

type GovernanceToolActionsResponse struct {
	Actions []ToolAction `json:"actions"`
	Count   int          `json:"count"`
}

type GovernanceGrantResponse struct {
	Grant AgentToolGrant `json:"grant"`
}

type GovernanceGrantListResponse struct {
	Grants []AgentToolGrant `json:"grants"`
	Count  int              `json:"count"`
}

type GovernanceDelegationResponse struct {
	Grant              DelegationGrant `json:"grant"`
	Token              string          `json:"token,omitempty"`
	TokenAlreadyIssued bool            `json:"token_already_issued,omitempty"`
}

type GovernanceRunResponse struct {
	Run       AgentRun         `json:"run"`
	Decisions []ActionDecision `json:"decisions"`
}

type GovernanceRunListResponse struct {
	Runs  []AgentRun `json:"runs"`
	Count int        `json:"count"`
}

type GovernanceRunDetailResponse struct {
	Run       AgentRun         `json:"run"`
	Decisions []ActionDecision `json:"decisions"`
}

type GovernanceEvaluateResponse struct {
	Decision ActionDecision `json:"decision"`
	Allowed  bool           `json:"allowed"`
}

type GovernanceApprovalResponse struct {
	Approval ActionApproval `json:"approval"`
	Denied   bool           `json:"denied"`
}

type GovernanceDispatchResponse struct {
	Decision     ActionDecision       `json:"decision"`
	Allowed      bool                 `json:"allowed"`
	DispatchMode string               `json:"dispatch_mode"`
	Invocation   *ConnectorInvocation `json:"invocation,omitempty"`
	Response     any                  `json:"response,omitempty"`
}

type GovernanceControlResponse struct {
	Control EmergencyControl `json:"control"`
}

type GovernanceControlsResponse struct {
	Controls []EmergencyControl `json:"controls"`
	Count    int                `json:"count"`
}

type GovernanceBudgetResponse struct {
	Budget BudgetPolicy `json:"budget"`
}

type GovernanceBudgetsResponse struct {
	Budgets []BudgetPolicy `json:"budgets"`
	Count   int            `json:"count"`
}

type GovernanceEvidenceEventResponse struct {
	Event EvidenceEvent `json:"event"`
}

type GovernanceTimelineResponse struct {
	Events []EvidenceEvent `json:"events"`
	Count  int             `json:"count"`
}

type GovernanceActivityResponse struct {
	Events []EvidenceEvent `json:"events"`
	Count  int             `json:"count"`
}

type GovernanceCheckpointsResponse struct {
	Checkpoints []EvidenceCheckpoint `json:"checkpoints"`
	Count       int                  `json:"count"`
}

type GovernanceOutboxResponse struct {
	Events     []OutboxEvent `json:"events"`
	NextCursor string        `json:"next_cursor,omitempty"`
	Count      int           `json:"count"`
}

type GovernanceOutboxEventResponse struct {
	Event OutboxEvent `json:"event"`
}

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

func writeGovernanceError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, GovernanceAPIError{Error: err.Error()})
}

// writeGovernanceServiceError maps governance sentinel errors to HTTP
// statuses; unknown errors become 500 with the generic code so no DB
// internals leak. Raw delegation tokens are NEVER included in any
// message.
func writeGovernanceServiceError(w http.ResponseWriter, err error, genericCode string) {
	switch {
	case errors.Is(err, ErrGovernanceUnavailable):
		writeGovernanceError(w, http.StatusServiceUnavailable, err)
	case errors.Is(err, ErrGovernanceNotAuthorized):
		writeGovernanceError(w, http.StatusForbidden, err)
	case errors.Is(err, ErrInvalidRequest):
		writeGovernanceError(w, http.StatusBadRequest, err)
	case errors.Is(err, ErrDelegationInvalid), errors.Is(err, ErrDelegationExpired):
		writeGovernanceError(w, http.StatusUnauthorized, err)
	case errors.Is(err, ErrDelegationReused), errors.Is(err, ErrIdempotencyConflict):
		writeGovernanceError(w, http.StatusConflict, err)
	case errors.Is(err, ErrToolNameConflict), errors.Is(err, ErrActionConflict), errors.Is(err, ErrGrantConflict):
		writeGovernanceError(w, http.StatusConflict, err)
	case errors.Is(err, ErrToolNotFound), errors.Is(err, ErrActionNotFound),
		errors.Is(err, ErrGrantNotFound), errors.Is(err, ErrRunNotFound), errors.Is(err, ErrApprovalNotFound),
		errors.Is(err, ErrControlNotFound), errors.Is(err, ErrEvidenceNotFound),
		errors.Is(err, ErrCheckpointNotFound), errors.Is(err, ErrOutboxEventNotFound),
		errors.Is(err, ErrConnectorNotFound), errors.Is(err, ErrConnectorNoManifest):
		writeGovernanceError(w, http.StatusNotFound, err)
	case errors.Is(err, ErrTrustNotFound), errors.Is(err, ErrExternalNotFound),
		errors.Is(err, ErrConsentNotFound), errors.Is(err, ErrTransferPolicyNotFound):
		writeGovernanceError(w, http.StatusNotFound, err)
	case errors.Is(err, ErrControlIrreversible), errors.Is(err, ErrControlInvalidState),
		errors.Is(err, ErrControlKillSwitched), errors.Is(err, ErrControlSuspended), errors.Is(err, ErrRunTerminated):
		writeGovernanceError(w, http.StatusConflict, err)
	case errors.Is(err, ErrConnectorNameConflict), errors.Is(err, ErrConnectorInvalidState):
		writeGovernanceError(w, http.StatusConflict, err)
	case errors.Is(err, ErrTrustConflict), errors.Is(err, ErrExternalConflict), errors.Is(err, ErrConsentConflict),
		errors.Is(err, ErrConsentRevoked), errors.Is(err, ErrTrustInvalidState), errors.Is(err, ErrNonceReplay),
		errors.Is(err, ErrTransferPolicyStateInvalid):
		writeGovernanceError(w, http.StatusConflict, err)
	case errors.Is(err, ErrDelegationInvalid), errors.Is(err, ErrDelegationExpired):
		writeGovernanceError(w, http.StatusUnauthorized, err)
	case errors.Is(err, ErrExternalInvalid), errors.Is(err, ErrExternalExpired):
		writeGovernanceError(w, http.StatusUnauthorized, err)
	case errors.Is(err, ErrConnectorUnavailable), errors.Is(err, ErrConnectorNotActive),
		errors.Is(err, ErrConnectorRevoked), errors.Is(err, ErrConnectorRegion),
		errors.Is(err, ErrConnectorUnregistered):
		writeGovernanceError(w, http.StatusServiceUnavailable, err)
	case errors.Is(err, ErrConnectorInvalidConfig), errors.Is(err, ErrConnectorDisabledTLS):
		writeGovernanceError(w, http.StatusBadRequest, err)
	case errors.Is(err, ErrDelegationRevoked), errors.Is(err, ErrDelegationRegion), errors.Is(err, ErrDelegationRun),
		errors.Is(err, ErrDelegationInactive), errors.Is(err, ErrDelegationPurpose), errors.Is(err, ErrDelegationNotAllowed),
		errors.Is(err, ErrToolInactive), errors.Is(err, ErrActionInactive), errors.Is(err, ErrGrantRevoked),
		errors.Is(err, ErrGrantRegion), errors.Is(err, ErrCallLimitExceeded), errors.Is(err, ErrRunNotActive),
		errors.Is(err, ErrApprovalRequired), errors.Is(err, ErrApprovalDenied), errors.Is(err, ErrApprovalConsumed),
		errors.Is(err, ErrBudgetExhausted),
		// Phase 6: trust, chain, consent, and external-agent denials
		// all fail closed as 403.
		errors.Is(err, ErrTrustNotActive), errors.Is(err, ErrTrustExpired), errors.Is(err, ErrTrustRequiresApproval),
		errors.Is(err, ErrChainTooDeep), errors.Is(err, ErrScopeExceedsParent), errors.Is(err, ErrExpiryExceedsParent),
		errors.Is(err, ErrRegionExceedsParent), errors.Is(err, ErrCrossTenantDenied), errors.Is(err, ErrCrossRegionDenied),
		errors.Is(err, ErrParentRevoked), errors.Is(err, ErrParentSuspended), errors.Is(err, ErrChildCannotDelegate),
		errors.Is(err, ErrChainBroken), errors.Is(err, ErrNoParentGrant), errors.Is(err, ErrExternalNotActive),
		errors.Is(err, ErrExternalUntrusted), errors.Is(err, ErrExternalNoTrust), errors.Is(err, ErrExternalDemoDenied),
		errors.Is(err, ErrConsentRequired), errors.Is(err, ErrConsentExpired), errors.Is(err, ErrTransferDenied):
		writeGovernanceError(w, http.StatusForbidden, err)
	case errors.Is(err, ErrOutboxBackpressure):
		// Phase 8.2: the evidence pipeline is backed up. Refuse the
		// work fail-closed instead of buffering it.
		writeGovernanceError(w, http.StatusServiceUnavailable, err)
	default:
		writeGovernanceError(w, http.StatusInternalServerError, errors.New(genericCode))
	}
}
