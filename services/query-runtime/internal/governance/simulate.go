package governance

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"groundwork/query-runtime/internal/relationship"
	"groundwork/query-runtime/internal/runtime"
)

// SimulateAction is the read-only policy simulator (Phase 7). It walks
// the SAME gate pipeline as the shared evaluator (evaluateInTx), in the
// same order, with the same reasons/reason codes — but it NEVER writes:
// no evidence, no budget counters, no approval consumption, no outbox.
//
// This is deliberately NOT a second authorization path: it is an
// analysis view over current state. The authoritative runtime decision
// remains EvaluateAction (invariant: services and the shared evaluator
// are authoritative). A divergence between simulateGates and
// evaluateInTx is a correctness bug.
func (s *Service) SimulateAction(ctx context.Context, tenantID, region string, req runtime.SimulateActionRequest) (runtime.SimulateActionResponse, error) {
	if strings.TrimSpace(req.AgentID) == "" || strings.TrimSpace(req.ToolName) == "" || strings.TrimSpace(req.Action) == "" {
		return runtime.SimulateActionResponse{}, errors.Join(runtime.ErrInvalidRequest, errors.New("simulate: agent_id, tool_name, and action are required"))
	}
	if s.agents == nil {
		return runtime.SimulateActionResponse{}, runtime.ErrAgentUnavailable
	}
	var resp runtime.SimulateActionResponse
	err := s.store.Transact(ctx, "simulate:"+req.AgentID, func(tx TxStore) error {
		resp = s.simulateInTx(ctx, tx, tenantID, region, req)
		return nil
	})
	if err != nil {
		return runtime.SimulateActionResponse{}, err
	}
	return resp, nil
}

// simulateInTx evaluates every gate and records each outcome. The
// decision is the first blocking gate (deny/approval_required/fail
// closed), matching evaluator precedence; remaining gates are still
// reported so the operator sees the full picture.
func (s *Service) simulateInTx(ctx context.Context, tx TxStore, tenantID, region string, req runtime.SimulateActionRequest) runtime.SimulateActionResponse {
	checks := make([]runtime.GateCheck, 0, 10)
	add := func(gate, name, status, detail, reasonCode string) {
		checks = append(checks, runtime.GateCheck{Gate: gate, Name: name, Status: status, Detail: detail, ReasonCode: reasonCode})
	}
	failClosed := func(detail, reasonCode string) runtime.SimulateActionResponse {
		return runtime.SimulateActionResponse{
			Decision: runtime.DecisionFailClosed, Allowed: false,
			Reason: detail, ReasonCode: reasonCode, Checks: checks,
			Simulated: true, SimulatedAt: s.now().UTC(),
		}
	}
	deny := func(detail, reasonCode string) runtime.SimulateActionResponse {
		return runtime.SimulateActionResponse{
			Decision: runtime.DecisionDenied, Allowed: false,
			Reason: detail, ReasonCode: reasonCode, Checks: checks,
			Simulated: true, SimulatedAt: s.now().UTC(),
		}
	}

	// 0. Emergency controls. Run and delegation rows do not exist in
	//    simulation (no token, no run) — reported as skipped. Agent,
	//    version, tool, and grant controls are real checks.
	add("emergency_controls", "run control", runtime.GateStatusSkipped, "no run in simulation; runtime evaluation checks the bound run", "")
	add("emergency_controls", "delegation control", runtime.GateStatusSkipped, "no delegation token in simulation; runtime evaluation checks the bound grant", "")
	if c, err := tx.GetEmergencyControl(ctx, tenantID, runtime.ControlEntityAgent, req.AgentID); err == nil {
		if c.ControlState == runtime.ControlStateKillSwitched {
			add("emergency_controls", "agent control", runtime.GateStatusFailed, "agent kill-switched", "emergency:kill_switch")
			return deny("agent kill-switched", "emergency:kill_switch")
		}
		if c.ControlState == runtime.ControlStateSuspended {
			add("emergency_controls", "agent control", runtime.GateStatusFailed, "agent suspended", "emergency:suspend")
			return deny("agent suspended", "emergency:suspend")
		}
		if c.ControlState == runtime.ControlStateRevoked {
			add("emergency_controls", "agent control", runtime.GateStatusFailed, "agent revoked", "emergency:revoke")
			return deny("agent revoked", "emergency:revoke")
		}
	} else if !errors.Is(err, runtime.ErrControlNotFound) {
		add("emergency_controls", "agent control", runtime.GateStatusUnavailable, "emergency control lookup failed", "")
		return failClosed("emergency control lookup failed", "")
	}
	add("emergency_controls", "agent control", runtime.GateStatusPassed, "no emergency control on agent", "")

	// 1. Delegation: skipped by design (see request doc). The grant gate
	//    below is the simulation equivalent of permitted+live scope.
	add("delegation", "live delegation", runtime.GateStatusSkipped, "runtime evaluation requires a live delegation token; simulation assumes the matching grant is the authority", "")

	// 2. Active agent + active version (defaults to the agent's active version).
	agent, versions, _, err := s.agents.GetAgent(ctx, tenantID, req.AgentID)
	if err != nil {
		add("agent", "agent lifecycle", runtime.GateStatusUnavailable, "agent lookup failed", "")
		return failClosed("agent lookup failed", "")
	}
	if agent.LifecycleState != runtime.AgentStateActive {
		add("agent", "agent lifecycle", runtime.GateStatusFailed, "agent not active", "")
		return deny("agent not active", "")
	}
	add("agent", "agent lifecycle", runtime.GateStatusPassed, "agent active", "")
	versionID := strings.TrimSpace(req.VersionID)
	if versionID == "" {
		versionID = agent.ActiveVersionID
	}
	versionOK := false
	for _, v := range versions {
		if v.ID == versionID && v.Status == runtime.VersionStatusActive {
			versionOK = true
			break
		}
	}
	if versionID == "" {
		add("agent", "agent version", runtime.GateStatusFailed, "no active version on agent", "")
		return deny("agent version not active", "")
	}
	if !versionOK {
		add("agent", "agent version", runtime.GateStatusFailed, "agent version not active", "")
		return deny("agent version not active", "")
	}
	add("agent", "agent version", runtime.GateStatusPassed, "version active: "+versionID, "")
	if c, err := tx.GetEmergencyControl(ctx, tenantID, runtime.ControlEntityAgentVersion, versionID); err == nil {
		if c.ControlState == runtime.ControlStateKillSwitched {
			add("emergency_controls", "version control", runtime.GateStatusFailed, "agent version kill-switched", "emergency:kill_switch")
			return deny("agent version kill-switched", "emergency:kill_switch")
		}
	} else if !errors.Is(err, runtime.ErrControlNotFound) {
		add("emergency_controls", "version control", runtime.GateStatusUnavailable, "emergency control lookup failed", "")
		return failClosed("emergency control lookup failed", "")
	}
	add("emergency_controls", "version control", runtime.GateStatusPassed, "no emergency control on version", "")

	// 3. Delegation permitted action: subsumed by the grant gate in
	//    simulation (no token). Reported as skipped for transparency.
	add("permitted_actions", "delegation permitted actions", runtime.GateStatusSkipped, "no delegation token in simulation; the grant's tool/action is the assumed permitted set", "")

	// 4. Registered, active tool + action.
	toolName := strings.TrimSpace(req.ToolName)
	actionName := strings.TrimSpace(req.Action)
	if toolName == "" || actionName == "" {
		add("tool", "tool registration", runtime.GateStatusFailed, "missing tool or action", "")
		return deny("missing tool or action", "")
	}
	tool, err := tx.GetToolByName(ctx, tenantID, toolName)
	if err != nil {
		add("tool", "tool registration", runtime.GateStatusFailed, "tool not found", "")
		return deny("tool not found", "")
	}
	toolAction, err := tx.GetToolActionByName(ctx, tenantID, tool.ID, actionName)
	if err != nil {
		add("tool", "tool action", runtime.GateStatusFailed, "tool action not found", "")
		return deny("tool action not found", "")
	}
	if tool.Lifecycle != runtime.ToolLifecycleActive {
		add("tool", "tool lifecycle", runtime.GateStatusFailed, "tool not active", "")
		return deny("tool not active", "")
	}
	if toolAction.Status != runtime.ActionStatusActive {
		add("tool", "tool action", runtime.GateStatusFailed, "tool action not active", "")
		return deny("tool action not active", "")
	}
	add("tool", "tool registration", runtime.GateStatusPassed, "tool active: "+tool.Name, "")
	add("tool", "tool action", runtime.GateStatusPassed, "action active: "+toolAction.Action, "")
	if c, err := tx.GetEmergencyControl(ctx, tenantID, runtime.ControlEntityTool, tool.ID); err == nil {
		if c.ControlState == runtime.ControlStateKillSwitched {
			add("emergency_controls", "tool control", runtime.GateStatusFailed, "tool kill-switched", "emergency:kill_switch")
			return deny("tool kill-switched", "emergency:kill_switch")
		}
	} else if !errors.Is(err, runtime.ErrControlNotFound) {
		add("emergency_controls", "tool control", runtime.GateStatusUnavailable, "emergency control lookup failed", "")
		return failClosed("emergency control lookup failed", "")
	}
	add("emergency_controls", "tool control", runtime.GateStatusPassed, "no emergency control on tool", "")

	// 5. Unrevoked grant honoring scope, region, call limit.
	grants, err := tx.GetGrantsForTuple(ctx, tenantID, req.AgentID, versionID, tool.ID, toolAction.ID)
	if err != nil {
		add("grant", "grant lookup", runtime.GateStatusUnavailable, "grant lookup failed", "")
		return failClosed("grant lookup failed", "")
	}
	var matched *runtime.AgentToolGrant
	for i := range grants {
		if !grants[i].RevokedAt.IsZero() {
			continue
		}
		if !scopeMatches(grants[i].ResourceScope, req.ResourceRef) {
			continue
		}
		if !regionMatches(grants[i].RegionConstraint, region) {
			continue
		}
		matched = &grants[i]
		break
	}
	if matched == nil {
		add("grant", "grant coverage", runtime.GateStatusFailed, "no active grant for tool action (scope, region, or revocation)", "")
		return deny("no active grant for tool action", "")
	}
	add("grant", "grant coverage", runtime.GateStatusPassed, "covered by grant "+matched.ID+" (scope "+matched.ResourceScope+", region "+matched.RegionConstraint+")", "")
	if c, err := tx.GetEmergencyControl(ctx, tenantID, runtime.ControlEntityToolGrant, matched.ID); err == nil {
		if c.ControlState == runtime.ControlStateKillSwitched {
			add("emergency_controls", "grant control", runtime.GateStatusFailed, "grant kill-switched", "emergency:kill_switch")
			return deny("grant kill-switched", "emergency:kill_switch")
		}
	} else if !errors.Is(err, runtime.ErrControlNotFound) {
		add("emergency_controls", "grant control", runtime.GateStatusUnavailable, "emergency control lookup failed", "")
		return failClosed("emergency control lookup failed", "")
	}
	add("emergency_controls", "grant control", runtime.GateStatusPassed, "no emergency control on grant", "")
	if matched.CallLimitPerRun > 0 {
		add("grant", "call limit", runtime.GateStatusSkipped, "call_limit_per_run="+strconv.Itoa(matched.CallLimitPerRun)+" applies per run; no run in simulation", "")
	}

	// 6. Budget policies: narrowest applicable scope (grant > version >
	//    tenant). Counter-based dimensions apply per run and are reported
	//    as skipped (no run); the policy itself is read for transparency.
	policy, err := s.GetEffectiveBudgetTx(ctx, tx, tenantID, versionID, matched.ID)
	if err != nil {
		add("budgets", "effective budget", runtime.GateStatusUnavailable, "budget lookup failed", "")
		return failClosed("budget lookup failed", "")
	}
	budgetDetails := []string{}
	if policy.MaxRunDurationSeconds > 0 {
		budgetDetails = append(budgetDetails, "max_run_duration_seconds="+strconv.Itoa(policy.MaxRunDurationSeconds))
	}
	if policy.MaxActionsPerRun > 0 {
		budgetDetails = append(budgetDetails, "max_actions_per_run="+strconv.Itoa(policy.MaxActionsPerRun))
	}
	if policy.MaxDeniedPerRun > 0 {
		budgetDetails = append(budgetDetails, "max_denied_per_run="+strconv.Itoa(policy.MaxDeniedPerRun))
	}
	if policy.MaxApprovalRequiredPerRun > 0 {
		budgetDetails = append(budgetDetails, "max_approval_required_per_run="+strconv.Itoa(policy.MaxApprovalRequiredPerRun))
	}
	if policy.MaxToolCallsPerActionPerRun > 0 {
		budgetDetails = append(budgetDetails, "max_tool_calls_per_action_per_run="+strconv.Itoa(policy.MaxToolCallsPerActionPerRun))
	}
	if policy.MaxCitationsPerQuery > 0 {
		budgetDetails = append(budgetDetails, "max_citations_per_query="+strconv.Itoa(policy.MaxCitationsPerQuery))
	}
	if len(budgetDetails) == 0 {
		add("budgets", "effective budget", runtime.GateStatusSkipped, "no budget policy configured", "")
	} else {
		add("budgets", "effective budget", runtime.GateStatusPassed, "budget policy applied per run; no run in simulation ("+strings.Join(budgetDetails, ", ")+")", "")
	}

	// 7. Relationship authorization for the (optional) verified principal.
	principal := strings.TrimSpace(req.PrincipalID)
	if principal == "" {
		add("relationship", "relationship permission", runtime.GateStatusSkipped, "no principal_id supplied; supply one to test relationship authorization", "")
	} else {
		if s.authorizer == nil {
			add("relationship", "relationship permission", runtime.GateStatusUnavailable, "permission backend unavailable", "")
			return failClosed("permission backend unavailable", "")
		}
		check := relationship.CheckRequest{
			TenantID:   tenantID,
			Subject:    relationship.UserRef(principal),
			Permission: relationship.PermissionUse,
			Resource:   relationship.ToolRef(tool.ID),
		}
		if !toolAction.ReadOnly {
			check.Permission = relationship.PermissionExecute
			check.Resource = relationship.ToolActionRef(tool.ID, toolAction.Action)
		}
		allowed, err := s.authorizer.Check(ctx, check)
		if err != nil || !allowed {
			add("relationship", "relationship permission", runtime.GateStatusFailed, "relationship permission denied for "+relationship.EncodeSubject(check.Subject)+" relation "+relationship.PermissionToRelation(check.Permission)+" object "+relationship.EncodeObject(check.Resource), "")
			return deny("relationship permission denied", "")
		}
		add("relationship", "relationship permission", runtime.GateStatusPassed, relationship.EncodeSubject(check.Subject)+" has relation "+relationship.PermissionToRelation(check.Permission)+" on "+relationship.EncodeObject(check.Resource), "")
	}

	// 8. Required one-time human approval.
	requiresApproval := matched.RequiresApproval || toolAction.RequiresHumanApproval
	if requiresApproval {
		add("approval", "human approval", runtime.GateStatusRequired, "one-time human approval required before dispatch (grant or action requires it)", "")
		return runtime.SimulateActionResponse{
			Decision: runtime.DecisionApprovalRequired, Allowed: false,
			Reason: "human approval required", Checks: checks,
			Simulated: true, SimulatedAt: s.now().UTC(),
		}
	}
	add("approval", "human approval", runtime.GateStatusPassed, "no approval required", "")

	return runtime.SimulateActionResponse{
		Decision: runtime.DecisionAllowed, Allowed: true,
		Reason: "allowed", Checks: checks,
		Simulated: true, SimulatedAt: s.now().UTC(),
	}
}
