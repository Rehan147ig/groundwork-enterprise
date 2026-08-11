package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	gwmetrics "groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/runtime"
)

// ---------------------------------------------------------------------
// Outbox helpers
// ---------------------------------------------------------------------

// enqueueOutbox buffers one security-relevant event in the current
// transaction. Payloads carry SAFE fields only (never tokens, secrets,
// assertions, or document text); a marshaling failure drops the event
// rather than failing the business operation.
func (s *Service) enqueueOutbox(ctx context.Context, tx TxStore, tenantID, eventType, eventID string, occurredAt time.Time, payload any) {
	if payload == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_ = tx.EnqueueOutbox(ctx, runtime.OutboxEvent{
		TenantID:      tenantID,
		EventID:       eventID,
		EventType:     eventType,
		SchemaVersion: 1,
		OccurredAt:    occurredAt,
		Payload:       data,
	})
}

func decisionPayload(d runtime.ActionDecision, traceID string) map[string]string {
	return map[string]string{
		"event_id":            d.ID,
		"tenant_id":           d.TenantID,
		"agent_id":            d.AgentID,
		"run_id":              d.RunID,
		"delegation_grant_id": d.DelegationGrantID,
		"tool_id":             d.ToolID,
		"action_id":           d.ActionID,
		"resource_ref":        d.ResourceRef,
		"decision":            d.Decision,
		"reason":              d.Reason,
		"reason_code":         d.ReasonCode,
		"policy_version":      d.PolicyVersion,
		"immutable_digest":    d.ImmutableDigest,
		"trace_id":            traceID,
	}
}

// enqueueDecision writes the action.decision outbox event for one
// evaluator outcome and publishes the SLO decision counter + evidence
// event counter (Phase 8.5). Every decision write funnels through here.
func (s *Service) enqueueDecision(ctx context.Context, tx TxStore, run runtime.AgentRun, d runtime.ActionDecision) {
	gwmetrics.RecordSLODecision(run.TenantID, d.Decision)
	gwmetrics.RecordEvidenceEvent(run.TenantID, runtime.EvidenceKindDecision)
	s.enqueueOutbox(ctx, tx, run.TenantID, runtime.OutboxEventActionDecision, d.ID, d.CreatedAt, decisionPayload(d, run.TraceID))
}

// ---------------------------------------------------------------------
// Budget counters (called after every evaluator outcome, same tx)
// ---------------------------------------------------------------------

// recordCounters increments the run budget counters for one decision.
// toolID/actionID are set for the allowed path so the per-tool-action
// call counter moves too.
func (s *Service) recordCounters(ctx context.Context, tx TxStore, run runtime.AgentRun, d runtime.ActionDecision, toolID, actionID string) {
	switch d.Decision {
	case runtime.DecisionAllowed:
		_, _ = tx.IncrementBudgetCounter(ctx, run.TenantID, run.ID, "", runtime.BudgetCounterActions)
		if toolID != "" && actionID != "" {
			_, _ = tx.IncrementBudgetCounter(ctx, run.TenantID, run.ID, toolID+"|"+actionID, runtime.BudgetCounterToolCalls)
		}
	case runtime.DecisionDenied, runtime.DecisionFailClosed:
		_, _ = tx.IncrementBudgetCounter(ctx, run.TenantID, run.ID, "", runtime.BudgetCounterActions)
		_, _ = tx.IncrementBudgetCounter(ctx, run.TenantID, run.ID, "", runtime.BudgetCounterDenied)
	case runtime.DecisionApprovalRequired:
		_, _ = tx.IncrementBudgetCounter(ctx, run.TenantID, run.ID, "", runtime.BudgetCounterActions)
		_, _ = tx.IncrementBudgetCounter(ctx, run.TenantID, run.ID, "", runtime.BudgetCounterApprovalRequired)
	}
}

// budgetKey packs tool+action into the per-action counter key.
func budgetKey(toolID, actionID string) string { return toolID + "|" + actionID }

// ---------------------------------------------------------------------
// Emergency controls
// ---------------------------------------------------------------------

func (s *Service) KillSwitchAgent(ctx context.Context, tenantID, agentID, actor string, admin bool, req runtime.ControlRequest) (runtime.EmergencyControl, error) {
	return s.setControl(ctx, tenantID, runtime.ControlEntityAgent, agentID, actor, admin, runtime.ControlActionKillSwitch, runtime.ControlStateKillSwitched, req)
}

func (s *Service) ResumeAgent(ctx context.Context, tenantID, agentID, actor string, admin bool, req runtime.ControlRequest) (runtime.EmergencyControl, error) {
	return s.setControl(ctx, tenantID, runtime.ControlEntityAgent, agentID, actor, admin, runtime.ControlActionResume, runtime.ControlStateActive, req)
}

func (s *Service) KillSwitchAgentVersion(ctx context.Context, tenantID, versionID, actor string, admin bool, req runtime.ControlRequest) (runtime.EmergencyControl, error) {
	return s.setControl(ctx, tenantID, runtime.ControlEntityAgentVersion, versionID, actor, admin, runtime.ControlActionKillSwitch, runtime.ControlStateKillSwitched, req)
}

func (s *Service) ResumeAgentVersion(ctx context.Context, tenantID, versionID, actor string, admin bool, req runtime.ControlRequest) (runtime.EmergencyControl, error) {
	return s.setControl(ctx, tenantID, runtime.ControlEntityAgentVersion, versionID, actor, admin, runtime.ControlActionResume, runtime.ControlStateActive, req)
}

func (s *Service) KillSwitchTool(ctx context.Context, tenantID, toolID, actor string, admin bool, req runtime.ControlRequest) (runtime.EmergencyControl, error) {
	return s.setControl(ctx, tenantID, runtime.ControlEntityTool, toolID, actor, admin, runtime.ControlActionKillSwitch, runtime.ControlStateKillSwitched, req)
}

func (s *Service) ResumeTool(ctx context.Context, tenantID, toolID, actor string, admin bool, req runtime.ControlRequest) (runtime.EmergencyControl, error) {
	return s.setControl(ctx, tenantID, runtime.ControlEntityTool, toolID, actor, admin, runtime.ControlActionResume, runtime.ControlStateActive, req)
}

func (s *Service) RevokeDelegationGrant(ctx context.Context, tenantID, grantID, actor string, admin bool, req runtime.ControlRequest) (runtime.EmergencyControl, error) {
	return s.setControl(ctx, tenantID, runtime.ControlEntityDelegation, grantID, actor, admin, runtime.ControlActionRevoke, runtime.ControlStateRevoked, req)
}

func (s *Service) TerminateRun(ctx context.Context, tenantID, runID, actor string, admin bool, req runtime.ControlRequest) (runtime.EmergencyControl, error) {
	return s.setControl(ctx, tenantID, runtime.ControlEntityRun, runID, actor, admin, runtime.ControlActionTerminate, runtime.ControlStateRevoked, req)
}

func (s *Service) ListEmergencyControls(ctx context.Context, tenantID string) ([]runtime.EmergencyControl, error) {
	return s.store.ListEmergencyControls(ctx, tenantID)
}

// validateControlTransition enforces the control state machine:
//   - kill_switch: any live state -> kill_switched (re-asserting is
//     idempotent); never from revoked.
//   - resume: kill_switched or suspended -> active; never from active
//     (invalid) or revoked (irreversible).
//   - revoke / terminate: any live state -> revoked (idempotent).
func validateControlTransition(entityType, actionType, previousState string) (string, error) {
	switch actionType {
	case runtime.ControlActionKillSwitch:
		if previousState == runtime.ControlStateRevoked {
			return "", runtime.ErrControlIrreversible
		}
		return runtime.ControlStateKillSwitched, nil
	case runtime.ControlActionResume:
		switch previousState {
		case runtime.ControlStateActive:
			return "", runtime.ErrControlInvalidState
		case runtime.ControlStateRevoked:
			return "", runtime.ErrControlIrreversible
		default:
			return runtime.ControlStateActive, nil
		}
	case runtime.ControlActionRevoke, runtime.ControlActionTerminate:
		return runtime.ControlStateRevoked, nil
	default:
		return "", runtime.ErrControlInvalidState
	}
}

// setControl is the single mutation path for every emergency control.
// It validates identity + reason, transitions the control row, records
// immutable hash-chained evidence, applies side effects (run
// termination, delegation revocation), and enqueues the outbox event —
// all in one transaction.
func (s *Service) setControl(ctx context.Context, tenantID, entityType, entityID, actor string, admin bool, actionType, targetState string, req runtime.ControlRequest) (runtime.EmergencyControl, error) {
	if !admin {
		return runtime.EmergencyControl{}, runtime.ErrGovernanceNotAuthorized
	}
	if actor == "" {
		return runtime.EmergencyControl{}, runtime.ErrInvalidRequest
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return runtime.EmergencyControl{}, fmt.Errorf("%w: reason required for emergency control", runtime.ErrInvalidRequest)
	}
	if entityID == "" {
		return runtime.EmergencyControl{}, runtime.ErrInvalidRequest
	}

	var control runtime.EmergencyControl
	err := s.store.Transact(ctx, "control:"+tenantID, func(tx TxStore) error {
		current, err := tx.GetEmergencyControl(ctx, tenantID, entityType, entityID)
		previousState := runtime.ControlStateActive
		if err == nil {
			previousState = current.ControlState
		} else if !errors.Is(err, runtime.ErrControlNotFound) {
			return err
		}
		// Idempotent re-assertion of the same state is a no-op.
		if previousState == targetState && previousState != runtime.ControlStateActive {
			control = current
			return nil
		}
		newState, err := validateControlTransition(entityType, actionType, previousState)
		if err != nil {
			return err
		}

		// Entity existence validation before any state moves.
		if err := s.validateControlEntity(ctx, tx, tenantID, entityType, entityID); err != nil {
			return err
		}

		control = runtime.EmergencyControl{
			TenantID:         tenantID,
			EntityType:       entityType,
			EntityID:         entityID,
			ControlState:     newState,
			Reason:           reason,
			Scope:            strings.TrimSpace(req.Scope),
			ActorPrincipalID: actor,
		}
		control, err = tx.SetEmergencyControl(ctx, control)
		if err != nil {
			return err
		}
		action := runtime.EmergencyControlAction{
			TenantID:         tenantID,
			EntityType:       entityType,
			EntityID:         entityID,
			ActionType:       actionType,
			ActorPrincipalID: actor,
			Reason:           reason,
			Scope:            strings.TrimSpace(req.Scope),
			PreviousState:    previousState,
			NewState:         newState,
			CreatedAt:        s.now().UTC().Truncate(time.Microsecond),
		}
		if _, err := tx.AppendEmergencyAction(ctx, action); err != nil {
			return err
		}
		gwmetrics.RecordControlEvent(tenantID, entityType, actionType)
		gwmetrics.RecordEvidenceEvent(tenantID, runtime.EvidenceKindEmergencyControl)

		// Side effects: kill-switched agents/versions and revoked
		// delegations terminate their active runs.
		switch entityType {
		case runtime.ControlEntityAgent:
			if err := s.terminateRunsOfAgent(ctx, tx, tenantID, entityID, "kill_switched"); err != nil {
				return err
			}
		case runtime.ControlEntityAgentVersion:
			if err := s.terminateRunsOfVersion(ctx, tx, tenantID, entityID, "kill_switched"); err != nil {
				return err
			}
		case runtime.ControlEntityDelegation:
			if err := s.revokeDelegationSideEffects(ctx, tx, tenantID, entityID, "revoked"); err != nil {
				return err
			}
		case runtime.ControlEntityRun:
			if err := s.terminateRunSideEffect(ctx, tx, tenantID, entityID, "terminated"); err != nil {
				return err
			}
		}

		s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventEmergencyControl, action.ID, action.CreatedAt, map[string]string{
			"event_id":           action.ID,
			"entity_type":        entityType,
			"entity_id":          entityID,
			"action_type":        actionType,
			"previous_state":     previousState,
			"new_state":          newState,
			"reason":             reason,
			"actor_principal_id": actor,
			"immutable_digest":   action.ImmutableDigest,
		})
		return nil
	})
	if err != nil {
		return runtime.EmergencyControl{}, err
	}
	return control, nil
}

// assertControlUsable fails when an entity's emergency control state
// prevents new work (kill-switched, revoked, or suspended). Absence of
// a control row means active.
func (s *Service) assertControlUsable(ctx context.Context, tx TxStore, tenantID, entityType, entityID string) error {
	c, err := tx.GetEmergencyControl(ctx, tenantID, entityType, entityID)
	if err != nil {
		if errors.Is(err, runtime.ErrControlNotFound) {
			return nil
		}
		return err
	}
	switch c.ControlState {
	case runtime.ControlStateKillSwitched, runtime.ControlStateRevoked:
		return runtime.ErrControlKillSwitched
	case runtime.ControlStateSuspended:
		return runtime.ErrControlSuspended
	}
	return nil
}

// validateControlEntity confirms the entity exists in the tenant before
// a control row is created (never trusts the body's identifiers).
func (s *Service) validateControlEntity(ctx context.Context, tx TxStore, tenantID, entityType, entityID string) error {
	switch entityType {
	case runtime.ControlEntityAgent:
		if s.agents == nil {
			return runtime.ErrGovernanceUnavailable
		}
		agent, _, _, err := s.agents.GetAgent(ctx, tenantID, entityID)
		if err != nil {
			return err
		}
		_ = agent
	case runtime.ControlEntityAgentVersion:
		if s.agents == nil {
			return runtime.ErrGovernanceUnavailable
		}
		// Version existence: any agent owning it is sufficient for the
		// tenant (agents reader lists versions per agent).
		found := false
		agents, err := s.agentIDs(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		for _, agentID := range agents {
			versions, err := s.agents.ListVersions(ctx, tenantID, agentID)
			if err != nil {
				continue
			}
			for _, v := range versions {
				if v.ID == entityID {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return runtime.ErrInvalidRequest
		}
	case runtime.ControlEntityTool:
		if _, err := tx.GetTool(ctx, tenantID, entityID); err != nil {
			return err
		}
	case runtime.ControlEntityDelegation:
		if _, err := tx.GetDelegationGrantByID(ctx, tenantID, entityID); err != nil {
			return err
		}
	case runtime.ControlEntityRun:
		if _, err := tx.GetRun(ctx, tenantID, entityID); err != nil {
			return err
		}
	}
	return nil
}

// agentIDs enumerates the tenant's agents. Without a registry-wide list
// surface this walks delegation grants and runs (both carry agent_id) —
// sufficient for version-existence checks.
func (s *Service) agentIDs(ctx context.Context, tx TxStore, tenantID string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	grants, err := tx.ListDelegationGrants(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, g := range grants {
		if !seen[g.AgentID] {
			seen[g.AgentID] = true
			out = append(out, g.AgentID)
		}
	}
	runs, err := tx.ListRunsByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, r := range runs {
		if !seen[r.AgentID] {
			seen[r.AgentID] = true
			out = append(out, r.AgentID)
		}
	}
	return out, nil
}

// terminateRunsOfAgent transitions every active run of the agent to
// revoked (kill-switch side effect) and enqueues run.ended events.
func (s *Service) terminateRunsOfAgent(ctx context.Context, tx TxStore, tenantID, agentID, errorCode string) error {
	return s.terminateRuns(ctx, tx, tenantID, func(r runtime.AgentRun) bool { return r.AgentID == agentID }, errorCode)
}

// terminateRunsOfVersion terminates active runs bound to a delegation
// of the kill-switched version.
func (s *Service) terminateRunsOfVersion(ctx context.Context, tx TxStore, tenantID, versionID, errorCode string) error {
	versionGrants := map[string]bool{}
	grants, err := tx.ListDelegationGrants(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, g := range grants {
		if g.AgentVersionID == versionID {
			versionGrants[g.ID] = true
		}
	}
	return s.terminateRuns(ctx, tx, tenantID, func(r runtime.AgentRun) bool {
		return versionGrants[r.DelegationGrantID]
	}, errorCode)
}

func (s *Service) terminateRuns(ctx context.Context, tx TxStore, tenantID string, match func(runtime.AgentRun) bool, errorCode string) error {
	runs, err := tx.ListRunsByTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, r := range runs {
		if r.Status != runtime.RunStatusPending && r.Status != runtime.RunStatusRunning {
			continue
		}
		if !match(r) {
			continue
		}
		if err := s.terminateRunSideEffect(ctx, tx, tenantID, r.ID, errorCode); err != nil {
			return err
		}
	}
	return nil
}

// terminateRunSideEffect transitions one run to revoked (irreversible)
// and records its run.ended outbox event.
func (s *Service) terminateRunSideEffect(ctx context.Context, tx TxStore, tenantID, runID, errorCode string) error {
	run, err := tx.GetRun(ctx, tenantID, runID)
	if err != nil {
		return err
	}
	if run.Status != runtime.RunStatusPending && run.Status != runtime.RunStatusRunning {
		return nil // already terminal: nothing to do
	}
	completed := s.now().UTC().Truncate(time.Microsecond)
	if err := tx.UpdateRunStatus(ctx, tenantID, runID, run.Status, runtime.RunStatusRevoked, &completed, errorCode); err != nil {
		return err
	}
	s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventRunEnded, runID+":end", completed, map[string]string{
		"run_id":     runID,
		"tenant_id":  tenantID,
		"agent_id":   run.AgentID,
		"status":     runtime.RunStatusRevoked,
		"error_code": errorCode,
	})
	return nil
}

// revokeDelegationSideEffects irreversibly revokes a delegation grant
// and terminates the run bound to it (if any).
func (s *Service) revokeDelegationSideEffects(ctx context.Context, tx TxStore, tenantID, grantID, errorCode string) error {
	grant, err := tx.GetDelegationGrantByID(ctx, tenantID, grantID)
	if err != nil {
		return err
	}
	if err := tx.RevokeDelegationGrantByID(ctx, tenantID, grantID); err != nil {
		return err
	}
	revokedAt := s.now().UTC().Truncate(time.Microsecond)
	s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventDelegationRevoked, grantID+":revoked", revokedAt, map[string]string{
		"delegation_grant_id": grantID,
		"tenant_id":           tenantID,
		"agent_id":            grant.AgentID,
		"purpose":             grant.Purpose,
		"immutable_digest":    grant.ImmutableDigest,
	})
	if grant.RunID != "" {
		if err := s.terminateRunSideEffect(ctx, tx, tenantID, grant.RunID, errorCode); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// Budgets
// ---------------------------------------------------------------------

func (s *Service) UpsertBudget(ctx context.Context, tenantID, actor string, admin bool, scopeType, agentVersionID, grantID string, req runtime.BudgetPolicyRequest) (runtime.BudgetPolicy, error) {
	if !admin {
		return runtime.BudgetPolicy{}, runtime.ErrGovernanceNotAuthorized
	}
	if actor == "" {
		return runtime.BudgetPolicy{}, runtime.ErrInvalidRequest
	}
	switch scopeType {
	case runtime.BudgetScopeTenant:
		if agentVersionID != "" || grantID != "" {
			return runtime.BudgetPolicy{}, runtime.ErrInvalidRequest
		}
	case runtime.BudgetScopeAgentVersion:
		if agentVersionID == "" || grantID != "" {
			return runtime.BudgetPolicy{}, runtime.ErrInvalidRequest
		}
	case runtime.BudgetScopeGrant:
		if grantID == "" || agentVersionID != "" {
			return runtime.BudgetPolicy{}, runtime.ErrInvalidRequest
		}
	default:
		return runtime.BudgetPolicy{}, runtime.ErrInvalidRequest
	}
	for _, v := range []int{req.MaxActionsPerRun, req.MaxDeniedPerRun, req.MaxApprovalRequiredPerRun,
		req.MaxToolCallsPerActionPerRun, req.MaxRunDurationSeconds, req.MaxCitationsPerQuery} {
		if v < 0 {
			return runtime.BudgetPolicy{}, runtime.ErrInvalidRequest
		}
	}
	policy := runtime.BudgetPolicy{
		TenantID:                    tenantID,
		ScopeType:                   scopeType,
		AgentVersionID:              agentVersionID,
		GrantID:                     grantID,
		MaxActionsPerRun:            req.MaxActionsPerRun,
		MaxDeniedPerRun:             req.MaxDeniedPerRun,
		MaxApprovalRequiredPerRun:   req.MaxApprovalRequiredPerRun,
		MaxToolCallsPerActionPerRun: req.MaxToolCallsPerActionPerRun,
		MaxRunDurationSeconds:       req.MaxRunDurationSeconds,
		MaxCitationsPerQuery:        req.MaxCitationsPerQuery,
		CreatedBy:                   actor,
	}
	var saved runtime.BudgetPolicy
	err := s.store.Transact(ctx, "budget:"+tenantID, func(tx TxStore) error {
		// A grant-scope policy must reference a grant in this tenant; a
		// version-scope policy must reference a version (FKs enforce
		// this, but surface a clean error first).
		if scopeType == runtime.BudgetScopeGrant {
			if _, err := tx.GetGrant(ctx, tenantID, grantID); err != nil {
				return err
			}
		}
		var err error
		saved, err = tx.UpsertBudgetPolicy(ctx, policy)
		return err
	})
	return saved, err
}

// GetEffectiveBudget merges the applicable policies (grant > agent
// version > tenant) per dimension: the narrowest NON-ZERO limit wins,
// so a stricter grant or version policy always tightens a tenant
// default. A 0 value everywhere means "no budget" (unlimited).
func (s *Service) GetEffectiveBudget(ctx context.Context, tenantID, agentVersionID, grantID string) (runtime.BudgetPolicy, error) {
	applicable := make([]runtime.BudgetPolicy, 0, 3)
	for _, scope := range []struct {
		scopeType, versionID, gid string
	}{
		{runtime.BudgetScopeGrant, "", grantID},
		{runtime.BudgetScopeAgentVersion, agentVersionID, ""},
		{runtime.BudgetScopeTenant, "", ""},
	} {
		if scope.scopeType == runtime.BudgetScopeGrant && scope.gid == "" {
			continue
		}
		if scope.scopeType == runtime.BudgetScopeAgentVersion && scope.versionID == "" {
			continue
		}
		if p, err := s.store.GetBudgetPolicy(ctx, tenantID, scope.scopeType, scope.versionID, scope.gid); err == nil {
			applicable = append(applicable, p)
		}
	}
	merged := runtime.BudgetPolicy{TenantID: tenantID}
	for _, p := range applicable {
		merged.MaxActionsPerRun = minBudget(merged.MaxActionsPerRun, p.MaxActionsPerRun)
		merged.MaxDeniedPerRun = minBudget(merged.MaxDeniedPerRun, p.MaxDeniedPerRun)
		merged.MaxApprovalRequiredPerRun = minBudget(merged.MaxApprovalRequiredPerRun, p.MaxApprovalRequiredPerRun)
		merged.MaxToolCallsPerActionPerRun = minBudget(merged.MaxToolCallsPerActionPerRun, p.MaxToolCallsPerActionPerRun)
		merged.MaxRunDurationSeconds = minBudget(merged.MaxRunDurationSeconds, p.MaxRunDurationSeconds)
		merged.MaxCitationsPerQuery = minBudget(merged.MaxCitationsPerQuery, p.MaxCitationsPerQuery)
	}
	return merged, nil
}

// minBudget returns the stricter (non-zero) of two limits.
func minBudget(a, b int) int {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if b < a {
		return b
	}
	return a
}

func (s *Service) ListBudgets(ctx context.Context, tenantID string) ([]runtime.BudgetPolicy, error) {
	return s.store.ListBudgetPolicies(ctx, tenantID)
}

// ---------------------------------------------------------------------
// Citation budgets (retrieval gate)
// ---------------------------------------------------------------------

func (s *Service) RecordQueryCitations(ctx context.Context, tenantID, runID string, count int) error {
	if count < 1 {
		return runtime.ErrInvalidRequest
	}
	var run runtime.AgentRun
	var grant runtime.DelegationGrant
	var denied bool
	err := s.store.Transact(ctx, "run:"+runID, func(tx TxStore) error {
		var err error
		run, err = tx.GetRun(ctx, tenantID, runID)
		if err != nil {
			return err
		}
		if run.Status == runtime.RunStatusCompleted || run.Status == runtime.RunStatusDenied ||
			run.Status == runtime.RunStatusFailed || run.Status == runtime.RunStatusRevoked {
			return runtime.ErrRunNotActive
		}
		grant, err = tx.GetDelegationGrantByID(ctx, tenantID, run.DelegationGrantID)
		if err != nil {
			return err
		}
		policy, err := s.GetEffectiveBudgetTx(ctx, tx, tenantID, grant.AgentVersionID, grant.ID)
		if err != nil {
			return err
		}
		used, err := tx.GetBudgetCounter(ctx, tenantID, runID, "", runtime.BudgetCounterCitations)
		if err != nil {
			return err
		}
		if policy.MaxCitationsPerQuery > 0 && used+count > policy.MaxCitationsPerQuery {
			denied = true
			toolID := ""
			if tool, err := tx.GetToolByName(ctx, tenantID, runtime.BuiltinSearchTool); err == nil {
				toolID = tool.ID
			}
			d, _ := tx.AppendDecision(ctx, runtime.ActionDecision{
				TenantID:          tenantID,
				AgentID:           run.AgentID,
				RunID:             runID,
				DelegationGrantID: grant.ID,
				ToolID:            toolID,
				ResourceRef:       "*",
				Decision:          runtime.DecisionDenied,
				Reason:            "citation budget exceeded",
				ReasonCode:        "budget_exhausted:max_citations_per_query",
				PolicyVersion:     s.policyVersion,
			})
			s.recordCounters(ctx, tx, run, d, toolID, "")
			s.enqueueDecision(ctx, tx, run, d)
			gwmetrics.RecordBudgetExhaustion(tenantID, "budget_exhausted:max_citations_per_query")
			s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventBudgetExhaustion, d.ID+":budget", d.CreatedAt, map[string]string{
				"run_id": runID, "tenant_id": tenantID, "reason_code": "budget_exhausted:max_citations_per_query",
			})
			return nil
		}
		_, err = tx.IncrementBudgetCounterN(ctx, tenantID, runID, "", runtime.BudgetCounterCitations, count)
		return err
	})
	if err != nil {
		return err
	}
	if denied {
		return runtime.ErrBudgetExhausted
	}
	return nil
}

// GetEffectiveBudgetTx is the transaction variant used by the evaluator
// and citation gate (consistent view inside the same unit of work).
func (s *Service) GetEffectiveBudgetTx(ctx context.Context, tx TxStore, tenantID, agentVersionID, grantID string) (runtime.BudgetPolicy, error) {
	applicable := make([]runtime.BudgetPolicy, 0, 3)
	if grantID != "" {
		if p, err := tx.GetBudgetPolicy(ctx, tenantID, runtime.BudgetScopeGrant, "", grantID); err == nil {
			applicable = append(applicable, p)
		}
	}
	if agentVersionID != "" {
		if p, err := tx.GetBudgetPolicy(ctx, tenantID, runtime.BudgetScopeAgentVersion, agentVersionID, ""); err == nil {
			applicable = append(applicable, p)
		}
	}
	if p, err := tx.GetBudgetPolicy(ctx, tenantID, runtime.BudgetScopeTenant, "", ""); err == nil {
		applicable = append(applicable, p)
	}
	merged := runtime.BudgetPolicy{TenantID: tenantID}
	for _, p := range applicable {
		merged.MaxActionsPerRun = minBudget(merged.MaxActionsPerRun, p.MaxActionsPerRun)
		merged.MaxDeniedPerRun = minBudget(merged.MaxDeniedPerRun, p.MaxDeniedPerRun)
		merged.MaxApprovalRequiredPerRun = minBudget(merged.MaxApprovalRequiredPerRun, p.MaxApprovalRequiredPerRun)
		merged.MaxToolCallsPerActionPerRun = minBudget(merged.MaxToolCallsPerActionPerRun, p.MaxToolCallsPerActionPerRun)
		merged.MaxRunDurationSeconds = minBudget(merged.MaxRunDurationSeconds, p.MaxRunDurationSeconds)
		merged.MaxCitationsPerQuery = minBudget(merged.MaxCitationsPerQuery, p.MaxCitationsPerQuery)
	}
	return merged, nil
}

// ---------------------------------------------------------------------
// Evidence read model
// ---------------------------------------------------------------------

func (s *Service) QueryEvidence(ctx context.Context, tenantID string, filter runtime.EvidenceFilter) (runtime.EvidencePage, error) {
	events, err := s.store.QueryEvidence(ctx, tenantID, filter)
	if err != nil {
		return runtime.EvidencePage{}, err
	}
	s.enrichEvidence(tenantID, events)
	page := runtime.EvidencePage{Events: events, Count: len(events)}
	if len(events) > 0 {
		last := events[len(events)-1]
		page.NextCursor = encodeEvidenceCursor(last.OccurredAt, last.EventID)
	}
	return page, nil
}

func (s *Service) GetEvidenceEvent(ctx context.Context, tenantID, eventID string) (runtime.EvidenceEvent, error) {
	event, err := s.store.GetEvidenceEvent(ctx, tenantID, eventID)
	if err != nil {
		return runtime.EvidenceEvent{}, err
	}
	s.enrichEvidence(tenantID, []runtime.EvidenceEvent{event})
	return event, nil
}

func (s *Service) GetRunTimeline(ctx context.Context, tenantID, runID string) ([]runtime.EvidenceEvent, error) {
	events, err := s.store.GetRunEvidence(ctx, tenantID, runID)
	if err != nil {
		return nil, err
	}
	s.enrichEvidence(tenantID, events)
	return events, nil
}

func (s *Service) GetAgentActivity(ctx context.Context, tenantID, agentID string, filter runtime.EvidenceFilter) ([]runtime.EvidenceEvent, error) {
	events, err := s.store.GetAgentEvidence(ctx, tenantID, agentID, filter)
	if err != nil {
		return nil, err
	}
	s.enrichEvidence(tenantID, events)
	return events, nil
}

// ---------------------------------------------------------------------
// Audit chain verification + checkpoints
// ---------------------------------------------------------------------

// verifyChainSince recomputes digests for one chained stream
// (decisions or emergency actions) ordered oldest-first, skipping
// events at or before the boundary. initialPrev is the digest of the
// last verified event in the chain at the boundary ("" when none).
func verifyChainSince(events []runtime.ActionDecision, boundary time.Time, initialPrev string) (checked int, problems []ChainProblem) {
	prev := initialPrev
	for _, d := range events {
		if !boundary.IsZero() && !d.CreatedAt.After(boundary) {
			prev = d.ImmutableDigest
			continue
		}
		if recomputed := ComputeDecisionDigest(d, prev); recomputed != d.ImmutableDigest {
			problems = append(problems, ChainProblem{Index: checked, ID: d.ID, Kind: "digest_mismatch", Detail: "stored immutable_digest does not match recomputed digest"})
			return checked, problems
		}
		prev = d.ImmutableDigest
		checked++
	}
	return checked, problems
}

func verifyEmergencyChainSince(actions []runtime.EmergencyControlAction, boundary time.Time, initialPrev string) (checked int, problems []ChainProblem) {
	prev := initialPrev
	for _, a := range actions {
		if !boundary.IsZero() && !a.CreatedAt.After(boundary) {
			prev = a.ImmutableDigest
			continue
		}
		if recomputed := ComputeEmergencyActionDigest(a, prev); recomputed != a.ImmutableDigest {
			problems = append(problems, ChainProblem{Index: checked, ID: a.ID, Kind: "digest_mismatch", Detail: "stored immutable_digest does not match recomputed digest"})
			return checked, problems
		}
		prev = a.ImmutableDigest
		checked++
	}
	return checked, problems
}

// chainTails computes, for each verified chain, the digest of its last
// event at or before the boundary (the linkage point for incremental
// verification), plus the count of events at or before the boundary.
func chainTails(decisionsByRun map[string][]runtime.ActionDecision, approvals []runtime.ActionApproval, emergency []runtime.EmergencyControlAction, delegations []runtime.DelegationGrant, boundary time.Time) (map[string]string, int) {
	tails := map[string]string{}
	count := 0
	atBoundary := func(ts time.Time) bool { return boundary.IsZero() || !ts.After(boundary) }
	for runID, chain := range decisionsByRun {
		for i := range chain {
			if atBoundary(chain[i].CreatedAt) {
				tails["decisions:"+runID] = chain[i].ImmutableDigest
				count++
			}
		}
	}
	for i := range approvals {
		if atBoundary(approvals[i].CreatedAt) {
			tails["approvals"] = approvals[i].ImmutableDigest
			count++
		}
	}
	for i := range emergency {
		if atBoundary(emergency[i].CreatedAt) {
			tails["emergency"] = emergency[i].ImmutableDigest
			count++
		}
	}
	for i := range delegations {
		if atBoundary(delegations[i].IssuedAt) {
			tails["delegations"] = delegations[i].ImmutableDigest
			count++
		}
	}
	return tails, count
}

// verifyOneDelegation checks a grant's immutable digest (covers all
// binding fields; lifecycle fields are excluded by design).
func verifyDelegationDigest(g runtime.DelegationGrant) string {
	if ComputeGrantDigest(g) != g.ImmutableDigest {
		return "stored immutable_digest does not match recomputed digest (fields edited)"
	}
	return ""
}

func (s *Service) VerifyAuditChain(ctx context.Context, tenantID, checkpointID string, createCheckpoint bool) (runtime.EvidenceVerifyResult, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	result := runtime.EvidenceVerifyResult{TenantID: tenantID, Verified: true, CheckedAt: now}

	decisions, err := s.store.ListDecisionsByTenant(ctx, tenantID)
	if err != nil {
		return result, err
	}
	approvals, err := s.store.ListApprovalsByTenant(ctx, tenantID)
	if err != nil {
		return result, err
	}
	emergency, err := s.store.ListEmergencyActions(ctx, tenantID)
	if err != nil {
		return result, err
	}
	delegations, err := s.store.ListDelegationGrants(ctx, tenantID)
	if err != nil {
		return result, err
	}

	decisionsByRun := map[string][]runtime.ActionDecision{}
	for _, d := range decisions {
		decisionsByRun[d.RunID] = append(decisionsByRun[d.RunID], d)
	}
	runIDs := make([]string, 0, len(decisionsByRun))
	for runID := range decisionsByRun {
		runIDs = append(runIDs, runID)
	}
	sort.Strings(runIDs)
	result.ChainsChecked = len(runIDs) + 3 // decision chains + approvals + emergency + delegations

	// boundary + initial linkage from the checkpoint, if any.
	boundary := time.Time{}
	initialPrev := map[string]string{}
	var checkpoint runtime.EvidenceCheckpoint
	if checkpointID != "" {
		checkpoint, err = s.store.GetCheckpoint(ctx, tenantID, checkpointID)
		if err != nil {
			return result, err
		}
		boundary = checkpoint.LastVerifiedAt
		tails, _ := chainTails(decisionsByRun, approvals, emergency, delegations, boundary)
		// The checkpoint's digest must match the CURRENT chain state at
		// the boundary — otherwise it was forged or the chain behind it
		// was tampered after creation.
		if computeCheckpointDigest(checkpoint.TenantID, checkpoint.LastEventID, checkpoint.EventsChecked, tails) != checkpoint.ChainDigest {
			result.Verified = false
			result.FirstBrokenKind = "checkpoint"
			result.FirstBrokenID = checkpoint.ID
			result.FirstBrokenAt = checkpoint.CreatedAt
			result.FirstBrokenDetail = "checkpoint digest does not match the verified chain state (checkpoint forged or chains edited behind it)"
			gwmetrics.RecordAuditVerify(tenantID, "failed")
			return result, s.recordVerifyFailure(ctx, tenantID, now, result)
		}
		for key, digest := range tails {
			initialPrev[key] = digest
		}
		result.FromCheckpoint = true
	}

	report := func(kind, id string, at time.Time, detail string) {
		if result.Verified {
			result.Verified = false
			result.FirstBrokenKind = kind
			result.FirstBrokenID = id
			result.FirstBrokenAt = at
			result.FirstBrokenDetail = detail
		}
	}

	for _, runID := range runIDs {
		chain := decisionsByRun[runID]
		checked, problems := verifyChainSince(chain, boundary, initialPrev["decisions:"+runID])
		result.EventsChecked += checked
		if len(problems) > 0 {
			p := problems[0]
			report("decisions", p.ID, atOfDecision(chain, p.Index), p.Detail)
		}
	}
	// Approvals: digest-only, no chaining.
	approved := 0
	for i := range approvals {
		if !boundary.IsZero() && !approvals[i].CreatedAt.After(boundary) {
			continue
		}
		approved++
		if detail := verifyApprovalDigest(approvals[i]); detail != "" {
			report("approvals", approvals[i].ID, approvals[i].CreatedAt, detail)
		}
	}
	result.EventsChecked += approved
	// Emergency actions: chained per tenant.
	checked, problems := verifyEmergencyChainSince(emergency, boundary, initialPrev["emergency"])
	result.EventsChecked += checked
	if len(problems) > 0 {
		p := problems[0]
		report("emergency_actions", p.ID, atOfEmergency(emergency, p.Index), p.Detail)
	}
	// Delegations: digest-only.
	checkedDelegations := 0
	for i := range delegations {
		if !boundary.IsZero() && !delegations[i].IssuedAt.After(boundary) {
			continue
		}
		checkedDelegations++
		if detail := verifyDelegationDigest(delegations[i]); detail != "" {
			report("delegations", delegations[i].ID, delegations[i].IssuedAt, detail)
		}
	}
	result.EventsChecked += checkedDelegations

	if createCheckpoint && result.Verified {
		newBoundary := now
		tails, _ := chainTails(decisionsByRun, approvals, emergency, delegations, newBoundary)
		lastEventID := boundaryEventID(decisionsByRun, approvals, emergency, delegations, newBoundary)
		cumulative := checkpoint.EventsChecked + result.EventsChecked
		if checkpointID == "" {
			cumulative = result.EventsChecked
		}
		cp := runtime.EvidenceCheckpoint{
			TenantID:       tenantID,
			LastEventID:    lastEventID,
			LastVerifiedAt: newBoundary,
			EventsChecked:  cumulative,
			ChainDigest:    computeCheckpointDigest(tenantID, lastEventID, cumulative, tails),
		}
		if _, err := s.store.CreateCheckpoint(ctx, cp); err != nil {
			return result, err
		}
	}
	if !result.Verified {
		gwmetrics.RecordAuditVerify(tenantID, "failed")
		return result, s.recordVerifyFailure(ctx, tenantID, now, result)
	}
	gwmetrics.RecordAuditVerify(tenantID, "verified")
	return result, nil
}

// recordVerifyFailure enqueues the audit.verify_failure outbox event
// (safe fields only) outside the read-only verification pass.
func (s *Service) recordVerifyFailure(ctx context.Context, tenantID string, at time.Time, result runtime.EvidenceVerifyResult) error {
	return s.store.Transact(ctx, "verify:"+tenantID, func(tx TxStore) error {
		s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventAuditVerifyFailure, "verify:"+result.FirstBrokenKind+":"+at.Format(time.RFC3339Nano), at, map[string]string{
			"tenant_id": tenantID,
			"verified":  "false",
			"kind":      result.FirstBrokenKind,
			"id":        result.FirstBrokenID,
			"detail":    result.FirstBrokenDetail,
		})
		return nil
	})
}

func verifyApprovalDigest(a runtime.ActionApproval) string {
	if ComputeApprovalDigest(a) != a.ImmutableDigest {
		return "stored immutable_digest does not match recomputed digest (fields edited)"
	}
	return ""
}

func atOfDecision(chain []runtime.ActionDecision, index int) time.Time {
	if index >= 0 && index < len(chain) {
		return chain[index].CreatedAt
	}
	return time.Time{}
}

func atOfEmergency(chain []runtime.EmergencyControlAction, index int) time.Time {
	if index >= 0 && index < len(chain) {
		return chain[index].CreatedAt
	}
	return time.Time{}
}

// boundaryEventID picks the last verified event id at the boundary
// (prefers decisions, then approvals, then emergency, then delegations)
// for checkpoint linkage.
func boundaryEventID(decisionsByRun map[string][]runtime.ActionDecision, approvals []runtime.ActionApproval, emergency []runtime.EmergencyControlAction, delegations []runtime.DelegationGrant, boundary time.Time) string {
	last := ""
	lastAt := time.Time{}
	consider := func(id string, at time.Time) {
		if id == "" {
			return
		}
		if lastAt.IsZero() || at.After(lastAt) {
			last, lastAt = id, at
		}
	}
	for _, chain := range decisionsByRun {
		for _, d := range chain {
			if !d.CreatedAt.After(boundary) {
				consider(d.ID, d.CreatedAt)
			}
		}
	}
	for _, a := range approvals {
		if !a.CreatedAt.After(boundary) {
			consider(a.ID, a.CreatedAt)
		}
	}
	for _, a := range emergency {
		if !a.CreatedAt.After(boundary) {
			consider(a.ID, a.CreatedAt)
		}
	}
	for _, g := range delegations {
		if !g.IssuedAt.After(boundary) {
			consider(g.ID, g.IssuedAt)
		}
	}
	return last
}

func (s *Service) ListCheckpoints(ctx context.Context, tenantID string) ([]runtime.EvidenceCheckpoint, error) {
	return s.store.ListCheckpoints(ctx, tenantID)
}

// ---------------------------------------------------------------------
// Outbox admin reads
// ---------------------------------------------------------------------

func (s *Service) ListOutboxEvents(ctx context.Context, tenantID, status string, limit int, cursor string) ([]runtime.OutboxEvent, string, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	events, err := s.store.ListOutboxEvents(ctx, tenantID, status, limit, cursor)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(events) > 0 && len(events) == limit {
		last := events[len(events)-1]
		next = encodeEvidenceCursor(last.OccurredAt, last.EventID)
	}
	return events, next, nil
}

func (s *Service) RetryOutboxEvent(ctx context.Context, tenantID, eventID string) (runtime.OutboxEvent, error) {
	if err := s.store.RetryOutboxEvent(ctx, tenantID, eventID); err != nil {
		return runtime.OutboxEvent{}, err
	}
	return s.store.GetOutboxEventByID(ctx, tenantID, eventID)
}
