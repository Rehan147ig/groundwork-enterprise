package governance

import (
	"errors"
	"strings"
	"testing"

	"groundwork/query-runtime/internal/runtime"
)

// simulateHarness reuses the shared test fixtures (MemoryStore + fake
// agent reader + fake relationship checker + fixed clock).
func (h *harness) simulate(t *testing.T, req runtime.SimulateActionRequest) runtime.SimulateActionResponse {
	t.Helper()
	resp, err := h.svc.SimulateAction(testCtx, testTenant, testRegion, req)
	if err != nil {
		t.Fatalf("SimulateAction: %v", err)
	}
	return resp
}

func (h *harness) gate(resp runtime.SimulateActionResponse, gate string) *runtime.GateCheck {
	for i := range resp.Checks {
		if resp.Checks[i].Gate == gate {
			return &resp.Checks[i]
		}
	}
	return nil
}

func (h *harness) gateNamed(resp runtime.SimulateActionResponse, name string) *runtime.GateCheck {
	for i := range resp.Checks {
		if resp.Checks[i].Name == name {
			return &resp.Checks[i]
		}
	}
	return nil
}

func TestSimulateWouldAllow(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	grant := h.grantSearch(t, tool)

	resp := h.simulate(t, runtime.SimulateActionRequest{
		AgentID:     "agent-1",
		ToolName:    runtime.BuiltinSearchTool,
		Action:      runtime.BuiltinSearchAction,
		ResourceRef: "doc:reports/q3",
		PrincipalID: subjectPr,
	})

	if !resp.Simulated {
		t.Fatal("simulation must be flagged simulated=true")
	}
	if !resp.Allowed || resp.Decision != runtime.DecisionAllowed {
		t.Fatalf("expected allowed, got %s: %s", resp.Decision, resp.Reason)
	}
	if resp.Reason != "allowed" {
		t.Fatalf("reason=%q", resp.Reason)
	}
	// Gate-by-gate expectations.
	if g := h.gate(resp, "agent"); g == nil || g.Status != runtime.GateStatusPassed {
		t.Fatalf("agent gate: %+v", g)
	}
	if g := h.gate(resp, "grant"); g == nil || g.Status != runtime.GateStatusPassed || !strings.HasPrefix(g.Detail, "covered by grant "+grant.ID) {
		t.Fatalf("grant gate: %+v", g)
	}
	if g := h.gate(resp, "relationship"); g == nil || g.Status != runtime.GateStatusPassed {
		t.Fatalf("relationship gate: %+v", g)
	}
	// The relationship check must have run for the VERIFIED principal.
	recorded := h.authorizer.recorded()
	if len(recorded) != 1 || recorded[0] != "user:"+subjectPr+" use tool:"+tool.ID {
		t.Fatalf("authorizer calls: %v", recorded)
	}
	// Delegation gates are honestly marked skipped (no token in simulation).
	if g := h.gate(resp, "delegation"); g == nil || g.Status != runtime.GateStatusSkipped {
		t.Fatalf("delegation gate: %+v", g)
	}
	if g := h.gate(resp, "permitted_actions"); g == nil || g.Status != runtime.GateStatusSkipped {
		t.Fatalf("permitted_actions gate: %+v", g)
	}
}

func TestSimulateWouldAllowWithoutPrincipalSkipsRelationship(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)

	resp := h.simulate(t, runtime.SimulateActionRequest{
		AgentID:     "agent-1",
		ToolName:    runtime.BuiltinSearchTool,
		Action:      runtime.BuiltinSearchAction,
		ResourceRef: "doc:reports/q3",
	})

	if !resp.Allowed {
		t.Fatalf("expected allowed without principal, got %s: %s", resp.Decision, resp.Reason)
	}
	if g := h.gate(resp, "relationship"); g == nil || g.Status != runtime.GateStatusSkipped {
		t.Fatalf("relationship gate should be skipped without principal: %+v", g)
	}
	if len(h.authorizer.recorded()) != 0 {
		t.Fatalf("authorizer must not be called without a principal, got %v", h.authorizer.recorded())
	}
}

func TestSimulateDeniesWithoutGrant(t *testing.T) {
	h := newHarness(t)
	h.registerSearchTool(t)

	resp := h.simulate(t, runtime.SimulateActionRequest{
		AgentID:     "agent-1",
		ToolName:    runtime.BuiltinSearchTool,
		Action:      runtime.BuiltinSearchAction,
		ResourceRef: "doc:reports/q3",
	})

	if resp.Allowed || resp.Decision != runtime.DecisionDenied {
		t.Fatalf("expected denied, got %s: %s", resp.Decision, resp.Reason)
	}
	if resp.Reason != "no active grant for tool action" {
		t.Fatalf("reason=%q", resp.Reason)
	}
	if g := h.gate(resp, "grant"); g == nil || g.Status != runtime.GateStatusFailed {
		t.Fatalf("grant gate: %+v", g)
	}
}

func TestSimulateDeniesInactiveAgent(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)
	h.agents.setAgent(runtime.Agent{
		ID: "agent-1", TenantID: testTenant, OwnerPrincipalID: ownerActor,
		LifecycleState: runtime.AgentStateDraft,
	}, nil)

	resp := h.simulate(t, runtime.SimulateActionRequest{
		AgentID:     "agent-1",
		ToolName:    runtime.BuiltinSearchTool,
		Action:      runtime.BuiltinSearchAction,
		ResourceRef: "doc:reports/q3",
	})

	if resp.Allowed || resp.Decision != runtime.DecisionDenied || resp.Reason != "agent not active" {
		t.Fatalf("got %s: %s", resp.Decision, resp.Reason)
	}
	if g := h.gate(resp, "agent"); g == nil || g.Status != runtime.GateStatusFailed {
		t.Fatalf("agent gate: %+v", g)
	}
}

func TestSimulateDeniesInactiveVersion(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)
	h.agents.setAgent(runtime.Agent{
		ID: "agent-1", TenantID: testTenant, OwnerPrincipalID: ownerActor,
		LifecycleState: runtime.AgentStateActive, ActiveVersionID: "version-1",
	}, []runtime.AgentVersion{{ID: "version-1", AgentID: "agent-1", Version: "1.0.0", Status: runtime.VersionStatusDraft}})

	resp := h.simulate(t, runtime.SimulateActionRequest{
		AgentID:     "agent-1",
		ToolName:    runtime.BuiltinSearchTool,
		Action:      runtime.BuiltinSearchAction,
		ResourceRef: "doc:reports/q3",
	})

	if resp.Allowed || resp.Decision != runtime.DecisionDenied || resp.Reason != "agent version not active" {
		t.Fatalf("got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestSimulateDeniesToolNotActive(t *testing.T) {
	h := newHarness(t)
	// Register a tool but do NOT activate it (draft lifecycle).
	tool, err := h.svc.RegisterTool(testCtx, testTenant, adminActor, true, runtime.RegisterToolRequest{
		Name: runtime.BuiltinSearchTool, Description: "draft tool",
		Transport: runtime.ToolTransportBuiltin, OwnerPrincipalID: ownerActor, Region: testRegion,
	})
	if err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}
	if _, err := h.svc.RegisterToolAction(testCtx, testTenant, tool.ID, adminActor, true, runtime.RegisterToolActionRequest{
		Action: runtime.BuiltinSearchAction, ResourceType: "document", RiskLevel: runtime.RiskLevelLow, ReadOnly: true,
	}); err != nil {
		t.Fatalf("RegisterToolAction: %v", err)
	}

	resp := h.simulate(t, runtime.SimulateActionRequest{
		AgentID:     "agent-1",
		ToolName:    runtime.BuiltinSearchTool,
		Action:      runtime.BuiltinSearchAction,
		ResourceRef: "doc:reports/q3",
	})

	if resp.Allowed || resp.Decision != runtime.DecisionDenied || resp.Reason != "tool not active" {
		t.Fatalf("got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestSimulateDeniesRelationship(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)
	h.authorizer.allowed = func(user, relation, object string) (bool, error) { return false, nil }

	resp := h.simulate(t, runtime.SimulateActionRequest{
		AgentID:     "agent-1",
		ToolName:    runtime.BuiltinSearchTool,
		Action:      runtime.BuiltinSearchAction,
		ResourceRef: "doc:reports/q3",
		PrincipalID: subjectPr,
	})

	if resp.Allowed || resp.Decision != runtime.DecisionDenied || resp.Reason != "relationship permission denied" {
		t.Fatalf("got %s: %s", resp.Decision, resp.Reason)
	}
	if g := h.gate(resp, "relationship"); g == nil || g.Status != runtime.GateStatusFailed {
		t.Fatalf("relationship gate: %+v", g)
	}
}

func TestSimulateFailsClosedWithoutPermissionBackend(t *testing.T) {
	// Service WITHOUT an authorizer checker: the relationship gate must fail
	// closed (never guess allowed).
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)
	h.svc = NewService(h.store, h.auth, nil, h.agents)
	h.svc.SetClock(h.clock.now)

	resp := h.simulate(t, runtime.SimulateActionRequest{
		AgentID:     "agent-1",
		ToolName:    runtime.BuiltinSearchTool,
		Action:      runtime.BuiltinSearchAction,
		ResourceRef: "doc:reports/q3",
		PrincipalID: subjectPr,
	})

	if resp.Allowed || resp.Decision != runtime.DecisionFailClosed || resp.Reason != "permission backend unavailable" {
		t.Fatalf("got %s: %s", resp.Decision, resp.Reason)
	}
	if g := h.gate(resp, "relationship"); g == nil || g.Status != runtime.GateStatusUnavailable {
		t.Fatalf("relationship gate: %+v", g)
	}
}

func TestSimulateApprovalRequired(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	_, actions, err := h.svc.GetTool(testCtx, testTenant, tool.ID)
	if err != nil {
		t.Fatalf("GetTool: %v", err)
	}
	if _, err := h.svc.GrantToolAccess(testCtx, testTenant, adminActor, true, runtime.GrantToolRequest{
		AgentID: "agent-1", VersionID: "version-1", ToolID: tool.ID, ActionID: actions[0].ID,
		RequiresApproval: true,
	}); err != nil {
		t.Fatalf("GrantToolAccess: %v", err)
	}

	resp := h.simulate(t, runtime.SimulateActionRequest{
		AgentID:     "agent-1",
		ToolName:    runtime.BuiltinSearchTool,
		Action:      runtime.BuiltinSearchAction,
		ResourceRef: "doc:reports/q3",
	})

	if resp.Allowed || resp.Decision != runtime.DecisionApprovalRequired || resp.Reason != "human approval required" {
		t.Fatalf("got %s: %s", resp.Decision, resp.Reason)
	}
	if g := h.gate(resp, "approval"); g == nil || g.Status != runtime.GateStatusRequired {
		t.Fatalf("approval gate: %+v", g)
	}
}

func TestSimulateDeniesKillSwitchedAgent(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)
	if _, err := h.svc.KillSwitchAgent(testCtx, testTenant, "agent-1", adminActor, true, runtime.ControlRequest{Reason: "incident-42"}); err != nil {
		t.Fatalf("KillSwitchAgent: %v", err)
	}

	resp := h.simulate(t, runtime.SimulateActionRequest{
		AgentID:     "agent-1",
		ToolName:    runtime.BuiltinSearchTool,
		Action:      runtime.BuiltinSearchAction,
		ResourceRef: "doc:reports/q3",
	})

	if resp.Allowed || resp.Decision != runtime.DecisionDenied || resp.Reason != "agent kill-switched" {
		t.Fatalf("got %s: %s", resp.Decision, resp.Reason)
	}
	if g := h.gateNamed(resp, "agent control"); g == nil || g.Status != runtime.GateStatusFailed {
		t.Fatalf("agent control gate: %+v", g)
	}
}

func TestSimulateDeniesToolNotFound(t *testing.T) {
	h := newHarness(t)
	resp := h.simulate(t, runtime.SimulateActionRequest{
		AgentID:     "agent-1",
		ToolName:    "no-such-tool",
		Action:      runtime.BuiltinSearchAction,
		ResourceRef: "doc:reports/q3",
	})
	if resp.Allowed || resp.Decision != runtime.DecisionDenied || resp.Reason != "tool not found" {
		t.Fatalf("got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestSimulateValidatesRequest(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.SimulateAction(testCtx, testTenant, testRegion, runtime.SimulateActionRequest{
		ToolName: runtime.BuiltinSearchTool,
		Action:   runtime.BuiltinSearchAction,
	})
	if !errors.Is(err, runtime.ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}
}

// TestSimulateIsReadOnly is the invariant guard: simulation must never
// write evidence, counters, approvals, or outbox events.
func TestSimulateIsReadOnly(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)

	for i := 0; i < 3; i++ {
		h.simulate(t, runtime.SimulateActionRequest{
			AgentID:     "agent-1",
			ToolName:    runtime.BuiltinSearchTool,
			Action:      runtime.BuiltinSearchAction,
			ResourceRef: "doc:reports/q3",
			PrincipalID: subjectPr,
		})
		h.simulate(t, runtime.SimulateActionRequest{
			AgentID:     "agent-1",
			ToolName:    runtime.BuiltinSearchTool,
			Action:      runtime.BuiltinSearchAction,
			ResourceRef: "doc:nope/missing",
			PrincipalID: subjectPr,
		})
	}

	page, err := h.svc.QueryEvidence(testCtx, testTenant, runtime.EvidenceFilter{})
	if err != nil {
		t.Fatalf("QueryEvidence: %v", err)
	}
	if page.Count != 0 || len(page.Events) != 0 {
		t.Fatalf("simulation must not write evidence, got %d events", page.Count)
	}
	outbox, _, err := h.svc.ListOutboxEvents(testCtx, testTenant, "", 50, "")
	if err != nil {
		t.Fatalf("ListOutboxEvents: %v", err)
	}
	if len(outbox) != 0 {
		t.Fatalf("simulation must not enqueue outbox events, got %d", len(outbox))
	}
}
