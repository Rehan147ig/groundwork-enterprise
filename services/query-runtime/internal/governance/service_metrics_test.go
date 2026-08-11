package governance

import (
	"testing"

	gwmetrics "groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/runtime"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Phase 8.5 SLO telemetry is wired at the service layer. These tests
// assert the counters move when governed decisions, emergency controls,
// budget exhaustions, and audit-chain verifications happen.

func TestMetricsSLODecisionOutcomes(t *testing.T) {
	h := newHarness(t)
	run, token := h.happyRun(t)

	allowed := func() float64 {
		return testutil.ToFloat64(gwmetrics.SLODecisionsTotal.WithLabelValues(testTenant, runtime.DecisionAllowed))
	}
	denied := func() float64 {
		return testutil.ToFloat64(gwmetrics.SLODecisionsTotal.WithLabelValues(testTenant, runtime.DecisionDenied))
	}
	failClosed := func() float64 {
		return testutil.ToFloat64(gwmetrics.SLODecisionsTotal.WithLabelValues(testTenant, runtime.DecisionFailClosed))
	}

	allowedBefore, deniedBefore, failClosedBefore := allowed(), denied(), failClosed()
	decisionsBefore := testutil.ToFloat64(gwmetrics.EvidenceEventsTotal.WithLabelValues(testTenant, runtime.EvidenceKindDecision))

	if _, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	}); err != nil {
		t.Fatalf("allowed EvaluateAction: %v", err)
	}
	if _, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: "delete_everything", ResourceRef: "*",
	}); err != nil {
		t.Fatalf("denied EvaluateAction: %v", err)
	}
	// A missing permission backend fails the decision closed.
	h.svc.authorizer = nil
	if _, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	}); err != nil {
		t.Fatalf("fail-closed EvaluateAction: %v", err)
	}

	if got := allowed() - allowedBefore; got < 1 {
		t.Fatalf("allowed decisions = %v, want >= 1 new", got)
	}
	if got := denied() - deniedBefore; got != 1 {
		t.Fatalf("denied decisions = %v, want 1 new", got)
	}
	if got := failClosed() - failClosedBefore; got != 1 {
		t.Fatalf("fail_closed decisions = %v, want 1 new", got)
	}
	if got := testutil.ToFloat64(gwmetrics.EvidenceEventsTotal.WithLabelValues(testTenant, runtime.EvidenceKindDecision)) - decisionsBefore; got < 3 {
		t.Fatalf("decision evidence events = %v, want >= 3 new", got)
	}
}

func TestMetricsControlAndEvidenceEvents(t *testing.T) {
	h := newHarness(t)
	agent := h.agents.agent.ID

	// Mint first (a kill-switched agent cannot mint): the mint path
	// records delegation evidence.
	delegationsBefore := testutil.ToFloat64(gwmetrics.EvidenceEventsTotal.WithLabelValues(testTenant, runtime.EvidenceKindDelegationMint))
	h.registerSearchTool(t)
	if _, err := h.svc.MintDelegation(testCtx, testTenant, testRegion, agent, ownerActor, false, "mint-metrics",
		runtime.MintDelegationRequest{SubjectPrincipalID: subjectPr, Purpose: "review", PermittedActions: []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction}}); err != nil {
		t.Fatalf("MintDelegation: %v", err)
	}
	if got := testutil.ToFloat64(gwmetrics.EvidenceEventsTotal.WithLabelValues(testTenant, runtime.EvidenceKindDelegationMint)) - delegationsBefore; got != 1 {
		t.Fatalf("delegation evidence events = %v, want 1 new", got)
	}

	controlsBefore := testutil.ToFloat64(gwmetrics.ControlEventsTotal.WithLabelValues(testTenant, runtime.ControlEntityAgent, runtime.ControlActionKillSwitch))
	emergencyBefore := testutil.ToFloat64(gwmetrics.EvidenceEventsTotal.WithLabelValues(testTenant, runtime.EvidenceKindEmergencyControl))
	if _, err := h.svc.KillSwitchAgent(testCtx, testTenant, agent, adminActor, true, runtime.ControlRequest{Reason: "incident-42"}); err != nil {
		t.Fatalf("KillSwitchAgent: %v", err)
	}
	if got := testutil.ToFloat64(gwmetrics.ControlEventsTotal.WithLabelValues(testTenant, runtime.ControlEntityAgent, runtime.ControlActionKillSwitch)) - controlsBefore; got != 1 {
		t.Fatalf("control events = %v, want 1 new", got)
	}
	if got := testutil.ToFloat64(gwmetrics.EvidenceEventsTotal.WithLabelValues(testTenant, runtime.EvidenceKindEmergencyControl)) - emergencyBefore; got != 1 {
		t.Fatalf("emergency evidence events = %v, want 1 new", got)
	}
}

func TestMetricsBudgetExhaustion(t *testing.T) {
	h := newHarness(t)
	h.grantSearch(t, h.registerSearchTool(t))
	minted := h.mint(t, "mint-budget", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	if _, err := h.svc.UpsertBudget(testCtx, testTenant, adminActor, true, runtime.BudgetScopeTenant, "", "",
		runtime.BudgetPolicyRequest{MaxActionsPerRun: 1}); err != nil {
		t.Fatalf("UpsertBudget: %v", err)
	}
	// The run-start action consumes the single budgeted action.
	run := h.createRun(t, minted.Token, "run-budget", searchAction("*"))

	before := testutil.ToFloat64(gwmetrics.BudgetExhaustionsTotal.WithLabelValues(testTenant, "budget_exhausted:max_actions_per_run"))
	if _, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: minted.Token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	}); err != nil {
		t.Fatalf("EvaluateAction: %v", err)
	}
	if got := testutil.ToFloat64(gwmetrics.BudgetExhaustionsTotal.WithLabelValues(testTenant, "budget_exhausted:max_actions_per_run")) - before; got != 1 {
		t.Fatalf("budget exhaustions = %v, want 1 new", got)
	}
}

func TestMetricsAuditVerifyOutcomes(t *testing.T) {
	h := newHarness(t)
	run, _ := h.happyRun(t)

	verifiedBefore := testutil.ToFloat64(gwmetrics.AuditVerifyTotal.WithLabelValues(testTenant, "verified"))
	if _, err := h.svc.VerifyAuditChain(testCtx, testTenant, "", false); err != nil {
		t.Fatalf("VerifyAuditChain (clean): %v", err)
	}
	if got := testutil.ToFloat64(gwmetrics.AuditVerifyTotal.WithLabelValues(testTenant, "verified")) - verifiedBefore; got != 1 {
		t.Fatalf("verified audit runs = %v, want 1 new", got)
	}

	// Tamper one decision in the stored chain: verification must fail.
	for i := range h.store.decisions[testTenant][run.Run.ID] {
		h.store.decisions[testTenant][run.Run.ID][i].ImmutableDigest = "tampered"
	}
	failedBefore := testutil.ToFloat64(gwmetrics.AuditVerifyTotal.WithLabelValues(testTenant, "failed"))
	if _, err := h.svc.VerifyAuditChain(testCtx, testTenant, "", false); err != nil {
		t.Fatalf("VerifyAuditChain (tampered): %v", err)
	}
	if got := testutil.ToFloat64(gwmetrics.AuditVerifyTotal.WithLabelValues(testTenant, "failed")) - failedBefore; got != 1 {
		t.Fatalf("failed audit runs = %v, want 1 new", got)
	}
}
