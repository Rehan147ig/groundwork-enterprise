package runtime_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"groundwork/query-runtime/internal/runtime"
)

// ---------------------------------------------------------------------
// Phase 3: emergency controls, budgets, evidence + verification, outbox
// ---------------------------------------------------------------------

func TestGovernanceEmergencyControlsHTTP(t *testing.T) {
	h := newGovAPIHarness(t)
	toolID, _, _ := govSetup(t, h.s, false)

	// Kill-switch the tool (reason is mandatory evidence).
	rec := doGov(t, h.s, http.MethodPost, "/v1/governance/tools/"+toolID+"/kill-switch", govAdminKey, tokenFor(t, govOwner), "",
		`{"reason":"incident-42"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("kill-switch tool: %d %s", rec.Code, rec.Body.String())
	}
	var ctrlResp runtime.GovernanceControlResponse
	decodeGov(t, rec, &ctrlResp)
	ctrl := ctrlResp.Control
	if ctrl.EntityType != runtime.ControlEntityTool || ctrl.EntityID != toolID ||
		ctrl.ControlState != runtime.ControlStateKillSwitched || ctrl.ActorPrincipalID != govOwner || ctrl.Reason != "incident-42" {
		t.Fatalf("unexpected control: %+v", ctrl)
	}

	// Repeating the same control is an idempotent no-op (200, state
	// unchanged) — never an error, never a new evidence action.
	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/tools/"+toolID+"/kill-switch", govAdminKey, tokenFor(t, govOwner), "",
		`{"reason":"again"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("second kill-switch: expected 200 idempotent, got %d: %s", rec.Code, rec.Body.String())
	}
	var repeat runtime.GovernanceControlResponse
	decodeGov(t, rec, &repeat)
	if repeat.Control.ControlState != runtime.ControlStateKillSwitched {
		t.Fatalf("idempotent kill-switch must stay kill_switched, got %s", repeat.Control.ControlState)
	}

	// Resume restores the tool to active.
	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/tools/"+toolID+"/resume", govAdminKey, tokenFor(t, govOwner), "",
		`{"reason":"false-alarm"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("resume tool: %d %s", rec.Code, rec.Body.String())
	}
	var resumed runtime.GovernanceControlResponse
	decodeGov(t, rec, &resumed)
	if resumed.Control.ControlState != runtime.ControlStateActive {
		t.Fatalf("resume must restore active, got %s", resumed.Control.ControlState)
	}

	// Kill-switch the agent; the immutable chain must now show 3 actions.
	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/agents/agent-1/kill-switch", govAdminKey, tokenFor(t, govOwner), "",
		`{"reason":"agent-compromised"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("kill-switch agent: %d %s", rec.Code, rec.Body.String())
	}

	// A killed agent cannot be minted a new delegation: fail closed 409.
	rec = govMint(t, h.s, "mint-killed", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"x","permitted_actions":["groundwork_search:search"]}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("mint on killed agent: expected 409, got %d: %s", rec.Code, rec.Body.String())
	}

	// List shows both controls (tool + agent).
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/emergency-controls", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list controls: %d %s", rec.Code, rec.Body.String())
	}
	var listResp runtime.GovernanceControlsResponse
	decodeGov(t, rec, &listResp)
	if listResp.Count < 2 {
		t.Fatalf("expected >= 2 controls, got %d: %+v", listResp.Count, listResp.Controls)
	}

	// Mutations require a verified identity: no assertion -> 401.
	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/agents/agent-1/resume", govAdminKey, "", "", `{"reason":"x"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no identity: expected 401, got %d", rec.Code)
	}

	// A non-admin governance-scoped key is denied by the service (403),
	// regardless of the verified identity.
	nonAdmin := newGovServer(t, h.svc, runtime.TenantContext{TenantID: govTenant, Region: govRegion, KeyName: "gov-test", Scopes: []string{"governance"}}, false, nil)
	rec = doGov(t, nonAdmin, http.MethodPost, "/v1/governance/agents/agent-1/resume", govAdminKey, tokenFor(t, "principal:mallory"), "",
		`{"reason":"x"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGovernanceRunTerminateHTTP(t *testing.T) {
	h := newGovAPIHarness(t)
	govSetup(t, h.s, false)
	minted := govMint(t, h.s, "mint-term", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["groundwork_search:search"]}`)
	var mintResp runtime.GovernanceDelegationResponse
	decodeGov(t, minted, &mintResp)
	run, _ := govCreateRun(t, h.s, mintResp.Token, "run-term")

	// Terminating a run is irreversible: 200 + revoke-state control.
	rec := doGov(t, h.s, http.MethodPost, "/v1/governance/runs/"+run.Run.ID+"/terminate", govAdminKey, tokenFor(t, govOwner), "",
		`{"reason":"run-out-of-control"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("terminate run: %d %s", rec.Code, rec.Body.String())
	}
	var ctrlResp runtime.GovernanceControlResponse
	decodeGov(t, rec, &ctrlResp)
	if ctrlResp.Control.EntityType != runtime.ControlEntityRun || ctrlResp.Control.EntityID != run.Run.ID {
		t.Fatalf("terminate must target the run: %+v", ctrlResp.Control)
	}

	// Further evaluation of the terminated run fails closed with a
	// recorded denial (reason_code run:terminated) — never allowed.
	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/runs/"+run.Run.ID+"/evaluate", govAdminKey, "", "",
		`{"delegation_token":"`+mintResp.Token+`","run_id":"`+run.Run.ID+`","tool_name":"groundwork_search","action":"search","resource_ref":"*"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("evaluate terminated run: expected 200 denial record, got %d: %s", rec.Code, rec.Body.String())
	}
	var evalResp runtime.GovernanceEvaluateResponse
	decodeGov(t, rec, &evalResp)
	if evalResp.Allowed || evalResp.Decision.Decision != "denied" || evalResp.Decision.ReasonCode != "run:terminated" {
		t.Fatalf("terminated run must fail closed with run:terminated, got %+v", evalResp.Decision)
	}
}

func TestGovernanceBudgetsHTTP(t *testing.T) {
	h := newGovAPIHarness(t)
	govSetup(t, h.s, false)

	// Upsert a tenant-scope budget capping actions per run at 2.
	rec := doGov(t, h.s, http.MethodPost, "/v1/governance/budgets", govAdminKey, tokenFor(t, govOwner), "",
		`{"scope_type":"tenant","max_actions_per_run":2}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("upsert budget: %d %s", rec.Code, rec.Body.String())
	}
	var budgetResp runtime.GovernanceBudgetResponse
	decodeGov(t, rec, &budgetResp)
	if budgetResp.Budget.ScopeType != runtime.BudgetScopeTenant || budgetResp.Budget.MaxActionsPerRun != 2 {
		t.Fatalf("unexpected budget: %+v", budgetResp.Budget)
	}

	// Effective budget resolves for a version.
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/budgets/effective?agent_version_id=version-1", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("effective budget: %d %s", rec.Code, rec.Body.String())
	}
	var effective runtime.GovernanceBudgetResponse
	decodeGov(t, rec, &effective)
	if effective.Budget.MaxActionsPerRun != 2 {
		t.Fatalf("effective must inherit tenant cap, got %d", effective.Budget.MaxActionsPerRun)
	}

	// List returns the tenant policy.
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/budgets", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list budgets: %d %s", rec.Code, rec.Body.String())
	}
	var listResp runtime.GovernanceBudgetsResponse
	decodeGov(t, rec, &listResp)
	if listResp.Count != 1 {
		t.Fatalf("expected 1 budget, got %d", listResp.Count)
	}

	// A run with 3 actions: the third must be denied with the budget
	// reason code, all recorded as evidence.
	minted := govMint(t, h.s, "mint-budget", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["groundwork_search:search"]}`)
	var mintResp runtime.GovernanceDelegationResponse
	decodeGov(t, minted, &mintResp)
	body := `{"delegation_token":"` + mintResp.Token + `","actions":[` +
		`{"tool_name":"groundwork_search","action":"search","resource_ref":"a"},` +
		`{"tool_name":"groundwork_search","action":"search","resource_ref":"b"},` +
		`{"tool_name":"groundwork_search","action":"search","resource_ref":"c"}]}`
	req := govRequest(http.MethodPost, "/v1/governance/runs", govAdminKey, "", "", body)
	recRec := httptest.NewRecorder()
	h.s.Routes().ServeHTTP(recRec, req)
	if recRec.Code != http.StatusCreated {
		t.Fatalf("create run: %d %s", recRec.Code, recRec.Body.String())
	}
	var runResp runtime.GovernanceRunResponse
	decodeGov(t, recRec, &runResp)
	if len(runResp.Decisions) != 3 {
		t.Fatalf("expected 3 decisions, got %d", len(runResp.Decisions))
	}
	if runResp.Decisions[2].Decision != "denied" ||
		runResp.Decisions[2].ReasonCode != "budget_exhausted:max_actions_per_run" {
		t.Fatalf("third action must be budget-denied, got %+v", runResp.Decisions[2])
	}

	// A further evaluate on the exhausted run also denies with the code.
	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/runs/"+runResp.Run.ID+"/evaluate", govAdminKey, "", "",
		`{"delegation_token":"`+mintResp.Token+`","run_id":"`+runResp.Run.ID+`","tool_name":"groundwork_search","action":"search","resource_ref":"d"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("evaluate: %d %s", rec.Code, rec.Body.String())
	}
	var evalResp runtime.GovernanceEvaluateResponse
	decodeGov(t, rec, &evalResp)
	if evalResp.Decision.Decision != "denied" || evalResp.Decision.ReasonCode != "budget_exhausted:max_actions_per_run" {
		t.Fatalf("expected budget denial, got %+v", evalResp.Decision)
	}
}

func TestGovernanceEvidenceAndAuditVerifyHTTP(t *testing.T) {
	h := newGovAPIHarness(t)
	govSetup(t, h.s, false)
	minted := govMint(t, h.s, "mint-ev", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["groundwork_search:search"]}`)
	var mintResp runtime.GovernanceDelegationResponse
	decodeGov(t, minted, &mintResp)
	run, _ := govCreateRun(t, h.s, mintResp.Token, "run-ev")

	// Evidence list contains the run + decision records.
	rec := doGov(t, h.s, http.MethodGet, "/v1/governance/evidence", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("evidence list: %d %s", rec.Code, rec.Body.String())
	}
	var page runtime.EvidencePage
	decodeGov(t, rec, &page)
	if page.Count < 2 {
		t.Fatalf("expected >= 2 evidence events, got %d", page.Count)
	}
	kinds := map[string]bool{}
	for _, e := range page.Events {
		kinds[e.Kind] = true
	}
	if !kinds[runtime.EvidenceKindRunStart] || !kinds[runtime.EvidenceKindDecision] {
		t.Fatalf("expected run_start + decision evidence, got kinds %v", kinds)
	}

	// Timeline scopes to the run.
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/runs/"+run.Run.ID+"/timeline", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("timeline: %d %s", rec.Code, rec.Body.String())
	}
	var timeline runtime.GovernanceTimelineResponse
	decodeGov(t, rec, &timeline)
	if timeline.Count == 0 {
		t.Fatal("timeline must not be empty")
	}
	for _, e := range timeline.Events {
		if e.RunID != run.Run.ID {
			t.Fatalf("timeline leaked another run's event: %+v", e)
		}
	}

	// Agent activity scopes to the agent.
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/agents/agent-1/activity", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("activity: %d %s", rec.Code, rec.Body.String())
	}
	var activity runtime.GovernanceActivityResponse
	decodeGov(t, rec, &activity)
	if activity.Count == 0 {
		t.Fatal("activity must not be empty")
	}

	// Single event fetch + kind filter.
	first := page.Events[0]
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/evidence/"+first.EventID, govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("evidence event: %d %s", rec.Code, rec.Body.String())
	}
	var single runtime.GovernanceEvidenceEventResponse
	decodeGov(t, rec, &single)
	if single.Event.EventID != first.EventID {
		t.Fatalf("wrong event returned: %+v", single.Event)
	}
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/evidence?kinds="+runtime.EvidenceKindDecision, govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("evidence filter: %d %s", rec.Code, rec.Body.String())
	}
	var filtered runtime.EvidencePage
	decodeGov(t, rec, &filtered)
	if filtered.Count == 0 {
		t.Fatal("kind filter must match decision events")
	}

	// Verification is read-only and reports the chains intact.
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/audit/verify", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
	var verify runtime.EvidenceVerifyResult
	decodeGov(t, rec, &verify)
	if !verify.Verified {
		t.Fatalf("clean chains must verify: %+v", verify)
	}
	if verify.EventsChecked < 1 || verify.ChainsChecked < 1 {
		t.Fatalf("verify must count checked events/chains: %+v", verify)
	}

	// Creating a checkpoint then verifying from it must also verify.
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/audit/verify?create_checkpoint=true", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("verify+checkpoint: %d %s", rec.Code, rec.Body.String())
	}
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/audit/checkpoints", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("checkpoints: %d %s", rec.Code, rec.Body.String())
	}
	var checkpoints runtime.GovernanceCheckpointsResponse
	decodeGov(t, rec, &checkpoints)
	if checkpoints.Count != 1 {
		t.Fatalf("expected 1 checkpoint, got %d", checkpoints.Count)
	}
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/audit/verify?checkpoint_id="+checkpoints.Checkpoints[0].ID, govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("verify from checkpoint: %d %s", rec.Code, rec.Body.String())
	}
	var fromCP runtime.EvidenceVerifyResult
	decodeGov(t, rec, &fromCP)
	if !fromCP.Verified || !fromCP.FromCheckpoint {
		t.Fatalf("checkpoint verify must succeed from the boundary: %+v", fromCP)
	}
}

func TestGovernanceOutboxSurfaceHTTP(t *testing.T) {
	h := newGovAPIHarness(t)
	govSetup(t, h.s, false)
	minted := govMint(t, h.s, "mint-outbox", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["groundwork_search:search"]}`)
	var mintResp runtime.GovernanceDelegationResponse
	decodeGov(t, minted, &mintResp)
	_, _ = govCreateRun(t, h.s, mintResp.Token, "run-outbox")

	rec := doGov(t, h.s, http.MethodGet, "/v1/governance/outbox", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("outbox list: %d %s", rec.Code, rec.Body.String())
	}
	var outbox runtime.GovernanceOutboxResponse
	decodeGov(t, rec, &outbox)
	if outbox.Count < 2 {
		t.Fatalf("expected >= 2 outbox events, got %d", outbox.Count)
	}
	types := map[string]bool{}
	for _, e := range outbox.Events {
		types[e.EventType] = true
	}
	for _, want := range []string{runtime.OutboxEventDelegationMinted, runtime.OutboxEventRunStarted, runtime.OutboxEventActionDecision} {
		if !types[want] {
			t.Fatalf("expected outbox event %s, got %v", want, types)
		}
	}

	// Status filter.
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/outbox?status=pending", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("outbox filter: %d %s", rec.Code, rec.Body.String())
	}
	var pending runtime.GovernanceOutboxResponse
	decodeGov(t, rec, &pending)
	if pending.Count == 0 {
		t.Fatal("pending filter must match pending events")
	}
	for _, e := range pending.Events {
		if e.Status != runtime.OutboxStatusPending {
			t.Fatalf("status filter leaked %s", e.Status)
		}
	}

	// Retry resets a pending event (200); retry is identity-gated.
	target := pending.Events[0]
	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/outbox/"+target.EventID+"/retry", govAdminKey, tokenFor(t, govOwner), "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body.String())
	}
	var retried runtime.GovernanceOutboxEventResponse
	decodeGov(t, rec, &retried)
	if retried.Event.Status != runtime.OutboxStatusPending {
		t.Fatalf("retry must return the event pending, got %s", retried.Event.Status)
	}
	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/outbox/"+target.EventID+"/retry", govAdminKey, "", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("retry without identity: expected 401, got %d", rec.Code)
	}
	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/outbox/does-not-exist/retry", govAdminKey, tokenFor(t, govOwner), "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("retry unknown event: expected 404, got %d: %s", rec.Code, rec.Body.String())
	}

	// Tenant isolation: another tenant's key (same scope) sees nothing.
	other := newGovServer(t, h.svc, runtime.TenantContext{TenantID: "tenant-other", Region: govRegion, KeyName: "gov-test", Scopes: []string{"admin"}}, false, nil)
	rec = doGov(t, other, http.MethodGet, "/v1/governance/outbox", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("other tenant outbox: %d %s", rec.Code, rec.Body.String())
	}
	var otherBox runtime.GovernanceOutboxResponse
	decodeGov(t, rec, &otherBox)
	if otherBox.Count != 0 {
		t.Fatalf("outbox must be tenant-isolated, got %d events", otherBox.Count)
	}
}
