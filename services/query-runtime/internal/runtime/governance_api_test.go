package runtime_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"groundwork/query-runtime/internal/governance"
	"groundwork/query-runtime/internal/relationship"
	"groundwork/query-runtime/internal/runtime"
	"groundwork/query-runtime/internal/usage"
)

// ---------------------------------------------------------------------
// Harness: real governance service (memory store + env-built authority)
// wired into a real Server, mirroring cmd/query-runtime.
// ---------------------------------------------------------------------

const (
	govTenant   = "tenant-acme"
	govRegion   = "us-east-1"
	govOwner    = "principal:alice"
	govSubject  = "principal:bob"
	govAdminKey = "gw_test_key"
)

type govFakeAgents struct {
	agent    runtime.Agent
	versions []runtime.AgentVersion
	err      error
}

func (f *govFakeAgents) GetAgent(context.Context, string, string) (runtime.Agent, []runtime.AgentVersion, []runtime.LifecycleEvent, error) {
	if f.err != nil {
		return runtime.Agent{}, nil, nil, f.err
	}
	return f.agent, f.versions, nil, nil
}

func (f *govFakeAgents) ListVersions(context.Context, string, string) ([]runtime.AgentVersion, error) {
	return f.versions, nil
}

type govFakeChecker struct {
	allowed func(user, relation, object string) (bool, error)
}

func (f *govFakeChecker) Check(_ context.Context, req relationship.CheckRequest) (bool, error) {
	user := relationship.EncodeSubject(req.Subject)
	relation := relationship.PermissionToRelation(req.Permission)
	object := relationship.EncodeObject(req.Resource)
	if f.allowed == nil {
		return true, nil
	}
	return f.allowed(user, relation, object)
}

func (f *govFakeChecker) Ready(context.Context) error { return nil }

// recordingExecutor captures the QueryRequest the engine would receive,
// so the query delegation gate can be asserted end-to-end.
type recordingExecutor struct {
	mu    sync.Mutex
	calls int
	got   runtime.QueryRequest
}

func (e *recordingExecutor) Execute(_ context.Context, req runtime.QueryRequest) runtime.QueryResponse {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	e.got = req
	return runtime.QueryResponse{}
}

func (e *recordingExecutor) last() runtime.QueryRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.got
}

type govAPIHarness struct {
	s   *runtime.Server
	svc runtime.GovernanceService
	gov *governance.Service
	ex  *recordingExecutor
}

// newGovAPIHarness builds a production-mode server (verified identity
// required, demo OFF) with an admin+query API key and a recording
// executor. Exactly one harness per test (t.Setenv is once-only).
func newGovAPIHarness(t *testing.T) *govAPIHarness {
	t.Helper()
	t.Setenv("GROUNDWORK_DELEGATION_HS_SECRET", "api-test-delegation-hs-secret-32chars-min")
	authority, err := governance.BuildAuthority()
	if err != nil {
		t.Fatalf("BuildAuthority: %v", err)
	}
	agents := &govFakeAgents{
		agent: runtime.Agent{
			ID:               "agent-1",
			TenantID:         govTenant,
			Name:             "finance-reviewer",
			OwnerPrincipalID: govOwner,
			LifecycleState:   runtime.AgentStateActive,
			ActiveVersionID:  "version-1",
		},
		versions: []runtime.AgentVersion{{ID: "version-1", AgentID: "agent-1", Version: "1.0.0", Status: runtime.VersionStatusActive}},
	}
	svc := governance.NewService(governance.NewMemoryStore(), authority, &govFakeChecker{}, agents)
	ex := &recordingExecutor{}
	s := newGovServer(t, svc, runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "gov-test", Scopes: []string{"admin", "query"},
	}, false, ex)
	return &govAPIHarness{s: s, svc: svc, gov: svc, ex: ex}
}

// newGovServer builds a Server around a shared governance service (no
// env setup — reuse across harnesses for region/demo variations).
func newGovServer(t *testing.T, svc runtime.GovernanceService, tenant runtime.TenantContext, allowDemo bool, ex runtime.QueryExecutor) *runtime.Server {
	t.Helper()
	backend := runtime.NewMemoryBackend()
	apiKeys := runtime.NewMemoryAPIKeyResolver(govAdminKey, tenant)
	s := runtime.NewServerWithExecutor(runtime.Config{}, backend, apiKeys, ex)
	s.SetGovernanceService(svc)
	s.SetIdentity(testVerifier{secret: "server-secret"}, allowDemo)
	return s
}

// ---------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------

func govRequest(method, path, key, assertion, delegation, body string) *http.Request {
	var reader *bytes.Reader
	if body == "" {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("X-Groundwork-API-Key", key)
	if assertion != "" {
		req.Header.Set("X-Groundwork-User-Assertion", assertion)
	}
	if delegation != "" {
		req.Header.Set(runtime.DelegationTokenHeader, delegation)
	}
	return req
}

func doGov(t *testing.T, s *runtime.Server, method, path, key, assertion, delegation, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := govRequest(method, path, key, assertion, delegation, body)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	return rec
}

func decodeGov(t *testing.T, rec *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
}

func govErrorOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var apiErr runtime.GovernanceAPIError
	decodeGov(t, rec, &apiErr)
	return apiErr.Error
}

// govSetup registers the builtin groundwork_search:search tool, activates
// it, and grants it to agent-1/version-1. requiresApproval sets the grant's
// requires_approval flag (approval_required decision path).
func govSetup(t *testing.T, s *runtime.Server, requiresApproval bool) (toolID, actionID, grantID string) {
	t.Helper()
	rec := doGov(t, s, http.MethodPost, "/v1/governance/tools", govAdminKey, tokenFor(t, govOwner), "",
		`{"name":"groundwork_search","description":"governed retrieval","transport":"builtin","owner_principal_id":"principal:alice","region":"us-east-1"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create tool: %d %s", rec.Code, rec.Body.String())
	}
	var toolResp runtime.GovernanceToolResponse
	decodeGov(t, rec, &toolResp)

	rec = doGov(t, s, http.MethodPost, "/v1/governance/tools/"+toolResp.Tool.ID+"/actions", govAdminKey, tokenFor(t, govOwner), "",
		`{"action":"search","resource_type":"document","risk_level":"low","read_only":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create action: %d %s", rec.Code, rec.Body.String())
	}
	var actionResp runtime.GovernanceToolActionResponse
	decodeGov(t, rec, &actionResp)

	rec = doGov(t, s, http.MethodPost, "/v1/governance/tools/"+toolResp.Tool.ID+"/lifecycle", govAdminKey, tokenFor(t, govOwner), "",
		`{"lifecycle":"active"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("activate tool: %d %s", rec.Code, rec.Body.String())
	}

	approval := ""
	if requiresApproval {
		approval = `,"requires_approval":true`
	}
	grantBody := `{"agent_id":"agent-1","version_id":"version-1","tool_id":"` + toolResp.Tool.ID +
		`","action_id":"` + actionResp.Action.ID + `"` + approval + `}`
	rec = doGov(t, s, http.MethodPost, "/v1/governance/grants", govAdminKey, tokenFor(t, govOwner), "", grantBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("grant: %d %s", rec.Code, rec.Body.String())
	}
	var grantResp runtime.GovernanceGrantResponse
	decodeGov(t, rec, &grantResp)
	return toolResp.Tool.ID, actionResp.Action.ID, grantResp.Grant.ID
}

// govMint mints a delegation for agent-1 with the given idempotency key.
func govMint(t *testing.T, s *runtime.Server, idem string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := govRequest(http.MethodPost, "/v1/governance/delegations", govAdminKey, tokenFor(t, govOwner), "", body)
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	return rec
}

// govCreateRun creates a run for the minted token with the builtin search action.
func govCreateRun(t *testing.T, s *runtime.Server, token, idem string) (runtime.GovernanceRunResponse, *httptest.ResponseRecorder) {
	t.Helper()
	body := `{"delegation_token":"` + token + `","actions":[{"tool_name":"groundwork_search","action":"search","resource_ref":"*"}]}`
	req := govRequest(http.MethodPost, "/v1/governance/runs", govAdminKey, "", "", body)
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	var resp runtime.GovernanceRunResponse
	if rec.Code == http.StatusCreated {
		decodeGov(t, rec, &resp)
	}
	return resp, rec
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

func TestGovernanceRequiresGovernanceScope(t *testing.T) {
	t.Setenv("GROUNDWORK_DELEGATION_HS_SECRET", "api-test-delegation-hs-secret-32chars-min")
	authority, err := governance.BuildAuthority()
	if err != nil {
		t.Fatalf("BuildAuthority: %v", err)
	}
	svc := governance.NewService(governance.NewMemoryStore(), authority, &govFakeChecker{}, &govFakeAgents{})
	s := newGovServer(t, svc, runtime.TenantContext{TenantID: govTenant, Region: govRegion, KeyName: "gov-test", Scopes: []string{"query"}}, false, nil)
	rec := doGov(t, s, http.MethodGet, "/v1/governance/tools", govAdminKey, "", "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if govErrorOf(t, rec) != "insufficient_scope" {
		t.Fatalf("expected insufficient_scope, got %q", govErrorOf(t, rec))
	}
}

func TestGovernanceMutationsRequireIdentity(t *testing.T) {
	h := newGovAPIHarness(t)
	// Admin key + NO user assertion -> 401 before the handler runs.
	rec := doGov(t, h.s, http.MethodPost, "/v1/governance/tools", govAdminKey, "", "",
		`{"name":"groundwork_search","description":"x","transport":"builtin","owner_principal_id":"principal:alice","region":"us-east-1"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
	if govErrorOf(t, rec) != "verified_identity_required" {
		t.Fatalf("expected verified_identity_required, got %q", govErrorOf(t, rec))
	}
}

func TestGovernanceToolsCRUDAndLifecycle(t *testing.T) {
	h := newGovAPIHarness(t)
	toolID, actionID, _ := govSetup(t, h.s, false)

	// Duplicate tool name -> 409.
	rec := doGov(t, h.s, http.MethodPost, "/v1/governance/tools", govAdminKey, tokenFor(t, govOwner), "",
		`{"name":"groundwork_search","description":"again","transport":"builtin","owner_principal_id":"principal:alice","region":"us-east-1"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}

	// List tools.
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/tools", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list tools: %d %s", rec.Code, rec.Body.String())
	}
	var list runtime.GovernanceToolListResponse
	decodeGov(t, rec, &list)
	if list.Count != 1 || len(list.Tools) != 1 || list.Tools[0].ID != toolID {
		t.Fatalf("unexpected tool list: %+v", list)
	}

	// Detail.
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/tools/"+toolID, govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get tool: %d %s", rec.Code, rec.Body.String())
	}
	var detail runtime.GovernanceToolDetailResponse
	decodeGov(t, rec, &detail)
	if detail.Tool.ID != toolID || len(detail.Actions) != 1 || detail.Actions[0].ID != actionID {
		t.Fatalf("unexpected detail: %+v", detail)
	}

	// List actions.
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/tools/"+toolID+"/actions", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list actions: %d %s", rec.Code, rec.Body.String())
	}
	var actions runtime.GovernanceToolActionsResponse
	decodeGov(t, rec, &actions)
	if actions.Count != 1 {
		t.Fatalf("expected 1 action, got %d", actions.Count)
	}

	// Unknown tool -> 404.
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/tools/tool-nope", govAdminKey, "", "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGovernanceGrantsLifecycleAndRevokeFailsClosed(t *testing.T) {
	h := newGovAPIHarness(t)
	_, _, grantID := govSetup(t, h.s, false)

	// List grants for the agent.
	rec := doGov(t, h.s, http.MethodGet, "/v1/governance/agents/agent-1/grants", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list grants: %d %s", rec.Code, rec.Body.String())
	}
	var list runtime.GovernanceGrantListResponse
	decodeGov(t, rec, &list)
	if list.Count != 1 || list.Grants[0].ID != grantID {
		t.Fatalf("unexpected grants: %+v", list)
	}

	// Mint + create run, then revoke the grant: evaluation must fail closed.
	minted := govMint(t, h.s, "mint-grants", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["groundwork_search:search"]}`)
	if minted.Code != http.StatusCreated {
		t.Fatalf("mint: %d %s", minted.Code, minted.Body.String())
	}
	var mintResp runtime.GovernanceDelegationResponse
	decodeGov(t, minted, &mintResp)
	run, rec := govCreateRun(t, h.s, mintResp.Token, "run-grants")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create run: %d %s", rec.Code, rec.Body.String())
	}

	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/grants/"+grantID+"/revoke", govAdminKey, tokenFor(t, govOwner), "", `{"reason":"compliance hold"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	var revoked runtime.GovernanceGrantResponse
	decodeGov(t, rec, &revoked)
	if revoked.Grant.RevokedAt.IsZero() {
		t.Fatalf("grant not revoked: %+v", revoked.Grant)
	}

	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/runs/"+run.Run.ID+"/evaluate", govAdminKey, "", "",
		`{"delegation_token":"`+mintResp.Token+`","tool_name":"groundwork_search","action":"search","resource_ref":"*"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("evaluate: %d %s", rec.Code, rec.Body.String())
	}
	var eval runtime.GovernanceEvaluateResponse
	decodeGov(t, rec, &eval)
	if eval.Allowed || eval.Decision.Decision != runtime.DecisionDenied {
		t.Fatalf("expected denied after revoke, got %+v", eval)
	}
}

func TestGovernanceMintSingleDeliveryAndReplay(t *testing.T) {
	h := newGovAPIHarness(t)
	govSetup(t, h.s, false)

	// First mint: token returned exactly once.
	first := govMint(t, h.s, "mint-1", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"quarterly review","permitted_actions":["groundwork_search:search"]}`)
	if first.Code != http.StatusCreated {
		t.Fatalf("mint: %d %s", first.Code, first.Body.String())
	}
	var firstResp runtime.GovernanceDelegationResponse
	decodeGov(t, first, &firstResp)
	if firstResp.Token == "" || firstResp.TokenAlreadyIssued {
		t.Fatalf("unexpected mint response: %+v", firstResp)
	}

	// Idempotent replay: same Idempotency-Key, no raw token.
	replay := govMint(t, h.s, "mint-1", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"quarterly review","permitted_actions":["groundwork_search:search"]}`)
	if replay.Code != http.StatusCreated {
		t.Fatalf("replay: %d %s", replay.Code, replay.Body.String())
	}
	var replayResp runtime.GovernanceDelegationResponse
	decodeGov(t, replay, &replayResp)
	if !replayResp.TokenAlreadyIssued || replayResp.Token != "" {
		t.Fatalf("expected single-delivery replay, got %+v", replayResp)
	}
	if replayResp.Grant.ID != firstResp.Grant.ID {
		t.Fatalf("replay returned a different grant: %s != %s", replayResp.Grant.ID, firstResp.Grant.ID)
	}

	// Invalid request (no permitted_actions) -> 400.
	bad := govMint(t, h.s, "mint-bad", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review"}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", bad.Code, bad.Body.String())
	}
}

func TestGovernanceMintRejectsDemoIdentity(t *testing.T) {
	t.Setenv("GROUNDWORK_DELEGATION_HS_SECRET", "api-test-delegation-hs-secret-32chars-min")
	authority, err := governance.BuildAuthority()
	if err != nil {
		t.Fatalf("BuildAuthority: %v", err)
	}
	svc := governance.NewService(governance.NewMemoryStore(), authority, &govFakeChecker{}, &govFakeAgents{})
	// Demo server: no assertion needed to pass the identity middleware,
	// but minting must still reject the demo actor.
	s := newGovServer(t, svc, runtime.TenantContext{TenantID: govTenant, Region: govRegion, KeyName: "gov-test", Scopes: []string{"admin"}}, true, nil)
	rec := doGov(t, s, http.MethodPost, "/v1/governance/delegations", govAdminKey, "", "",
		`{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["groundwork_search:search"]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if govErrorOf(t, rec) != "verified_identity_required_for_delegation" {
		t.Fatalf("expected verified_identity_required_for_delegation, got %q", govErrorOf(t, rec))
	}
}

func TestGovernanceRunReuseRejected(t *testing.T) {
	h := newGovAPIHarness(t)
	govSetup(t, h.s, false)
	minted := govMint(t, h.s, "mint-reuse", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["groundwork_search:search"]}`)
	var mintResp runtime.GovernanceDelegationResponse
	decodeGov(t, minted, &mintResp)

	_, rec := govCreateRun(t, h.s, mintResp.Token, "run-reuse")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create run: %d %s", rec.Code, rec.Body.String())
	}
	// Second run with the same token (no idempotency key) -> 409: the
	// delegation is already bound to a run.
	_, rec = govCreateRun(t, h.s, mintResp.Token, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGovernanceApprovalLifecycle(t *testing.T) {
	h := newGovAPIHarness(t)
	_, actionID, _ := govSetup(t, h.s, true)
	minted := govMint(t, h.s, "mint-approval", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["groundwork_search:search"]}`)
	var mintResp runtime.GovernanceDelegationResponse
	decodeGov(t, minted, &mintResp)
	run, rec := govCreateRun(t, h.s, mintResp.Token, "run-approval")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create run: %d %s", rec.Code, rec.Body.String())
	}
	if len(run.Decisions) != 1 || run.Decisions[0].Decision != runtime.DecisionApprovalRequired {
		t.Fatalf("expected approval_required, got %+v", run.Decisions)
	}

	// Approve -> 200.
	req := govRequest(http.MethodPost, "/v1/governance/runs/"+run.Run.ID+"/approve/"+run.Decisions[0].ActionID, govAdminKey, tokenFor(t, govOwner), "", `{"resource_ref":"*"}`)
	req.Header.Set("Idempotency-Key", "appr-1")
	rec = httptest.NewRecorder()
	h.s.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	var approved runtime.GovernanceApprovalResponse
	decodeGov(t, rec, &approved)
	if approved.Denied || approved.Approval.Decision != runtime.ApprovalApproved {
		t.Fatalf("unexpected approval: %+v", approved)
	}

	// Idempotent replay of the approval returns the same approval.
	req = govRequest(http.MethodPost, "/v1/governance/runs/"+run.Run.ID+"/approve/"+run.Decisions[0].ActionID, govAdminKey, tokenFor(t, govOwner), "", `{"resource_ref":"*"}`)
	req.Header.Set("Idempotency-Key", "appr-1")
	rec2 := httptest.NewRecorder()
	h.s.Routes().ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("approval replay: %d %s", rec2.Code, rec2.Body.String())
	}
	var replay runtime.GovernanceApprovalResponse
	decodeGov(t, rec2, &replay)
	if replay.Approval.ID != approved.Approval.ID {
		t.Fatalf("replay returned different approval: %s != %s", replay.Approval.ID, approved.Approval.ID)
	}

	// Evaluate: consumed approval -> allowed.
	eval := func() runtime.GovernanceEvaluateResponse {
		rec := doGov(t, h.s, http.MethodPost, "/v1/governance/runs/"+run.Run.ID+"/evaluate", govAdminKey, "", "",
			`{"delegation_token":"`+mintResp.Token+`","tool_name":"groundwork_search","action":"search","resource_ref":"*"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("evaluate: %d %s", rec.Code, rec.Body.String())
		}
		var e runtime.GovernanceEvaluateResponse
		decodeGov(t, rec, &e)
		return e
	}
	if d := eval(); !d.Allowed || d.Decision.Decision != runtime.DecisionAllowed {
		t.Fatalf("expected allowed after approval, got %+v", d)
	}
	// One-time consumption: needs a fresh approval.
	if d := eval(); d.Decision.Decision != runtime.DecisionApprovalRequired {
		t.Fatalf("expected approval_required after consume, got %+v", d)
	}
	// Deny blocks the action.
	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/runs/"+run.Run.ID+"/deny/"+run.Decisions[0].ActionID, govAdminKey, tokenFor(t, govOwner), "", `{"resource_ref":"*"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body.String())
	}
	var denied runtime.GovernanceApprovalResponse
	decodeGov(t, rec, &denied)
	if !denied.Denied {
		t.Fatalf("expected denied approval, got %+v", denied)
	}
	if d := eval(); d.Allowed || d.Decision.Decision != runtime.DecisionDenied {
		t.Fatalf("expected denied after denial, got %+v", d)
	}
	_ = actionID
}

func TestGovernanceApprovalRejectsDemoIdentity(t *testing.T) {
	h := newGovAPIHarness(t)
	_, _, _ = govSetup(t, h.s, true)
	minted := govMint(t, h.s, "mint-demo-appr", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["groundwork_search:search"]}`)
	var mintResp runtime.GovernanceDelegationResponse
	decodeGov(t, minted, &mintResp)
	run, rec := govCreateRun(t, h.s, mintResp.Token, "run-demo-appr")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create run: %d %s", rec.Code, rec.Body.String())
	}
	// Demo server sharing the same service: approval must be rejected.
	demo := newGovServer(t, h.svc, runtime.TenantContext{TenantID: govTenant, Region: govRegion, KeyName: "gov-test", Scopes: []string{"admin"}}, true, nil)
	rec = doGov(t, demo, http.MethodPost, "/v1/governance/runs/"+run.Run.ID+"/approve/"+run.Decisions[0].ActionID, govAdminKey, "", "", `{"resource_ref":"*"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if govErrorOf(t, rec) != "verified_identity_required_for_approval" {
		t.Fatalf("expected verified_identity_required_for_approval, got %q", govErrorOf(t, rec))
	}
}

func TestGovernanceDispatchBuiltin(t *testing.T) {
	h := newGovAPIHarness(t)
	govSetup(t, h.s, false)
	minted := govMint(t, h.s, "mint-dispatch", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["groundwork_search:search"]}`)
	var mintResp runtime.GovernanceDelegationResponse
	decodeGov(t, minted, &mintResp)
	run, _ := govCreateRun(t, h.s, mintResp.Token, "run-dispatch")

	rec := doGov(t, h.s, http.MethodPost, "/v1/governance/dispatch", govAdminKey, "", "",
		`{"delegation_token":"`+mintResp.Token+`","run_id":"`+run.Run.ID+`","tool_name":"groundwork_search","action":"search","resource_ref":"*"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("dispatch: %d %s", rec.Code, rec.Body.String())
	}
	var resp runtime.GovernanceDispatchResponse
	decodeGov(t, rec, &resp)
	if !resp.Allowed || resp.DispatchMode != "dispatched" {
		t.Fatalf("unexpected dispatch: %+v", resp)
	}
}

// httpRecordingDispatcher records gateway invocations so the quota
// fail-closed gate can be asserted end-to-end (no outbound call when
// the connector_calls quota is exhausted).
type httpRecordingDispatcher struct {
	calls int
}

func (d *httpRecordingDispatcher) Dispatch(_ context.Context, _ runtime.ConnectorDispatchRequest) (runtime.ConnectorDispatchResult, error) {
	d.calls++
	return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationSuccess, StatusCode: http.StatusOK, ResponseBytes: 8}, nil
}

func TestGovernanceDispatchConnectorQuotaDenied(t *testing.T) {
	h := newGovAPIHarness(t)

	// Register an http-transport tool, activate it, and grant it.
	rec := doGov(t, h.s, http.MethodPost, "/v1/governance/tools", govAdminKey, tokenFor(t, govOwner), "",
		`{"name":"webhook","description":"external hook","transport":"http","endpoint_or_server":"https://hooks.example.com","owner_principal_id":"principal:alice","region":"us-east-1"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create tool: %d %s", rec.Code, rec.Body.String())
	}
	var toolResp runtime.GovernanceToolResponse
	decodeGov(t, rec, &toolResp)
	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/tools/"+toolResp.Tool.ID+"/actions", govAdminKey, tokenFor(t, govOwner), "",
		`{"action":"send","resource_type":"document","risk_level":"low","read_only":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create action: %d %s", rec.Code, rec.Body.String())
	}
	var actionResp runtime.GovernanceToolActionResponse
	decodeGov(t, rec, &actionResp)
	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/tools/"+toolResp.Tool.ID+"/lifecycle", govAdminKey, tokenFor(t, govOwner), "", `{"lifecycle":"active"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("activate tool: %d %s", rec.Code, rec.Body.String())
	}
	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/grants", govAdminKey, tokenFor(t, govOwner), "",
		`{"agent_id":"agent-1","version_id":"version-1","tool_id":"`+toolResp.Tool.ID+`","action_id":"`+actionResp.Action.ID+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("grant: %d %s", rec.Code, rec.Body.String())
	}

	minted1 := govMint(t, h.s, "mint-http-q1", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["webhook:send"]}`)
	var mint1 runtime.GovernanceDelegationResponse
	decodeGov(t, minted1, &mint1)
	minted2 := govMint(t, h.s, "mint-http-q2", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["webhook:send"]}`)
	var mint2 runtime.GovernanceDelegationResponse
	decodeGov(t, minted2, &mint2)
	createRun := func(token, idem string) runtime.GovernanceRunResponse {
		rec := doGov(t, h.s, http.MethodPost, "/v1/governance/runs", govAdminKey, "", "",
			`{"delegation_token":"`+token+`","actions":[{"tool_name":"webhook","action":"send","resource_ref":"*"}]}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create run: %d %s", rec.Code, rec.Body.String())
		}
		var r runtime.GovernanceRunResponse
		decodeGov(t, rec, &r)
		return r
	}
	run1 := createRun(mint1.Token, "run-http-q1")
	run2 := createRun(mint2.Token, "run-http-q2")
	dispatch := func(token, runID string) *httptest.ResponseRecorder {
		return doGov(t, h.s, http.MethodPost, "/v1/governance/dispatch", govAdminKey, "", "",
			`{"delegation_token":"`+token+`","run_id":"`+runID+`","tool_name":"webhook","action":"send","resource_ref":"*"}`)
	}

	// connector_calls quota already exhausted (limit 1, 1 recorded).
	ctx := context.Background()
	mem := usage.NewMemoryStore()
	meter := usage.NewService(mem)
	if _, err := meter.UpsertLimits(ctx, govTenant, []usage.Limit{{Metric: usage.MetricConnectorCalls, Period: usage.PeriodMonthly, Limit: 1}}); err != nil {
		t.Fatalf("set connector quota: %v", err)
	}
	if err := meter.Record(ctx, govTenant, usage.MetricConnectorCalls, 1); err != nil {
		t.Fatalf("pre-record connector call: %v", err)
	}
	h.s.SetUsageMeter(meter)
	disp := &httpRecordingDispatcher{}
	h.gov.SetUsageMeter(meter)
	h.gov.SetConnectorDispatcher(disp)

	rec = dispatch(mint1.Token, run1.Run.ID)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("over quota: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := govErrorOf(t, rec); got != "quota_exceeded:connector_calls" {
		t.Fatalf("expected quota_exceeded:connector_calls, got %q", got)
	}
	if disp.calls != 0 {
		t.Fatalf("no outbound call may open over quota, got %d", disp.calls)
	}

	// Quota raised: the next dispatch succeeds and reaches the gateway.
	if _, err := meter.UpsertLimits(ctx, govTenant, []usage.Limit{{Metric: usage.MetricConnectorCalls, Period: usage.PeriodMonthly, Limit: 10}}); err != nil {
		t.Fatalf("raise connector quota: %v", err)
	}
	rec = dispatch(mint2.Token, run2.Run.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("quota released: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp runtime.GovernanceDispatchResponse
	decodeGov(t, rec, &resp)
	if resp.DispatchMode != "dispatched" {
		t.Fatalf("expected dispatched, got %+v", resp)
	}
	if disp.calls != 1 {
		t.Fatalf("expected 1 outbound call, got %d", disp.calls)
	}
}

func TestGovernanceQueryGateDelegated(t *testing.T) {
	h := newGovAPIHarness(t)
	govSetup(t, h.s, false)
	minted := govMint(t, h.s, "mint-query", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["groundwork_search:search"]}`)
	var mintResp runtime.GovernanceDelegationResponse
	decodeGov(t, minted, &mintResp)
	run, _ := govCreateRun(t, h.s, mintResp.Token, "run-query")

	// /v1/query with a delegation token: no end-user assertion needed,
	// and the engine runs as the delegation's subject principal.
	rec := doGov(t, h.s, http.MethodPost, "/v1/query", govAdminKey, "", mintResp.Token,
		`{"question":"what changed?","run_id":"`+run.Run.ID+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("query: %d %s", rec.Code, rec.Body.String())
	}
	if h.ex.calls != 1 {
		t.Fatalf("expected 1 executor call, got %d", h.ex.calls)
	}
	got := h.ex.last()
	if got.UserID != govSubject || got.TenantID != govTenant || got.Region != govRegion || got.RunID != run.Run.ID {
		t.Fatalf("executor saw wrong identity: %+v", got)
	}

	// Unknown run id -> 404 (fail closed, no executor call).
	before := h.ex.calls
	rec = doGov(t, h.s, http.MethodPost, "/v1/query", govAdminKey, "", mintResp.Token,
		`{"question":"what changed?","run_id":"run-nope"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
	if h.ex.calls != before {
		t.Fatalf("executor must not run on a failed gate")
	}

	// Missing run id -> 400.
	rec = doGov(t, h.s, http.MethodPost, "/v1/query", govAdminKey, "", mintResp.Token, `{"question":"what changed?"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGovernanceQueryGateRegionMismatch(t *testing.T) {
	h := newGovAPIHarness(t)
	govSetup(t, h.s, false)
	minted := govMint(t, h.s, "mint-region", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["groundwork_search:search"]}`)
	var mintResp runtime.GovernanceDelegationResponse
	decodeGov(t, minted, &mintResp)
	run, _ := govCreateRun(t, h.s, mintResp.Token, "run-region")

	// Same service, different region context: the token was minted for
	// us-east-1, so the eu-west-1 tenant context fails closed (403).
	other := newGovServer(t, h.svc, runtime.TenantContext{TenantID: govTenant, Region: "eu-west-1", KeyName: "gov-test", Scopes: []string{"query"}}, false, nil)
	rec := doGov(t, other, http.MethodPost, "/v1/query", govAdminKey, "", mintResp.Token,
		`{"question":"what changed?","run_id":"`+run.Run.ID+`"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGovernanceQueryGateWithoutService(t *testing.T) {
	// No SetGovernanceService: a delegation token fails closed with 503
	// (governance_unavailable), never reaching the engine.
	backend := runtime.NewMemoryBackend()
	apiKeys := runtime.NewMemoryAPIKeyResolver(govAdminKey, runtime.TenantContext{TenantID: govTenant, Region: govRegion, KeyName: "gov-test", Scopes: []string{"query"}})
	s := runtime.NewServerWithExecutor(runtime.Config{}, backend, apiKeys, nil)
	s.SetIdentity(testVerifier{secret: "server-secret"}, false)
	rec := doGov(t, s, http.MethodPost, "/v1/query", govAdminKey, "", "not-a-token", `{"question":"hi","run_id":"run-1"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGovernanceSimulateWouldAllowOverHTTP(t *testing.T) {
	h := newGovAPIHarness(t)
	govSetup(t, h.s, false)

	// Simulation is an analysis endpoint: no identity required.
	rec := doGov(t, h.s, http.MethodPost, "/v1/governance/simulate", govAdminKey, "", "",
		`{"agent_id":"agent-1","tool_name":"groundwork_search","action":"search","resource_ref":"doc:q3","principal_id":"principal:bob"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("simulate: %d %s", rec.Code, rec.Body.String())
	}
	var resp runtime.GovernanceSimulateResponse
	decodeGov(t, rec, &resp)
	sim := resp.Simulation
	if !sim.Simulated || !sim.Allowed || sim.Decision != runtime.DecisionAllowed {
		t.Fatalf("expected allowed simulation, got %+v", sim)
	}
	if len(sim.Checks) == 0 {
		t.Fatal("expected gate checks")
	}
	// The emergency-controls gate reports the run/delegation entities as
	// skipped and the relationship gate ran because a principal was given.
	var sawAgentGate, sawDelegationSkipped, sawRelationship bool
	for _, c := range sim.Checks {
		switch c.Gate {
		case "agent":
			sawAgentGate = true
		case "relationship":
			sawRelationship = c.Status == runtime.GateStatusPassed
		case "delegation":
			sawDelegationSkipped = c.Status == runtime.GateStatusSkipped
		}
	}
	if !sawAgentGate || !sawDelegationSkipped || !sawRelationship {
		t.Fatalf("unexpected gate summary: %+v", sim.Checks)
	}
}

func TestGovernanceSimulateWouldDenyOverHTTP(t *testing.T) {
	h := newGovAPIHarness(t)
	_, _, grantID := govSetup(t, h.s, false)
	// Revoke the grant so the coverage gate must fail closed.
	rec := doGov(t, h.s, http.MethodPost, "/v1/governance/grants/"+grantID+"/revoke", govAdminKey, tokenFor(t, govOwner), "", `{"reason":"compliance hold"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}

	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/simulate", govAdminKey, "", "",
		`{"agent_id":"agent-1","tool_name":"groundwork_search","action":"search","resource_ref":"doc:q3"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("simulate: %d %s", rec.Code, rec.Body.String())
	}
	var resp runtime.GovernanceSimulateResponse
	decodeGov(t, rec, &resp)
	sim := resp.Simulation
	if sim.Allowed || sim.Decision != runtime.DecisionDenied {
		t.Fatalf("expected denied simulation, got %+v", sim)
	}
	// Gates are reported up to and including the first blocking failure;
	// the grant coverage gate fails with no active grant.
	var sawGrantFailed bool
	for _, c := range sim.Checks {
		if c.Gate == "grant" && c.Status == runtime.GateStatusFailed {
			sawGrantFailed = true
		}
	}
	if !sawGrantFailed {
		t.Fatalf("unexpected gate summary: %+v", sim.Checks)
	}
}

func TestGovernanceSimulateBadRequest(t *testing.T) {
	h := newGovAPIHarness(t)
	// Missing agent_id -> 400 invalid_request (message includes field names).
	rec := doGov(t, h.s, http.MethodPost, "/v1/governance/simulate", govAdminKey, "", "",
		`{"tool_name":"groundwork_search","action":"search","resource_ref":"doc:q3"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	got := govErrorOf(t, rec)
	if !strings.HasPrefix(got, "invalid request") || !strings.Contains(got, "agent_id") {
		t.Fatalf("error=%q", got)
	}

	// Malformed JSON -> 400.
	rec = doGov(t, h.s, http.MethodPost, "/v1/governance/simulate", govAdminKey, "", "", `{`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed body, got %d: %s", rec.Code, rec.Body.String())
	}
}
