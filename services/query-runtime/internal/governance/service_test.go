package governance

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"groundwork/query-runtime/internal/relationship"
	"groundwork/query-runtime/internal/runtime"
	"groundwork/query-runtime/internal/usage"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testTenant = "tenant-acme"
	testRegion = "us-east-1"
	ownerActor = "principal:alice"
	subjectPr  = "principal:bob"
	adminActor = "principal:root"
)

var testCtx = context.Background()

// ---------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------

type clockFunc struct{ t time.Time }

func (c *clockFunc) now() time.Time          { return c.t }
func (c *clockFunc) advance(d time.Duration) { c.t = c.t.Add(d) }

type fakeAgents struct {
	mu       sync.Mutex
	agents   map[string]runtime.Agent
	agent    runtime.Agent
	versions []runtime.AgentVersion
	err      error
}

func (f *fakeAgents) GetAgent(_ context.Context, _ string, agentID string) (runtime.Agent, []runtime.AgentVersion, []runtime.LifecycleEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return runtime.Agent{}, nil, nil, f.err
	}
	if f.agents != nil {
		if a, ok := f.agents[agentID]; ok {
			return a, f.versions, nil, nil
		}
	}
	return f.agent, f.versions, nil, nil
}

func (f *fakeAgents) setAgent(agent runtime.Agent, versions []runtime.AgentVersion) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.agents == nil {
		f.agents = map[string]runtime.Agent{}
	}
	f.agents[agent.ID] = agent
	if versions != nil {
		f.versions = versions
	}
}

func (f *fakeAgents) ListVersions(context.Context, string, string) ([]runtime.AgentVersion, error) {
	return f.versions, nil
}

type fakeAuthorizer struct {
	mu      sync.Mutex
	calls   []string // "user relation object"
	allowed func(user, relation, object string) (bool, error)
}

// Check implements relationship.Authorizer for tests: it encodes the
// typed request to the relationship wire format and records it exactly like
// the legacy checker, so assertions on recorded() keep working.
func (f *fakeAuthorizer) Check(_ context.Context, req relationship.CheckRequest) (bool, error) {
	user := relationship.EncodeSubject(req.Subject)
	relation := relationship.PermissionToRelation(req.Permission)
	object := relationship.EncodeObject(req.Resource)
	f.mu.Lock()
	f.calls = append(f.calls, user+" "+relation+" "+object)
	f.mu.Unlock()
	if f.allowed == nil {
		return true, nil
	}
	return f.allowed(user, relation, object)
}

func (f *fakeAuthorizer) Ready(context.Context) error { return nil }

func (f *fakeAuthorizer) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func newTestAuthority(now func() time.Time) *Authority {
	a := &Authority{
		issuer:   "test-issuer",
		audience: "test-audience",
		methods:  []string{"HS256"},
		now:      now,
		hsSecret: []byte("test-hs-secret-at-least-32-chars-1234567890"),
	}
	a.parser = jwt.NewParser(
		jwt.WithValidMethods(a.methods),
		jwt.WithIssuer(a.issuer),
		jwt.WithAudience(a.audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(2*time.Second),
		jwt.WithTimeFunc(now),
	)
	return a
}

// harness wires a MemoryStore + Authority + fakes into a Service with a
// single fixed clock shared by every component.
type harness struct {
	clock  *clockFunc
	store  *MemoryStore
	auth   *Authority
	agents *fakeAgents
	authorizer    *fakeAuthorizer
	svc    *Service
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	clock := &clockFunc{t: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}
	store := NewMemoryStore()
	store.SetClock(clock.now)
	auth := newTestAuthority(clock.now)
	agents := &fakeAgents{
		agent: runtime.Agent{
			ID:               "agent-1",
			TenantID:         testTenant,
			Name:             "finance-reviewer",
			OwnerPrincipalID: ownerActor,
			LifecycleState:   runtime.AgentStateActive,
			ActiveVersionID:  "version-1",
		},
		versions: []runtime.AgentVersion{{ID: "version-1", AgentID: "agent-1", Version: "1.0.0", Status: runtime.VersionStatusActive}},
	}
	authorizer := &fakeAuthorizer{}
	svc := NewService(store, auth, authorizer, agents)
	svc.SetClock(clock.now)
	return &harness{clock: clock, store: store, auth: auth, agents: agents, authorizer: authorizer, svc: svc}
}

// registerSearchTool registers the builtin groundwork_search:search
// (read-only) and activates it.
func (h *harness) registerSearchTool(t *testing.T) runtime.Tool {
	t.Helper()
	tool, err := h.svc.RegisterTool(testCtx, testTenant, adminActor, true, runtime.RegisterToolRequest{
		Name:             runtime.BuiltinSearchTool,
		Description:      "governed retrieval",
		Transport:        runtime.ToolTransportBuiltin,
		OwnerPrincipalID: ownerActor,
		Region:           testRegion,
	})
	if err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}
	if _, err := h.svc.RegisterToolAction(testCtx, testTenant, tool.ID, adminActor, true, runtime.RegisterToolActionRequest{
		Action:       runtime.BuiltinSearchAction,
		ResourceType: "document",
		RiskLevel:    runtime.RiskLevelLow,
		ReadOnly:     true,
	}); err != nil {
		t.Fatalf("RegisterToolAction: %v", err)
	}
	if _, err := h.svc.TransitionTool(testCtx, testTenant, tool.ID, adminActor, true, runtime.TransitionToolRequest{Lifecycle: runtime.ToolLifecycleActive}); err != nil {
		t.Fatalf("TransitionTool: %v", err)
	}
	return tool
}

// grantSearch ties the search action to the active agent version.
func (h *harness) grantSearch(t *testing.T, tool runtime.Tool) runtime.AgentToolGrant {
	t.Helper()
	_, actions, err := h.svc.GetTool(testCtx, testTenant, tool.ID)
	if err != nil || len(actions) != 1 {
		t.Fatalf("GetTool: %v (actions %d)", err, len(actions))
	}
	grant, err := h.svc.GrantToolAccess(testCtx, testTenant, adminActor, true, runtime.GrantToolRequest{
		AgentID:   "agent-1",
		VersionID: "version-1",
		ToolID:    tool.ID,
		ActionID:  actions[0].ID,
	})
	if err != nil {
		t.Fatalf("GrantToolAccess: %v", err)
	}
	return grant
}

func (h *harness) mint(t *testing.T, idem string, permitted []string) runtime.MintDelegationResponse {
	t.Helper()
	resp, err := h.svc.MintDelegation(testCtx, testTenant, testRegion, "agent-1", ownerActor, false, idem, runtime.MintDelegationRequest{
		SubjectPrincipalID: subjectPr,
		Purpose:            "quarterly review",
		PermittedActions:   permitted,
	})
	if err != nil {
		t.Fatalf("MintDelegation: %v", err)
	}
	return resp
}

func (h *harness) createRun(t *testing.T, token, idem string, actions ...runtime.RunActionRequest) runtime.CreateRunResponse {
	t.Helper()
	resp, err := h.svc.CreateRun(testCtx, testTenant, testRegion, idem, runtime.CreateRunRequest{
		DelegationToken: token,
		Actions:         actions,
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	return resp
}

func searchAction(ref string) runtime.RunActionRequest {
	return runtime.RunActionRequest{ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: ref}
}

// happyRun wires a fully-permitting world and returns the run response
// plus the delegation token.
func (h *harness) happyRun(t *testing.T) (runtime.CreateRunResponse, string) {
	t.Helper()
	h.grantSearch(t, h.registerSearchTool(t))
	minted := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	run := h.createRun(t, minted.Token, "run-1", searchAction("*"))
	return run, minted.Token
}

func expectDenied(t *testing.T, decision runtime.ActionDecision, reason string) {
	t.Helper()
	if decision.Decision != runtime.DecisionDenied {
		t.Fatalf("expected denied, got %q (%s)", decision.Decision, decision.Reason)
	}
	if reason != "" && decision.Reason != reason {
		t.Fatalf("expected reason %q, got %q", reason, decision.Reason)
	}
}

func expectAllowed(t *testing.T, decision runtime.ActionDecision) {
	t.Helper()
	if decision.Decision != runtime.DecisionAllowed {
		t.Fatalf("expected allowed, got %q (%s)", decision.Decision, decision.Reason)
	}
}

func expectFailClosed(t *testing.T, decision runtime.ActionDecision, reason string) {
	t.Helper()
	if decision.Decision != runtime.DecisionFailClosed {
		t.Fatalf("expected fail_closed, got %q (%s)", decision.Decision, decision.Reason)
	}
	if reason != "" && decision.Reason != reason {
		t.Fatalf("expected reason %q, got %q", reason, decision.Reason)
	}
}

// ---------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------

func TestAuthorityMintVerifyRoundtrip(t *testing.T) {
	clock := &clockFunc{t: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}
	a := newTestAuthority(clock.now)
	issued := clock.t
	expires := issued.Add(15 * time.Minute)
	token, err := a.Mint(testTenant, "agent-1", "version-1", ownerActor, subjectPr, "purpose", testRegion,
		[]string{"groundwork_search:search"}, "digest-1", "jti-1", issued, expires)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	claims, err := a.Verify(testCtx, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.TenantID != testTenant || claims.AgentID != "agent-1" || claims.AgentVersionID != "version-1" ||
		claims.DelegatorPrincipalID != ownerActor || claims.SubjectPrincipalID != subjectPr ||
		claims.Purpose != "purpose" || claims.Region != testRegion || claims.ID != "jti-1" ||
		claims.PermittedActionsDigest != "digest-1" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
}

func TestAuthorityVerifyTamperedTokenFails(t *testing.T) {
	clock := &clockFunc{t: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}
	a := newTestAuthority(clock.now)
	token, err := a.Mint(testTenant, "agent-1", "version-1", ownerActor, subjectPr, "purpose", testRegion,
		[]string{"groundwork_search:search"}, "digest-1", "jti-1", clock.t, clock.t.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// Flip one payload character without re-signing.
	tampered := token[:len(token)-6] + "XXXXXX"
	if _, err := a.Verify(testCtx, tampered); !errors.Is(err, runtime.ErrDelegationInvalid) {
		t.Fatalf("expected ErrDelegationInvalid, got %v", err)
	}
	if _, err := a.Verify(testCtx, ""); !errors.Is(err, runtime.ErrDelegationInvalid) {
		t.Fatalf("expected ErrDelegationInvalid for empty token, got %v", err)
	}
}

func TestAuthorityVerifyExpiredTokenFails(t *testing.T) {
	clock := &clockFunc{t: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}
	a := newTestAuthority(clock.now)
	token, err := a.Mint(testTenant, "agent-1", "version-1", ownerActor, subjectPr, "purpose", testRegion,
		[]string{"groundwork_search:search"}, "digest-1", "jti-1", clock.t, clock.t.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	clock.advance(16 * time.Minute)
	if _, err := a.Verify(testCtx, token); !errors.Is(err, runtime.ErrDelegationInvalid) {
		t.Fatalf("expected ErrDelegationInvalid after expiry, got %v", err)
	}
}

func TestAuthorityVerifyWrongIssuerFails(t *testing.T) {
	clock := &clockFunc{t: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}
	issuer := newTestAuthority(clock.now)
	token, err := issuer.Mint(testTenant, "agent-1", "version-1", ownerActor, subjectPr, "purpose", testRegion,
		[]string{"groundwork_search:search"}, "digest-1", "jti-1", clock.t, clock.t.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	other := newTestAuthority(clock.now)
	other.issuer = "other-issuer"
	other.parser = jwt.NewParser(jwt.WithValidMethods(other.methods), jwt.WithIssuer(other.issuer),
		jwt.WithAudience(other.audience), jwt.WithExpirationRequired(), jwt.WithLeeway(2*time.Second),
		jwt.WithTimeFunc(clock.now))
	if _, err := other.Verify(testCtx, token); !errors.Is(err, runtime.ErrDelegationInvalid) {
		t.Fatalf("expected ErrDelegationInvalid for wrong issuer, got %v", err)
	}
}

func TestAuthorityVerifyRejectsMissingBindings(t *testing.T) {
	clock := &clockFunc{t: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}
	a := newTestAuthority(clock.now)
	// Mint with an empty region: Verify must reject the missing binding
	// even though the signature is valid.
	token, err := a.Mint(testTenant, "agent-1", "version-1", ownerActor, subjectPr, "purpose", "",
		[]string{"groundwork_search:search"}, "digest-1", "jti-1", clock.t, clock.t.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := a.Verify(testCtx, token); !errors.Is(err, runtime.ErrDelegationInvalid) {
		t.Fatalf("expected ErrDelegationInvalid for missing binding, got %v", err)
	}
}

func TestAuthorityRotationVerifiesPreviousSecret(t *testing.T) {
	clock := &clockFunc{t: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}
	oldSecret := []byte("old-secret-at-least-32-characters-xxxxxxxxxxxx")
	old := &Authority{issuer: "test-issuer", audience: "test-audience", methods: []string{"HS256"},
		now: clock.now, hsSecret: oldSecret}
	old.parser = jwt.NewParser(jwt.WithValidMethods(old.methods), jwt.WithIssuer(old.issuer),
		jwt.WithAudience(old.audience), jwt.WithExpirationRequired(), jwt.WithLeeway(2*time.Second),
		jwt.WithTimeFunc(clock.now))
	token, err := old.Mint(testTenant, "agent-1", "version-1", ownerActor, subjectPr, "purpose", testRegion,
		[]string{"groundwork_search:search"}, "digest-1", "jti-1", clock.t, clock.t.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// Rotated authority: new current secret, old secret as previous.
	rotated := newTestAuthority(clock.now)
	rotated.hsSecret = []byte("new-secret-at-least-32-characters-xxxxxxxxxxxx")
	rotated.prevHSSecrets = [][]byte{oldSecret}
	if _, err := rotated.Verify(testCtx, token); err != nil {
		t.Fatalf("rotation verify: %v", err)
	}
	// Without the previous secret the same token must fail.
	noPrev := newTestAuthority(clock.now)
	noPrev.hsSecret = []byte("new-secret-at-least-32-characters-xxxxxxxxxxxx")
	if _, err := noPrev.Verify(testCtx, token); !errors.Is(err, runtime.ErrDelegationInvalid) {
		t.Fatalf("expected failure without previous key, got %v", err)
	}
}

func TestBuildAuthorityRejectsMissingKey(t *testing.T) {
	t.Setenv("GROUNDWORK_DELEGATION_RS_PRIVATE_KEY", "")
	t.Setenv("GROUNDWORK_DELEGATION_RS_PRIVATE_KEY_FILE", "")
	t.Setenv("GROUNDWORK_DELEGATION_HS_SECRET", "")
	if _, err := BuildAuthority(); err == nil {
		t.Fatal("expected error with no signing key configured")
	}
}

func TestBuildAuthorityRejectsShortSecret(t *testing.T) {
	t.Setenv("GROUNDWORK_DELEGATION_RS_PRIVATE_KEY", "")
	t.Setenv("GROUNDWORK_DELEGATION_RS_PRIVATE_KEY_FILE", "")
	t.Setenv("GROUNDWORK_DELEGATION_HS_SECRET", "short")
	if _, err := BuildAuthority(); err == nil {
		t.Fatal("expected error with short HS secret")
	}
}

// ---------------------------------------------------------------------
// Delegation minting
// ---------------------------------------------------------------------

func TestMintDelegationRequiresAgentsReader(t *testing.T) {
	h := newHarness(t)
	svc := NewService(h.store, h.auth, h.authorizer, nil)
	_, err := svc.MintDelegation(testCtx, testTenant, testRegion, "agent-1", ownerActor, false, "mint-1",
		runtime.MintDelegationRequest{SubjectPrincipalID: subjectPr, Purpose: "p", PermittedActions: []string{"groundwork_search:search"}})
	if !errors.Is(err, runtime.ErrGovernanceUnavailable) {
		t.Fatalf("expected ErrGovernanceUnavailable, got %v", err)
	}
}

func TestMintDelegationRequiresRequestFields(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.MintDelegation(testCtx, testTenant, testRegion, "agent-1", ownerActor, false, "mint-1",
		runtime.MintDelegationRequest{}); !errors.Is(err, runtime.ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for empty request, got %v", err)
	}
	if _, err := h.svc.MintDelegation(testCtx, testTenant, testRegion, "agent-1", ownerActor, false, "mint-1",
		runtime.MintDelegationRequest{SubjectPrincipalID: subjectPr, Purpose: "p"}); !errors.Is(err, runtime.ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest without permitted actions, got %v", err)
	}
}

func TestMintDelegationRequiresOwnerOrAdmin(t *testing.T) {
	h := newHarness(t)
	h.registerSearchTool(t)
	_, err := h.svc.MintDelegation(testCtx, testTenant, testRegion, "agent-1", "principal:mallory", false, "mint-1",
		runtime.MintDelegationRequest{SubjectPrincipalID: subjectPr, Purpose: "p", PermittedActions: []string{"groundwork_search:search"}})
	if !errors.Is(err, runtime.ErrGovernanceNotAuthorized) {
		t.Fatalf("expected ErrGovernanceNotAuthorized, got %v", err)
	}
	// Admin (no ownership) is allowed.
	if _, err := h.svc.MintDelegation(testCtx, testTenant, testRegion, "agent-1", adminActor, true, "mint-2",
		runtime.MintDelegationRequest{SubjectPrincipalID: subjectPr, Purpose: "p", PermittedActions: []string{"groundwork_search:search"}}); err != nil {
		t.Fatalf("admin mint failed: %v", err)
	}
}

func TestMintDelegationRejectsInactiveAgent(t *testing.T) {
	h := newHarness(t)
	h.registerSearchTool(t)
	h.agents.agent.LifecycleState = runtime.AgentStateSuspended
	_, err := h.svc.MintDelegation(testCtx, testTenant, testRegion, "agent-1", ownerActor, false, "mint-1",
		runtime.MintDelegationRequest{SubjectPrincipalID: subjectPr, Purpose: "p", PermittedActions: []string{"groundwork_search:search"}})
	if !errors.Is(err, runtime.ErrDelegationInactive) {
		t.Fatalf("expected ErrDelegationInactive, got %v", err)
	}
}

func TestMintDelegationRejectsUnknownToolAction(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.MintDelegation(testCtx, testTenant, testRegion, "agent-1", ownerActor, false, "mint-1",
		runtime.MintDelegationRequest{SubjectPrincipalID: subjectPr, Purpose: "p", PermittedActions: []string{"groundwork_search:search"}})
	if !errors.Is(err, runtime.ErrDelegationNotAllowed) {
		t.Fatalf("expected ErrDelegationNotAllowed, got %v", err)
	}
}

func TestMintDelegationHappyPathAndSingleDelivery(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)

	resp := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	if resp.Token == "" || resp.TokenAlreadyIssued {
		t.Fatalf("expected a fresh token, got %+v", resp)
	}
	grant := resp.Grant
	if grant.AgentVersionID != "version-1" || grant.DelegatorPrincipalID != ownerActor ||
		grant.SubjectPrincipalID != subjectPr || grant.Region != testRegion {
		t.Fatalf("grant bindings mismatch: %+v", grant)
	}
	if got := grant.ExpiresAt.Sub(grant.IssuedAt); got != runtime.DefaultDelegationTTL {
		t.Fatalf("expected TTL %v, got %v", runtime.DefaultDelegationTTL, got)
	}
	expected := ComputePermittedActionsDigest([]string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	if grant.PermittedActionsDigest != expected {
		t.Fatalf("digest mismatch: %q != %q", grant.PermittedActionsDigest, expected)
	}
	// The store holds the jti, never the raw token. The permitted
	// actions LIST is persisted (Phase 6) so every child delegation can
	// be verified as a subset of its parent's scope at mint time; the
	// digest remains the authoritative check.
	stored, err := h.store.GetDelegationGrantByIdempotencyKey(testCtx, testTenant, "mint-1")
	if err != nil {
		t.Fatalf("GetDelegationGrantByIdempotencyKey: %v", err)
	}
	if len(stored.PermittedActions) != 1 || stored.PermittedActions[0] != runtime.BuiltinSearchTool+":"+runtime.BuiltinSearchAction {
		t.Fatalf("stored permitted actions mismatch: %v", stored.PermittedActions)
	}
	// Idempotent replay: same key, no new token.
	replay, err := h.svc.MintDelegation(testCtx, testTenant, testRegion, "agent-1", ownerActor, false, "mint-1",
		runtime.MintDelegationRequest{SubjectPrincipalID: subjectPr, Purpose: "quarterly review", PermittedActions: []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction}})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !replay.TokenAlreadyIssued || replay.Token != "" || replay.Grant.ID != grant.ID {
		t.Fatalf("replay must return the existing grant without a token: %+v", replay)
	}
}

func TestMintDelegationTTLCapped(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)
	resp, err := h.svc.MintDelegation(testCtx, testTenant, testRegion, "agent-1", ownerActor, false, "mint-1",
		runtime.MintDelegationRequest{
			SubjectPrincipalID: subjectPr,
			Purpose:            "p",
			PermittedActions:   []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction},
			TTLSeconds:         3600,
		})
	if err != nil {
		t.Fatalf("MintDelegation: %v", err)
	}
	if got := resp.Grant.ExpiresAt.Sub(resp.Grant.IssuedAt); got != runtime.MaxDelegationTTL {
		t.Fatalf("expected TTL capped at %v, got %v", runtime.MaxDelegationTTL, got)
	}
}

// ---------------------------------------------------------------------
// Run creation
// ---------------------------------------------------------------------

func TestCreateRunRejectsInvalidToken(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.CreateRun(testCtx, testTenant, testRegion, "run-1", runtime.CreateRunRequest{DelegationToken: "garbage"}); !errors.Is(err, runtime.ErrDelegationInvalid) {
		t.Fatalf("expected ErrDelegationInvalid, got %v", err)
	}
}

func TestCreateRunRejectsWrongTenantAndRegion(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)
	minted := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	if _, err := h.svc.CreateRun(testCtx, "tenant-other", testRegion, "run-1",
		runtime.CreateRunRequest{DelegationToken: minted.Token}); !errors.Is(err, runtime.ErrDelegationInvalid) {
		t.Fatalf("expected ErrDelegationInvalid for wrong tenant, got %v", err)
	}
	if _, err := h.svc.CreateRun(testCtx, testTenant, "eu-west-1", "run-1",
		runtime.CreateRunRequest{DelegationToken: minted.Token}); !errors.Is(err, runtime.ErrDelegationRegion) {
		t.Fatalf("expected ErrDelegationRegion for wrong region, got %v", err)
	}
}

func TestCreateRunHappyPath(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)
	minted := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})

	run := h.createRun(t, minted.Token, "run-1", searchAction("*"))
	if run.Run.Status != runtime.RunStatusRunning {
		t.Fatalf("expected running, got %q", run.Run.Status)
	}
	if run.Run.UserID != subjectPr || run.Run.AgentID != "agent-1" || run.Run.Region != testRegion {
		t.Fatalf("run bindings mismatch: %+v", run.Run)
	}
	if len(run.Decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(run.Decisions))
	}
	expectAllowed(t, run.Decisions[0])
	// The grant is now bound to exactly this run.
	stored, err := h.store.GetDelegationGrantByIdempotencyKey(testCtx, testTenant, "mint-1")
	if err != nil {
		t.Fatalf("store lookup: %v", err)
	}
	if stored.RunID != run.Run.ID || stored.UsedAt.IsZero() {
		t.Fatalf("grant not bound: %+v", stored)
	}
	// Idempotent replay: same idempotency key returns the same run.
	replay, err := h.svc.CreateRun(testCtx, testTenant, testRegion, "run-1",
		runtime.CreateRunRequest{DelegationToken: minted.Token, Actions: []runtime.RunActionRequest{searchAction("*")}})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replay.Run.ID != run.Run.ID {
		t.Fatalf("replay returned a different run: %s != %s", replay.Run.ID, run.Run.ID)
	}
}

func TestCreateRunRejectsReuse(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)
	minted := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	h.createRun(t, minted.Token, "run-1", searchAction("*"))
	// A second run with a different idempotency key must fail: the
	// delegation is single-run.
	if _, err := h.svc.CreateRun(testCtx, testTenant, testRegion, "run-2",
		runtime.CreateRunRequest{DelegationToken: minted.Token, Actions: []runtime.RunActionRequest{searchAction("*")}}); !errors.Is(err, runtime.ErrDelegationReused) {
		t.Fatalf("expected ErrDelegationReused, got %v", err)
	}
}

func TestCreateRunRejectsExpiredDelegation(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)
	minted := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	// Advance just past the grant expiry but within the verify leeway so
	// the token still parses and the grant-level expiry check fires.
	h.clock.advance(15*time.Minute + time.Second)
	if _, err := h.svc.CreateRun(testCtx, testTenant, testRegion, "run-1",
		runtime.CreateRunRequest{DelegationToken: minted.Token}); !errors.Is(err, runtime.ErrDelegationExpired) {
		t.Fatalf("expected ErrDelegationExpired, got %v", err)
	}
}

func TestCreateRunRejectsRevokedDelegation(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)
	minted := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	stored, err := h.store.GetDelegationGrantByIdempotencyKey(testCtx, testTenant, "mint-1")
	if err != nil {
		t.Fatalf("store lookup: %v", err)
	}
	if err := h.store.RevokeGrantByJTI(testCtx, testTenant, stored.TokenJTI); err != nil {
		t.Fatalf("RevokeGrantByJTI: %v", err)
	}
	if _, err := h.svc.CreateRun(testCtx, testTenant, testRegion, "run-1",
		runtime.CreateRunRequest{DelegationToken: minted.Token}); !errors.Is(err, runtime.ErrDelegationRevoked) {
		t.Fatalf("expected ErrDelegationRevoked, got %v", err)
	}
}

func TestCreateRunRejectsTamperedPermittedDigest(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)
	minted := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	// Tamper with the stored digest: the signed claims no longer match.
	stored, err := h.store.GetDelegationGrantByIdempotencyKey(testCtx, testTenant, "mint-1")
	if err != nil {
		t.Fatalf("store lookup: %v", err)
	}
	tampered := stored
	tampered.PermittedActionsDigest = "deadbeef"
	h.store.delegations[testTenant][stored.TokenJTI] = tampered
	if _, err := h.svc.CreateRun(testCtx, testTenant, testRegion, "run-1",
		runtime.CreateRunRequest{DelegationToken: minted.Token}); !errors.Is(err, runtime.ErrDelegationInvalid) {
		t.Fatalf("expected ErrDelegationInvalid, got %v", err)
	}
}

func TestCreateRunEmptyActionsStaysPending(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)
	minted := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	run := h.createRun(t, minted.Token, "run-1")
	if run.Run.Status != runtime.RunStatusPending {
		t.Fatalf("expected pending, got %q", run.Run.Status)
	}
}

func TestCreateRunAllDeniedLandsInDenied(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	h.grantSearch(t, tool)
	minted := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	// The action is granted but the relationship check denies it.
	h.authorizer.allowed = func(string, string, string) (bool, error) { return false, nil }
	run := h.createRun(t, minted.Token, "run-1", searchAction("*"))
	if run.Run.Status != runtime.RunStatusDenied {
		t.Fatalf("expected denied run, got %q", run.Run.Status)
	}
	if run.Run.ErrorCode != "all_actions_denied" {
		t.Fatalf("expected all_actions_denied, got %q", run.Run.ErrorCode)
	}
	expectDenied(t, run.Decisions[0], "relationship permission denied")
}

// ---------------------------------------------------------------------
// The evaluator invariant (EvaluateAction)
// ---------------------------------------------------------------------

func TestEvaluateActionHappyPathAndEvidence(t *testing.T) {
	h := newHarness(t)
	run, token := h.happyRun(t)
	resp, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token,
		RunID:           run.Run.ID,
		ToolName:        runtime.BuiltinSearchTool,
		Action:          runtime.BuiltinSearchAction,
		ResourceRef:     "*",
	})
	if err != nil {
		t.Fatalf("EvaluateAction: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed, got %+v", resp.Decision)
	}
	// Evidence is appended to the chain.
	decisions, err := h.store.ListDecisions(testCtx, testTenant, run.Run.ID)
	if err != nil {
		t.Fatalf("ListDecisions: %v", err)
	}
	if len(decisions) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(decisions))
	}
	if problems := VerifyDecisionChain(decisions); len(problems) > 0 {
		t.Fatalf("decision chain invalid: %+v", problems)
	}
	if decisions[1].PolicyVersion == "" || decisions[1].ImmutableDigest == "" {
		t.Fatalf("evidence incomplete: %+v", decisions[1])
	}
}

func TestEvaluateActionAgentNotActive(t *testing.T) {
	h := newHarness(t)
	run, token := h.happyRun(t)
	h.agents.agent.LifecycleState = runtime.AgentStateSuspended
	resp, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	})
	if err != nil {
		t.Fatalf("EvaluateAction: %v", err)
	}
	expectDenied(t, resp.Decision, "agent not active")
}

func TestEvaluateActionVersionNotActive(t *testing.T) {
	h := newHarness(t)
	run, token := h.happyRun(t)
	h.agents.versions[0].Status = runtime.VersionStatusSuperseded
	resp, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	})
	if err != nil {
		t.Fatalf("EvaluateAction: %v", err)
	}
	expectDenied(t, resp.Decision, "agent version not active")
}

func TestEvaluateActionAgentRegistryUnavailableFailsClosed(t *testing.T) {
	h := newHarness(t)
	run, token := h.happyRun(t)
	h.svc.agents = nil
	resp, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	})
	if err != nil {
		t.Fatalf("EvaluateAction: %v", err)
	}
	expectFailClosed(t, resp.Decision, "agent registry unavailable")
}

func TestEvaluateActionNotPermittedByDelegation(t *testing.T) {
	h := newHarness(t)
	run, token := h.happyRun(t)
	resp, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: "delete_everything", ResourceRef: "*",
	})
	if err != nil {
		t.Fatalf("EvaluateAction: %v", err)
	}
	expectDenied(t, resp.Decision, "action not permitted by delegation")
}

func TestEvaluateActionToolNotActive(t *testing.T) {
	h := newHarness(t)
	run, token := h.happyRun(t)
	if _, err := h.svc.TransitionTool(testCtx, testTenant, h.toolOf(t), adminActor, true,
		runtime.TransitionToolRequest{Lifecycle: runtime.ToolLifecycleSuspended}); err != nil {
		t.Fatalf("TransitionTool: %v", err)
	}
	resp, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	})
	if err != nil {
		t.Fatalf("EvaluateAction: %v", err)
	}
	expectDenied(t, resp.Decision, "tool not active")
}

func (h *harness) toolOf(t *testing.T) string {
	t.Helper()
	tools, err := h.svc.ListTools(testCtx, testTenant)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, tool := range tools {
		if tool.Name == runtime.BuiltinSearchTool {
			return tool.ID
		}
	}
	t.Fatal("groundwork_search not found")
	return ""
}

func TestEvaluateActionNoGrantForTuple(t *testing.T) {
	h := newHarness(t)
	h.registerSearchTool(t)
	// Permitted in the delegation but NO grant exists.
	minted := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	run := h.createRun(t, minted.Token, "run-1", searchAction("*"))
	expectDenied(t, run.Decisions[0], "no active grant for tool action")
	if run.Run.Status != runtime.RunStatusDenied {
		t.Fatalf("expected denied run, got %q", run.Run.Status)
	}
}

func TestEvaluateActionResourceScopePrefixMatch(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	_, actions, err := h.svc.GetTool(testCtx, testTenant, tool.ID)
	if err != nil {
		t.Fatalf("GetTool: %v", err)
	}
	if _, err := h.svc.GrantToolAccess(testCtx, testTenant, adminActor, true, runtime.GrantToolRequest{
		AgentID: "agent-1", VersionID: "version-1", ToolID: tool.ID, ActionID: actions[0].ID,
		ResourceScope: "docs/acme",
	}); err != nil {
		t.Fatalf("GrantToolAccess: %v", err)
	}
	minted := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	// Both references evaluated in ONE run: outside the scope is denied,
	// inside the scope (prefix match) is allowed.
	run := h.createRun(t, minted.Token, "run-1", searchAction("docs/other/file"), searchAction("docs/acme/report"))
	expectDenied(t, run.Decisions[0], "no active grant for tool action")
	expectAllowed(t, run.Decisions[1])
}

func TestEvaluateActionRegionConstraint(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	_, actions, err := h.svc.GetTool(testCtx, testTenant, tool.ID)
	if err != nil {
		t.Fatalf("GetTool: %v", err)
	}
	if _, err := h.svc.GrantToolAccess(testCtx, testTenant, adminActor, true, runtime.GrantToolRequest{
		AgentID: "agent-1", VersionID: "version-1", ToolID: tool.ID, ActionID: actions[0].ID,
		RegionConstraint: "eu-west-1",
	}); err != nil {
		t.Fatalf("GrantToolAccess: %v", err)
	}
	minted := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	run := h.createRun(t, minted.Token, "run-1", searchAction("*"))
	expectDenied(t, run.Decisions[0], "no active grant for tool action")
}

func TestEvaluateActionCallLimitPerRun(t *testing.T) {
	h := newHarness(t)
	tool := h.registerSearchTool(t)
	_, actions, err := h.svc.GetTool(testCtx, testTenant, tool.ID)
	if err != nil {
		t.Fatalf("GetTool: %v", err)
	}
	if _, err := h.svc.GrantToolAccess(testCtx, testTenant, adminActor, true, runtime.GrantToolRequest{
		AgentID: "agent-1", VersionID: "version-1", ToolID: tool.ID, ActionID: actions[0].ID,
		CallLimitPerRun: 1,
	}); err != nil {
		t.Fatalf("GrantToolAccess: %v", err)
	}
	minted := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	run := h.createRun(t, minted.Token, "run-1", searchAction("*"))
	expectAllowed(t, run.Decisions[0])
	// Second evaluation of the same action in the same run: limit hit.
	resp, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: minted.Token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	})
	if err != nil {
		t.Fatalf("EvaluateAction: %v", err)
	}
	expectDenied(t, resp.Decision, "per-run call limit exceeded")
}

func TestEvaluateActionDenied(t *testing.T) {
	h := newHarness(t)
	run, token := h.happyRun(t)
	h.authorizer.allowed = func(string, string, string) (bool, error) { return false, nil }
	resp, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	})
	if err != nil {
		t.Fatalf("EvaluateAction: %v", err)
	}
	expectDenied(t, resp.Decision, "relationship permission denied")
}

func TestEvaluateActionBackendUnavailableFailsClosed(t *testing.T) {
	h := newHarness(t)
	run, token := h.happyRun(t)
	h.svc.authorizer = nil
	resp, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	})
	if err != nil {
		t.Fatalf("EvaluateAction: %v", err)
	}
	expectFailClosed(t, resp.Decision, "permission backend unavailable")
}

// TestEvaluateActionContract verifies the exact relationship subject
// and object shapes: read-only actions check "use" on tool:<id>, write
// actions check "execute" on tool_action:<id>:<action>, and the subject
// is ALWAYS the verified delegated principal.
func TestEvaluateActionContract(t *testing.T) {
	h := newHarness(t)
	// Read-only builtin search.
	searchTool := h.registerSearchTool(t)

	h.grantSearch(t, searchTool)
	minted := h.mint(t, "mint-1", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	run := h.createRun(t, minted.Token, "run-1", searchAction("*"))
	expectAllowed(t, run.Decisions[0])

	// Write action on a second tool.
	ciTool, err := h.svc.RegisterTool(testCtx, testTenant, adminActor, true, runtime.RegisterToolRequest{
		Name: "ci", Transport: runtime.ToolTransportHTTP, EndpointOrServer: "https://ci.example.com",
		OwnerPrincipalID: ownerActor, Region: testRegion,
	})
	if err != nil {
		t.Fatalf("RegisterTool ci: %v", err)
	}
	deployAction, err := h.svc.RegisterToolAction(testCtx, testTenant, ciTool.ID, adminActor, true,
		runtime.RegisterToolActionRequest{Action: "deploy", RiskLevel: runtime.RiskLevelHigh, ReadOnly: false})
	if err != nil {
		t.Fatalf("RegisterToolAction deploy: %v", err)
	}
	if _, err := h.svc.TransitionTool(testCtx, testTenant, ciTool.ID, adminActor, true,
		runtime.TransitionToolRequest{Lifecycle: runtime.ToolLifecycleActive}); err != nil {
		t.Fatalf("TransitionTool ci: %v", err)
	}
	if _, err := h.svc.GrantToolAccess(testCtx, testTenant, adminActor, true, runtime.GrantToolRequest{
		AgentID: "agent-1", VersionID: "version-1", ToolID: ciTool.ID, ActionID: deployAction.ID,
	}); err != nil {
		t.Fatalf("GrantToolAccess ci: %v", err)
	}
	minted2 := h.mint(t, "mint-2", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction, "ci:deploy"})
	run2 := h.createRun(t, minted2.Token, "run-2", runtime.RunActionRequest{ToolName: "ci", Action: "deploy", ResourceRef: "*"})
	expectAllowed(t, run2.Decisions[0])

	calls := h.authorizer.recorded()
	var sawUse, sawExecute bool
	for _, call := range calls {
		parts := strings.Split(call, " ")
		if len(parts) != 3 {
			t.Fatalf("malformed recorded call %q", call)
		}
		user, relation, object := parts[0], parts[1], parts[2]
		// The subject is ALWAYS the verified delegated principal.
		if user != "user:"+subjectPr {
			t.Fatalf("subject must be the verified principal, got %q", user)
		}
		if strings.Contains(user, ownerActor) {
			t.Fatalf("subject must never be the delegator/owner: %q", user)
		}
		switch relation {
		case "use":
			if object != "tool:"+searchTool.ID {
				t.Fatalf("use must target tool:<id>, got %q", object)
			}
			sawUse = true
		case "execute":
			if object != "tool_action:"+ciTool.ID+":deploy" {
				t.Fatalf("execute must target tool_action:<id>:<action>, got %q", object)
			}
			sawExecute = true
		default:
			t.Fatalf("unexpected relation %q", relation)
		}
	}
	if !sawUse || !sawExecute {
		t.Fatalf("expected both use and execute checks, got %v", calls)
	}
}

func TestEvaluateActionRunTerminal(t *testing.T) {
	h := newHarness(t)
	run, token := h.happyRun(t)
	stored := h.store.runs[testTenant][run.Run.ID]
	stored.Status = runtime.RunStatusCompleted
	h.store.runs[testTenant][run.Run.ID] = stored
	resp, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	})
	if err != nil {
		t.Fatalf("EvaluateAction: %v", err)
	}
	expectDenied(t, resp.Decision, "run is terminal")
}

func TestEvaluateActionRegionMismatch(t *testing.T) {
	h := newHarness(t)
	run, token := h.happyRun(t)
	if _, err := h.svc.EvaluateAction(testCtx, testTenant, "eu-west-1", runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	}); !errors.Is(err, runtime.ErrDelegationRegion) {
		t.Fatalf("expected ErrDelegationRegion, got %v", err)
	}
}

// ---------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------

func (h *harness) approvalRun(t *testing.T, mintKey, runKey string) (runtime.CreateRunResponse, string) {
	t.Helper()
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
	minted := h.mint(t, mintKey, []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	run := h.createRun(t, minted.Token, runKey, searchAction("*"))
	return run, minted.Token
}

func TestApprovalLifecycle(t *testing.T) {
	h := newHarness(t)
	run, token := h.approvalRun(t, "mint-1", "run-1")
	if run.Decisions[0].Decision != runtime.DecisionApprovalRequired {
		t.Fatalf("expected approval_required, got %q (%s)", run.Decisions[0].Decision, run.Decisions[0].Reason)
	}
	// Approve once.
	approved, err := h.svc.ApproveAction(testCtx, testTenant, run.Run.ID, run.Decisions[0].ActionID, ownerActor, "appr-1",
		runtime.ApproveActionRequest{ResourceRef: "*"})
	if err != nil {
		t.Fatalf("ApproveAction: %v", err)
	}
	if approved.Denied || approved.Approval.Decision != runtime.ApprovalApproved {
		t.Fatalf("unexpected approval: %+v", approved)
	}
	// The pending decision is now allowed and the approval consumed.
	resp, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	})
	if err != nil {
		t.Fatalf("EvaluateAction: %v", err)
	}
	expectAllowed(t, resp.Decision)
	approvals, err := h.store.ListApprovals(testCtx, testTenant, run.Run.ID)
	if err != nil || len(approvals) != 1 {
		t.Fatalf("approvals: %v (%d)", err, len(approvals))
	}
	if approvals[0].ConsumedAt.IsZero() {
		t.Fatalf("approval not consumed: %+v", approvals[0])
	}
	// Consumption is one-time: without a fresh approval the action is
	// approval_required again.
	resp2, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	})
	if err != nil {
		t.Fatalf("EvaluateAction: %v", err)
	}
	if resp2.Decision.Decision != runtime.DecisionApprovalRequired {
		t.Fatalf("expected approval_required after consume, got %q", resp2.Decision.Decision)
	}
}

func TestApprovalIdempotentReplay(t *testing.T) {
	h := newHarness(t)
	run, _ := h.approvalRun(t, "mint-1", "run-1")
	first, err := h.svc.ApproveAction(testCtx, testTenant, run.Run.ID, run.Decisions[0].ActionID, ownerActor, "appr-1",
		runtime.ApproveActionRequest{ResourceRef: "*"})
	if err != nil {
		t.Fatalf("ApproveAction: %v", err)
	}
	replay, err := h.svc.ApproveAction(testCtx, testTenant, run.Run.ID, run.Decisions[0].ActionID, ownerActor, "appr-1",
		runtime.ApproveActionRequest{ResourceRef: "*"})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replay.Approval.ID != first.Approval.ID {
		t.Fatalf("replay returned a different approval: %s != %s", replay.Approval.ID, first.Approval.ID)
	}
}

func TestApprovalDenyBlocksAction(t *testing.T) {
	h := newHarness(t)
	run, token := h.approvalRun(t, "mint-1", "run-1")
	if _, err := h.svc.DenyAction(testCtx, testTenant, run.Run.ID, run.Decisions[0].ActionID, ownerActor, "deny-1",
		runtime.ApproveActionRequest{ResourceRef: "*"}); err != nil {
		t.Fatalf("DenyAction: %v", err)
	}
	resp, err := h.svc.EvaluateAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	})
	if err != nil {
		t.Fatalf("EvaluateAction: %v", err)
	}
	expectDenied(t, resp.Decision, "human approval denied")
}

// TestApprovalExpiryIgnoresStaleApproval verifies at the store level
// that an unconsumed approval is only consumable within its TTL: an
// expired approval must never satisfy the evaluator's step 7, because
// otherwise stale approvals could be replayed after long delays.
func TestApprovalExpiryIgnoresStaleApproval(t *testing.T) {
	h := newHarness(t)
	approval, err := h.store.AppendApproval(testCtx, runtime.ActionApproval{
		TenantID: testTenant, RunID: "run-1", ToolID: "tool-1", ActionID: "action-1",
		ResourceRef: "*", ApprovingPrincipalID: ownerActor, Decision: runtime.ApprovalApproved,
		ExpiresAt: h.clock.t.Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("AppendApproval: %v", err)
	}
	if _, err := h.store.GetApprovalForConsume(testCtx, testTenant, "run-1", "tool-1", "action-1", "*"); err != nil {
		t.Fatalf("fresh approval should be consumable: %v", err)
	}
	h.clock.advance(15*time.Minute + time.Second)
	if _, err := h.store.GetApprovalForConsume(testCtx, testTenant, "run-1", "tool-1", "action-1", "*"); !errors.Is(err, runtime.ErrApprovalNotFound) {
		t.Fatalf("expected ErrApprovalNotFound for expired approval, got %v", err)
	}
	// The stale approval must still verify as untampered evidence.
	approvals, err := h.store.ListApprovals(testCtx, testTenant, "run-1")
	if err != nil {
		t.Fatalf("ListApprovals: %v", err)
	}
	approvals[0].ID = approval.ID
	if err := VerifyApprovalChain(approvals); err != nil {
		t.Fatalf("approval chain: %v", err)
	}
}

func TestApprovalRejectedOnTerminalRun(t *testing.T) {
	h := newHarness(t)
	run, _ := h.approvalRun(t, "mint-1", "run-1")
	stored := h.store.runs[testTenant][run.Run.ID]
	stored.Status = runtime.RunStatusCompleted
	h.store.runs[testTenant][run.Run.ID] = stored
	if _, err := h.svc.ApproveAction(testCtx, testTenant, run.Run.ID, run.Decisions[0].ActionID, ownerActor, "appr-1",
		runtime.ApproveActionRequest{ResourceRef: "*"}); !errors.Is(err, runtime.ErrRunNotActive) {
		t.Fatalf("expected ErrRunNotActive, got %v", err)
	}
}

// ---------------------------------------------------------------------
// Delegated query gate
// ---------------------------------------------------------------------

func TestEvaluateDelegatedQueryHappyPath(t *testing.T) {
	h := newHarness(t)
	run, token := h.happyRun(t)
	result, err := h.svc.EvaluateDelegatedQuery(testCtx, testTenant, testRegion, token, run.Run.ID, "what changed?")
	if err != nil {
		t.Fatalf("EvaluateDelegatedQuery: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed, got %+v", result.Decision)
	}
	// The engine must run the query as the VERIFIED subject.
	if result.UserID != subjectPr {
		t.Fatalf("expected subject %s, got %s", subjectPr, result.UserID)
	}
}

func TestEvaluateDelegatedQueryDeniedWithoutPermission(t *testing.T) {
	h := newHarness(t)
	run, token := h.happyRun(t)
	h.authorizer.allowed = func(string, string, string) (bool, error) { return false, nil }
	result, err := h.svc.EvaluateDelegatedQuery(testCtx, testTenant, testRegion, token, run.Run.ID, "what changed?")
	if err != nil {
		t.Fatalf("EvaluateDelegatedQuery: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected denied")
	}
	expectDenied(t, result.Decision, "relationship permission denied")
}

// ---------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------

func TestDispatchActionBuiltinDispatched(t *testing.T) {
	h := newHarness(t)
	run, token := h.happyRun(t)
	resp, err := h.svc.DispatchAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: token, RunID: run.Run.ID,
		ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*",
	})
	if err != nil {
		t.Fatalf("DispatchAction: %v", err)
	}
	if !resp.Allowed || resp.DispatchMode != "dispatched" {
		t.Fatalf("expected dispatched, got %+v", resp)
	}
}

func TestDispatchActionExternalTransportDeferred(t *testing.T) {
	h := newHarness(t)
	httpTool, err := h.svc.RegisterTool(testCtx, testTenant, adminActor, true, runtime.RegisterToolRequest{
		Name: "webhook", Transport: runtime.ToolTransportHTTP, EndpointOrServer: "https://hooks.example.com",
		OwnerPrincipalID: ownerActor, Region: testRegion,
	})
	if err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}
	action, err := h.svc.RegisterToolAction(testCtx, testTenant, httpTool.ID, adminActor, true,
		runtime.RegisterToolActionRequest{Action: "send", ReadOnly: true})
	if err != nil {
		t.Fatalf("RegisterToolAction: %v", err)
	}
	if _, err := h.svc.TransitionTool(testCtx, testTenant, httpTool.ID, adminActor, true,
		runtime.TransitionToolRequest{Lifecycle: runtime.ToolLifecycleActive}); err != nil {
		t.Fatalf("TransitionTool: %v", err)
	}
	if _, err := h.svc.GrantToolAccess(testCtx, testTenant, adminActor, true, runtime.GrantToolRequest{
		AgentID: "agent-1", VersionID: "version-1", ToolID: httpTool.ID, ActionID: action.ID,
	}); err != nil {
		t.Fatalf("GrantToolAccess: %v", err)
	}
	minted := h.mint(t, "mint-1", []string{"webhook:send"})
	run := h.createRun(t, minted.Token, "run-1", runtime.RunActionRequest{ToolName: "webhook", Action: "send", ResourceRef: "*"})
	expectAllowed(t, run.Decisions[0])
	resp, err := h.svc.DispatchAction(testCtx, testTenant, testRegion, runtime.EvaluateActionRequest{
		DelegationToken: minted.Token, RunID: run.Run.ID,
		ToolName: "webhook", Action: "send", ResourceRef: "*",
	})
	if err != nil {
		t.Fatalf("DispatchAction: %v", err)
	}
	if !resp.Allowed || resp.DispatchMode != "connector_failed" {
		t.Fatalf("expected connector_failed (nil dispatcher fails closed), got %+v", resp)
	}
	if resp.Invocation == nil {
		t.Fatalf("expected fail-closed invocation evidence, got none")
	}
	if resp.Invocation.ErrorCode != "connector_dispatcher_unavailable" {
		t.Fatalf("expected connector_dispatcher_unavailable error code, got %q", resp.Invocation.ErrorCode)
	}
}

// quotaMeter is a controllable UsageMeter: deny makes every Record
// return a quota error for the given metric.
type quotaMeter struct {
	deny   bool
	calls  int
	denied bool
}

func (m *quotaMeter) Record(_ context.Context, _, metric string, _ int64) error {
	m.calls++
	if m.deny {
		m.denied = true
		return &usage.QuotaError{Metric: metric}
	}
	return nil
}

// recordingDispatcher counts gateway invocations to prove the quota
// gate closes before any outbound call.
type recordingDispatcher struct {
	calls int
}

func (d *recordingDispatcher) Dispatch(_ context.Context, _ runtime.ConnectorDispatchRequest) (runtime.ConnectorDispatchResult, error) {
	d.calls++
	return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationSuccess, StatusCode: 200, ResponseBytes: 128, ConnectorID: "conn-webhook"}, nil
}

func TestDispatchActionConnectorQuotaFailClosed(t *testing.T) {
	h := newHarness(t)
	httpTool, err := h.svc.RegisterTool(testCtx, testTenant, adminActor, true, runtime.RegisterToolRequest{
		Name: "webhook", Transport: runtime.ToolTransportHTTP, EndpointOrServer: "https://hooks.example.com",
		OwnerPrincipalID: ownerActor, Region: testRegion,
	})
	if err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}
	action, err := h.svc.RegisterToolAction(testCtx, testTenant, httpTool.ID, adminActor, true,
		runtime.RegisterToolActionRequest{Action: "send", ReadOnly: true})
	if err != nil {
		t.Fatalf("RegisterToolAction: %v", err)
	}
	if _, err := h.svc.TransitionTool(testCtx, testTenant, httpTool.ID, adminActor, true,
		runtime.TransitionToolRequest{Lifecycle: runtime.ToolLifecycleActive}); err != nil {
		t.Fatalf("TransitionTool: %v", err)
	}
	if _, err := h.svc.GrantToolAccess(testCtx, testTenant, adminActor, true, runtime.GrantToolRequest{
		AgentID: "agent-1", VersionID: "version-1", ToolID: httpTool.ID, ActionID: action.ID,
	}); err != nil {
		t.Fatalf("GrantToolAccess: %v", err)
	}
	minted := h.mint(t, "mint-q", []string{"webhook:send"})
	run := h.createRun(t, minted.Token, "run-q", runtime.RunActionRequest{ToolName: "webhook", Action: "send", ResourceRef: "*"})
	req := runtime.EvaluateActionRequest{
		DelegationToken: minted.Token, RunID: run.Run.ID,
		ToolName: "webhook", Action: "send", ResourceRef: "*",
	}

	meter := &quotaMeter{}
	disp := &recordingDispatcher{}
	h.svc.SetUsageMeter(meter)
	h.svc.SetConnectorDispatcher(disp)

	// Over quota: denied BEFORE any outbound call, with invocation
	// evidence recorded in the chain.
	meter.deny = true
	resp, err := h.svc.DispatchAction(testCtx, testTenant, testRegion, req)
	if err != nil {
		t.Fatalf("DispatchAction: %v", err)
	}
	if !meter.denied {
		t.Fatal("the meter must have been consulted before the call")
	}
	if resp.DispatchMode != "connector_failed" {
		t.Fatalf("expected connector_failed over quota, got %+v", resp)
	}
	if resp.Invocation == nil || resp.Invocation.ErrorCode != "quota_exceeded:connector_calls" {
		t.Fatalf("expected quota_exceeded:connector_calls evidence, got %+v", resp.Invocation)
	}
	if disp.calls != 0 {
		t.Fatalf("no outbound call may open over quota, got %d", disp.calls)
	}

	// Quota released: the call proceeds and reaches the dispatcher.
	meter.deny = false
	resp, err = h.svc.DispatchAction(testCtx, testTenant, testRegion, req)
	if err != nil {
		t.Fatalf("DispatchAction: %v", err)
	}
	if resp.DispatchMode != "dispatched" {
		t.Fatalf("expected dispatched after quota release, got %+v", resp)
	}
	if disp.calls != 1 {
		t.Fatalf("expected 1 outbound call, got %d", disp.calls)
	}
}

// ---------------------------------------------------------------------
// Digest chains
// ---------------------------------------------------------------------

func TestGrantDigestExcludesLifecycleFields(t *testing.T) {
	base := runtime.DelegationGrant{
		TenantID: testTenant, AgentID: "agent-1", AgentVersionID: "version-1", TokenJTI: "jti-1",
		DelegatorPrincipalID: ownerActor, SubjectPrincipalID: subjectPr, Purpose: "p", Region: testRegion,
		PermittedActionsDigest: "digest-1", IssuedAt: time.Now().Truncate(time.Microsecond),
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Microsecond),
	}
	d1 := ComputeGrantDigest(base)
	bound := base
	bound.RunID = "run-1"
	bound.UsedAt = time.Now()
	bound.RevokedAt = time.Now()
	if d1 != ComputeGrantDigest(bound) {
		t.Fatal("lifecycle fields must not affect the grant digest")
	}
	changed := base
	changed.SubjectPrincipalID = "principal:eve"
	if d1 == ComputeGrantDigest(changed) {
		t.Fatal("binding changes must change the grant digest")
	}
}

func TestDecisionChainDetectsTampering(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC).Truncate(time.Microsecond)
	var chain []runtime.ActionDecision
	for i, decision := range []string{runtime.DecisionAllowed, runtime.DecisionDenied, runtime.DecisionAllowed} {
		prev := ""
		if len(chain) > 0 {
			prev = chain[len(chain)-1].ImmutableDigest
		}
		d := runtime.ActionDecision{
			TenantID: testTenant, RunID: "run-1", AgentID: "agent-1",
			Decision: decision, Reason: "r", PolicyVersion: "v1", CreatedAt: now.Add(time.Duration(i) * time.Second),
		}
		d.ImmutableDigest = ComputeDecisionDigest(d, prev)
		chain = append(chain, d)
	}
	if problems := VerifyDecisionChain(chain); len(problems) > 0 {
		t.Fatalf("chain should verify: %+v", problems)
	}
	// Tamper with a middle record.
	tampered := chain[1]
	tampered.Reason = "rewritten"
	tampered.ImmutableDigest = ComputeDecisionDigest(tampered, chain[0].ImmutableDigest)
	chain[1] = tampered
	problems := VerifyDecisionChain(chain)
	if len(problems) != 1 || problems[0].Kind != "digest_mismatch" {
		t.Fatalf("expected digest_mismatch, got %+v", problems)
	}
	if problems[0].Index != 2 {
		t.Fatalf("expected break at index 2, got %d", problems[0].Index)
	}
}

func TestApprovalChainAllowsConsumedAt(t *testing.T) {
	a1 := runtime.ActionApproval{TenantID: testTenant, RunID: "run-1", ToolID: "t1", ActionID: "a1",
		ResourceRef: "*", ApprovingPrincipalID: ownerActor, Decision: runtime.ApprovalApproved,
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Microsecond), CreatedAt: time.Now().Truncate(time.Microsecond)}
	a1.ImmutableDigest = ComputeApprovalDigest(a1)
	// Consuming (setting consumed_at) must not invalidate the digest.
	a1.ConsumedAt = time.Now().Truncate(time.Microsecond)
	chain := []runtime.ActionApproval{a1}
	if problems := VerifyApprovalChain(chain); len(problems) > 0 {
		t.Fatalf("consumed approval must still verify: %+v", problems)
	}
	tampered := a1
	tampered.ApprovingPrincipalID = "principal:eve"
	chain[0] = tampered
	if problems := VerifyApprovalChain(chain); len(problems) == 0 {
		t.Fatal("expected tamper detection")
	}
}
