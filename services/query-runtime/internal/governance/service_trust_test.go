// Phase 6 service-layer tests: trust relationships, agent-to-agent
// delegation chains, external-agent onboarding/lifecycle + identity,
// consent records, transfer policies, external budgets, and provenance.
// Every test uses the fixed-clock harness from service_test.go so
// expiry behavior is deterministic.

package governance

import (
	"errors"
	"strings"
	"testing"
	"time"

	"groundwork/query-runtime/internal/runtime"

	"github.com/golang-jwt/jwt/v5"
)

const (
	extOrg       = "org-partner-1"
	extAgentID   = "ext-agent-1"
	extIssuer    = "https://issuer.partner.example"
	childAgentID = "agent-2"
	childVersion = "version-2"
)

// trustReq is a fully-populated, valid trust relationship request for
// agent-1 -> agent-2 in the test region.
func trustReq(parent, child string) runtime.TrustRelationshipRequest {
	return runtime.TrustRelationshipRequest{
		ParentAgentID:      parent,
		ChildAgentID:       child,
		TrustDomain:        "finance",
		Purpose:            "vendor reconciliation",
		MaxDelegationDepth: 2,
		Region:             testRegion,
		ExpiresAt:          time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}
}

// createTrustActive creates an approved relationship and activates it.
func (h *harness) createTrustActive(t *testing.T) runtime.AgentTrustRelationship {
	t.Helper()
	rel, err := h.svc.CreateTrustRelationship(testCtx, testTenant, ownerActor, false, trustReq("agent-1", childAgentID))
	if err != nil {
		t.Fatalf("CreateTrustRelationship: %v", err)
	}
	if _, err := h.svc.TransitionTrustRelationship(testCtx, testTenant, rel.ID, ownerActor, false, "activate", runtime.TrustTransitionRequest{Reason: "go live"}); err != nil {
		t.Fatalf("activate trust: %v", err)
	}
	rel, err = h.svc.GetTrustRelationship(testCtx, testTenant, rel.ID)
	if err != nil {
		t.Fatalf("GetTrustRelationship: %v", err)
	}
	return rel
}

// registerChildAgent registers a second active agent (agent-2) on the
// fake registry so child delegation can target it.
func (h *harness) registerChildAgent(t *testing.T) {
	t.Helper()
	h.agents.setAgent(runtime.Agent{
		ID:               childAgentID,
		TenantID:         testTenant,
		Name:             "child-reviewer",
		OwnerPrincipalID: subjectPr,
		LifecycleState:   runtime.AgentStateActive,
		ActiveVersionID:  childVersion,
	}, []runtime.AgentVersion{{ID: childVersion, AgentID: childAgentID, Version: "1.0.0", Status: runtime.VersionStatusActive}})
}

// ---------------------------------------------------------------------
// Trust relationships
// ---------------------------------------------------------------------

func TestCreateTrustRelationshipValidates(t *testing.T) {
	h := newHarness(t)
	// Missing actor.
	if _, err := h.svc.CreateTrustRelationship(testCtx, testTenant, "", false, trustReq("agent-1", childAgentID)); !errors.Is(err, runtime.ErrInvalidRequest) {
		t.Fatalf("expected invalid request for empty actor, got %v", err)
	}
	// Exactly one of child_agent_id / external_agent_id required.
	both := trustReq("agent-1", childAgentID)
	both.ExternalAgentID = extAgentID
	if _, err := h.svc.CreateTrustRelationship(testCtx, testTenant, ownerActor, false, both); !errors.Is(err, runtime.ErrInvalidRequest) {
		t.Fatalf("expected invalid request for both ids, got %v", err)
	}
	neither := trustReq("agent-1", "")
	if _, err := h.svc.CreateTrustRelationship(testCtx, testTenant, ownerActor, false, neither); !errors.Is(err, runtime.ErrInvalidRequest) {
		t.Fatalf("expected invalid request for no ids, got %v", err)
	}
	// Expiry must be in the future.
	past := trustReq("agent-1", childAgentID)
	past.ExpiresAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	if _, err := h.svc.CreateTrustRelationship(testCtx, testTenant, ownerActor, false, past); !errors.Is(err, runtime.ErrInvalidRequest) {
		t.Fatalf("expected invalid request for past expiry, got %v", err)
	}
}

func TestCreateTrustRelationshipRequiresActiveParentAndOwner(t *testing.T) {
	h := newHarness(t)
	// Owner-or-admin gate: bob is not the parent agent's owner.
	if _, err := h.svc.CreateTrustRelationship(testCtx, testTenant, subjectPr, false, trustReq("agent-1", childAgentID)); !errors.Is(err, runtime.ErrGovernanceNotAuthorized) {
		t.Fatalf("expected not authorized for non-owner, got %v", err)
	}
	// Admin bypasses the owner check.
	if _, err := h.svc.CreateTrustRelationship(testCtx, testTenant, subjectPr, true, trustReq("agent-1", childAgentID)); err != nil {
		t.Fatalf("admin create: %v", err)
	}
	// Inactive parent agent denies.
	h.agents.agent.LifecycleState = runtime.AgentStateSuspended
	if _, err := h.svc.CreateTrustRelationship(testCtx, testTenant, ownerActor, false, trustReq("agent-1", childAgentID)); !errors.Is(err, runtime.ErrDelegationInactive) {
		t.Fatalf("expected inactive parent denial, got %v", err)
	}
}

func TestCreateTrustRelationshipApprovalFlowAndConflict(t *testing.T) {
	h := newHarness(t)
	req := trustReq("agent-1", childAgentID)
	req.ApprovalRequired = true
	rel, err := h.svc.CreateTrustRelationship(testCtx, testTenant, ownerActor, false, req)
	if err != nil {
		t.Fatalf("create requested: %v", err)
	}
	if rel.Status != runtime.TrustStateRequested {
		t.Fatalf("expected requested, got %q", rel.Status)
	}
	// Approve -> activate.
	rel, err = h.svc.TransitionTrustRelationship(testCtx, testTenant, rel.ID, ownerActor, false, "approve", runtime.TrustTransitionRequest{Reason: "approved"})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if rel.Status != runtime.TrustStateApproved {
		t.Fatalf("expected approved, got %q", rel.Status)
	}
	// Duplicate pair is a conflict even before activation.
	if _, err := h.svc.CreateTrustRelationship(testCtx, testTenant, ownerActor, false, req); !errors.Is(err, runtime.ErrTrustConflict) {
		t.Fatalf("expected trust conflict, got %v", err)
	}
	// Non-owner cannot transition.
	if _, err := h.svc.TransitionTrustRelationship(testCtx, testTenant, rel.ID, subjectPr, false, "activate", runtime.TrustTransitionRequest{}); !errors.Is(err, runtime.ErrGovernanceNotAuthorized) {
		t.Fatalf("expected not authorized, got %v", err)
	}
	// Activate from wrong state fails closed.
	if _, err := h.svc.TransitionTrustRelationship(testCtx, testTenant, rel.ID, ownerActor, false, "suspend", runtime.TrustTransitionRequest{}); !errors.Is(err, runtime.ErrTrustInvalidState) {
		t.Fatalf("expected invalid state, got %v", err)
	}
	if _, err := h.svc.TransitionTrustRelationship(testCtx, testTenant, rel.ID, ownerActor, false, "activate", runtime.TrustTransitionRequest{Reason: "live"}); err != nil {
		t.Fatalf("activate: %v", err)
	}
}

func TestTrustRelationshipRevokeIsTerminalAndEventsChain(t *testing.T) {
	h := newHarness(t)
	rel := h.createTrustActive(t)
	revoked, err := h.svc.TransitionTrustRelationship(testCtx, testTenant, rel.ID, ownerActor, false, "revoke", runtime.TrustTransitionRequest{Reason: "partner ended"})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Status != runtime.TrustStateRevoked {
		t.Fatalf("expected revoked, got %q", revoked.Status)
	}
	// Re-revoke fails closed.
	if _, err := h.svc.TransitionTrustRelationship(testCtx, testTenant, rel.ID, ownerActor, false, "revoke", runtime.TrustTransitionRequest{}); !errors.Is(err, runtime.ErrTrustInvalidState) {
		t.Fatalf("expected invalid state on re-revoke, got %v", err)
	}
	// Every lifecycle transition produced hash-chained evidence.
	events, err := h.svc.ListTrustEvents(testCtx, testTenant, 0)
	if err != nil {
		t.Fatalf("ListTrustEvents: %v", err)
	}
	want := []string{runtime.TrustEventApproved, runtime.TrustEventActivated, runtime.TrustEventRevoked}
	if len(events) != len(want) {
		t.Fatalf("expected %d trust events, got %d", len(want), len(events))
	}
	for i, e := range events {
		if e.EventType != want[i] {
			t.Fatalf("event %d: expected %q, got %q", i, want[i], e.EventType)
		}
		if e.ImmutableDigest == "" {
			t.Fatalf("event %d: empty digest", i)
		}
		if i > 0 && events[i-1].ID != e.PreviousEventID {
			t.Fatalf("event %d: previous_event_id must reference the prior event's ID (got %q)", i, e.PreviousEventID)
		}
	}
	// The digest chain must verify: digests hash the prior event's
	// digest, so both ID linkage and digest continuity are checked.
	if problems := VerifyTrustEventChain(events); len(problems) != 0 {
		t.Fatalf("trust event chain failed verification: %+v", problems)
	}
}

func TestTrustRelationshipExpiredStampsOnRead(t *testing.T) {
	h := newHarness(t)
	req := trustReq("agent-1", childAgentID)
	req.ExpiresAt = time.Date(2026, 8, 7, 13, 0, 0, 0, time.UTC).Format(time.RFC3339) // 1h after fixed clock
	rel, err := h.svc.CreateTrustRelationship(testCtx, testTenant, ownerActor, false, req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	h.clock.advance(2 * time.Hour)
	got, err := h.svc.GetTrustRelationship(testCtx, testTenant, rel.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != runtime.TrustStateExpired {
		t.Fatalf("expected expired stamp, got %q", got.Status)
	}
}

// ---------------------------------------------------------------------
// Agent-to-agent delegation chains
// ---------------------------------------------------------------------

// childHarness wires a root grant for agent-1, an active trust
// relationship to agent-2, and the child agent on the registry.
func (h *harness) childHarness(t *testing.T) (root runtime.MintDelegationResponse) {
	t.Helper()
	h.registerSearchTool(t)
	root = h.mint(t, "mint-root", []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction})
	h.createTrustActive(t)
	h.registerChildAgent(t)
	return root
}

func TestChildDelegationHappyPathAndAttenuation(t *testing.T) {
	h := newHarness(t)
	root := h.childHarness(t)

	child, err := h.svc.DelegateToChildAgent(testCtx, testTenant, testRegion, "agent-1", ownerActor, false, "mint-child-1",
		runtime.ChildDelegationRequest{
			ParentGrantID:       root.Grant.ID,
			ChildAgentID:        childAgentID,
			TrustRelationshipID: h.relationshipID(t),
			Purpose:             "child purpose",
			PermittedActions:    []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction},
		})
	if err != nil {
		t.Fatalf("DelegateToChildAgent: %v", err)
	}
	if child.Grant.DelegationDepth != 1 || !child.Grant.IsAgentDelegation {
		t.Fatalf("child grant fields wrong: depth=%d agentDelegation=%v", child.Grant.DelegationDepth, child.Grant.IsAgentDelegation)
	}
	if child.Grant.ParentGrantID != root.Grant.ID || child.Grant.RootGrantID != root.Grant.ID {
		t.Fatalf("chain links wrong: parent=%q root=%q", child.Grant.ParentGrantID, child.Grant.RootGrantID)
	}
	if child.Grant.AgentID != childAgentID {
		t.Fatalf("child grant bound to wrong agent %q", child.Grant.AgentID)
	}
	if child.Grant.SubjectPrincipalID != subjectPr {
		t.Fatalf("child did not inherit subject: %q", child.Grant.SubjectPrincipalID)
	}

	// Chain reads: root first, verified.
	chain, err := h.svc.GetDelegationChain(testCtx, testTenant, child.Grant.ID)
	if err != nil {
		t.Fatalf("GetDelegationChain: %v", err)
	}
	if !chain.Verified || chain.Depth != 1 {
		t.Fatalf("expected verified depth-1 chain, got verified=%v depth=%d", chain.Verified, chain.Depth)
	}
	if len(chain.Nodes) != 2 || chain.Nodes[0].Grant.ID != root.Grant.ID || chain.Nodes[1].Grant.ID != child.Grant.ID {
		t.Fatalf("chain nodes wrong: %d nodes", len(chain.Nodes))
	}

	// Idempotent replay returns the same grant without minting twice.
	replay, err := h.svc.DelegateToChildAgent(testCtx, testTenant, testRegion, "agent-1", ownerActor, false, "mint-child-1",
		runtime.ChildDelegationRequest{
			ParentGrantID:       root.Grant.ID,
			ChildAgentID:        childAgentID,
			TrustRelationshipID: h.relationshipID(t),
			Purpose:             "child purpose",
			PermittedActions:    []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction},
		})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !replay.TokenAlreadyIssued || replay.Grant.ID != child.Grant.ID {
		t.Fatalf("replay did not dedupe: already=%v", replay.TokenAlreadyIssued)
	}
}

// relationshipID returns the active agent->agent relationship id.
func (h *harness) relationshipID(t *testing.T) string {
	t.Helper()
	rels, err := h.svc.ListTrustRelationships(testCtx, testTenant)
	if err != nil || len(rels) != 1 {
		t.Fatalf("expected one relationship: %v (%d)", err, len(rels))
	}
	return rels[0].ID
}

// restoreParentAgent points the fake registry back at agent-1 (child
// setup adds agent-2; the parent must remain resolvable).
func (h *harness) restoreParentAgent() {
	h.agents.setAgent(runtime.Agent{
		ID:               "agent-1",
		TenantID:         testTenant,
		Name:             "finance-reviewer",
		OwnerPrincipalID: ownerActor,
		LifecycleState:   runtime.AgentStateActive,
		ActiveVersionID:  "version-1",
	}, []runtime.AgentVersion{{ID: "version-1", AgentID: "agent-1", Version: "1.0.0", Status: runtime.VersionStatusActive}})
}

func TestChildDelegationScopeCannotExceedParent(t *testing.T) {
	h := newHarness(t)
	root := h.childHarness(t)
	// Unknown action in permitted list -> resolution fails.
	_, err := h.svc.DelegateToChildAgent(testCtx, testTenant, testRegion, "agent-1", ownerActor, false, "mint-child-2",
		runtime.ChildDelegationRequest{
			ParentGrantID:       root.Grant.ID,
			ChildAgentID:        childAgentID,
			TrustRelationshipID: h.relationshipID(t),
			Purpose:             "child purpose",
			PermittedActions:    []string{"tool_nope:nope"},
		})
	if err == nil {
		t.Fatalf("expected unknown-action rejection")
	}
	// A subset is fine.
	_, err = h.svc.DelegateToChildAgent(testCtx, testTenant, testRegion, "agent-1", ownerActor, false, "mint-child-3",
		runtime.ChildDelegationRequest{
			ParentGrantID:       root.Grant.ID,
			ChildAgentID:        childAgentID,
			TrustRelationshipID: h.relationshipID(t),
			Purpose:             "child purpose",
			PermittedActions:    []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction},
		})
	if err != nil {
		t.Fatalf("subset mint: %v", err)
	}
}

func TestChildDelegationRequiresActiveTrustAndParentOwner(t *testing.T) {
	h := newHarness(t)
	root := h.childHarness(t)

	// Non-owner, non-admin cannot mint a child grant (active trust).
	_, err := h.svc.DelegateToChildAgent(testCtx, testTenant, testRegion, "agent-1", subjectPr, false, "mint-child-5",
		runtime.ChildDelegationRequest{
			ParentGrantID:       root.Grant.ID,
			ChildAgentID:        childAgentID,
			TrustRelationshipID: h.relationshipID(t),
			Purpose:             "child purpose",
			PermittedActions:    []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction},
		})
	if !errors.Is(err, runtime.ErrGovernanceNotAuthorized) {
		t.Fatalf("expected not authorized, got %v", err)
	}

	// No active trust relationship -> denied.
	if _, err := h.svc.TransitionTrustRelationship(testCtx, testTenant, h.relationshipID(t), ownerActor, false, "revoke", runtime.TrustTransitionRequest{Reason: "test"}); err != nil {
		t.Fatalf("revoke trust: %v", err)
	}
	_, err = h.svc.DelegateToChildAgent(testCtx, testTenant, testRegion, "agent-1", ownerActor, false, "mint-child-4",
		runtime.ChildDelegationRequest{
			ParentGrantID:       root.Grant.ID,
			ChildAgentID:        childAgentID,
			TrustRelationshipID: h.relationshipID(t),
			Purpose:             "child purpose",
			PermittedActions:    []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction},
		})
	if !errors.Is(err, runtime.ErrTrustNotActive) {
		t.Fatalf("expected trust not active, got %v", err)
	}
}

func TestChildDelegationRevokedParentInvalidatesChild(t *testing.T) {
	h := newHarness(t)
	root := h.childHarness(t)
	child, err := h.svc.DelegateToChildAgent(testCtx, testTenant, testRegion, "agent-1", ownerActor, false, "mint-child-6",
		runtime.ChildDelegationRequest{
			ParentGrantID:       root.Grant.ID,
			ChildAgentID:        childAgentID,
			TrustRelationshipID: h.relationshipID(t),
			Purpose:             "child purpose",
			PermittedActions:    []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction},
		})
	if err != nil {
		t.Fatalf("mint child: %v", err)
	}
	// Chain-scope revoke (admin) hits the grant and its descendants.
	changed, err := h.svc.RevokeDelegationChain(testCtx, testTenant, root.Grant.ID, adminActor, true, runtime.ControlRequest{Reason: "incident"})
	if err != nil {
		t.Fatalf("RevokeDelegationChain: %v", err)
	}
	if changed != 2 {
		t.Fatalf("expected 2 grants revoked, got %d", changed)
	}
	// The child chain read now reports broken/revoked.
	chain, err := h.svc.GetDelegationChain(testCtx, testTenant, child.Grant.ID)
	if err != nil {
		t.Fatalf("GetDelegationChain: %v", err)
	}
	if chain.Verified {
		t.Fatalf("expected revoked chain to be unverified")
	}
	if !strings.Contains(chain.Problem, "revoked") {
		t.Fatalf("expected revoked problem, got %q", chain.Problem)
	}
	// Non-admin cannot chain-scope revoke.
	if _, err := h.svc.RevokeDelegationChain(testCtx, testTenant, root.Grant.ID, ownerActor, false, runtime.ControlRequest{Reason: "x"}); !errors.Is(err, runtime.ErrGovernanceNotAuthorized) {
		t.Fatalf("expected not authorized, got %v", err)
	}
}

// ---------------------------------------------------------------------
// External agents
// ---------------------------------------------------------------------

func (h *harness) onboardExternal(t *testing.T) runtime.ExternalAgent {
	t.Helper()
	ext, err := h.svc.OnboardExternalAgent(testCtx, testTenant, adminActor, true, runtime.ExternalAgentRequest{
		ExternalAgentID:  extAgentID,
		AgentID:          "agent-1",
		OrganizationID:   extOrg,
		VerifiedIssuer:   extIssuer,
		AllowedAudiences: []string{"groundwork-api"},
		AuthMethod:       runtime.ExternalAuthInternalDemo,
		TrustTier:        runtime.TrustTierPartner,
		Region:           testRegion,
	})
	if err != nil {
		t.Fatalf("OnboardExternalAgent: %v", err)
	}
	if ext.LifecycleState != runtime.ExternalStateActive {
		t.Fatalf("expected active, got %q", ext.LifecycleState)
	}
	return ext
}

// onboardExternalOIDC is the same as onboardExternal but with an OIDC
// auth method, which is not gated by the internal-demo env flag.
func (h *harness) onboardExternalOIDC(t *testing.T) runtime.ExternalAgent {
	t.Helper()
	ext, err := h.svc.OnboardExternalAgent(testCtx, testTenant, adminActor, true, runtime.ExternalAgentRequest{
		ExternalAgentID:  extAgentID,
		AgentID:          "agent-1",
		OrganizationID:   extOrg,
		VerifiedIssuer:   extIssuer,
		AllowedAudiences: []string{"groundwork-api"},
		AuthMethod:       runtime.ExternalAuthOIDC,
		TrustTier:        runtime.TrustTierPartner,
		Region:           testRegion,
	})
	if err != nil {
		t.Fatalf("OnboardExternalAgent (oidc): %v", err)
	}
	if ext.LifecycleState != runtime.ExternalStateActive {
		t.Fatalf("expected active, got %q", ext.LifecycleState)
	}
	return ext
}

func TestOnboardExternalAgentRequiresAdminAndDemoGate(t *testing.T) {
	h := newHarness(t)
	// Non-admin denied.
	if _, err := h.svc.OnboardExternalAgent(testCtx, testTenant, ownerActor, false, runtime.ExternalAgentRequest{
		ExternalAgentID: extAgentID, AgentID: "agent-1", OrganizationID: extOrg,
		VerifiedIssuer: extIssuer, AllowedAudiences: []string{"gw"}, AuthMethod: runtime.ExternalAuthOIDC,
	}); !errors.Is(err, runtime.ErrGovernanceNotAuthorized) {
		t.Fatalf("expected not authorized, got %v", err)
	}
	// internal_demo is gated off by default (fail closed).
	if _, err := h.svc.OnboardExternalAgent(testCtx, testTenant, adminActor, true, runtime.ExternalAgentRequest{
		ExternalAgentID: extAgentID, AgentID: "agent-1", OrganizationID: extOrg,
		VerifiedIssuer: extIssuer, AllowedAudiences: []string{"gw"}, AuthMethod: runtime.ExternalAuthInternalDemo,
	}); !errors.Is(err, runtime.ErrExternalDemoDenied) {
		t.Fatalf("expected demo denied, got %v", err)
	}
	// Invalid auth method rejected.
	if _, err := h.svc.OnboardExternalAgent(testCtx, testTenant, adminActor, true, runtime.ExternalAgentRequest{
		ExternalAgentID: extAgentID, AgentID: "agent-1", OrganizationID: extOrg,
		VerifiedIssuer: extIssuer, AllowedAudiences: []string{"gw"}, AuthMethod: "saml",
	}); !errors.Is(err, runtime.ErrInvalidRequest) {
		t.Fatalf("expected invalid request, got %v", err)
	}
}

func TestExternalAgentLifecycleAndTenantIsolation(t *testing.T) {
	h := newHarness(t)
	ext := h.onboardExternalOIDC(t)

	suspended, err := h.svc.TransitionExternalAgent(testCtx, testTenant, ext.ExternalAgentID, adminActor, true, "suspend", runtime.TrustTransitionRequest{Reason: "review"})
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if suspended.LifecycleState != runtime.ExternalStateSuspended {
		t.Fatalf("expected suspended, got %q", suspended.LifecycleState)
	}
	// Suspend again from suspended fails closed.
	if _, err := h.svc.TransitionExternalAgent(testCtx, testTenant, ext.ExternalAgentID, adminActor, true, "suspend", runtime.TrustTransitionRequest{}); !errors.Is(err, runtime.ErrExternalInvalid) {
		t.Fatalf("expected invalid, got %v", err)
	}
	// Non-admin cannot transition.
	if _, err := h.svc.TransitionExternalAgent(testCtx, testTenant, ext.ExternalAgentID, ownerActor, false, "activate", runtime.TrustTransitionRequest{}); !errors.Is(err, runtime.ErrGovernanceNotAuthorized) {
		t.Fatalf("expected not authorized, got %v", err)
	}
	// Another tenant cannot see the external agent.
	if _, err := h.svc.GetExternalAgent(testCtx, "tenant-other", ext.ExternalAgentID); !errors.Is(err, runtime.ErrExternalNotFound) {
		t.Fatalf("expected not found for other tenant, got %v", err)
	}
	// List is tenant-scoped.
	exts, err := h.svc.ListExternalAgents(testCtx, testTenant)
	if err != nil || len(exts) != 1 {
		t.Fatalf("expected 1 external agent, got %d (%v)", len(exts), err)
	}
}

// demoExternalToken mints an internal_demo identity token for the test
// external agent using the harness authority's HS256 secret. exp is
// based on the real wall clock because jwt.ParseWithClaims validates
// expiry against time.Now, not the fixed harness clock.
func (h *harness) demoExternalToken(t *testing.T, external runtime.ExternalAgent, cid, purpose, jti string) string {
	t.Helper()
	return h.demoExternalTokenIssuer(t, external, external.VerifiedIssuer, cid, purpose, jti)
}

// demoExternalTokenIssuer signs a demo identity token with an explicit
// issuer (used to prove the wrong-issuer fail-closed path).
func (h *harness) demoExternalTokenIssuer(t *testing.T, external runtime.ExternalAgent, issuer, cid, purpose, jti string) string {
	t.Helper()
	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": external.ExternalAgentID,
		"aud": "groundwork-api",
		"exp": now + 3600,
		"iat": now,
		"jti": jti,
		"cid": cid,
		"pur": purpose,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(h.auth.hsSecret)
	if err != nil {
		t.Fatalf("sign external token: %v", err)
	}
	return signed
}

func TestVerifyExternalSessionValidatesToken(t *testing.T) {
	// internal_demo verification is gated behind an explicit env flag
	// (fail closed by default). The external-run + session path can only
	// be exercised in this build with the flag on.
	t.Setenv("GROUNDWORK_EXTERNAL_INTERNAL_DEMO", "true")
	h := newHarness(t)
	ext := h.onboardExternal(t) // internal_demo agent (now allowed)

	// Wrong issuer fails closed (lookup by issuer fails).
	bad := h.demoExternalTokenIssuer(t, ext, "https://evil.example", "customer-1", "purpose-1", "jti-1")
	if _, err := h.svc.VerifyExternalSession(testCtx, testTenant, testRegion, runtime.ExternalSessionRequest{Token: bad}); err == nil {
		t.Fatalf("expected wrong-issuer failure")
	}

	// Valid token produces a session bound to the paired identity.
	session, err := h.svc.VerifyExternalSession(testCtx, testTenant, testRegion, runtime.ExternalSessionRequest{Token: h.demoExternalToken(t, ext, "customer-1", "purpose-1", "jti-2")})
	if err != nil {
		t.Fatalf("VerifyExternalSession: %v", err)
	}
	if session.ExternalAgentID != ext.ExternalAgentID || session.AgentID != "agent-1" {
		t.Fatalf("session identity wrong: %+v", session)
	}
	if session.CustomerPrincipalID != "customer-1" || session.Purpose != "purpose-1" {
		t.Fatalf("session claims wrong: %+v", session)
	}

	// Wrong region denies.
	if _, err := h.svc.VerifyExternalSession(testCtx, testTenant, "eu-central-1", runtime.ExternalSessionRequest{Token: h.demoExternalToken(t, ext, "customer-1", "purpose-1", "jti-3")}); !errors.Is(err, runtime.ErrDelegationRegion) {
		t.Fatalf("expected region mismatch, got %v", err)
	}

	// Non-demo auth methods fail closed in this build (no remote JWKS).
	// Pair to a distinct registry agent so it does not collide on the
	// demo agent's (agent_id, issuer) uniqueness.
	h.agents.setAgent(runtime.Agent{
		ID:               "agent-3",
		TenantID:         testTenant,
		Name:             "oidc-paired",
		OwnerPrincipalID: ownerActor,
		LifecycleState:   runtime.AgentStateActive,
		ActiveVersionID:  "version-3",
	}, []runtime.AgentVersion{{ID: "version-3", AgentID: "agent-3", Version: "1.0.0", Status: runtime.VersionStatusActive}})
	oidcAgent, err := h.svc.OnboardExternalAgent(testCtx, testTenant, adminActor, true, runtime.ExternalAgentRequest{
		ExternalAgentID:  "ext-agent-oidc",
		AgentID:          "agent-3",
		OrganizationID:   "org-oidc",
		VerifiedIssuer:   "https://issuer.oidc.example",
		AllowedAudiences: []string{"groundwork-api"},
		AuthMethod:       runtime.ExternalAuthOIDC,
		TrustTier:        runtime.TrustTierVerified,
		Region:           testRegion,
	})
	if err != nil {
		t.Fatalf("onboard oidc: %v", err)
	}
	if _, err := h.svc.VerifyExternalSession(testCtx, testTenant, testRegion, runtime.ExternalSessionRequest{Token: h.demoExternalToken(t, oidcAgent, "customer-1", "purpose-1", "jti-4")}); !errors.Is(err, runtime.ErrExternalInvalid) {
		t.Fatalf("expected OIDC verification to fail closed, got %v", err)
	}
}

// ---------------------------------------------------------------------
// Consent records
// ---------------------------------------------------------------------

func (h *harness) createConsent(t *testing.T, cid, purpose string) runtime.ConsentRecord {
	t.Helper()
	consent, err := h.svc.CreateConsentRecord(testCtx, testTenant, adminActor, true, runtime.ConsentRequest{
		OrganizationID:      extOrg,
		ExternalAgentID:     extAgentID,
		CustomerPrincipalID: cid,
		Purpose:             purpose,
		ResourceRefPattern:  "*",
	})
	if err != nil {
		t.Fatalf("CreateConsentRecord: %v", err)
	}
	return consent
}

func TestConsentLifecycleAndSingleActiveRule(t *testing.T) {
	h := newHarness(t)
	h.onboardExternalOIDC(t)

	consent := h.createConsent(t, "customer-1", "purpose-1")
	if consent.Status != "active" {
		t.Fatalf("expected active, got %q", consent.Status)
	}
	// Second active consent for the same scope is a conflict.
	if _, err := h.svc.CreateConsentRecord(testCtx, testTenant, adminActor, true, runtime.ConsentRequest{
		OrganizationID: extOrg, ExternalAgentID: extAgentID, CustomerPrincipalID: "customer-1", Purpose: "purpose-1",
	}); !errors.Is(err, runtime.ErrConsentConflict) {
		t.Fatalf("expected consent conflict, got %v", err)
	}
	// Non-admin cannot grant consent.
	if _, err := h.svc.CreateConsentRecord(testCtx, testTenant, ownerActor, false, runtime.ConsentRequest{
		OrganizationID: extOrg, ExternalAgentID: extAgentID, CustomerPrincipalID: "customer-2", Purpose: "purpose-2",
	}); !errors.Is(err, runtime.ErrGovernanceNotAuthorized) {
		t.Fatalf("expected not authorized, got %v", err)
	}
	// Revoke -> re-grant is allowed (fresh row).
	revoked, err := h.svc.RevokeConsentRecord(testCtx, testTenant, consent.ID, adminActor, true, "customer withdrew")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Status != "revoked" {
		t.Fatalf("expected revoked, got %q", revoked.Status)
	}
	// Re-revoke fails closed.
	if _, err := h.svc.RevokeConsentRecord(testCtx, testTenant, consent.ID, adminActor, true, "again"); !errors.Is(err, runtime.ErrConsentRevoked) {
		t.Fatalf("expected revoked, got %v", err)
	}
	recreated := h.createConsent(t, "customer-1", "purpose-1")
	if recreated.ID == consent.ID {
		t.Fatalf("expected a fresh consent row after revocation")
	}
}

// ---------------------------------------------------------------------
// Transfer policies
// ---------------------------------------------------------------------

func TestTransferPolicyLifecycleAndCrossRegionGate(t *testing.T) {
	h := newHarness(t)
	policy, err := h.svc.UpsertTransferPolicy(testCtx, testTenant, adminActor, true, runtime.TransferPolicyRequest{
		SourceRegion: "eu-central-1", TargetRegion: "us-east-1", PurposePattern: "vendor reconciliation", Enabled: true,
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if policy.SourceRegion != "eu-central-1" || !policy.Enabled {
		t.Fatalf("policy fields wrong: %+v", policy)
	}
	// Same-region policy rejected.
	if _, err := h.svc.UpsertTransferPolicy(testCtx, testTenant, adminActor, true, runtime.TransferPolicyRequest{
		SourceRegion: "eu-central-1", TargetRegion: "eu-central-1", PurposePattern: "*", Enabled: true,
	}); !errors.Is(err, runtime.ErrInvalidRequest) {
		t.Fatalf("expected invalid request, got %v", err)
	}
	// Non-admin cannot upsert.
	if _, err := h.svc.UpsertTransferPolicy(testCtx, testTenant, ownerActor, false, runtime.TransferPolicyRequest{
		SourceRegion: "us-east-1", TargetRegion: "eu-central-1", PurposePattern: "*", Enabled: true,
	}); !errors.Is(err, runtime.ErrGovernanceNotAuthorized) {
		t.Fatalf("expected not authorized, got %v", err)
	}
	// Suspend disables the policy (cross-region delegation denied).
	suspended, err := h.svc.TransitionTransferPolicy(testCtx, testTenant, policy.ID, adminActor, true, "suspend", runtime.TrustTransitionRequest{Reason: "review"})
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if suspended.Enabled {
		t.Fatalf("expected disabled after suspend")
	}
	// Cross-region child delegation without an enabled policy fails closed.
	h.childHarness(t)
	h.restoreParentAgent()
	root, err := h.svc.MintDelegation(testCtx, testTenant, "eu-central-1", "agent-1", ownerActor, false, "mint-eu", runtime.MintDelegationRequest{
		SubjectPrincipalID: subjectPr, Purpose: "vendor reconciliation",
		PermittedActions: []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction},
	})
	if err != nil {
		t.Fatalf("eu mint: %v", err)
	}
	_, err = h.svc.DelegateToChildAgent(testCtx, testTenant, "us-east-1", "agent-1", ownerActor, false, "mint-cross", runtime.ChildDelegationRequest{
		ParentGrantID:       root.Grant.ID,
		ChildAgentID:        childAgentID,
		TrustRelationshipID: h.relationshipID(t),
		Purpose:             "vendor reconciliation",
		PermittedActions:    []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction},
	})
	if !errors.Is(err, runtime.ErrCrossRegionDenied) {
		t.Fatalf("expected cross-region denial, got %v", err)
	}
}

// ---------------------------------------------------------------------
// External budgets
// ---------------------------------------------------------------------

func TestExternalBudgetUpsertValidatesScopeAndAdmin(t *testing.T) {
	h := newHarness(t)
	h.onboardExternalOIDC(t)

	budget, err := h.svc.UpsertExternalBudget(testCtx, testTenant, adminActor, true, runtime.ExternalBudgetRequest{
		ScopeType:        runtime.ExternalBudgetScopeAgent,
		ExternalAgentID:  extAgentID,
		MaxTotalActions:  100,
		MaxActionsPerRun: 10,
		MaxDeniedPerRun:  2,
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if budget.MaxTotalActions != 100 {
		t.Fatalf("expected max_total_actions 100, got %d", budget.MaxTotalActions)
	}
	// Unknown scope type rejected.
	if _, err := h.svc.UpsertExternalBudget(testCtx, testTenant, adminActor, true, runtime.ExternalBudgetRequest{
		ScopeType: "tenant", ExternalAgentID: extAgentID,
	}); !errors.Is(err, runtime.ErrInvalidRequest) {
		t.Fatalf("expected invalid request, got %v", err)
	}
	// Customer scope requires customer principal.
	if _, err := h.svc.UpsertExternalBudget(testCtx, testTenant, adminActor, true, runtime.ExternalBudgetRequest{
		ScopeType: runtime.ExternalBudgetScopeCustomer, ExternalAgentID: extAgentID,
	}); !errors.Is(err, runtime.ErrInvalidRequest) {
		t.Fatalf("expected invalid request, got %v", err)
	}
	// Non-admin denied.
	if _, err := h.svc.UpsertExternalBudget(testCtx, testTenant, ownerActor, false, runtime.ExternalBudgetRequest{
		ScopeType: runtime.ExternalBudgetScopeAgent, ExternalAgentID: extAgentID,
	}); !errors.Is(err, runtime.ErrGovernanceNotAuthorized) {
		t.Fatalf("expected not authorized, got %v", err)
	}
	budgets, err := h.svc.ListExternalBudgets(testCtx, testTenant)
	if err != nil || len(budgets) != 1 {
		t.Fatalf("expected 1 budget, got %d (%v)", len(budgets), err)
	}
}

// ---------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------

func TestEvidenceProvenanceResolution(t *testing.T) {
	h := newHarness(t)
	h.happyRun(t)
	page, err := h.svc.QueryEvidence(testCtx, testTenant, runtime.EvidenceFilter{})
	if err != nil {
		t.Fatalf("QueryEvidence: %v", err)
	}
	// happyRun produced at least one decision event; provenance must
	// resolve it without errors and without leaking raw tokens.
	var decisionID string
	for _, e := range page.Events {
		if e.Kind == runtime.EvidenceKindDecision {
			decisionID = e.EventID
			break
		}
	}
	if decisionID == "" {
		t.Fatalf("no decision evidence found")
	}
	view, err := h.svc.GetEvidenceProvenance(testCtx, testTenant, decisionID)
	if err != nil {
		t.Fatalf("GetEvidenceProvenance: %v", err)
	}
	if view.FinalDecision != runtime.DecisionAllowed {
		t.Fatalf("expected allowed decision, got %q", view.FinalDecision)
	}
	if view.SubjectPrincipalID != subjectPr {
		t.Fatalf("expected subject %q, got %q", subjectPr, view.SubjectPrincipalID)
	}
	if strings.Contains(view.ImmutableDigest, "token") {
		t.Fatalf("provenance leaked raw material: %+v", view)
	}
}
