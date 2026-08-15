//go:build integration

package integration

// Phase 6 trust lifecycle against real Postgres: trust relationships,
// agent-to-agent delegation, the cross-region transfer-policy gate,
// external-agent onboarding + sessions, consent records, external
// budgets, and the full external-run evaluation path (evidence written
// through the shared Postgres governance store).

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"groundwork/query-runtime/internal/agentregistry"
	"groundwork/query-runtime/internal/governance"
	"groundwork/query-runtime/internal/relationship"
	"groundwork/query-runtime/internal/runtime"

	"github.com/golang-jwt/jwt/v5"
)

// trustStack wires the real Postgres governance store, the real
// Postgres agent registry (AgentReader), and an env-built Authority.
type trustStack struct {
	svc      *governance.Service
	agents   *agentregistry.Service
	govStore *governance.PostgresStore
}

func newTrustStack(t *testing.T, db *sql.DB, authorizer relationship.Authorizer) *trustStack {
	t.Helper()
	t.Setenv("GROUNDWORK_DELEGATION_HS_SECRET", "integration-hs-secret-0123456789abcdef")
	auth, err := governance.BuildAuthority()
	if err != nil {
		t.Fatalf("build authority: %v", err)
	}
	agents := agentregistry.NewService(agentregistry.NewPostgresStore(db))
	govStore := governance.NewPostgresStore(db)
	return &trustStack{svc: governance.NewService(govStore, auth, authorizer, agents), agents: agents, govStore: govStore}
}

// activateAgent creates, versions, and activates one agent.
func (s *trustStack) activateAgent(t *testing.T, tenant, name, owner string) runtime.Agent {
	t.Helper()
	ctx := context.Background()
	created, err := s.agents.CreateAgent(ctx, tenant, owner, runtime.CreateAgentRequest{
		Name: name, RiskTier: runtime.RiskTierLow, Environment: runtime.EnvProduction,
	})
	if err != nil {
		t.Fatalf("create agent %s: %v", name, err)
	}
	if _, err := s.agents.AddVersion(ctx, tenant, created.ID, owner, false, runtime.AddAgentVersionRequest{Version: "1.0.0"}); err != nil {
		t.Fatalf("add version %s: %v", name, err)
	}
	active, err := s.agents.ActivateAgent(ctx, tenant, created.ID, owner, false, "ship")
	if err != nil {
		t.Fatalf("activate %s: %v", name, err)
	}
	if active.LifecycleState != runtime.AgentStateActive || active.ActiveVersionID == "" {
		t.Fatalf("agent %s must be active with a bound version, got %+v", name, active)
	}
	return active
}

// registerToolAndGrant registers an active tool + action and grants it
// to the agent's active version; returns tool id, action id, and the
// registered tool name.
func (s *trustStack) registerToolAndGrant(t *testing.T, tenant string, agentID, versionID, toolName string) (string, string, string) {
	t.Helper()
	ctx := context.Background()
	tool, err := s.svc.RegisterTool(ctx, tenant, "principal:admin", true, runtime.RegisterToolRequest{
		Name: toolName, Description: "integration tool", Transport: runtime.ToolTransportBuiltin,
		OwnerPrincipalID: "principal:owner", Region: testRegion,
	})
	if err != nil {
		t.Fatalf("register tool %s: %v", toolName, err)
	}
	action, err := s.svc.RegisterToolAction(ctx, tenant, tool.ID, "principal:admin", true, runtime.RegisterToolActionRequest{
		Action: "run", ResourceType: "document", RiskLevel: runtime.RiskLevelLow, ReadOnly: true,
	})
	if err != nil {
		t.Fatalf("register action: %v", err)
	}
	if _, err := s.svc.TransitionTool(ctx, tenant, tool.ID, "principal:admin", true, runtime.TransitionToolRequest{Lifecycle: runtime.ToolLifecycleActive}); err != nil {
		t.Fatalf("activate tool: %v", err)
	}
	if _, err := s.svc.GrantToolAccess(ctx, tenant, "principal:admin", true, runtime.GrantToolRequest{
		AgentID: agentID, VersionID: versionID, ToolID: tool.ID, ActionID: action.ID,
	}); err != nil {
		t.Fatalf("grant tool: %v", err)
	}
	return tool.ID, action.ID, tool.Name
}

// TestTrustRelationshipPostgresLifecycle exercises trust relationships
// end to end through Postgres: creation (approved + approval-required
// flows), authorization, lifecycle transitions, lazy expiry stamping,
// persistence across a fresh store handle, and hash-chained evidence
// through both ListTrustEvents and the evidence union.
func TestTrustRelationshipPostgresLifecycle(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)
	ctx := context.Background()
	tenant := "tenant_trust_rel_" + unique()
	stack := newTrustStack(t, db, nil)

	parent := stack.activateAgent(t, tenant, "trust-parent", "principal:owner")
	child := stack.activateAgent(t, tenant, "trust-child", "principal:child-owner")
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)

	rel, err := stack.svc.CreateTrustRelationship(ctx, tenant, "principal:owner", false, runtime.TrustRelationshipRequest{
		ParentAgentID: parent.ID, ChildAgentID: child.ID,
		TrustDomain: "internal", Purpose: "quarterly review",
		MaxDelegationDepth: 3, Region: testRegion, ExpiresAt: expires.Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("create trust relationship: %v", err)
	}
	if rel.Status != runtime.TrustStateApproved || rel.ParentAgentID != parent.ID || rel.ChildAgentID != child.ID {
		t.Fatalf("unexpected relationship: %+v", rel)
	}
	if rel.ImmutableDigest == "" || rel.OwnerPrincipalID != "principal:owner" {
		t.Fatalf("relationship must carry owner + digest, got %+v", rel)
	}

	// Non-owner (and not admin) cannot act on it.
	if _, err := stack.svc.TransitionTrustRelationship(ctx, tenant, rel.ID, "principal:eve", false, "activate", runtime.TrustTransitionRequest{}); !errors.Is(err, runtime.ErrGovernanceNotAuthorized) {
		t.Fatalf("expected not authorized for non-owner, got %v", err)
	}

	// approved -> active -> suspended -> active -> revoked (terminal).
	active, err := stack.svc.TransitionTrustRelationship(ctx, tenant, rel.ID, "principal:owner", false, "activate", runtime.TrustTransitionRequest{})
	if err != nil || active.Status != runtime.TrustStateActive {
		t.Fatalf("activate: %+v (%v)", active, err)
	}
	if _, err := stack.svc.TransitionTrustRelationship(ctx, tenant, rel.ID, "principal:owner", false, "activate", runtime.TrustTransitionRequest{}); !errors.Is(err, runtime.ErrTrustInvalidState) {
		t.Fatalf("expected invalid state on double-activate, got %v", err)
	}
	suspended, err := stack.svc.TransitionTrustRelationship(ctx, tenant, rel.ID, "principal:owner", false, "suspend", runtime.TrustTransitionRequest{Reason: "review"})
	if err != nil || suspended.Status != runtime.TrustStateSuspended {
		t.Fatalf("suspend: %+v (%v)", suspended, err)
	}
	resumed, err := stack.svc.TransitionTrustRelationship(ctx, tenant, rel.ID, "principal:owner", false, "resume", runtime.TrustTransitionRequest{})
	if err != nil || resumed.Status != runtime.TrustStateActive {
		t.Fatalf("resume: %+v (%v)", resumed, err)
	}
	revoked, err := stack.svc.TransitionTrustRelationship(ctx, tenant, rel.ID, "principal:owner", false, "revoke", runtime.TrustTransitionRequest{Reason: "partner ended"})
	if err != nil || revoked.Status != runtime.TrustStateRevoked {
		t.Fatalf("revoke: %+v (%v)", revoked, err)
	}
	if _, err := stack.svc.TransitionTrustRelationship(ctx, tenant, rel.ID, "principal:owner", false, "revoke", runtime.TrustTransitionRequest{}); !errors.Is(err, runtime.ErrTrustInvalidState) {
		t.Fatalf("expected invalid state on re-revoke, got %v", err)
	}

	// Approval-required flow: requested -> approved -> active (new pair:
	// the unique (parent, child) index allows only one relationship per pair).
	reqChild := stack.activateAgent(t, tenant, "trust-req-child", "principal:req-owner")
	reqRel, err := stack.svc.CreateTrustRelationship(ctx, tenant, "principal:owner", false, runtime.TrustRelationshipRequest{
		ParentAgentID: parent.ID, ChildAgentID: reqChild.ID,
		TrustDomain: "internal", Purpose: "approval flow",
		Region: testRegion, ExpiresAt: expires.Format(time.RFC3339), ApprovalRequired: true,
	})
	if err != nil {
		t.Fatalf("create approval-required relationship: %v", err)
	}
	if reqRel.Status != runtime.TrustStateRequested {
		t.Fatalf("expected requested, got %q", reqRel.Status)
	}
	approved, err := stack.svc.TransitionTrustRelationship(ctx, tenant, reqRel.ID, "principal:owner", false, "approve", runtime.TrustTransitionRequest{Reason: "ok"})
	if err != nil || approved.Status != runtime.TrustStateApproved {
		t.Fatalf("approve: %+v (%v)", approved, err)
	}
	if _, err := stack.svc.TransitionTrustRelationship(ctx, tenant, reqRel.ID, "principal:owner", false, "activate", runtime.TrustTransitionRequest{}); err != nil {
		t.Fatalf("activate after approve: %v", err)
	}

	// Expiry stamping: a short-lived relationship reads back as expired.
	shortChild := stack.activateAgent(t, tenant, "trust-short-child", "principal:short-owner")
	short, err := stack.svc.CreateTrustRelationship(ctx, tenant, "principal:owner", false, runtime.TrustRelationshipRequest{
		ParentAgentID: parent.ID, ChildAgentID: shortChild.ID,
		TrustDomain: "internal", Purpose: "short-lived",
		Region: testRegion, ExpiresAt: time.Now().UTC().Add(2 * time.Second).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("create short-lived relationship: %v", err)
	}
	time.Sleep(2100 * time.Millisecond)
	expired, err := stack.svc.GetTrustRelationship(ctx, tenant, short.ID)
	if err != nil {
		t.Fatalf("get expired relationship: %v", err)
	}
	if expired.Status != runtime.TrustStateExpired {
		t.Fatalf("expected expired stamp, got %q", expired.Status)
	}

	// Persistence across a fresh store handle.
	freshStore := governance.NewPostgresStore(db)
	freshSvc := governance.NewService(freshStore, nil, nil, nil)
	listed, err := freshSvc.ListTrustRelationships(ctx, tenant)
	if err != nil {
		t.Fatalf("list relationships: %v", err)
	}
	if len(listed) != 3 {
		t.Fatalf("expected 3 relationships after re-read, got %d", len(listed))
	}
	byID := map[string]runtime.AgentTrustRelationship{}
	for _, r := range listed {
		byID[r.ID] = r
	}
	if byID[rel.ID].Status != runtime.TrustStateRevoked || byID[reqRel.ID].Status != runtime.TrustStateActive {
		t.Fatalf("re-read states mismatch: %+v", byID)
	}

	// Hash-chained evidence: every transition appended a chained event.
	events, err := stack.svc.ListTrustEvents(ctx, tenant, 0)
	if err != nil {
		t.Fatalf("list trust events: %v", err)
	}
	if len(events) < 7 {
		t.Fatalf("expected >= 7 trust events, got %d", len(events))
	}
	for i, e := range events {
		if e.ImmutableDigest == "" {
			t.Fatalf("event %d has no digest", i)
		}
		if i > 0 && e.PreviousEventID != events[i-1].ID {
			t.Fatalf("event %d must chain to %s, got previous %q", i, events[i-1].ID, e.PreviousEventID)
		}
	}
	if problems := governance.VerifyTrustEventChain(events); len(problems) != 0 {
		t.Fatalf("persisted trust chain failed verification: %+v", problems)
	}

	// The evidence union surfaces trust events with digests.
	ev, err := stack.govStore.QueryEvidence(ctx, tenant, runtime.EvidenceFilter{Kinds: []string{runtime.EvidenceKindTrustEvent}, Limit: 100})
	if err != nil {
		t.Fatalf("query evidence: %v", err)
	}
	found := false
	for _, e := range ev {
		if e.EntityType == "relationship" && e.EntityID == rel.ID {
			found = true
			if e.ImmutableDigest == "" || e.Kind != runtime.EvidenceKindTrustEvent {
				t.Fatalf("relationship evidence malformed: %+v", e)
			}
		}
	}
	if !found {
		t.Fatalf("relationship evidence missing from the union")
	}
}

// TestTrustPostgresChildDelegationAndTransferPolicyGate mints a root
// grant for the parent agent, then delegates to the child across the
// explicit trust edge. Cross-region delegation is denied until an
// enabled transfer policy exists, and the minted child grant forms a
// verified chain back to the root.
func TestTrustPostgresChildDelegationAndTransferPolicyGate(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)
	ctx := context.Background()
	tenant := "tenant_trust_del_" + unique()
	stack := newTrustStack(t, db, nil)

	parent := stack.activateAgent(t, tenant, "del-parent", "principal:owner")
	child := stack.activateAgent(t, tenant, "del-child", "principal:child-owner")
	_, _, toolName := stack.registerToolAndGrant(t, tenant, parent.ID, parent.ActiveVersionID, "del_tool_"+unique())
	action := toolName + ":run"
	_, _, otherToolName := stack.registerToolAndGrant(t, tenant, parent.ID, parent.ActiveVersionID, "other_tool_"+unique())
	otherAction := otherToolName + ":run"

	// Root grant for the parent agent (region uk).
	root, err := stack.svc.MintDelegation(ctx, tenant, testRegion, parent.ID, "principal:owner", false, "root-"+unique(), runtime.MintDelegationRequest{
		SubjectPrincipalID: "principal:rehan", Purpose: "quarterly review",
		PermittedActions: []string{action},
	})
	if err != nil {
		t.Fatalf("mint root grant: %v", err)
	}
	if root.Grant.Region != testRegion || len(root.Grant.PermittedActions) != 1 {
		t.Fatalf("unexpected root grant: %+v", root.Grant)
	}

	// Trust edge parent -> child in a DIFFERENT region (eu).
	rel, err := stack.svc.CreateTrustRelationship(ctx, tenant, "principal:owner", false, runtime.TrustRelationshipRequest{
		ParentAgentID: parent.ID, ChildAgentID: child.ID,
		TrustDomain: "internal", Purpose: "quarterly review",
		MaxDelegationDepth: 2, Region: "eu",
		AllowedToolsActions: []string{action},
		ExpiresAt:           time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("create relationship: %v", err)
	}
	if _, err := stack.svc.TransitionTrustRelationship(ctx, tenant, rel.ID, "principal:owner", false, "activate", runtime.TrustTransitionRequest{}); err != nil {
		t.Fatalf("activate relationship: %v", err)
	}

	delegate := func() error {
		_, err := stack.svc.DelegateToChildAgent(ctx, tenant, "eu", parent.ID, "principal:owner", false, "child-"+unique(), runtime.ChildDelegationRequest{
			ParentGrantID:       root.Grant.ID,
			ChildAgentID:        child.ID,
			TrustRelationshipID: rel.ID,
			Purpose:             "quarterly review",
			PermittedActions:    []string{action},
		})
		return err
	}

	// No transfer policy uk -> eu yet: cross-region delegation denied.
	if err := delegate(); !errors.Is(err, runtime.ErrCrossRegionDenied) {
		t.Fatalf("expected cross-region denial, got %v", err)
	}

	// Enabled transfer policy uk -> eu (exact-purpose match) permits it.
	policy, err := stack.svc.UpsertTransferPolicy(ctx, tenant, "principal:admin", true, runtime.TransferPolicyRequest{
		SourceRegion: testRegion, TargetRegion: "eu", PurposePattern: "quarterly review", Enabled: true,
	})
	if err != nil {
		t.Fatalf("upsert transfer policy: %v", err)
	}
	if !policy.Enabled {
		t.Fatalf("policy must be enabled, got %+v", policy)
	}
	if err := delegate(); err != nil {
		t.Fatalf("delegate with policy: %v", err)
	}
	childMints, err := stack.svc.ListChildDelegations(ctx, tenant, parent.ID)
	if err != nil || len(childMints) < 1 {
		t.Fatalf("list child delegations after policy: %v", err)
	}
	childMint := childMints[len(childMints)-1]
	if childMint.DelegationDepth != 1 || childMint.ParentGrantID != root.Grant.ID {
		t.Fatalf("unexpected child grant: %+v", childMint)
	}

	// The chain root -> child verifies through Postgres.
	chain, err := stack.svc.GetDelegationChain(ctx, tenant, childMint.ID)
	if err != nil {
		t.Fatalf("get chain: %v", err)
	}
	if !chain.Verified || chain.Depth != 1 || chain.RootGrantID != root.Grant.ID || chain.LeafGrantID != childMint.ID {
		t.Fatalf("chain must verify, got %+v", chain)
	}

	// Child scope cannot exceed the relationship scope.
	if _, err := stack.svc.DelegateToChildAgent(ctx, tenant, "eu", parent.ID, "principal:owner", false, "child-"+unique(), runtime.ChildDelegationRequest{
		ParentGrantID: root.Grant.ID, ChildAgentID: child.ID, TrustRelationshipID: rel.ID,
		Purpose: "quarterly review", PermittedActions: []string{action, otherAction},
	}); !errors.Is(err, runtime.ErrScopeExceedsParent) {
		t.Fatalf("expected scope exceeded, got %v", err)
	}

	// Suspend the policy: cross-region delegation is denied again.
	if _, err := stack.svc.TransitionTransferPolicy(ctx, tenant, policy.ID, "principal:admin", true, "suspend", runtime.TrustTransitionRequest{Reason: "audit"}); err != nil {
		t.Fatalf("suspend policy: %v", err)
	}
	if err := delegate(); !errors.Is(err, runtime.ErrCrossRegionDenied) {
		t.Fatalf("expected denial after policy suspension, got %v", err)
	}

	// Same-region delegation needs no policy: activate a uk relationship
	// (distinct child — Postgres allows one relationship per pair ever).
	childUK := stack.activateAgent(t, tenant, "del-child-uk", "principal:child-owner")
	relUK, err := stack.svc.CreateTrustRelationship(ctx, tenant, "principal:owner", false, runtime.TrustRelationshipRequest{
		ParentAgentID: parent.ID, ChildAgentID: childUK.ID,
		TrustDomain: "internal", Purpose: "same region", Region: testRegion,
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("create uk relationship: %v", err)
	}
	if _, err := stack.svc.TransitionTrustRelationship(ctx, tenant, relUK.ID, "principal:owner", false, "activate", runtime.TrustTransitionRequest{}); err != nil {
		t.Fatalf("activate uk relationship: %v", err)
	}
	if _, err := stack.svc.DelegateToChildAgent(ctx, tenant, testRegion, parent.ID, "principal:owner", false, "child-"+unique(), runtime.ChildDelegationRequest{
		ParentGrantID: root.Grant.ID, ChildAgentID: childUK.ID, TrustRelationshipID: relUK.ID,
		Purpose: "same region", PermittedActions: []string{action},
	}); err != nil {
		t.Fatalf("same-region delegation must not require a policy: %v", err)
	}

	// Child grants are surfaced by ListChildDelegations.
	children, err := stack.svc.ListChildDelegations(ctx, tenant, parent.ID)
	if err != nil {
		t.Fatalf("list child delegations: %v", err)
	}
	if len(children) < 2 {
		t.Fatalf("expected >= 2 child delegations, got %d", len(children))
	}
}

// TestExternalAgentPostgresLifecycle onboard + lifecycle + tenant
// isolation of external agents against real Postgres (migration 019).
func TestExternalAgentPostgresLifecycle(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)
	ctx := context.Background()
	t.Setenv("GROUNDWORK_EXTERNAL_INTERNAL_DEMO", "true")
	tenant := "tenant_ext_agent_" + unique()
	stack := newTrustStack(t, db, nil)

	paired := stack.activateAgent(t, tenant, "paired-agent", "principal:owner")

	// Non-admin cannot onboard.
	if _, err := stack.svc.OnboardExternalAgent(ctx, tenant, "principal:owner", false, runtime.ExternalAgentRequest{
		ExternalAgentID: "ext-demo-1", AgentID: paired.ID, OrganizationID: "acme-corp",
		VerifiedIssuer: "https://demo-issuer.example.com", AllowedAudiences: []string{"groundwork-api"},
		AuthMethod: runtime.ExternalAuthInternalDemo, TrustTier: runtime.TrustTierPartner, Region: testRegion,
	}); !errors.Is(err, runtime.ErrGovernanceNotAuthorized) {
		t.Fatalf("expected not authorized, got %v", err)
	}

	ext, err := stack.svc.OnboardExternalAgent(ctx, tenant, "principal:admin", true, runtime.ExternalAgentRequest{
		ExternalAgentID: "ext-demo-1", AgentID: paired.ID, OrganizationID: "acme-corp",
		VerifiedIssuer: "https://demo-issuer.example.com", AllowedAudiences: []string{"groundwork-api"},
		AuthMethod: runtime.ExternalAuthInternalDemo, TrustTier: runtime.TrustTierPartner, Region: testRegion,
	})
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	if ext.LifecycleState != runtime.ExternalStateActive || ext.TrustTier != runtime.TrustTierPartner {
		t.Fatalf("unexpected external agent: %+v", ext)
	}
	if ext.ID == "" {
		t.Fatalf("external agent must carry a persisted id")
	}

	// Duplicate external_agent_id conflicts.
	if _, err := stack.svc.OnboardExternalAgent(ctx, tenant, "principal:admin", true, runtime.ExternalAgentRequest{
		ExternalAgentID: "ext-demo-1", AgentID: paired.ID, OrganizationID: "acme-corp",
		VerifiedIssuer: "https://demo-issuer.example.com", AllowedAudiences: []string{"groundwork-api"},
		AuthMethod: runtime.ExternalAuthInternalDemo, Region: testRegion,
	}); err == nil {
		t.Fatalf("duplicate external agent must conflict")
	}

	// Lifecycle: suspend -> activate -> revoke (terminal).
	suspended, err := stack.svc.TransitionExternalAgent(ctx, tenant, ext.ExternalAgentID, "principal:admin", true, "suspend", runtime.TrustTransitionRequest{Reason: "review"})
	if err != nil || suspended.LifecycleState != runtime.ExternalStateSuspended {
		t.Fatalf("suspend: %+v (%v)", suspended, err)
	}
	if _, err := stack.svc.TransitionExternalAgent(ctx, tenant, ext.ExternalAgentID, "principal:admin", true, "suspend", runtime.TrustTransitionRequest{}); !errors.Is(err, runtime.ErrExternalInvalid) {
		t.Fatalf("expected invalid on double-suspend, got %v", err)
	}
	reactivated, err := stack.svc.TransitionExternalAgent(ctx, tenant, ext.ExternalAgentID, "principal:admin", true, "activate", runtime.TrustTransitionRequest{})
	if err != nil || reactivated.LifecycleState != runtime.ExternalStateActive {
		t.Fatalf("reactivate: %+v (%v)", reactivated, err)
	}
	revoked, err := stack.svc.TransitionExternalAgent(ctx, tenant, ext.ExternalAgentID, "principal:admin", true, "revoke", runtime.TrustTransitionRequest{Reason: "contract ended"})
	if err != nil || revoked.LifecycleState != runtime.ExternalStateRevoked {
		t.Fatalf("revoke: %+v (%v)", revoked, err)
	}

	// Tenant isolation.
	if _, err := stack.svc.GetExternalAgent(ctx, "tenant_other_"+unique(), ext.ExternalAgentID); !errors.Is(err, runtime.ErrExternalNotFound) {
		t.Fatalf("cross-tenant read must 404, got %v", err)
	}
	exts, err := stack.svc.ListExternalAgents(ctx, tenant)
	if err != nil || len(exts) != 1 || exts[0].LifecycleState != runtime.ExternalStateRevoked {
		t.Fatalf("expected 1 revoked external agent, got %+v (%v)", exts, err)
	}

	// Evidence: every transition produced a chained trust event.
	events, err := stack.svc.ListTrustEvents(ctx, tenant, 0)
	if err != nil {
		t.Fatalf("list trust events: %v", err)
	}
	if len(events) < 4 { // onboard, suspend, activate, revoke
		t.Fatalf("expected >= 4 trust events, got %d", len(events))
	}
	if problems := governance.VerifyTrustEventChain(events); len(problems) != 0 {
		t.Fatalf("external-agent trust chain failed verification: %+v", problems)
	}
}

// TestPhase6TrustPolicyObjectsPostgres covers the consent, transfer
// policy, and external budget admin surfaces against Postgres.
func TestPhase6TrustPolicyObjectsPostgres(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)
	ctx := context.Background()
	t.Setenv("GROUNDWORK_EXTERNAL_INTERNAL_DEMO", "true")
	tenant := "tenant_trust_pol_" + unique()
	stack := newTrustStack(t, db, nil)

	paired := stack.activateAgent(t, tenant, "pol-paired", "principal:owner")
	ext, err := stack.svc.OnboardExternalAgent(ctx, tenant, "principal:admin", true, runtime.ExternalAgentRequest{
		ExternalAgentID: "ext-pol-1", AgentID: paired.ID, OrganizationID: "acme-corp",
		VerifiedIssuer: "https://pol-issuer.example.com", AllowedAudiences: []string{"groundwork-api"},
		AuthMethod: runtime.ExternalAuthInternalDemo, TrustTier: runtime.TrustTierPartner, Region: testRegion,
	})
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	// --- Consent lifecycle ---
	consent, err := stack.svc.CreateConsentRecord(ctx, tenant, "principal:admin", true, runtime.ConsentRequest{
		OrganizationID: "acme-corp", ExternalAgentID: ext.ExternalAgentID,
		CustomerPrincipalID: "principal:customer-1", Purpose: "tax filing",
	})
	if err != nil {
		t.Fatalf("create consent: %v", err)
	}
	if consent.Status != "active" || consent.ResourceRefPattern != "*" || consent.ImmutableDigest == "" {
		t.Fatalf("unexpected consent: %+v", consent)
	}
	// Non-admin cannot revoke.
	if _, err := stack.svc.RevokeConsentRecord(ctx, tenant, consent.ID, "principal:owner", false, "no"); !errors.Is(err, runtime.ErrGovernanceNotAuthorized) {
		t.Fatalf("expected not authorized, got %v", err)
	}
	revokedConsent, err := stack.svc.RevokeConsentRecord(ctx, tenant, consent.ID, "principal:admin", true, "customer withdrew")
	if err != nil || revokedConsent.Status != "revoked" {
		t.Fatalf("revoke consent: %+v (%v)", revokedConsent, err)
	}
	if _, err := stack.svc.RevokeConsentRecord(ctx, tenant, consent.ID, "principal:admin", true, "again"); !errors.Is(err, runtime.ErrConsentRevoked) {
		t.Fatalf("expected consent revoked on re-revoke, got %v", err)
	}
	records, err := stack.svc.ListConsentRecords(ctx, tenant)
	if err != nil || len(records) != 1 || records[0].Status != "revoked" {
		t.Fatalf("expected 1 revoked consent record, got %+v (%v)", records, err)
	}
	got, err := stack.svc.GetConsentRecord(ctx, tenant, consent.ID)
	if err != nil || got.ID != consent.ID {
		t.Fatalf("get consent: %+v (%v)", got, err)
	}

	// --- Transfer policy lifecycle ---
	pol, err := stack.svc.UpsertTransferPolicy(ctx, tenant, "principal:admin", true, runtime.TransferPolicyRequest{
		SourceRegion: testRegion, TargetRegion: "eu", PurposePattern: "*", Enabled: false,
	})
	if err != nil {
		t.Fatalf("upsert policy: %v", err)
	}
	if pol.Enabled {
		t.Fatalf("policy must start disabled, got %+v", pol)
	}
	// Same source+target must be rejected.
	if _, err := stack.svc.UpsertTransferPolicy(ctx, tenant, "principal:admin", true, runtime.TransferPolicyRequest{
		SourceRegion: testRegion, TargetRegion: testRegion, PurposePattern: "*",
	}); !errors.Is(err, runtime.ErrInvalidRequest) {
		t.Fatalf("expected invalid request for same-region policy, got %v", err)
	}
	enabled, err := stack.svc.TransitionTransferPolicy(ctx, tenant, pol.ID, "principal:admin", true, "activate", runtime.TrustTransitionRequest{})
	if err != nil || !enabled.Enabled {
		t.Fatalf("activate policy: %+v (%v)", enabled, err)
	}
	if _, err := stack.svc.TransitionTransferPolicy(ctx, tenant, pol.ID, "principal:admin", true, "bogus", runtime.TrustTransitionRequest{}); !errors.Is(err, runtime.ErrTransferPolicyStateInvalid) {
		t.Fatalf("expected state invalid for bogus action, got %v", err)
	}
	disabled, err := stack.svc.TransitionTransferPolicy(ctx, tenant, pol.ID, "principal:admin", true, "suspend", runtime.TrustTransitionRequest{Reason: "audit"})
	if err != nil || disabled.Enabled {
		t.Fatalf("suspend policy: %+v (%v)", disabled, err)
	}
	policies, err := stack.svc.ListTransferPolicies(ctx, tenant)
	if err != nil || len(policies) != 1 || policies[0].Enabled {
		t.Fatalf("expected 1 disabled policy, got %+v (%v)", policies, err)
	}

	// --- External budget lifecycle ---
	bad, err := stack.svc.UpsertExternalBudget(ctx, tenant, "principal:admin", true, runtime.ExternalBudgetRequest{
		ScopeType: runtime.ExternalBudgetScopeCustomer, ExternalAgentID: ext.ExternalAgentID,
	})
	if !errors.Is(err, runtime.ErrInvalidRequest) {
		t.Fatalf("customer-scope budget without customer id must fail, got %v", err)
	}
	_ = bad
	budget, err := stack.svc.UpsertExternalBudget(ctx, tenant, "principal:admin", true, runtime.ExternalBudgetRequest{
		ScopeType: runtime.ExternalBudgetScopeAgent, ExternalAgentID: ext.ExternalAgentID,
		MaxTotalActions: 100, MaxActionsPerRun: 10,
	})
	if err != nil {
		t.Fatalf("upsert budget: %v", err)
	}
	if budget.ScopeType != runtime.ExternalBudgetScopeAgent || budget.MaxTotalActions != 100 {
		t.Fatalf("unexpected budget: %+v", budget)
	}
	// Upsert updates the same row (single policy per scope).
	budget2, err := stack.svc.UpsertExternalBudget(ctx, tenant, "principal:admin", true, runtime.ExternalBudgetRequest{
		ScopeType: runtime.ExternalBudgetScopeAgent, ExternalAgentID: ext.ExternalAgentID,
		MaxTotalActions: 200, MaxActionsPerRun: 20,
	})
	if err != nil || budget2.ID != budget.ID || budget2.MaxTotalActions != 200 {
		t.Fatalf("budget upsert must update in place: %+v (%v)", budget2, err)
	}
	budgets, err := stack.svc.ListExternalBudgets(ctx, tenant)
	if err != nil || len(budgets) != 1 {
		t.Fatalf("expected 1 budget, got %+v (%v)", budgets, err)
	}
}

// TestExternalRunPostgresLifecycle drives the full external path through
// Postgres: identity session, demo-path grant minting, allowed decision,
// nonce replay protection, budget counters, consent revocation gating,
// per-run budget denial, and termination.
func TestExternalRunPostgresLifecycle(t *testing.T) {
	requireFullStack(t)
	db := openDB(t)
	ctx := context.Background()
	t.Setenv("GROUNDWORK_EXTERNAL_INTERNAL_DEMO", "true")
	tenant := "tenant_ext_run_" + unique()
	client := newSpiceDBChecker(t)
	stack := newTrustStack(t, db, client)

	paired := stack.activateAgent(t, tenant, "run-paired", "principal:owner")
	toolName := "bank_tool_" + unique()
	toolID, _, toolName := stack.registerToolAndGrant(t, tenant, paired.ID, paired.ActiveVersionID, toolName)
	customerPrincipal := "customer-1"
	writeSpiceDBRelationship(t, client, tenant, "user:"+customerPrincipal, "use", "tool:"+toolID)
	action := toolName + ":run"

	ext, err := stack.svc.OnboardExternalAgent(ctx, tenant, "principal:admin", true, runtime.ExternalAgentRequest{
		ExternalAgentID: "ext-run-1", AgentID: paired.ID, OrganizationID: "acme-corp",
		VerifiedIssuer: "https://run-issuer.example.com", AllowedAudiences: []string{"groundwork-api"},
		AuthMethod: runtime.ExternalAuthInternalDemo, TrustTier: runtime.TrustTierPartner, Region: testRegion,
		AllowedToolsActions: []string{action},
	})
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	// Active trust edge tenant-agent -> external agent.
	rel, err := stack.svc.CreateTrustRelationship(ctx, tenant, "principal:owner", false, runtime.TrustRelationshipRequest{
		ParentAgentID: paired.ID, ExternalAgentID: ext.ExternalAgentID,
		TrustDomain: "external", Purpose: "tax filing",
		AllowedToolsActions: []string{action},
		Region:              testRegion,
		ExpiresAt:           time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("create external relationship: %v", err)
	}
	if _, err := stack.svc.TransitionTrustRelationship(ctx, tenant, rel.ID, "principal:owner", false, "activate", runtime.TrustTransitionRequest{}); err != nil {
		t.Fatalf("activate relationship: %v", err)
	}

	// Customer consent + per-agent budget.
	consent, err := stack.svc.CreateConsentRecord(ctx, tenant, "principal:admin", true, runtime.ConsentRequest{
		OrganizationID: "acme-corp", ExternalAgentID: ext.ExternalAgentID,
		CustomerPrincipalID: customerPrincipal, Purpose: "tax filing",
	})
	if err != nil {
		t.Fatalf("create consent: %v", err)
	}
	if _, err := stack.svc.UpsertExternalBudget(ctx, tenant, "principal:admin", true, runtime.ExternalBudgetRequest{
		ScopeType: runtime.ExternalBudgetScopeAgent, ExternalAgentID: ext.ExternalAgentID,
		MaxTotalActions: 100, MaxActionsPerRun: 2,
	}); err != nil {
		t.Fatalf("upsert budget: %v", err)
	}

	// Identity session: token -> validated external identity.
	token1 := demoExternalToken(t, ext, customerPrincipal, "tax filing", "jti-run-1")
	session, err := stack.svc.VerifyExternalSession(ctx, tenant, testRegion, runtime.ExternalSessionRequest{Token: token1})
	if err != nil {
		t.Fatalf("verify session: %v", err)
	}
	if session.ExternalAgentID != ext.ExternalAgentID || session.CustomerPrincipalID != customerPrincipal ||
		session.Purpose != "tax filing" || session.Subject != ext.ExternalAgentID || session.JTI != "jti-run-1" {
		t.Fatalf("unexpected session: %+v", session)
	}

	// Full external run (demo path mints the grant server-side).
	run, err := stack.svc.CreateExternalRun(ctx, tenant, testRegion, "extrun-"+unique(), runtime.CreateExternalRunRequest{
		ExternalToken: token1,
		Actions:       []runtime.RunActionRequest{{ToolName: toolName, Action: "run", ResourceRef: "*"}},
	})
	if err != nil {
		t.Fatalf("create external run: %v", err)
	}
	if run.Run.ExternalAgentID != ext.ExternalAgentID || run.Run.CustomerPrincipalID != customerPrincipal ||
		run.Run.Status != runtime.RunStatusRunning || run.Run.ConsentID != consent.ID {
		t.Fatalf("unexpected run: %+v\ndecisions: %+v", run.Run, run.Decisions)
	}
	if len(run.Decisions) != 1 || run.Decisions[0].Decision != runtime.DecisionAllowed {
		t.Fatalf("expected 1 allowed decision, got %+v", run.Decisions)
	}

	// The demo-path grant is persisted and consumed by this run.
	grants, err := stack.svc.ListDelegationGrants(ctx, tenant)
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	var externalGrant *runtime.DelegationGrant
	for i := range grants {
		if grants[i].ExternalAgentID == ext.ExternalAgentID {
			externalGrant = &grants[i]
		}
	}
	if externalGrant == nil || externalGrant.RunID != run.Run.ID || externalGrant.IssuedVia != "external" ||
		externalGrant.SubjectPrincipalID != customerPrincipal {
		t.Fatalf("external grant must be bound to the run: %+v", externalGrant)
	}

	// Budget counters were incremented by the run.
	budgets, err := stack.svc.ListExternalBudgets(ctx, tenant)
	if err != nil || len(budgets) != 1 || budgets[0].ActionsCount < 1 {
		t.Fatalf("budget counters not incremented: %+v (%v)", budgets, err)
	}

	// Decision evidence for the run is on the evidence chain.
	ev, err := stack.govStore.QueryEvidence(ctx, tenant, runtime.EvidenceFilter{Kinds: []string{runtime.EvidenceKindDecision}, Limit: 100})
	if err != nil {
		t.Fatalf("query decision evidence: %v", err)
	}
	found := false
	for _, e := range ev {
		if e.RunID == run.Run.ID && e.Decision == runtime.DecisionAllowed {
			found = true
			if e.ImmutableDigest == "" {
				t.Fatalf("decision evidence missing digest: %+v", e)
			}
		}
	}
	if !found {
		t.Fatalf("allowed decision evidence missing for external run")
	}

	// Nonce replay: the same identity token cannot be used twice.
	if _, err := stack.svc.CreateExternalRun(ctx, tenant, testRegion, "extrun-"+unique(), runtime.CreateExternalRunRequest{
		ExternalToken: token1,
		Actions:       []runtime.RunActionRequest{{ToolName: toolName, Action: "run", ResourceRef: "*"}},
	}); !errors.Is(err, runtime.ErrNonceReplay) {
		t.Fatalf("expected nonce replay, got %v", err)
	}

	// Per-run budget gate: 3 actions exceed max_actions_per_run=2.
	token2 := demoExternalToken(t, ext, customerPrincipal, "tax filing", "jti-run-2")
	if _, err := stack.svc.CreateExternalRun(ctx, tenant, testRegion, "extrun-"+unique(), runtime.CreateExternalRunRequest{
		ExternalToken: token2,
		Actions: []runtime.RunActionRequest{
			{ToolName: toolName, Action: "run", ResourceRef: "*"},
			{ToolName: toolName, Action: "run", ResourceRef: "*"},
			{ToolName: toolName, Action: "run", ResourceRef: "*"},
		},
	}); !errors.Is(err, runtime.ErrDelegationNotAllowed) {
		t.Fatalf("expected per-run budget denial, got %v", err)
	}

	// Consent revocation gates the next run pre-evaluation.
	if _, err := stack.svc.RevokeConsentRecord(ctx, tenant, consent.ID, "principal:admin", true, "customer withdrew"); err != nil {
		t.Fatalf("revoke consent: %v", err)
	}
	token3 := demoExternalToken(t, ext, customerPrincipal, "tax filing", "jti-run-3")
	if _, err := stack.svc.CreateExternalRun(ctx, tenant, testRegion, "extrun-"+unique(), runtime.CreateExternalRunRequest{
		ExternalToken: token3,
		Actions:       []runtime.RunActionRequest{{ToolName: toolName, Action: "run", ResourceRef: "*"}},
	}); !errors.Is(err, runtime.ErrConsentRequired) {
		t.Fatalf("expected consent required, got %v", err)
	}

	// A suspended external agent fails closed at the session gate.
	if _, err := stack.svc.TransitionExternalAgent(ctx, tenant, ext.ExternalAgentID, "principal:admin", true, "revoke", runtime.TrustTransitionRequest{Reason: "ended"}); err != nil {
		t.Fatalf("revoke external: %v", err)
	}
	token4 := demoExternalToken(t, ext, customerPrincipal, "tax filing", "jti-run-4")
	if _, err := stack.svc.VerifyExternalSession(ctx, tenant, testRegion, runtime.ExternalSessionRequest{Token: token4}); !errors.Is(err, runtime.ErrExternalNotActive) {
		t.Fatalf("expected not-active fail closed, got %v", err)
	}

	// Terminate the running external run; evidence + control recorded.
	terminated, err := stack.svc.TerminateExternalRun(ctx, tenant, run.Run.ID, "principal:admin", true, runtime.ControlRequest{Reason: "incident"})
	if err != nil {
		t.Fatalf("terminate external run: %v", err)
	}
	if terminated.ControlState != runtime.ControlStateRevoked {
		t.Fatalf("unexpected control state: %+v", terminated)
	}
	gotRun, gotDecisions, err := stack.svc.GetExternalRun(ctx, tenant, run.Run.ID)
	if err != nil {
		t.Fatalf("get external run: %v", err)
	}
	if gotRun.Status != runtime.RunStatusRevoked || len(gotDecisions) != 1 {
		t.Fatalf("run must be revoked with its decisions: %+v (%d)", gotRun, len(gotDecisions))
	}

	// The whole tenant trust chain still verifies after everything.
	events, err := stack.svc.ListTrustEvents(ctx, tenant, 0)
	if err != nil {
		t.Fatalf("list trust events: %v", err)
	}
	if len(events) < 6 {
		t.Fatalf("expected >= 6 trust events, got %d", len(events))
	}
	if problems := governance.VerifyTrustEventChain(events); len(problems) != 0 {
		t.Fatalf("external-run trust chain failed verification: %+v", problems)
	}
}

// demoExternalToken mints an internal_demo identity token signed with
// the same HS256 secret the governance authority was built from.
func demoExternalToken(t *testing.T, external runtime.ExternalAgent, cid, purpose, jti string) string {
	t.Helper()
	now := time.Now().Unix()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": external.VerifiedIssuer,
		"sub": external.ExternalAgentID,
		"aud": "groundwork-api",
		"exp": now + 3600,
		"iat": now,
		"jti": jti,
		"cid": cid,
		"pur": purpose,
	})
	signed, err := tok.SignedString([]byte("integration-hs-secret-0123456789abcdef"))
	if err != nil {
		t.Fatalf("sign external token: %v", err)
	}
	return signed
}
