package agentregistry

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"groundwork/query-runtime/internal/runtime"
)

func newTestService() (*Service, *MemoryStore) {
	store := NewMemoryStore()
	return NewService(store), store
}

const (
	tenantA = "tenant_demo"
	tenantB = "tenant_other"
	owner   = "principal:alice"
	admin   = "principal:admin"
	other   = "principal:mallory"
)

func createDraftAgent(t *testing.T, svc *Service, tenantID, actor, name string) runtime.Agent {
	t.Helper()
	agent, err := svc.CreateAgent(context.Background(), tenantID, actor, runtime.CreateAgentRequest{
		Name: name, RiskTier: runtime.RiskTierMedium, Environment: runtime.EnvDevelopment,
	})
	if err != nil {
		t.Fatalf("create agent %q: %v", name, err)
	}
	if agent.LifecycleState != runtime.AgentStateDraft {
		t.Fatalf("new agent must land in draft, got %s", agent.LifecycleState)
	}
	if agent.OwnerPrincipalID != actor {
		t.Fatalf("owner must default to actor, got %s", agent.OwnerPrincipalID)
	}
	if agent.TenantID != tenantID {
		t.Fatalf("agent tenant must be %s, got %s", tenantID, agent.TenantID)
	}
	return agent
}

func addVersion(t *testing.T, svc *Service, tenantID, agentID, actor, version string) runtime.AgentVersion {
	t.Helper()
	v, err := svc.AddVersion(context.Background(), tenantID, agentID, actor, false, runtime.AddAgentVersionRequest{Version: version})
	if err != nil {
		t.Fatalf("add version %s: %v", version, err)
	}
	if v.Status != runtime.VersionStatusDraft {
		t.Fatalf("new version must be draft, got %s", v.Status)
	}
	return v
}

func TestCreateAgentValidation(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	if _, err := svc.CreateAgent(ctx, tenantA, owner, runtime.CreateAgentRequest{RiskTier: "low"}); !errors.Is(err, runtime.ErrAgentInvalidRequest) {
		t.Fatalf("empty name: expected ErrAgentInvalidRequest, got %v", err)
	}
	if _, err := svc.CreateAgent(ctx, tenantA, owner, runtime.CreateAgentRequest{Name: "x", RiskTier: "extreme"}); !errors.Is(err, runtime.ErrAgentInvalidRequest) {
		t.Fatalf("bad risk tier: expected ErrAgentInvalidRequest, got %v", err)
	}
	if _, err := svc.CreateAgent(ctx, tenantA, owner, runtime.CreateAgentRequest{Name: "x", RiskTier: "low", Environment: "moon"}); !errors.Is(err, runtime.ErrAgentInvalidRequest) {
		t.Fatalf("bad environment: expected ErrAgentInvalidRequest, got %v", err)
	}
	if _, err := svc.CreateAgent(ctx, tenantA, "", runtime.CreateAgentRequest{Name: "x", RiskTier: "low"}); !errors.Is(err, runtime.ErrAgentInvalidRequest) {
		t.Fatalf("no actor and no owner: expected ErrAgentInvalidRequest, got %v", err)
	}
	// Risk tier case-insensitive, environment defaults to development.
	a, err := svc.CreateAgent(ctx, tenantA, owner, runtime.CreateAgentRequest{Name: "ok", RiskTier: "HIGH"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.RiskTier != runtime.RiskTierHigh || a.Environment != runtime.EnvDevelopment {
		t.Fatalf("tier/env normalization wrong: %s/%s", a.RiskTier, a.Environment)
	}
}

func TestCreateAgentNameConflictPerTenant(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	createDraftAgent(t, svc, tenantA, owner, "treasury-bot")
	// Same name in a different tenant is fine.
	createDraftAgent(t, svc, tenantB, owner, "treasury-bot")
	// Same tenant collides.
	if _, err := svc.CreateAgent(ctx, tenantA, owner, runtime.CreateAgentRequest{Name: "treasury-bot", RiskTier: "low"}); !errors.Is(err, runtime.ErrAgentNameConflict) {
		t.Fatalf("expected ErrAgentNameConflict, got %v", err)
	}
}

func TestTenantIsolation(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	agent := createDraftAgent(t, svc, tenantA, owner, "iso-agent")

	if _, _, _, err := svc.GetAgent(ctx, tenantB, agent.ID); !errors.Is(err, runtime.ErrAgentNotFound) {
		t.Fatalf("tenant B must not see tenant A agent, got %v", err)
	}
	if agents, err := svc.ListAgents(ctx, tenantB, ""); err != nil || len(agents) != 0 {
		t.Fatalf("tenant B must see an empty list, got %d err=%v", len(agents), err)
	}
	// Cross-tenant transition attempts must not leak existence.
	if _, err := svc.ActivateAgent(ctx, tenantB, agent.ID, owner, true, ""); !errors.Is(err, runtime.ErrAgentNotFound) {
		t.Fatalf("cross-tenant transition must 404, got %v", err)
	}
	// A second tenant can use the same agent name.
	createDraftAgent(t, svc, tenantB, owner, "iso-agent")
}

func TestAddVersionAuthorization(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	agent := createDraftAgent(t, svc, tenantA, owner, "authz-agent")

	if _, err := svc.AddVersion(ctx, tenantA, agent.ID, other, false, runtime.AddAgentVersionRequest{Version: "1.0.0"}); !errors.Is(err, runtime.ErrAgentNotAuthorized) {
		t.Fatalf("non-owner non-admin must be denied, got %v", err)
	}
	// Admin scope overrides.
	if _, err := svc.AddVersion(ctx, tenantA, agent.ID, other, true, runtime.AddAgentVersionRequest{Version: "1.0.0"}); err != nil {
		t.Fatalf("admin should be allowed: %v", err)
	}
}

func TestAddVersionValidation(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	agent := createDraftAgent(t, svc, tenantA, owner, "ver-agent")

	if _, err := svc.AddVersion(ctx, tenantA, agent.ID, owner, false, runtime.AddAgentVersionRequest{Version: "  "}); !errors.Is(err, runtime.ErrAgentInvalidRequest) {
		t.Fatalf("empty version: expected ErrAgentInvalidRequest, got %v", err)
	}
	addVersion(t, svc, tenantA, agent.ID, owner, "1.0.0")
	if _, err := svc.AddVersion(ctx, tenantA, agent.ID, owner, false, runtime.AddAgentVersionRequest{Version: "1.0.0"}); !errors.Is(err, runtime.ErrAgentVersionConflict) {
		t.Fatalf("duplicate version: expected ErrAgentVersionConflict, got %v", err)
	}
}

func TestActivatePromotesNewestUsableVersion(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	agent := createDraftAgent(t, svc, tenantA, owner, "promote-agent")

	// Activation without any version must fail.
	if _, err := svc.ActivateAgent(ctx, tenantA, agent.ID, owner, false, ""); !errors.Is(err, runtime.ErrAgentInvalidTransition) {
		t.Fatalf("activate with no version: expected ErrAgentInvalidTransition, got %v", err)
	}

	v1 := addVersion(t, svc, tenantA, agent.ID, owner, "1.0.0")
	activated, err := svc.ActivateAgent(ctx, tenantA, agent.ID, owner, false, "first ship")
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if activated.LifecycleState != runtime.AgentStateActive || activated.ActivatedAt.IsZero() {
		t.Fatalf("agent must be active with activated_at set: %+v", activated)
	}
	if activated.ActiveVersionID != v1.ID {
		t.Fatalf("active version must be the promoted one, got %s want %s", activated.ActiveVersionID, v1.ID)
	}
	if activated.ActiveVersion != "1.0.0" {
		t.Fatalf("expected active version label 1.0.0, got %s", activated.ActiveVersion)
	}

	// Adding a version to an ACTIVE agent immediately supersedes the
	// current active version (service AddVersion).
	v2 := addVersion(t, svc, tenantA, agent.ID, owner, "2.0.0")
	gotVersions, err := svc.store.ListVersions(ctx, tenantA, agent.ID)
	if err != nil {
		t.Fatalf("list versions: %v", err)
	}
	for _, v := range gotVersions {
		switch v.ID {
		case v1.ID:
			if v.Status != runtime.VersionStatusSuperseded {
				t.Fatalf("adding v2 to an active agent must supersede v1, got %s", v.Status)
			}
		case v2.ID:
			if v.Status != runtime.VersionStatusDraft {
				t.Fatalf("new version must stay draft, got %s", v.Status)
			}
		}
	}

	// Activation only from draft|pending_approval|suspended; an active
	// agent must be suspended first, then the newest usable version
	// (v2) is promoted.
	if _, err := svc.ActivateAgent(ctx, tenantA, agent.ID, owner, false, "v2"); !errors.Is(err, runtime.ErrAgentInvalidTransition) {
		t.Fatalf("double activation must be invalid, got %v", err)
	}
	if _, err := svc.SuspendAgent(ctx, tenantA, agent.ID, owner, false, "promote v2"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	activated2, err := svc.ActivateAgent(ctx, tenantA, agent.ID, owner, false, "v2")
	if err != nil {
		t.Fatalf("re-activate: %v", err)
	}
	if activated2.ActiveVersionID != v2.ID {
		t.Fatalf("active version must roll to 2.0.0, got %s", activated2.ActiveVersion)
	}
	gotVersions, err = svc.store.ListVersions(ctx, tenantA, agent.ID)
	if err != nil {
		t.Fatalf("list versions: %v", err)
	}
	for _, v := range gotVersions {
		switch v.ID {
		case v1.ID:
			if v.Status != runtime.VersionStatusSuperseded {
				t.Fatalf("v1 must be superseded after v2 activation, got %s", v.Status)
			}
		case v2.ID:
			if v.Status != runtime.VersionStatusActive {
				t.Fatalf("v2 must be active, got %s", v.Status)
			}
		}
	}
}

func TestActivateFromSuspendedResumesActiveVersion(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	agent := createDraftAgent(t, svc, tenantA, owner, "resume-agent")
	v := addVersion(t, svc, tenantA, agent.ID, owner, "1.0.0")
	if _, err := svc.ActivateAgent(ctx, tenantA, agent.ID, owner, false, ""); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if _, err := svc.SuspendAgent(ctx, tenantA, agent.ID, owner, false, "change freeze"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	resumed, err := svc.ActivateAgent(ctx, tenantA, agent.ID, owner, false, "")
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if resumed.ActiveVersionID != v.ID {
		t.Fatalf("resume must keep the same active version, got %s want %s", resumed.ActiveVersionID, v.ID)
	}
}

func TestTransitionAuthorizationAndInvalid(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	agent := createDraftAgent(t, svc, tenantA, owner, "trans-agent")

	// Non-owner, non-admin cannot transition anything.
	for _, tc := range []struct {
		name string
		fn   func() error
	}{
		{"activate", func() error { _, err := svc.ActivateAgent(ctx, tenantA, agent.ID, other, false, ""); return err }},
		{"suspend", func() error { _, err := svc.SuspendAgent(ctx, tenantA, agent.ID, other, false, ""); return err }},
		{"revoke", func() error { _, err := svc.RevokeAgent(ctx, tenantA, agent.ID, other, false, ""); return err }},
		{"retire", func() error { _, err := svc.RetireAgent(ctx, tenantA, agent.ID, other, false, ""); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); !errors.Is(err, runtime.ErrAgentNotAuthorized) {
				t.Fatalf("expected ErrAgentNotAuthorized, got %v", err)
			}
		})
	}

	// Admin scope allows a non-owner to transition.
	if _, err := svc.ActivateAgent(ctx, tenantA, agent.ID, admin, true, ""); !errors.Is(err, runtime.ErrAgentInvalidTransition) {
		t.Fatalf("admin reached service but activation must still fail without a version, got %v", err)
	}

	// Draft cannot be suspended.
	if _, err := svc.SuspendAgent(ctx, tenantA, agent.ID, owner, false, ""); !errors.Is(err, runtime.ErrAgentInvalidTransition) {
		t.Fatalf("draft->suspended must be invalid, got %v", err)
	}
	// Invalid state filter.
	if _, err := svc.ListAgents(ctx, tenantA, "banana"); !errors.Is(err, runtime.ErrAgentInvalidRequest) {
		t.Fatalf("bad state filter: expected ErrAgentInvalidRequest, got %v", err)
	}
}

func TestRevokeIsIrreversible(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	agent := createDraftAgent(t, svc, tenantA, owner, "revoke-agent")
	addVersion(t, svc, tenantA, agent.ID, owner, "1.0.0")

	revoked, err := svc.RevokeAgent(ctx, tenantA, agent.ID, owner, false, "compromise")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.LifecycleState != runtime.AgentStateRevoked || revoked.RevokedAt.IsZero() {
		t.Fatalf("agent must be revoked with revoked_at set: %+v", revoked)
	}
	// Every version is revoked too.
	versions, err := svc.store.ListVersions(ctx, tenantA, agent.ID)
	if err != nil {
		t.Fatalf("list versions: %v", err)
	}
	if len(versions) != 1 || versions[0].Status != runtime.VersionStatusRevoked {
		t.Fatalf("versions must all be revoked, got %+v", versions)
	}

	// No further transitions, no new versions, no un-revocation.
	if _, err := svc.ActivateAgent(ctx, tenantA, agent.ID, owner, false, ""); !errors.Is(err, runtime.ErrAgentInvalidTransition) {
		t.Fatalf("activate revoked: expected invalid transition, got %v", err)
	}
	if _, err := svc.RetireAgent(ctx, tenantA, agent.ID, owner, false, ""); !errors.Is(err, runtime.ErrAgentInvalidTransition) {
		t.Fatalf("retire revoked: expected invalid transition, got %v", err)
	}
	if _, err := svc.RevokeAgent(ctx, tenantA, agent.ID, owner, false, ""); !errors.Is(err, runtime.ErrAgentInvalidTransition) {
		t.Fatalf("double revoke: expected invalid transition, got %v", err)
	}
	if _, err := svc.AddVersion(ctx, tenantA, agent.ID, owner, false, runtime.AddAgentVersionRequest{Version: "2.0.0"}); !errors.Is(err, runtime.ErrAgentInvalidTransition) {
		t.Fatalf("add version to revoked agent: expected invalid transition, got %v", err)
	}
}

func TestRetireIsTerminal(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	agent := createDraftAgent(t, svc, tenantA, owner, "retire-agent")

	retired, err := svc.RetireAgent(ctx, tenantA, agent.ID, owner, false, "end of life")
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if retired.LifecycleState != runtime.AgentStateRetired {
		t.Fatalf("expected retired, got %s", retired.LifecycleState)
	}
	if _, err := svc.ActivateAgent(ctx, tenantA, agent.ID, owner, false, ""); !errors.Is(err, runtime.ErrAgentInvalidTransition) {
		t.Fatalf("activate retired: expected invalid transition, got %v", err)
	}
	if _, err := svc.RetireAgent(ctx, tenantA, agent.ID, owner, false, ""); !errors.Is(err, runtime.ErrAgentInvalidTransition) {
		t.Fatalf("double retire: expected invalid transition, got %v", err)
	}
	// A retired agent can still be... nothing: no versions either.
	if _, err := svc.AddVersion(ctx, tenantA, agent.ID, owner, false, runtime.AddAgentVersionRequest{Version: "1.0.0"}); !errors.Is(err, runtime.ErrAgentInvalidTransition) {
		t.Fatalf("add version to retired agent: expected invalid transition, got %v", err)
	}
}

func TestListAgentsFiltersAndEnrichment(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	createDraftAgent(t, svc, tenantA, owner, "list-a")
	draft := createDraftAgent(t, svc, tenantA, owner, "list-b")
	addVersion(t, svc, tenantA, draft.ID, owner, "1.0.0")
	if _, err := svc.ActivateAgent(ctx, tenantA, draft.ID, owner, false, ""); err != nil {
		t.Fatalf("activate: %v", err)
	}

	all, err := svc.ListAgents(ctx, tenantA, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(all))
	}
	for _, a := range all {
		switch a.Name {
		case "list-a": // draft, never shipped a version
			if a.VersionCount != 0 || a.ActiveVersion != "" {
				t.Fatalf("list-a must have 0 versions and no active version, got count=%d active=%q", a.VersionCount, a.ActiveVersion)
			}
		case "list-b": // active with one version
			if a.VersionCount != 1 || a.LifecycleState != runtime.AgentStateActive || a.ActiveVersion == "" {
				t.Fatalf("list-b must be active with 1 version, got state=%s count=%d active=%q", a.LifecycleState, a.VersionCount, a.ActiveVersion)
			}
		}
	}
	activeOnly, err := svc.ListAgents(ctx, tenantA, "active")
	if err != nil || len(activeOnly) != 1 {
		t.Fatalf("expected 1 active agent, got %d err=%v", len(activeOnly), err)
	}
}

func TestEventChainIsTamperEvident(t *testing.T) {
	svc, store := newTestService()
	ctx := context.Background()
	agent := createDraftAgent(t, svc, tenantA, owner, "chain-agent")
	addVersion(t, svc, tenantA, agent.ID, owner, "1.0.0")
	if _, err := svc.ActivateAgent(ctx, tenantA, agent.ID, owner, false, "ship it"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if _, err := svc.SuspendAgent(ctx, tenantA, agent.ID, owner, false, "freeze"); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	events, err := store.ListEvents(ctx, tenantA, agent.ID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	// created, version_created, version_approved, version_activated, activated, suspended
	if len(events) != 6 {
		t.Fatalf("expected 6 events, got %d: %+v", len(events), events)
	}
	if problems := VerifyEventChain(events); len(problems) != 0 {
		t.Fatalf("clean chain must verify: %+v", problems)
	}
	// Every event's digest must reference its predecessor (chain linkage).
	for i := 1; i < len(events); i++ {
		if recomputed := ComputeEventDigest(events[i], events[i-1].ImmutableDigest); recomputed != events[i].ImmutableDigest {
			t.Fatalf("event %d does not chain to event %d", i, i-1)
		}
	}
	// Tampering with a field is detected.
	tampered := events[1]
	tampered.Reason = "forged"
	problems := VerifyEventChain([]runtime.LifecycleEvent{events[0], tampered, events[2]})
	if len(problems) == 0 {
		t.Fatal("field tampering must be detected")
	}
	// Deleting a middle event is detected (successor digest no longer recomputes).
	if problems := VerifyEventChain([]runtime.LifecycleEvent{events[0], events[2]}); len(problems) == 0 {
		t.Fatal("event deletion must break the chain")
	}
	// Reordering is detected.
	reordered := []runtime.LifecycleEvent{events[0], events[2], events[1], events[3], events[4], events[5]}
	if problems := VerifyEventChain(reordered); len(problems) == 0 {
		t.Fatal("reordering must break the chain")
	}
}

func TestEventChainCoversReasonAndActor(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	agent := createDraftAgent(t, svc, tenantA, owner, "chain-actor")
	addVersion(t, svc, tenantA, agent.ID, owner, "1.0.0")
	if _, err := svc.ActivateAgent(ctx, tenantA, agent.ID, owner, false, "with-reason"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	_, _, events, err := svc.GetAgent(ctx, tenantA, agent.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	activated := events[len(events)-1]
	if activated.EventType != runtime.EventActivated || activated.Reason != "with-reason" || activated.ActorPrincipal != owner {
		t.Fatalf("activated event must carry reason+actor: %+v", activated)
	}
	if activated.PreviousState != runtime.AgentStateDraft || activated.NewState != runtime.AgentStateActive {
		t.Fatalf("event must record the state change: %s -> %s", activated.PreviousState, activated.NewState)
	}
}

func TestOwnerPrincipalIDFromBodyIsLabel(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	// The body's owner_principal_id is honored as the ownership label
	// (defaulting to the actor when omitted). The actor who calls
	// CreateAgent is NOT implicitly the owner when an explicit owner is
	// asserted — authorization still keys off the label.
	agent, err := svc.CreateAgent(ctx, tenantA, owner, runtime.CreateAgentRequest{
		Name: "owner-agent", RiskTier: "low", OwnerPrincipalID: "someone-else",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if agent.OwnerPrincipalID != "someone-else" {
		t.Fatalf("explicit owner must be honored when provided, got %s", agent.OwnerPrincipalID)
	}
	// The asserted owner can manage the agent (activation fails on the
	// missing version, not on authorization).
	if _, err := svc.ActivateAgent(ctx, tenantA, agent.ID, "someone-else", false, ""); !errors.Is(err, runtime.ErrAgentInvalidTransition) {
		t.Fatalf("expected no-version activation failure (authz passed for owner), got %v", err)
	}
	// The creator actor and mallory are not owners and must be denied.
	for _, attacker := range []string{owner, other} {
		if _, err := svc.RetireAgent(ctx, tenantA, agent.ID, attacker, false, ""); !errors.Is(err, runtime.ErrAgentNotAuthorized) {
			t.Fatalf("%s must be denied, got %v", attacker, err)
		}
	}
}

func TestNamesAreTrimmed(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	a, err := svc.CreateAgent(ctx, tenantA, owner, runtime.CreateAgentRequest{Name: "  padded  ", RiskTier: "low"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if strings.TrimSpace(a.Name) != "padded" || a.Name != "padded" {
		t.Fatalf("name must be trimmed, got %q", a.Name)
	}
}

func TestLifecycleEventsReachOutbox(t *testing.T) {
	svc, store := newTestService()
	ctx := context.Background()

	agent := createDraftAgent(t, svc, tenantA, owner, "outbox-agent")
	addVersion(t, svc, tenantA, agent.ID, owner, "1.0.0")
	if _, err := svc.ActivateAgent(ctx, tenantA, agent.ID, owner, false, "activate it"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if _, err := svc.SuspendAgent(ctx, tenantA, agent.ID, owner, false, "freeze it"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if _, err := svc.RevokeAgent(ctx, tenantA, agent.ID, admin, true, "security"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	events, err := store.ListEvents(ctx, tenantA, agent.ID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	got, err := store.ListOutboxEvents(ctx, tenantA)
	if err != nil {
		t.Fatalf("list outbox: %v", err)
	}

	// One outbox event per lifecycle chain event, same ordering, same
	// event ids — the outbox must never be ahead of or behind the chain.
	if len(got) != len(events) {
		t.Fatalf("expected %d outbox events for %d lifecycle events, got %d", len(events), len(events), len(got))
	}
	for i, e := range got {
		chain := events[len(events)-1-i]
		if e.EventID != chain.ID {
			t.Fatalf("outbox event %d must carry the chain event id %s, got %s", i, chain.ID, e.EventID)
		}
		if e.EventType != runtime.OutboxEventAgentLifecycle {
			t.Fatalf("outbox event %d must be agent.lifecycle, got %s", i, e.EventType)
		}
		if e.TenantID != tenantA || e.OccurredAt != chain.CreatedAt {
			t.Fatalf("outbox event %d must mirror tenant + occurred_at", i)
		}
		if len(e.Payload) == 0 || bytes.Contains(e.Payload, []byte(chain.ImmutableDigest)) {
			t.Fatalf("outbox payload must be safe metadata only (no digest), got %s", e.Payload)
		}
	}

	// The newest outbox event is the revoke (list is newest-first).
	last := got[0]
	if !strings.Contains(string(last.Payload), `"to":"revoked"`) {
		t.Fatalf("last event must record the revoked state, got %s", last.Payload)
	}

	// Enqueueing the same chain event again is a no-op (idempotent).
	if err := store.EnqueueOutbox(ctx, lifecycleOutboxEvent(events[0])); err != nil {
		t.Fatalf("re-enqueue: %v", err)
	}
	got, err = store.ListOutboxEvents(ctx, tenantA)
	if err != nil {
		t.Fatalf("list outbox: %v", err)
	}
	if len(got) != len(events) {
		t.Fatalf("idempotent re-enqueue must not duplicate, got %d events", len(got))
	}

	// The other tenant sees nothing (tenant isolation).
	otherTenant, err := store.ListOutboxEvents(ctx, tenantB)
	if err != nil {
		t.Fatalf("list other tenant: %v", err)
	}
	if len(otherTenant) != 0 {
		t.Fatalf("outbox must be tenant-isolated, got %d events for %s", len(otherTenant), tenantB)
	}
}
