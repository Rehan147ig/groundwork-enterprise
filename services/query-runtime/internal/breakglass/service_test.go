// Four-eyes break-glass approval flow (Milestone 5): a grant opened
// with admin2_id waits in pending_approval without a minted key; only
// the exact second admin can activate it (approve) or terminate it
// (reject); every transition appends hash-chained evidence and the key
// is minted/bound only at activation.

package breakglass

import (
	"context"
	"errors"
	"testing"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

const (
	testTenant  = "tenant-acme"
	testRegion  = "US"
	admin1      = "principal:alice"
	secondAdmin = "slack:UADMIN2"
)

func testService(t *testing.T, keys *runtime.MemoryAPIKeyResolver) *Service {
	t.Helper()
	return NewService(NewMemoryStore(), keys, 60*time.Minute)
}

func fourEyesHarness(t *testing.T) (*Service, *runtime.MemoryAPIKeyResolver, runtime.TenantContext) {
	t.Helper()
	keys := runtime.NewMemoryAPIKeyResolver("sk-admin", runtime.TenantContext{TenantID: testTenant, Region: testRegion})
	return testService(t, keys), keys, runtime.TenantContext{TenantID: testTenant, Region: testRegion}
}

func TestOpenFourEyesWaitsForSecondAdmin(t *testing.T) {
	svc, keys, tenant := fourEyesHarness(t)
	grant, mintedKey, err := svc.Open(context.Background(), tenant, admin1, runtime.OpenBreakGlassRequest{
		Reason:          "prod incident",
		DurationMinutes: 30,
		Admin2ID:        secondAdmin,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if grant.Status != runtime.BreakGlassStatusPendingApproval {
		t.Fatalf("status = %q, want pending_approval", grant.Status)
	}
	if grant.PendingApprovalBy != secondAdmin {
		t.Fatalf("pending_approval_by = %q, want %q", grant.PendingApprovalBy, secondAdmin)
	}
	if grant.Approver1 != admin1 {
		t.Fatalf("approver1 = %q, want %q", grant.Approver1, admin1)
	}
	if mintedKey != "" || grant.KeyID != 0 {
		t.Fatalf("pending grant must not carry a live key (key=%q id=%d)", mintedKey, grant.KeyID)
	}
	// The key store must have exactly the bootstrap key: the pending
	// grant minted nothing.
	if _, err := keys.Resolve(context.Background(), mintedKey); !errors.Is(err, runtime.ErrInvalidAPIKey) {
		t.Fatalf("unexpected resolver behavior: %v", err)
	}
	events, err := svc.store.ListEvents(context.Background(), testTenant, grant.ID)
	if err != nil || len(events) != 1 || events[0].EventType != runtime.BreakGlassEventOpened {
		t.Fatalf("events = %v (%v), want one 'opened'", events, err)
	}
}

func TestApproveByWrongActorForbidden(t *testing.T) {
	svc, _, tenant := fourEyesHarness(t)
	grant, _, err := svc.Open(context.Background(), tenant, admin1, runtime.OpenBreakGlassRequest{
		Reason:          "prod incident",
		DurationMinutes: 30,
		Admin2ID:        secondAdmin,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, _, err = svc.Approve(context.Background(), tenant, grant.ID, "slack:INTRUDER")
	if !errors.Is(err, runtime.ErrBreakGlassForbidden) {
		t.Fatalf("approve by non-admin2: err = %v, want ErrBreakGlassForbidden", err)
	}
	// The intruder must not have minted anything.
	g, _, err := svc.Get(context.Background(), testTenant, grant.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if g.Status != runtime.BreakGlassStatusPendingApproval || g.KeyID != 0 {
		t.Fatalf("grant state changed after forbidden approve: %+v", g)
	}
}

func TestApproveActivatesAndMintsKeyOnce(t *testing.T) {
	svc, _, tenant := fourEyesHarness(t)
	grant, _, err := svc.Open(context.Background(), tenant, admin1, runtime.OpenBreakGlassRequest{
		Reason:          "prod incident",
		DurationMinutes: 30,
		Admin2ID:        secondAdmin,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	activated, mintedKey, err := svc.Approve(context.Background(), tenant, grant.ID, secondAdmin)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if activated.Status != runtime.BreakGlassStatusActive {
		t.Fatalf("status = %q, want active", activated.Status)
	}
	if activated.Approver2 != secondAdmin || activated.KeyID == 0 {
		t.Fatalf("activation incomplete: %+v", activated)
	}
	if mintedKey == "" {
		t.Fatal("approve must mint the admin key")
	}
	resolved, err := svc.keys.(*runtime.MemoryAPIKeyResolver).Resolve(context.Background(), mintedKey)
	if err != nil || resolved.TenantID != testTenant || resolved.KeyName != "break-glass" {
		t.Fatalf("minted key resolve = %+v (%v)", resolved, err)
	}
	// Double approval must fail.
	if _, _, err := svc.Approve(context.Background(), tenant, grant.ID, secondAdmin); !errors.Is(err, runtime.ErrBreakGlassNotPendingApproval) {
		t.Fatalf("double approve: err = %v, want ErrBreakGlassNotPendingApproval", err)
	}
}

func TestRejectRequiresReasonAndActor(t *testing.T) {
	svc, _, tenant := fourEyesHarness(t)
	grant, _, err := svc.Open(context.Background(), tenant, admin1, runtime.OpenBreakGlassRequest{
		Reason:          "prod incident",
		DurationMinutes: 30,
		Admin2ID:        secondAdmin,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := svc.Reject(context.Background(), tenant, grant.ID, secondAdmin, runtime.RevokeBreakGlassRequest{}); err == nil {
		t.Fatal("reject without reason must fail")
	}
	if _, err := svc.Reject(context.Background(), tenant, grant.ID, "slack:INTRUDER", runtime.RevokeBreakGlassRequest{Reason: "nope"}); !errors.Is(err, runtime.ErrBreakGlassForbidden) {
		t.Fatalf("reject by wrong actor: err = %v, want ErrBreakGlassForbidden", err)
	}
	rejected, err := svc.Reject(context.Background(), tenant, grant.ID, secondAdmin, runtime.RevokeBreakGlassRequest{Reason: "not the right window"})
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rejected.Status != runtime.BreakGlassStatusRejected {
		t.Fatalf("status = %q, want rejected", rejected.Status)
	}
	events, err := svc.store.ListEvents(context.Background(), testTenant, grant.ID)
	if err != nil || len(events) != 2 || events[1].EventType != runtime.BreakGlassEventRejected {
		t.Fatalf("events = %v (%v), want opened+rejected", events, err)
	}
	if problems := VerifyBreakGlassEventChain(events); len(problems) > 0 {
		t.Fatalf("chain problems: %+v", problems)
	}
}

func TestRecordNotificationFailureAppendsEvidence(t *testing.T) {
	svc, _, tenant := fourEyesHarness(t)
	grant, _, err := svc.Open(context.Background(), tenant, admin1, runtime.OpenBreakGlassRequest{
		Reason:          "prod incident",
		DurationMinutes: 30,
		Admin2ID:        secondAdmin,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := svc.RecordNotificationFailure(context.Background(), testTenant, grant.ID, "slack", "webhook returned status 500"); err != nil {
		t.Fatalf("record: %v", err)
	}
	events, err := svc.store.ListEvents(context.Background(), testTenant, grant.ID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 2 || events[1].EventType != runtime.BreakGlassEventNotificationFailed {
		t.Fatalf("events = %+v, want opened + notification_failed", events)
	}
	if events[1].ActorPrincipalID != "notification-delivery" {
		t.Fatalf("actor = %q", events[1].ActorPrincipalID)
	}
	if problems := VerifyBreakGlassEventChain(events); len(problems) > 0 {
		t.Fatalf("chain problems: %+v", problems)
	}
}

func TestLegacyOpenWithoutSecondAdminStillActive(t *testing.T) {
	svc, _, tenant := fourEyesHarness(t)
	grant, mintedKey, err := svc.Open(context.Background(), tenant, admin1, runtime.OpenBreakGlassRequest{
		Reason:          "quick fix",
		DurationMinutes: 15,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if grant.Status != runtime.BreakGlassStatusActive || mintedKey == "" {
		t.Fatalf("legacy open must be immediately active with a key: %+v key=%q", grant, mintedKey)
	}
}

func TestPendingGrantExpiresLazily(t *testing.T) {
	svc, _, tenant := fourEyesHarness(t)
	svc.now = func() time.Time { return time.Now().UTC().Add(-2 * time.Hour) }
	grant, _, err := svc.Open(context.Background(), tenant, admin1, runtime.OpenBreakGlassRequest{
		Reason:          "prod incident",
		DurationMinutes: 30,
		Admin2ID:        secondAdmin,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	svc.now = time.Now
	g, _, err := svc.Get(context.Background(), testTenant, grant.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if g.Status != runtime.BreakGlassStatusExpired {
		t.Fatalf("status = %q, want expired", g.Status)
	}
}
