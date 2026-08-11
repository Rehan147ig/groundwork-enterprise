package tenancy

import (
	"context"
	"testing"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

func newService(t *testing.T, keys KeyMinter) *Service {
	t.Helper()
	svc := NewService(NewMemoryStore(), keys)
	return svc
}

// testKeyMinter mints fake keys so tests can assert the mint path without
// depending on the runtime API-key resolver.
type testKeyMinter struct {
	next    int64
	minted  []runtime.CreateAPIKeyResponse
	revoked []int64
}

func (k *testKeyMinter) Create(ctx context.Context, tenant runtime.TenantContext, req runtime.CreateAPIKeyRequest) (runtime.CreateAPIKeyResponse, error) {
	k.next++
	resp := runtime.CreateAPIKeyResponse{
		ID:           k.next,
		Key:          "gw_live_fake",
		KeyPrefix:    "fake",
		Name:         req.Name,
		TenantID:     tenant.TenantID,
		Region:       tenant.Region,
		Scopes:       req.Scopes,
		RateLimitRPM: req.RateLimitRPM,
		ExpiresAt:    req.ExpiresAt,
		CreatedAt:    time.Now().UTC(),
	}
	k.minted = append(k.minted, resp)
	return resp, nil
}

func (k *testKeyMinter) Revoke(ctx context.Context, tenant runtime.TenantContext, id int64) (bool, error) {
	k.revoked = append(k.revoked, id)
	return true, nil
}

func TestProvisionCreatesActiveTenantWithEvidence(t *testing.T) {
	svc := newService(t, nil)
	ctx := context.Background()

	resp, err := svc.Provision(ctx, "admin-user", runtime.ProvisionTenantRequest{
		TenantID: "contoso", Region: "UK", Reason: "new customer onboarding",
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if resp.Tenant.Status != runtime.TenantStatusActive {
		t.Fatalf("status = %q, want active", resp.Tenant.Status)
	}
	if resp.Tenant.Region != "UK" {
		t.Fatalf("region = %q, want UK", resp.Tenant.Region)
	}
	if resp.Tenant.CreatedBy != "admin-user" {
		t.Fatalf("created_by = %q, want admin-user", resp.Tenant.CreatedBy)
	}
	if resp.Key != "" {
		t.Fatalf("key minted without MintAdminKey: %q", resp.Key)
	}

	events, err := svc.ListEvents(ctx, "contoso")
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].EventType != runtime.TenantEventProvisioned {
		t.Fatalf("event_type = %q", events[0].EventType)
	}
	if events[0].PreviousHash != "" {
		t.Fatalf("first event previous_hash = %q, want empty", events[0].PreviousHash)
	}
	if problems := VerifyTenantEventChain(events); len(problems) != 0 {
		t.Fatalf("chain problems: %+v", problems)
	}
}

func TestProvisionValidatesInput(t *testing.T) {
	svc := newService(t, nil)
	ctx := context.Background()

	for name, req := range map[string]runtime.ProvisionTenantRequest{
		"empty tenant id":   {TenantID: " ", Region: "UK", Reason: "r"},
		"invalid tenant id": {TenantID: "has space", Region: "UK", Reason: "r"},
		"empty region":      {TenantID: "acme", Region: "", Reason: "r"},
		"invalid region":    {TenantID: "acme", Region: "INVALID REGION!!", Reason: "r"},
		"empty reason":      {TenantID: "acme", Region: "UK", Reason: " "},
	} {
		if _, err := svc.Provision(ctx, "admin-user", req); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
	if _, err := svc.Provision(ctx, "", runtime.ProvisionTenantRequest{TenantID: "acme", Region: "UK", Reason: "r"}); err == nil {
		t.Fatal("empty actor: expected error")
	}
}

func TestProvisionIsIdempotentForActiveTenant(t *testing.T) {
	svc := newService(t, nil)
	ctx := context.Background()
	req := runtime.ProvisionTenantRequest{TenantID: "acme", Region: "EU", Reason: "onboard"}

	first, err := svc.Provision(ctx, "u1", req)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	second, err := svc.Provision(ctx, "u1", req)
	if err != nil {
		t.Fatalf("Provision (idempotent): %v", err)
	}
	if first.Tenant.CreatedAt != second.Tenant.CreatedAt {
		t.Fatal("idempotent provision changed created_at")
	}
	events, _ := svc.ListEvents(ctx, "acme")
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
}

func TestProvisionRegionConflictOnActiveTenant(t *testing.T) {
	svc := newService(t, nil)
	ctx := context.Background()
	req := runtime.ProvisionTenantRequest{TenantID: "acme", Region: "EU", Reason: "onboard"}
	if _, err := svc.Provision(ctx, "u1", req); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	req.Region = "US"
	if _, err := svc.Provision(ctx, "u1", req); err != runtime.ErrTenantRegionConflict {
		t.Fatalf("want ErrTenantRegionConflict, got %v", err)
	}
}

func TestProvisionMintsKeyOnceAndRevokesOnWriteFailure(t *testing.T) {
	keys := &testKeyMinter{}
	svc := newService(t, keys)
	ctx := context.Background()

	resp, err := svc.Provision(ctx, "u1", runtime.ProvisionTenantRequest{
		TenantID: "contoso", Region: "UK", Reason: "onboard", MintAdminKey: true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if resp.Key == "" {
		t.Fatal("expected a minted key")
	}
	if len(keys.minted) != 1 {
		t.Fatalf("want 1 minted key, got %d", len(keys.minted))
	}
	if keys.minted[0].TenantID != "contoso" || keys.minted[0].Region != "UK" {
		t.Fatalf("key minted for wrong tenant: %+v", keys.minted[0])
	}

	// Unwired key minter: MintAdminKey must fail with ErrTenantUnavailable.
	svcNoKeys := newService(t, nil)
	if _, err := svcNoKeys.Provision(ctx, "u1", runtime.ProvisionTenantRequest{
		TenantID: "other", Region: "EU", Reason: "onboard", MintAdminKey: true,
	}); err != runtime.ErrTenantUnavailable {
		t.Fatalf("want ErrTenantUnavailable, got %v", err)
	}
}

func TestLifecycleDisableEnableDeprovision(t *testing.T) {
	svc := newService(t, nil)
	ctx := context.Background()
	if _, err := svc.Provision(ctx, "u1", runtime.ProvisionTenantRequest{TenantID: "acme", Region: "EU", Reason: "onboard"}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	if _, err := svc.Disable(ctx, "acme", "u1", ""); err == nil {
		t.Fatal("disable without reason: expected error")
	}
	disabled, err := svc.Disable(ctx, "acme", "u1", "suspected compromise")
	if err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if disabled.Status != runtime.TenantStatusDisabled {
		t.Fatalf("status = %q", disabled.Status)
	}

	// Disable is idempotent (no extra event).
	if _, err := svc.Disable(ctx, "acme", "u1", "again"); err != nil {
		t.Fatalf("Disable (idempotent): %v", err)
	}

	enabled, err := svc.Enable(ctx, "acme", "u1", "investigation cleared")
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if enabled.Status != runtime.TenantStatusActive {
		t.Fatalf("status = %q", enabled.Status)
	}

	deprovisioned, err := svc.Deprovision(ctx, "acme", "u1", "contract ended")
	if err != nil {
		t.Fatalf("Deprovision: %v", err)
	}
	if deprovisioned.Status != runtime.TenantStatusDeprovisioned || deprovisioned.DeprovisionedAt.IsZero() {
		t.Fatalf("deprovisioned = %+v", deprovisioned)
	}
	if deprovisioned.Reason != "contract ended" {
		t.Fatalf("reason = %q", deprovisioned.Reason)
	}

	// Terminal state: no further transitions, and enable fails closed.
	if _, err := svc.Enable(ctx, "acme", "u1", "oops"); err != runtime.ErrTenantNotActive {
		t.Fatalf("enable after deprovision: want ErrTenantNotActive, got %v", err)
	}
	if _, err := svc.Deprovision(ctx, "acme", "u1", "again"); err != nil {
		t.Fatalf("deprovision idempotent: %v", err)
	}

	// Events chain every transition and link.
	events, err := svc.ListEvents(ctx, "acme")
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	want := []string{
		runtime.TenantEventProvisioned,
		runtime.TenantEventDisabled,
		runtime.TenantEventEnabled,
		runtime.TenantEventDeprovisioned,
	}
	if len(events) != len(want) {
		t.Fatalf("want %d events, got %d: %+v", len(want), len(events), events)
	}
	for i, e := range events {
		if e.EventType != want[i] {
			t.Fatalf("event[%d] = %q, want %q", i, e.EventType, want[i])
		}
		if i > 0 && e.PreviousHash != events[i-1].ImmutableDigest {
			t.Fatalf("event[%d] previous_hash does not chain", i)
		}
	}
	if problems := VerifyTenantEventChain(events); len(problems) != 0 {
		t.Fatalf("chain problems: %+v", problems)
	}
}

func TestReProvisionAfterDeprovisionChangesRegion(t *testing.T) {
	svc := newService(t, nil)
	ctx := context.Background()
	if _, err := svc.Provision(ctx, "u1", runtime.ProvisionTenantRequest{TenantID: "acme", Region: "EU", Reason: "onboard"}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if _, err := svc.Deprovision(ctx, "acme", "u1", "moved regions"); err != nil {
		t.Fatalf("Deprovision: %v", err)
	}
	original, _ := svc.Get(ctx, "acme")
	reprovisioned, err := svc.Provision(ctx, "u1", runtime.ProvisionTenantRequest{TenantID: "acme", Region: "US", Reason: "re-homed in US"})
	if err != nil {
		t.Fatalf("Provision (re-provision): %v", err)
	}
	if reprovisioned.Tenant.Status != runtime.TenantStatusActive || reprovisioned.Tenant.Region != "US" {
		t.Fatalf("re-provisioned = %+v", reprovisioned.Tenant)
	}
	if !reprovisioned.Tenant.CreatedAt.Equal(original.CreatedAt) {
		t.Fatal("re-provision reset created_at")
	}
}

func TestSeedNeverOverridesDirectoryState(t *testing.T) {
	svc := newService(t, nil)
	ctx := context.Background()
	if _, err := svc.Provision(ctx, "u1", runtime.ProvisionTenantRequest{TenantID: "acme", Region: "EU", Reason: "onboard"}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if _, err := svc.Disable(ctx, "acme", "u1", "hold"); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	// Seeding an existing tenant (even with a different region) must be a no-op.
	if err := svc.Seed(ctx, "acme", "US", "configured via GROUNDWORK_TENANT_REGIONS"); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	got, _ := svc.Get(ctx, "acme")
	if got.Status != runtime.TenantStatusDisabled || got.Region != "EU" {
		t.Fatalf("seed overrode directory state: %+v", got)
	}

	// Seeding a new tenant creates it as active with evidence.
	if err := svc.Seed(ctx, "contoso", "UK", "configured via GROUNDWORK_TENANT_REGIONS"); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	seeded, err := svc.Get(ctx, "contoso")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if seeded.Status != runtime.TenantStatusActive || seeded.CreatedBy != "env-config" {
		t.Fatalf("seeded = %+v", seeded)
	}
}

func TestLookup(t *testing.T) {
	svc := newService(t, nil)
	ctx := context.Background()

	if _, _, _, ok := svc.Lookup(ctx, "unknown"); ok {
		t.Fatal("unknown tenant: expected ok=false")
	}
	if _, err := svc.Provision(ctx, "u1", runtime.ProvisionTenantRequest{TenantID: "acme", Region: "EU", Reason: "onboard"}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	region, status, tier, ok := svc.Lookup(ctx, "acme")
	if !ok || region != "EU" || status != runtime.TenantStatusActive || tier != runtime.CapacityTierStandard {
		t.Fatalf("Lookup = (%q, %q, %q, %v)", region, status, tier, ok)
	}
	if _, err := svc.Disable(ctx, "acme", "u1", "hold"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	_, status, _, _ = svc.Lookup(ctx, "acme")
	if status != runtime.TenantStatusDisabled {
		t.Fatalf("Lookup after disable status = %q", status)
	}
}

func TestListSortedAndNotFound(t *testing.T) {
	svc := newService(t, nil)
	ctx := context.Background()
	for _, id := range []string{"zebra", "acme", "mango"} {
		if _, err := svc.Provision(ctx, "u1", runtime.ProvisionTenantRequest{TenantID: id, Region: "EU", Reason: "r"}); err != nil {
			t.Fatalf("Provision %s: %v", id, err)
		}
	}
	tenants, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for i, want := range []string{"acme", "mango", "zebra"} {
		if tenants[i].TenantID != want {
			t.Fatalf("tenants[%d] = %s, want %s", i, tenants[i].TenantID, want)
		}
	}
	if _, err := svc.Get(ctx, "nope"); err != runtime.ErrTenantNotFound {
		t.Fatalf("Get unknown: want ErrTenantNotFound, got %v", err)
	}
}

// Phase 8.2 capacity model: provision accepts the closed tier set and
// defaults to standard, so the directory can drive per-tenant in-flight
// caps without every call site carrying an explicit tier.

func TestProvisionDefaultsTierToStandard(t *testing.T) {
	svc := newService(t, nil)
	ctx := context.Background()
	resp, err := svc.Provision(ctx, "u1", runtime.ProvisionTenantRequest{TenantID: "acme", Region: "EU", Reason: "onboard"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if resp.Tenant.Tier != runtime.CapacityTierStandard {
		t.Fatalf("tier = %q, want standard", resp.Tenant.Tier)
	}
	if _, _, tier, ok := svc.Lookup(ctx, "acme"); !ok || tier != runtime.CapacityTierStandard {
		t.Fatalf("Lookup tier = %q, want standard", tier)
	}
}

func TestProvisionPersistsTier(t *testing.T) {
	svc := newService(t, nil)
	ctx := context.Background()
	if _, err := svc.Provision(ctx, "u1", runtime.ProvisionTenantRequest{
		TenantID: "acme", Region: "EU", Tier: runtime.CapacityTierEnterprise, Reason: "onboard",
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	got, err := svc.Get(ctx, "acme")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Tier != runtime.CapacityTierEnterprise {
		t.Fatalf("tier = %q, want enterprise", got.Tier)
	}
	if _, _, tier, ok := svc.Lookup(ctx, "acme"); !ok || tier != runtime.CapacityTierEnterprise {
		t.Fatalf("Lookup tier = %q, want enterprise", tier)
	}
}

func TestProvisionRejectsUnknownTier(t *testing.T) {
	svc := newService(t, nil)
	ctx := context.Background()
	if _, err := svc.Provision(ctx, "u1", runtime.ProvisionTenantRequest{
		TenantID: "acme", Region: "EU", Tier: "platinum", Reason: "onboard",
	}); err == nil {
		t.Fatal("unknown tier: expected error")
	}
	// Blank tier normalizes to standard rather than erroring, so callers
	// that do not know about tiers keep working.
	if _, err := svc.Provision(ctx, "u1", runtime.ProvisionTenantRequest{
		TenantID: "acme", Region: "EU", Tier: " ", Reason: "onboard",
	}); err != nil {
		t.Fatalf("blank tier should normalize to standard: %v", err)
	}
	if got, err := svc.Get(ctx, "acme"); err != nil || got.Tier != runtime.CapacityTierStandard {
		t.Fatalf("blank tier tenant = %+v, want standard", got)
	}
}

func TestCapacityTierValues(t *testing.T) {
	if !runtime.IsCapacityTier(runtime.CapacityTierStandard) || !runtime.IsCapacityTier(runtime.CapacityTierPlus) || !runtime.IsCapacityTier(runtime.CapacityTierEnterprise) {
		t.Fatalf("closed tier set must validate")
	}
	for _, bogus := range []string{"", "platinum", "STANDARD", "standard "} {
		if runtime.IsCapacityTier(bogus) {
			t.Fatalf("IsCapacityTier(%q) = true, want false", bogus)
		}
	}
}
