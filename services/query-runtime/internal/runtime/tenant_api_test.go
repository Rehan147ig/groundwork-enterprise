package runtime_test

import (
	"context"
	"net/http"
	"testing"

	"groundwork/query-runtime/internal/runtime"
	"groundwork/query-runtime/internal/tenancy"
)

// ---------------------------------------------------------------------
// Harness: real tenancy service (memory store + shared API-key resolver
// as the KeyMinter) wired into a real Server, mirroring
// cmd/query-runtime. Verified identity required (demo OFF).
// ---------------------------------------------------------------------

type tenantAPIHarness struct {
	s       *runtime.Server
	apiKeys *runtime.MemoryAPIKeyResolver
	svc     runtime.TenantService
}

func newTenantHarness(t *testing.T) *tenantAPIHarness {
	t.Helper()
	apiKeys := runtime.NewMemoryAPIKeyResolver(govAdminKey, runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "tenant-admin", Scopes: []string{"admin", "query"},
	})
	svc := tenancy.NewService(tenancy.NewMemoryStore(), apiKeys)
	s := newTenantServer(t, svc, apiKeys)
	return &tenantAPIHarness{s: s, apiKeys: apiKeys, svc: svc}
}

// mintTenantKey mints an admin-scoped key for an arbitrary tenant (the
// same path break-glass uses) so auth-layer fail-closed behavior can be
// asserted for provisioned tenants.
func (h *tenantAPIHarness) mintTenantKey(t *testing.T, tenantID, region string) string {
	t.Helper()
	resp, err := h.apiKeys.Create(context.Background(), runtime.TenantContext{TenantID: tenantID, Region: region},
		runtime.CreateAPIKeyRequest{Name: "tenant-admin", Scopes: []string{"admin", "query"}})
	if err != nil {
		t.Fatalf("Create key: %v", err)
	}
	return resp.Key
}

func newTenantServer(t *testing.T, svc runtime.TenantService, apiKeys *runtime.MemoryAPIKeyResolver) *runtime.Server {
	t.Helper()
	s := runtime.NewServerWithAuth(runtime.Config{}, runtime.NewMemoryBackend(), apiKeys)
	s.SetTenantService(svc)
	s.SetIdentity(testVerifier{secret: "server-secret"}, false)
	return s
}

func TestTenantUnavailableWhenNotWired(t *testing.T) {
	apiKeys := runtime.NewMemoryAPIKeyResolver(govAdminKey, runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "t", Scopes: []string{"admin"},
	})
	s := newTenantServer(t, nil, apiKeys)

	cases := []struct{ method, path string }{
		{http.MethodPost, "/v1/admin/tenants"},
		{http.MethodGet, "/v1/admin/tenants"},
		{http.MethodGet, "/v1/admin/tenants/acme"},
		{http.MethodGet, "/v1/admin/tenants/acme/events"},
		{http.MethodPost, "/v1/admin/tenants/acme/disable"},
		{http.MethodPost, "/v1/admin/tenants/acme/enable"},
		{http.MethodPost, "/v1/admin/tenants/acme/deprovision"},
	}
	for _, c := range cases {
		rec := doGov(t, s, c.method, c.path, govAdminKey, "", "", "")
		if c.method == http.MethodGet {
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s %s: want 503, got %d (%s)", c.method, c.path, rec.Code, rec.Body.String())
			}
			continue
		}
		// Mutations sit behind the verified-identity middleware, so a
		// missing assertion is rejected (401) before the nil-service
		// check; with a verified identity the 503 surfaces.
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s (no identity): want 401, got %d (%s)", c.method, c.path, rec.Code, rec.Body.String())
		}
		rec = doGov(t, s, c.method, c.path, govAdminKey, adminTokenFor(t, govOwner), "", `{"reason":"r","tenant_id":"acme","region":"uk"}`)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s (verified): want 503, got %d (%s)", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
}

func TestTenantRequiresProvisionScope(t *testing.T) {
	h := newTenantHarness(t)
	apiKeys := runtime.NewMemoryAPIKeyResolver("gw_query_key", runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "query-only", Scopes: []string{"query"},
	})
	s := newTenantServer(t, h.svc, apiKeys)

	rec := doGov(t, s, http.MethodGet, "/v1/admin/tenants", "gw_query_key", "", "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestTenantProvisionRequiresVerifiedIdentity(t *testing.T) {
	h := newTenantHarness(t)
	// Without a verified assertion the identity middleware fails closed.
	rec := doGov(t, h.s, http.MethodPost, "/v1/admin/tenants", govAdminKey, "", "",
		`{"tenant_id":"contoso","region":"uk","reason":"onboarding"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d (%s)", rec.Code, rec.Body.String())
	}

	// With demo identity enabled the middleware passes but the handler
	// still rejects unverified (demo) actors.
	apiKeys := runtime.NewMemoryAPIKeyResolver(govAdminKey, runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "t", Scopes: []string{"admin"},
	})
	s := runtime.NewServerWithAuth(runtime.Config{}, runtime.NewMemoryBackend(), apiKeys)
	s.SetTenantService(h.svc)
	s.SetIdentity(testVerifier{secret: "server-secret"}, true)
	rec = doGov(t, s, http.MethodPost, "/v1/admin/tenants", govAdminKey, "", "",
		`{"tenant_id":"contoso","region":"uk","reason":"onboarding"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("demo actor: want 403, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestTenantProvisionLifecycle(t *testing.T) {
	h := newTenantHarness(t)

	// Provision with an initial admin key.
	rec := doGov(t, h.s, http.MethodPost, "/v1/admin/tenants", govAdminKey, adminTokenFor(t, govOwner), "",
		`{"tenant_id":"contoso","region":"uk","reason":"new customer","mint_admin_key":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("provision: %d %s", rec.Code, rec.Body.String())
	}
	var provisioned runtime.ProvisionTenantResponse
	decodeGov(t, rec, &provisioned)
	if provisioned.Tenant.Status != runtime.TenantStatusActive || provisioned.Tenant.Region != "uk" {
		t.Fatalf("provisioned = %+v", provisioned.Tenant)
	}
	if provisioned.Key == "" {
		t.Fatal("expected minted key in provision response")
	}

	// Directory list includes the new tenant.
	rec = doGov(t, h.s, http.MethodGet, "/v1/admin/tenants", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Tenants []runtime.Tenant `json:"tenants"`
	}
	decodeGov(t, rec, &listed)
	found := false
	for _, tn := range listed.Tenants {
		if tn.TenantID == "contoso" && tn.Status == runtime.TenantStatusActive {
			found = true
		}
	}
	if !found {
		t.Fatalf("contoso missing from directory: %+v", listed.Tenants)
	}

	// Events show one provisioned event, chain head.
	rec = doGov(t, h.s, http.MethodGet, "/v1/admin/tenants/contoso/events", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("events: %d %s", rec.Code, rec.Body.String())
	}
	var events struct {
		Events []runtime.TenantEvent `json:"events"`
	}
	decodeGov(t, rec, &events)
	if len(events.Events) != 1 || events.Events[0].EventType != runtime.TenantEventProvisioned {
		t.Fatalf("events = %+v", events.Events)
	}

	// The tenant's own minted key works (active in the directory).
	rec = doGov(t, h.s, http.MethodGet, "/v1/admin/tenants", provisioned.Key, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant key on active tenant: %d %s", rec.Code, rec.Body.String())
	}
}

func TestTenantDisableFailsClosedAtAuth(t *testing.T) {
	h := newTenantHarness(t)
	if _, err := h.svc.Provision(context.Background(), govOwner, runtime.ProvisionTenantRequest{
		TenantID: "contoso", Region: "uk", Reason: "onboarding",
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	tenantKey := h.mintTenantKey(t, "contoso", "uk")

	rec := doGov(t, h.s, http.MethodPost, "/v1/admin/tenants/contoso/disable", govAdminKey, adminTokenFor(t, govOwner), "",
		`{"reason":"suspected compromise"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}

	// The tenant's key now fails closed at the auth layer — before any
	// handler runs.
	rec = doGov(t, h.s, http.MethodGet, "/v1/admin/tenants", tenantKey, "", "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disabled tenant key: want 403, got %d (%s)", rec.Code, rec.Body.String())
	}

	// Disable requires a reason.
	rec = doGov(t, h.s, http.MethodPost, "/v1/admin/tenants/contoso/disable", govAdminKey, adminTokenFor(t, govOwner), "", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("disable without reason: want 400, got %d", rec.Code)
	}

	// Enable restores access.
	rec = doGov(t, h.s, http.MethodPost, "/v1/admin/tenants/contoso/enable", govAdminKey, adminTokenFor(t, govOwner), "",
		`{"reason":"investigation cleared"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body.String())
	}
	rec = doGov(t, h.s, http.MethodGet, "/v1/admin/tenants", tenantKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("enabled tenant key: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestTenantDeprovisionIsNonDestructiveAndReProvisionable(t *testing.T) {
	h := newTenantHarness(t)
	if _, err := h.svc.Provision(context.Background(), govOwner, runtime.ProvisionTenantRequest{
		TenantID: "contoso", Region: "uk", Reason: "onboarding",
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	rec := doGov(t, h.s, http.MethodPost, "/v1/admin/tenants/contoso/deprovision", govAdminKey, adminTokenFor(t, govOwner), "",
		`{"reason":"contract ended"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("deprovision: %d %s", rec.Code, rec.Body.String())
	}

	// The record still exists (no destructive delete).
	rec = doGov(t, h.s, http.MethodGet, "/v1/admin/tenants/contoso", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get after deprovision: %d %s", rec.Code, rec.Body.String())
	}
	var tenant runtime.Tenant
	decodeGov(t, rec, &tenant)
	if tenant.Status != runtime.TenantStatusDeprovisioned {
		t.Fatalf("status = %q", tenant.Status)
	}

	// There is no DELETE route at all.
	rec = doGov(t, h.s, http.MethodDelete, "/v1/admin/tenants/contoso", govAdminKey, "", "", "")
	if rec.Code == http.StatusOK || rec.Code == http.StatusNoContent {
		t.Fatalf("DELETE must not exist: got %d", rec.Code)
	}

	// Re-provision reactivates; region may change.
	rec = doGov(t, h.s, http.MethodPost, "/v1/admin/tenants", govAdminKey, adminTokenFor(t, govOwner), "",
		`{"tenant_id":"contoso","region":"eu","reason":"re-homed"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("re-provision: %d %s", rec.Code, rec.Body.String())
	}
	var reProvisioned runtime.ProvisionTenantResponse
	decodeGov(t, rec, &reProvisioned)
	if reProvisioned.Tenant.Status != runtime.TenantStatusActive || reProvisioned.Tenant.Region != "eu" {
		t.Fatalf("re-provisioned = %+v", reProvisioned.Tenant)
	}
}

func TestTenantProvisionValidationAndConflicts(t *testing.T) {
	h := newTenantHarness(t)

	cases := []struct{ name, body string }{
		{"empty tenant id", `{"region":"uk","reason":"r"}`},
		{"invalid tenant id", `{"tenant_id":"has space","region":"uk","reason":"r"}`},
		{"invalid region", `{"tenant_id":"acme","region":"NOT A REGION!!","reason":"r"}`},
		{"missing reason", `{"tenant_id":"acme","region":"uk"}`},
	}
	for _, c := range cases {
		rec := doGov(t, h.s, http.MethodPost, "/v1/admin/tenants", govAdminKey, adminTokenFor(t, govOwner), "", c.body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d (%s)", c.name, rec.Code, rec.Body.String())
		}
	}

	if _, err := h.svc.Provision(context.Background(), govOwner, runtime.ProvisionTenantRequest{
		TenantID: "acme", Region: "uk", Reason: "onboarding",
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// Region conflict on an active tenant.
	rec := doGov(t, h.s, http.MethodPost, "/v1/admin/tenants", govAdminKey, adminTokenFor(t, govOwner), "",
		`{"tenant_id":"acme","region":"eu","reason":"move"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("region conflict: want 409, got %d (%s)", rec.Code, rec.Body.String())
	}

	// Unknown tenant transitions 404.
	rec = doGov(t, h.s, http.MethodPost, "/v1/admin/tenants/ghost/disable", govAdminKey, adminTokenFor(t, govOwner), "", `{"reason":"r"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant disable: want 404, got %d", rec.Code)
	}
	rec = doGov(t, h.s, http.MethodGet, "/v1/admin/tenants/ghost", govAdminKey, "", "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant get: want 404, got %d", rec.Code)
	}
}

func TestTenantEventsChainOverHTTP(t *testing.T) {
	h := newTenantHarness(t)
	if _, err := h.svc.Provision(context.Background(), govOwner, runtime.ProvisionTenantRequest{
		TenantID: "contoso", Region: "uk", Reason: "onboarding",
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	for _, path := range []string{"disable", "enable", "deprovision"} {
		rec := doGov(t, h.s, http.MethodPost, "/v1/admin/tenants/contoso/"+path, govAdminKey, adminTokenFor(t, govOwner), "",
			`{"reason":"r"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	rec := doGov(t, h.s, http.MethodGet, "/v1/admin/tenants/contoso/events", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("events: %d %s", rec.Code, rec.Body.String())
	}
	var events struct {
		Events []runtime.TenantEvent `json:"events"`
	}
	decodeGov(t, rec, &events)
	want := []string{
		runtime.TenantEventProvisioned,
		runtime.TenantEventDisabled,
		runtime.TenantEventEnabled,
		runtime.TenantEventDeprovisioned,
	}
	if len(events.Events) != len(want) {
		t.Fatalf("want %d events, got %d", len(want), len(events.Events))
	}
	prev := ""
	for i, e := range events.Events {
		if e.EventType != want[i] {
			t.Fatalf("event[%d] = %q, want %q", i, e.EventType, want[i])
		}
		if e.PreviousHash != prev {
			t.Fatalf("event[%d] does not chain (previous_hash %q, want %q)", i, e.PreviousHash, prev)
		}
		prev = e.ImmutableDigest
	}
}
