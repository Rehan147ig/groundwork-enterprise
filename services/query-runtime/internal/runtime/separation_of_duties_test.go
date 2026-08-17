// Phase 8.4 administrative separation of duties: platform operator
// duties are split into distinct API-key roles — key_admin (API-key
// management), break_glass (emergency grants), provision (tenant
// lifecycle) — so no single operator key can do everything. The legacy
// "admin" scope still satisfies every role (hasScope override), so
// pre-existing operator keys keep working unchanged.

package runtime_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"groundwork/query-runtime/internal/breakglass"
	"groundwork/query-runtime/internal/runtime"
	"groundwork/query-runtime/internal/tenancy"
)

// sodHarness wires the three platform-operator surfaces (key management,
// break-glass, tenant provisioning) around one shared API-key resolver,
// mirroring cmd/query-runtime.
type sodHarness struct {
	s         *runtime.Server
	keys      *runtime.MemoryAPIKeyResolver
	tenantSvc runtime.TenantService
}

func newSODHarness(t *testing.T) *sodHarness {
	t.Helper()
	keys := runtime.NewMemoryAPIKeyResolver(govAdminKey, runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "sod-bootstrap", Scopes: []string{"admin", "query"},
	})
	tenantSvc := tenancy.NewService(tenancy.NewMemoryStore(), keys)
	bg := breakglass.NewService(breakglass.NewMemoryStore(), keys, 60*time.Minute)
	s := runtime.NewServerWithExecutor(runtime.Config{}, runtime.NewMemoryBackend(), keys, &simpleExecutor{})
	s.SetTenantService(tenantSvc)
	s.SetBreakGlassService(bg)
	s.SetIdentity(testVerifier{secret: "server-secret"}, false)
	return &sodHarness{s: s, keys: keys, tenantSvc: tenantSvc}
}

// mintOperatorKey mints a key for the test tenant with the given role
// scopes, exactly as a key-admin operator would.
func (h *sodHarness) mintOperatorKey(t *testing.T, name string, scopes []string) string {
	t.Helper()
	resp, err := h.keys.Create(context.Background(), runtime.TenantContext{TenantID: govTenant, Region: govRegion, KeyName: name, Scopes: scopes},
		runtime.CreateAPIKeyRequest{Name: name, Scopes: scopes})
	if err != nil {
		t.Fatalf("Create key %s: %v", name, err)
	}
	return resp.Key
}

func doSOD(t *testing.T, s *runtime.Server, method, path, key, assertion, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := govRequest(method, path, key, assertion, "", body)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	return rec
}

// expectDenied asserts the 403 insufficient_scope envelope for a role
// that must NOT be able to perform the action.
func expectDenied(t *testing.T, rec *httptest.ResponseRecorder, action string) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("%s: want 403, got %d: %s", action, rec.Code, rec.Body.String())
	}
}

func TestKeyAdminRoleMintsKeysButNotGrantsOrTenants(t *testing.T) {
	h := newSODHarness(t)
	key := h.mintOperatorKey(t, "key-admin", []string{"key_admin"})

	// Key management: allowed (201).
	rec := doSOD(t, h.s, http.MethodPost, "/v1/admin/api-keys", key, adminTokenFor(t, govOwner), `{"name":"worker","scopes":["query"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("key_admin create key: want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	// Break-glass and tenant provisioning: forbidden — one role, one duty.
	expectDenied(t, doSOD(t, h.s, http.MethodPost, "/v1/security/break-glass/grants", key, adminTokenFor(t, govOwner), `{"reason":"incident","duration_minutes":15}`), "key_admin open grant")
	expectDenied(t, doSOD(t, h.s, http.MethodPost, "/v1/admin/tenants", key, adminTokenFor(t, govOwner), `{"tenant_id":"tenant-sod","region":"us-east-1","reason":"onboarding"}`), "key_admin provision")
}

func TestBreakGlassRoleOpensGrantsButNotKeysOrTenants(t *testing.T) {
	h := newSODHarness(t)
	key := h.mintOperatorKey(t, "bg-ops", []string{"break_glass"})

	rec := doSOD(t, h.s, http.MethodPost, "/v1/security/break-glass/grants", key, adminTokenFor(t, govOwner), `{"reason":"incident","duration_minutes":15}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("break_glass open grant: want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	expectDenied(t, doSOD(t, h.s, http.MethodPost, "/v1/admin/api-keys", key, adminTokenFor(t, govOwner), `{"name":"sneaky","scopes":["admin"]}`), "break_glass mint key")
	expectDenied(t, doSOD(t, h.s, http.MethodPost, "/v1/admin/tenants", key, adminTokenFor(t, govOwner), `{"tenant_id":"tenant-sod","region":"us-east-1","reason":"onboarding"}`), "break_glass provision")
}

func TestProvisionRoleManagesTenantsButNotKeysOrGrants(t *testing.T) {
	h := newSODHarness(t)
	key := h.mintOperatorKey(t, "tenant-ops", []string{"provision"})

	rec := doSOD(t, h.s, http.MethodPost, "/v1/admin/tenants", key, adminTokenFor(t, govOwner), `{"tenant_id":"tenant-sod","region":"us-east-1","reason":"onboarding"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("provision create tenant: want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	expectDenied(t, doSOD(t, h.s, http.MethodPost, "/v1/admin/api-keys", key, adminTokenFor(t, govOwner), `{"name":"worker","scopes":["query"]}`), "provision mint key")
	expectDenied(t, doSOD(t, h.s, http.MethodPost, "/v1/security/break-glass/grants", key, adminTokenFor(t, govOwner), `{"reason":"incident","duration_minutes":15}`), "provision open grant")
}

func TestLegacyAdminSatisfiesEveryOperatorRole(t *testing.T) {
	h := newSODHarness(t)

	rec := doSOD(t, h.s, http.MethodPost, "/v1/admin/api-keys", govAdminKey, adminTokenFor(t, govOwner), `{"name":"worker","scopes":["query"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("legacy admin create key: want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = doSOD(t, h.s, http.MethodPost, "/v1/security/break-glass/grants", govAdminKey, adminTokenFor(t, govOwner), `{"reason":"incident","duration_minutes":15}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("legacy admin open grant: want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = doSOD(t, h.s, http.MethodPost, "/v1/admin/tenants", govAdminKey, adminTokenFor(t, govOwner), `{"tenant_id":"tenant-sod","region":"us-east-1","reason":"onboarding"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("legacy admin provision: want 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestQueryOnlyKeyIsNoOperator(t *testing.T) {
	h := newSODHarness(t)
	key := h.mintOperatorKey(t, "query-only", []string{"query"})

	expectDenied(t, doSOD(t, h.s, http.MethodPost, "/v1/admin/api-keys", key, "", `{"name":"x","scopes":["query"]}`), "query key mint")
	expectDenied(t, doSOD(t, h.s, http.MethodPost, "/v1/security/break-glass/grants", key, adminTokenFor(t, govOwner), `{"reason":"incident","duration_minutes":15}`), "query key grant")
	expectDenied(t, doSOD(t, h.s, http.MethodPost, "/v1/admin/tenants", key, adminTokenFor(t, govOwner), `{"tenant_id":"tenant-sod","region":"us-east-1","reason":"onboarding"}`), "query key provision")
}
