// Phase 8.4 runtime admin identity gate: requireAdminIdentity rejects
// verified-but-non-admin callers with 403 admin_identity_required
// BEFORE any handler runs on the operator surfaces (API-key minting,
// tenant provisioning, break-glass, governance tools/grants/budgets,
// connectors, external agents, consents, transfer policies, external
// budgets, usage limits, support bundles), while an admin assertion
// passes the gate. Unwired identity verification fails closed with 401
// identity_verifier_unavailable.

package runtime_test

import (
	"net/http"
	"testing"
	"time"

	"groundwork/query-runtime/internal/breakglass"
	"groundwork/query-runtime/internal/governance"
	"groundwork/query-runtime/internal/runtime"
	"groundwork/query-runtime/internal/tenancy"
)

func newAdminGateServer(t *testing.T) *runtime.Server {
	t.Helper()
	t.Setenv("GROUNDWORK_DELEGATION_HS_SECRET", "admin-gate-delegation-hs-secret-32chars-min")
	keys := runtime.NewMemoryAPIKeyResolver(govAdminKey, runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "gate", Scopes: []string{"admin", "query"},
	})
	authority, err := governance.BuildAuthority()
	if err != nil {
		t.Fatalf("BuildAuthority: %v", err)
	}
	s := runtime.NewServerWithExecutor(runtime.Config{}, runtime.NewMemoryBackend(), keys, &recordingExecutor{})
	s.SetTenantService(tenancy.NewService(tenancy.NewMemoryStore(), keys))
	s.SetBreakGlassService(breakglass.NewService(breakglass.NewMemoryStore(), keys, 60*time.Minute))
	s.SetGovernanceService(governance.NewService(governance.NewMemoryStore(), authority, &govFakeChecker{}, &govFakeAgents{}))
	s.SetSupportBundleSource(&fakeBundleSource{})
	s.SetIdentity(testVerifier{secret: "server-secret"}, false)
	return s
}

// TestAdminIdentityGateDeniesVerifiedNonAdmin proves every operator
// surface fails closed (403) for a verified but non-admin caller, and
// admits an admin assertion (any response other than the 401/403 auth
// envelope proves the gate passed).
func TestAdminIdentityGateDeniesVerifiedNonAdmin(t *testing.T) {
	s := newAdminGateServer(t)
	cases := []struct {
		name, method, path, body string
	}{
		{"api-key mint", http.MethodPost, "/v1/admin/api-keys", `{"name":"k","scopes":["query"]}`},
		{"api-key revoke", http.MethodDelete, "/v1/admin/api-keys/1", ""},
		{"tenant provision", http.MethodPost, "/v1/admin/tenants", `{"tenant_id":"gate-tenant","region":"uk","reason":"r"}`},
		{"tenant disable", http.MethodPost, "/v1/admin/tenants/gate-tenant/disable", `{"reason":"r"}`},
		{"tenant enable", http.MethodPost, "/v1/admin/tenants/gate-tenant/enable", `{"reason":"r"}`},
		{"tenant deprovision", http.MethodPost, "/v1/admin/tenants/gate-tenant/deprovision", `{"reason":"r"}`},
		{"break-glass open", http.MethodPost, "/v1/security/break-glass/grants", `{"reason":"r","duration_minutes":15}`},
		{"break-glass approve", http.MethodPost, "/v1/security/break-glass/grants/g-1/approve", `{"reason":"r"}`},
		{"break-glass reject", http.MethodPost, "/v1/security/break-glass/grants/g-1/reject", `{"reason":"r"}`},
		{"break-glass revoke", http.MethodPost, "/v1/security/break-glass/grants/g-1/revoke", `{"reason":"r"}`},
		{"governance tool create", http.MethodPost, "/v1/governance/tools", `{"name":"t","risk_tier":"high","requires_approval":true}`},
		{"governance tool lifecycle", http.MethodPost, "/v1/governance/tools/tool-1/lifecycle", `{"lifecycle":"active"}`},
		{"governance grant", http.MethodPost, "/v1/governance/grants", `{"tool_id":"tool-1","agent_id":"agent-1","action_id":"action-1","principal_id":"u","purpose":"p"}`},
		{"budget upsert", http.MethodPost, "/v1/governance/budgets", `{"metric":"agents","period":"weekly","limit":5}`},
		{"connector register", http.MethodPost, "/v1/governance/connectors", `{"connector_id":"c1","agent_id":"agent-1","provider":"msgraph","scopes":["User.Read"]}`},
		{"connector activate", http.MethodPost, "/v1/governance/connectors/c1/activate", `{"reason":"r"}`},
		{"connector suspend", http.MethodPost, "/v1/governance/connectors/c1/suspend", `{"reason":"r"}`},
		{"connector revoke", http.MethodPost, "/v1/governance/connectors/c1/revoke", `{"reason":"r"}`},
		{"connector config", http.MethodPost, "/v1/governance/connectors/c1/config", `{}`},
		{"external agent", http.MethodPost, "/v1/governance/external-agents", `{"external_agent_id":"e1","agent_id":"agent-1","organization_id":"o1","verified_issuer":"https://iss","allowed_audiences":["gw"],"auth_method":"oidc","region":"us-east-1"}`},
		{"external agent activate", http.MethodPost, "/v1/governance/external-agents/e1/activate", `{"reason":"r"}`},
		{"consent create", http.MethodPost, "/v1/governance/consents", `{"organization_id":"o1","external_agent_id":"e1","customer_principal_id":"c1","purpose":"p"}`},
		{"transfer policy", http.MethodPost, "/v1/governance/transfer-policies", `{"source_region":"eu-central-1","target_region":"us-east-1","purpose_pattern":"*","enabled":true}`},
		{"external budget", http.MethodPut, "/v1/governance/external-budgets/e1", `{"scope_type":"external_agent","external_agent_id":"e1","max_total_actions":1}`},
		{"chain control", http.MethodPost, "/v1/governance/delegations/g-1/chain/revoke", `{"reason":"r"}`},
		{"usage limits", http.MethodPut, "/v1/usage/limits", `{"limits":[{"metric":"agents","period":"weekly","limit":5}]}`},
		{"support bundle", http.MethodGet, "/v1/security/support-bundle", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doGov(t, s, tc.method, tc.path, govAdminKey, tokenFor(t, govOwner), "", tc.body)
			if rec.Code != http.StatusForbidden || govErrorOf(t, rec) != "admin_identity_required" {
				t.Fatalf("verified non-admin: got %d %q, want 403 admin_identity_required", rec.Code, rec.Body.String())
			}
			rec = doGov(t, s, tc.method, tc.path, govAdminKey, adminTokenFor(t, govOwner), "", tc.body)
			if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
				t.Fatalf("admin assertion: got %d %q, gate should have passed", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestAdminIdentityGateNoAssertionFailsClosed proves the identity-less
// caller is rejected (401) even on the read-heavy admin surface.
func TestAdminIdentityGateNoAssertionFailsClosed(t *testing.T) {
	s := newAdminGateServer(t)
	rec := doGov(t, s, http.MethodPost, "/v1/admin/tenants", govAdminKey, "",
		"", `{"tenant_id":"gate-tenant","region":"uk","reason":"r"}`)
	if rec.Code != http.StatusUnauthorized || govErrorOf(t, rec) != "verified_identity_required" {
		t.Fatalf("no assertion: got %d %q, want 401 verified_identity_required", rec.Code, rec.Body.String())
	}
}

// TestAdminIdentityGateUnwiredVerifierFailsClosed proves an admin
// surface without a configured identity verifier never reaches the
// handler: it fails closed with 401 identity_verifier_unavailable.
func TestAdminIdentityGateUnwiredVerifierFailsClosed(t *testing.T) {
	keys := runtime.NewMemoryAPIKeyResolver(govAdminKey, runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "gate", Scopes: []string{"admin"},
	})
	s := runtime.NewServerWithExecutor(runtime.Config{}, runtime.NewMemoryBackend(), keys, &recordingExecutor{})
	s.SetSupportBundleSource(&fakeBundleSource{})

	rec := doGov(t, s, http.MethodGet, "/v1/security/support-bundle", govAdminKey, adminTokenFor(t, govOwner), "", "")
	if rec.Code != http.StatusUnauthorized || govErrorOf(t, rec) != "identity_verifier_unavailable" {
		t.Fatalf("unwired verifier: got %d %q, want 401 identity_verifier_unavailable", rec.Code, rec.Body.String())
	}
}

// TestAdminIdentityGateDemoIdentityAllowed proves the local/dev gate:
// when demo identity is allowed and no assertion is present, the admin
// middleware admits the call as a demo decision (the handler may still
// reject unverified actors, as the tenant service does).
func TestAdminIdentityGateDemoIdentityAllowed(t *testing.T) {
	keys := runtime.NewMemoryAPIKeyResolver(govAdminKey, runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "gate", Scopes: []string{"admin"},
	})
	s := runtime.NewServerWithExecutor(runtime.Config{}, runtime.NewMemoryBackend(), keys, &recordingExecutor{})
	s.SetTenantService(tenancy.NewService(tenancy.NewMemoryStore(), keys))
	s.SetIdentity(testVerifier{secret: "server-secret"}, true)

	rec := doGov(t, s, http.MethodPost, "/v1/admin/tenants", govAdminKey, "",
		"", `{"tenant_id":"gate-tenant","region":"uk","reason":"r"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("demo actor: got %d %s, want handler-level 403 (demo identity must not pass the service)", rec.Code, rec.Body.String())
	}
}
