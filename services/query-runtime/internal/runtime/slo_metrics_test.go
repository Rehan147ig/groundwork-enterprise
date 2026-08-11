package runtime_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gwmetrics "groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/runtime"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The SLO HTTP counter is emitted by requireAPIKey for every
// authenticated API response, keyed by tenant and status class. Early
// failures (bad key) record with an empty tenant id.

func TestSLOHTTPRequestsCounter(t *testing.T) {
	h := newGovAPIHarness(t)

	tenant2xx := func() float64 {
		return testutil.ToFloat64(gwmetrics.HTTPRequestsTotal.WithLabelValues(govTenant, http.MethodGet, "2xx"))
	}
	empty4xx := func() float64 {
		return testutil.ToFloat64(gwmetrics.HTTPRequestsTotal.WithLabelValues("", http.MethodGet, "4xx"))
	}
	tenant2xxBefore, empty4xxBefore := tenant2xx(), empty4xx()

	rec := doGov(t, h.s, http.MethodGet, "/v1/governance/tools", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/governance/tools = %d, want 200", rec.Code)
	}
	if got := tenant2xx() - tenant2xxBefore; got != 1 {
		t.Fatalf("http requests (tenant 2xx) = %v, want 1 new", got)
	}

	// Unauthenticated request: 401 recorded with an empty tenant id.
	req := govRequest(http.MethodGet, "/v1/governance/tools", "", "", "", "")
	rr := httptest.NewRecorder()
	h.s.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rr.Code)
	}
	if got := empty4xx() - empty4xxBefore; got != 1 {
		t.Fatalf("http requests (empty tenant 4xx) = %v, want 1 new", got)
	}

	// Wrong scope: 403 recorded under the tenant. The admin key inherits
	// every scope, so use a server whose key carries only the agents
	// scope and hit a governance route.
	agentsOnly := newGovServer(t, h.svc, runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "agents-only", Scopes: []string{"agents"},
	}, false, h.ex)
	tenant4xx := func() float64 {
		return testutil.ToFloat64(gwmetrics.HTTPRequestsTotal.WithLabelValues(govTenant, http.MethodGet, "4xx"))
	}
	tenant4xxBefore := tenant4xx()
	rec = doGov(t, agentsOnly, http.MethodGet, "/v1/governance/tools", govAdminKey, "", "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /v1/governance/tools (agents-only key) = %d, want 403", rec.Code)
	}
	if got := tenant4xx() - tenant4xxBefore; got != 1 {
		t.Fatalf("http requests (tenant 4xx) = %v, want 1 new", got)
	}
}
