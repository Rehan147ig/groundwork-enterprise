// Phase 8.1 usage metering HTTP surface tests: scope gating, the usage
// snapshot, limits upsert (verified identity + Idempotency-Key), and
// fail-closed quota enforcement at the recording points (agents).

package runtime_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundwork/query-runtime/internal/agentregistry"
	"groundwork/query-runtime/internal/runtime"
	"groundwork/query-runtime/internal/usage"
)

func newUsageServer(t *testing.T, meter runtime.UsageService, scopes []string) *runtime.Server {
	t.Helper()
	s := newGovServer(t, nil, runtime.TenantContext{TenantID: govTenant, Region: govRegion, KeyName: "usage-test", Scopes: scopes}, false, nil)
	s.SetUsageMeter(meter)
	return s
}

func usageRequest(method, path, key, assertion, body string) *http.Request {
	req := govRequest(method, path, key, assertion, "", body)
	return req
}

func doUsage(t *testing.T, s *runtime.Server, method, path, key, assertion, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := usageRequest(method, path, key, assertion, body)
	req.Header.Set("Idempotency-Key", "test-usage-idem")
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	return rec
}

func decodeUsage[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %T: %v (body %s)", out, err, rec.Body.String())
	}
	return out
}

// usageTestExecutor is a minimal QueryExecutor for the query metering
// test (the shared capturingExecutor lives in package runtime).
type usageTestExecutor struct{}

func (u *usageTestExecutor) Execute(_ context.Context, _ runtime.QueryRequest) runtime.QueryResponse {
	return runtime.QueryResponse{Answer: "usage-test-answer"}
}

func TestUsageRequiresUsageScope(t *testing.T) {
	s := newUsageServer(t, usage.NewService(usage.NewMemoryStore()), []string{"query"})
	rec := doUsage(t, s, http.MethodGet, "/v1/usage", govAdminKey, "", "")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "insufficient_scope") {
		t.Fatalf("expected 403 insufficient_scope, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = doUsage(t, s, http.MethodGet, "/v1/usage/limits", govAdminKey, "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for limits read, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUsageUnavailableWhenUnset(t *testing.T) {
	s := newUsageServer(t, nil, []string{"admin"})
	rec := doUsage(t, s, http.MethodGet, "/v1/usage", govAdminKey, "", "")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "usage_unavailable") {
		t.Fatalf("expected 503 usage_unavailable, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUsageSnapshotShapeAndLimitsLifecycle(t *testing.T) {
	svc := usage.NewService(usage.NewMemoryStore())
	s := newUsageServer(t, svc, []string{"admin"})

	// Record some usage directly so the snapshot has non-zero counts.
	if err := svc.Record(context.Background(), govTenant, usage.MetricAgents, 2); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := svc.Record(context.Background(), govTenant, usage.MetricRuns, 3); err != nil {
		t.Fatalf("record: %v", err)
	}

	rec := doUsage(t, s, http.MethodGet, "/v1/usage", govAdminKey, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("usage read: %d %s", rec.Code, rec.Body.String())
	}
	snap := decodeUsage[usage.UsageSnapshot](t, rec)
	if snap.TenantID != govTenant || snap.Period != "monthly" {
		t.Fatalf("snapshot = %+v", snap)
	}
	if len(snap.Usage) != len(usage.AllMetrics())*2 {
		t.Fatalf("expected %d usage rows, got %d", len(usage.AllMetrics())*2, len(snap.Usage))
	}
	for _, u := range snap.Usage {
		if u.Metric == usage.MetricAgents && u.Period == "monthly" {
			if u.Count != 2 || u.Limit != 0 || u.Remaining != -1 {
				t.Fatalf("agents monthly = %+v", u)
			}
		}
		if u.Metric == usage.MetricRuns && u.Period == "monthly" && u.Count != 3 {
			t.Fatalf("runs monthly = %+v", u)
		}
	}

	// Upsert limits (verified identity + Idempotency-Key via doUsage).
	body := `{"limits":[{"metric":"agents","period":"monthly","limit":5}]}`
	rec = doUsage(t, s, http.MethodPut, "/v1/usage/limits", govAdminKey, tokenFor(t, govOwner), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("limits upsert: %d %s", rec.Code, rec.Body.String())
	}
	lims := decodeUsage[usage.LimitsSnapshot](t, rec)
	if len(lims.Limits) != 1 || lims.Limits[0].Metric != usage.MetricAgents || lims.Limits[0].Limit != 5 {
		t.Fatalf("limits = %+v", lims.Limits)
	}

	rec = doUsage(t, s, http.MethodGet, "/v1/usage/limits", govAdminKey, "", "")
	lims = decodeUsage[usage.LimitsSnapshot](t, rec)
	if len(lims.Limits) != 1 || lims.Limits[0].Period != "monthly" {
		t.Fatalf("limits read = %+v", lims.Limits)
	}

	// Snapshot now pairs count with limit + remaining.
	rec = doUsage(t, s, http.MethodGet, "/v1/usage", govAdminKey, "", "")
	snap = decodeUsage[usage.UsageSnapshot](t, rec)
	for _, u := range snap.Usage {
		if u.Metric == usage.MetricAgents && u.Period == "monthly" {
			if u.Limit != 5 || u.Remaining != 3 {
				t.Fatalf("agents monthly with limit = %+v", u)
			}
		}
	}
}

func TestUsageLimitsRequireIdempotencyAndIdentity(t *testing.T) {
	s := newUsageServer(t, usage.NewService(usage.NewMemoryStore()), []string{"admin"})

	// Missing Idempotency-Key fails closed even with a valid identity.
	req := govRequest(http.MethodPut, "/v1/usage/limits", govAdminKey, tokenFor(t, govOwner), "", `{"limits":[]}`)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without Idempotency-Key, got %d: %s", rec.Code, rec.Body.String())
	}

	// Without a verified identity (demo off) the mutation fails closed.
	rec = doUsage(t, s, http.MethodPut, "/v1/usage/limits", govAdminKey, "", `{"limits":[]}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without identity, got %d: %s", rec.Code, rec.Body.String())
	}

	// Invalid period is rejected with 400.
	rec = doUsage(t, s, http.MethodPut, "/v1/usage/limits", govAdminKey, tokenFor(t, govOwner), `{"limits":[{"metric":"agents","period":"weekly","limit":5}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid period, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestUsageAgentsQuotaFailsClosed proves end-to-end enforcement: the
// agents limit is applied at POST /v1/agents and a denied create does
// not consume quota.
func TestUsageAgentsQuotaFailsClosed(t *testing.T) {
	svc := usage.NewService(usage.NewMemoryStore())
	s := newUsageServer(t, svc, []string{"admin"})
	s.SetAgentRegistry(agentregistry.NewService(agentregistry.NewMemoryStore()))
	s.SetIdentity(testVerifier{secret: "server-secret"}, false)

	// One agent under no limit.
	rec := doUsage(t, s, http.MethodPost, "/v1/agents", govAdminKey, tokenFor(t, govOwner), `{"name":"a1","risk_tier":"low"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create a1: %d %s", rec.Code, rec.Body.String())
	}

	// Lock the quota at the current count: further creates must fail.
	rec = doUsage(t, s, http.MethodPut, "/v1/usage/limits", govAdminKey, tokenFor(t, govOwner), `{"limits":[{"metric":"agents","period":"monthly","limit":1}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("set limit: %d %s", rec.Code, rec.Body.String())
	}
	rec = doUsage(t, s, http.MethodPost, "/v1/agents", govAdminKey, tokenFor(t, govOwner), `{"name":"a2","risk_tier":"low"}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "quota_exceeded:agents") {
		t.Fatalf("expected 403 quota_exceeded:agents, got %d: %s", rec.Code, rec.Body.String())
	}

	// The denied attempt must not consume quota.
	rec = doUsage(t, s, http.MethodGet, "/v1/usage", govAdminKey, "", "")
	snap := decodeUsage[usage.UsageSnapshot](t, rec)
	for _, u := range snap.Usage {
		if u.Metric == usage.MetricAgents && u.Period == "monthly" && u.Count != 1 {
			t.Fatalf("denied create consumed quota: %+v", u)
		}
	}
}

// TestUsageRunsMeteredOnQuery proves the /v1/query execution records
// the runs metric and that an exhausted runs quota fails the query
// closed.
func TestUsageRunsMeteredOnQuery(t *testing.T) {
	backend := runtime.NewMemoryBackend()
	apiKeys := runtime.NewMemoryAPIKeyResolver("gw_test_key", runtime.TenantContext{
		TenantID: "tenant_demo", Region: "uk", KeyName: "usage-query",
	})
	captor := &usageTestExecutor{}
	server := runtime.NewServerWithExecutor(runtime.Config{}, backend, apiKeys, captor)
	server.SetIdentity(testVerifier{secret: "server-secret"}, true)

	svc := usage.NewService(usage.NewMemoryStore())
	server.SetUsageMeter(svc)

	body := `{"user_id":"demo_user","question":"q"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/query", bytes.NewBufferString(body))
	req.Header.Set("X-Groundwork-API-Key", "gw_test_key")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("query: %d %s", rec.Code, rec.Body.String())
	}
	if runs := usageCountFor(t, svc, "tenant_demo", usage.MetricRuns); runs != 1 {
		t.Fatalf("runs count = %d, want 1", runs)
	}

	// Exhaust the runs quota, then the next query must fail closed.
	if _, err := svc.UpsertLimits(context.Background(), "tenant_demo", []usage.Limit{{Metric: usage.MetricRuns, Period: "monthly", Limit: 1}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/query", bytes.NewBufferString(body))
	req.Header.Set("X-Groundwork-API-Key", "gw_test_key")
	rec = httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "quota_exceeded:runs") {
		t.Fatalf("expected 403 quota_exceeded:runs, got %d: %s", rec.Code, rec.Body.String())
	}
	if runs := usageCountFor(t, svc, "tenant_demo", usage.MetricRuns); runs != 1 {
		t.Fatalf("denied query consumed quota: runs=%d", runs)
	}
}

func usageCountFor(t *testing.T, svc *usage.Service, tenantID, metric string) int64 {
	t.Helper()
	rows, err := svc.Usage(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	for _, u := range rows {
		if u.Metric == metric && u.Period == "monthly" {
			return u.Count
		}
	}
	return -1
}
