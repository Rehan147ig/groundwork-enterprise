// Phase 8.1 noisy-neighbor protections: per-tenant rate limiting (429 +
// Retry-After) and per-tenant concurrency caps (503). Health endpoints
// stay exempt; other tenants are unaffected; defaults remain unlimited.

package runtime_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

type simpleExecutor struct{}

func (s *simpleExecutor) Execute(_ context.Context, _ runtime.QueryRequest) runtime.QueryResponse {
	return runtime.QueryResponse{Answer: "rate-test-answer"}
}

type blockingExecutor struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingExecutor) Execute(_ context.Context, _ runtime.QueryRequest) runtime.QueryResponse {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return runtime.QueryResponse{Answer: "rate-test-answer"}
}

func rateServer(t *testing.T, tenant runtime.TenantContext, ex runtime.QueryExecutor) *runtime.Server {
	t.Helper()
	s := newGovServer(t, nil, tenant, true, ex)
	return s
}

func doQuery(t *testing.T, s *runtime.Server, key string) *httptest.ResponseRecorder {
	t.Helper()
	req := govRequest(http.MethodPost, "/v1/query", key, "", "", `{"user_id":"u","question":"q"}`)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	return rec
}

func TestTenantRateLimitReturns429WithRetryAfter(t *testing.T) {
	s := rateServer(t, runtime.TenantContext{TenantID: govTenant, Region: govRegion, KeyName: "tenant-rl", Scopes: []string{"query"}}, &simpleExecutor{})
	s.SetTenantRateLimiter(runtime.NewTenantRateLimiterWindow(1, time.Minute))

	first := doQuery(t, s, govAdminKey)
	if first.Code != http.StatusOK {
		t.Fatalf("first request should pass (200), got %d: %s", first.Code, first.Body.String())
	}
	second := doQuery(t, s, govAdminKey)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request should be rate-limited (429), got %d: %s", second.Code, second.Body.String())
	}
	if ra := second.Header().Get("Retry-After"); ra == "" || strings.TrimSpace(ra) == "" {
		t.Fatal("rate-limited response must carry a Retry-After header")
	}
	var envelope map[string]string
	if err := json.Unmarshal(second.Body.Bytes(), &envelope); err != nil || envelope["error"] != "rate_limit_exceeded" {
		t.Fatalf("error envelope = %s", second.Body.String())
	}
}

func TestTenantRateLimitDoesNotAffectOtherTenants(t *testing.T) {
	limiter := runtime.NewTenantRateLimiterWindow(1, time.Minute)
	sA := rateServer(t, runtime.TenantContext{TenantID: "tenant_noisy", Region: govRegion, KeyName: "a", Scopes: []string{"query"}}, &simpleExecutor{})
	sA.SetTenantRateLimiter(limiter)
	sB := rateServer(t, runtime.TenantContext{TenantID: "tenant_quiet", Region: govRegion, KeyName: "b", Scopes: []string{"query"}}, &simpleExecutor{})
	sB.SetTenantRateLimiter(limiter)

	if code := doQuery(t, sA, govAdminKey).Code; code != http.StatusOK {
		t.Fatalf("noisy tenant first request: %d", code)
	}
	if code := doQuery(t, sA, govAdminKey).Code; code != http.StatusTooManyRequests {
		t.Fatalf("noisy tenant second request should be 429, got %d", code)
	}
	// The quiet tenant has its own window: it must not inherit the noisy
	// tenant's exhaustion (rpm=1 caps it at one request per window).
	if code := doQuery(t, sB, govAdminKey).Code; code != http.StatusOK {
		t.Fatalf("quiet tenant must not inherit the noisy tenant's budget, got %d", code)
	}
}

func TestTenantRateLimitExemptsHealthEndpoints(t *testing.T) {
	s := rateServer(t, runtime.TenantContext{TenantID: govTenant, Region: govRegion, KeyName: "tenant-rl", Scopes: []string{"query"}}, &simpleExecutor{})
	s.SetTenantRateLimiter(runtime.NewTenantRateLimiterWindow(1, time.Minute))

	for i := 0; i < 5; i++ {
		req := govRequest(http.MethodGet, "/healthz", govAdminKey, "", "", "")
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("healthz request %d should never be rate-limited, got %d", i, rec.Code)
		}
	}
}

func TestConcurrencyLimitReturns503(t *testing.T) {
	blocker := &blockingExecutor{started: make(chan struct{}), release: make(chan struct{})}

	s := rateServer(t, runtime.TenantContext{TenantID: govTenant, Region: govRegion, KeyName: "conc", Scopes: []string{"query"}}, blocker)
	s.SetConcurrencyLimiter(runtime.NewTenantConcurrencyLimiter(1))

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := govRequest(http.MethodPost, "/v1/query", govAdminKey, "", "", `{"user_id":"u","question":"q"}`)
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, req)
		firstDone <- rec
	}()

	select {
	case <-blocker.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first request never reached the executor")
	}

	second := doQuery(t, s, govAdminKey)
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("second request should be 503 at the concurrency cap, got %d: %s", second.Code, second.Body.String())
	}
	var envelope map[string]string
	if err := json.Unmarshal(second.Body.Bytes(), &envelope); err != nil || envelope["error"] != "concurrency_limit_exceeded" {
		t.Fatalf("error envelope = %s", second.Body.String())
	}

	close(blocker.release)
	select {
	case first := <-firstDone:
		if first.Code != http.StatusOK {
			t.Fatalf("first request should complete 200 after release, got %d", first.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first request never completed after release")
	}

	third := doQuery(t, s, govAdminKey)
	if third.Code != http.StatusOK {
		t.Fatalf("request after release should pass (200), got %d: %s", third.Code, third.Body.String())
	}
}

func TestConcurrencyLimitDoesNotAffectOtherTenants(t *testing.T) {
	blocker := &blockingExecutor{started: make(chan struct{}), release: make(chan struct{})}

	limiter := runtime.NewTenantConcurrencyLimiter(1)
	sNoisy := rateServer(t, runtime.TenantContext{TenantID: "tenant_noisy", Region: govRegion, KeyName: "a", Scopes: []string{"query"}}, blocker)
	sNoisy.SetConcurrencyLimiter(limiter)
	sQuiet := rateServer(t, runtime.TenantContext{TenantID: "tenant_quiet", Region: govRegion, KeyName: "b", Scopes: []string{"query"}}, &simpleExecutor{})
	sQuiet.SetConcurrencyLimiter(limiter)

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := govRequest(http.MethodPost, "/v1/query", govAdminKey, "", "", `{"user_id":"u","question":"q"}`)
		rec := httptest.NewRecorder()
		sNoisy.Routes().ServeHTTP(rec, req)
		firstDone <- rec
	}()

	select {
	case <-blocker.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first request never reached the executor")
	}

	if code := doQuery(t, sQuiet, govAdminKey).Code; code != http.StatusOK {
		t.Fatalf("quiet tenant must not be affected by noisy tenant's in-flight request, got %d", code)
	}
	close(blocker.release)
	<-firstDone
}

// Bytes import is unused in this file but kept for parity with govRequest
// usages elsewhere; remove if the compiler flags it.
var _ = bytes.NewReader
