// Phase 8.2 overload protection: instance-wide in-flight cap sheds
// load when the whole process is saturated. New requests get an
// immediate 503 overload_exceeded + Retry-After instead of piling onto
// a queue; no request is ever queued; health stays exempt.

package runtime_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

func TestOverloadLimitReturns503Immediately(t *testing.T) {
	blocker := &blockingExecutor{started: make(chan struct{}), release: make(chan struct{})}

	s := rateServer(t, runtime.TenantContext{TenantID: govTenant, Region: govRegion, KeyName: "ovl", Scopes: []string{"query"}}, blocker)
	s.SetOverloadLimiter(runtime.NewOverloadLimiter(1))

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

	start := time.Now()
	second := doQuery(t, s, govAdminKey)
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("second request should be 503 at the overload cap, got %d: %s", second.Code, second.Body.String())
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("overload refusal must be immediate (no queueing), took %v", elapsed)
	}
	if ra := second.Header().Get("Retry-After"); ra == "" || strings.TrimSpace(ra) == "" {
		t.Fatal("overload response must carry a Retry-After header")
	}
	var envelope map[string]string
	if err := json.Unmarshal(second.Body.Bytes(), &envelope); err != nil || envelope["error"] != "overload_exceeded" {
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

func TestOverloadLimitExemptsHealthEndpoints(t *testing.T) {
	s := rateServer(t, runtime.TenantContext{TenantID: govTenant, Region: govRegion, KeyName: "ovl", Scopes: []string{"query"}}, &blockingExecutor{started: make(chan struct{}), release: make(chan struct{})})
	s.SetOverloadLimiter(runtime.NewOverloadLimiter(1))

	for i := 0; i < 3; i++ {
		req := govRequest(http.MethodGet, "/healthz", govAdminKey, "", "", "")
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("healthz request %d should never be overload-refused, got %d", i, rec.Code)
		}
	}
}

func TestOverloadLimitNoopWhenUnset(t *testing.T) {
	s := rateServer(t, runtime.TenantContext{TenantID: govTenant, Region: govRegion, KeyName: "ovl", Scopes: []string{"query"}}, &simpleExecutor{})
	// No limiter wired: capacity is effectively unlimited.
	if code := doQuery(t, s, govAdminKey).Code; code != http.StatusOK {
		t.Fatalf("request without an overload limiter should pass, got %d", code)
	}
}

var _ = context.Background
