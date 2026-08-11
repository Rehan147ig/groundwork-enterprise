// Phase 8.2 capacity model: per-tenant in-flight caps derived from the
// tenant directory's deployment tier. A standard tenant at its cap is
// rejected 503 while an enterprise tenant on the same instance keeps
// passing (higher tier cap); tenants outside the directory fall back to
// the model default.

package runtime_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"groundwork/query-runtime/internal/runtime"
	"groundwork/query-runtime/internal/tenancy"
)

func TestCapacityModelConcurrencyFor(t *testing.T) {
	model := &runtime.CapacityModel{
		DefaultLimit: 1,
		Concurrency: map[string]int{
			runtime.CapacityTierStandard:   1,
			runtime.CapacityTierPlus:       2,
			runtime.CapacityTierEnterprise: 5,
		},
	}
	if got := model.ConcurrencyFor(runtime.CapacityTierStandard); got != 1 {
		t.Fatalf("standard = %d", got)
	}
	if got := model.ConcurrencyFor(runtime.CapacityTierEnterprise); got != 5 {
		t.Fatalf("enterprise = %d", got)
	}
	if got := model.ConcurrencyFor("unknown-tier"); got != 1 {
		t.Fatalf("unknown tier must fall back to the default, got %d", got)
	}
	if got := model.ConcurrencyFor(""); got != 1 {
		t.Fatalf("empty tier must fall back to the default, got %d", got)
	}
	var nilModel *runtime.CapacityModel
	if got := nilModel.ConcurrencyFor(runtime.CapacityTierEnterprise); got != 0 {
		t.Fatalf("nil model must be unlimited (0), got %d", got)
	}
}

func TestConcurrencyLimiterAcquireWithLimit(t *testing.T) {
	cl := runtime.NewTenantConcurrencyLimiter(1)
	r1, ok := cl.AcquireWithLimit("t-a", 2)
	if !ok {
		t.Fatal("first acquire under limit 2 must succeed")
	}
	r2, ok := cl.AcquireWithLimit("t-a", 2)
	if !ok {
		t.Fatal("second acquire under limit 2 must succeed")
	}
	if _, ok := cl.AcquireWithLimit("t-a", 2); ok {
		t.Fatal("third acquire must hit the per-call cap")
	}
	if _, ok := cl.AcquireWithLimit("t-b", 2); !ok {
		t.Fatal("an idle tenant must not inherit another tenant's exhaustion")
	}
	if _, ok := cl.AcquireWithLimit("t-b", 0); !ok {
		t.Fatal("limit 0 must be unlimited")
	}
	r1()
	r3, ok := cl.AcquireWithLimit("t-a", 2)
	if !ok {
		t.Fatal("acquire must succeed after a release frees a slot")
	}
	r2()
	r3()
	// Draining the channel returns the tenant to a fresh, reusable state.
	if release, ok := cl.AcquireWithLimit("t-a", 2); !ok || release == nil {
		t.Fatal("a drained tenant must be acquirable again")
	} else {
		release()
	}
	// The plain Acquire path uses the constructor default.
	if _, ok := cl.Acquire("t-default"); !ok {
		t.Fatal("constructor default acquire must succeed when idle")
	}
	if _, ok := cl.Acquire("t-default"); ok {
		t.Fatal("constructor default (1) caps the second acquire")
	}
	var nilCL *runtime.TenantConcurrencyLimiter
	if release, ok := nilCL.AcquireWithLimit("t-c", 1); !ok || release == nil {
		t.Fatal("nil limiter AcquireWithLimit must no-op succeed")
	}
	if release, ok := nilCL.Acquire("t-c"); !ok || release == nil {
		t.Fatal("nil limiter Acquire must no-op succeed")
	}
}

// firstBlockExecutor blocks only the first request in flight until
// release is closed; later requests complete immediately, so requests
// that pass the middleware (higher tier caps) are not held up.
type firstBlockExecutor struct {
	started  chan struct{}
	release  chan struct{}
	once     sync.Once
	mu       sync.Mutex
	inFlight int
}

func (b *firstBlockExecutor) Execute(_ context.Context, _ runtime.QueryRequest) runtime.QueryResponse {
	b.once.Do(func() { close(b.started) })
	b.mu.Lock()
	block := b.inFlight == 0
	b.inFlight++
	b.mu.Unlock()
	if block {
		<-b.release
	}
	return runtime.QueryResponse{Answer: "capacity-test-answer"}
}

// capacityServer wires a real tenancy directory + capacity model into a
// server, mirroring cmd/query-runtime.
func capacityServer(t *testing.T, keys *runtime.MemoryAPIKeyResolver, svc runtime.TenantService, ex runtime.QueryExecutor, model *runtime.CapacityModel) *runtime.Server {
	t.Helper()
	s := runtime.NewServerWithExecutor(runtime.Config{}, runtime.NewMemoryBackend(), keys, ex)
	s.SetTenantService(svc)
	s.SetIdentity(testVerifier{secret: "server-secret"}, true)
	s.SetConcurrencyLimiter(runtime.NewTenantConcurrencyLimiter(1))
	s.SetCapacityModel(model)
	return s
}

// mintTierKey provisions a tenant at a tier and mints its admin key.
func mintTierKey(t *testing.T, keys *runtime.MemoryAPIKeyResolver, svc runtime.TenantService, tenantID, tier string) string {
	t.Helper()
	if _, err := svc.Provision(context.Background(), "test-operator", runtime.ProvisionTenantRequest{
		TenantID: tenantID, Region: govRegion, Tier: tier, Reason: "capacity test",
	}); err != nil {
		t.Fatalf("Provision(%s): %v", tenantID, err)
	}
	resp, err := keys.Create(context.Background(), runtime.TenantContext{TenantID: tenantID, Region: govRegion},
		runtime.CreateAPIKeyRequest{Name: "tier-test", Scopes: []string{"admin", "query"}})
	if err != nil {
		t.Fatalf("Create key(%s): %v", tenantID, err)
	}
	return resp.Key
}

// TestCapacityModelTierGrantsMoreHeadroom: on one instance (shared
// limiter) the standard tenant is rejected 503 at its cap while the
// enterprise tenant keeps passing; an unprovisioned tenant falls back to
// the model default and is rejected at the default cap.
func TestCapacityModelTierGrantsMoreHeadroom(t *testing.T) {
	model := &runtime.CapacityModel{
		DefaultLimit: 1,
		Concurrency: map[string]int{
			runtime.CapacityTierStandard:   1,
			runtime.CapacityTierPlus:       2,
			runtime.CapacityTierEnterprise: 5,
		},
	}
	blocker := &firstBlockExecutor{started: make(chan struct{}), release: make(chan struct{})}
	keys := runtime.NewMemoryAPIKeyResolver(govAdminKey, runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "capacity-admin", Scopes: []string{"admin", "query"},
	})
	svc := tenancy.NewService(tenancy.NewMemoryStore(), keys)
	s := capacityServer(t, keys, svc, blocker, model)

	stdKey := mintTierKey(t, keys, svc, "tenant-standard", runtime.CapacityTierStandard)
	entKey := mintTierKey(t, keys, svc, "tenant-enterprise", runtime.CapacityTierEnterprise)

	// Standard tenant: first request in flight, second rejected (cap 1).
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstDone <- doQuery(t, s, stdKey)
	}()
	select {
	case <-blocker.started:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked request never reached the executor")
	}

	second := doQuery(t, s, stdKey)
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("standard tenant at its cap must get 503, got %d: %s", second.Code, second.Body.String())
	}
	var envelope map[string]string
	if err := json.Unmarshal(second.Body.Bytes(), &envelope); err != nil || envelope["error"] != "concurrency_limit_exceeded" {
		t.Fatalf("error envelope = %s", second.Body.String())
	}
	if ra := second.Header().Get("Retry-After"); ra == "" || strings.TrimSpace(ra) == "" {
		t.Fatal("capacity rejection must carry a Retry-After header")
	}

	// Enterprise tenant on the same instance: tier cap 5, keeps passing.
	if code := doQuery(t, s, entKey).Code; code != http.StatusOK {
		t.Fatalf("enterprise tenant must keep its headroom, got %d", code)
	}
	if code := doQuery(t, s, entKey).Code; code != http.StatusOK {
		t.Fatalf("enterprise tenant second request must keep passing, got %d", code)
	}

	// Standard tenant recovers once the in-flight request completes.
	close(blocker.release)
	if code := (<-firstDone).Code; code != http.StatusOK {
		t.Fatalf("blocked request should complete 200 after release, got %d", code)
	}
	if code := doQuery(t, s, stdKey).Code; code != http.StatusOK {
		t.Fatalf("standard tenant after release must pass, got %d", code)
	}

	// Unprovisioned tenant: not in the directory, model default (1) cap.
	ghostKey, err := keys.Create(context.Background(), runtime.TenantContext{TenantID: "tenant-ghost", Region: govRegion},
		runtime.CreateAPIKeyRequest{Name: "ghost", Scopes: []string{"query"}})
	if err != nil {
		t.Fatalf("Create ghost key: %v", err)
	}
	ghostBlocker := &firstBlockExecutor{started: make(chan struct{}), release: make(chan struct{})}
	gs := capacityServer(t, keys, svc, ghostBlocker, model)
	ghostDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		ghostDone <- doQuery(t, gs, ghostKey.Key)
	}()
	select {
	case <-ghostBlocker.started:
	case <-time.After(5 * time.Second):
		t.Fatal("ghost request never reached the executor")
	}
	if code := doQuery(t, gs, ghostKey.Key).Code; code != http.StatusServiceUnavailable {
		t.Fatalf("unprovisioned tenant must fall back to the default cap (503), got %d", code)
	}
	close(ghostBlocker.release)
	if code := (<-ghostDone).Code; code != http.StatusOK {
		t.Fatalf("ghost blocked request should complete 200 after release, got %d", code)
	}
}
