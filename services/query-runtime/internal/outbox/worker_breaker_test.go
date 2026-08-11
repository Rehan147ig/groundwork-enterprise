// Phase 8.2 delivery circuit: a dead webhook opens the tenant's circuit
// after 3 consecutive failures and the worker stops POSTing (events stay
// pending, no attempt consumed) until a probe succeeds. A dead endpoint
// is priced in failed attempts once, not every poll cycle. Circuits are
// per tenant.

package outbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	gwmetrics "groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/runtime"
)

func breakerWorker(t *testing.T, endpoint string, openTimeout time.Duration) (*Worker, *fakeStore) {
	t.Helper()
	store := newFakeStore()
	w := NewWorker(store, Config{
		Endpoint:            endpoint,
		HTTPClient:          &http.Client{Timeout: 2 * time.Second},
		PollInterval:        10 * time.Millisecond,
		BackoffBase:         time.Millisecond,
		BackoffCap:          time.Millisecond,
		MaxAttempts:         8,
		BreakerFailureLimit: 3,
		BreakerOpenTimeout:  openTimeout,
	})
	return w, store
}

func event(id, tenant string) runtime.OutboxEvent {
	return runtime.OutboxEvent{
		ID: id, EventID: id, TenantID: tenant, EventType: "evidence.created",
		Payload: []byte(`{}`), Attempts: 0,
		Status:        runtime.OutboxStatusPending,
		NextAttemptAt: time.Now().Add(-time.Minute),
	}
}

func TestWorkerBreakerOpensAndSkipsWithoutPosting(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	w, store := breakerWorker(t, ts.URL, time.Hour) // stays open for the test
	ev := event("e1", "tenant-a")
	store.events[ev.ID] = &ev

	// 3 failures trip the circuit; every subsequent call skips.
	for i := 0; i < 6; i++ {
		_ = w.deliver(context.Background(), *store.events[ev.ID]) // failures reschedule and return the webhook error
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("webhook hit %d times, want 3 (failures only, skips must not POST)", got)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if e := store.events[ev.ID]; e.Status != runtime.OutboxStatusPending {
		t.Fatalf("skipped event must stay pending, got %s", e.Status)
	}
	if e := store.events[ev.ID]; e.Attempts != 3 {
		t.Fatalf("attempts = %d, want 3 (skips must not consume attempts)", e.Attempts)
	}
	if skips := testutil.ToFloat64(gwmetrics.OutboxDeliveryBreakerSkipsTotal.WithLabelValues("tenant-a")); skips != 3 {
		t.Fatalf("breaker skip counter = %v, want 3", skips)
	}
	if trips := testutil.ToFloat64(gwmetrics.OutboxDeliveryBreakerTripsTotal.WithLabelValues("tenant-a")); trips != 1 {
		t.Fatalf("breaker trip counter = %v, want 1", trips)
	}
	if state := testutil.ToFloat64(gwmetrics.OutboxDeliveryBreakerState.WithLabelValues("tenant-a")); state != 2 {
		t.Fatalf("breaker state = %v, want 2 (open)", state)
	}
}

func TestWorkerBreakerProbeClosesOnRecovery(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	w, store := breakerWorker(t, ts.URL, 40*time.Millisecond)
	ev := event("e1", "tenant-a")
	store.events[ev.ID] = &ev

	for i := 0; i < 3; i++ {
		_ = w.deliver(context.Background(), *store.events[ev.ID]) // expected failures
	}
	// 4th call: circuit open -> skip (no POST).
	if err := w.deliver(context.Background(), *store.events[ev.ID]); err != nil {
		t.Fatalf("skipped deliver: %v", err)
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("hits after skip = %d, want 3", got)
	}

	// After the open timeout a probe goes through; the recovered
	// endpoint answers 200 and the event delivers.
	time.Sleep(60 * time.Millisecond)
	if err := w.deliver(context.Background(), *store.events[ev.ID]); err != nil {
		t.Fatalf("probe deliver: %v", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if e := store.events[ev.ID]; e.Status != runtime.OutboxStatusDelivered {
		t.Fatalf("probe must deliver the event, got %s", e.Status)
	}
	if state := testutil.ToFloat64(gwmetrics.OutboxDeliveryBreakerState.WithLabelValues("tenant-a")); state != 0 {
		t.Fatalf("breaker state after recovery = %v, want 0 (closed)", state)
	}
}

func TestWorkerBreakerIsPerTenant(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	w, store := breakerWorker(t, ts.URL, time.Hour)
	for _, ev := range []runtime.OutboxEvent{event("a1", "tenant-a"), event("b1", "tenant-b")} {
		store.events[ev.ID] = &ev
	}

	for i := 0; i < 3; i++ {
		_ = w.deliver(context.Background(), *store.events["a1"]) // expected failures
	}
	// Tenant A's circuit is open; tenant B's delivery must proceed (and
	// fail on the dead endpoint like any normal attempt, but never be
	// skipped by A's circuit).
	_ = w.deliver(context.Background(), *store.events["b1"])
	if skips := testutil.ToFloat64(gwmetrics.OutboxDeliveryBreakerSkipsTotal.WithLabelValues("tenant-b")); skips != 0 {
		t.Fatalf("tenant B must not inherit tenant A's open circuit (skips = %v)", skips)
	}
	if got := hits.Load(); got != 4 {
		t.Fatalf("hits = %d, want 4 (3 failures for A + 1 attempt for B)", got)
	}
}
