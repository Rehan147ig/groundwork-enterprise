package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	gwmetrics "groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/runtime"
)

// fakeStore is an in-memory DeliveryStore for worker tests.
type fakeStore struct {
	mu        sync.Mutex
	events    map[string]*runtime.OutboxEvent
	order     []string
	reapCalls int
}

func newFakeStore(events ...runtime.OutboxEvent) *fakeStore {
	f := &fakeStore{events: map[string]*runtime.OutboxEvent{}}
	for _, e := range events {
		e.Status = runtime.OutboxStatusPending
		e.Attempts = 0
		e.NextAttemptAt = time.Now().Add(-time.Minute)
		f.events[e.ID] = &e
		f.order = append(f.order, e.ID)
	}
	return f
}

func (f *fakeStore) ListPendingOutbox(_ context.Context, limit int) ([]runtime.OutboxEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	out := make([]runtime.OutboxEvent, 0)
	for _, id := range f.order {
		e := f.events[id]
		if e.Status != runtime.OutboxStatusPending || e.NextAttemptAt.After(now) {
			continue
		}
		out = append(out, *e)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeStore) ClaimOutboxEvent(_ context.Context, eventID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.events[eventID]
	if e == nil || e.Status != runtime.OutboxStatusPending {
		return nil
	}
	e.Status = runtime.OutboxStatusDelivering
	e.Attempts++
	return nil
}

func (f *fakeStore) MarkOutboxDelivered(_ context.Context, eventID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e := f.events[eventID]; e != nil && e.Status == runtime.OutboxStatusDelivering {
		e.Status = runtime.OutboxStatusDelivered
	}
	return nil
}

func (f *fakeStore) MarkOutboxDeadLetter(_ context.Context, eventID, lastError string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e := f.events[eventID]; e != nil && e.Status == runtime.OutboxStatusDelivering {
		e.Status = runtime.OutboxStatusDeadLetter
		e.LastError = lastError
	}
	return nil
}

func (f *fakeStore) RescheduleOutboxEvent(_ context.Context, eventID string, nextAttemptAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e := f.events[eventID]; e != nil && e.Status == runtime.OutboxStatusDelivering {
		e.Status = runtime.OutboxStatusPending
		e.NextAttemptAt = nextAttemptAt
	}
	return nil
}

func (f *fakeStore) statuses() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for id, e := range f.events {
		out[id] = e.Status
	}
	return out
}

func sampleEvent(id string) runtime.OutboxEvent {
	return runtime.OutboxEvent{
		ID: id, TenantID: "tenant_demo", EventID: "evt-" + id,
		EventType: runtime.OutboxEventActionDecision, SchemaVersion: 1,
		OccurredAt: time.Now().UTC().Truncate(time.Microsecond),
		Payload:    json.RawMessage(`{"run_id":"run-1","decision":"deny","reason_code":"budget_exhausted:max_actions_per_run"}`),
	}
}

func TestWorkerDeliversSignedEvents(t *testing.T) {
	secret := []byte("test-secret")
	ok := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			ok <- "read error: " + err.Error()
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-Groundwork-Event-ID") == "" || r.Header.Get("X-Groundwork-Tenant-ID") != "tenant_demo" {
			ok <- "missing delivery headers"
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ts, _ := strconv.ParseInt(r.Header.Get("X-Groundwork-Timestamp"), 10, 64)
		sig := strings.TrimPrefix(r.Header.Get("X-Groundwork-Signature"), "v1=")
		eventID := r.Header.Get("X-Groundwork-Event-ID")
		if !VerifySignature(secret, ts, eventID, body, sig) {
			ok <- "signature mismatch for " + eventID
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !json.Valid(body) {
			ok <- "payload must be valid JSON: " + string(body)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ok <- ""
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	store := newFakeStore(sampleEvent("one"), sampleEvent("two"), sampleEvent("three"))
	w := NewWorker(store, Config{
		Endpoint: srv.URL, Secret: secret,
		PollInterval: 10 * time.Millisecond, BackoffBase: time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	for i := 0; i < 3; i++ {
		select {
		case msg := <-ok:
			if msg != "" {
				t.Fatalf("delivery rejected: %s", msg)
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for deliveries")
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st := store.statuses()
		if st["one"] == runtime.OutboxStatusDelivered && st["two"] == runtime.OutboxStatusDelivered && st["three"] == runtime.OutboxStatusDelivered {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for id, want := range map[string]string{"one": "delivered", "two": "delivered", "three": "delivered"} {
		if got := store.statuses()[id]; got != want {
			t.Fatalf("event %s: expected %s, got %s", id, want, got)
		}
	}
	cancel()
	<-done
}

func TestWorkerBackoffThenDeadLetter(t *testing.T) {
	secret := []byte("s")
	status := make(chan int, 1)
	status <- http.StatusInternalServerError
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := <-status
		status <- http.StatusInternalServerError
		w.WriteHeader(s)
	}))
	defer srv.Close()

	store := newFakeStore(sampleEvent("flaky"))
	w := NewWorker(store, Config{
		Endpoint: srv.URL, Secret: secret,
		PollInterval: time.Millisecond, MaxAttempts: 3,
		BackoffBase: time.Millisecond, BackoffCap: 5 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = w.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st := store.statuses()["flaky"]; st == runtime.OutboxStatusDeadLetter {
			cancel()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("event must reach dead_letter after max attempts, got %s", store.statuses()["flaky"])
}

func TestWorkerPreDeliverSkipsOverQuota(t *testing.T) {
	var (
		mu        sync.Mutex
		posts     int
		gateSeen  []string
		gateSkips int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posts++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	store := newFakeStore(sampleEvent("quota-ok"), sampleEvent("quota-deny"))
	store.events["quota-deny"].TenantID = "tenant_over"

	w := NewWorker(store, Config{
		Endpoint: srv.URL, PollInterval: time.Hour,
		PreDeliver: func(tenantID string) error {
			mu.Lock()
			gateSeen = append(gateSeen, tenantID)
			mu.Unlock()
			if tenantID == "tenant_over" {
				mu.Lock()
				gateSkips++
				mu.Unlock()
				return errors.New("quota_exceeded:outbox_deliveries")
			}
			return nil
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.tick(ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}

	// The denied event is left untouched (pending, zero attempts); the
	// allowed one is delivered exactly once.
	if got := store.statuses()["quota-deny"]; got != runtime.OutboxStatusPending {
		t.Fatalf("over-quota event must stay pending, got %s", got)
	}
	if got := store.events["quota-deny"].Attempts; got != 0 {
		t.Fatalf("over-quota event must not consume an attempt, got %d", got)
	}
	if got := store.statuses()["quota-ok"]; got != runtime.OutboxStatusDelivered {
		t.Fatalf("allowed event must be delivered, got %s", got)
	}
	if posts != 1 {
		t.Fatalf("expected exactly 1 webhook POST, got %d", posts)
	}
	if gateSkips != 1 {
		t.Fatalf("expected 1 quota skip, got %d", gateSkips)
	}
	mu.Lock()
	wantSeen := map[string]bool{"tenant_demo": true, "tenant_over": true}
	for _, tid := range gateSeen {
		delete(wantSeen, tid)
	}
	mu.Unlock()
	if len(wantSeen) != 0 {
		t.Fatalf("pre-deliver gate must see both tenants, missed %v", wantSeen)
	}
}

func TestWorkerReschedulesAfterFailure(t *testing.T) {
	secret := []byte("s")
	status := make(chan int, 1)
	status <- http.StatusInternalServerError
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := <-status
		status <- http.StatusOK
		w.WriteHeader(s)
	}))
	defer srv.Close()

	store := newFakeStore(sampleEvent("slow"))
	w := NewWorker(store, Config{
		Endpoint: srv.URL, Secret: secret,
		PollInterval: time.Millisecond, MaxAttempts: 8,
		BackoffBase: 2 * time.Millisecond, BackoffCap: 8 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = w.Run(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st := store.statuses()["slow"]; st == runtime.OutboxStatusDelivered {
			cancel()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("event must eventually deliver after failures, got %s", store.statuses()["slow"])
}

func TestVerifySignatureRejectsTampering(t *testing.T) {
	secret := []byte("secret")
	body := []byte(`{"a":1}`)
	good := signature(secret, 123, "evt-1", body)
	if !VerifySignature(secret, 123, "evt-1", body, good) {
		t.Fatal("valid signature must verify")
	}
	if VerifySignature(secret, 124, "evt-1", body, good) {
		t.Fatal("timestamp tampering must fail")
	}
	if VerifySignature(secret, 123, "evt-2", body, good) {
		t.Fatal("event id tampering must fail")
	}
	if VerifySignature(secret, 123, "evt-1", []byte(`{"a":2}`), good) {
		t.Fatal("body tampering must fail")
	}
	if VerifySignature([]byte("other"), 123, "evt-1", body, good) {
		t.Fatal("wrong secret must fail")
	}
}

// statsStore wraps fakeStore and reports canned outbox health stats so
// worker ticks publish gauges (Phase 8.5).
type statsStore struct {
	fakeStore
	stats []runtime.OutboxTenantStats
}

func (s *statsStore) OutboxPendingStats(context.Context) ([]runtime.OutboxTenantStats, error) {
	return s.stats, nil
}

func TestWorkerPublishesOutboxStats(t *testing.T) {
	gwmetrics.RegisterPhase8()
	store := &statsStore{stats: []runtime.OutboxTenantStats{
		{TenantID: "tenant_a", PendingCount: 3, OldestPendingAt: time.Now().UTC().Add(-90 * time.Second), DeadLetterCount: 2},
		{TenantID: "tenant_b", PendingCount: 0, DeadLetterCount: 0},
	}}
	w := NewWorker(store, Config{
		Endpoint: "http://127.0.0.1:1", PollInterval: time.Hour,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.tick(ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}

	if got := testutil.ToFloat64(gwmetrics.OutboxPending.WithLabelValues("tenant_a")); got != 3 {
		t.Fatalf("tenant_a pending = %v, want 3", got)
	}
	if got := testutil.ToFloat64(gwmetrics.OutboxPending.WithLabelValues("tenant_b")); got != 0 {
		t.Fatalf("tenant_b pending = %v, want 0", got)
	}
	if got := testutil.ToFloat64(gwmetrics.OutboxPendingAgeSeconds.WithLabelValues("tenant_a")); got < 80 || got > 100 {
		t.Fatalf("tenant_a pending age = %v, want ~90s", got)
	}
	if got := testutil.ToFloat64(gwmetrics.OutboxPendingAgeSeconds.WithLabelValues("tenant_b")); got != 0 {
		t.Fatalf("tenant_b pending age = %v, want 0", got)
	}
	if got := testutil.ToFloat64(gwmetrics.OutboxDeadLetterPending.WithLabelValues("tenant_a")); got != 2 {
		t.Fatalf("tenant_a dead letter = %v, want 2", got)
	}
	if got := testutil.ToFloat64(gwmetrics.OutboxDeadLetterPending.WithLabelValues("tenant_b")); got != 0 {
		t.Fatalf("tenant_b dead letter = %v, want 0", got)
	}
}

func TestWorkerRecordsDeliveryCounters(t *testing.T) {
	gwmetrics.RegisterPhase8()
	ok := make(chan struct{}, 1)
	ok <- struct{}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-ok:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	deliveredBefore := testutil.ToFloat64(gwmetrics.OutboxDeliveredTotal.WithLabelValues(runtime.OutboxEventActionDecision))
	w := NewWorker(newFakeStore(sampleEvent("metrics-ok")), Config{
		Endpoint: srv.URL, PollInterval: time.Hour,
	})
	if err := w.tick(context.Background()); err != nil {
		t.Fatalf("delivered tick: %v", err)
	}
	if got := testutil.ToFloat64(gwmetrics.OutboxDeliveredTotal.WithLabelValues(runtime.OutboxEventActionDecision)) - deliveredBefore; got != 1 {
		t.Fatalf("outbox delivered = %v, want 1 new", got)
	}

	deadBefore := testutil.ToFloat64(gwmetrics.OutboxDeadLetterTotal.WithLabelValues(runtime.OutboxEventActionDecision))
	w2 := NewWorker(newFakeStore(sampleEvent("metrics-dead")), Config{
		Endpoint: srv.URL, PollInterval: time.Hour, MaxAttempts: 1,
	})
	if err := w2.tick(context.Background()); err != nil {
		t.Fatalf("dead-letter tick: %v", err)
	}
	if got := testutil.ToFloat64(gwmetrics.OutboxDeadLetterTotal.WithLabelValues(runtime.OutboxEventActionDecision)) - deadBefore; got != 1 {
		t.Fatalf("outbox dead letters = %v, want 1 new", got)
	}
}

// plainStore is a DeliveryStore WITHOUT the stats capability; a tick must
// still succeed (gauges stay stale, no failure).
type plainStore struct{ fakeStore }

func TestWorkerTickSkipsStatsWhenUnsupported(t *testing.T) {
	w := NewWorker(&plainStore{}, Config{
		Endpoint: "http://127.0.0.1:1", PollInterval: time.Hour,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.tick(ctx); err != nil {
		t.Fatalf("tick must succeed without stats source: %v", err)
	}
}
