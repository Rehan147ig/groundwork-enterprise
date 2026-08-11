package governance

import (
	"testing"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

func TestMemoryStoreOutboxPendingStats(t *testing.T) {
	clock := &clockFunc{t: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}
	store := NewMemoryStore()
	store.SetClock(clock.now)

	enqueue := func(tenantID, eventID string) {
		t.Helper()
		if err := store.EnqueueOutbox(testCtx, runtime.OutboxEvent{
			TenantID: tenantID, EventID: eventID, EventType: runtime.OutboxEventActionDecision,
		}); err != nil {
			t.Fatalf("enqueue %s/%s: %v", tenantID, eventID, err)
		}
	}
	enqueue("tenant_a", "e1")
	enqueue("tenant_a", "e2")
	enqueue("tenant_b", "e3")

	stats, err := store.OutboxPendingStats(testCtx)
	if err != nil {
		t.Fatalf("OutboxPendingStats: %v", err)
	}
	if len(stats) != 2 {
		t.Fatalf("want 2 tenants, got %d", len(stats))
	}
	a, b := stats[0], stats[1]
	if a.TenantID != "tenant_a" || b.TenantID != "tenant_b" {
		t.Fatalf("unexpected order: %+v", stats)
	}
	if a.DeadLetterCount != 0 || a.OldestPendingAt.IsZero() || a.PendingCount != 2 {
		t.Fatalf("tenant_a: want 0 dead letters + nonzero oldest pending + 2 pending, got %+v", a)
	}
	if b.DeadLetterCount != 0 || b.OldestPendingAt.IsZero() || b.PendingCount != 1 {
		t.Fatalf("tenant_b: want 0 dead letters + nonzero oldest pending + 1 pending, got %+v", b)
	}

	// Dead-letter e1 (the tenant_a oldest pending) via the delivery map.
	e1, err := store.GetOutboxEventByID(testCtx, "tenant_a", "e1")
	if err != nil {
		t.Fatalf("get e1: %v", err)
	}
	if err := store.MarkOutboxDeadLetter(testCtx, e1.ID, "webhook 500"); err != nil {
		t.Fatalf("dead-letter e1: %v", err)
	}

	stats, err = store.OutboxPendingStats(testCtx)
	if err != nil {
		t.Fatalf("OutboxPendingStats after dead-letter: %v", err)
	}
	a = stats[0]
	if a.DeadLetterCount != 1 {
		t.Fatalf("tenant_a: want 1 dead letter, got %d", a.DeadLetterCount)
	}
	if a.PendingCount != 1 {
		t.Fatalf("tenant_a: want 1 pending after dead-letter, got %d", a.PendingCount)
	}
	if e2, _ := store.GetOutboxEventByID(testCtx, "tenant_a", "e2"); a.OldestPendingAt != e2.CreatedAt {
		t.Fatalf("tenant_a oldest pending must advance to e2 after e1 dead-lettered: got %v, want %v", a.OldestPendingAt, e2.CreatedAt)
	}
}
