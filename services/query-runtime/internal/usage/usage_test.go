package usage

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryStore_RecordCountsPerMonth(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	if n, err := s.Record(ctx, "acme", MetricAgents, 1); err != nil || n != 1 {
		t.Fatalf("record 1: n=%d err=%v", n, err)
	}
	if n, err := s.Record(ctx, "acme", MetricAgents, 2); err != nil || n != 3 {
		t.Fatalf("record 2: n=%d err=%v", n, err)
	}
	if n, err := s.MonthlyCount(ctx, "acme", MetricAgents); err != nil || n != 3 {
		t.Fatalf("monthly count = %d err=%v", n, err)
	}
	if n, err := s.TotalCount(ctx, "acme", MetricAgents); err != nil || n != 3 {
		t.Fatalf("total count = %d err=%v", n, err)
	}
	// Other metrics / tenants untouched.
	if n, _ := s.MonthlyCount(ctx, "acme", MetricRuns); n != 0 {
		t.Fatalf("runs should be 0, got %d", n)
	}
	if n, _ := s.MonthlyCount(ctx, "other", MetricAgents); n != 0 {
		t.Fatalf("other tenant agents should be 0, got %d", n)
	}
}

func TestMemoryStore_MonthlyLimitFailsClosed(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	if err := s.UpsertLimit(ctx, "acme", Limit{Metric: MetricAgents, Period: PeriodMonthly, Limit: 2}); err != nil {
		t.Fatalf("upsert limit: %v", err)
	}
	if _, err := s.Record(ctx, "acme", MetricAgents, 1); err != nil {
		t.Fatalf("record within limit: %v", err)
	}
	if _, err := s.Record(ctx, "acme", MetricAgents, 1); err != nil {
		t.Fatalf("record at limit: %v", err)
	}
	// Third unit must be denied AND not consume quota.
	_, err := s.Record(ctx, "acme", MetricAgents, 1)
	var qe *QuotaError
	if !errors.As(err, &qe) || qe.Metric != MetricAgents {
		t.Fatalf("expected QuotaError(agents), got %v", err)
	}
	if n, _ := s.MonthlyCount(ctx, "acme", MetricAgents); n != 2 {
		t.Fatalf("denied attempt consumed quota: count=%d", n)
	}
	// Other tenants unaffected by the limit.
	if _, err := s.Record(ctx, "other", MetricAgents, 5); err != nil {
		t.Fatalf("other tenant limited: %v", err)
	}
}

func TestMemoryStore_LifetimeLimitAndClear(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	if err := s.UpsertLimit(ctx, "acme", Limit{Metric: MetricRuns, Period: PeriodLifetime, Limit: 3}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.Record(ctx, "acme", MetricRuns, 1); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if _, err := s.Record(ctx, "acme", MetricRuns, 1); err == nil {
		t.Fatal("expected lifetime denial")
	}
	// Clearing the limit (0) restores recording.
	if err := s.UpsertLimit(ctx, "acme", Limit{Metric: MetricRuns, Period: PeriodLifetime, Limit: 0}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, err := s.Record(ctx, "acme", MetricRuns, 1); err != nil {
		t.Fatalf("record after clear: %v", err)
	}
	lims, err := s.Limits(ctx, "acme")
	if err != nil || len(lims) != 0 {
		t.Fatalf("limits after clear = %v err=%v", lims, err)
	}
}

func TestService_UsageSnapshot(t *testing.T) {
	s := NewService(NewMemoryStore())
	ctx := context.Background()
	if err := s.Record(ctx, "acme", MetricAgents, 2); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, err := s.UpsertLimits(ctx, "acme", []Limit{{Metric: MetricAgents, Period: PeriodMonthly, Limit: 5}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	usage, err := s.Usage(ctx, "acme")
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if len(usage) != len(AllMetrics())*2 {
		t.Fatalf("expected %d entries, got %d", len(AllMetrics())*2, len(usage))
	}
	found := false
	for _, u := range usage {
		if u.Metric == MetricAgents && u.Period == PeriodMonthly {
			found = true
			if u.Count != 2 || u.Limit != 5 || u.Remaining != 3 {
				t.Fatalf("agents monthly = %+v", u)
			}
		}
	}
	if !found {
		t.Fatal("agents monthly entry missing")
	}
	// Unlimited metrics report remaining -1.
	for _, u := range usage {
		if u.Metric == MetricRuns && u.Remaining != -1 {
			t.Fatalf("unlimited runs remaining = %d", u.Remaining)
		}
	}
}

func TestService_UpsertLimitsValidates(t *testing.T) {
	s := NewService(NewMemoryStore())
	_, err := s.UpsertLimits(context.Background(), "acme", []Limit{{Metric: MetricAgents, Period: "weekly", Limit: 5}})
	if err == nil {
		t.Fatal("expected validation error for unknown period")
	}
	_, err = s.UpsertLimits(context.Background(), "acme", []Limit{{Metric: "", Period: PeriodMonthly, Limit: 5}})
	if err == nil {
		t.Fatal("expected validation error for empty metric")
	}
}

func TestService_NilSafe(t *testing.T) {
	var s *Service
	if err := s.Record(context.Background(), "acme", MetricAgents, 1); err != nil {
		t.Fatalf("nil record: %v", err)
	}
	if u, err := s.Usage(context.Background(), "acme"); err != nil || len(u) != 0 {
		t.Fatalf("nil usage: %v %v", u, err)
	}
}
