//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"groundwork/query-runtime/internal/usage"
)

// TestUsagePostgresRecordAndLimits proves the Postgres usage store
// (migration 025): atomic counter upserts, fail-closed quota
// enforcement with rollback, limit upsert/clear, and lifetime sums.
func TestUsagePostgresRecordAndLimits(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)
	ctx := context.Background()

	store := usage.NewPostgresStore(db)
	tenant := "tenant_usage_" + unique()

	// Record accumulates into the current-month counter.
	if _, err := store.Record(ctx, tenant, usage.MetricRuns, 1); err != nil {
		t.Fatalf("record 1: %v", err)
	}
	if _, err := store.Record(ctx, tenant, usage.MetricRuns, 4); err != nil {
		t.Fatalf("record 4: %v", err)
	}
	if n, err := store.MonthlyCount(ctx, tenant, usage.MetricRuns); err != nil || n != 5 {
		t.Fatalf("monthly = %d err=%v", n, err)
	}
	if n, err := store.TotalCount(ctx, tenant, usage.MetricRuns); err != nil || n != 5 {
		t.Fatalf("total = %d err=%v", n, err)
	}

	// Monthly limit: the over-limit increment fails closed AND is rolled
	// back (a denied attempt never consumes quota).
	if err := store.UpsertLimit(ctx, tenant, usage.Limit{Metric: usage.MetricRuns, Period: usage.PeriodMonthly, Limit: 6}); err != nil {
		t.Fatalf("upsert limit: %v", err)
	}
	if _, err := store.Record(ctx, tenant, usage.MetricRuns, 1); err != nil {
		t.Fatalf("record to limit: %v", err)
	}
	if _, err := store.Record(ctx, tenant, usage.MetricRuns, 1); err == nil {
		t.Fatal("expected quota denial at limit 6 with count 6")
	} else {
		var qe *usage.QuotaError
		if !errors.As(err, &qe) || qe.Metric != usage.MetricRuns {
			t.Fatalf("expected QuotaError(runs), got %v", err)
		}
	}
	if n, _ := store.MonthlyCount(ctx, tenant, usage.MetricRuns); n != 6 {
		t.Fatalf("denied attempt consumed quota: count=%d", n)
	}

	// Other metrics and tenants are isolated.
	if _, err := store.Record(ctx, tenant, usage.MetricAgents, 1); err != nil {
		t.Fatalf("other metric: %v", err)
	}
	if _, err := store.Record(ctx, "tenant_usage_other_"+unique(), usage.MetricRuns, 100); err != nil {
		t.Fatalf("other tenant: %v", err)
	}
	if n, _ := store.MonthlyCount(ctx, tenant, usage.MetricAgents); n != 1 {
		t.Fatalf("agents = %d", n)
	}

	// Clearing a limit (Limit <= 0) restores recording.
	if err := store.UpsertLimit(ctx, tenant, usage.Limit{Metric: usage.MetricRuns, Period: usage.PeriodMonthly, Limit: 0}); err != nil {
		t.Fatalf("clear limit: %v", err)
	}
	if _, err := store.Record(ctx, tenant, usage.MetricRuns, 1); err != nil {
		t.Fatalf("record after clear: %v", err)
	}
	lims, err := store.Limits(ctx, tenant)
	if err != nil {
		t.Fatalf("limits: %v", err)
	}
	for _, l := range lims {
		if l.Metric == usage.MetricRuns {
			t.Fatalf("runs limit should be cleared, got %+v", l)
		}
	}
}

// TestUsagePostgresTenantIsolation proves limit rows and counters never
// leak across tenants.
func TestUsagePostgresTenantIsolation(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)
	ctx := context.Background()

	store := usage.NewPostgresStore(db)
	tenantA := "tenant_usage_a_" + unique()
	tenantB := "tenant_usage_b_" + unique()

	if err := store.UpsertLimit(ctx, tenantA, usage.Limit{Metric: usage.MetricExports, Period: usage.PeriodMonthly, Limit: 1}); err != nil {
		t.Fatalf("upsert A: %v", err)
	}
	// Tenant A is limited; tenant B (no limit) is not affected.
	if _, err := store.Record(ctx, tenantB, usage.MetricExports, 50); err != nil {
		t.Fatalf("B record: %v", err)
	}
	if n, _ := store.MonthlyCount(ctx, tenantB, usage.MetricExports); n != 50 {
		t.Fatalf("B exports = %d", n)
	}
	lims, err := store.Limits(ctx, tenantB)
	if err != nil || len(lims) != 0 {
		t.Fatalf("B limits = %v err=%v", lims, err)
	}
	lims, err = store.Limits(ctx, tenantA)
	if err != nil || len(lims) != 1 || lims[0].Metric != usage.MetricExports {
		t.Fatalf("A limits = %v err=%v", lims, err)
	}
}
