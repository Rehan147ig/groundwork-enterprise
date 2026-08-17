package leakreport

import (
	"context"
	"errors"
	"testing"
	"time"

	"groundwork/query-runtime/internal/aclsync"
)

// TestDiff_PermissionAddition_NewWorldReadable is the verification test
// for the drift surface: a permission addition in the current run must
// surface as a NewFinding, and it must be the world_readable finding for
// the newly public document.
func TestDiff_PermissionAddition_NewWorldReadable(t *testing.T) {
	// Previous run: a normal single-owner doc, no exposure.
	prev := Analyze(mkPS("acme",
		doc("budget.xlsx", []string{"finance-team"}, nil),
	), nil)

	// Current run: an operator granted user:* (public) viewer on an
	// additional document — introduced exposure.
	curr := Analyze(mkPS("acme",
		doc("budget.xlsx", []string{"finance-team"}, nil),
		doc("sharepoint-export.csv", nil, []string{"user:*"}),
	), nil)

	drift := Diff(prev, curr)

	if len(drift.NewFindings) != 1 {
		t.Fatalf("expected exactly 1 new finding, got %+v", drift.NewFindings)
	}
	f := drift.NewFindings[0]
	if f.Kind != KindWorldReadable || f.DocumentID != "sharepoint-export.csv" {
		t.Fatalf("expected world_readable finding for sharepoint-export.csv, got %+v", f)
	}
	if len(drift.ResolvedFindings) != 0 {
		t.Fatalf("no exposure was remediated; got resolved %+v", drift.ResolvedFindings)
	}
}

// TestDiff_PermissionRemoval_Resolved: removing the public grant must
// surface as a ResolvedFinding, not a new one.
func TestDiff_PermissionRemoval_Resolved(t *testing.T) {
	prev := Analyze(mkPS("acme",
		doc("sharepoint-export.csv", nil, []string{"user:*"}),
	), nil)
	curr := Analyze(mkPS("acme",
		doc("sharepoint-export.csv", []string{"finance-team"}, nil),
	), nil)

	drift := Diff(prev, curr)

	if len(drift.ResolvedFindings) != 1 ||
		drift.ResolvedFindings[0].Kind != KindWorldReadable ||
		drift.ResolvedFindings[0].DocumentID != "sharepoint-export.csv" {
		t.Fatalf("expected resolved world_readable for sharepoint-export.csv, got %+v", drift.ResolvedFindings)
	}
	if len(drift.NewFindings) != 0 {
		t.Fatalf("nothing was introduced; got new %+v", drift.NewFindings)
	}
}

// TestDiff_NoChange: identical reports must produce an empty drift.
func TestDiff_NoChange(t *testing.T) {
	ps := mkPS("acme",
		doc("budget.xlsx", []string{"finance-team"}, nil),
		doc("export.csv", nil, []string{"user:*"}),
	)
	prev := Analyze(ps, nil)
	curr := Analyze(ps, nil)

	drift := Diff(prev, curr)
	if len(drift.NewFindings) != 0 || len(drift.ResolvedFindings) != 0 {
		t.Fatalf("identical runs must not drift, got new=%+v resolved=%+v", drift.NewFindings, drift.ResolvedFindings)
	}
}

// TestDiff_SameFindingTwice: equal findings cancel one-to-one across
// runs (a task regenerating findings must not fabricate drift).
func TestDiff_SameFindingTwice(t *testing.T) {
	ps := mkPS("acme", doc("a", nil, []string{"user:*"}), doc("b", nil, []string{"user:*"}))
	prev := Analyze(ps, nil)
	curr := Analyze(ps, nil)

	drift := Diff(prev, curr)
	if len(drift.NewFindings) != 0 || len(drift.ResolvedFindings) != 0 {
		t.Fatalf("expected empty drift for repeated identical findings, got %+v", drift)
	}
}

func TestParseSchedule_Every(t *testing.T) {
	s, err := ParseSchedule("@every 6h")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	base := time.Date(2026, 8, 15, 10, 30, 0, 0, time.UTC)
	if next := s.Next(base); !next.Equal(base.Add(6 * time.Hour)) {
		t.Fatalf("Next(@every 6h) from %v = %v, want %v", base, next, base.Add(6*time.Hour))
	}
	if s.String() != "@every 6h" {
		t.Fatalf("String() = %q", s.String())
	}
}

func TestParseSchedule_FiveField(t *testing.T) {
	s, err := ParseSchedule("0 */6 * * *")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	base := time.Date(2026, 8, 15, 10, 30, 0, 0, time.UTC)
	if next := s.Next(base); !next.Equal(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("Next(0 */6) from %v = %v, want 12:00Z", base, next)
	}

	daily, err := ParseSchedule("0 2 * * *")
	if err != nil {
		t.Fatalf("parse daily: %v", err)
	}
	if next := daily.Next(base); !next.Equal(time.Date(2026, 8, 16, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("Next(0 2) from %v = %v, want next day 02:00Z", base, next)
	}
}

func TestParseSchedule_Invalid(t *testing.T) {
	for _, expr := range []string{"", "not-cron", "* * *", "60 * * * *", "0 24 * * *", "0 */x * * *", "0 */6 * * 7", "0 0 32 * *"} {
		if _, err := ParseSchedule(expr); err == nil {
			t.Fatalf("ParseSchedule(%q) should fail", expr)
		}
	}
}

func TestMemoryHistoryStore(t *testing.T) {
	store := NewMemoryHistoryStore()
	ctx := context.Background()

	if _, err := store.Latest(ctx, "acme"); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("Latest on empty store: %v", err)
	}

	id1, err := store.Save(ctx, Snapshot{
		TenantID:      "acme",
		RanAt:         time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC),
		DocumentCount: 2,
		GroupCount:    1,
		Findings:      []Finding{{Kind: KindWorldReadable, DocumentID: "export.csv"}},
	})
	if err != nil || id1 != 1 {
		t.Fatalf("first save: id=%d err=%v", id1, err)
	}
	id2, err := store.Save(ctx, Snapshot{
		TenantID:      "acme",
		RanAt:         time.Date(2026, 8, 15, 15, 0, 0, 0, time.UTC),
		DocumentCount: 2,
		GroupCount:    1,
		Findings:      nil,
	})
	if err != nil || id2 != 2 {
		t.Fatalf("second save: id=%d err=%v", id2, err)
	}

	latest, err := store.Latest(ctx, "acme")
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if latest.ID != 2 || len(latest.Findings) != 0 {
		t.Fatalf("latest = %+v, want id 2 with no findings", latest)
	}

	got, err := store.Get(ctx, "acme", id1)
	if err != nil || got.Findings[0].Kind != KindWorldReadable {
		t.Fatalf("get id1: %+v err=%v", got, err)
	}

	list, err := store.List(ctx, "acme", 0)
	if err != nil || len(list) != 2 || list[0].ID != 2 || list[1].ID != 1 {
		t.Fatalf("list = %+v err=%v", list, err)
	}
	if _, err := store.Latest(ctx, "other"); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("Latest on other tenant: %v", err)
	}
}

// TestScheduler_RunOnce_PermissionAddition tracks two scheduled cycles:
// the second snapshot gains a world_readable document and the cycle
// result reports the new exposure while the store keeps both runs.
func TestScheduler_RunOnce_PermissionAddition(t *testing.T) {
	ctx := context.Background()
	state := []aclsync.PermissionSet{
		mkPS("acme", doc("budget.xlsx", []string{"finance-team"}, nil)),
		mkPS("acme",
			doc("budget.xlsx", []string{"finance-team"}, nil),
			doc("sharepoint-export.csv", nil, []string{"user:*"}),
		),
	}
	called := 0
	provider := SnapshotFunc(func(_ context.Context, tenantID string) (aclsync.PermissionSet, error) {
		ps := state[called%len(state)]
		called++
		return ps, nil
	})

	store := NewMemoryHistoryStore()
	sched, err := NewScheduler("0 */6 * * *", store, provider, []string{"acme"}, nil)
	if err != nil {
		t.Fatalf("scheduler: %v", err)
	}

	first := sched.RunOnce(ctx)
	if len(first) != 1 || first[0].Err != nil {
		t.Fatalf("first cycle: %+v", first)
	}
	if first[0].Findings != 0 || first[0].New != 0 || first[0].Resolved != 0 {
		t.Fatalf("first cycle should be clean, got %+v", first[0])
	}

	second := sched.RunOnce(ctx)
	if len(second) != 1 || second[0].Err != nil {
		t.Fatalf("second cycle: %+v", second)
	}
	if second[0].New != 1 || second[0].Resolved != 0 || second[0].Findings != 1 {
		t.Fatalf("second cycle should add 1 finding, got %+v", second[0])
	}

	snaps, err := store.List(ctx, "acme", 0)
	if err != nil || len(snaps) != 2 {
		t.Fatalf("history: %d snapshots err=%v", len(snaps), err)
	}
	if len(snaps[0].Findings) != 1 || snaps[0].Findings[0].Kind != KindWorldReadable {
		t.Fatalf("latest snapshot missing world_readable finding: %+v", snaps[0])
	}
	latest, err := store.Latest(ctx, "acme")
	if err != nil || latest.ID != second[0].RunID {
		t.Fatalf("RunID %d != latest %d err=%v", second[0].RunID, latest.ID, err)
	}
}

// TestScheduler_RunOnce_ProviderError: a failed snapshot must not
// poison the store and must be reported on the result.
func TestScheduler_RunOnce_ProviderError(t *testing.T) {
	ctx := context.Background()
	provider := SnapshotFunc(func(_ context.Context, tenantID string) (aclsync.PermissionSet, error) {
		return aclsync.PermissionSet{}, errors.New("connector boom")
	})
	store := NewMemoryHistoryStore()
	sched, err := NewScheduler("@every 6h", store, provider, []string{"acme"}, nil)
	if err != nil {
		t.Fatalf("scheduler: %v", err)
	}

	res := sched.RunOnce(ctx)
	if len(res) != 1 || res[0].Err == nil {
		t.Fatalf("expected tenant error, got %+v", res)
	}
	if _, err := store.Latest(ctx, "acme"); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("failed cycle must not write a snapshot: %v", err)
	}
}

// TestHistoryService_DiffLatestTwo: the read service diffs the two most
// recent runs for the tenant only.
func TestHistoryService_DiffLatestTwo(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryHistoryStore()
	svc := NewHistoryService(store)
	if _, err := svc.Diff(ctx, "acme", 0, 0); err == nil {
		t.Fatal("diff on empty history must fail")
	}

	_, _ = store.Save(ctx, Snapshot{TenantID: "acme", RanAt: time.Now(), DocumentCount: 1,
		Findings: []Finding{{Kind: KindWorldReadable, DocumentID: "a"}}})
	if _, err := svc.Diff(ctx, "acme", 0, 0); err == nil {
		t.Fatal("diff with one snapshot must fail")
	}
	_, _ = store.Save(ctx, Snapshot{TenantID: "acme", RanAt: time.Now(), DocumentCount: 2,
		Findings: []Finding{{Kind: KindWorldReadable, DocumentID: "a"}, {Kind: KindOrphaned, DocumentID: "b"}}})

	drift, err := svc.Diff(ctx, "acme", 0, 0)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(drift.NewFindings) != 1 || drift.NewFindings[0].Kind != "orphaned_document" {
		t.Fatalf("new findings = %+v", drift.NewFindings)
	}
	entries, err := svc.List(ctx, "acme", 0)
	if err != nil || len(entries) != 2 {
		t.Fatalf("list: %d entries err=%v", len(entries), err)
	}
	if entries[0].Findings[0].Title == "" {
		t.Fatal("history entry finding should carry a humanized title")
	}
}
