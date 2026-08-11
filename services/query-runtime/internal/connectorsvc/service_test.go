package connectorsvc

import (
	"context"
	"testing"

	"groundwork/query-runtime/internal/aclsync/github"
)

// TestLeakReport_OfflineCatchesLeak: with the Acme MockClient (no network,
// no relationship backend), LeakReport returns the connector-derived findings including
// the planted engineering→finance-budget cross-department exposure, mapped
// into the runtime.LeakFinding shape the console consumes.
func TestLeakReport_OfflineCatchesLeak(t *testing.T) {
	svc := New(github.NewMockClient(), "acme-financial", nil)
	res, err := svc.LeakReport(context.Background(), "acme-financial")
	if err != nil {
		t.Fatalf("LeakReport: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected findings, got none")
	}
	var crossDept bool
	for _, f := range res.Findings {
		if f.Kind == "cross_department_access" {
			crossDept = true
			if f.Severity != "high" {
				t.Fatalf("cross-department finding should be high severity: %+v", f)
			}
			if f.Title == "" || f.Detail == "" {
				t.Fatalf("finding missing title/detail for the console: %+v", f)
			}
		}
	}
	if !crossDept {
		t.Fatalf("expected a cross_department_access finding; got %+v", res.Findings)
	}
}

// TestSync_RequiresSink: Sync produces the snapshot but must fail
// clearly when it has nowhere to write tuples, rather than silently
// succeeding.
func TestSync_RequiresSink(t *testing.T) {
	svc := New(github.NewMockClient(), "acme-financial", nil)
	if _, err := svc.Sync(context.Background(), "acme-financial"); err == nil {
		t.Fatal("expected Sync to error when no authorization store is configured")
	}
}

func TestHumanize(t *testing.T) {
	if got := humanize("cross_department_access"); got != "Cross department access" {
		t.Fatalf("humanize: got %q", got)
	}
}
