package aclsync_test

import (
	"context"
	"testing"

	"groundwork/query-runtime/internal/aclsync"
)

// TestMockConnector_PermissionMapping verifies that the enterprise-style
// MockConnector snapshot maps onto the relationship model: group
// membership (including nested groups), folder-level viewer grants, and
// folder→document viewer inheritance all resolve through the in-memory
// evaluator.
func TestMockConnector_PermissionMapping(t *testing.T) {
	ctx := context.Background()
	ps, err := aclsync.NewMockConnector().Snapshot(ctx, "tenant_demo")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	store := aclsync.NewMemoryTupleSink()
	if err := store.WriteTuples(ctx, "tenant_demo", aclsync.PermissionSetToTuples(ps)); err != nil {
		t.Fatalf("WriteTuples: %v", err)
	}

	tests := []struct {
		user     string
		doc      string
		expected bool
	}{
		{"user:finance_user", "document:security-policy", true},  // finance -> finance-folder -> doc
		{"user:general_user", "document:security-policy", false}, // not in finance
		{"user:executive_user", "document:security-policy", false},
		{"user:general_user", "document:handbook", true},   // employees -> public-folder -> doc
		{"user:finance_user", "document:handbook", true},   // nested: finance ⊂ employees
		{"user:executive_user", "document:handbook", true}, // nested: executives ⊂ employees
		{"user:executive_user", "document:board-minutes", true},
		{"user:finance_user", "document:board-minutes", false},
	}

	for _, tt := range tests {
		t.Run(tt.user+"_"+tt.doc, func(t *testing.T) {
			got := store.Check("tenant_demo", tt.user, "viewer", tt.doc)
			if got != tt.expected {
				t.Errorf("Check(%s viewer %s) = %v, want %v", tt.user, tt.doc, got, tt.expected)
			}
		})
	}
}

// TestMockConnector_SyncAndRevoke proves the full pipeline against the
// mock source: a synced grant resolves, and a source revocation is
// removed from the backend by the next sync.
func TestMockConnector_SyncAndRevoke(t *testing.T) {
	ctx := context.Background()
	mock := aclsync.NewMockConnector()
	store := aclsync.NewMemoryTupleSink()
	syncer := aclsync.NewSyncer(mock, store, nil)

	if _, err := syncer.Sync(ctx, "tenant_demo"); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	if !store.Check("tenant_demo", "user:finance_user", "viewer", "document:security-policy") {
		t.Fatal("finance_user should view security-policy before revocation")
	}

	mock.RevokeGroupMember("finance", "finance_user")
	res, err := syncer.Sync(ctx, "tenant_demo")
	if err != nil {
		t.Fatalf("re-sync after revocation: %v", err)
	}
	if res.TuplesDeleted == 0 {
		t.Fatalf("expected revocation to delete tuples, got %+v", res)
	}
	if store.Check("tenant_demo", "user:finance_user", "viewer", "document:security-policy") {
		t.Fatal("finance_user must lose access after the source revocation is synced")
	}
}
