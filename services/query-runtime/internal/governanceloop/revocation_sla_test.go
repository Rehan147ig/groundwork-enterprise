package governanceloop

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"groundwork/query-runtime/internal/aclsync"
	"groundwork/query-runtime/internal/engine"
	"groundwork/query-runtime/internal/runtime"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type revocationRetrieval struct{ candidates []runtime.Candidate }

func (f revocationRetrieval) Retrieve(context.Context, runtime.QueryRequest, int) ([]runtime.Candidate, error) {
	return f.candidates, nil
}

type noopAudit struct{}

func (noopAudit) Write(context.Context, engine.AuditEntry) error { return nil }

// TestRevocationSLA proves the end-to-end guarantee: a source revocation,
// once synced, is enforced at QUERY TIME through the unchanged
// engine.Execute + relationship check.
func TestRevocationSLA(t *testing.T) {
	ctx := context.Background()
	mock := aclsync.NewMockConnector()
	store := aclsync.NewMemoryTupleSink()
	syncer := aclsync.NewSyncer(mock, store, discardLogger())
	if _, err := syncer.Sync(ctx, "tenant_demo"); err != nil {
		t.Fatal(err)
	}

	eng := &engine.Engine{
		Config: engine.TimeoutConfig{
			Total:        2 * time.Second,
			QdrantSearch: time.Second,
			ACLCheck: time.Second,
			AuditWrite:   200 * time.Millisecond,
		},
		Backend: revocationRetrieval{candidates: []runtime.Candidate{{
			Chunk: runtime.Chunk{
				TenantID: "tenant_demo", Region: "uk", DocumentID: "security-policy",
				ChunkID: "chk1", ChunkHash: "h", Text: "finance security policy", FreshnessScore: 1,
			},
			Score: 0.9, Rank: 1,
		}}},
		ACL: engine.ACLCheckFunc(func(ctx context.Context, req runtime.QueryRequest, chunk runtime.Chunk) (bool, error) {
			if chunk.TenantID != req.TenantID || chunk.SoftDeleted {
				return false, nil
			}
			return store.Check(req.TenantID, "user:"+req.UserID, "viewer", "document:"+chunk.DocumentID), nil
		}),
		Auditor: noopAudit{},
	}
	req := runtime.QueryRequest{TenantID: "tenant_demo", Region: "uk", UserID: "finance_user", Question: "policy"}

	// BEFORE revocation: finance_user can retrieve the finance document.
	before := eng.Execute(ctx, req)
	if len(before.Citations) != 1 {
		t.Fatalf("BEFORE: finance_user should access security-policy, got %d citations (trace=%+v)", len(before.Citations), before.Trace)
	}

	// Revoke finance_user from the finance group at the source, then sync.
	mock.RevokeGroupMember("finance", "finance_user")
	res, err := syncer.Sync(ctx, "tenant_demo")
	if err != nil {
		t.Fatal(err)
	}
	if res.TuplesDeleted == 0 {
		t.Fatalf("revocation should delete at least one tuple, got %+v", res)
	}

	// AFTER revocation+sync: query-time enforcement denies finance_user.
	after := eng.Execute(ctx, req)
	if len(after.Citations) != 0 {
		t.Fatalf("AFTER: finance_user must be denied at query time, got %d citations", len(after.Citations))
	}
}
