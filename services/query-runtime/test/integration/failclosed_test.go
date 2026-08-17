//go:build integration

package integration

import (
	"context"
	"testing"

	"groundwork/query-runtime/internal/engine"
	"groundwork/query-runtime/internal/runtime"
)

// TestFailClosedWrongRegionAndTenant proves the engine enforces the two
// hard boundaries that shadow mode must never weaken: a candidate whose
// tenant or region differs from the verified request context is dropped
// before any ACL decision.
func TestFailClosedWrongRegionAndTenant(t *testing.T) {
	requireFullStack(t)
	db := openDB(t)

	tenant := "tenant_iso_" + unique()
	collection := "gw_int_iso_" + unique()
	seedQdrantChunk(t, collection, tenant, testDoc, "Isolation boundary chunk.")

	client := newSpiceDBChecker(t)
	checker := runtime.NewACLAdapter(client)
	writeSpiceDBRelationship(t, client, tenant, "user:user_alice", "viewer", "document:"+testDoc)

	eng := newEngine(qdrantSearcher(collection, startStubEmbedder(t)), checker, postgresAuditor(db))
	ctx := context.Background()

	// Wrong region: same tenant, different region -> blocked by residency.
	badRegion := eng.Execute(ctx, runtime.QueryRequest{TenantID: tenant, Region: "us-east-1", UserID: "user_alice", Question: "boundary"})
	if len(badRegion.Citations) != 0 {
		t.Fatalf("wrong region must fail closed; got %d citations", len(badRegion.Citations))
	}
	if badRegion.Trace.BlockedByResidency == 0 {
		t.Fatalf("expected residency block; trace=%+v", badRegion.Trace)
	}

	// Wrong tenant: a different verified tenant must never see this chunk.
	// Isolation is enforced at retrieval (Qdrant filters by
	// metadata.tenant_id), so no candidates are ever produced for the
	// foreign tenant — an even earlier fail-closed boundary than the
	// residency gate.
	badTenant := eng.Execute(ctx, runtime.QueryRequest{TenantID: "other_" + unique(), Region: testRegion, UserID: "user_alice", Question: "boundary"})
	if len(badTenant.Citations) != 0 {
		t.Fatalf("wrong tenant must fail closed; got %d citations", len(badTenant.Citations))
	}
	if badTenant.Trace.VectorCandidates != 0 {
		t.Fatalf("foreign tenant must retrieve zero candidates (retrieval-time isolation); trace=%+v", badTenant.Trace)
	}
}

// TestFailClosedWhenAuditWriteFails proves the evidence boundary is
// fail-closed: when the audit ledger is unreachable, a query returns zero
// citations rather than serving data without an evidence record.
func TestFailClosedWhenAuditWriteFails(t *testing.T) {
	requireFullStack(t)

	tenant := "tenant_auditdown_" + unique()
	collection := "gw_int_auditdown_" + unique()
	seedQdrantChunk(t, collection, tenant, testDoc, "Audit-down fail-closed chunk.")

	client := newSpiceDBChecker(t)
	checker := runtime.NewACLAdapter(client)
	writeSpiceDBRelationship(t, client, tenant, "user:user_alice", "viewer", "document:"+testDoc)

	// errorAuditor always fails, simulating an unreachable audit ledger.
	eng := newEngine(qdrantSearcher(collection, startStubEmbedder(t)), checker, errorAuditor{})

	resp := eng.Execute(context.Background(), runtime.QueryRequest{TenantID: tenant, Region: testRegion, UserID: "user_alice", Question: "finance policy"})
	if len(resp.Citations) != 0 {
		t.Fatalf("audit write failure must fail closed; got %d citations (trace=%+v)", len(resp.Citations), resp.Trace)
	}
	if resp.Trace.FailureStage != "audit" {
		t.Fatalf("expected audit failure stage; trace=%+v", resp.Trace)
	}
}

// errorAuditor always fails, simulating an unreachable audit ledger.
type errorAuditor struct{}

func (errorAuditor) Write(ctx context.Context, entry engine.AuditEntry) error {
	return context.DeadlineExceeded
}
