//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"groundwork/query-runtime/internal/engine"
	"groundwork/query-runtime/internal/relationship/spicedb"
	"groundwork/query-runtime/internal/runtime"
)

// Test 1: a verified-but-unauthorized user receives ZERO documents, while the authorized user
// receives the document — proving live per-user enforcement against real Qdrant + SpiceDB.
func TestFailClosedOnUnauthorizedUser(t *testing.T) {
	requireFullStack(t)
	db := openDB(t)

	tenant := "tenant_authz_" + unique()
	collection := "gw_int_authz_" + unique()
	seedQdrantChunk(t, collection, tenant, testDoc, "Quarterly finance policy. Live ACL checks must fail closed.")

	client := newSpiceDBChecker(t)
	checker := runtime.NewACLAdapter(client)
	// Grant ONLY user_alice viewer access to the document.
	writeSpiceDBRelationship(t, client, tenant, "user:user_alice", "viewer", "document:"+testDoc)

	eng := newEngine(qdrantSearcher(collection, startStubEmbedder(t)), checker, postgresAuditor(db))
	ctx := context.Background()

	// Authorized user sees the document.
	alice := eng.Execute(ctx, runtime.QueryRequest{TenantID: tenant, Region: testRegion, UserID: "user_alice", Question: "finance policy"})
	if len(alice.Citations) == 0 {
		t.Fatalf("authorized user_alice must receive the document; got 0 citations (trace=%+v)", alice.Trace)
	}
	if alice.Citations[0].DocumentID != testDoc {
		t.Fatalf("expected document %q, got %q", testDoc, alice.Citations[0].DocumentID)
	}

	// Unauthorized user is denied — fail closed (zero documents, candidate blocked by ACL).
	bob := eng.Execute(ctx, runtime.QueryRequest{TenantID: tenant, Region: testRegion, UserID: "user_bob", Question: "finance policy"})
	if len(bob.Citations) != 0 {
		t.Fatalf("unauthorized user_bob must receive ZERO documents; got %d (trace=%+v)", len(bob.Citations), bob.Trace)
	}
	if bob.Trace.BlockedByACL == 0 {
		t.Fatalf("expected the retrieved candidate to be blocked by ACL; trace=%+v", bob.Trace)
	}
}

// Test 2: when SpiceDB is unreachable, the engine must fail closed — return zero documents
// rather than fall open. Retrieval still succeeds (Qdrant is up); only the ACL backend is down.
func TestFailClosedWhenSpiceDBDown(t *testing.T) {
	requireFullStack(t)
	db := openDB(t)

	tenant := "tenant_down_" + unique()
	collection := "gw_int_down_" + unique()
	seedQdrantChunk(t, collection, tenant, testDoc, "Finance policy chunk for the SpiceDB-down scenario.")

	// ACL checker pointed at a closed port => every check errors (ACL backend unavailable).
	client, err := spicedb.New(deadGRPCEndpoint(t), "", spicedb.WithInsecurePlaintext(), spicedb.WithTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("spicedb client: %v", err)
	}
	defer client.Close()
	acl := runtime.NewACLAdapter(client)
	eng := newEngine(qdrantSearcher(collection, startStubEmbedder(t)), acl, postgresAuditor(db))

	resp := eng.Execute(context.Background(), runtime.QueryRequest{TenantID: tenant, Region: testRegion, UserID: "user_alice", Question: "finance policy"})
	if len(resp.Citations) != 0 {
		t.Fatalf("SpiceDB unreachable must fail closed (zero documents); got %d (trace=%+v)", len(resp.Citations), resp.Trace)
	}
	if resp.Trace.BlockedByACL == 0 {
		t.Fatalf("expected the candidate to be blocked because ACL was unavailable; trace=%+v", resp.Trace)
	}
}

// Test 3: queries actually write to the immutable Postgres audit ledger, and the persisted
// rows form a valid hash chain (read back via the production LoadAuditChain + VerifyChain).
func TestAuditChainWritesToPostgres(t *testing.T) {
	requireFullStack(t)
	db := openDB(t)

	tenant := "tenant_audit_" + unique() // isolated chain for deterministic assertions
	collection := "gw_int_audit_" + unique()
	seedQdrantChunk(t, collection, tenant, testDoc, "Finance policy chunk for the audit-chain scenario.")

	client := newSpiceDBChecker(t)
	checker := runtime.NewACLAdapter(client)
	writeSpiceDBRelationship(t, client, tenant, "user:user_alice", "viewer", "document:"+testDoc)

	eng := newEngine(qdrantSearcher(collection, startStubEmbedder(t)), checker, postgresAuditor(db))
	ctx := context.Background()

	const n = 3
	for i := 0; i < n; i++ {
		resp := eng.Execute(ctx, runtime.QueryRequest{TenantID: tenant, Region: testRegion, UserID: "user_alice", Question: "finance policy"})
		if len(resp.Citations) == 0 {
			t.Fatalf("query %d should have returned the authorized document; trace=%+v", i, resp.Trace)
		}
	}

	entries, err := engine.LoadAuditChain(ctx, db, tenant)
	if err != nil {
		// A missing column here would mean migration 007 didn't apply — surfacing that is the point.
		t.Fatalf("LoadAuditChain failed (are migrations 003-007 applied?): %v", err)
	}
	if len(entries) != n {
		t.Fatalf("expected exactly %d audit rows for a fresh tenant, got %d", n, len(entries))
	}
	for i, e := range entries {
		if e.ImmutableDigest == "" {
			t.Fatalf("entry %d has empty immutable_digest", i)
		}
		if e.TenantID != tenant {
			t.Fatalf("entry %d wrong tenant: %q", i, e.TenantID)
		}
	}
	// The first row opens the chain; each subsequent row links to the previous row's digest.
	if entries[1].PreviousHash != entries[0].ImmutableDigest {
		t.Fatalf("hash chain not linked: entry[1].previous_hash %q != entry[0].immutable_digest %q",
			entries[1].PreviousHash, entries[0].ImmutableDigest)
	}
	// Full tamper-evidence check: recompute every digest + validate every link.
	if problems := engine.VerifyChain(entries); len(problems) != 0 {
		t.Fatalf("persisted audit chain failed verification: %+v", problems)
	}
}
