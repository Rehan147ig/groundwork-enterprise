//go:build integration

package integration

// SQL-level integration tests for the immutable audit ledger. These run
// against Postgres alone (no SpiceDB/Qdrant) and are the suite CI
// executes with its Postgres 16 service container.

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"groundwork/query-runtime/internal/engine"
)

// auditEntry builds a deterministic insert for a query audit row. Only
// the fields the digest covers are set; stored columns outside the
// digest (agent attribution, decision blob) are left as defaults.
func auditEntry(tenantID, traceID string) engine.AuditEntry {
	return engine.AuditEntry{
		TraceID:             traceID,
		TenantID:            tenantID,
		UserID:              "user_alice",
		QueryHash:           sha256hex("SELECT ..."),
		TimestampUTC:        time.Now().UTC().Truncate(time.Microsecond),
		Region:              testRegion,
		CandidatesRetrieved: 1,
		CandidatesAllowed:   1,
		CandidatesBlocked:   0,
		FailClosed:          false,
		TotalLatencyMs:      3,
		CircuitBreakerState: "closed",
		DecisionMode:        "enforce",
	}
}

// forgeAuditRow inserts a row directly (bypassing the writer, like a
// tampering attacker who can write to the table). Every column the
// digest formula covers (see engine.ComputeDigestWithSalt) is written
// from the entry so the stored digest is self-consistent unless the
// caller deliberately skews a field.
func forgeAuditRow(t *testing.T, db *sql.DB, entry engine.AuditEntry) {
	t.Helper()
	ctx := context.Background()
	_, err := db.ExecContext(ctx, `
		INSERT INTO audit_log (
			trace_id, tenant_id, user_id, query_hash, timestamp_utc,
			region, candidates_retrieved, candidates_allowed, candidates_blocked,
			fail_closed, fail_stage, error_code, error_message,
			openfga_latency_ms, qdrant_latency_ms, total_latency_ms,
			circuit_breaker_state, decision_mode, acl_decision, reason,
			identity_resolution, principal_id,
			immutable_digest, previous_hash
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
	`,
		entry.TraceID, entry.TenantID, entry.UserID, entry.QueryHash, entry.TimestampUTC,
		entry.Region, entry.CandidatesRetrieved, entry.CandidatesAllowed, entry.CandidatesBlocked,
		entry.FailClosed, sqlNullString(entry.FailStage), sqlNullString(entry.ErrorCode), sqlNullString(entry.ErrorMessage),
		sqlNullInt64(entry.OpenFGALatencyMs), sqlNullInt64(entry.QdrantLatencyMs), entry.TotalLatencyMs,
		entry.CircuitBreakerState, entry.DecisionMode, entry.ACLDecision, entry.Reason,
		entry.IdentityResolution, entry.PrincipalID,
		entry.ImmutableDigest, sqlNullString(entry.PreviousHash),
	)
	if err != nil {
		t.Fatalf("forge audit row %s: %v", entry.TraceID, err)
	}
}

func sqlNullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func sqlNullInt64(v int) sql.NullInt64 { return sql.NullInt64{Int64: int64(v), Valid: v != 0} }

// auditSeqOrder returns the seq values in the tenant's chain in
// LoadAuditChain's read-back order, proving the ledger surfaces rows in
// monotonic insertion order even with timestamp ties.
func auditSeqOrder(t *testing.T, db *sql.DB, tenant string) []int64 {
	t.Helper()
	rows, err := db.QueryContext(context.Background(),
		`SELECT seq FROM audit_log WHERE tenant_id = $1 ORDER BY seq`, tenant)
	if err != nil {
		t.Fatalf("audit_seq_order: %v", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan seq: %v", err)
		}
		out = append(out, s)
	}
	return out
}

// TestAuditWriteOnceSQL proves the SQL-level write-once contract
// (migration 003: no_update_audit / no_delete_audit RULEs): after the
// writer appends an entry, an UPDATE or DELETE of the row silently
// affects zero rows — and the chain still verifies afterwards.
func TestAuditWriteOnceSQL(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)
	ctx := context.Background()

	tenant := "tenant_wronce_" + unique()
	writer := postgresAuditor(db)
	for i := 0; i < 2; i++ {
		if err := writer.Write(ctx, auditEntry(tenant, fmt.Sprintf("won-%s-%d", tenant, i))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// UPDATE: the RULE swallows it — zero rows affected, no error.
	res, err := db.ExecContext(ctx,
		`UPDATE audit_log SET user_id = 'user_mallory' WHERE tenant_id = $1`, tenant)
	if err != nil {
		t.Fatalf("UPDATE audit_log: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 0 {
		t.Fatalf("UPDATE must be a no-op under no_update_audit; %d rows affected", n)
	}

	// DELETE: same no-op under no_delete_audit.
	res, err = db.ExecContext(ctx, `DELETE FROM audit_log WHERE tenant_id = $1`, tenant)
	if err != nil {
		t.Fatalf("DELETE audit_log: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 0 {
		t.Fatalf("DELETE must be a no-op under no_delete_audit; %d rows affected", n)
	}

	// Neither the UPDATE nor the DELETE changed stored content: the
	// digest of every row still recomputes cleanly.
	entries, err := engine.LoadAuditChain(ctx, db, tenant)
	if err != nil {
		t.Fatalf("LoadAuditChain: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 audit rows, got %d", len(entries))
	}
	for i, e := range entries {
		if e.UserID != "user_alice" {
			t.Fatalf("entry %d user tampered to %q despite no_update_audit", i, e.UserID)
		}
	}
	if problems := engine.VerifyChain(entries); len(problems) != 0 {
		t.Fatalf("chain failed verification after attempted tamper: %+v", problems)
	}
}

// TestAuditChainVerificationSQL proves hash-chain verification over
// Postgres storage: rows written by the production writer form a valid
// linked chain, and a forged row smuggled in at the SQL level is caught
// by VerifyChain — broken_link when its previous_hash lies, and
// digest_mismatch when its stored digest does not recompute.
func TestAuditChainVerificationSQL(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)
	ctx := context.Background()

	tenant := "tenant_verifysql_" + unique()
	writer := postgresAuditor(db)
	for i := 0; i < 3; i++ {
		if err := writer.Write(ctx, auditEntry(tenant, fmt.Sprintf("vfy-%s-%d", tenant, i))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	entries, err := engine.LoadAuditChain(ctx, db, tenant)
	if err != nil {
		t.Fatalf("LoadAuditChain: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(entries))
	}
	if entries[0].PreviousHash != "" {
		t.Fatalf("first entry must open the chain, previous_hash=%q", entries[0].PreviousHash)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].PreviousHash != entries[i-1].ImmutableDigest {
			t.Fatalf("broken link row %d: %q != %q", i, entries[i].PreviousHash, entries[i-1].ImmutableDigest)
		}
	}
	if problems := engine.VerifyChain(entries); len(problems) != 0 {
		t.Fatalf("expected clean chain, got %+v", problems)
	}

	// Forgery A: correct digest, lying previous_hash -> broken_link.
	forge := auditEntry(tenant, "forge-a-"+unique())
	forge.PreviousHash = "deadbeef"
	forge.ImmutableDigest = engine.ComputeDigestWithSalt(forge, "")
	forgeAuditRow(t, db, forge)

	// Forgery B: correct previous_hash (linked from forge-a, which is
	// now the tail of the chain), impossible digest -> digest_mismatch.
	forgeB := auditEntry(tenant, "forge-b-"+unique())
	forgeB.PreviousHash = forge.ImmutableDigest
	forgeB.ImmutableDigest = sha256hex("tampered payload")
	forgeAuditRow(t, db, forgeB)

	entries, err = engine.LoadAuditChain(ctx, db, tenant)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 rows after forgeries, got %d", len(entries))
	}
	problems := engine.VerifyChain(entries)
	if len(problems) != 2 {
		t.Fatalf("expected 2 verification problems, got %d: %+v", len(problems), problems)
	}
	kinds := map[string]bool{}
	for _, p := range problems {
		kinds[p.TraceID] = true
		switch p.TraceID {
		case forge.TraceID:
			if p.Kind != "broken_link" {
				t.Fatalf("forge-a expected broken_link, got %q (%s)", p.Kind, p.Detail)
			}
		case forgeB.TraceID:
			if p.Kind != "digest_mismatch" {
				t.Fatalf("forge-b expected digest_mismatch, got %q (%s)", p.Kind, p.Detail)
			}
		default:
			t.Fatalf("unexpected problem on genuine entry %s: %+v", p.TraceID, p)
		}
	}

	// The forgeries are still on disk (write-once: they cannot be wiped).
	res, err := db.ExecContext(ctx, `DELETE FROM audit_log WHERE tenant_id = $1`, tenant)
	if err != nil {
		t.Fatalf("cleanup delete: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 0 {
		t.Fatalf("DELETE must be a no-op; %d rows affected", n)
	}
}

// TestAuditCrossTenantIsolationConcurrentWrites proves per-tenant chain
// isolation under concurrent writes: N tenants are written to in
// parallel (multiple writers each), and afterwards every tenant's chain
// contains exactly its own rows, opens its own genesis, and verifies
// cleanly — no cross-tenant leakage and no forked links.
func TestAuditCrossTenantIsolationConcurrentWrites(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)
	ctx := context.Background()

	const (
		numTenants        = 4
		numWriters        = 3 // concurrent writers per tenant
		numEntries        = 5 // entries per writer goroutine
		expectedPerTenant = numWriters * numEntries
	)

	tenants := make([]string, numTenants)
	for i := range tenants {
		tenants[i] = fmt.Sprintf("tenant_xiso_%d_%s", i, unique())
	}

	var wg sync.WaitGroup
	for _, tenant := range tenants {
		for w := 0; w < numWriters; w++ {
			wg.Add(1)
			go func(tenant string, w int) {
				defer wg.Done()
				writer := postgresAuditor(db)
				for k := 0; k < numEntries; k++ {
					entry := auditEntry(tenant, fmt.Sprintf("iso-%s-%d-%d", tenant, w, k))
					if err := writer.Write(ctx, entry); err != nil {
						t.Errorf("tenant %s writer %d entry %d: %v", tenant, w, k, err)
						return
					}
				}
			}(tenant, w)
		}
	}
	wg.Wait()

	for _, tenant := range tenants {
		entries, err := engine.LoadAuditChain(ctx, db, tenant)
		if err != nil {
			t.Fatalf("tenant %s LoadAuditChain: %v", tenant, err)
		}
		if len(entries) != expectedPerTenant {
			t.Fatalf("tenant %s: expected %d rows, got %d", tenant, expectedPerTenant, len(entries))
		}
		// Rows must not have been read back out of insertion order even
		// under microsecond timestamp ties (migration 030: seq ordering;
		// the old ORDER BY (timestamp_utc, id) inverted same-µs writes
		// and broke the chain).
		seqs := auditSeqOrder(t, db, tenant)
		for i := 1; i < len(seqs); i++ {
			if seqs[i] < seqs[i-1] {
				t.Fatalf("tenant %s: chain read back out of insert order at %d (seq %d after %d)",
					tenant, i, seqs[i], seqs[i-1])
			}
		}
		if entries[0].PreviousHash != "" {
			t.Fatalf("tenant %s: chain must open fresh, previous_hash=%q", tenant, entries[0].PreviousHash)
		}
		for _, e := range entries {
			if e.TenantID != tenant {
				t.Fatalf("tenant %s: row for foreign tenant %q leaked into chain", tenant, e.TenantID)
			}
		}
		if problems := engine.VerifyChain(entries); len(problems) != 0 {
			t.Fatalf("tenant %s chain failed verification (cross-tenant link or fork): %+v", tenant, problems)
		}
	}
}
