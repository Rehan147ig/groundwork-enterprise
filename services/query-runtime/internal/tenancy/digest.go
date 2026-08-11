package tenancy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// ComputeTenantEventDigest covers every immutable field of one tenant
// lifecycle event plus the digest of the previous event in the tenant's
// chain (previousDigest), so both field edits and chain tampering
// (deletion, reordering, insertion) are detectable. CreatedAt must be
// truncated to microsecond precision before storage.
func ComputeTenantEventDigest(e runtime.TenantEvent, previousDigest string) string {
	e.ImmutableDigest = ""
	payload := strings.Join([]string{
		e.ID,
		e.TenantID,
		e.EventType,
		e.Actor,
		e.Reason,
		e.Region,
		e.CreatedAt.UTC().Format(time.RFC3339Nano),
		previousDigest,
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ChainProblem describes a single integrity violation found while
// verifying a tenant event chain.
type ChainProblem struct {
	Index  int
	ID     string
	Kind   string // "digest_mismatch"
	Detail string
}

// VerifyTenantEventChain recomputes the digest of every event and
// validates the previous-digest linkage. Events must be ordered
// oldest-first (as returned by the store). A non-empty result means the
// stream was modified after write.
func VerifyTenantEventChain(events []runtime.TenantEvent) []ChainProblem {
	var problems []ChainProblem
	prev := ""
	for i, e := range events {
		if recomputed := ComputeTenantEventDigest(e, prev); recomputed != e.ImmutableDigest {
			problems = append(problems, ChainProblem{
				Index:  i,
				ID:     e.ID,
				Kind:   "digest_mismatch",
				Detail: "stored immutable_digest does not match recomputed digest (fields edited, or the chain was cut/reordered at this point)",
			})
		}
		prev = e.ImmutableDigest
	}
	return problems
}
