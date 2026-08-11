package breakglass

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// ComputeGrantDigest produces the canonical digest of a break-glass
// grant's binding fields. Lifecycle fields (status, revoked_at,
// revoked_by, revocation_reason) are intentionally excluded — they are
// covered by the write-once event chain. ExpiresAt and RequestedAt must
// be truncated to microsecond precision before storage so the digest
// computed at write time matches the digest recomputed after a Postgres
// round-trip.
func ComputeGrantDigest(g runtime.BreakGlassGrant) string {
	payload := strings.Join([]string{
		g.TenantID,
		g.OperatorPrincipalID,
		g.Reason,
		fmt.Sprintf("%d", g.DurationMinutes),
		g.ExpiresAt.UTC().Format(time.RFC3339Nano),
		g.RequestedAt.UTC().Format(time.RFC3339Nano),
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ComputeBreakGlassEventDigest covers every immutable field of one
// break-glass event plus the digest of the previous event in the
// tenant's chain (previousDigest), so both field edits and chain
// tampering (deletion, reordering, insertion) are detectable. CreatedAt
// must be truncated to microsecond precision before storage.
func ComputeBreakGlassEventDigest(e runtime.BreakGlassEvent, previousDigest string) string {
	e.ImmutableDigest = ""
	payload := strings.Join([]string{
		e.ID,
		e.TenantID,
		e.GrantID,
		e.EventType,
		e.ActorPrincipalID,
		e.Reason,
		fmt.Sprintf("%d", e.DurationMinutes),
		fmt.Sprintf("%d", e.KeyID),
		e.ExpiresAt.UTC().Format(time.RFC3339Nano),
		e.CreatedAt.UTC().Format(time.RFC3339Nano),
		previousDigest,
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ChainProblem describes a single integrity violation found while
// verifying a break-glass event chain.
type ChainProblem struct {
	Index  int
	ID     string
	Kind   string // "digest_mismatch"
	Detail string
}

// VerifyBreakGlassEventChain recomputes the digest of every event and
// validates the previous-digest linkage. Events must be ordered
// oldest-first (as returned by the store). A non-empty result means the
// stream was modified after write.
func VerifyBreakGlassEventChain(events []runtime.BreakGlassEvent) []ChainProblem {
	var problems []ChainProblem
	prev := ""
	for i, e := range events {
		if recomputed := ComputeBreakGlassEventDigest(e, prev); recomputed != e.ImmutableDigest {
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
