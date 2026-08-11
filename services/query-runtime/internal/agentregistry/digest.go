package agentregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// ComputeEventDigest computes the tamper-evident digest of one lifecycle
// event. The digest covers every security-relevant field of the event
// plus the digest of the previous event in the agent's chain
// (previousDigest), so reordering, deletion, or field edits are
// detectable. The formula mirrors engine.ComputeDigest (plain SHA-256
// over a \x1f-joined payload) for consistency with the query audit
// ledger. CreatedAt must be truncated to microsecond precision before
// storage so the digest computed at write time matches the digest
// recomputed after a Postgres round-trip.
func ComputeEventDigest(e runtime.LifecycleEvent, previousDigest string) string {
	e.ImmutableDigest = ""
	payload := strings.Join([]string{
		e.ID,
		e.TenantID,
		e.AgentID,
		e.AgentVersionID,
		e.ActorPrincipal,
		e.EventType,
		e.PreviousState,
		e.NewState,
		e.Reason,
		e.CreatedAt.UTC().Format(time.RFC3339Nano),
		previousDigest,
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// EventChainProblem describes a single integrity violation found while
// verifying an agent's lifecycle event chain.
type EventChainProblem struct {
	Index   int
	EventID string
	Kind    string // "digest_mismatch" (covers broken links too — see below)
	Detail  string
}

// VerifyEventChain recomputes the digest of every event and validates
// the previous-digest linkage. Events must be ordered oldest-first (as
// returned by the store). Because the previous event's digest is an
// input to each event's own digest, both row edits and chain tampering
// (deletion, reordering, insertion) surface as a digest_mismatch on the
// first affected event: a deleted middle event changes the
// "previous digest" input of its successor, so the successor's stored
// digest no longer recomputes. A non-empty result means the event
// stream was modified after write.
func VerifyEventChain(events []runtime.LifecycleEvent) []EventChainProblem {
	var problems []EventChainProblem
	prevDigest := ""
	for i, e := range events {
		if recomputed := ComputeEventDigest(e, prevDigest); recomputed != e.ImmutableDigest {
			problems = append(problems, EventChainProblem{
				Index:   i,
				EventID: e.ID,
				Kind:    "digest_mismatch",
				Detail:  "stored immutable_digest does not match recomputed digest (fields edited, or the chain was cut/reordered at this point)",
			})
		}
		prevDigest = e.ImmutableDigest
	}
	return problems
}
