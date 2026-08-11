package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// ComputePermittedActionsDigest produces the canonical digest of a
// permitted-actions list (each entry "tool:action"), sorted so the same
// set always hashes identically. Both the grant row and the token carry
// this digest; a mismatch fails the delegation closed.
func ComputePermittedActionsDigest(actions []string) string {
	sorted := make([]string, 0, len(actions))
	for _, action := range actions {
		if trimmed := strings.TrimSpace(action); trimmed != "" {
			sorted = append(sorted, trimmed)
		}
	}
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\x1f")))
	return hex.EncodeToString(sum[:])
}

// ComputeGrantDigest covers every immutable binding field of a
// delegation grant. Lifecycle fields (used_at, run_id, revoked_at) are
// intentionally excluded — they change with the run lifecycle and are
// validated by the store's atomic transitions. CreatedAt must be
// truncated to microsecond precision before storage so the digest
// computed at write time matches the digest recomputed after a Postgres
// round-trip.
func ComputeGrantDigest(g runtime.DelegationGrant) string {
	payload := strings.Join([]string{
		g.ID,
		g.TenantID,
		g.AgentID,
		g.AgentVersionID,
		g.TokenJTI,
		g.DelegatorPrincipalID,
		g.SubjectPrincipalID,
		g.Purpose,
		g.Region,
		g.PermittedActionsDigest,
		g.IssuedAt.UTC().Format(time.RFC3339Nano),
		g.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ComputeDecisionDigest computes the tamper-evident digest of one
// evaluator outcome. The digest covers every security-relevant field
// plus the digest of the previous decision in the run's chain
// (previousDigest), so reordering, deletion, or field edits are
// detectable. Mirrors engine.ComputeDigest and agentregistry
// ComputeEventDigest (SHA-256 over a \x1f-joined payload).
func ComputeDecisionDigest(d runtime.ActionDecision, previousDigest string) string {
	d.ImmutableDigest = ""
	payload := strings.Join([]string{
		d.ID,
		d.TenantID,
		d.AgentID,
		d.RunID,
		d.DelegationGrantID,
		d.ToolID,
		d.ActionID,
		d.ResourceRef,
		d.Decision,
		d.Reason,
		d.ReasonCode,
		d.PolicyVersion,
		d.CreatedAt.UTC().Format(time.RFC3339Nano),
		previousDigest,
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ComputeApprovalDigest covers every field of an approval record.
// consumed_at is a lifecycle field (one-time transition) and is not
// covered; it can only ever move NULL -> set via the atomic consume.
func ComputeApprovalDigest(a runtime.ActionApproval) string {
	payload := strings.Join([]string{
		a.ID,
		a.TenantID,
		a.RunID,
		a.ToolID,
		a.ActionID,
		a.ResourceRef,
		a.ApprovingPrincipalID,
		a.Decision,
		a.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ChainProblem describes a single integrity violation found while
// verifying an evidence chain (decisions or approvals).
type ChainProblem struct {
	Index  int
	ID     string
	Kind   string // "digest_mismatch"
	Detail string
}

// VerifyDecisionChain recomputes the digest of every decision and
// validates the previous-digest linkage. Decisions must be ordered
// oldest-first (as returned by the store). Because the previous
// decision's digest is an input to each decision's own digest, both row
// edits and chain tampering (deletion, reordering, insertion) surface as
// a digest_mismatch on the first affected decision. A non-empty result
// means the stream was modified after write.
func VerifyDecisionChain(decisions []runtime.ActionDecision) []ChainProblem {
	var problems []ChainProblem
	prev := ""
	for i, d := range decisions {
		if recomputed := ComputeDecisionDigest(d, prev); recomputed != d.ImmutableDigest {
			problems = append(problems, ChainProblem{
				Index:  i,
				ID:     d.ID,
				Kind:   "digest_mismatch",
				Detail: "stored immutable_digest does not match recomputed digest (fields edited, or the chain was cut/reordered at this point)",
			})
		}
		prev = d.ImmutableDigest
	}
	return problems
}

// VerifyApprovalChain validates the digest of every approval record,
// ordered oldest-first by created_at. Approvals are not hash-chained to
// each other (each binds a distinct one-time decision); their digest
// covers all immutable evidence fields.
func VerifyApprovalChain(approvals []runtime.ActionApproval) []ChainProblem {
	var problems []ChainProblem
	for i, a := range approvals {
		if recomputed := ComputeApprovalDigest(a); recomputed != a.ImmutableDigest {
			problems = append(problems, ChainProblem{
				Index:  i,
				ID:     a.ID,
				Kind:   "digest_mismatch",
				Detail: "stored immutable_digest does not match recomputed digest (fields edited)",
			})
		}
	}
	return problems
}

// ComputeEmergencyActionDigest covers every immutable field of one
// emergency control action plus the digest of the previous action in the
// tenant's chain (previousDigest), so both field edits and chain
// tampering are detectable. CreatedAt must be truncated to microsecond
// precision before storage (matches the grant/decision convention).
func ComputeEmergencyActionDigest(a runtime.EmergencyControlAction, previousDigest string) string {
	a.ImmutableDigest = ""
	payload := strings.Join([]string{
		a.ID,
		a.TenantID,
		a.EntityType,
		a.EntityID,
		a.ActionType,
		a.ActorPrincipalID,
		a.Reason,
		a.Scope,
		a.PreviousState,
		a.NewState,
		a.CreatedAt.UTC().Format(time.RFC3339Nano),
		previousDigest,
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// VerifyEmergencyActionChain recomputes digests for a tenant's control
// actions (oldest-first) and validates the previous-digest linkage.
func VerifyEmergencyActionChain(actions []runtime.EmergencyControlAction) []ChainProblem {
	var problems []ChainProblem
	prev := ""
	for i, a := range actions {
		if recomputed := ComputeEmergencyActionDigest(a, prev); recomputed != a.ImmutableDigest {
			problems = append(problems, ChainProblem{
				Index:  i,
				ID:     a.ID,
				Kind:   "digest_mismatch",
				Detail: "stored immutable_digest does not match recomputed digest (fields edited, or the chain was cut/reordered at this point)",
			})
		}
		prev = a.ImmutableDigest
	}
	return problems
}

// ---------------------------------------------------------------------
// Phase 6: delegation-chain digests.
//
// The authority scope of a grant is (permitted actions digest, region,
// purpose). A child scope is a strict subset or equal subset of the
// parent scope: same tenant, actions ⊆ parent actions, region equal or
// transfer-policy-approved, expiry <= parent expiry, depth bounded. The
// attenuation digest binds the child's scope to its parent's scope so a
// chain cannot silently grow authority at a later hop.
// ---------------------------------------------------------------------

// ComputeAuthorityScopeDigest is the canonical digest of one grant's
// authority scope. It is stored on the grant (authority_scope_digest)
// and carried in the token, so scope attenuation is verifiable without
// persisting the action list twice.
func ComputeAuthorityScopeDigest(permittedActionsDigest, region, purpose string) string {
	payload := strings.Join([]string{
		permittedActionsDigest,
		region,
		purpose,
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ComputeAttenuationDigest binds a child scope to its parent scope and
// expiry. Equal scopes produce the same digest family; any widening
// (actions, region, purpose) or expiry extension changes it, and the
// evaluator recomputes it for every ancestor link.
func ComputeAttenuationDigest(parentScopeDigest, childScopeDigest, parentExpiry, childExpiry string) string {
	payload := strings.Join([]string{
		parentScopeDigest,
		childScopeDigest,
		parentExpiry,
		childExpiry,
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// VerifyGrantChainLink verifies one parent->child link: the child's
// parent_scope_digest must equal the parent's authority_scope_digest,
// and the stored attenuation_digest must match a recomputation over
// the two scopes. A mismatch means the chain was edited or the scope
// was widened after mint.
func VerifyGrantChainLink(parent, child runtime.DelegationGrant) error {
	if parent.ParentGrantID != "" && parent.RootGrantID != "" && child.RootGrantID != "" && parent.RootGrantID != child.RootGrantID {
		return runtime.ErrChainBroken
	}
	if child.ParentGrantID != parent.ID {
		return fmt.Errorf("%w: child.parent_grant_id does not reference parent", runtime.ErrChainBroken)
	}
	if child.ParentScopeDigest != parent.AuthorityScopeDigest {
		return fmt.Errorf("%w: parent scope digest mismatch", runtime.ErrChainBroken)
	}
	recomputed := ComputeAttenuationDigest(
		parent.AuthorityScopeDigest,
		child.AuthorityScopeDigest,
		parent.ExpiresAt.UTC().Format(time.RFC3339Nano),
		child.ExpiresAt.UTC().Format(time.RFC3339Nano),
	)
	if recomputed != child.AttenuationDigest {
		return fmt.Errorf("%w: attenuation digest mismatch", runtime.ErrChainBroken)
	}
	return nil
}

// ComputeTrustRelationshipDigest covers every immutable binding field
// of a trust relationship. Lifecycle fields (status, reason, updated_at)
// are excluded — they are covered by the trust event chain.
func ComputeTrustRelationshipDigest(r runtime.AgentTrustRelationship) string {
	payload := strings.Join([]string{
		r.ID,
		r.TenantID,
		r.ParentAgentID,
		r.ChildAgentID,
		r.ExternalAgentID,
		r.TrustDomain,
		r.OwnerPrincipalID,
		r.Purpose,
		itos(r.MaxDelegationDepth),
		strings.Join(r.AllowedToolsActions, ","),
		r.Region,
		r.ExpiresAt.UTC().Format(time.RFC3339Nano),
		btoa(r.ApprovalRequired),
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ComputeExternalAgentDigest covers the identity bindings of an
// external agent (issuer, audiences, auth method, tier, region, scope).
func ComputeExternalAgentDigest(a runtime.ExternalAgent) string {
	payload := strings.Join([]string{
		a.ExternalAgentID,
		a.OrganizationID,
		a.VerifiedIssuer,
		strings.Join(a.AllowedAudiences, ","),
		a.AuthMethod,
		a.TrustTier,
		a.Region,
		strings.Join(a.AllowedToolsActions, ","),
		a.ManifestDigest,
		a.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ComputeConsentDigest covers every immutable field of a consent record.
func ComputeConsentDigest(c runtime.ConsentRecord) string {
	payload := strings.Join([]string{
		c.ID,
		c.TenantID,
		c.OrganizationID,
		c.ExternalAgentID,
		c.CustomerPrincipalID,
		c.Purpose,
		c.ResourceRefPattern,
		c.GrantedAt.UTC().Format(time.RFC3339Nano),
		c.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ComputeTrustEventDigest covers every immutable field of one trust
// event plus the digest of the previous event in the tenant's chain
// (previousDigest), so both field edits and chain tampering are
// detectable. OccurredAt must be truncated to microsecond precision.
func ComputeTrustEventDigest(e runtime.TrustEvent, previousDigest string) string {
	payload := strings.Join([]string{
		e.ID,
		e.TenantID,
		e.EventType,
		e.EntityType,
		e.EntityID,
		e.ActorPrincipalID,
		e.PreviousState,
		e.NewState,
		e.Reason,
		e.GrantID,
		e.ParentGrantID,
		e.RootGrantID,
		itos(e.DelegationDepth),
		e.SubjectPrincipalID,
		e.TrustDomain,
		e.OrganizationID,
		e.ScopeDigest,
		e.AttenuationDigest,
		e.RevocationSource,
		e.OccurredAt.UTC().Format(time.RFC3339Nano),
		previousDigest,
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// VerifyTrustEventChain recomputes digests for a tenant's trust events
// (oldest-first) and validates the previous-digest linkage.
func VerifyTrustEventChain(events []runtime.TrustEvent) []ChainProblem {
	var problems []ChainProblem
	prev := ""
	for i, e := range events {
		if recomputed := ComputeTrustEventDigest(e, prev); recomputed != e.ImmutableDigest {
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

func itos(v int) string { return strconv.Itoa(v) }

func btoa(v bool) string {
	if v {
		return "1"
	}
	return "0"
}
