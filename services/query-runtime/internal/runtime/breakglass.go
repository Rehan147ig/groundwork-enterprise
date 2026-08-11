package runtime

import (
	"context"
	"errors"
	"time"
)

// Break-glass operator access (Phase 8.4): time-bounded, reason-mandatory
// emergency admin access. A verified operator opens a grant which mints a
// short-lived admin-scoped API key; every lifecycle transition appends
// hash-chained, write-once evidence. Expired and revoked grants fail
// closed at the API-key auth layer on the next request.

const (
	BreakGlassStatusActive  = "active"
	BreakGlassStatusExpired = "expired"
	BreakGlassStatusRevoked = "revoked"

	BreakGlassEventOpened  = "opened"
	BreakGlassEventExpired = "expired"
	BreakGlassEventRevoked = "revoked"
)

var (
	// ErrBreakGlassNotFound means the grant id does not exist for the
	// tenant.
	ErrBreakGlassNotFound = errors.New("break glass grant not found")
	// ErrBreakGlassUnavailable means the break-glass service is not
	// wired (no durable store or key manager available).
	ErrBreakGlassUnavailable = errors.New("break glass service unavailable")
	// ErrBreakGlassNotActive means a transition was attempted on a
	// grant that is no longer active (revoked or expired).
	ErrBreakGlassNotActive = errors.New("break glass grant is not active")
)

// BreakGlassGrant is one time-bounded emergency admin grant. It binds an
// operator principal, a mandatory reason, a duration, and the minted
// API key (key_id / key_prefix). ImmutableDigest covers every binding
// field (tenant, operator, reason, duration, expires_at, requested_at)
// so the record itself is tamper-evident; lifecycle transitions live in
// the write-once event chain.
type BreakGlassGrant struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	OperatorPrincipalID string    `json:"operator_principal_id"`
	Reason              string    `json:"reason"`
	DurationMinutes     int       `json:"duration_minutes"`
	KeyID               int64     `json:"key_id"`
	KeyPrefix           string    `json:"key_prefix"`
	Status              string    `json:"status"`
	ExpiresAt           time.Time `json:"expires_at"`
	RequestedAt         time.Time `json:"requested_at"`
	RevokedAt           time.Time `json:"revoked_at,omitempty"`
	RevokedBy           string    `json:"revoked_by,omitempty"`
	RevocationReason    string    `json:"revocation_reason,omitempty"`
	ImmutableDigest     string    `json:"immutable_digest"`
	CreatedAt           time.Time `json:"created_at"`
}

// BreakGlassEvent is immutable hash-chained evidence of one grant
// lifecycle transition (opened / expired / revoked). Events chain per
// tenant (each row digests its predecessor).
type BreakGlassEvent struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	GrantID          string    `json:"grant_id"`
	EventType        string    `json:"event_type"`
	ActorPrincipalID string    `json:"actor_principal_id"`
	Reason           string    `json:"reason"`
	DurationMinutes  int       `json:"duration_minutes"`
	KeyID            int64     `json:"key_id"`
	ExpiresAt        time.Time `json:"expires_at"`
	ImmutableDigest  string    `json:"immutable_digest"`
	PreviousHash     string    `json:"previous_hash"`
	CreatedAt        time.Time `json:"created_at"`
}

// OpenBreakGlassRequest opens a grant. Reason is mandatory; duration is
// capped by the service configuration (BREAK_GLASS_MAX_MINUTES).
type OpenBreakGlassRequest struct {
	Reason          string `json:"reason"`
	DurationMinutes int    `json:"duration_minutes"`
}

// RevokeBreakGlassRequest terminates a grant early. Reason is mandatory:
// every access revocation is evidence with an accountable rationale.
type RevokeBreakGlassRequest struct {
	Reason string `json:"reason"`
}

// BreakGlassService is the authoritative break-glass surface. The
// service layer validates reasons and durations, mints and revokes the
// bound API key, and appends hash-chained evidence — handlers never
// bypass it.
type BreakGlassService interface {
	// Open mints a short-lived admin-scoped API key and opens an active
	// grant for the tenant with hash-chained 'opened' evidence. The
	// minted raw key is returned once, in the Open response only — it
	// is never persisted, so an operator who loses it must open a new
	// grant.
	Open(ctx context.Context, tenant TenantContext, operatorPrincipalID string, req OpenBreakGlassRequest) (BreakGlassGrant, string, error)
	// List returns the tenant's grants, lazily flipping grants that
	// have reached expires_at to 'expired'.
	List(ctx context.Context, tenantID string) ([]BreakGlassGrant, error)
	// Get returns one grant with its event chain, lazily expiring it.
	Get(ctx context.Context, tenantID, grantID string) (BreakGlassGrant, []BreakGlassEvent, error)
	// Revoke terminates an active grant early (revoking its API key)
	// with mandatory reason and hash-chained 'revoked' evidence.
	Revoke(ctx context.Context, tenant TenantContext, grantID, actor string, req RevokeBreakGlassRequest) (BreakGlassGrant, error)
}
