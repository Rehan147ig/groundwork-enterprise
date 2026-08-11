package runtime

import (
	"context"
	"errors"
	"time"
)

// Tenant provisioning (Phase 8.1 Multi-tenancy and isolation): the
// operator-managed tenant directory with lifecycle evidence. Tenants are
// provisioned (or re-provisioned) through the admin API, and the auth
// layer consults the directory so a disabled or deprovisioned tenant
// fails closed on its next request. There is no destructive delete —
// deprovisioning is the terminal state, per the roadmap ("do not add
// destructive delete by default").

const (
	TenantStatusActive        = "active"
	TenantStatusDisabled      = "disabled"
	TenantStatusDeprovisioned = "deprovisioned"

	TenantEventProvisioned   = "provisioned"
	TenantEventDisabled      = "disabled"
	TenantEventEnabled       = "enabled"
	TenantEventDeprovisioned = "deprovisioned"

	// Capacity tiers (Phase 8.2 capacity model): the deployment tier
	// the auth layer maps to per-tenant capacity limits (in-flight
	// concurrency cap derived from the operator's capacity model).
	CapacityTierStandard   = "standard"
	CapacityTierPlus       = "plus"
	CapacityTierEnterprise = "enterprise"
)

// IsCapacityTier reports whether tier is one of the closed capacity
// tier set.
func IsCapacityTier(tier string) bool {
	switch tier {
	case CapacityTierStandard, CapacityTierPlus, CapacityTierEnterprise:
		return true
	}
	return false
}

var (
	// ErrTenantNotFound means the tenant is not in the directory.
	ErrTenantNotFound = errors.New("tenant not found")
	// ErrTenantUnavailable means the tenant service is not wired (no
	// durable store available).
	ErrTenantUnavailable = errors.New("tenant service unavailable")
	// ErrTenantNotActive means the tenant exists but is disabled or
	// deprovisioned; the auth layer fails closed with this error.
	ErrTenantNotActive = errors.New("tenant is not active")
	// ErrTenantRegionConflict means an active tenant already exists with
	// a different region; region changes require deprovisioning first.
	ErrTenantRegionConflict = errors.New("tenant region conflict")
)

// Tenant is one directory entry: identity, trusted region, lifecycle
// status, deployment tier (capacity model), and the audit trail binding
// (who created it and why).
type Tenant struct {
	TenantID string `json:"tenant_id"`
	Region   string `json:"region"`
	Status   string `json:"status"`
	// Tier is the capacity model tier (standard|plus|enterprise).
	// Empty means standard (the restrictive default).
	Tier            string    `json:"capacity_tier,omitempty"`
	CreatedBy       string    `json:"created_by"`
	Reason          string    `json:"reason"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	DeprovisionedAt time.Time `json:"deprovisioned_at,omitempty"`
}

// TenantEvent is immutable hash-chained evidence of one tenant lifecycle
// transition. Events chain per tenant (each row digests its
// predecessor).
type TenantEvent struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	EventType       string    `json:"event_type"`
	Actor           string    `json:"actor"`
	Reason          string    `json:"reason"`
	Region          string    `json:"region"`
	ImmutableDigest string    `json:"immutable_digest"`
	PreviousHash    string    `json:"previous_hash"`
	CreatedAt       time.Time `json:"created_at"`
}

// ProvisionTenantRequest provisions a tenant. MintAdminKey optionally
// mints an initial admin+query scoped API key for the tenant; the raw
// key is returned once in the response (never persisted). Reason is
// mandatory for every provisioning action. Tier optionally sets the
// capacity model tier (standard|plus|enterprise); empty defaults to
// standard.
type ProvisionTenantRequest struct {
	TenantID     string `json:"tenant_id"`
	Region       string `json:"region"`
	Tier         string `json:"capacity_tier,omitempty"`
	Reason       string `json:"reason"`
	MintAdminKey bool   `json:"mint_admin_key"`
}

// ProvisionTenantResponse returns the tenant directory entry and, when
// requested, the one-time minted admin key.
type ProvisionTenantResponse struct {
	Tenant Tenant `json:"tenant"`
	// Key is the one-time raw admin key for the tenant; "" when
	// MintAdminKey was false. It is never persisted.
	Key string `json:"key,omitempty"`
}

// TenantTransitionRequest carries the mandatory reason for disable /
// enable / deprovision transitions.
type TenantTransitionRequest struct {
	Reason string `json:"reason"`
}

// TenantService is the authoritative tenant-provisioning surface. The
// service layer validates tenant ids and regions, enforces lifecycle
// transitions (no destructive delete), mints the optional admin key, and
// appends hash-chained evidence — handlers never bypass it.
type TenantService interface {
	// Provision creates or re-provisions a tenant. Provisioning an
	// existing active tenant with the same region is idempotent;
	// provisioning an active tenant with a different region fails with
	// ErrTenantRegionConflict; provisioning a deprovisioned tenant
	// reactivates it (region may change).
	Provision(ctx context.Context, actor string, req ProvisionTenantRequest) (ProvisionTenantResponse, error)
	// List returns the full tenant directory.
	List(ctx context.Context) ([]Tenant, error)
	// Get returns one tenant entry.
	Get(ctx context.Context, tenantID string) (Tenant, error)
	// ListEvents returns the tenant's hash-chained lifecycle evidence.
	ListEvents(ctx context.Context, tenantID string) ([]TenantEvent, error)
	// Disable suspends an active tenant (reason mandatory). A disabled
	// tenant fails closed at the auth layer on the next request.
	Disable(ctx context.Context, tenantID, actor, reason string) (Tenant, error)
	// Enable reactivates a disabled tenant (reason mandatory).
	Enable(ctx context.Context, tenantID, actor, reason string) (Tenant, error)
	// Deprovision is the terminal, non-destructive lifecycle state
	// (reason mandatory). A deprovisioned tenant fails closed at the
	// auth layer and can only be re-provisioned through Provision.
	Deprovision(ctx context.Context, tenantID, actor, reason string) (Tenant, error)
}

// TenantDirectory is the read surface the auth layer consults after key
// resolution: it maps a tenant to its directory region, lifecycle
// status, and capacity tier. ok=false means the tenant is not in the
// directory (it remains governed only by the trusted region resolver,
// and the auth layer falls back to the default capacity tier). A tenant
// in the directory with status != active fails closed
// (ErrTenantNotActive).
type TenantDirectory interface {
	Lookup(ctx context.Context, tenantID string) (region, status, tier string, ok bool)
}
