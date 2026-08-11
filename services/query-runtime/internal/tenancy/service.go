package tenancy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"groundwork/query-runtime/internal/deployment"
	"groundwork/query-runtime/internal/runtime"
)

// KeyMinter is the subset of runtime.APIKeyManager the tenant service
// needs: mint an initial admin key for a newly provisioned tenant. The
// server's API key resolver implements it; the raw key is returned once
// in the provisioning response and never persisted.
type KeyMinter interface {
	Create(ctx context.Context, tenant runtime.TenantContext, req runtime.CreateAPIKeyRequest) (runtime.CreateAPIKeyResponse, error)
	Revoke(ctx context.Context, tenant runtime.TenantContext, id int64) (bool, error)
}

var tenantIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// Service is the authoritative tenant-provisioning surface: validates
// tenant ids and regions, enforces the lifecycle (active -> disabled ->
// deprovisioned, with no destructive delete), mints the optional initial
// admin key, and appends hash-chained evidence atomically with every
// transition.
type Service struct {
	store Store
	keys  KeyMinter
	now   func() time.Time
}

// NewService builds the tenant-provisioning service. keys may be nil
// (provisioning works; MintAdminKey requests fail with
// runtime.ErrTenantUnavailable).
func NewService(store Store, keys KeyMinter) *Service {
	return &Service{store: store, keys: keys, now: time.Now}
}

// Provision creates or re-provisions a tenant. Provisioning an existing
// active tenant with the same region is idempotent; a region change on
// an active tenant fails with runtime.ErrTenantRegionConflict;
// provisioning a deprovisioned tenant reactivates it (region may
// change). When MintAdminKey is set, an initial admin+query scoped API
// key is minted for the tenant first; if the directory write fails the
// key is revoked best-effort so no orphaned key survives.
func (s *Service) Provision(ctx context.Context, actor string, req runtime.ProvisionTenantRequest) (runtime.ProvisionTenantResponse, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if !tenantIDPattern.MatchString(tenantID) {
		return runtime.ProvisionTenantResponse{}, fmt.Errorf("%w: tenant_id must be 1-64 chars of [A-Za-z0-9._-]", runtime.ErrInvalidRequest)
	}
	region, err := deployment.ParseRegion(req.Region)
	if err != nil {
		return runtime.ProvisionTenantResponse{}, fmt.Errorf("%w: %v", runtime.ErrInvalidRequest, err)
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return runtime.ProvisionTenantResponse{}, fmt.Errorf("%w: reason required for provisioning", runtime.ErrInvalidRequest)
	}
	if actor == "" {
		return runtime.ProvisionTenantResponse{}, runtime.ErrInvalidRequest
	}
	// Phase 8.2 capacity model: the deployment tier is a closed set;
	// empty defaults to standard (the restrictive default, so an
	// operator omitting the field never silently expands capacity).
	tier := strings.TrimSpace(req.Tier)
	if tier == "" {
		tier = runtime.CapacityTierStandard
	}
	if !runtime.IsCapacityTier(tier) {
		return runtime.ProvisionTenantResponse{}, fmt.Errorf("%w: capacity_tier must be one of standard, plus, enterprise", runtime.ErrInvalidRequest)
	}

	var minted *runtime.CreateAPIKeyResponse
	if req.MintAdminKey {
		if s.keys == nil {
			return runtime.ProvisionTenantResponse{}, runtime.ErrTenantUnavailable
		}
		key, err := s.keys.Create(ctx, runtime.TenantContext{TenantID: tenantID, Region: region.String()}, runtime.CreateAPIKeyRequest{
			Name:   "bootstrap-admin",
			Scopes: []string{"admin", "query"},
		})
		if err != nil {
			return runtime.ProvisionTenantResponse{}, err
		}
		minted = &key
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	var tenant runtime.Tenant
	err = s.store.Transact(ctx, "tenancy:"+tenantID, func(tx TxStore) error {
		current, err := tx.GetTenant(ctx, tenantID)
		switch {
		case err == nil && current.Status == runtime.TenantStatusActive && current.Region == region.String():
			tenant = current
			return nil // idempotent: provision of an already-active tenant
		case err == nil && current.Status == runtime.TenantStatusActive:
			return runtime.ErrTenantRegionConflict
		case err == nil && current.Status == runtime.TenantStatusDisabled:
			return runtime.ErrTenantNotActive
		case err != nil && !errors.Is(err, runtime.ErrTenantNotFound):
			return err
		}
		// Preserve the original provisioning date on re-provision.
		createdAt := now
		if err == nil {
			createdAt = current.CreatedAt
		}
		upserted, err := tx.UpsertTenant(ctx, runtime.Tenant{
			TenantID:  tenantID,
			Region:    region.String(),
			Status:    runtime.TenantStatusActive,
			Tier:      tier,
			CreatedBy: actor,
			Reason:    reason,
			CreatedAt: createdAt,
			UpdatedAt: now,
		})
		if err != nil {
			return err
		}
		tenant = upserted
		_, err = tx.AppendEvent(ctx, runtime.TenantEvent{
			TenantID:  tenantID,
			EventType: runtime.TenantEventProvisioned,
			Actor:     actor,
			Reason:    reason,
			Region:    region.String(),
			CreatedAt: now,
		})
		return err
	})
	if err != nil {
		// The key is minted but the directory write never landed:
		// revoke it so the failed provision leaves no key behind.
		if minted != nil {
			_, _ = s.keys.Revoke(ctx, runtime.TenantContext{TenantID: tenantID, Region: region.String()}, minted.ID)
		}
		return runtime.ProvisionTenantResponse{}, err
	}
	key := ""
	if minted != nil {
		key = minted.Key
	}
	return runtime.ProvisionTenantResponse{Tenant: tenant, Key: key}, nil
}

// List returns the full tenant directory (sorted by tenant id).
func (s *Service) List(ctx context.Context) ([]runtime.Tenant, error) {
	return s.store.ListTenants(ctx)
}

// Get returns one tenant entry.
func (s *Service) Get(ctx context.Context, tenantID string) (runtime.Tenant, error) {
	return s.store.GetTenant(ctx, strings.TrimSpace(tenantID))
}

// ListEvents returns the tenant's hash-chained lifecycle evidence.
func (s *Service) ListEvents(ctx context.Context, tenantID string) ([]runtime.TenantEvent, error) {
	return s.store.ListEvents(ctx, strings.TrimSpace(tenantID))
}

// Disable suspends an active tenant. A disabled tenant fails closed at
// the auth layer on its next request (TenantDirectory check).
func (s *Service) Disable(ctx context.Context, tenantID, actor, reason string) (runtime.Tenant, error) {
	return s.transition(ctx, tenantID, actor, reason, runtime.TenantStatusDisabled, runtime.TenantEventDisabled,
		func(status string) bool { return status == runtime.TenantStatusActive },
		func(status string) bool { return status == runtime.TenantStatusDisabled })
}

// Enable reactivates a disabled tenant.
func (s *Service) Enable(ctx context.Context, tenantID, actor, reason string) (runtime.Tenant, error) {
	return s.transition(ctx, tenantID, actor, reason, runtime.TenantStatusActive, runtime.TenantEventEnabled,
		func(status string) bool { return status == runtime.TenantStatusDisabled },
		func(status string) bool { return status == runtime.TenantStatusActive })
}

// Deprovision is the terminal, non-destructive lifecycle state. A
// deprovisioned tenant fails closed at the auth layer and can only be
// re-provisioned through Provision. There is no delete path anywhere.
func (s *Service) Deprovision(ctx context.Context, tenantID, actor, reason string) (runtime.Tenant, error) {
	return s.transition(ctx, tenantID, actor, reason, runtime.TenantStatusDeprovisioned, runtime.TenantEventDeprovisioned,
		func(status string) bool {
			return status == runtime.TenantStatusActive || status == runtime.TenantStatusDisabled
		},
		func(status string) bool { return status == runtime.TenantStatusDeprovisioned })
}

// transition implements one lifecycle step. fromTo is the set of statuses
// the transition is allowed from; alreadyIn is the set where the
// transition is idempotent. Any other status fails closed with
// runtime.ErrTenantNotActive.
func (s *Service) transition(ctx context.Context, tenantID, actor, reason, target, eventType string, fromTo, alreadyIn func(string) bool) (runtime.Tenant, error) {
	tenantID = strings.TrimSpace(tenantID)
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return runtime.Tenant{}, fmt.Errorf("%w: reason required for tenant %s", runtime.ErrInvalidRequest, target)
	}
	if actor == "" {
		return runtime.Tenant{}, runtime.ErrInvalidRequest
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var tenant runtime.Tenant
	err := s.store.Transact(ctx, "tenancy:"+tenantID, func(tx TxStore) error {
		current, err := tx.GetTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		if alreadyIn(current.Status) {
			tenant = current
			return nil
		}
		if !fromTo(current.Status) {
			return runtime.ErrTenantNotActive
		}
		updated, err := tx.SetTenantStatus(ctx, tenantID, target, actor, reason, now)
		if err != nil {
			return err
		}
		tenant = updated
		_, err = tx.AppendEvent(ctx, runtime.TenantEvent{
			TenantID:  tenantID,
			EventType: eventType,
			Actor:     actor,
			Reason:    reason,
			Region:    updated.Region,
			CreatedAt: now,
		})
		return err
	})
	if err != nil {
		return runtime.Tenant{}, err
	}
	return tenant, nil
}

// Seed inserts a configuration-sourced tenant into the directory if (and
// only if) it is not already present. Existing rows are never modified —
// config can only seed, never override directory state. Used by
// cmd/query-runtime to mirror GROUNDWORK_TENANT_REGIONS into the
// directory at startup. Best-effort at the caller: errors are logged,
// not fatal.
func (s *Service) Seed(ctx context.Context, tenantID, region, reason string) error {
	tenantID = strings.TrimSpace(tenantID)
	r, err := deployment.ParseRegion(region)
	if err != nil {
		return err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	return s.store.Transact(ctx, "tenancy:"+tenantID, func(tx TxStore) error {
		if _, err := tx.GetTenant(ctx, tenantID); err == nil {
			return nil // config seeding never overrides directory state
		} else if !errors.Is(err, runtime.ErrTenantNotFound) {
			return err
		}
		if _, err := tx.UpsertTenant(ctx, runtime.Tenant{
			TenantID:  tenantID,
			Region:    r.String(),
			Status:    runtime.TenantStatusActive,
			CreatedBy: "env-config",
			Reason:    reason,
			CreatedAt: now,
			UpdatedAt: now,
		}); err != nil {
			return err
		}
		_, err := tx.AppendEvent(ctx, runtime.TenantEvent{
			TenantID:  tenantID,
			EventType: runtime.TenantEventProvisioned,
			Actor:     "env-config",
			Reason:    reason,
			Region:    r.String(),
			CreatedAt: now,
		})
		return err
	})
}

// Lookup implements runtime.TenantDirectory: the auth layer consults the
// directory after key resolution so disabled/deprovisioned tenants fail
// closed on their next request. ok=false for tenants not in the
// directory (they stay governed by the trusted region resolver only and
// fall back to the default capacity tier).
func (s *Service) Lookup(ctx context.Context, tenantID string) (region, status, tier string, ok bool) {
	t, err := s.store.GetTenant(ctx, strings.TrimSpace(tenantID))
	if err != nil {
		return "", "", "", false
	}
	if t.Tier == "" {
		t.Tier = runtime.CapacityTierStandard
	}
	return t.Region, t.Status, t.Tier, true
}

var _ runtime.TenantService = (*Service)(nil)
var _ runtime.TenantDirectory = (*Service)(nil)
