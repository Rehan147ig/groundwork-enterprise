package breakglass

import (
	"context"
	"fmt"
	"strings"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// KeyMinter is the subset of runtime.APIKeyManager the break-glass
// service needs: mint a short-lived key and revoke it. The server's API
// key resolver implements it; expiry is enforced at the auth layer, so a
// revoked or expired break-glass key fails closed on its next use.
type KeyMinter interface {
	Create(ctx context.Context, tenant runtime.TenantContext, req runtime.CreateAPIKeyRequest) (runtime.CreateAPIKeyResponse, error)
	Revoke(ctx context.Context, tenant runtime.TenantContext, id int64) (bool, error)
}

// Service is the authoritative break-glass surface: validates reasons
// and durations, mints/revokes the bound admin key, and appends
// hash-chained evidence atomically with each lifecycle transition.
type Service struct {
	store       Store
	keys        KeyMinter
	maxDuration time.Duration
	now         func() time.Time
}

// NewService builds the break-glass service. maxDuration caps how long a
// single grant may run (BREAK_GLASS_MAX_MINUTES); grants over the cap
// are rejected, they are never silently shortened.
func NewService(store Store, keys KeyMinter, maxDuration time.Duration) *Service {
	if maxDuration <= 0 {
		maxDuration = time.Hour
	}
	return &Service{store: store, keys: keys, maxDuration: maxDuration, now: time.Now}
}

// Open mints a short-lived admin-scoped API key and opens an active
// grant with 'opened' evidence. The key is minted first; if the grant
// record cannot be persisted, the key is revoked best-effort so no
// orphaned access key survives a failed grant. The minted raw key is
// returned once in the response; it is never persisted anywhere.
//
// Four-eyes mode (req.Admin2ID set): the grant is created in
// pending_approval with approver1 = the opener and pending_approval_by =
// the named second admin. No API key is minted — a pending grant must
// not carry a live admin key. The key is minted and returned only when
// the second admin approves (see Approve), so the raw key reaches
// exactly the two-admins-approved path.
func (s *Service) Open(ctx context.Context, tenant runtime.TenantContext, operatorPrincipalID string, req runtime.OpenBreakGlassRequest) (runtime.BreakGlassGrant, string, error) {
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return runtime.BreakGlassGrant{}, "", fmt.Errorf("%w: reason required for break-glass access", runtime.ErrInvalidRequest)
	}
	if operatorPrincipalID == "" {
		return runtime.BreakGlassGrant{}, "", runtime.ErrInvalidRequest
	}
	if s.keys == nil {
		return runtime.BreakGlassGrant{}, "", runtime.ErrBreakGlassUnavailable
	}
	if req.DurationMinutes < 1 {
		return runtime.BreakGlassGrant{}, "", fmt.Errorf("%w: duration_minutes must be at least 1", runtime.ErrInvalidRequest)
	}
	if maxMinutes := int(s.maxDuration.Minutes()); req.DurationMinutes > maxMinutes {
		return runtime.BreakGlassGrant{}, "", fmt.Errorf("%w: duration_minutes %d exceeds the maximum %d", runtime.ErrInvalidRequest, req.DurationMinutes, maxMinutes)
	}

	now := s.now().UTC()
	expiresAt := now.Add(time.Duration(req.DurationMinutes) * time.Minute).Truncate(time.Microsecond)
	keyTenant := runtime.TenantContext{
		TenantID: tenant.TenantID,
		Region:   tenant.Region,
	}
	fourEyes := strings.TrimSpace(req.Admin2ID) != ""
	var keyID int64
	var keyPrefix, mintedKey string
	if !fourEyes {
		key, err := s.keys.Create(ctx, keyTenant, runtime.CreateAPIKeyRequest{
			Name:      "break-glass",
			Scopes:    []string{"admin"},
			ExpiresAt: expiresAt,
		})
		if err != nil {
			return runtime.BreakGlassGrant{}, "", err
		}
		keyID, keyPrefix, mintedKey = key.ID, key.KeyPrefix, key.Key
	}

	status := runtime.BreakGlassStatusActive
	if fourEyes {
		status = runtime.BreakGlassStatusPendingApproval
	}
	grant := runtime.BreakGlassGrant{
		TenantID:            tenant.TenantID,
		OperatorPrincipalID: operatorPrincipalID,
		Reason:              reason,
		DurationMinutes:     req.DurationMinutes,
		KeyID:               keyID,
		KeyPrefix:           keyPrefix,
		Status:              status,
		ExpiresAt:           expiresAt,
		RequestedAt:         now,
	}
	if fourEyes {
		// Admin 1's opening is the first of the two approvals; the
		// grant waits for the named second admin.
		grant.PendingApprovalBy = strings.TrimSpace(req.Admin2ID)
		grant.PendingApprovalReason = reason
		grant.Approver1 = operatorPrincipalID
	}
	grant.ImmutableDigest = ComputeGrantDigest(grant)

	event := runtime.BreakGlassEvent{
		TenantID:         tenant.TenantID,
		GrantID:          grant.ID,
		EventType:        runtime.BreakGlassEventOpened,
		ActorPrincipalID: operatorPrincipalID,
		Reason:           reason,
		DurationMinutes:  req.DurationMinutes,
		KeyID:            keyID,
		ExpiresAt:        expiresAt,
		CreatedAt:        now.Truncate(time.Microsecond),
	}

	err := s.store.Transact(ctx, "breakglass:"+tenant.TenantID, func(tx TxStore) error {
		created, err := tx.CreateGrant(ctx, grant)
		if err != nil {
			return err
		}
		grant = created
		event.GrantID = grant.ID
		_, err = tx.AppendEvent(ctx, event)
		return err
	})
	if err != nil {
		// The key is minted but the grant never persisted: revoke it so
		// the failed grant leaves no live admin key behind.
		if !fourEyes {
			_, _ = s.keys.Revoke(ctx, keyTenant, keyID)
		}
		return runtime.BreakGlassGrant{}, "", err
	}
	return grant, mintedKey, nil
}

// List returns the tenant's grants, lazily flipping grants that have
// reached expires_at to 'expired' (evidence appended).
func (s *Service) List(ctx context.Context, tenantID string) ([]runtime.BreakGlassGrant, error) {
	grants, err := s.store.ListGrants(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	expired := false
	for i := range grants {
		if (grants[i].Status == runtime.BreakGlassStatusActive || grants[i].Status == runtime.BreakGlassStatusPendingApproval) && !grants[i].ExpiresAt.After(now) {
			if err := s.expire(ctx, tenantID, grants[i]); err != nil {
				return nil, err
			}
			grants[i].Status = runtime.BreakGlassStatusExpired
			expired = true
		}
	}
	if !expired {
		return grants, nil
	}
	return s.store.ListGrants(ctx, tenantID)
}

// Get returns one grant with its event chain, lazily expiring it.
func (s *Service) Get(ctx context.Context, tenantID, grantID string) (runtime.BreakGlassGrant, []runtime.BreakGlassEvent, error) {
	grant, err := s.store.GetGrant(ctx, tenantID, grantID)
	if err != nil {
		return runtime.BreakGlassGrant{}, nil, err
	}
	if (grant.Status == runtime.BreakGlassStatusActive || grant.Status == runtime.BreakGlassStatusPendingApproval) && !grant.ExpiresAt.After(s.now().UTC()) {
		if err := s.expire(ctx, tenantID, grant); err != nil {
			return runtime.BreakGlassGrant{}, nil, err
		}
		grant.Status = runtime.BreakGlassStatusExpired
	}
	events, err := s.store.ListEvents(ctx, tenantID, grantID)
	if err != nil {
		return runtime.BreakGlassGrant{}, nil, err
	}
	return grant, events, nil
}

// Revoke terminates an active grant early: the API key is revoked
// immediately and 'revoked' evidence is appended with the mandatory
// reason.
func (s *Service) Revoke(ctx context.Context, tenant runtime.TenantContext, grantID, actor string, req runtime.RevokeBreakGlassRequest) (runtime.BreakGlassGrant, error) {
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return runtime.BreakGlassGrant{}, fmt.Errorf("%w: reason required for break-glass revocation", runtime.ErrInvalidRequest)
	}
	if actor == "" {
		return runtime.BreakGlassGrant{}, runtime.ErrInvalidRequest
	}

	var grant runtime.BreakGlassGrant
	err := s.store.Transact(ctx, "breakglass:"+tenant.TenantID, func(tx TxStore) error {
		current, err := tx.GetGrant(ctx, tenant.TenantID, grantID)
		if err != nil {
			return err
		}
		if current.Status != runtime.BreakGlassStatusActive {
			return runtime.ErrBreakGlassNotActive
		}
		revoked, err := tx.SetGrantStatus(ctx, tenant.TenantID, grantID, runtime.BreakGlassStatusRevoked, actor, reason)
		if err != nil {
			return err
		}
		grant = revoked
		_, err = tx.AppendEvent(ctx, runtime.BreakGlassEvent{
			TenantID:         tenant.TenantID,
			GrantID:          grantID,
			EventType:        runtime.BreakGlassEventRevoked,
			ActorPrincipalID: actor,
			Reason:           reason,
			DurationMinutes:  revoked.DurationMinutes,
			KeyID:            revoked.KeyID,
			ExpiresAt:        revoked.ExpiresAt,
			CreatedAt:        s.now().UTC().Truncate(time.Microsecond),
		})
		return err
	})
	if err != nil {
		return runtime.BreakGlassGrant{}, err
	}
	// Key revocation is idempotent; best-effort after the evidence is
	// durable.
	_, _ = s.keys.Revoke(ctx, runtime.TenantContext{TenantID: tenant.TenantID, Region: tenant.Region}, grant.KeyID)
	return grant, nil
}

// Approve is the second admin's four-eyes approval. The actor must be
// exactly the admin the grant is waiting on (server-side role check —
// the HTTP surface and interactive actions never trust a self-declared
// role). The key is minted first; if the activation cannot be
// persisted, the key is revoked best-effort. The raw key is returned
// once, only to the approving admin.
func (s *Service) Approve(ctx context.Context, tenant runtime.TenantContext, grantID, actor string) (runtime.BreakGlassGrant, string, error) {
	if strings.TrimSpace(actor) == "" {
		return runtime.BreakGlassGrant{}, "", runtime.ErrInvalidRequest
	}
	if s.keys == nil {
		return runtime.BreakGlassGrant{}, "", runtime.ErrBreakGlassUnavailable
	}

	var pending runtime.BreakGlassGrant
	err := s.store.Transact(ctx, "breakglass:"+tenant.TenantID, func(tx TxStore) error {
		current, err := tx.GetGrant(ctx, tenant.TenantID, grantID)
		if err != nil {
			return err
		}
		if current.Status != runtime.BreakGlassStatusPendingApproval {
			return runtime.ErrBreakGlassNotPendingApproval
		}
		if current.PendingApprovalBy != actor {
			return runtime.ErrBreakGlassForbidden
		}
		pending = current
		return nil
	})
	if err != nil {
		return runtime.BreakGlassGrant{}, "", err
	}

	key, err := s.keys.Create(ctx, runtime.TenantContext{TenantID: tenant.TenantID, Region: tenant.Region}, runtime.CreateAPIKeyRequest{
		Name:      "break-glass",
		Scopes:    []string{"admin"},
		ExpiresAt: pending.ExpiresAt,
	})
	if err != nil {
		return runtime.BreakGlassGrant{}, "", err
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	var activated runtime.BreakGlassGrant
	err = s.store.Transact(ctx, "breakglass:"+tenant.TenantID, func(tx TxStore) error {
		current, err := tx.GetGrant(ctx, tenant.TenantID, grantID)
		if err != nil {
			return err
		}
		if current.Status != runtime.BreakGlassStatusPendingApproval {
			return runtime.ErrBreakGlassNotPendingApproval
		}
		if current.PendingApprovalBy != actor {
			return runtime.ErrBreakGlassForbidden
		}
		activated, err = tx.ApproveStep(ctx, tenant.TenantID, grantID, actor, 2, now)
		if err != nil {
			return err
		}
		activated, err = tx.BindGrantKey(ctx, tenant.TenantID, grantID, key.ID, key.KeyPrefix)
		if err != nil {
			return err
		}
		_, err = tx.AppendEvent(ctx, runtime.BreakGlassEvent{
			TenantID:         tenant.TenantID,
			GrantID:          grantID,
			EventType:        runtime.BreakGlassEventApprovedByAdmin2,
			ActorPrincipalID: actor,
			Reason:           "second admin approval",
			DurationMinutes:  activated.DurationMinutes,
			KeyID:            key.ID,
			ExpiresAt:        activated.ExpiresAt,
			CreatedAt:        now,
		})
		return err
	})
	if err != nil {
		// The key is minted but the activation never persisted: revoke
		// it so a failed approval leaves no live admin key behind.
		_, _ = s.keys.Revoke(ctx, runtime.TenantContext{TenantID: tenant.TenantID, Region: tenant.Region}, key.ID)
		return runtime.BreakGlassGrant{}, "", err
	}
	return activated, key.Key, nil
}

// Reject terminates a pending grant. The actor must be exactly the
// admin the grant is waiting on; the reason is mandatory and recorded
// as hash-chained 'rejected' evidence.
func (s *Service) Reject(ctx context.Context, tenant runtime.TenantContext, grantID, actor string, req runtime.RevokeBreakGlassRequest) (runtime.BreakGlassGrant, error) {
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return runtime.BreakGlassGrant{}, fmt.Errorf("%w: reason required for break-glass rejection", runtime.ErrInvalidRequest)
	}
	if strings.TrimSpace(actor) == "" {
		return runtime.BreakGlassGrant{}, runtime.ErrInvalidRequest
	}

	var grant runtime.BreakGlassGrant
	err := s.store.Transact(ctx, "breakglass:"+tenant.TenantID, func(tx TxStore) error {
		current, err := tx.GetGrant(ctx, tenant.TenantID, grantID)
		if err != nil {
			return err
		}
		if current.Status != runtime.BreakGlassStatusPendingApproval {
			return runtime.ErrBreakGlassNotPendingApproval
		}
		if current.PendingApprovalBy != actor {
			return runtime.ErrBreakGlassForbidden
		}
		rejected, err := tx.SetGrantStatus(ctx, tenant.TenantID, grantID, runtime.BreakGlassStatusRejected, actor, reason)
		if err != nil {
			return err
		}
		grant = rejected
		_, err = tx.AppendEvent(ctx, runtime.BreakGlassEvent{
			TenantID:         tenant.TenantID,
			GrantID:          grantID,
			EventType:        runtime.BreakGlassEventRejected,
			ActorPrincipalID: actor,
			Reason:           reason,
			DurationMinutes:  rejected.DurationMinutes,
			KeyID:            rejected.KeyID,
			ExpiresAt:        rejected.ExpiresAt,
			CreatedAt:        s.now().UTC().Truncate(time.Microsecond),
		})
		return err
	})
	if err != nil {
		return runtime.BreakGlassGrant{}, err
	}
	// A pending grant has no key; this is defensive in case a rejected
	// grant ever carried one.
	_, _ = s.keys.Revoke(ctx, runtime.TenantContext{TenantID: tenant.TenantID, Region: tenant.Region}, grant.KeyID)
	return grant, nil
}

// RecordNotificationFailure appends 'notification_failed' evidence to a
// grant's chain so a failed delivery (Slack/Teams) is never silent —
// the grant's lifecycle remains fully accountable even when the alert
// channel itself failed. Best-effort: errors are returned for the
// caller to log; the grant operation itself is never rolled back.
func (s *Service) RecordNotificationFailure(ctx context.Context, tenantID, grantID, channel, detail string) error {
	if s.store == nil {
		return runtime.ErrBreakGlassUnavailable
	}
	return s.store.Transact(ctx, "breakglass:"+tenantID, func(tx TxStore) error {
		grant, err := tx.GetGrant(ctx, tenantID, grantID)
		if err != nil {
			return err
		}
		_, err = tx.AppendEvent(ctx, runtime.BreakGlassEvent{
			TenantID:         tenantID,
			GrantID:          grantID,
			EventType:        runtime.BreakGlassEventNotificationFailed,
			ActorPrincipalID: "notification-delivery",
			Reason:           channel + ": " + detail,
			DurationMinutes:  grant.DurationMinutes,
			KeyID:            grant.KeyID,
			ExpiresAt:        grant.ExpiresAt,
			CreatedAt:        s.now().UTC().Truncate(time.Microsecond),
		})
		return err
	})
}

// expire flips one active grant to 'expired' and appends 'expired'
// evidence atomically.
func (s *Service) expire(ctx context.Context, tenantID string, grant runtime.BreakGlassGrant) error {
	return s.store.Transact(ctx, "breakglass:"+tenantID, func(tx TxStore) error {
		current, err := tx.GetGrant(ctx, tenantID, grant.ID)
		if err != nil {
			return err
		}
		if current.Status != runtime.BreakGlassStatusActive && current.Status != runtime.BreakGlassStatusPendingApproval {
			return nil // already transitioned by a concurrent call
		}
		if _, err := tx.SetGrantStatus(ctx, tenantID, grant.ID, runtime.BreakGlassStatusExpired, "", ""); err != nil {
			return err
		}
		_, err = tx.AppendEvent(ctx, runtime.BreakGlassEvent{
			TenantID:         tenantID,
			GrantID:          grant.ID,
			EventType:        runtime.BreakGlassEventExpired,
			ActorPrincipalID: grant.OperatorPrincipalID,
			Reason:           "grant expired",
			DurationMinutes:  grant.DurationMinutes,
			KeyID:            grant.KeyID,
			ExpiresAt:        grant.ExpiresAt,
			CreatedAt:        s.now().UTC().Truncate(time.Microsecond),
		})
		return err
	})
}

var _ runtime.BreakGlassService = (*Service)(nil)
