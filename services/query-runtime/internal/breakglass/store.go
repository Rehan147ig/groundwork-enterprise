package breakglass

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// TxStore is the set of break-glass operations that mutate state or must
// observe state consistently with writes. Implementations run inside a
// transaction (Postgres) or a store-wide lock (memory) so grant creation
// + evidence append and revocation + evidence append are atomic and the
// evidence chain cannot fork.
type TxStore interface {
	Reader
	// CreateGrant persists a new grant row with its own status (active,
	// or pending_approval for the four-eyes flow).
	CreateGrant(ctx context.Context, g runtime.BreakGlassGrant) (runtime.BreakGlassGrant, error)
	// AppendEvent persists immutable hash-chained evidence. The chain
	// links per tenant (each event digests its predecessor).
	AppendEvent(ctx context.Context, e runtime.BreakGlassEvent) (runtime.BreakGlassEvent, error)
	// SetGrantStatus transitions a grant's lifecycle status and, for a
	// revocation or rejection, records who terminated it and why.
	SetGrantStatus(ctx context.Context, tenantID, grantID, status, revokedBy, revocationReason string) (runtime.BreakGlassGrant, error)
	// ApproveStep records one four-eyes approval: step 1 records
	// approver1 / approved_by_admin1_at (grant stays pending), step 2
	// records approver2 / approved_by_admin2_at and flips the grant to
	// active.
	ApproveStep(ctx context.Context, tenantID, grantID, approver string, adminStep int, at time.Time) (runtime.BreakGlassGrant, error)
	// BindGrantKey attaches the minted API key when a pending grant is
	// activated (a pending grant never carries a live key, so the key is
	// minted only at activation and bound here atomically with the
	// active transition).
	BindGrantKey(ctx context.Context, tenantID, grantID string, keyID int64, keyPrefix string) (runtime.BreakGlassGrant, error)
}

// Reader is the read surface (tenant-scoped only).
type Reader interface {
	GetGrant(ctx context.Context, tenantID, grantID string) (runtime.BreakGlassGrant, error)
	ListGrants(ctx context.Context, tenantID string) ([]runtime.BreakGlassGrant, error)
	ListEvents(ctx context.Context, tenantID, grantID string) ([]runtime.BreakGlassEvent, error)
}

// Store is the persistence surface.
type Store interface {
	Reader
	Transact(ctx context.Context, lockKey string, fn func(tx TxStore) error) error
}

// ---------------------------------------------------------------------
// In-memory store (local/dev/demo). Ephemeral and per-process.
// ---------------------------------------------------------------------

type memoryStore struct {
	mu     sync.Mutex
	grants map[string]runtime.BreakGlassGrant   // key: tenantID|grantID
	events map[string][]runtime.BreakGlassEvent // key: tenantID
	next   int
}

// NewMemoryStore returns an ephemeral in-memory store.
func NewMemoryStore() *memoryStore {
	return &memoryStore{
		grants: map[string]runtime.BreakGlassGrant{},
		events: map[string][]runtime.BreakGlassEvent{},
	}
}

func memGrantKey(tenantID, grantID string) string { return tenantID + "|" + grantID }

// memNext returns a monotonically increasing local identifier.
func (s *memoryStore) memNext() int {
	s.next++
	return s.next
}

func (s *memoryStore) Transact(ctx context.Context, lockKey string, fn func(tx TxStore) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(s)
}

func (s *memoryStore) CreateGrant(ctx context.Context, g runtime.BreakGlassGrant) (runtime.BreakGlassGrant, error) {
	if g.ID == "" {
		g.ID = fmt.Sprintf("grant-%d", s.memNext())
	}
	s.grants[memGrantKey(g.TenantID, g.ID)] = g
	return g, nil
}

func (s *memoryStore) AppendEvent(ctx context.Context, e runtime.BreakGlassEvent) (runtime.BreakGlassEvent, error) {
	if e.ID == "" {
		e.ID = fmt.Sprintf("evt-%d", s.memNext())
	}
	// Mirror the Postgres store: the digest is computed over the
	// previous event in the tenant's chain, so the memory store's
	// evidence verifies identically (VerifyBreakGlassEventChain).
	var prev string
	chain := s.events[e.TenantID]
	if len(chain) > 0 {
		prev = chain[len(chain)-1].ImmutableDigest
	}
	e.ImmutableDigest = ComputeBreakGlassEventDigest(e, prev)
	e.PreviousHash = prev
	s.events[e.TenantID] = append(s.events[e.TenantID], e)
	return e, nil
}

func (s *memoryStore) SetGrantStatus(ctx context.Context, tenantID, grantID, status, revokedBy, revocationReason string) (runtime.BreakGlassGrant, error) {
	g, ok := s.grants[memGrantKey(tenantID, grantID)]
	if !ok {
		return runtime.BreakGlassGrant{}, runtime.ErrBreakGlassNotFound
	}
	g.Status = status
	if status == runtime.BreakGlassStatusRevoked || status == runtime.BreakGlassStatusRejected {
		g.RevokedBy = revokedBy
		g.RevocationReason = revocationReason
	}
	s.grants[memGrantKey(tenantID, grantID)] = g
	return g, nil
}

func (s *memoryStore) ApproveStep(ctx context.Context, tenantID, grantID, approver string, adminStep int, at time.Time) (runtime.BreakGlassGrant, error) {
	g, ok := s.grants[memGrantKey(tenantID, grantID)]
	if !ok {
		return runtime.BreakGlassGrant{}, runtime.ErrBreakGlassNotFound
	}
	switch adminStep {
	case 1:
		g.Approver1 = approver
		g.ApprovedByAdmin1At = at
	case 2:
		g.Approver2 = approver
		g.ApprovedByAdmin2At = at
		g.Status = runtime.BreakGlassStatusActive
	default:
		return runtime.BreakGlassGrant{}, fmt.Errorf("invalid approval step %d", adminStep)
	}
	s.grants[memGrantKey(tenantID, grantID)] = g
	return g, nil
}

func (s *memoryStore) BindGrantKey(ctx context.Context, tenantID, grantID string, keyID int64, keyPrefix string) (runtime.BreakGlassGrant, error) {
	g, ok := s.grants[memGrantKey(tenantID, grantID)]
	if !ok {
		return runtime.BreakGlassGrant{}, runtime.ErrBreakGlassNotFound
	}
	if g.KeyID != 0 {
		return runtime.BreakGlassGrant{}, fmt.Errorf("%w: grant already has a bound key", runtime.ErrBreakGlassNotPendingApproval)
	}
	g.KeyID = keyID
	g.KeyPrefix = keyPrefix
	s.grants[memGrantKey(tenantID, grantID)] = g
	return g, nil
}

func (s *memoryStore) GetGrant(ctx context.Context, tenantID, grantID string) (runtime.BreakGlassGrant, error) {
	g, ok := s.grants[memGrantKey(tenantID, grantID)]
	if !ok {
		return runtime.BreakGlassGrant{}, runtime.ErrBreakGlassNotFound
	}
	return g, nil
}

func (s *memoryStore) ListGrants(ctx context.Context, tenantID string) ([]runtime.BreakGlassGrant, error) {
	prefix := tenantID + "|"
	out := []runtime.BreakGlassGrant{}
	for k, g := range s.grants {
		if strings.HasPrefix(k, prefix) {
			out = append(out, g)
		}
	}
	return out, nil
}

func (s *memoryStore) ListEvents(ctx context.Context, tenantID, grantID string) ([]runtime.BreakGlassEvent, error) {
	out := []runtime.BreakGlassEvent{}
	for _, e := range s.events[tenantID] {
		if e.GrantID == grantID {
			out = append(out, e)
		}
	}
	return out, nil
}

var _ Store = (*memoryStore)(nil)
