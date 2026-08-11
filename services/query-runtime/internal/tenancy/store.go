package tenancy

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// TxStore is the set of tenant-directory operations that mutate state or
// must observe state consistently with writes. Implementations run
// inside a transaction (Postgres) or a store-wide lock (memory) so a
// tenant status change + evidence append are atomic and the evidence
// chain cannot fork.
type TxStore interface {
	Reader
	// UpsertTenant persists a tenant row (create or update).
	UpsertTenant(ctx context.Context, t runtime.Tenant) (runtime.Tenant, error)
	// AppendEvent persists immutable hash-chained evidence. The chain
	// links per tenant (each event digests its predecessor).
	AppendEvent(ctx context.Context, e runtime.TenantEvent) (runtime.TenantEvent, error)
	// SetTenantStatus transitions a tenant's lifecycle status and
	// records who transitioned it and why.
	SetTenantStatus(ctx context.Context, tenantID, status, actor, reason string, now time.Time) (runtime.Tenant, error)
}

// Reader is the read surface of the tenant directory.
type Reader interface {
	GetTenant(ctx context.Context, tenantID string) (runtime.Tenant, error)
	ListTenants(ctx context.Context) ([]runtime.Tenant, error)
	ListEvents(ctx context.Context, tenantID string) ([]runtime.TenantEvent, error)
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
	mu      sync.Mutex
	tenants map[string]runtime.Tenant
	events  map[string][]runtime.TenantEvent
	next    int
}

// NewMemoryStore returns an ephemeral in-memory tenant directory store.
func NewMemoryStore() *memoryStore {
	return &memoryStore{
		tenants: map[string]runtime.Tenant{},
		events:  map[string][]runtime.TenantEvent{},
	}
}

func (s *memoryStore) memNext() int {
	s.next++
	return s.next
}

func (s *memoryStore) Transact(ctx context.Context, lockKey string, fn func(tx TxStore) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(s)
}

func (s *memoryStore) UpsertTenant(ctx context.Context, t runtime.Tenant) (runtime.Tenant, error) {
	if t.Tier == "" {
		t.Tier = runtime.CapacityTierStandard
	}
	s.tenants[t.TenantID] = t
	return t, nil
}

func (s *memoryStore) AppendEvent(ctx context.Context, e runtime.TenantEvent) (runtime.TenantEvent, error) {
	if e.ID == "" {
		e.ID = fmt.Sprintf("evt-%d", s.memNext())
	}
	// The chain links per tenant: each event digests its predecessor
	// (same invariant as the Postgres store).
	prev := ""
	events := s.events[e.TenantID]
	if n := len(events); n > 0 {
		prev = events[n-1].ImmutableDigest
	}
	e.ImmutableDigest = ComputeTenantEventDigest(e, prev)
	e.PreviousHash = prev
	s.events[e.TenantID] = append(events, e)
	return e, nil
}

func (s *memoryStore) SetTenantStatus(ctx context.Context, tenantID, status, actor, reason string, now time.Time) (runtime.Tenant, error) {
	t, ok := s.tenants[tenantID]
	if !ok {
		return runtime.Tenant{}, runtime.ErrTenantNotFound
	}
	t.Status = status
	t.Reason = reason
	t.UpdatedAt = now
	if status == runtime.TenantStatusDeprovisioned {
		t.DeprovisionedAt = now
	}
	s.tenants[tenantID] = t
	return t, nil
}

func (s *memoryStore) GetTenant(ctx context.Context, tenantID string) (runtime.Tenant, error) {
	t, ok := s.tenants[tenantID]
	if !ok {
		return runtime.Tenant{}, runtime.ErrTenantNotFound
	}
	if t.Tier == "" {
		t.Tier = runtime.CapacityTierStandard
	}
	return t, nil
}

func (s *memoryStore) ListTenants(ctx context.Context) ([]runtime.Tenant, error) {
	out := make([]runtime.Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out, nil
}

func (s *memoryStore) ListEvents(ctx context.Context, tenantID string) ([]runtime.TenantEvent, error) {
	events := append([]runtime.TenantEvent(nil), s.events[tenantID]...)
	return events, nil
}

var _ Store = (*memoryStore)(nil)
