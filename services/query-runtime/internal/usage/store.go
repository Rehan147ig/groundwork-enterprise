package usage

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// Store is the metering persistence surface. Implementations must make
// Record atomic: the increment and the quota check happen in one
// critical section, and an over-limit increment is rolled back so a
// denied attempt never consumes quota.
type Store interface {
	// Record increments the current-month counter for (tenantID,
	// metric) by delta and returns the new monthly count. When the
	// increment would exceed an applicable limit (monthly or lifetime)
	// it is rolled back and a *QuotaError is returned.
	Record(ctx context.Context, tenantID, metric string, delta int64) (int64, error)
	// MonthlyCount returns the current-month counter value.
	MonthlyCount(ctx context.Context, tenantID, metric string) (int64, error)
	// TotalCount returns the sum of the counter across all months.
	TotalCount(ctx context.Context, tenantID, metric string) (int64, error)
	// UpsertLimit sets (or, with Limit <= 0, clears) one quota row.
	UpsertLimit(ctx context.Context, tenantID string, l Limit) error
	// Limits returns the tenant's quota rows.
	Limits(ctx context.Context, tenantID string) ([]Limit, error)
}

// ErrQuotaExceeded is the unwrapped sentinel; use errors.As to recover
// the metric from *QuotaError.
var ErrQuotaExceeded = errors.New("usage quota exceeded")

func quotaError(metric string) *QuotaError { return &QuotaError{Metric: metric} }

// ---------------------------------------------------------------------
// In-memory store (local/dev/demo). Ephemeral and per-process.
// ---------------------------------------------------------------------

type memoryStore struct {
	mu       sync.Mutex
	counters map[string]int64 // key: tenantID|metric|month
	limits   map[string]Limit // key: tenantID|metric|period
}

// NewMemoryStore returns an ephemeral in-memory store.
func NewMemoryStore() *memoryStore {
	return &memoryStore{
		counters: map[string]int64{},
		limits:   map[string]Limit{},
	}
}

func memCounterKey(tenantID, metric, period string) string {
	return tenantID + "|" + metric + "|" + period
}

func (s *memoryStore) Record(ctx context.Context, tenantID, metric string, delta int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	period := MonthKey(time.Now())
	key := memCounterKey(tenantID, metric, period)
	newCount := s.counters[key] + delta

	// Monthly limit.
	if l, ok := s.limits[memCounterKey(tenantID, metric, PeriodMonthly)]; ok && l.Limit > 0 && newCount > l.Limit {
		return 0, quotaError(metric)
	}
	// Lifetime limit (sum across all months, including the increment).
	if l, ok := s.limits[memCounterKey(tenantID, metric, PeriodLifetime)]; ok && l.Limit > 0 {
		if s.totalLocked(tenantID, metric)+delta > l.Limit {
			return 0, quotaError(metric)
		}
	}
	s.counters[key] = newCount
	return newCount, nil
}

func (s *memoryStore) MonthlyCount(ctx context.Context, tenantID, metric string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counters[memCounterKey(tenantID, metric, MonthKey(time.Now()))], nil
}

func (s *memoryStore) TotalCount(ctx context.Context, tenantID, metric string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totalLocked(tenantID, metric), nil
}

func (s *memoryStore) totalLocked(tenantID, metric string) int64 {
	var total int64
	prefix := tenantID + "|" + metric + "|"
	for k, v := range s.counters {
		if strings.HasPrefix(k, prefix) {
			total += v
		}
	}
	return total
}

func (s *memoryStore) UpsertLimit(ctx context.Context, tenantID string, l Limit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memCounterKey(tenantID, l.Metric, l.Period)
	if l.Limit <= 0 {
		delete(s.limits, key)
		return nil
	}
	s.limits[key] = l
	return nil
}

func (s *memoryStore) Limits(ctx context.Context, tenantID string) ([]Limit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := tenantID + "|"
	out := []Limit{}
	for k, v := range s.limits {
		if strings.HasPrefix(k, prefix) {
			out = append(out, v)
		}
	}
	return out, nil
}

var _ Store = (*memoryStore)(nil)
