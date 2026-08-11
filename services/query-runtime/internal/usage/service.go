package usage

import (
	"context"
	"errors"
)

// Service is the metering facade the runtime wires in. It layers the
// read/limit surface over the Store and maps enforcement outcomes to
// *QuotaError (which the HTTP layer turns into 403
// quota_exceeded:<metric>).
type Service struct {
	store Store
}

// NewService returns a metering service over the given store.
func NewService(store Store) *Service {
	return &Service{store: store}
}

// Record meters one unit (or delta bytes) of metric for the tenant.
// It fails closed: when the tenant's applicable quota (monthly or
// lifetime) would be exceeded, the increment is rolled back and a
// *QuotaError is returned. Absent limits are unlimited.
func (s *Service) Record(ctx context.Context, tenantID, metric string, delta int64) error {
	if s == nil || s.store == nil {
		return nil
	}
	if delta == 0 {
		return nil
	}
	_, err := s.store.Record(ctx, tenantID, metric, delta)
	return err
}

// Usage returns the current snapshot for every metered metric: the
// current-month count and the all-time count, each paired with its
// applicable limit (0 = unlimited, remaining = -1).
func (s *Service) Usage(ctx context.Context, tenantID string) ([]MetricUsage, error) {
	if s == nil || s.store == nil {
		return []MetricUsage{}, nil
	}
	limits, err := s.store.Limits(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	limitFor := map[string]int64{} // key: metric|period
	for _, l := range limits {
		limitFor[l.Metric+"|"+l.Period] = l.Limit
	}
	out := make([]MetricUsage, 0, len(AllMetrics())*2)
	for _, metric := range AllMetrics() {
		monthly, err := s.store.MonthlyCount(ctx, tenantID, metric)
		if err != nil {
			return nil, err
		}
		total, err := s.store.TotalCount(ctx, tenantID, metric)
		if err != nil {
			return nil, err
		}
		for _, period := range []string{PeriodMonthly, PeriodLifetime} {
			limit := limitFor[metric+"|"+period]
			count := monthly
			if period == PeriodLifetime {
				count = total
			}
			out = append(out, MetricUsage{
				Metric:    metric,
				Period:    period,
				Count:     count,
				Limit:     limit,
				Remaining: remaining(count, limit),
			})
		}
	}
	return out, nil
}

// Limits returns the tenant's quota rows.
func (s *Service) Limits(ctx context.Context, tenantID string) ([]Limit, error) {
	if s == nil || s.store == nil {
		return []Limit{}, nil
	}
	return s.store.Limits(ctx, tenantID)
}

// UpsertLimits applies quota rows (Limit <= 0 clears) and returns the
// tenant's resulting limit set.
func (s *Service) UpsertLimits(ctx context.Context, tenantID string, limits []Limit) ([]Limit, error) {
	if s == nil || s.store == nil {
		return []Limit{}, nil
	}
	for _, l := range limits {
		if l.Metric == "" || l.Period == "" {
			return nil, errors.New("invalid limit: metric and period are required")
		}
		if l.Period != PeriodMonthly && l.Period != PeriodLifetime {
			return nil, errors.New("invalid limit period: monthly or lifetime")
		}
		if err := s.store.UpsertLimit(ctx, tenantID, l); err != nil {
			return nil, err
		}
	}
	return s.store.Limits(ctx, tenantID)
}

func remaining(count, limit int64) int64 {
	if limit <= 0 {
		return -1
	}
	if r := limit - count; r < 0 {
		return 0
	} else {
		return r
	}
}
