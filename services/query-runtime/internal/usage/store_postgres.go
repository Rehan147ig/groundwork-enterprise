package usage

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Postgres store (production). Requires migration 025
// (025_usage_metering.up.sql). Counters are per-month rows upserted
// atomically; Record runs the increment and both limit checks inside
// one transaction and rolls back on an over-limit increment, so a
// denied attempt never consumes quota and concurrent tenants cannot
// overrun a limit.
type postgresStore struct {
	db *sql.DB
}

// NewPostgresStore returns the Postgres-backed metering store.
func NewPostgresStore(db *sql.DB) *postgresStore {
	return &postgresStore{db: db}
}

const recordSQL = `
INSERT INTO usage_counters (tenant_id, metric, period, count, updated_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (tenant_id, metric, period)
DO UPDATE SET count = usage_counters.count + EXCLUDED.count, updated_at = now()
RETURNING count`

func (s *postgresStore) Record(ctx context.Context, tenantID, metric string, delta int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	period := monthKeyUTC()
	var newCount int64
	if err := tx.QueryRowContext(ctx, recordSQL, tenantID, metric, period, delta).Scan(&newCount); err != nil {
		return 0, err
	}

	// Monthly limit.
	var monthlyLimit, lifetimeLimit int64
	err = tx.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(limit_value), 0) FROM usage_limits
		 WHERE tenant_id = $1 AND metric = $2 AND period = $3`,
		tenantID, metric, PeriodMonthly).Scan(&monthlyLimit)
	if err != nil {
		return 0, err
	}
	if monthlyLimit > 0 && newCount > monthlyLimit {
		return 0, quotaError(metric)
	}

	// Lifetime limit (sum across all months, including the increment).
	err = tx.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(limit_value), 0) FROM usage_limits
		 WHERE tenant_id = $1 AND metric = $2 AND period = $3`,
		tenantID, metric, PeriodLifetime).Scan(&lifetimeLimit)
	if err != nil {
		return 0, err
	}
	if lifetimeLimit > 0 {
		var total int64
		if err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(count), 0) FROM usage_counters
			 WHERE tenant_id = $1 AND metric = $2`,
			tenantID, metric).Scan(&total); err != nil {
			return 0, err
		}
		if total > lifetimeLimit {
			return 0, quotaError(metric)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return newCount, nil
}

func (s *postgresStore) MonthlyCount(ctx context.Context, tenantID, metric string) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx,
		`SELECT count FROM usage_counters WHERE tenant_id = $1 AND metric = $2 AND period = $3`,
		tenantID, metric, monthKeyUTC()).Scan(&count)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return count, err
}

func (s *postgresStore) TotalCount(ctx context.Context, tenantID, metric string) (int64, error) {
	var total int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(count), 0) FROM usage_counters WHERE tenant_id = $1 AND metric = $2`,
		tenantID, metric).Scan(&total)
	return total, err
}

func (s *postgresStore) UpsertLimit(ctx context.Context, tenantID string, l Limit) error {
	if l.Limit <= 0 {
		_, err := s.db.ExecContext(ctx,
			`DELETE FROM usage_limits WHERE tenant_id = $1 AND metric = $2 AND period = $3`,
			tenantID, l.Metric, l.Period)
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO usage_limits (tenant_id, metric, period, limit_value, updated_at)
		 VALUES ($1, $2, $3, $4, now())
		 ON CONFLICT (tenant_id, metric, period)
		 DO UPDATE SET limit_value = EXCLUDED.limit_value, updated_at = now()`,
		tenantID, l.Metric, l.Period, l.Limit)
	return err
}

func (s *postgresStore) Limits(ctx context.Context, tenantID string) ([]Limit, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT metric, period, limit_value FROM usage_limits WHERE tenant_id = $1 ORDER BY metric, period`,
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Limit{}
	for rows.Next() {
		var l Limit
		if err := rows.Scan(&l.Metric, &l.Period, &l.Limit); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

var _ Store = (*postgresStore)(nil)

func monthKeyUTC() string { return MonthKey(time.Now()) }
