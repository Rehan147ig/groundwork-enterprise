package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"groundwork/query-runtime/internal/usage"
)

// Usage Metering & Tenant Limits (Phase 8.1).
//
// Endpoints:
//
//	GET /v1/usage          tenant-scoped usage snapshot (monthly + lifetime
//	                       counts for every metered metric, paired with
//	                       applicable limits)
//	GET /v1/usage/limits   tenant quota rows
//	PUT /v1/usage/limits   upsert quota rows (verified identity +
//	                       Idempotency-Key; admin semantics; Limit <= 0
//	                       clears the row)
//
// Metering is recorded at the runtime layer — never by clients: agent
// creation, query executions, governed runs/decisions, connector
// invocations, exports, and outbox deliveries all flow through the
// UsageService wired via SetUsageMeter. Enforcement is fail-closed:
// a limited metric that would exceed its quota denies the operation
// with 403 quota_exceeded:<metric> and the counter is NOT incremented.
// Without a limit row every metric is unlimited and metering is a
// no-op for enforcement.
//
// usageScope is the API-key scope required for the usage endpoints
// (hasScope's existing "admin" override grants access too, so bootstrap
// and admin keys work unchanged).
const usageScope = "usage"

// UsageService is the metering surface the runtime calls. Implemented
// by internal/usage.Service and wired via SetUsageMeter from
// cmd/query-runtime. Nil-safe: when unset, usage endpoints return 503
// usage_unavailable and metering calls are no-ops.
type UsageService interface {
	Record(ctx context.Context, tenantID, metric string, delta int64) error
	Usage(ctx context.Context, tenantID string) ([]usage.MetricUsage, error)
	Limits(ctx context.Context, tenantID string) ([]usage.Limit, error)
	UpsertLimits(ctx context.Context, tenantID string, limits []usage.Limit) ([]usage.Limit, error)
}

// usageMeter is the Server's optional meter. Nil-safe.
func (s *Server) usageMeter() UsageService { return s.meter }

// SetUsageMeter wires the usage metering service. When set, the
// /v1/usage endpoints are served and the enforcement points in
// agents/query/governance/exports record usage. When nil (the default
// for existing tests), recording is a no-op and /v1/usage returns 503
// usage_unavailable.
func (s *Server) SetUsageMeter(meter UsageService) { s.meter = meter }

var ErrUsageUnavailable = errors.New("usage_unavailable")

// recordUsage meters one unit with fail-closed enforcement: it writes
// the quota_exceeded:<metric> response when the metric is over its
// limit. Returns false when a response was already written.
func (s *Server) recordUsage(w http.ResponseWriter, tenantID, metric string, delta int64) bool {
	if s.meter == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.meter.Record(ctx, tenantID, metric, delta); err != nil {
		var qe *usage.QuotaError
		if errors.As(err, &qe) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "quota_exceeded:" + qe.Metric})
			return false
		}
		// Metering failures never break the operation; they are logged.
		log.Printf("usage: record %s for %s: %v", metric, tenantID, err)
	}
	return true
}

// recordUsageBestEffort meters without enforcement. Only the dispatch
// response volume uses this today (storage_bytes at dispatch): the
// volume is unknowable before the outbound connector call, so it
// cannot be denied fail-closed there — the storage quota IS enforced
// at export time, where the payload is fully materialized first. A
// recording failure is logged and the operation proceeds.
func (s *Server) recordUsageBestEffort(tenantID, metric string, delta int64) {
	if s.meter == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.meter.Record(ctx, tenantID, metric, delta); err != nil {
		log.Printf("usage: best-effort %s for %s: %v", metric, tenantID, err)
	}
}

func (s *Server) getUsage(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	if s.meter == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrUsageUnavailable.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	usageRows, err := s.meter.Usage(ctx, tenant.TenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "usage_query_failed"})
		return
	}
	writeJSON(w, http.StatusOK, usage.UsageSnapshot{TenantID: tenant.TenantID, Period: usage.PeriodMonthly, Usage: usageRows})
}

func (s *Server) getUsageLimits(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	if s.meter == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrUsageUnavailable.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	limits, err := s.meter.Limits(ctx, tenant.TenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "usage_limits_query_failed"})
		return
	}
	writeJSON(w, http.StatusOK, usage.LimitsSnapshot{TenantID: tenant.TenantID, Limits: limits})
}

// putUsageLimits upserts quota rows. Admin semantics: the operation
// requires a verified identity and an Idempotency-Key header (Phase 6
// mutation convention). A Limit <= 0 clears the row (unlimited).
func (s *Server) putUsageLimits(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	if _, ok := s.requireIdempotency(w, r); !ok {
		return
	}
	if s.meter == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrUsageUnavailable.Error()})
		return
	}
	var req usage.LimitsSnapshot
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	limits, err := s.meter.UpsertLimits(ctx, tenant.TenantID, req.Limits)
	if err != nil {
		msg := strings.TrimSpace(err.Error())
		if strings.HasPrefix(msg, "invalid limit") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "usage_limits_upsert_failed"})
		return
	}
	writeJSON(w, http.StatusOK, usage.LimitsSnapshot{TenantID: tenant.TenantID, Limits: limits})
}
