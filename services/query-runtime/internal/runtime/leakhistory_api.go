package runtime

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// Leak-history surface for the V1 console: scheduled leak-report
// snapshots (history) and the drift between two runs (diff). As with
// the live leak-report endpoint, the implementation lives in a leaf
// package (internal/leakreport — which imports aclsync, which imports
// runtime, so runtime cannot import it directly). cmd/query-runtime
// wires the implementation via SetLeakHistoryService.

// LeakHistoryService is the read-side snapshot/diff surface.
type LeakHistoryService interface {
	// List returns up to limit snapshots, newest first.
	List(ctx context.Context, tenantID string, limit int) ([]LeakHistoryEntry, error)
	// Diff returns the drift between two stored runs. Zero ids select
	// the two most recent runs; with fewer than two runs it returns
	// ErrLeakHistoryInsufficient.
	Diff(ctx context.Context, tenantID string, fromID, toID int64) (LeakDriftResult, error)
}

// LeakHistoryEntry is one stored scheduled run.
type LeakHistoryEntry struct {
	ID            int64         `json:"id"`
	TenantID      string        `json:"tenant_id"`
	RanAt         time.Time     `json:"ran_at"`
	DocumentCount int           `json:"document_count"`
	GroupCount    int           `json:"group_count"`
	Findings      []LeakFinding `json:"findings"`
}

// LeakDriftResult is the exposure delta between two runs.
type LeakDriftResult struct {
	TenantID         string        `json:"tenant_id"`
	PreviousID       int64         `json:"previous_id"`
	CurrentID        int64         `json:"current_id"`
	PreviousRanAt    time.Time     `json:"previous_ran_at"`
	CurrentRanAt     time.Time     `json:"current_ran_at"`
	NewFindings      []LeakFinding `json:"new_findings"`
	ResolvedFindings []LeakFinding `json:"resolved_findings"`
}

// ErrLeakHistoryInsufficient is returned when fewer than two snapshots
// exist for the tenant, so no drift can be computed.
var ErrLeakHistoryInsufficient = errors.New("leak-report history: insufficient snapshots")

// SetLeakHistoryService wires the snapshot/diff service. Nil-safe: when
// unset, the history/diff endpoints return 503 leak_history_unavailable.
func (s *Server) SetLeakHistoryService(svc LeakHistoryService) { s.leakHistorySvc = svc }

// leakReportHistory handles GET /v1/leak-report/history. Read-only;
// requires the "audit" scope (admin inherits). Tenant comes only from
// the API-key context.
func (s *Server) leakReportHistory(w http.ResponseWriter, r *http.Request) {
	if s.leakHistorySvc == nil {
		writeAuditError(w, http.StatusServiceUnavailable, "leak_history_unavailable")
		return
	}
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeAuditError(w, http.StatusUnauthorized, "missing_tenant_context")
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	entries, err := s.leakHistorySvc.List(ctx, tenant.TenantID, limit)
	if err != nil {
		writeAuditError(w, http.StatusInternalServerError, "leak_history_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": entries})
}

// leakReportDiff handles GET /v1/leak-report/diff. Read-only; requires
// the "audit" scope. Optional from/to select the compared runs;
// omitted, the two most recent runs are compared.
func (s *Server) leakReportDiff(w http.ResponseWriter, r *http.Request) {
	if s.leakHistorySvc == nil {
		writeAuditError(w, http.StatusServiceUnavailable, "leak_history_unavailable")
		return
	}
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeAuditError(w, http.StatusUnauthorized, "missing_tenant_context")
		return
	}
	var fromID, toID int64
	if raw := r.URL.Query().Get("from"); raw != "" {
		fromID, _ = strconv.ParseInt(raw, 10, 64)
	}
	if raw := r.URL.Query().Get("to"); raw != "" {
		toID, _ = strconv.ParseInt(raw, 10, 64)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	res, err := s.leakHistorySvc.Diff(ctx, tenant.TenantID, fromID, toID)
	if err != nil {
		if errors.Is(err, ErrLeakHistoryInsufficient) {
			writeAuditError(w, http.StatusConflict, "insufficient_history")
			return
		}
		writeAuditError(w, http.StatusInternalServerError, "leak_history_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"drift": res})
}
