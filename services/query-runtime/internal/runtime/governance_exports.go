package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"groundwork/query-runtime/internal/exports"
	"groundwork/query-runtime/internal/usage"
)

// governanceExportSource adapts the runtime GovernanceService to the
// exports.Source contract. Evidence is read from the tenant-scoped read
// model (governance scope) with the exact same filtering used by
// /v1/governance/evidence; chain verification reuses the tamper-evident
// audit chain verification (read-only, never repairs).
type governanceExportSource struct {
	gov GovernanceService
}

// Evidence implements exports.Source: full-window paginated read.
func (g governanceExportSource) Evidence(ctx context.Context, tenantID string, from, to time.Time) ([]exports.EvidenceRef, error) {
	cursor := ""
	var refs []exports.EvidenceRef
	// RFC3339Nano preserves sub-second precision: the store's [from, to)
	// window is exclusive on `to`, and truncating to whole seconds would
	// drop evidence created in the same second as the window end.
	fromParam := from.UTC().Format(time.RFC3339Nano)
	toParam := to.UTC().Format(time.RFC3339Nano)
	for {
		page, err := g.gov.QueryEvidence(ctx, tenantID, EvidenceFilter{
			From:   fromParam,
			To:     toParam,
			Limit:  200,
			Cursor: cursor,
		})
		if err != nil {
			return nil, err
		}
		for _, ev := range page.Events {
			refs = append(refs, exports.EvidenceRef{
				EventID:         ev.EventID,
				Kind:            ev.Kind,
				OccurredAt:      ev.OccurredAt,
				Decision:        ev.Decision,
				ReasonCode:      ev.ReasonCode,
				Region:          ev.Region,
				Jurisdiction:    ev.Jurisdiction,
				ImmutableDigest: ev.ImmutableDigest,
			})
		}
		if page.NextCursor == "" || len(page.Events) == 0 {
			break
		}
		cursor = page.NextCursor
	}
	return refs, nil
}

// VerifyChain implements exports.Source.
func (g governanceExportSource) VerifyChain(ctx context.Context, tenantID string) (exports.ChainResult, error) {
	result, err := g.gov.VerifyAuditChain(ctx, tenantID, "", false)
	if err != nil {
		return exports.ChainResult{}, err
	}
	problems := 0
	detail := ""
	if !result.Verified {
		problems = 1
		detail = "first broken: " + result.FirstBrokenKind + " " + result.FirstBrokenID + " at " + result.FirstBrokenAt.UTC().Format(time.RFC3339)
	}
	return exports.ChainResult{
		Checked:  result.EventsChecked,
		Problems: problems,
		Verified: result.Verified,
		Detail:   detail,
	}, nil
}

// getGovernanceExport serves GET /v1/governance/exports/{framework}:
// a tenant-scoped framework evidence report (governance scope, read-only).
// The region/jurisdiction come from the trusted API-key tenant context —
// never from the request.
func (s *Server) getGovernanceExport(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	frameworkID := strings.TrimSpace(r.PathValue("framework"))
	if exports.Lookup(frameworkID) == nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("unknown_framework"))
		return
	}

	// Window defaults to the trailing 90 days; explicit from/to must be
	// RFC3339 and from < to (malformed values fail, never default).
	now := time.Now().UTC()
	from := now.Add(-90 * 24 * time.Hour)
	to := now
	q := r.URL.Query()
	if f := strings.TrimSpace(q.Get("from")); f != "" {
		parsed, err := time.Parse(time.RFC3339, f)
		if err != nil {
			writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_from"))
			return
		}
		from = parsed.UTC()
	}
	if t := strings.TrimSpace(q.Get("to")); t != "" {
		parsed, err := time.Parse(time.RFC3339, t)
		if err != nil {
			writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_to"))
			return
		}
		to = parsed.UTC()
	}
	if !to.After(from) {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_window"))
		return
	}

	// Owner: the verified actor principal when one is presented (the
	// export itself is read-only and does not require identity).
	owner := ""
	if decision, ok := identityFromContext(r.Context()); ok && decision.identity.Verified {
		if effective, _, err := CanonicalizeIdentity(r.Context(), s.resolver, s.canonicalIdentity, tenant.TenantID, decision.identity); err == nil {
			owner = effective
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	// Phase 8.1: exports are metered (fail closed — quota_exceeded:exports).
	if !s.recordUsage(w, tenant.TenantID, usage.MetricExports, 1) {
		return
	}
	svc := exports.NewService(governanceExportSource{gov: s.governance})
	report, err := svc.Export(ctx, frameworkID, tenant.TenantID, tenant.Region, tenant.Jurisdiction, owner, from, to)
	if err != nil {
		writeGovernanceServiceError(w, err, "export_failed")
		return
	}
	// Phase 8.1: storage_bytes is enforced fail-closed at export time.
	// The payload is fully materialized BEFORE anything is streamed, so
	// an over-quota tenant receives 403 quota_exceeded:storage_bytes
	// and no bytes leave the service.
	payload, err := json.Marshal(report)
	if err != nil {
		writeGovernanceError(w, http.StatusInternalServerError, errors.New("export_marshal_failed"))
		return
	}
	if !s.recordUsage(w, tenant.TenantID, usage.MetricStorageBytes, int64(len(payload))) {
		return
	}
	writeJSON(w, http.StatusOK, report)
}
