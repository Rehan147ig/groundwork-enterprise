package runtime_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"groundwork/query-runtime/internal/exports"
	"groundwork/query-runtime/internal/runtime"
	"groundwork/query-runtime/internal/usage"
)

// ---------------------------------------------------------------------
// Phase 4e: framework evidence exports
// ---------------------------------------------------------------------

func TestGovernanceExportHTTP(t *testing.T) {
	h := newGovAPIHarness(t)
	govSetup(t, h.s, false)
	minted := govMint(t, h.s, "mint-export", `{"agent_id":"agent-1","subject_principal_id":"principal:bob","purpose":"review","permitted_actions":["groundwork_search:search"]}`)
	var mintResp runtime.GovernanceDelegationResponse
	decodeGov(t, minted, &mintResp)
	govCreateRun(t, h.s, mintResp.Token, "run-export")

	// Sanity: the read model must contain evidence before the export.
	rec := doGov(t, h.s, http.MethodGet, "/v1/governance/evidence", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("evidence list: %d %s", rec.Code, rec.Body.String())
	}
	var evPage runtime.EvidencePage
	decodeGov(t, rec, &evPage)
	if evPage.Count == 0 {
		t.Fatal("expected evidence events before export")
	}

	// An EU AI Act export must carry framework/region/tenant identity,
	// control reports, and a chain-verification result. Region comes
	// from the trusted API-key context (govRegion).
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/exports/eu_ai_act", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d %s", rec.Code, rec.Body.String())
	}
	var report exports.Export
	decodeGov(t, rec, &report)
	if report.FrameworkID != "eu_ai_act" || report.TenantID != govTenant || report.Region != govRegion {
		t.Errorf("export header: %+v", report)
	}
	if len(report.Controls) == 0 {
		t.Fatal("export must carry control reports")
	}
	if report.Chain.Checked == 0 {
		t.Errorf("chain verification must have checked events: %+v", report.Chain)
	}
	byID := map[string]exports.ControlReport{}
	for _, c := range report.Controls {
		byID[c.ControlID] = c
	}
	art9 := byID["art_9_risk_management"]
	if len(art9.Evidence) == 0 {
		t.Fatalf("decision evidence must substantiate art_9: %+v", art9)
	}
	if art9.Status != exports.StatusSatisfied && art9.Status != exports.StatusPartiallyMet && art9.Status != exports.StatusChainUnverified {
		t.Errorf("art_9 status not derived from evidence: %q", art9.Status)
	}
	for _, ev := range art9.Evidence {
		if ev.ImmutableDigest == "" || ev.EventID == "" {
			t.Errorf("evidence ref must carry digest + id: %+v", ev)
		}
	}
	if len(report.Limitations) == 0 {
		t.Error("export must carry limitations")
	}
}

func TestGovernanceExportWindowFilter(t *testing.T) {
	h := newGovAPIHarness(t)
	govSetup(t, h.s, false)

	from := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	to := time.Now().UTC().Format(time.RFC3339)
	rec := doGov(t, h.s, http.MethodGet,
		"/v1/governance/exports/gdpr?from="+from+"&to="+to, govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export with window: %d %s", rec.Code, rec.Body.String())
	}
	fromTime, _ := time.Parse(time.RFC3339, from)
	toTime, _ := time.Parse(time.RFC3339, to)
	var report exports.Export
	decodeGov(t, rec, &report)
	if !report.WindowFrom.Equal(fromTime) || !report.WindowTo.Equal(toTime) {
		t.Errorf("window not echoed: got %s..%s want %s..%s", report.WindowFrom, report.WindowTo, fromTime, toTime)
	}

	// Inverted window must fail, not default.
	rec = doGov(t, h.s, http.MethodGet,
		"/v1/governance/exports/gdpr?from="+to+"&to="+from, govAdminKey, "", "", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("inverted window: expected 400, got %d", rec.Code)
	}
	if got := govErrorOf(t, rec); got != "invalid_window" {
		t.Errorf("error = %q, want invalid_window", got)
	}
}

func TestGovernanceExportUnknownFramework(t *testing.T) {
	h := newGovAPIHarness(t)
	rec := doGov(t, h.s, http.MethodGet, "/v1/governance/exports/bogus", govAdminKey, "", "", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown framework: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := govErrorOf(t, rec); got != "unknown_framework" {
		t.Errorf("error = %q, want unknown_framework", got)
	}
}

func TestGovernanceExportRequiresGovernanceScope(t *testing.T) {
	// A key without the governance scope must be refused (fail closed).
	queryOnly := newGovServer(t, nil, runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "query-only", Scopes: []string{"query"},
	}, false, nil)
	rec := doGov(t, queryOnly, http.MethodGet, "/v1/governance/exports/eu_ai_act", govAdminKey, "", "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("query-only key: expected 403, got %d", rec.Code)
	}
}

func TestGovernanceExportStorageQuotaDenied(t *testing.T) {
	h := newGovAPIHarness(t)
	govSetup(t, h.s, false)

	// storage_bytes quota of 10 bytes: every real export payload is far
	// larger, so the export must be denied BEFORE any bytes stream.
	ctx := context.Background()
	mem := usage.NewMemoryStore()
	meter := usage.NewService(mem)
	if _, err := meter.UpsertLimits(ctx, govTenant, []usage.Limit{{Metric: usage.MetricStorageBytes, Period: usage.PeriodMonthly, Limit: 10}}); err != nil {
		t.Fatalf("set storage quota: %v", err)
	}
	h.s.SetUsageMeter(meter)

	rec := doGov(t, h.s, http.MethodGet, "/v1/governance/exports/eu_ai_act", govAdminKey, "", "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("over storage quota: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := govErrorOf(t, rec); got != "quota_exceeded:storage_bytes" {
		t.Fatalf("expected quota_exceeded:storage_bytes, got %q", got)
	}

	// Clearing the limit (Limit <= 0 deletes the row) restores exports.
	if _, err := meter.UpsertLimits(ctx, govTenant, []usage.Limit{{Metric: usage.MetricStorageBytes, Period: usage.PeriodMonthly, Limit: 0}}); err != nil {
		t.Fatalf("clear storage quota: %v", err)
	}
	rec = doGov(t, h.s, http.MethodGet, "/v1/governance/exports/eu_ai_act", govAdminKey, "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("quota cleared: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
