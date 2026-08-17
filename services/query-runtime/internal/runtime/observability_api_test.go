// Phase 8.5 observability HTTP surface tests: correlation-id round-trip
// + engine trace stamping, and the support bundle endpoint (nil-safe
// 503, scope + verified-identity gating, zip contents with status).

package runtime_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"groundwork/query-runtime/internal/runtime"
)

// ---------------------------------------------------------------------
// Correlation IDs
// ---------------------------------------------------------------------

func queryBody() string { return `{"user_id":"user_1","question":"test"}` }

func TestCorrelationRoundTripAndTraceStamping(t *testing.T) {
	h := newGovAPIHarness(t)
	req := govRequest(http.MethodPost, "/v1/query", govAdminKey, tokenFor(t, govOwner), "", queryBody())
	req.Header.Set(runtime.CorrelationIDHeader, "corr-test-123")
	rec := httptest.NewRecorder()
	h.s.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(runtime.CorrelationIDHeader); got != "corr-test-123" {
		t.Fatalf("echoed correlation id = %q, want corr-test-123", got)
	}
	if got := h.ex.last().TraceID; got != "corr-test-123" {
		t.Fatalf("executor trace id = %q, want corr-test-123", got)
	}
}

func TestCorrelationGeneratedWhenAbsent(t *testing.T) {
	h := newGovAPIHarness(t)
	req := govRequest(http.MethodPost, "/v1/query", govAdminKey, tokenFor(t, govOwner), "", queryBody())
	rec := httptest.NewRecorder()
	h.s.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	echoed := rec.Header().Get(runtime.CorrelationIDHeader)
	if echoed == "" {
		t.Fatal("a correlation id must be generated and echoed")
	}
	if got := h.ex.last().TraceID; got != echoed {
		t.Fatalf("executor trace id = %q, want echoed id %q", got, echoed)
	}
}

func TestCorrelationGenericHeaderFallback(t *testing.T) {
	h := newGovAPIHarness(t)
	req := govRequest(http.MethodPost, "/v1/query", govAdminKey, tokenFor(t, govOwner), "", queryBody())
	req.Header.Set("X-Correlation-Id", "gen-abc")
	rec := httptest.NewRecorder()
	h.s.Routes().ServeHTTP(rec, req)

	if got := rec.Header().Get(runtime.CorrelationIDHeader); got != "gen-abc" {
		t.Fatalf("generic X-Correlation-Id must be honored: got %q, want gen-abc", got)
	}
	if got := h.ex.last().TraceID; got != "gen-abc" {
		t.Fatalf("executor trace id = %q, want gen-abc", got)
	}
}

// ---------------------------------------------------------------------
// Support bundle
// ---------------------------------------------------------------------

type fakeBundleSource struct {
	sections []runtime.SupportBundleSection
	err      error
}

func (f *fakeBundleSource) Sections(context.Context, string) ([]runtime.SupportBundleSection, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.sections, nil
}

func newBundleServer(t *testing.T, src runtime.SupportBundleSource) *runtime.Server {
	t.Helper()
	s := newGovServer(t, nil, runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "bundle-test", Scopes: []string{"admin", "query"},
	}, false, &recordingExecutor{})
	if src != nil {
		s.SetSupportBundleSource(src)
	}
	return s
}

func TestSupportBundleUnavailableWhenUnwired(t *testing.T) {
	s := newBundleServer(t, nil)
	rec := doGov(t, s, http.MethodGet, "/v1/security/support-bundle", govAdminKey, adminTokenFor(t, govOwner), "", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := govErrorOf(t, rec); got != "support_bundle_unavailable" {
		t.Fatalf("error = %q, want support_bundle_unavailable", got)
	}
}

func TestSupportBundleRequiresVerifiedIdentity(t *testing.T) {
	s := newBundleServer(t, &fakeBundleSource{})
	rec := doGov(t, s, http.MethodGet, "/v1/security/support-bundle", govAdminKey, "", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without an assertion, got %d", rec.Code)
	}
}

func TestSupportBundleScopeGated(t *testing.T) {
	// A query-only key cannot download a support bundle.
	s := newGovServer(t, nil, runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "query-only", Scopes: []string{"query"},
	}, false, &recordingExecutor{})
	s.SetSupportBundleSource(&fakeBundleSource{})
	rec := doGov(t, s, http.MethodGet, "/v1/security/support-bundle", govAdminKey, adminTokenFor(t, govOwner), "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSupportBundleStreamsZip(t *testing.T) {
	s := newBundleServer(t, &fakeBundleSource{sections: []runtime.SupportBundleSection{
		{Name: "keys", Data: map[string]string{"webhook": "2027-01-01T00:00:00Z"}},
		{Name: "outbox", Data: []runtime.OutboxTenantStats{{TenantID: govTenant, DeadLetterCount: 1}}},
	}})
	s.AddReadinessProbe(runtime.ReadinessProbe{Name: "postgres", Check: func(context.Context) error { return nil }})

	rec := doGov(t, s, http.MethodGet, "/v1/security/support-bundle", govAdminKey, adminTokenFor(t, govOwner), "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("content type = %q, want application/zip", ct)
	}

	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("read zip: %v", err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		files[f.Name] = body
	}
	for _, want := range []string{"manifest.json", "status.json", "keys.json", "outbox.json"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("zip missing %s (have %v)", want, len(files))
		}
	}

	var manifest struct {
		TenantID string   `json:"tenant_id"`
		Sections []string `json:"sections"`
	}
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if manifest.TenantID != govTenant {
		t.Fatalf("manifest tenant = %q, want %q", manifest.TenantID, govTenant)
	}
	if len(manifest.Sections) != 3 || manifest.Sections[0] != "status" {
		t.Fatalf("manifest sections = %v, want [status keys outbox]", manifest.Sections)
	}

	var status map[string]any
	if err := json.Unmarshal(files["status.json"], &status); err != nil {
		t.Fatalf("status: %v", err)
	}
	if status["tenant_id"] != govTenant {
		t.Fatalf("status tenant = %v, want %v", status["tenant_id"], govTenant)
	}
	probes, ok := status["probes"].(map[string]any)
	if !ok || probes["postgres"] != "ok" {
		t.Fatalf("status probes = %v, want postgres=ok", status["probes"])
	}

	var keys map[string]string
	if err := json.Unmarshal(files["keys.json"], &keys); err != nil {
		t.Fatalf("keys: %v", err)
	}
	if keys["webhook"] != "2027-01-01T00:00:00Z" {
		t.Fatalf("keys = %v", keys)
	}
}

func TestSupportBundleFailsWhenSourceErrors(t *testing.T) {
	s := newBundleServer(t, &fakeBundleSource{err: context.DeadlineExceeded})
	rec := doGov(t, s, http.MethodGet, "/v1/security/support-bundle", govAdminKey, adminTokenFor(t, govOwner), "", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := govErrorOf(t, rec); got != "support_bundle_failed" {
		t.Fatalf("error = %q, want support_bundle_failed", got)
	}
}
