// Support Bundle (Phase 8.5): a tenant-scoped diagnostics archive
// streamed as a zip (manifest.json + one JSON file per section) for
// operator escalation. Requires the "admin" scope AND a verified
// operator identity — same bar as break-glass Open/Revoke. The source
// (wired from cmd/query-runtime) MUST NEVER include secrets, key
// material, tokens, assertions, or document text: expiries, health,
// and counts only.
//
//	GET /v1/security/support-bundle → application/zip
//
// The server prepends a "status" section from its own readiness probes
// and API-key resolver so the archive is self-contained even before any
// external source is wired. The source is Nil-safe: when unset the
// endpoint returns 503 support_bundle_unavailable.

package runtime

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SupportBundleSection is one named JSON document inside the support
// bundle archive. Name becomes "<name>.json" in the zip; Data must be
// JSON-serializable and free of secrets.
type SupportBundleSection struct {
	Name string
	Data any
}

// SupportBundleSource assembles a tenant's support bundle sections.
// Implementations MUST NOT include secrets or key material — expiries
// and health only.
type SupportBundleSource interface {
	Sections(ctx context.Context, tenantID string) ([]SupportBundleSection, error)
}

const supportBundleScope = "admin"

// SetSupportBundleSource wires the Phase 8.5 support bundle source.
// When nil (the default for existing tests), /v1/security/support-bundle
// returns 503 support_bundle_unavailable.
func (s *Server) SetSupportBundleSource(src SupportBundleSource) { s.supportBundle = src }

func (s *Server) serveSupportBundle(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	decision, ok := identityFromContext(r.Context())
	if !ok || !decision.identity.Verified || decision.identity.UserID == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "verified_identity_required"})
		return
	}
	if s.supportBundle == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "support_bundle_unavailable"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	sections, err := s.supportBundle.Sections(ctx, tenant.TenantID)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "support_bundle_failed"})
		return
	}

	// Self-contained status section: readiness probes + API-key wiring.
	status := map[string]any{
		"service":      "groundwork-query-runtime",
		"tenant_id":    tenant.TenantID,
		"region":       tenant.Region,
		"generated_at": time.Now().UTC(),
		"api_keys":     s.apiKeys != nil,
		"probes":       map[string]string{},
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, 2*time.Second)
	defer probeCancel()
	for _, p := range s.readinessProbes {
		healthy := "ok"
		if err := p.Check(probeCtx); err != nil {
			healthy = "unhealthy"
		}
		status["probes"].(map[string]string)[p.Name] = healthy
	}
	sections = append([]SupportBundleSection{{Name: "status", Data: status}}, sections...)

	ts := time.Now().UTC().Format("20060102T150405Z")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="groundwork-support-%s-%s.zip"`, tenant.TenantID, ts))
	zw := zip.NewWriter(w)
	defer zw.Close()

	writeSection := func(name string, data any) error {
		f, err := zw.Create(name + ".json")
		if err != nil {
			return err
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(data)
	}
	names := make([]string, 0, len(sections))
	for _, sec := range sections {
		names = append(names, sec.Name)
	}
	if err := writeSection("manifest", map[string]any{
		"generated_at": time.Now().UTC(),
		"tenant_id":    tenant.TenantID,
		"service":      "groundwork-query-runtime",
		"sections":     names,
	}); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "support_bundle_failed"})
		return
	}
	for _, sec := range sections {
		if err := writeSection(sec.Name, sec.Data); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "support_bundle_failed"})
			return
		}
	}
}
