package runtime

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"groundwork/query-runtime/internal/aclsync"
)

// Connector status surface (Milestone 3, requirement 9: console status).
//
//	GET /v1/connectors/status
//
// Requires an API key with the "query" scope; tenant comes from the
// verified API key, never the body. Returns the tenant's connector
// installations with their health surface (status, last success, lag,
// drift, credential expiry, delta cursor presence). The response NEVER
// includes credential material — only the reference's scheme
// (keyring:// vs other) for auditability.
//
// The store is Nil-safe: when no InstallationStore is wired, the
// endpoint returns 503 connector_status_unavailable.

const connectorStatusScope = "query"

// SetConnectorStatusStore wires the connector installation store used by
// /v1/connectors/status. When nil, the endpoint returns 503.
func (s *Server) SetConnectorStatusStore(store aclsync.InstallationStore) {
	s.connectorStatusStore = store
}

// connectorStatusView is the JSON view of one installation. It mirrors
// the registry record minus anything that could carry secrets.
type connectorStatusView struct {
	TenantID          string `json:"tenant_id"`
	Provider          string `json:"provider"`
	Status            string `json:"status"`
	CredentialScheme  string `json:"credential_scheme"`               // "keyring" | "secrets_manager" | "unknown"
	CredentialExpires string `json:"credential_expires_at,omitempty"` // RFC3339; omitted = none
	DeltaCursor       bool   `json:"delta_cursor_present"`
	LastSuccessAgeSec int64  `json:"last_success_age_seconds"` // -1 = never succeeded
	SyncLagSeconds    int64  `json:"sync_lag_seconds"`
	DriftItems        int    `json:"drift_items"`
	LastError         string `json:"last_error,omitempty"`
	Region            string `json:"region,omitempty"`
}

func (s *Server) connectorStatusHandler(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	if s.connectorStatusStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "connector_status_unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	insts, err := s.connectorStatusStore.List(ctx, "")
	if err != nil {
		slog.Error("connector_status_list_failed", "tenant", tenant.TenantID, "err", err.Error())
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "connector_status_unavailable"})
		return
	}
	now := time.Now().UTC()
	out := make([]connectorStatusView, 0, len(insts))
	for _, inst := range insts {
		if inst.TenantID != tenant.TenantID {
			continue // tenant isolation: never leak another tenant's installations
		}
		age := int64(-1)
		if !inst.LastSuccessAt.IsZero() {
			age = int64(now.Sub(inst.LastSuccessAt).Seconds())
		}
		v := connectorStatusView{
			TenantID:          inst.TenantID,
			Provider:          inst.Provider,
			Status:            string(inst.Status),
			CredentialScheme:  credentialScheme(inst.CredentialRef),
			DeltaCursor:       inst.DeltaCursor != "",
			LastSuccessAgeSec: age,
			SyncLagSeconds:    inst.SyncLagSeconds,
			DriftItems:        inst.DriftItems,
			LastError:         inst.LastError,
			Region:            inst.Region,
		}
		if !inst.CredentialTTL.IsZero() {
			v.CredentialExpires = inst.CredentialTTL.UTC().Format(time.RFC3339)
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"installations": out})
}

// credentialScheme reports the reference's scheme without exposing the
// reference itself (which may embed tenant ids — still not secret, but
// keeping the surface minimal).
func credentialScheme(ref string) string {
	switch {
	case ref == "":
		return "unknown"
	case len(ref) >= 10 && ref[:10] == "keyring://":
		return "keyring"
	case len(ref) >= 16 && ref[:16] == "secretsmanager://":
		return "secrets_manager"
	case len(ref) >= 4 && ref[:4] == "aws:":
		return "secrets_manager"
	case len(ref) >= 4 && ref[:4] == "gcp:":
		return "secrets_manager"
	case len(ref) >= 6 && ref[:6] == "vault:":
		return "secrets_manager"
	default:
		return "unknown"
	}
}
