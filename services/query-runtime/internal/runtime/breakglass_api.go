package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Break-Glass Operator Access (Phase 8.4).
//
// Endpoints (all require the "break_glass" scope — the legacy "admin"
// scope inherits via hasScope; Open/Revoke additionally require a
// verified operator identity):
//
//	POST /v1/security/break-glass/grants      open a time-bounded grant,
//	                                           minting a short-lived
//	                                           admin-scoped API key
//	                                           (reason mandatory, duration
//	                                           capped by service config)
//	GET  /v1/security/break-glass/grants      list the tenant's grants
//	GET  /v1/security/break-glass/grants/{id} one grant + its
//	                                           hash-chained event log
//	POST /v1/security/break-glass/grants/{id}/revoke
//	                                           early revocation with
//	                                           mandatory reason
//
// Every lifecycle transition appends write-once, hash-chained evidence;
// expired/revoked grants fail closed at the API-key auth layer on the
// next request. The service is Nil-safe: when unset (no durable store
// wired in cmd/query-runtime), every endpoint returns 503
// break_glass_unavailable.
const breakGlassScope = "break_glass"

// SetBreakGlassService wires the Phase 8.4 break-glass service. When
// set, /v1/security/break-glass* endpoints are served. When nil (the
// default for existing tests), those endpoints return 503
// break_glass_unavailable.
func (s *Server) SetBreakGlassService(svc BreakGlassService) { s.breakGlass = svc }

func (s *Server) openBreakGlassGrant(w http.ResponseWriter, r *http.Request) {
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
	if s.breakGlass == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
		return
	}
	var req OpenBreakGlassRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.Reason == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reason_required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grant, mintedKey, err := s.breakGlass.Open(ctx, tenant, decision.identity.UserID, req)
	if err != nil {
		if errors.Is(err, ErrBreakGlassUnavailable) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "break_glass_open_failed"})
		return
	}
	// The minted admin key is returned exactly once, in the Open
	// response. It is never persisted, so losing it means opening a
	// new grant.
	writeJSON(w, http.StatusCreated, map[string]any{"grant": grant, "key": mintedKey})
}

func (s *Server) listBreakGlassGrants(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	if s.breakGlass == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grants, err := s.breakGlass.List(ctx, tenant.TenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "break_glass_list_failed"})
		return
	}
	if grants == nil {
		grants = []BreakGlassGrant{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": grants})
}

func (s *Server) getBreakGlassGrant(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	grantID := r.PathValue("id")
	if grantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "grant_id_required"})
		return
	}
	if s.breakGlass == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grant, events, err := s.breakGlass.Get(ctx, tenant.TenantID, grantID)
	if err != nil {
		if errors.Is(err, ErrBreakGlassNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "break_glass_grant_not_found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "break_glass_get_failed"})
		return
	}
	if events == nil {
		events = []BreakGlassEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"grant": grant, "events": events})
}

func (s *Server) revokeBreakGlassGrant(w http.ResponseWriter, r *http.Request) {
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
	grantID := r.PathValue("id")
	if grantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "grant_id_required"})
		return
	}
	if s.breakGlass == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
		return
	}
	var req RevokeBreakGlassRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.Reason == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reason_required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grant, err := s.breakGlass.Revoke(ctx, tenant, grantID, decision.identity.UserID, req)
	if err != nil {
		if errors.Is(err, ErrBreakGlassUnavailable) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
			return
		}
		if errors.Is(err, ErrBreakGlassNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "break_glass_grant_not_found"})
			return
		}
		if errors.Is(err, ErrBreakGlassNotActive) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "break_glass_grant_not_active"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "break_glass_revoke_failed"})
		return
	}
	writeJSON(w, http.StatusOK, grant)
}
