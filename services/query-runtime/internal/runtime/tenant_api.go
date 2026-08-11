package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Tenant Provisioning (Phase 8.1 Multi-tenancy and isolation).
//
// Endpoints (all require the "provision" scope — admin inherits; all
// mutations additionally require a verified operator identity):
//
//	POST /v1/admin/tenants                        provision (or
//	                                                 re-provision) a
//	                                                 tenant; optionally
//	                                                 mints its initial
//	                                                 admin key
//	GET  /v1/admin/tenants                        list the directory
//	GET  /v1/admin/tenants/{tenant_id}            one tenant entry
//	GET  /v1/admin/tenants/{tenant_id}/events     the tenant's
//	                                                 hash-chained
//	                                                 lifecycle evidence
//	POST /v1/admin/tenants/{tenant_id}/disable    suspend (reason
//	                                                 mandatory)
//	POST /v1/admin/tenants/{tenant_id}/enable     reactivate (reason
//	                                                 mandatory)
//	POST /v1/admin/tenants/{tenant_id}/deprovision
//	                                                 terminal,
//	                                                 non-destructive
//	                                                 state (reason
//	                                                 mandatory)
//
// There is deliberately NO DELETE route: deprovisioning is the terminal
// lifecycle state, per the roadmap ("do not add destructive delete by
// default"). Every lifecycle transition appends write-once, hash-chained
// evidence; a disabled or deprovisioned tenant fails closed at the auth
// layer on its next request. The service is Nil-safe: when unset, every
// endpoint returns 503 tenant_management_unavailable.
const tenantProvisionScope = "provision"

func (s *Server) provisionTenant(w http.ResponseWriter, r *http.Request) {
	actor := verifiedActor(r)
	if actor == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "verified_identity_required"})
		return
	}
	if s.tenantSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tenant_management_unavailable"})
		return
	}
	var req ProvisionTenantRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant_id_required"})
		return
	}
	if strings.TrimSpace(req.Region) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "region_required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	resp, err := s.tenantSvc.Provision(ctx, actor, req)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidRequest):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		case errors.Is(err, ErrTenantRegionConflict):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "tenant_region_conflict", "hint": "deprovision the tenant first to change its region"})
		case errors.Is(err, ErrTenantNotActive):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "tenant_not_active", "hint": "enable the tenant before re-provisioning"})
		case errors.Is(err, ErrTenantUnavailable):
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tenant_management_unavailable"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tenant_provision_failed"})
		}
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	if s.tenantSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tenant_management_unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tenants, err := s.tenantSvc.List(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tenant_list_failed"})
		return
	}
	if tenants == nil {
		tenants = []Tenant{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": tenants})
}

func (s *Server) getTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant_id_required"})
		return
	}
	if s.tenantSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tenant_management_unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tenant, err := s.tenantSvc.Get(ctx, tenantID)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant_not_found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tenant_get_failed"})
		return
	}
	writeJSON(w, http.StatusOK, tenant)
}

func (s *Server) listTenantEvents(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant_id_required"})
		return
	}
	if s.tenantSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tenant_management_unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	events, err := s.tenantSvc.ListEvents(ctx, tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tenant_events_failed"})
		return
	}
	if events == nil {
		events = []TenantEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) disableTenant(w http.ResponseWriter, r *http.Request) {
	s.tenantTransition(w, r, func(ctx context.Context, tenantID, actor, reason string) (Tenant, error) {
		return s.tenantSvc.Disable(ctx, tenantID, actor, reason)
	})
}

func (s *Server) enableTenant(w http.ResponseWriter, r *http.Request) {
	s.tenantTransition(w, r, func(ctx context.Context, tenantID, actor, reason string) (Tenant, error) {
		return s.tenantSvc.Enable(ctx, tenantID, actor, reason)
	})
}

func (s *Server) deprovisionTenant(w http.ResponseWriter, r *http.Request) {
	s.tenantTransition(w, r, func(ctx context.Context, tenantID, actor, reason string) (Tenant, error) {
		return s.tenantSvc.Deprovision(ctx, tenantID, actor, reason)
	})
}

// tenantTransition is the shared handler body for disable / enable /
// deprovision: verified identity, mandatory reason, tenant-scoped
// 404/409/400 mapping, and the tenant response.
func (s *Server) tenantTransition(w http.ResponseWriter, r *http.Request, transition func(ctx context.Context, tenantID, actor, reason string) (Tenant, error)) {
	actor := verifiedActor(r)
	if actor == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "verified_identity_required"})
		return
	}
	tenantID := r.PathValue("tenant_id")
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant_id_required"})
		return
	}
	if s.tenantSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tenant_management_unavailable"})
		return
	}
	var req TenantTransitionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reason_required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	tenant, err := transition(ctx, tenantID, actor, strings.TrimSpace(req.Reason))
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidRequest):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		case errors.Is(err, ErrTenantNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant_not_found"})
		case errors.Is(err, ErrTenantNotActive):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "tenant_not_active"})
		case errors.Is(err, ErrTenantUnavailable):
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tenant_management_unavailable"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tenant_transition_failed"})
		}
		return
	}
	writeJSON(w, http.StatusOK, tenant)
}

// verifiedActor returns the verified identity user id from the request
// context, or "" when no verified (non-demo) identity is present.
func verifiedActor(r *http.Request) string {
	decision, ok := identityFromContext(r.Context())
	if !ok || !decision.identity.Verified || decision.identity.UserID == "" {
		return ""
	}
	return decision.identity.UserID
}
