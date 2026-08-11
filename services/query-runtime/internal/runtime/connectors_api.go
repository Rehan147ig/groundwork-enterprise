// Phase 5: Production Connector Gateway — HTTP surface.
//
// The connector registry lives under the governance scope; every
// mutation requires a verified end-user identity and owner-or-admin
// authorization (enforced by the service), mirrors the kill-switch
// conventions. Reads need the governance scope only. All responses are
// redacted by construction — the gateway never returns raw secrets.

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	gwmetrics "groundwork/query-runtime/internal/metrics"
)

// ConnectorScope is the API key scope required for connector
// registry reads and mutations (same scope as the rest of the
// governance plane).
const ConnectorScope = governanceScope

// SetConnectorService wires the Phase 5 connector gateway.
// Nil-safe: when unset, /v1/governance/connectors* returns 503
// connector_gateway_unavailable and DispatchAction fails closed
// (connector_dispatcher_unavailable evidence).
func (s *Server) SetConnectorService(c ConnectorService) { s.connectors = c }

// connectorActor resolves the actor principal for a connector
// mutation. Connector registration, lifecycle transitions, and config
// updates REQUIRE a verified identity (a demo actor can never mutate
// the registry).
func (s *Server) connectorActor(w http.ResponseWriter, r *http.Request) (string, bool) {
	actor, verified, ok := s.governanceActor(w, r)
	if !ok {
		return "", false
	}
	if !verified {
		writeGovernanceError(w, http.StatusForbidden, errors.New("verified_identity_required_for_connector_mutation"))
		return "", false
	}
	return actor, true
}

func (s *Server) connectorService(w http.ResponseWriter) (ConnectorService, bool) {
	if s.connectors == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, errors.New("connector_gateway_unavailable"))
		return nil, false
	}
	return s.connectors, true
}

// registerConnector creates a connector in 'draft' together with its
// governed tool and tool actions.
func (s *Server) registerConnector(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	svc, ok := s.connectorService(w)
	if !ok {
		return
	}
	actor, ok := s.connectorActor(w, r)
	if !ok {
		return
	}
	var req ConnectorRegisterRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	detail, err := svc.Register(ctx, tenant.TenantID, actor, hasScope(tenant, "admin"), req)
	if err != nil {
		writeGovernanceServiceError(w, err, "connector_register_failed")
		return
	}
	writeJSON(w, http.StatusCreated, GovernanceConnectorDetailResponse{Detail: detail})
}

func (s *Server) listConnectors(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	svc, ok := s.connectorService(w)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	conns, err := svc.List(ctx, tenant.TenantID)
	if err != nil {
		writeGovernanceServiceError(w, err, "connector_list_failed")
		return
	}
	if conns == nil {
		conns = []Connector{}
	}
	writeJSON(w, http.StatusOK, GovernanceConnectorsResponse{Connectors: conns, Count: len(conns)})
}

func (s *Server) getConnector(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	svc, ok := s.connectorService(w)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("connector_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_connector_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	detail, err := svc.Get(ctx, tenant.TenantID, id)
	if err != nil {
		writeGovernanceServiceError(w, err, "connector_get_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceConnectorDetailResponse{Detail: detail})
}

func (s *Server) getConnectorManifest(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	svc, ok := s.connectorService(w)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("connector_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_connector_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	version, actions, err := svc.GetManifest(ctx, tenant.TenantID, id)
	if err != nil {
		writeGovernanceServiceError(w, err, "connector_manifest_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceConnectorManifestResponse{Actions: actions, ManifestDigest: version.ManifestDigest})
}

func (s *Server) connectorHealthProbe(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	svc, ok := s.connectorService(w)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("connector_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_connector_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	health, err := svc.Health(ctx, tenant.TenantID, id)
	if err != nil {
		writeGovernanceServiceError(w, err, "connector_health_failed")
		return
	}
	gwmetrics.SetConnectorHealth(tenant.TenantID, id, health.Healthy)
	if !health.Healthy {
		gwmetrics.RecordConnectorError(tenant.TenantID, id, health.ErrorCode)
	}
	writeJSON(w, http.StatusOK, GovernanceConnectorHealthResponse{Health: health})
}

// connectorTransition drives activate/suspend/revoke mutations.
func (s *Server) connectorTransition(w http.ResponseWriter, r *http.Request, to string) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	svc, ok := s.connectorService(w)
	if !ok {
		return
	}
	actor, ok := s.connectorActor(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("connector_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_connector_id"))
		return
	}
	var req ConnectorTransitionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	conn, err := svc.Transition(ctx, tenant.TenantID, id, actor, hasScope(tenant, "admin"), to, req)
	if err != nil {
		writeGovernanceServiceError(w, err, "connector_transition_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceConnectorTransitionResponse{Connector: conn})
}

func (s *Server) activateConnector(w http.ResponseWriter, r *http.Request) {
	s.connectorTransition(w, r, ConnectorLifecycleActive)
}

func (s *Server) suspendConnector(w http.ResponseWriter, r *http.Request) {
	s.connectorTransition(w, r, ConnectorLifecycleSuspended)
}

func (s *Server) revokeConnector(w http.ResponseWriter, r *http.Request) {
	s.connectorTransition(w, r, ConnectorLifecycleRevoked)
}

func (s *Server) updateConnectorConfig(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	svc, ok := s.connectorService(w)
	if !ok {
		return
	}
	actor, ok := s.connectorActor(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("connector_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_connector_id"))
		return
	}
	var req ConnectorRegisterRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	detail, err := svc.UpdateConfig(ctx, tenant.TenantID, id, actor, hasScope(tenant, "admin"), req)
	if err != nil {
		writeGovernanceServiceError(w, err, "connector_config_update_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceConnectorDetailResponse{Detail: detail})
}

// ---------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------

type GovernanceConnectorsResponse struct {
	Connectors []Connector `json:"connectors"`
	Count      int         `json:"count"`
}

type GovernanceConnectorDetailResponse struct {
	Detail ConnectorDetail `json:"detail"`
}

type GovernanceConnectorManifestResponse struct {
	Actions        []ConnectorActionManifest `json:"actions"`
	ManifestDigest string                    `json:"manifest_digest"`
}

type GovernanceConnectorHealthResponse struct {
	Health ConnectorHealth `json:"health"`
}

type GovernanceConnectorTransitionResponse struct {
	Connector Connector `json:"connector"`
}
