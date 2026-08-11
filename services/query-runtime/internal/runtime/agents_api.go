package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"groundwork/query-runtime/internal/usage"
)

// Agent Registry HTTP surface (Phase 1: Agent Trust and Control Plane).
//
// Endpoints:
//
//	POST /v1/agents                          create (always lands in draft)
//	GET  /v1/agents                          list (?state= filter)
//	GET  /v1/agents/{agent_id}               detail + versions + events
//	POST /v1/agents/{agent_id}/versions      register a draft version
//	POST /v1/agents/{agent_id}/activate      draft|pending|suspended -> active
//	POST /v1/agents/{agent_id}/suspend       active -> suspended
//	POST /v1/agents/{agent_id}/revoke        any non-terminal -> revoked (IRREVERSIBLE)
//	POST /v1/agents/{agent_id}/retire        any non-terminal -> retired (terminal)
//
// Security model:
//   - tenant_id comes only from the verified API-key context (the
//     requireAPIKey middleware) — never from bodies, URLs, or params;
//   - mutations require a verified end-user identity (requireVerifiedIdentity);
//     the actor principal is the canonicalized identity, or a demo
//     identity only when ALLOW_DEMO_IDENTITY=true. Absent identity fails
//     closed with 401.
//   - transitions additionally require the agent owner or a key with
//     the admin scope (hasScope override), enforced by the registry
//     service (ErrAgentNotAuthorized -> 403);
//   - every lifecycle change appends a hash-chained write-once event.
//
// Like the Audit Read API, the AgentRegistry interface and the JSON
// DTOs live in this package; the implementation (internal/agentregistry)
// is wired via SetAgentRegistry. When unset, endpoints return 503
// agent_registry_unavailable.

// agentActor resolves the actor principal for a mutation request. A
// verified identity is canonicalized (or fails closed when unresolved);
// a demo identity is honored only when demo identity is enabled.
func (s *Server) agentActor(w http.ResponseWriter, r *http.Request) (string, bool) {
	decision, ok := identityFromContext(r.Context())
	if !ok {
		writeAgentError(w, http.StatusUnauthorized, ErrIdentityMissing)
		return "", false
	}
	tenant, _ := tenantFromContext(r.Context())
	if decision.identity.Verified {
		effective, _, err := CanonicalizeIdentity(r.Context(), s.resolver, s.canonicalIdentity, tenant.TenantID, decision.identity)
		if err != nil {
			writeAgentError(w, http.StatusForbidden, ErrIdentityUnresolved)
			return "", false
		}
		return effective, true
	}
	// Demo identity (ALLOW_DEMO_IDENTITY=true, dev only): a shared
	// synthetic actor. Demo mode carries no real authorization — it is
	// for local development and is never enabled in production.
	return "demo_actor", true
}

func (s *Server) createAgent(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeAgentError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.agentRegistry == nil {
		writeAgentError(w, http.StatusServiceUnavailable, ErrAgentUnavailable)
		return
	}
	actor, ok := s.agentActor(w, r)
	if !ok {
		return
	}
	var req CreateAgentRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeAgentError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Phase 8.1: meter agent creation against the tenant's agents
	// quota (fail closed — quota_exceeded:agents denies the create).
	if !s.recordUsage(w, tenant.TenantID, usage.MetricAgents, 1) {
		return
	}
	agent, err := s.agentRegistry.CreateAgent(ctx, tenant.TenantID, actor, req)
	if err != nil {
		writeAgentServiceError(w, err, "agent_create_failed")
		return
	}
	writeJSON(w, http.StatusCreated, AgentResponse{Agent: agent})
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeAgentError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.agentRegistry == nil {
		writeAgentError(w, http.StatusServiceUnavailable, ErrAgentUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	agents, err := s.agentRegistry.ListAgents(ctx, tenant.TenantID, strings.TrimSpace(r.URL.Query().Get("state")))
	if err != nil {
		writeAgentServiceError(w, err, "agents_query_failed")
		return
	}
	if agents == nil {
		agents = []Agent{}
	}
	writeJSON(w, http.StatusOK, AgentListResponse{Agents: agents, Count: len(agents)})
}

func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeAgentError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.agentRegistry == nil {
		writeAgentError(w, http.StatusServiceUnavailable, ErrAgentUnavailable)
		return
	}
	agentID := strings.TrimSpace(r.PathValue("agent_id"))
	if agentID == "" {
		writeAgentError(w, http.StatusBadRequest, errors.New("invalid_agent_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	agent, versions, events, err := s.agentRegistry.GetAgent(ctx, tenant.TenantID, agentID)
	if err != nil {
		writeAgentServiceError(w, err, "agents_query_failed")
		return
	}
	if versions == nil {
		versions = []AgentVersion{}
	}
	if events == nil {
		events = []LifecycleEvent{}
	}
	writeJSON(w, http.StatusOK, AgentDetailResponse{Agent: agent, Versions: versions, LifecycleEvents: events})
}

func (s *Server) addAgentVersion(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeAgentError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.agentRegistry == nil {
		writeAgentError(w, http.StatusServiceUnavailable, ErrAgentUnavailable)
		return
	}
	actor, ok := s.agentActor(w, r)
	if !ok {
		return
	}
	agentID := strings.TrimSpace(r.PathValue("agent_id"))
	if agentID == "" {
		writeAgentError(w, http.StatusBadRequest, errors.New("invalid_agent_id"))
		return
	}
	var req AddAgentVersionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeAgentError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	version, err := s.agentRegistry.AddVersion(ctx, tenant.TenantID, agentID, actor, hasScope(tenant, "admin"), req)
	if err != nil {
		writeAgentServiceError(w, err, "agent_version_create_failed")
		return
	}
	writeJSON(w, http.StatusCreated, AgentVersionResponse{Version: version})
}

// agentTransitionHandler builds the handler for one lifecycle action.
// The registry method is passed in so the action dispatch stays next to
// the route registration.
func (s *Server) agentTransitionHandler(action string, transition func(ctx context.Context, tenantID, agentID, actor string, admin bool, reason string) (Agent, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := tenantFromContext(r.Context())
		if !ok {
			writeAgentError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
			return
		}
		if s.agentRegistry == nil {
			writeAgentError(w, http.StatusServiceUnavailable, ErrAgentUnavailable)
			return
		}
		actor, ok := s.agentActor(w, r)
		if !ok {
			return
		}
		agentID := strings.TrimSpace(r.PathValue("agent_id"))
		if agentID == "" {
			writeAgentError(w, http.StatusBadRequest, errors.New("invalid_agent_id"))
			return
		}
		var req LifecycleActionRequest
		// Actions accept an optional {"reason": "..."} body; an empty
		// body is fine. Tenant/state are never taken from the body.
		if r.Body != nil {
			_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req)
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		agent, err := transition(ctx, tenant.TenantID, agentID, actor, hasScope(tenant, "admin"), req.Reason)
		if err != nil {
			writeAgentServiceError(w, err, "agent_"+action+"_failed")
			return
		}
		writeJSON(w, http.StatusOK, AgentResponse{Agent: agent})
	}
}

func (s *Server) activateAgent(w http.ResponseWriter, r *http.Request) {
	s.agentTransitionHandler("activate", s.agentRegistry.ActivateAgent)(w, r)
}

func (s *Server) suspendAgent(w http.ResponseWriter, r *http.Request) {
	s.agentTransitionHandler("suspend", s.agentRegistry.SuspendAgent)(w, r)
}

func (s *Server) revokeAgent(w http.ResponseWriter, r *http.Request) {
	s.agentTransitionHandler("revoke", s.agentRegistry.RevokeAgent)(w, r)
}

func (s *Server) retireAgent(w http.ResponseWriter, r *http.Request) {
	s.agentTransitionHandler("retire", s.agentRegistry.RetireAgent)(w, r)
}

// writeAgentError renders the /v1/agents error envelope.
func writeAgentError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, AgentAPIError{Error: err.Error()})
}

// writeAgentServiceError maps registry sentinel errors to HTTP statuses;
// unknown errors become 500 with the generic code so no DB internals leak.
func writeAgentServiceError(w http.ResponseWriter, err error, genericCode string) {
	switch {
	case errors.Is(err, ErrAgentNotFound), errors.Is(err, ErrAgentVersionNotFound):
		writeAgentError(w, http.StatusNotFound, err)
	case errors.Is(err, ErrAgentNameConflict), errors.Is(err, ErrAgentVersionConflict):
		writeAgentError(w, http.StatusConflict, err)
	case errors.Is(err, ErrAgentNotAuthorized):
		writeAgentError(w, http.StatusForbidden, err)
	case errors.Is(err, ErrAgentInvalidTransition), errors.Is(err, ErrAgentInvalidRequest):
		writeAgentError(w, http.StatusBadRequest, err)
	default:
		writeAgentError(w, http.StatusInternalServerError, errors.New(genericCode))
	}
}
