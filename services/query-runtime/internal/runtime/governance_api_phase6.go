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

// Phase 6 HTTP surface: Multi-Agent Delegation & External-Agent Trust.
//
// Endpoints:
//
//	POST /v1/governance/trust-relationships                         create (admin + verified identity)
//	GET  /v1/governance/trust-relationships                         list (governance scope)
//	GET  /v1/governance/trust-relationships/{relationship_id}       detail
//	POST /v1/governance/trust-relationships/{id}/{approve|activate|suspend|resume|revoke}
//	GET  /v1/governance/delegations                                 list delegation grants
//	GET  /v1/governance/delegations/{grant_id}/chain                verified chain (root first)
//	POST /v1/governance/delegations/{grant_id}/chain/{revoke|suspend|resume}  cascade (admin)
//	GET  /v1/governance/runs/{run_id}/delegation-chain              chain for a run
//	GET  /v1/governance/evidence/{evidence_id}/provenance           provenance view
//	POST /v1/governance/external-agents                             onboard (admin + verified identity)
//	GET  /v1/governance/external-agents                             list
//	GET  /v1/governance/external-agents/{external_agent_id}         detail
//	GET  /v1/governance/external-agents/{external_agent_id}/health  health probe
//	POST /v1/governance/external-agents/{external_agent_id}/{activate|suspend|revoke}
//	POST /v1/governance/external-runs                               create (auth via external token)
//	GET  /v1/governance/external-runs                               list (external only)
//	GET  /v1/governance/external-runs/{run_id}                      detail + decisions
//	POST /v1/governance/external-runs/{run_id}/terminate            terminate (admin)
//	POST /v1/governance/consents                                    create (admin + verified identity)
//	GET  /v1/governance/consents                                    list
//	GET  /v1/governance/consents/{consent_id}                       detail
//	POST /v1/governance/consents/{consent_id}/revoke                revoke (admin + verified identity)
//	POST /v1/governance/transfer-policies                           upsert (admin + verified identity)
//	GET  /v1/governance/transfer-policies                           list
//	POST /v1/governance/transfer-policies/{policy_id}/{activate|suspend|revoke}
//	GET  /v1/governance/external-budgets                            list
//	PUT  /v1/governance/external-budgets/{external_agent_id}        upsert (admin + verified identity)
//
// Security model:
//   - tenant_id and region come ONLY from the verified API-key context;
//   - reads require the "governance" scope (admin inherits);
//   - mutations require a verified end-user identity (demo identity is
//     rejected by requireVerifiedIdentity's production wiring; service
//     methods additionally enforce owner-or-admin / admin-only);
//   - external runs authenticate through the external identity token
//     itself (VerifyExternalSession) — request bodies never carry
//     tenant, region, or authoritative identity;
//   - every mutation requires an Idempotency-Key header; the two
//     single-delivery surfaces (child delegation mint, external run)
//     dedupe in the service, and unique constraints catch replays on
//     the remaining surfaces;
//   - raw tokens and secrets are never echoed in responses or errors.

// requireIdempotency enforces the Idempotency-Key header on Phase 6
// mutations. Safe retries are honored by the service (child mint,
// external run); the remaining surfaces dedupe via unique constraints.
func (s *Server) requireIdempotency(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := idempotencyKey(r)
	if key == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_idempotency_key"))
		return "", false
	}
	return key, true
}

// ---------------------------------------------------------------------
// Trust relationships
// ---------------------------------------------------------------------

func (s *Server) createGovernanceTrustRelationship(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	if _, ok := s.requireIdempotency(w, r); !ok {
		return
	}
	actor, _, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	var req TrustRelationshipRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rel, err := s.governance.CreateTrustRelationship(ctx, tenant.TenantID, actor, hasScope(tenant, "admin"), req)
	if err != nil {
		writeGovernanceServiceError(w, err, "trust_relationship_create_failed")
		return
	}
	writeJSON(w, http.StatusCreated, GovernanceTrustRelationshipResponse{Relationship: rel})
}

func (s *Server) listGovernanceTrustRelationships(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rels, err := s.governance.ListTrustRelationships(ctx, tenant.TenantID)
	if err != nil {
		writeGovernanceServiceError(w, err, "trust_relationships_list_failed")
		return
	}
	if rels == nil {
		rels = []AgentTrustRelationship{}
	}
	writeJSON(w, http.StatusOK, GovernanceTrustRelationshipsResponse{Relationships: rels, Count: len(rels)})
}

func (s *Server) getGovernanceTrustRelationship(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	id := strings.TrimSpace(r.PathValue("relationship_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_relationship_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rel, err := s.governance.GetTrustRelationship(ctx, tenant.TenantID, id)
	if err != nil {
		writeGovernanceServiceError(w, err, "trust_relationship_get_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceTrustRelationshipResponse{Relationship: rel})
}

// governanceTrustTransition drives one lifecycle transition of a trust
// relationship (approve/activate/suspend/resume/revoke) through the
// service state machine.
func (s *Server) governanceTrustTransition(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := tenantFromContext(r.Context())
		if !ok {
			writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
			return
		}
		if s.governance == nil {
			writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
			return
		}
		if _, ok := s.requireIdempotency(w, r); !ok {
			return
		}
		actor, _, ok := s.governanceActor(w, r)
		if !ok {
			return
		}
		id := strings.TrimSpace(r.PathValue("relationship_id"))
		if id == "" {
			writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_relationship_id"))
			return
		}
		var req TrustTransitionRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		rel, err := s.governance.TransitionTrustRelationship(ctx, tenant.TenantID, id, actor, hasScope(tenant, "admin"), action, req)
		if err != nil {
			writeGovernanceServiceError(w, err, "trust_relationship_transition_failed")
			return
		}
		writeJSON(w, http.StatusOK, GovernanceTrustRelationshipResponse{Relationship: rel})
	}
}

// ---------------------------------------------------------------------
// Delegation chains
// ---------------------------------------------------------------------

func (s *Server) listGovernanceDelegationGrants(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grants, err := s.governance.ListDelegationGrants(ctx, tenant.TenantID)
	if err != nil {
		writeGovernanceServiceError(w, err, "delegations_list_failed")
		return
	}
	if grants == nil {
		grants = []DelegationGrant{}
	}
	writeJSON(w, http.StatusOK, GovernanceDelegationsResponse{Grants: grants, Count: len(grants)})
}

func (s *Server) getGovernanceDelegationChain(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	id := strings.TrimSpace(r.PathValue("grant_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_grant_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	chain, err := s.governance.GetDelegationChain(ctx, tenant.TenantID, id)
	if err != nil {
		writeGovernanceServiceError(w, err, "delegation_chain_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceDelegationChainResponse{Chain: chain})
}

func (s *Server) getGovernanceRunDelegationChain(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	id := strings.TrimSpace(r.PathValue("run_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_run_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	chain, err := s.governance.GetRunDelegationChain(ctx, tenant.TenantID, id)
	if err != nil {
		writeGovernanceServiceError(w, err, "run_delegation_chain_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceDelegationChainResponse{Chain: chain})
}

func (s *Server) getGovernanceEvidenceProvenance(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	id := strings.TrimSpace(r.PathValue("evidence_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_evidence_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	prov, err := s.governance.GetEvidenceProvenance(ctx, tenant.TenantID, id)
	if err != nil {
		writeGovernanceServiceError(w, err, "evidence_provenance_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceProvenanceResponse{Provenance: prov})
}

// governanceChainControl cascades revoke/suspend/resume across the
// grant and every descendant (admin-only, enforced by the service).
func (s *Server) governanceChainControl(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := tenantFromContext(r.Context())
		if !ok {
			writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
			return
		}
		if s.governance == nil {
			writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
			return
		}
		if _, ok := s.requireIdempotency(w, r); !ok {
			return
		}
		actor, _, ok := s.governanceActor(w, r)
		if !ok {
			return
		}
		id := strings.TrimSpace(r.PathValue("grant_id"))
		if id == "" {
			writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_grant_id"))
			return
		}
		var req ControlRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		admin := hasScope(tenant, "admin")
		var changed int
		var err error
		switch action {
		case "revoke":
			changed, err = s.governance.RevokeDelegationChain(ctx, tenant.TenantID, id, actor, admin, req)
		case "suspend":
			changed, err = s.governance.SuspendDelegationChain(ctx, tenant.TenantID, id, actor, admin, req)
		case "resume":
			changed, err = s.governance.ResumeDelegationChain(ctx, tenant.TenantID, id, actor, admin, req)
		}
		if err != nil {
			writeGovernanceServiceError(w, err, "delegation_chain_control_failed")
			return
		}
		writeJSON(w, http.StatusOK, GovernanceChainControlResponse{GrantsChanged: changed})
	}
}

// ---------------------------------------------------------------------
// External agents
// ---------------------------------------------------------------------

func (s *Server) createGovernanceExternalAgent(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	if _, ok := s.requireIdempotency(w, r); !ok {
		return
	}
	actor, _, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	var req ExternalAgentRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	agent, err := s.governance.OnboardExternalAgent(ctx, tenant.TenantID, actor, hasScope(tenant, "admin"), req)
	if err != nil {
		writeGovernanceServiceError(w, err, "external_agent_create_failed")
		return
	}
	writeJSON(w, http.StatusCreated, GovernanceExternalAgentResponse{Agent: agent})
}

func (s *Server) listGovernanceExternalAgents(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	agents, err := s.governance.ListExternalAgents(ctx, tenant.TenantID)
	if err != nil {
		writeGovernanceServiceError(w, err, "external_agents_list_failed")
		return
	}
	if agents == nil {
		agents = []ExternalAgent{}
	}
	writeJSON(w, http.StatusOK, GovernanceExternalAgentsResponse{Agents: agents, Count: len(agents)})
}

func (s *Server) getGovernanceExternalAgent(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	id := strings.TrimSpace(r.PathValue("external_agent_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_external_agent_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	agent, err := s.governance.GetExternalAgent(ctx, tenant.TenantID, id)
	if err != nil {
		writeGovernanceServiceError(w, err, "external_agent_get_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceExternalAgentResponse{Agent: agent})
}

// governanceExternalAgentTransition drives activate/suspend/revoke.
func (s *Server) governanceExternalAgentTransition(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := tenantFromContext(r.Context())
		if !ok {
			writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
			return
		}
		if s.governance == nil {
			writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
			return
		}
		if _, ok := s.requireIdempotency(w, r); !ok {
			return
		}
		actor, _, ok := s.governanceActor(w, r)
		if !ok {
			return
		}
		id := strings.TrimSpace(r.PathValue("external_agent_id"))
		if id == "" {
			writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_external_agent_id"))
			return
		}
		var req TrustTransitionRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		agent, err := s.governance.TransitionExternalAgent(ctx, tenant.TenantID, id, actor, hasScope(tenant, "admin"), action, req)
		if err != nil {
			writeGovernanceServiceError(w, err, "external_agent_transition_failed")
			return
		}
		writeJSON(w, http.StatusOK, GovernanceExternalAgentResponse{Agent: agent})
	}
}

// governanceExternalAgentHealth is a read-only status probe derived from
// the registered lifecycle state (GetExternalAgent lazily stamps
// expiry). It carries no identity or secret material.
func (s *Server) governanceExternalAgentHealth(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	id := strings.TrimSpace(r.PathValue("external_agent_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_external_agent_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	agent, err := s.governance.GetExternalAgent(ctx, tenant.TenantID, id)
	if err != nil {
		writeGovernanceServiceError(w, err, "external_agent_health_failed")
		return
	}
	reason := agent.LifecycleState
	healthy := agent.LifecycleState == ExternalStateActive && time.Now().UTC().Before(agent.ExpiresAt)
	if agent.LifecycleState == ExternalStateActive && !time.Now().UTC().Before(agent.ExpiresAt) {
		reason = ExternalStateExpired
	}
	writeJSON(w, http.StatusOK, GovernanceExternalAgentHealthResponse{
		ExternalAgentID: agent.ExternalAgentID,
		LifecycleState:  agent.LifecycleState,
		TrustTier:       agent.TrustTier,
		Region:          agent.Region,
		ExpiresAt:       agent.ExpiresAt,
		Healthy:         healthy,
		Reason:          reason,
	})
}

// ---------------------------------------------------------------------
// External runs (authenticated by the external identity token)
// ---------------------------------------------------------------------

func (s *Server) createGovernanceExternalRun(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	key, ok := s.requireIdempotency(w, r)
	if !ok {
		return
	}
	var req CreateExternalRunRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	// Phase 8.1: external runs are metered (fail closed).
	if !s.recordUsage(w, tenant.TenantID, usage.MetricRuns, 1) {
		return
	}
	resp, err := s.governance.CreateExternalRun(ctx, tenant.TenantID, tenant.Region, key, req)
	if err != nil {
		writeGovernanceServiceError(w, err, "external_run_create_failed")
		return
	}
	writeJSON(w, http.StatusCreated, GovernanceRunResponse{Run: resp.Run, Decisions: resp.Decisions})
}

func (s *Server) listGovernanceExternalRuns(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	runs, err := s.governance.ListExternalRuns(ctx, tenant.TenantID)
	if err != nil {
		writeGovernanceServiceError(w, err, "external_runs_list_failed")
		return
	}
	if runs == nil {
		runs = []AgentRun{}
	}
	writeJSON(w, http.StatusOK, GovernanceRunListResponse{Runs: runs, Count: len(runs)})
}

func (s *Server) getGovernanceExternalRun(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	id := strings.TrimSpace(r.PathValue("run_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_run_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	run, decisions, err := s.governance.GetExternalRun(ctx, tenant.TenantID, id)
	if err != nil {
		writeGovernanceServiceError(w, err, "external_run_get_failed")
		return
	}
	if decisions == nil {
		decisions = []ActionDecision{}
	}
	writeJSON(w, http.StatusOK, GovernanceRunDetailResponse{Run: run, Decisions: decisions})
}

func (s *Server) terminateGovernanceExternalRun(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	if _, ok := s.requireIdempotency(w, r); !ok {
		return
	}
	actor, _, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("run_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_run_id"))
		return
	}
	var req ControlRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	control, err := s.governance.TerminateExternalRun(ctx, tenant.TenantID, id, actor, hasScope(tenant, "admin"), req)
	if err != nil {
		writeGovernanceServiceError(w, err, "external_run_terminate_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceControlResponse{Control: control})
}

// ---------------------------------------------------------------------
// Consent records
// ---------------------------------------------------------------------

func (s *Server) createGovernanceConsentRecord(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	if _, ok := s.requireIdempotency(w, r); !ok {
		return
	}
	actor, _, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	var req ConsentRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	consent, err := s.governance.CreateConsentRecord(ctx, tenant.TenantID, actor, hasScope(tenant, "admin"), req)
	if err != nil {
		writeGovernanceServiceError(w, err, "consent_create_failed")
		return
	}
	writeJSON(w, http.StatusCreated, GovernanceConsentResponse{Consent: consent})
}

func (s *Server) listGovernanceConsentRecords(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	consents, err := s.governance.ListConsentRecords(ctx, tenant.TenantID)
	if err != nil {
		writeGovernanceServiceError(w, err, "consents_list_failed")
		return
	}
	if consents == nil {
		consents = []ConsentRecord{}
	}
	writeJSON(w, http.StatusOK, GovernanceConsentsResponse{Consents: consents, Count: len(consents)})
}

func (s *Server) getGovernanceConsentRecord(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	id := strings.TrimSpace(r.PathValue("consent_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_consent_id"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	consent, err := s.governance.GetConsentRecord(ctx, tenant.TenantID, id)
	if err != nil {
		writeGovernanceServiceError(w, err, "consent_get_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceConsentResponse{Consent: consent})
}

func (s *Server) revokeGovernanceConsentRecord(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	if _, ok := s.requireIdempotency(w, r); !ok {
		return
	}
	actor, _, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("consent_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_consent_id"))
		return
	}
	var req TrustTransitionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	consent, err := s.governance.RevokeConsentRecord(ctx, tenant.TenantID, id, actor, hasScope(tenant, "admin"), req.Reason)
	if err != nil {
		writeGovernanceServiceError(w, err, "consent_revoke_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceConsentResponse{Consent: consent})
}

// ---------------------------------------------------------------------
// Transfer policies
// ---------------------------------------------------------------------

func (s *Server) upsertGovernanceTransferPolicy(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	if _, ok := s.requireIdempotency(w, r); !ok {
		return
	}
	actor, _, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	var req TransferPolicyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	policy, err := s.governance.UpsertTransferPolicy(ctx, tenant.TenantID, actor, hasScope(tenant, "admin"), req)
	if err != nil {
		writeGovernanceServiceError(w, err, "transfer_policy_upsert_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceTransferPolicyResponse{Policy: policy})
}

func (s *Server) listGovernanceTransferPolicies(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	policies, err := s.governance.ListTransferPolicies(ctx, tenant.TenantID)
	if err != nil {
		writeGovernanceServiceError(w, err, "transfer_policies_list_failed")
		return
	}
	if policies == nil {
		policies = []TransferPolicy{}
	}
	writeJSON(w, http.StatusOK, GovernanceTransferPoliciesResponse{Policies: policies, Count: len(policies)})
}

// governanceTransferPolicyTransition drives activate/suspend/revoke.
func (s *Server) governanceTransferPolicyTransition(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := tenantFromContext(r.Context())
		if !ok {
			writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
			return
		}
		if s.governance == nil {
			writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
			return
		}
		if _, ok := s.requireIdempotency(w, r); !ok {
			return
		}
		actor, _, ok := s.governanceActor(w, r)
		if !ok {
			return
		}
		id := strings.TrimSpace(r.PathValue("policy_id"))
		if id == "" {
			writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_policy_id"))
			return
		}
		var req TrustTransitionRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		policy, err := s.governance.TransitionTransferPolicy(ctx, tenant.TenantID, id, actor, hasScope(tenant, "admin"), action, req)
		if err != nil {
			writeGovernanceServiceError(w, err, "transfer_policy_transition_failed")
			return
		}
		writeJSON(w, http.StatusOK, GovernanceTransferPolicyResponse{Policy: policy})
	}
}

// ---------------------------------------------------------------------
// External budgets
// ---------------------------------------------------------------------

func (s *Server) listGovernanceExternalBudgets(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	budgets, err := s.governance.ListExternalBudgets(ctx, tenant.TenantID)
	if err != nil {
		writeGovernanceServiceError(w, err, "external_budgets_list_failed")
		return
	}
	if budgets == nil {
		budgets = []ExternalBudgetPolicy{}
	}
	writeJSON(w, http.StatusOK, GovernanceExternalBudgetsResponse{Budgets: budgets, Count: len(budgets)})
}

// upsertGovernanceExternalBudget configures a budget for the external
// agent named in the path. The path value is authoritative for the
// scope; a mismatched body declaration is rejected.
func (s *Server) upsertGovernanceExternalBudget(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeGovernanceError(w, http.StatusUnauthorized, errors.New("missing_tenant_context"))
		return
	}
	if s.governance == nil {
		writeGovernanceError(w, http.StatusServiceUnavailable, ErrGovernanceUnavailable)
		return
	}
	if _, ok := s.requireIdempotency(w, r); !ok {
		return
	}
	actor, _, ok := s.governanceActor(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.PathValue("external_agent_id"))
	if id == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_external_agent_id"))
		return
	}
	var req ExternalBudgetRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_json"))
		return
	}
	// The path names the external agent; a conflicting body declaration
	// is a request-error, never an authorization source.
	if strings.TrimSpace(req.ExternalAgentID) != "" && req.ExternalAgentID != id {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("external_agent_id_mismatch"))
		return
	}
	req.ExternalAgentID = id
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	budget, err := s.governance.UpsertExternalBudget(ctx, tenant.TenantID, actor, hasScope(tenant, "admin"), req)
	if err != nil {
		writeGovernanceServiceError(w, err, "external_budget_upsert_failed")
		return
	}
	writeJSON(w, http.StatusOK, GovernanceExternalBudgetResponse{Budget: budget})
}

// ---------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------

type GovernanceTrustRelationshipResponse struct {
	Relationship AgentTrustRelationship `json:"relationship"`
}

type GovernanceTrustRelationshipsResponse struct {
	Relationships []AgentTrustRelationship `json:"relationships"`
	Count         int                      `json:"count"`
}

type GovernanceDelegationsResponse struct {
	Grants []DelegationGrant `json:"grants"`
	Count  int               `json:"count"`
}

type GovernanceDelegationChainResponse struct {
	Chain DelegationChain `json:"chain"`
}

type GovernanceChainControlResponse struct {
	GrantsChanged int `json:"grants_changed"`
}

type GovernanceProvenanceResponse struct {
	Provenance ProvenanceView `json:"provenance"`
}

type GovernanceExternalAgentResponse struct {
	Agent ExternalAgent `json:"agent"`
}

type GovernanceExternalAgentsResponse struct {
	Agents []ExternalAgent `json:"agents"`
	Count  int             `json:"count"`
}

type GovernanceExternalAgentHealthResponse struct {
	ExternalAgentID string    `json:"external_agent_id"`
	LifecycleState  string    `json:"lifecycle_state"`
	TrustTier       string    `json:"trust_tier"`
	Region          string    `json:"region"`
	ExpiresAt       time.Time `json:"expires_at"`
	Healthy         bool      `json:"healthy"`
	Reason          string    `json:"reason,omitempty"`
}

type GovernanceConsentResponse struct {
	Consent ConsentRecord `json:"consent"`
}

type GovernanceConsentsResponse struct {
	Consents []ConsentRecord `json:"consents"`
	Count    int             `json:"count"`
}

type GovernanceTransferPolicyResponse struct {
	Policy TransferPolicy `json:"policy"`
}

type GovernanceTransferPoliciesResponse struct {
	Policies []TransferPolicy `json:"policies"`
	Count    int              `json:"count"`
}

type GovernanceExternalBudgetResponse struct {
	Budget ExternalBudgetPolicy `json:"budget"`
}

type GovernanceExternalBudgetsResponse struct {
	Budgets []ExternalBudgetPolicy `json:"budgets"`
	Count   int                    `json:"count"`
}
