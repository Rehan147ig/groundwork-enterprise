package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// FakeRuntime is an in-memory stand-in for the Groundwork API used by
// client and provider tests. It enforces the same fail-closed
// conventions the real runtime enforces: API key presence, JSON error
// envelopes, and Idempotency-Key on Phase 6 mutations. It is a test
// double only — the provider binary never depends on it.
type FakeRuntime struct {
	mu         sync.Mutex
	apiKey     string
	tenants    map[string]Tenant
	grants     map[string]AgentToolGrant
	policies   map[string]TransferPolicy
	budgets    map[string]BudgetPolicy
	connectors map[string]ConnectorDetail
	agents     map[string]Agent
}

// NewFakeRuntime returns a fresh fake with a fixed API key.
func NewFakeRuntime() *FakeRuntime {
	return &FakeRuntime{
		apiKey:     "test-api-key",
		tenants:    map[string]Tenant{},
		grants:     map[string]AgentToolGrant{},
		policies:   map[string]TransferPolicy{},
		budgets:    map[string]BudgetPolicy{},
		connectors: map[string]ConnectorDetail{},
		agents:     map[string]Agent{},
	}
}

// APIKey returns the key the fake authenticates requests with.
func (f *FakeRuntime) APIKey() string { return f.apiKey }

// TenantStatus returns the stored status for a tenant, or "" if absent.
func (f *FakeRuntime) TenantStatus(tenantID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tenants[tenantID].Status
}

// AgentLifecycle returns the stored lifecycle state for an agent.
func (f *FakeRuntime) AgentLifecycle(agentID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.agents[agentID].LifecycleState
}

// Handler returns the HTTP surface of the fake.
func (f *FakeRuntime) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/admin/tenants", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		var req provisionTenantRequest
		if !f.decode(w, r, &req) {
			return
		}
		f.mu.Lock()
		existing, ok := f.tenants[req.TenantID]
		if ok && existing.Region != req.Region {
			f.mu.Unlock()
			f.err(w, http.StatusConflict, "region_conflict")
			return
		}
		t := Tenant{TenantID: req.TenantID, Region: req.Region, Status: "active", Tier: req.Tier, Reason: req.Reason}
		if ok {
			t.Status = existing.Status
		}
		f.tenants[req.TenantID] = t
		f.mu.Unlock()
		f.json(w, http.StatusCreated, provisionTenantResponse{Tenant: t})
	})
	mux.HandleFunc("GET /v1/admin/tenants/{tenant_id}", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		f.mu.Lock()
		t, ok := f.tenants[r.PathValue("tenant_id")]
		f.mu.Unlock()
		if !ok {
			f.err(w, http.StatusNotFound, "tenant_not_found")
			return
		}
		f.json(w, http.StatusOK, tenantResponse{Tenant: t})
	})
	mux.HandleFunc("POST /v1/admin/tenants/{tenant_id}/deprovision", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		f.mu.Lock()
		t, ok := f.tenants[r.PathValue("tenant_id")]
		if ok {
			t.Status = "deprovisioned"
			f.tenants[t.TenantID] = t
		}
		f.mu.Unlock()
		if !ok {
			f.err(w, http.StatusNotFound, "tenant_not_found")
			return
		}
		f.json(w, http.StatusOK, tenantResponse{Tenant: t})
	})

	mux.HandleFunc("POST /v1/governance/grants", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		var req grantToolRequest
		if !f.decode(w, r, &req) {
			return
		}
		g := AgentToolGrant{
			ID:               "grant-1",
			AgentID:          req.AgentID,
			VersionID:        req.VersionID,
			ToolID:           req.ToolID,
			ActionID:         req.ActionID,
			ResourceScope:    req.ResourceScope,
			RegionConstraint: req.RegionConstraint,
			CallLimitPerRun:  req.CallLimitPerRun,
			RequiresApproval: req.RequiresApproval,
		}
		f.mu.Lock()
		f.grants[g.ID] = g
		f.mu.Unlock()
		f.json(w, http.StatusCreated, grantResponse{Grant: g})
	})
	mux.HandleFunc("GET /v1/governance/agents/{agent_id}/grants", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		f.mu.Lock()
		var list []AgentToolGrant
		for _, g := range f.grants {
			if g.AgentID == r.PathValue("agent_id") {
				list = append(list, g)
			}
		}
		f.mu.Unlock()
		if list == nil {
			list = []AgentToolGrant{}
		}
		f.json(w, http.StatusOK, grantListResponse{Grants: list, Count: len(list)})
	})
	mux.HandleFunc("POST /v1/governance/grants/{grant_id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		f.mu.Lock()
		g, ok := f.grants[r.PathValue("grant_id")]
		if ok {
			delete(f.grants, g.ID)
		}
		f.mu.Unlock()
		if !ok {
			f.err(w, http.StatusNotFound, "grant_not_found")
			return
		}
		f.json(w, http.StatusOK, grantResponse{Grant: g})
	})

	mux.HandleFunc("POST /v1/governance/transfer-policies", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
			f.err(w, http.StatusBadRequest, "idempotency_key_required")
			return
		}
		var req transferPolicyRequest
		if !f.decode(w, r, &req) {
			return
		}
		p := TransferPolicy{
			ID:             "policy-1",
			SourceRegion:   req.SourceRegion,
			TargetRegion:   req.TargetRegion,
			PurposePattern: req.PurposePattern,
			Enabled:        req.Enabled,
		}
		f.mu.Lock()
		f.policies[p.ID] = p
		f.mu.Unlock()
		f.json(w, http.StatusOK, transferPolicyResponse{Policy: p})
	})
	mux.HandleFunc("GET /v1/governance/transfer-policies", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		f.mu.Lock()
		list := []TransferPolicy{}
		for _, p := range f.policies {
			list = append(list, p)
		}
		f.mu.Unlock()
		f.json(w, http.StatusOK, transferPoliciesResponse{Policies: list, Count: len(list)})
	})
	mux.HandleFunc("POST /v1/governance/transfer-policies/{policy_id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		f.mu.Lock()
		p, ok := f.policies[r.PathValue("policy_id")]
		if ok {
			delete(f.policies, p.ID)
		}
		f.mu.Unlock()
		if !ok {
			f.err(w, http.StatusNotFound, "transfer_policy_not_found")
			return
		}
		f.json(w, http.StatusOK, transferPolicyResponse{Policy: p})
	})

	mux.HandleFunc("POST /v1/governance/budgets", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		var req upsertBudgetRequest
		if !f.decode(w, r, &req) {
			return
		}
		b := BudgetPolicy{
			ID:                          "budget-1",
			ScopeType:                   req.ScopeType,
			AgentVersionID:              req.AgentVersionID,
			GrantID:                     req.GrantID,
			MaxActionsPerRun:            req.MaxActionsPerRun,
			MaxDeniedPerRun:             req.MaxDeniedPerRun,
			MaxApprovalRequiredPerRun:   req.MaxApprovalRequiredPerRun,
			MaxToolCallsPerActionPerRun: req.MaxToolCallsPerActionPerRun,
			MaxRunDurationSeconds:       req.MaxRunDurationSeconds,
			MaxCitationsPerQuery:        req.MaxCitationsPerQuery,
		}
		f.mu.Lock()
		f.budgets[b.ID] = b
		f.mu.Unlock()
		f.json(w, http.StatusOK, budgetResponse{Budget: b})
	})
	mux.HandleFunc("GET /v1/governance/budgets", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		f.mu.Lock()
		list := []BudgetPolicy{}
		for _, b := range f.budgets {
			list = append(list, b)
		}
		f.mu.Unlock()
		f.json(w, http.StatusOK, budgetsResponse{Budgets: list, Count: len(list)})
	})

	mux.HandleFunc("POST /v1/governance/connectors", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		var req connectorRegisterRequest
		if !f.decode(w, r, &req) {
			return
		}
		d := ConnectorDetail{
			Connector: Connector{ID: "conn-1", Name: req.Name, Type: req.Type, Lifecycle: "active"},
			Config:    req.Config,
			Actions:   req.Actions,
		}
		f.mu.Lock()
		f.connectors[d.Connector.ID] = d
		f.mu.Unlock()
		f.json(w, http.StatusCreated, connectorDetailResponse{Detail: d})
	})
	mux.HandleFunc("GET /v1/governance/connectors/{connector_id}", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		f.mu.Lock()
		d, ok := f.connectors[r.PathValue("connector_id")]
		f.mu.Unlock()
		if !ok {
			f.err(w, http.StatusNotFound, "connector_not_found")
			return
		}
		f.json(w, http.StatusOK, connectorDetailResponse{Detail: d})
	})
	mux.HandleFunc("POST /v1/governance/connectors/{connector_id}/config", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		var req connectorRegisterRequest
		if !f.decode(w, r, &req) {
			return
		}
		f.mu.Lock()
		d, ok := f.connectors[r.PathValue("connector_id")]
		if ok {
			d.Config = req.Config
			d.Actions = req.Actions
			f.connectors[d.Connector.ID] = d
		}
		f.mu.Unlock()
		if !ok {
			f.err(w, http.StatusNotFound, "connector_not_found")
			return
		}
		f.json(w, http.StatusOK, connectorDetailResponse{Detail: d})
	})
	mux.HandleFunc("POST /v1/governance/connectors/{connector_id}/activate", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		f.mu.Lock()
		d, ok := f.connectors[r.PathValue("connector_id")]
		if ok {
			d.Connector.Lifecycle = "active"
			f.connectors[d.Connector.ID] = d
		}
		f.mu.Unlock()
		if !ok {
			f.err(w, http.StatusNotFound, "connector_not_found")
			return
		}
		f.json(w, http.StatusOK, connectorDetailResponse{Detail: d})
	})
	mux.HandleFunc("POST /v1/governance/connectors/{connector_id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		f.mu.Lock()
		d, ok := f.connectors[r.PathValue("connector_id")]
		if ok {
			delete(f.connectors, d.Connector.ID)
		}
		f.mu.Unlock()
		if !ok {
			f.err(w, http.StatusNotFound, "connector_not_found")
			return
		}
		f.json(w, http.StatusOK, connectorDetailResponse{Detail: d})
	})

	mux.HandleFunc("POST /v1/agents", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		var req createAgentRequest
		if !f.decode(w, r, &req) {
			return
		}
		a := Agent{ID: "agent-1", Name: req.Name, RiskTier: req.RiskTier, Environment: req.Environment, LifecycleState: "pending"}
		f.mu.Lock()
		f.agents[a.ID] = a
		f.mu.Unlock()
		f.json(w, http.StatusCreated, agentResponse{Agent: a})
	})
	mux.HandleFunc("GET /v1/agents/{agent_id}", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		f.mu.Lock()
		a, ok := f.agents[r.PathValue("agent_id")]
		f.mu.Unlock()
		if !ok {
			f.err(w, http.StatusNotFound, "agent_not_found")
			return
		}
		f.json(w, http.StatusOK, agentResponse{Agent: a})
	})
	mux.HandleFunc("POST /v1/agents/{agent_id}/versions", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		var req addAgentVersionRequest
		if !f.decode(w, r, &req) {
			return
		}
		f.mu.Lock()
		a, ok := f.agents[r.PathValue("agent_id")]
		if ok {
			a.ActiveVersion = req.Version
			f.agents[a.ID] = a
		}
		f.mu.Unlock()
		if !ok {
			f.err(w, http.StatusNotFound, "agent_not_found")
			return
		}
		f.json(w, http.StatusOK, agentResponse{Agent: a})
	})
	mux.HandleFunc("POST /v1/agents/{agent_id}/activate", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		f.mu.Lock()
		a, ok := f.agents[r.PathValue("agent_id")]
		if ok {
			a.LifecycleState = "active"
			f.agents[a.ID] = a
		}
		f.mu.Unlock()
		if !ok {
			f.err(w, http.StatusNotFound, "agent_not_found")
			return
		}
		f.json(w, http.StatusOK, agentResponse{Agent: a})
	})
	mux.HandleFunc("POST /v1/agents/{agent_id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !f.auth(w, r) {
			return
		}
		f.mu.Lock()
		a, ok := f.agents[r.PathValue("agent_id")]
		if ok {
			delete(f.agents, a.ID)
		}
		f.mu.Unlock()
		if !ok {
			f.err(w, http.StatusNotFound, "agent_not_found")
			return
		}
		f.json(w, http.StatusOK, agentResponse{Agent: a})
	})

	return mux
}

// URL spins up an httptest server for the fake and returns its base
// URL. The server is cleaned up when the test finishes.
func (f *FakeRuntime) URL(t interface{ Cleanup(func()) }) string {
	srv := httptest.NewServer(f.Handler())
	t.Cleanup(srv.Close)
	return srv.URL
}

func (f *FakeRuntime) auth(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Groundwork-API-Key") != f.apiKey {
		f.err(w, http.StatusUnauthorized, "invalid_api_key")
		return false
	}
	return true
}

func (f *FakeRuntime) decode(w http.ResponseWriter, r *http.Request, out any) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		f.err(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	if err := json.Unmarshal(body, out); err != nil {
		f.err(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func (f *FakeRuntime) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *FakeRuntime) err(w http.ResponseWriter, status int, code string) {
	f.json(w, status, map[string]string{"error": code})
}
