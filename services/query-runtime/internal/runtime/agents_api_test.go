package runtime_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundwork/query-runtime/internal/agentregistry"
	"groundwork/query-runtime/internal/runtime"

	"github.com/golang-jwt/jwt/v5"
)

// --- servers -------------------------------------------------------------

// testVerifier implements runtime.IdentityVerifier for tests: HS256,
// expiry required, "none" rejected — mirrors the production verifier.
// A `roles` claim is honored exactly like the OIDC verifier: an "admin"
// role value sets Identity.Admin, and the raw role list is preserved.
type testVerifier struct{ secret string }

func (v testVerifier) Verify(_ context.Context, token string) (runtime.Identity, error) {
	tok, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(v.secret), nil
	}, jwt.WithExpirationRequired())
	if err != nil || !tok.Valid {
		return runtime.Identity{}, errors.New("invalid token")
	}
	sub := claimSub(tok.Claims)
	roles := claimRoles(tok.Claims)
	admin := false
	for _, r := range roles {
		if r == "admin" {
			admin = true
		}
	}
	return runtime.Identity{UserID: sub, Subject: sub, Verified: true, Roles: roles, Admin: admin}, nil
}

func claimSub(claims jwt.Claims) string {
	if mc, ok := claims.(jwt.MapClaims); ok {
		if s, ok := mc["sub"].(string); ok {
			return s
		}
	}
	return ""
}

func claimRoles(claims jwt.Claims) []string {
	mc, ok := claims.(jwt.MapClaims)
	if !ok {
		return nil
	}
	raw, ok := mc["roles"].([]any)
	if !ok {
		return nil
	}
	var roles []string
	for _, item := range raw {
		if s, ok := item.(string); ok {
			roles = append(roles, s)
		}
	}
	return roles
}

// newAgentsServer builds a production-mode server (verified-identity
// required, demo identity OFF) with the real agent registry wired on a
// memory store. Every mutation must carry a valid JWT, exactly like prod.
func newAgentsServer(t *testing.T, store *agentregistry.MemoryStore, rawKey string, tenant runtime.TenantContext) *runtime.Server {
	t.Helper()
	backend := runtime.NewMemoryBackend()
	apiKeys := runtime.NewMemoryAPIKeyResolver(rawKey, tenant)
	s := runtime.NewServerWithExecutor(runtime.Config{}, backend, apiKeys, nil)
	s.SetAgentRegistry(agentregistry.NewService(store))
	s.SetIdentity(testVerifier{secret: "server-secret"}, false)
	return s
}

func newDemoAgentsServer(t *testing.T) *runtime.Server {
	t.Helper()
	return newAgentsServer(t, agentregistry.NewMemoryStore(), "gw_test_key", runtime.TenantContext{
		TenantID: "tenant_demo", Region: "uk", KeyName: "agents-test", Scopes: []string{"agents"},
	})
}

func tokenFor(t *testing.T, subject string) string {
	t.Helper()
	return agentSignHS256(t, "server-secret", subject)
}

// adminTokenFor signs a token carrying the admin role — the OIDC-mapped
// admin identity required by requireAdminIdentity-gated routes.
func adminTokenFor(t *testing.T, subject string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   subject,
		"roles": []string{"admin"},
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	signed, err := tok.SignedString([]byte("server-secret"))
	if err != nil {
		t.Fatalf("sign admin token: %v", err)
	}
	return signed
}

// agentSignHS256 signs an HS256 JWT with an exp claim (mirrors the
// runtime tests' signHS256 helper, which lives in package runtime).
func agentSignHS256(t *testing.T, secret, subject string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": subject,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// --- request helpers -----------------------------------------------------

func agentsRequest(method, path, key string, body string) *http.Request {
	var reader *bytes.Reader
	if body == "" {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("X-Groundwork-API-Key", key)
	return req
}

func agentsRequestAs(method, path, key, token, body string) (*http.Request, *httptest.ResponseRecorder) {
	req := agentsRequest(method, path, key, body)
	if token != "" {
		req.Header.Set("X-Groundwork-User-Assertion", token)
	}
	return req, httptest.NewRecorder()
}

func doAgents(t *testing.T, s *runtime.Server, method, path, key, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req, rec := agentsRequestAs(method, path, key, token, body)
	s.Routes().ServeHTTP(rec, req)
	return rec
}

func decodeAgent(t *testing.T, rec *httptest.ResponseRecorder) runtime.Agent {
	t.Helper()
	var resp runtime.AgentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode agent response %q: %v", rec.Body.String(), err)
	}
	return resp.Agent
}

func mustCreateAgent(t *testing.T, s *runtime.Server, key, token, body string) runtime.Agent {
	t.Helper()
	rec := doAgents(t, s, http.MethodPost, "/v1/agents", key, token, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create agent: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	return decodeAgent(t, rec)
}

// --- digest reimplementation (mirrors agentregistry.ComputeEventDigest;
// drift here fails the chain assertions, which is the point) ------------

func verifyChain(events []runtime.LifecycleEvent) []string {
	var problems []string
	prev := ""
	for i, e := range events {
		recomputed := computeEventDigest(e, prev)
		if recomputed != e.ImmutableDigest {
			problems = append(problems, "event "+e.ID+" at index "+itoa(i)+": digest mismatch")
		}
		prev = e.ImmutableDigest
	}
	return problems
}

func computeEventDigest(e runtime.LifecycleEvent, previousDigest string) string {
	e.ImmutableDigest = ""
	payload := strings.Join([]string{
		e.ID,
		e.TenantID,
		e.AgentID,
		e.AgentVersionID,
		e.ActorPrincipal,
		e.EventType,
		e.PreviousState,
		e.NewState,
		e.Reason,
		e.CreatedAt.UTC().Format(time.RFC3339Nano),
		previousDigest,
	}, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func itoa(n int) string {
	return time.Unix(int64(n), 0).UTC().String()
}

// --- tests ---------------------------------------------------------------

func TestAgentsAPI_RequiresAPIKey(t *testing.T) {
	server := newDemoAgentsServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/agents", nil)
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without API key, got %d", rec.Code)
	}
}

func TestAgentsAPI_RequiresAgentsScope(t *testing.T) {
	server := newAgentsServer(t, agentregistry.NewMemoryStore(), "gw_query_only", runtime.TenantContext{
		TenantID: "tenant_demo", Region: "uk", KeyName: "query-only", Scopes: []string{"query"},
	})
	rec := doAgents(t, server, http.MethodGet, "/v1/agents", "gw_query_only", "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 insufficient_scope, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAgentsAPI_UnavailableWhenUnset(t *testing.T) {
	backend := runtime.NewMemoryBackend()
	apiKeys := runtime.NewMemoryAPIKeyResolver("gw_test_key", runtime.TenantContext{
		TenantID: "tenant_demo", Region: "uk", Scopes: []string{"agents"},
	})
	server := runtime.NewServerWithExecutor(runtime.Config{}, backend, apiKeys, nil)
	// Registry intentionally NOT wired.

	rec := doAgents(t, server, http.MethodGet, "/v1/agents", "gw_test_key", "", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 agent_registry_unavailable, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAgentsAPI_FullLifecycleOverHTTP(t *testing.T) {
	server := newDemoAgentsServer(t)
	alice := tokenFor(t, "alice")

	agent := mustCreateAgent(t, server, "gw_test_key", alice,
		`{"name":"treasury-bot","risk_tier":"high","environment":"production","business_purpose":"reconcile daily cash"}`)
	if agent.LifecycleState != runtime.AgentStateDraft || agent.OwnerPrincipalID != "alice" {
		t.Fatalf("new agent must be draft owned by alice: %+v", agent)
	}
	if agent.TenantID != "tenant_demo" {
		t.Fatalf("tenant must come from the API key, got %s", agent.TenantID)
	}

	// Activating with no version fails with 400.
	rec := doAgents(t, server, http.MethodPost, "/v1/agents/"+agent.ID+"/activate", "gw_test_key", alice, `{"reason":"ship"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("activate with no version: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}

	// Register a version, then activate.
	rec = doAgents(t, server, http.MethodPost, "/v1/agents/"+agent.ID+"/versions", "gw_test_key", alice,
		`{"version":"1.0.0","model_provider":"anthropic","model_name":"claude-4"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add version: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = doAgents(t, server, http.MethodPost, "/v1/agents/"+agent.ID+"/activate", "gw_test_key", alice, `{"reason":"approved by risk"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("activate: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	activated := decodeAgent(t, rec)
	if activated.LifecycleState != runtime.AgentStateActive || activated.ActiveVersion != "1.0.0" || activated.ActivatedAt.IsZero() {
		t.Fatalf("agent must be active on 1.0.0: %+v", activated)
	}

	// List with state filter.
	rec = doAgents(t, server, http.MethodGet, "/v1/agents?state=active", "gw_test_key", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var list runtime.AgentListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if list.Count != 1 || len(list.Agents) != 1 || list.Agents[0].ActiveVersion != "1.0.0" {
		t.Fatalf("expected 1 active agent, got %+v", list)
	}

	// Detail shows the tamper-evident chain: created, version_created,
	// version_approved, version_activated, activated.
	rec = doAgents(t, server, http.MethodGet, "/v1/agents/"+agent.ID, "gw_test_key", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("detail: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var detail runtime.AgentDetailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if len(detail.Versions) != 1 || len(detail.LifecycleEvents) != 5 {
		t.Fatalf("expected 1 version and 5 events, got %d versions, %d events", len(detail.Versions), len(detail.LifecycleEvents))
	}
	if problems := verifyChain(detail.LifecycleEvents); len(problems) != 0 {
		t.Fatalf("event chain must verify: %+v", problems)
	}

	// Suspend, then revoke — revocation is terminal.
	rec = doAgents(t, server, http.MethodPost, "/v1/agents/"+agent.ID+"/suspend", "gw_test_key", alice, `{"reason":"freeze"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("suspend: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = doAgents(t, server, http.MethodPost, "/v1/agents/"+agent.ID+"/revoke", "gw_test_key", alice, `{"reason":"compromised key material"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	revoked := decodeAgent(t, rec)
	if revoked.LifecycleState != runtime.AgentStateRevoked || revoked.RevokedAt.IsZero() {
		t.Fatalf("agent must be revoked: %+v", revoked)
	}
	rec = doAgents(t, server, http.MethodPost, "/v1/agents/"+agent.ID+"/activate", "gw_test_key", alice, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("activate revoked: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAgentsAPI_TenantFromKeyNotBody(t *testing.T) {
	server := newDemoAgentsServer(t)
	alice := tokenFor(t, "alice")

	agent := mustCreateAgent(t, server, "gw_test_key", alice, `{"name":"forged-tenant","risk_tier":"low","tenant_id":"attacker"}`)
	if agent.TenantID != "tenant_demo" {
		t.Fatalf("tenant must come from the API key, got %q", agent.TenantID)
	}
}

func TestAgentsAPI_TenantIsolationAcrossServers(t *testing.T) {
	// Two tenants, one shared registry: tenant_other must never see
	// tenant_demo's agents.
	store := agentregistry.NewMemoryStore()
	serverA := newAgentsServer(t, store, "gw_test_key", runtime.TenantContext{
		TenantID: "tenant_demo", Region: "uk", KeyName: "agents-test", Scopes: []string{"agents"},
	})
	alice := tokenFor(t, "alice")
	agent := mustCreateAgent(t, serverA, "gw_test_key", alice, `{"name":"shared-registry-agent","risk_tier":"low"}`)

	serverB := newAgentsServer(t, store, "gw_other", runtime.TenantContext{
		TenantID: "tenant_other", Region: "eu", KeyName: "other", Scopes: []string{"agents"},
	})
	rec := doAgents(t, serverB, http.MethodGet, "/v1/agents/"+agent.ID, "gw_other", "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("tenant_other must 404 on tenant_demo agent, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = doAgents(t, serverB, http.MethodGet, "/v1/agents", "gw_other", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list for tenant_other: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var list runtime.AgentListResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if list.Count != 0 {
		t.Fatalf("tenant_other must see an empty registry, got %+v", list)
	}
}

func TestAgentsAPI_ProdModeFailsClosedWithoutVerifiedIdentity(t *testing.T) {
	server := newDemoAgentsServer(t)

	// No assertion -> 401.
	rec := doAgents(t, server, http.MethodPost, "/v1/agents", "gw_test_key", "", `{"name":"x","risk_tier":"low"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without identity assertion, got %d: %s", rec.Code, rec.Body.String())
	}

	// Invalid assertion -> 401.
	req, rec := agentsRequestAs(http.MethodPost, "/v1/agents", "gw_test_key", "", `{"name":"x","risk_tier":"low"}`)
	req.Header.Set("X-Groundwork-User-Assertion", agentSignHS256(t, "WRONG-secret", "alice"))
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on invalid JWT, got %d: %s", rec.Code, rec.Body.String())
	}

	// Valid assertion -> 201, owner = verified subject.
	rec = doAgents(t, server, http.MethodPost, "/v1/agents", "gw_test_key", tokenFor(t, "alice@corp.com"), `{"name":"real-agent","risk_tier":"low"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 with verified identity, got %d: %s", rec.Code, rec.Body.String())
	}
	agent := decodeAgent(t, rec)
	if agent.OwnerPrincipalID != "alice@corp.com" {
		t.Fatalf("owner must be the verified subject, got %s", agent.OwnerPrincipalID)
	}
}

func TestAgentsAPI_OwnerAuthorization(t *testing.T) {
	server := newDemoAgentsServer(t)
	alice := tokenFor(t, "alice")
	mallory := tokenFor(t, "mallory")

	agent := mustCreateAgent(t, server, "gw_test_key", alice, `{"name":"alice-agent","risk_tier":"medium"}`)

	// Mallory (verified, but not the owner, key not admin) cannot act.
	rec := doAgents(t, server, http.MethodPost, "/v1/agents/"+agent.ID+"/retire", "gw_test_key", mallory, `{"reason":"nope"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("mallory must get 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// Alice can.
	rec = doAgents(t, server, http.MethodPost, "/v1/agents/"+agent.ID+"/retire", "gw_test_key", alice, `{"reason":"done"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("alice must be allowed, got %d: %s", rec.Code, rec.Body.String())
	}
	if decodeAgent(t, rec).LifecycleState != runtime.AgentStateRetired {
		t.Fatalf("expected retired state, got %s", decodeAgent(t, rec).LifecycleState)
	}
}

func TestAgentsAPI_AdminScopeOverridesOwnership(t *testing.T) {
	// Admin-scoped key: the agents scope gate AND the owner check are
	// both overridden by hasScope's admin override.
	server := newAgentsServer(t, agentregistry.NewMemoryStore(), "gw_admin", runtime.TenantContext{
		TenantID: "tenant_demo", Region: "uk", KeyName: "admin-key", Scopes: []string{"admin"},
	})
	alice := tokenFor(t, "alice")

	agent := mustCreateAgent(t, server, "gw_admin", alice, `{"name":"admin-agent","risk_tier":"low"}`)

	// Bob, verified but not the owner, acts through the admin-scoped key.
	rec := doAgents(t, server, http.MethodPost, "/v1/agents/"+agent.ID+"/revoke", "gw_admin", tokenFor(t, "bob"), `{"reason":"policy"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin scope must override ownership, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAgentsAPI_ErrorEnvelopeAndUnknownAgent(t *testing.T) {
	server := newDemoAgentsServer(t)

	rec := doAgents(t, server, http.MethodGet, "/v1/agents/no-such-agent", "gw_test_key", "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
	var errResp runtime.AgentAPIError
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil || errResp.Error != runtime.ErrAgentNotFound.Error() {
		t.Fatalf("expected agent_not_found envelope, got %q (err=%v)", rec.Body.String(), err)
	}

	// Invalid JSON -> 400.
	rec = doAgents(t, server, http.MethodPost, "/v1/agents", "gw_test_key", tokenFor(t, "alice"), `{not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on bad JSON, got %d: %s", rec.Code, rec.Body.String())
	}

	// Duplicate name -> 409.
	mustCreateAgent(t, server, "gw_test_key", tokenFor(t, "alice"), `{"name":"dup-agent","risk_tier":"low"}`)
	rec = doAgents(t, server, http.MethodPost, "/v1/agents", "gw_test_key", tokenFor(t, "alice"), `{"name":"dup-agent","risk_tier":"low"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 on duplicate name, got %d: %s", rec.Code, rec.Body.String())
	}
}
