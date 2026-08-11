// Phase 6 MCP governance-tool tests: the governance_* tools must mirror
// the REST surface's enforcement — reads are tenant-scoped, mutations
// require a verified identity, and the shared governance service
// records the same evidence. These run through the real dispatch path
// (tools/call) with a real governance service on a memory store.

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"groundwork/query-runtime/internal/engine"
	"groundwork/query-runtime/internal/governance"
	"groundwork/query-runtime/internal/runtime"

	"github.com/golang-jwt/jwt/v5"
)

// mcpPhase6Harness wires a real governance service with the builtin
// search tool + grant + root delegation (like mcpGovService) plus the
// Phase 6 trust/external/consent fixtures, and an MCP server.
type mcpPhase6Harness struct {
	svc      *governance.Service
	server   *Server
	relID    string
	extAgent runtime.ExternalAgent
	buf      bytes.Buffer
}

func newMCPPhase6Harness(t *testing.T) *mcpPhase6Harness {
	t.Helper()
	t.Setenv("GROUNDWORK_DELEGATION_HS_SECRET", "mcp-p6-delegation-hs-secret-32chars-min")
	t.Setenv("GROUNDWORK_JWT_HS_SECRET", "mcp-secret")
	authority, err := governance.BuildAuthority()
	if err != nil {
		t.Fatalf("BuildAuthority: %v", err)
	}
	verifier := adminVerifier{secret: "mcp-secret"}
	agents := &mcpFakeAgents{
		agent: runtime.Agent{
			ID: "agent-1", TenantID: mcpTenant, Name: "finance-reviewer",
			OwnerPrincipalID: "principal:alice", LifecycleState: runtime.AgentStateActive, ActiveVersionID: "version-1",
		},
		versions: []runtime.AgentVersion{{ID: "version-1", AgentID: "agent-1", Version: "1.0.0", Status: runtime.VersionStatusActive}},
	}
	svc := governance.NewService(governance.NewMemoryStore(), authority, mcpFakeChecker{}, agents)
	ctx := context.Background()

	// Base governed world: tool, action, grant, root delegation.
	tool, err := svc.RegisterTool(ctx, mcpTenant, "principal:alice", true, runtime.RegisterToolRequest{
		Name: runtime.BuiltinSearchTool, Description: "governed retrieval",
		Transport: runtime.ToolTransportBuiltin, OwnerPrincipalID: "principal:alice", Region: mcpRegion,
	})
	if err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}
	if _, err := svc.RegisterToolAction(ctx, mcpTenant, tool.ID, "principal:alice", true, runtime.RegisterToolActionRequest{
		Action: runtime.BuiltinSearchAction, ResourceType: "document", RiskLevel: runtime.RiskLevelLow, ReadOnly: true,
	}); err != nil {
		t.Fatalf("RegisterToolAction: %v", err)
	}
	if _, err := svc.TransitionTool(ctx, mcpTenant, tool.ID, "principal:alice", true, runtime.TransitionToolRequest{Lifecycle: runtime.ToolLifecycleActive}); err != nil {
		t.Fatalf("TransitionTool: %v", err)
	}
	_, actions, err := svc.GetTool(ctx, mcpTenant, tool.ID)
	if err != nil || len(actions) != 1 {
		t.Fatalf("GetTool: %v (%d)", err, len(actions))
	}
	if _, err := svc.GrantToolAccess(ctx, mcpTenant, "principal:alice", true, runtime.GrantToolRequest{
		AgentID: "agent-1", VersionID: "version-1", ToolID: tool.ID, ActionID: actions[0].ID,
	}); err != nil {
		t.Fatalf("GrantToolAccess: %v", err)
	}

	// Active trust relationship agent-1 -> agent-2.
	rel, err := svc.CreateTrustRelationship(ctx, mcpTenant, "principal:alice", true, runtime.TrustRelationshipRequest{
		ParentAgentID: "agent-1", ChildAgentID: "agent-2", TrustDomain: "finance",
		Purpose: "vendor reconciliation", MaxDelegationDepth: 2, Region: mcpRegion,
		ExpiresAt: "2026-12-31T23:59:59Z",
	})
	if err != nil {
		t.Fatalf("CreateTrustRelationship: %v", err)
	}
	if _, err := svc.TransitionTrustRelationship(ctx, mcpTenant, rel.ID, "principal:alice", true, "activate", runtime.TrustTransitionRequest{Reason: "go live"}); err != nil {
		t.Fatalf("activate trust: %v", err)
	}

	// External agent (OIDC, not gated).
	ext, err := svc.OnboardExternalAgent(ctx, mcpTenant, "principal:alice", true, runtime.ExternalAgentRequest{
		ExternalAgentID: "ext-mcp-1", AgentID: "agent-1", OrganizationID: "org-mcp",
		VerifiedIssuer: "https://issuer.mcp.example", AllowedAudiences: []string{"gw"},
		AuthMethod: runtime.ExternalAuthOIDC, TrustTier: runtime.TrustTierPartner, Region: mcpRegion,
	})
	if err != nil {
		t.Fatalf("OnboardExternalAgent: %v", err)
	}

	srv := NewServer(newTestEngine(), mcpTenant, mcpRegion, verifier, false)
	srv.SetGovernanceService(svc)
	h := &mcpPhase6Harness{svc: svc, server: srv, relID: rel.ID, extAgent: ext}
	h.server.writer = &h.buf
	return h
}

// call dispatches a tools/call JSON-RPC request through the MCP server's
// shared dispatch path (same code both stdio and /mcp use).
func (h *mcpPhase6Harness) call(t *testing.T, name string, args map[string]any) string {
	t.Helper()
	h.buf.Reset()
	params := map[string]any{"name": name, "arguments": args}
	raw, _ := json.Marshal(params)
	req := jsonrpcRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: raw}
	resp, ok := h.server.dispatch(context.Background(), mcpTenant, mcpRegion, "", "", req)
	if !ok {
		t.Fatalf("tools/call %s produced no response", name)
	}
	data, _ := json.Marshal(resp)
	return string(data)
}

// resultText extracts the tool result's text content from a JSON-RPC
// response.
func resultText(t *testing.T, out string) string {
	t.Helper()
	var resp struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("unmarshal response %q: %v", out, err)
	}
	if resp.Error != nil {
		return "RPC_ERROR: " + resp.Error.Message
	}
	if len(resp.Result.Content) == 0 {
		return ""
	}
	return resp.Result.Content[0].Text
}

// TestMCPGovernanceToolsRegistered proves the governance tools are
// advertised by tools/list.
func TestMCPGovernanceToolsRegistered(t *testing.T) {
	h := newMCPPhase6Harness(t)
	req := jsonrpcRequest{JSONRPC: "2.0", ID: 1, Method: "tools/list"}
	resp, ok := h.server.dispatch(context.Background(), mcpTenant, mcpRegion, "", "", req)
	if !ok {
		t.Fatalf("tools/list produced no response")
	}
	data, _ := json.Marshal(resp)
	if !strings.Contains(string(data), "governance_trust_relationship_list") ||
		!strings.Contains(string(data), "governance_external_agent_onboard") ||
		!strings.Contains(string(data), "governance_consent_create") ||
		!strings.Contains(string(data), "governance_transfer_policy_upsert") ||
		!strings.Contains(string(data), "governance_external_budget_upsert") ||
		!strings.Contains(string(data), "governance_delegation_chain") ||
		!strings.Contains(string(data), "governance_evidence_provenance") {
		t.Fatalf("governance tools missing from tools/list: %s", data)
	}
}

// TestMCPGovernanceReadsRequireNoIdentity proves read tools work
// without a user_token and are tenant-scoped.
func TestMCPGovernanceReadsRequireNoIdentity(t *testing.T) {
	h := newMCPPhase6Harness(t)

	out := h.call(t, "governance_trust_relationship_list", map[string]any{})
	text := resultText(t, out)
	if !strings.Contains(text, `"count":1`) || !strings.Contains(text, "finance") {
		t.Fatalf("trust list wrong: %s", text)
	}

	out = h.call(t, "governance_external_agent_list", map[string]any{})
	text = resultText(t, out)
	if !strings.Contains(text, "ext-mcp-1") {
		t.Fatalf("external agent list wrong: %s", text)
	}

	out = h.call(t, "governance_external_agent_get", map[string]any{"external_agent_id": "ext-mcp-1"})
	text = resultText(t, out)
	if !strings.Contains(text, "ext-mcp-1") || strings.Contains(text, "FAIL CLOSED") {
		t.Fatalf("external agent get wrong: %s", text)
	}
}

// TestMCPGovernanceMutationRequiresIdentity proves every mutation
// fails closed without a verified user_token — the MCP analog of
// requireVerifiedIdentity on REST.
func TestMCPGovernanceMutationRequiresIdentity(t *testing.T) {
	h := newMCPPhase6Harness(t)

	// Trust create without user_token -> fail closed, no state change.
	before, _ := h.svc.ListTrustRelationships(context.Background(), mcpTenant)
	out := h.call(t, "governance_trust_relationship_create", map[string]any{
		"parent_agent_id": "agent-1", "child_agent_id": "agent-3", "trust_domain": "d",
		"purpose": "p", "region": mcpRegion, "expires_at": "2026-12-31T23:59:59Z",
	})
	text := resultText(t, out)
	if !strings.Contains(text, "FAIL CLOSED") || !strings.Contains(text, "verified") {
		t.Fatalf("expected fail-closed without identity, got: %s", text)
	}
	after, _ := h.svc.ListTrustRelationships(context.Background(), mcpTenant)
	if len(after) != len(before) {
		t.Fatalf("mutation changed state without identity: %d -> %d", len(before), len(after))
	}

	// Consent create without user_token -> fail closed.
	out = h.call(t, "governance_consent_create", map[string]any{
		"organization_id": "org-mcp", "external_agent_id": "ext-mcp-1",
		"customer_principal_id": "cust-1", "purpose": "refunds",
	})
	if !strings.Contains(resultText(t, out), "FAIL CLOSED") {
		t.Fatalf("expected consent create to fail closed, got: %s", out)
	}
}

// adminVerifier verifies HS256 tokens and reports Admin=true, so the
// MCP admin-gated mutations can be exercised (mirrors the REST tests'
// testVerifier + admin API-key scope).
type adminVerifier struct{ secret string }

func (v adminVerifier) Verify(_ context.Context, token string) (runtime.Identity, error) {
	parsed, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(v.secret), nil
	}, jwt.WithExpirationRequired())
	if err != nil || !parsed.Valid {
		return runtime.Identity{}, errors.New("invalid token")
	}
	claims := parsed.Claims.(jwt.MapClaims)
	sub, _ := claims["sub"].(string)
	return runtime.Identity{UserID: sub, Subject: sub, Verified: true, Admin: true}, nil
}

// adminToken mints a verified identity token for the adminVerifier.
func adminToken(t *testing.T) string {
	t.Helper()
	return signMCP(t, "mcp-secret", "principal:alice")
}

// TestMCPGovernanceExternalAgentOnboardGate proves internal_demo stays
// gated (fail closed) over MCP even with a verified admin identity.
func TestMCPGovernanceExternalAgentOnboardGate(t *testing.T) {
	h := newMCPPhase6Harness(t)
	out := h.call(t, "governance_external_agent_onboard", map[string]any{
		"user_token": adminToken(t), "external_agent_id": "ext-demo",
		"agent_id": "agent-1", "organization_id": "org-1", "verified_issuer": "https://iss",
		"allowed_audiences": []string{"gw"}, "auth_method": "internal_demo", "region": mcpRegion,
	})
	text := resultText(t, out)
	if !strings.Contains(text, "FAIL CLOSED") || !strings.Contains(text, "demo") {
		t.Fatalf("expected internal_demo to fail closed, got: %s", text)
	}
}

// TestMCPGovernanceFullLifecycle drives the Phase 6 surface over MCP:
// trust transitions, consent create/revoke, transfer policy, budget,
// delegation chain read, and provenance read.
func TestMCPGovernanceFullLifecycle(t *testing.T) {
	h := newMCPPhase6Harness(t)
	tok := adminToken(t)

	// Suspend -> resume the trust relationship.
	out := h.call(t, "governance_trust_relationship_transition", map[string]any{
		"user_token": tok, "relationship_id": h.relID, "action": "suspend", "reason": "review",
	})
	if !strings.Contains(resultText(t, out), "suspended") {
		t.Fatalf("suspend failed: %s", resultText(t, out))
	}
	out = h.call(t, "governance_trust_relationship_transition", map[string]any{
		"user_token": tok, "relationship_id": h.relID, "action": "resume", "reason": "released",
	})
	if !strings.Contains(resultText(t, out), "active") {
		t.Fatalf("resume failed: %s", resultText(t, out))
	}

	// Consent create + list.
	out = h.call(t, "governance_consent_create", map[string]any{
		"user_token": tok, "organization_id": "org-mcp", "external_agent_id": "ext-mcp-1",
		"customer_principal_id": "cust-1", "purpose": "refunds",
	})
	if strings.Contains(resultText(t, out), "FAIL CLOSED") {
		t.Fatalf("consent create failed: %s", resultText(t, out))
	}
	var consentResp struct {
		Consent runtime.ConsentRecord `json:"consent"`
	}
	if err := json.Unmarshal([]byte(resultText(t, out)), &consentResp); err != nil {
		t.Fatalf("decode consent: %v (%s)", err, resultText(t, out))
	}
	out = h.call(t, "governance_consent_list", map[string]any{})
	if !strings.Contains(resultText(t, out), "cust-1") {
		t.Fatalf("consent list wrong: %s", resultText(t, out))
	}
	// Revoke.
	out = h.call(t, "governance_consent_revoke", map[string]any{
		"user_token": tok, "consent_id": consentResp.Consent.ID, "reason": "withdrew",
	})
	if !strings.Contains(resultText(t, out), "revoked") {
		t.Fatalf("consent revoke failed: %s", resultText(t, out))
	}

	// Transfer policy upsert + list.
	out = h.call(t, "governance_transfer_policy_upsert", map[string]any{
		"user_token": tok, "source_region": "eu-central-1", "target_region": "us-east-1",
		"purpose_pattern": "*", "enabled": true,
	})
	if strings.Contains(resultText(t, out), "FAIL CLOSED") {
		t.Fatalf("transfer policy upsert failed: %s", resultText(t, out))
	}
	out = h.call(t, "governance_transfer_policy_list", map[string]any{})
	if !strings.Contains(resultText(t, out), "eu-central-1") {
		t.Fatalf("transfer policy list wrong: %s", resultText(t, out))
	}

	// External budget upsert + list.
	out = h.call(t, "governance_external_budget_upsert", map[string]any{
		"user_token": tok, "scope_type": runtime.ExternalBudgetScopeAgent,
		"external_agent_id": "ext-mcp-1", "max_total_actions": 50,
	})
	if strings.Contains(resultText(t, out), "FAIL CLOSED") {
		t.Fatalf("external budget upsert failed: %s", resultText(t, out))
	}
	out = h.call(t, "governance_external_budget_list", map[string]any{})
	if !strings.Contains(resultText(t, out), `"max_total_actions":50`) {
		t.Fatalf("external budget list wrong: %s", resultText(t, out))
	}

	// Delegation chain read: mint a root grant first via the service.
	root, err := h.svc.MintDelegation(context.Background(), mcpTenant, mcpRegion, "agent-1", "principal:alice", true, "mcp-p6-chain",
		runtime.MintDelegationRequest{
			SubjectPrincipalID: "principal:bob", Purpose: "chain", PermittedActions: []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction},
		})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	out = h.call(t, "governance_delegation_chain", map[string]any{"grant_id": root.Grant.ID})
	if !strings.Contains(resultText(t, out), `"verified":true`) {
		t.Fatalf("delegation chain read wrong: %s", resultText(t, out))
	}
}

// TestMCPGovernanceEvidenceProvenance drives the provenance tool.
func TestMCPGovernanceEvidenceProvenance(t *testing.T) {
	h := newMCPPhase6Harness(t)
	page, err := h.svc.QueryEvidence(context.Background(), mcpTenant, runtime.EvidenceFilter{})
	if err != nil {
		t.Fatalf("QueryEvidence: %v", err)
	}
	if len(page.Events) == 0 {
		t.Fatalf("expected trust events from fixture setup")
	}
	// Trust events are EvidenceKindTrustEvent; provenance resolves them.
	first := page.Events[0]
	out := h.call(t, "governance_evidence_provenance", map[string]any{"evidence_id": first.EventID})
	text := resultText(t, out)
	if strings.Contains(text, "FAIL CLOSED") {
		t.Fatalf("provenance failed: %s", text)
	}
	if !strings.Contains(text, first.EventID) {
		t.Fatalf("provenance did not resolve event %s: %s", first.EventID, text)
	}
	if strings.Contains(text, "token") {
		t.Fatalf("provenance leaked raw material: %s", text)
	}
}

// TestMCPGovernanceUnknownToolFailsClosed proves a non-governance tool
// name is not silently dispatched.
func TestMCPGovernanceUnknownToolFailsClosed(t *testing.T) {
	h := newMCPPhase6Harness(t)
	req := jsonrpcRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call",
		Params: mustJSON(map[string]any{"name": "governance_not_a_tool", "arguments": map[string]any{}})}
	resp, ok := h.server.dispatch(context.Background(), mcpTenant, mcpRegion, "", "", req)
	if !ok {
		t.Fatalf("expected a response")
	}
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "unknown governance tool") {
		t.Fatalf("expected unknown-governance-tool error, got %+v", resp)
	}
}

func mustJSON(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

var _ = engine.Engine{} // keep engine import for the harness's engine type
