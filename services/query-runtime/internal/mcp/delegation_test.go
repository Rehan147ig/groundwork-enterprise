package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"groundwork/query-runtime/internal/engine"
	"groundwork/query-runtime/internal/governance"
	"groundwork/query-runtime/internal/relationship"
	"groundwork/query-runtime/internal/runtime"
)

const (
	mcpTenant  = "tenant_demo"
	mcpRegion  = "uk"
	mcpSubject = "principal:bob"
)

type mcpFakeAgents struct {
	agent    runtime.Agent
	versions []runtime.AgentVersion
}

func (f *mcpFakeAgents) GetAgent(context.Context, string, string) (runtime.Agent, []runtime.AgentVersion, []runtime.LifecycleEvent, error) {
	return f.agent, f.versions, nil, nil
}

func (f *mcpFakeAgents) ListVersions(context.Context, string, string) ([]runtime.AgentVersion, error) {
	return f.versions, nil
}

type mcpFakeChecker struct{}

func (mcpFakeChecker) Check(context.Context, relationship.CheckRequest) (bool, error) {
	return true, nil
}

func (mcpFakeChecker) Ready(context.Context) error { return nil }

// mcpGovService wires the REAL governance service (memory store +
// env-built authority) through the full governed flow: tool, action,
// grant, mint, run. Returns the service, the minted token, and the
// bound run id.
func mcpGovService(t *testing.T) (*governance.Service, string, string) {
	t.Helper()
	t.Setenv("GROUNDWORK_DELEGATION_HS_SECRET", "mcp-test-delegation-hs-secret-32chars-min")
	authority, err := governance.BuildAuthority()
	if err != nil {
		t.Fatalf("BuildAuthority: %v", err)
	}
	agents := &mcpFakeAgents{
		agent: runtime.Agent{
			ID: "agent-1", TenantID: mcpTenant, Name: "finance-reviewer",
			OwnerPrincipalID: "principal:alice", LifecycleState: runtime.AgentStateActive, ActiveVersionID: "version-1",
		},
		versions: []runtime.AgentVersion{{ID: "version-1", AgentID: "agent-1", Version: "1.0.0", Status: runtime.VersionStatusActive}},
	}
	svc := governance.NewService(governance.NewMemoryStore(), authority, mcpFakeChecker{}, agents)
	ctx := context.Background()

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
	minted, err := svc.MintDelegation(ctx, mcpTenant, mcpRegion, "agent-1", "principal:alice", true, "mint-mcp-1",
		runtime.MintDelegationRequest{
			SubjectPrincipalID: mcpSubject, Purpose: "quarterly review",
			PermittedActions: []string{runtime.BuiltinSearchTool + ":" + runtime.BuiltinSearchAction},
		})
	if err != nil {
		t.Fatalf("MintDelegation: %v", err)
	}
	run, err := svc.CreateRun(ctx, mcpTenant, mcpRegion, "run-mcp-1", runtime.CreateRunRequest{
		DelegationToken: minted.Token,
		Actions:         []runtime.RunActionRequest{{ToolName: runtime.BuiltinSearchTool, Action: runtime.BuiltinSearchAction, ResourceRef: "*"}},
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	return svc, minted.Token, run.Run.ID
}

// A delegation token on groundwork_search must run the engine as the
// delegation's subject principal — even when a forged raw user_id is
// also supplied (delegation supersedes end-user identity).
func TestMCPDelegationRunsAsSubjectPrincipal(t *testing.T) {
	svc, token, runID := mcpGovService(t)

	backend := runtime.NewMemoryBackend()
	rec := &recordingACL{}
	eng := &engine.Engine{
		Config: engine.TimeoutConfig{
			Total: 500 * 1000 * 1000, QdrantSearch: 100 * 1000 * 1000,
			ACLCheck: 150 * 1000 * 1000, AuditWrite: 50 * 1000 * 1000,
		},
		Backend: engine.VectorRetrievalClient{Vector: backend.Vector},
		ACL:     rec,
		Auditor: engine.RuntimeTraceAuditWriter{Trace: backend.Trace},
	}

	srv := NewServer(eng, mcpTenant, mcpRegion, nil, false)
	srv.SetGovernanceService(svc)
	var buf bytes.Buffer
	srv.writer = &buf

	args, _ := json.Marshal(map[string]string{
		"user_id": "attacker", "delegation_token": token, "run_id": runID, "question": aclQuestion,
	})
	srv.handleGroundworkSearch(context.Background(), 1, json.RawMessage(args))

	out := buf.String()
	if strings.Contains(out, "FAIL CLOSED") {
		t.Fatalf("delegated query must not fail closed, got: %s", out)
	}
	if !strings.Contains(out, "sharepoint-policy") {
		t.Fatalf("expected governed retrieval to return the document, got: %s", out)
	}
	if !rec.saw(mcpSubject) {
		t.Fatalf("engine must check the delegated subject, observed users=%v", rec.users)
	}
	if rec.saw("attacker") {
		t.Fatalf("delegation must supersede the raw user_id, observed users=%v", rec.users)
	}
}

// Without a wired governance service, a delegation token fails closed.
func TestMCPDelegationFailsClosedWithoutService(t *testing.T) {
	srv := NewServer(newTestEngine(), mcpTenant, mcpRegion, nil, false)
	var buf bytes.Buffer
	srv.writer = &buf

	args, _ := json.Marshal(map[string]string{
		"delegation_token": "anything", "run_id": "run-1", "question": aclQuestion,
	})
	srv.handleGroundworkSearch(context.Background(), 2, json.RawMessage(args))

	out := buf.String()
	if !strings.Contains(out, "FAIL CLOSED") || !strings.Contains(out, "governance_unavailable") {
		t.Fatalf("expected fail-closed governance_unavailable, got: %s", out)
	}
	if strings.Contains(out, "sharepoint-policy") {
		t.Fatalf("no document may be returned without a governance service, got: %s", out)
	}
}

// A delegation token without its bound run_id is a protocol error.
func TestMCPDelegationRequiresRunID(t *testing.T) {
	svc, token, _ := mcpGovService(t)
	srv := NewServer(newTestEngine(), mcpTenant, mcpRegion, nil, false)
	srv.SetGovernanceService(svc)
	var buf bytes.Buffer
	srv.writer = &buf

	args, _ := json.Marshal(map[string]string{"delegation_token": token, "question": aclQuestion})
	srv.handleGroundworkSearch(context.Background(), 3, json.RawMessage(args))

	if !strings.Contains(buf.String(), "run_id is required") {
		t.Fatalf("expected run_id protocol error, got: %s", buf.String())
	}
}

// A tampered/unknown token fails closed with no documents.
func TestMCPDelegationRejectsBadToken(t *testing.T) {
	svc, _, runID := mcpGovService(t)
	srv := NewServer(newTestEngine(), mcpTenant, mcpRegion, nil, false)
	srv.SetGovernanceService(svc)
	var buf bytes.Buffer
	srv.writer = &buf

	args, _ := json.Marshal(map[string]string{
		"delegation_token": "not-a-real-token", "run_id": runID, "question": aclQuestion,
	})
	srv.handleGroundworkSearch(context.Background(), 4, json.RawMessage(args))

	out := buf.String()
	if !strings.Contains(out, "FAIL CLOSED") {
		t.Fatalf("expected fail-closed on invalid token, got: %s", out)
	}
	if strings.Contains(out, "sharepoint-policy") {
		t.Fatalf("no document may be returned for an invalid delegation, got: %s", out)
	}
}
