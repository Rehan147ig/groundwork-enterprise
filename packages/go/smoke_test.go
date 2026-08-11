// Live smoke test mirroring packages/typescript/test/smoke.mjs and
// packages/python/test/smoke.py. Skips unless GW_BASE_URL is set.
//
// Requires the demo runtime on :18080 (ALLOW_DEMO_IDENTITY=true,
// ALLOW_MEMORY_API_KEYS=true, key gw_local_acme_key).
//
// Run with:  go test -count=1 -run TestLiveSmoke -v
package sdk

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

type smokeRunner struct {
	t    *testing.T
	pass int
	fail int
}

func (s *smokeRunner) check(label string, ok bool, extra string) {
	s.t.Logf("%s %s (%s)", passLabel(ok), label, extra)
	if ok {
		s.pass++
	} else {
		s.fail++
	}
}

func passLabel(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func TestLiveSmoke(t *testing.T) {
	baseURL := os.Getenv("GW_BASE_URL")
	if baseURL == "" {
		t.Skip("GW_BASE_URL not set; run with a demo runtime on :18080")
	}
	apiKey := os.Getenv("GW_API_KEY")
	if apiKey == "" {
		apiKey = "gw_local_acme_key"
	}
	ctx := context.Background()
	client := NewClient(ClientOptions{BaseURL: baseURL, APIKey: apiKey, Timeout: 15 * time.Second})
	s := &smokeRunner{t: t}
	uniq := time.Now().UnixMilli()

	// 1. healthz
	health, err := client.Health(ctx)
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	s.check("healthz returns ok", health.Status == "ok", health.Status)

	// 2. create agent (demo identity) -> {agent}
	risk := "low"
	agent, err := client.CreateAgent(ctx, CreateAgentRequest{
		Name:            fmt.Sprintf("sdk-smoke-agent-%d", uniq),
		BusinessPurpose: "live smoke test via groundwork/sdk (go)",
		RiskTier:        &risk,
	})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	s.check("create agent returns {agent}", agent.Agent.ID != "", shortID(agent.Agent.ID))

	// 3. list agents with count envelope
	list, err := client.ListAgents(ctx, "", "")
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	s.check("list agents has count envelope", list.Count >= 1, fmt.Sprintf("count=%d", list.Count))

	// 4. get agent detail envelope {agent, versions, lifecycle_events}
	detail, err := client.GetAgent(ctx, agent.Agent.ID)
	if err != nil {
		t.Fatalf("get agent: %v", err)
	}
	s.check("agent detail has agent/versions/lifecycle_events",
		detail.Agent.ID != "" && detail.Versions != nil && detail.LifecycleEvents != nil, "")

	// 4b. add a draft version
	versionRes, err := client.AddAgentVersion(ctx, agent.Agent.ID, AddAgentVersionRequest{
		Version: "1.0.0", ModelProvider: "acme", ModelName: "research-1",
		PromptDigest: "sha256:smoke-prompt", ToolManifestDigest: "sha256:smoke-manifest",
		PolicyBundleVersion: "2026.01", ArtifactDigest: "sha256:smoke-artifact",
	})
	if err != nil {
		t.Fatalf("add agent version: %v", err)
	}
	versionID := versionRes.Version.ID
	s.check("add agent version returns id", versionID != "", shortID(versionID))

	activated, err := client.ActivateAgent(ctx, agent.Agent.ID, "smoke activate")
	if err != nil {
		t.Fatalf("activate agent: %v", err)
	}
	s.check("activate agent returns active state", activated.Agent.LifecycleState == "active", activated.Agent.LifecycleState)

	// 5. register tool + action + grant
	tool, err := client.RegisterTool(ctx, RegisterToolRequest{
		Name: fmt.Sprintf("sdk-smoke-tool-%d", uniq), Description: "tool registered by the go SDK smoke test",
		Transport: "http", EndpointOrServer: "http://internal-service:8080",
		OwnerPrincipalID: "demo@groundwork.local", Region: "US",
	})
	if err != nil {
		t.Fatalf("register tool: %v", err)
	}
	s.check("register tool returns {tool}", tool.Tool.ID != "", shortID(tool.Tool.ID))

	actionRes, err := client.RegisterToolAction(ctx, tool.Tool.ID, RegisterToolActionRequest{
		Action: "read_health", ResourceType: "health", RiskLevel: "low",
		ReadOnly: true, RequiresHumanApproval: false,
	})
	if err != nil {
		t.Fatalf("register tool action: %v", err)
	}
	actionID := actionRes.Action.ID
	s.check("register tool action returns id", actionID != "", shortID(actionID))

	toolDetail, err := client.GetTool(ctx, tool.Tool.ID)
	if err != nil {
		t.Fatalf("get tool: %v", err)
	}
	s.check("tool detail has actions", len(toolDetail.Actions) == 1, fmt.Sprintf("actions=%d", len(toolDetail.Actions)))

	limit := 10
	grantRes, err := client.GrantTool(ctx, GrantToolRequest{
		AgentID: agent.Agent.ID, VersionID: versionID, ToolID: tool.Tool.ID, ActionID: actionID,
		ResourceScope: "*", RegionConstraint: "US", CallLimitPerRun: &limit,
	})
	if err != nil {
		t.Fatalf("grant tool: %v", err)
	}
	s.check("grant tool returns grant", grantRes.Grant.ID != "", shortID(grantRes.Grant.ID))

	agentGrants, err := client.ListAgentGrants(ctx, agent.Agent.ID)
	if err != nil {
		t.Fatalf("list agent grants: %v", err)
	}
	s.check("list agent grants has count", agentGrants.Count >= 1, fmt.Sprintf("count=%d", agentGrants.Count))

	tools, err := client.ListTools(ctx)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	s.check("list tools has count envelope", tools.Count >= 1, fmt.Sprintf("count=%d", tools.Count))

	// 5b. activate the tool, then exercise the policy simulator
	activatedTool, err := client.ToolLifecycle(ctx, tool.Tool.ID, TransitionToolRequest{Lifecycle: "active"})
	if err != nil {
		t.Fatalf("tool lifecycle: %v", err)
	}
	s.check("activate tool returns active lifecycle", activatedTool.Tool.Lifecycle == "active", activatedTool.Tool.Lifecycle)

	simAllowed, err := client.SimulateAction(ctx, SimulateActionRequest{
		AgentID: agent.Agent.ID, ToolName: tool.Tool.Name, Action: "read_health", ResourceRef: "health:check",
	})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	sim := simAllowed.Simulation
	s.check("simulate would-allow with simulated flag",
		sim.Allowed && sim.Decision == "allowed" && sim.Simulated,
		fmt.Sprintf("%s gates=%d", sim.Decision, len(sim.Checks)))
	grantGatePassed := false
	for _, c := range sim.Checks {
		if c.Gate == "grant" && c.Status == "passed" {
			grantGatePassed = true
		}
	}
	s.check("simulate explains grant gate as passed", grantGatePassed, fmt.Sprintf("gates=%d", len(sim.Checks)))

	simFailClosed, err := client.SimulateAction(ctx, SimulateActionRequest{
		AgentID: agent.Agent.ID, ToolName: tool.Tool.Name, Action: "read_health",
		ResourceRef: "health:check", PrincipalID: "principal:bob",
	})
	if err != nil {
		t.Fatalf("simulate (fail-closed): %v", err)
	}
	fc := simFailClosed.Simulation
	s.check("simulate fails closed without permission backend",
		!fc.Allowed && fc.Decision == "fail_closed", fmt.Sprintf("%s: %s", fc.Decision, fc.Reason))

	simNoGrant, err := client.SimulateAction(ctx, SimulateActionRequest{
		AgentID: agent.Agent.ID, ToolName: "unregistered-tool", Action: "read_health", ResourceRef: "health:check",
	})
	if err != nil {
		t.Fatalf("simulate (no grant): %v", err)
	}
	ng := simNoGrant.Simulation
	s.check("simulate denies unknown tool", !ng.Allowed && ng.Decision == "denied", fmt.Sprintf("%s: %s", ng.Decision, ng.Reason))

	// 6. emergency controls (read)
	controls, err := client.ListEmergencyControls(ctx)
	if err != nil {
		t.Fatalf("list emergency controls: %v", err)
	}
	s.check("list emergency controls", controls.Count >= 0, fmt.Sprintf("count=%d", controls.Count))

	// 7. budgets (read)
	budgets, err := client.ListBudgets(ctx)
	if err != nil {
		t.Fatalf("list budgets: %v", err)
	}
	s.check("list budgets", budgets.Count >= 0, fmt.Sprintf("count=%d", budgets.Count))

	// 8. evidence + outbox (read)
	evidence, err := client.QueryEvidence(ctx, EvidenceFilters{})
	if err != nil {
		t.Fatalf("query evidence: %v", err)
	}
	s.check("query evidence returns page", evidence.Count >= 0, fmt.Sprintf("events=%d", len(evidence.Events)))

	outbox, err := client.ListOutbox(ctx, OutboxFilters{})
	if err != nil {
		t.Fatalf("list outbox: %v", err)
	}
	s.check("list outbox returns page", outbox.Count >= 0, fmt.Sprintf("count=%d", outbox.Count))

	// 9. connectors (read)
	connectors, err := client.ListConnectors(ctx)
	if err != nil {
		t.Fatalf("list connectors: %v", err)
	}
	s.check("list connectors has count", connectors.Count >= 0, fmt.Sprintf("count=%d", connectors.Count))

	// 10. audit 503 in memory mode
	_, err = client.Audit(ctx, AuditFilters{Limit: 10})
	var gwErr *GroundworkError
	if err == nil {
		s.check("audit fails in memory mode", false, "expected 503")
	} else if asGroundworkError(err, &gwErr) {
		s.check("audit 503 audit_unavailable envelope", gwErr.Status == 503 && gwErr.Code == "audit_unavailable", fmt.Sprintf("%d %s", gwErr.Status, gwErr.Code))
	} else {
		s.check("audit 503 audit_unavailable envelope", false, fmt.Sprintf("%T: %v", err, err))
	}

	// 11. wrong key rejected
	bad := NewClient(ClientOptions{BaseURL: baseURL, APIKey: "wrong-key", Timeout: 5 * time.Second})
	_, err = bad.ListAgents(ctx, "", "")
	if err == nil {
		s.check("wrong key rejected 401", false, "expected 401")
	} else if asGroundworkError(err, &gwErr) {
		s.check("wrong key rejected 401", gwErr.Status == 401, fmt.Sprintf("%d %s", gwErr.Status, gwErr.Code))
	} else {
		s.check("wrong key rejected 401", false, fmt.Sprintf("%T: %v", err, err))
	}

	// 12. Phase 6 reads
	trust, err := client.ListTrustRelationships(ctx)
	if err != nil {
		t.Fatalf("list trust relationships: %v", err)
	}
	s.check("list trust relationships", trust.Count >= 0, fmt.Sprintf("count=%d", trust.Count))

	externalAgents, err := client.ListExternalAgents(ctx)
	if err != nil {
		t.Fatalf("list external agents: %v", err)
	}
	s.check("list external agents", externalAgents.Count >= 0, fmt.Sprintf("count=%d", externalAgents.Count))

	consents, err := client.ListConsents(ctx)
	if err != nil {
		t.Fatalf("list consents: %v", err)
	}
	s.check("list consents", consents.Count >= 0, fmt.Sprintf("count=%d", consents.Count))

	transferPolicies, err := client.ListTransferPolicies(ctx)
	if err != nil {
		t.Fatalf("list transfer policies: %v", err)
	}
	s.check("list transfer policies", transferPolicies.Count >= 0, fmt.Sprintf("count=%d", transferPolicies.Count))

	externalBudgets, err := client.ListExternalBudgets(ctx)
	if err != nil {
		t.Fatalf("list external budgets: %v", err)
	}
	s.check("list external budgets", externalBudgets.Count >= 0, fmt.Sprintf("count=%d", externalBudgets.Count))

	// 13. usage metering
	usage, err := client.GetUsage(ctx)
	if err != nil {
		t.Fatalf("get usage: %v", err)
	}
	s.check("get usage returns envelope with agents and runs",
		usage.TenantID != "" && usage.Usage != nil && hasUsage(usage.Usage, "agents", func(u MetricUsage) bool { return u.Count >= 1 }) && hasUsage(usage.Usage, "runs", func(u MetricUsage) bool { return u.Period == "monthly" }),
		fmt.Sprintf("metrics=%d", len(usage.Usage)))

	limits, err := client.GetUsageLimits(ctx)
	if err != nil {
		t.Fatalf("get usage limits: %v", err)
	}
	s.check("get usage limits returns envelope", limits.TenantID != "" && limits.Limits != nil, "")

	var agentCount int64
	for _, u := range usage.Usage {
		if u.Metric == "agents" && u.Period == "monthly" {
			agentCount = u.Count
		}
	}
	if _, err := client.PutUsageLimits(ctx, PutUsageLimitsRequest{
		Limits: []UsageLimit{{Metric: "agents", Period: "monthly", Limit: agentCount}},
	}, fmt.Sprintf("idem-usage-smoke-%d", uniq)); err != nil {
		t.Fatalf("put usage limits: %v", err)
	}
	_, err = client.CreateAgent(ctx, CreateAgentRequest{
		Name:            fmt.Sprintf("sdk-smoke-overquota-%d", uniq),
		BusinessPurpose: "should be blocked by quota",
	})
	if err == nil {
		s.check("agents quota blocks create", false, "expected 403")
	} else if asGroundworkError(err, &gwErr) {
		s.check("agents quota 403 quota_exceeded envelope", gwErr.Status == 403 && gwErr.Code == "quota_exceeded:agents", fmt.Sprintf("%d %s", gwErr.Status, gwErr.Code))
	} else {
		s.check("agents quota 403 quota_exceeded envelope", false, fmt.Sprintf("%T: %v", err, err))
	}
	if _, err := client.PutUsageLimits(ctx, PutUsageLimitsRequest{
		Limits: []UsageLimit{{Metric: "agents", Period: "monthly", Limit: 0}},
	}, fmt.Sprintf("idem-usage-clear-%d", uniq)); err != nil {
		t.Fatalf("clear usage limits: %v", err)
	}
	usageAfter, err := client.GetUsage(ctx)
	if err != nil {
		t.Fatalf("get usage (after): %v", err)
	}
	var agentsEntry MetricUsage
	for _, u := range usageAfter.Usage {
		if u.Metric == "agents" && u.Period == "monthly" {
			agentsEntry = u
		}
	}
	s.check("clearing agents limit restores unlimited", agentsEntry.Limit == 0 && agentsEntry.Remaining == -1, fmt.Sprintf("limit=%d remaining=%d", agentsEntry.Limit, agentsEntry.Remaining))

	if s.fail > 0 {
		t.Fatalf("SMOKE FAILED (%d failures, %d passed)", s.fail, s.pass)
	}
	t.Logf("SMOKE OK (%d checks)", s.pass)
}

func hasUsage(usage []MetricUsage, metric string, pred func(MetricUsage) bool) bool {
	for _, u := range usage {
		if u.Metric == metric && pred(u) {
			return true
		}
	}
	return false
}

func asGroundworkError(err error, out **GroundworkError) bool {
	gwErr, ok := err.(*GroundworkError)
	if ok {
		*out = gwErr
	}
	return ok
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
