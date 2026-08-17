package client

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func testClient(t *testing.T) (*Client, *FakeRuntime) {
	t.Helper()
	fake := NewFakeRuntime()
	baseURL := fake.URL(t)
	c, err := New(Config{BaseURL: baseURL, APIKey: fake.APIKey()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, fake
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{APIKey: "k"}); err == nil {
		t.Error("expected error for missing base URL")
	}
	if _, err := New(Config{BaseURL: "http://insecure.example", APIKey: "k"}); err == nil {
		t.Error("expected error for non-https, non-loopback base URL")
	}
	if _, err := New(Config{BaseURL: "ftp://gw.example", APIKey: "k"}); err == nil {
		t.Error("expected error for non-http scheme")
	}
	if _, err := New(Config{BaseURL: "https://gw.example", APIKey: "  "}); err == nil {
		t.Error("expected error for blank API key")
	}
	c, err := New(Config{BaseURL: "https://gw.example", APIKey: "k"})
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	// Loopback hosts are the only tolerated plain-http targets.
	if _, err := New(Config{BaseURL: "http://localhost:8080", APIKey: "k"}); err != nil {
		t.Fatalf("loopback http rejected: %v", err)
	}
}

func TestIdempotencyKeyDeterministic(t *testing.T) {
	a := IdempotencyKey("tenant", "acme", "US", "enterprise")
	b := IdempotencyKey("tenant", "acme", "US", "enterprise")
	c := IdempotencyKey("tenant", "acme", "EU", "enterprise")
	if a != b {
		t.Fatal("same inputs must produce the same key")
	}
	if a == c {
		t.Fatal("different inputs must produce different keys")
	}
}

func TestTenantLifecycle(t *testing.T) {
	c, fake := testClient(t)

	ten, err := c.ProvisionTenant(context.Background(), "acme-prod", "US", "enterprise", "provisioned by test")
	if err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	if ten.TenantID != "acme-prod" || ten.Region != "US" || ten.Status != "active" {
		t.Fatalf("unexpected tenant: %+v", ten)
	}

	got, err := c.GetTenant(context.Background(), "acme-prod")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.Tier != "enterprise" {
		t.Fatalf("tier mismatch: %q", got.Tier)
	}

	if err := c.DeprovisionTenant(context.Background(), "acme-prod", "deprovisioned by test"); err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}
	if fake.TenantStatus("acme-prod") != "deprovisioned" {
		t.Fatalf("expected deprovisioned, got %q", fake.TenantStatus("acme-prod"))
	}
}

func TestTenantRegionConflictFailsClosed(t *testing.T) {
	c, _ := testClient(t)
	if _, err := c.ProvisionTenant(context.Background(), "acme-prod", "US", "", "first"); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	_, err := c.ProvisionTenant(context.Background(), "acme-prod", "EU", "", "second")
	var ae *Error
	if !errors.As(err, &ae) {
		t.Fatalf("expected client.Error, got %v", err)
	}
	if ae.StatusCode != http.StatusConflict || ae.Code != "region_conflict" {
		t.Fatalf("unexpected error: %+v", ae)
	}
}

func TestGrantLifecycle(t *testing.T) {
	c, _ := testClient(t)

	g, err := c.GrantToolAccess(context.Background(), GrantInput{
		AgentID:          "agent-1",
		VersionID:        "ver-1",
		ToolID:           "tool-1",
		ActionID:         "read",
		ResourceScope:    "acme-docs://*",
		RegionConstraint: "US",
		CallLimitPerRun:  10,
		RequiresApproval: true,
	})
	if err != nil {
		t.Fatalf("GrantToolAccess: %v", err)
	}
	if g.ID == "" || g.AgentID != "agent-1" || !g.RequiresApproval {
		t.Fatalf("unexpected grant: %+v", g)
	}

	got, err := c.GetGrant(context.Background(), "agent-1", g.ID)
	if err != nil {
		t.Fatalf("GetGrant: %v", err)
	}
	if got.ID != g.ID {
		t.Fatalf("grant id mismatch: %q != %q", got.ID, g.ID)
	}

	if err := c.RevokeGrant(context.Background(), g.ID, "revoked by test"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if _, err := c.GetGrant(context.Background(), "agent-1", g.ID); !IsNotFound(err) {
		t.Fatalf("expected not found after revoke, got %v", err)
	}
}

func TestTransferPolicyLifecycle(t *testing.T) {
	c, _ := testClient(t)

	p, err := c.UpsertTransferPolicy(context.Background(), PolicyInput{
		SourceRegion:   "US",
		TargetRegion:   "EU",
		PurposePattern: "*",
		Enabled:        true,
	})
	if err != nil {
		t.Fatalf("UpsertTransferPolicy: %v", err)
	}
	if p.ID == "" || !p.Enabled || p.SourceRegion != "US" {
		t.Fatalf("unexpected policy: %+v", p)
	}

	got, err := c.GetTransferPolicy(context.Background(), p.ID)
	if err != nil {
		t.Fatalf("GetTransferPolicy: %v", err)
	}
	if got.ID != p.ID {
		t.Fatalf("policy id mismatch")
	}

	if err := c.RevokeTransferPolicy(context.Background(), p.ID, "revoked by test"); err != nil {
		t.Fatalf("RevokeTransferPolicy: %v", err)
	}
	if _, err := c.GetTransferPolicy(context.Background(), p.ID); !IsNotFound(err) {
		t.Fatalf("expected not found after revoke, got %v", err)
	}
}

func TestBudgetLifecycle(t *testing.T) {
	c, _ := testClient(t)

	b, err := c.UpsertBudget(context.Background(), BudgetInput{
		ScopeType:                   "agent_version",
		AgentVersionID:              "ver-1",
		MaxActionsPerRun:            5,
		MaxRunDurationSeconds:       300,
		MaxToolCallsPerActionPerRun: 3,
	})
	if err != nil {
		t.Fatalf("UpsertBudget: %v", err)
	}
	if b.ID == "" || b.MaxActionsPerRun != 5 || b.ScopeType != "agent_version" {
		t.Fatalf("unexpected budget: %+v", b)
	}

	got, err := c.GetBudget(context.Background(), b.ID)
	if err != nil {
		t.Fatalf("GetBudget: %v", err)
	}
	if got.MaxRunDurationSeconds != 300 {
		t.Fatalf("duration mismatch: %+v", got)
	}

	zeroed, err := c.ZeroBudget(context.Background(), BudgetInput{
		ScopeType:      "agent_version",
		AgentVersionID: "ver-1",
	})
	if err != nil {
		t.Fatalf("ZeroBudget: %v", err)
	}
	if zeroed.MaxActionsPerRun != 0 || zeroed.MaxRunDurationSeconds != 0 || zeroed.MaxToolCallsPerActionPerRun != 0 {
		t.Fatalf("expected all-zero deprovisioned budget, got %+v", zeroed)
	}
}

func TestConnectorLifecycle(t *testing.T) {
	c, _ := testClient(t)

	detail, err := c.RegisterConnector(context.Background(), RegisterConnectorInput{
		Name: "prod-docs",
		Type: "confluence",
		Config: ConnectorConfig{
			BaseURL:   "https://wiki.example.com",
			Region:    "US",
			SecretRef: "keyring://confluence-prod",
			TLSVerify: true,
		},
		Actions: []ConnectorAction{
			{Name: "search", TransportMethod: "GET", PathTemplate: "/rest/api/search", Risk: "low", ReadOnly: true},
			{Name: "update_page", TransportMethod: "PUT", PathTemplate: "/rest/api/content/{id}", Risk: "high"},
		},
		Description: "prod confluence",
	})
	if err != nil {
		t.Fatalf("RegisterConnector: %v", err)
	}
	if detail.Connector.ID != "conn-1" || detail.Config.SecretRef != "keyring://confluence-prod" {
		t.Fatalf("unexpected detail: %+v", detail)
	}
	if len(detail.Actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(detail.Actions))
	}

	got, err := c.GetConnector(context.Background(), "conn-1")
	if err != nil {
		t.Fatalf("GetConnector: %v", err)
	}
	if got.Actions[1].Risk != "high" || !got.Actions[0].ReadOnly {
		t.Fatalf("unexpected actions: %+v", got.Actions)
	}

	updated, err := c.UpdateConnectorConfig(context.Background(), "conn-1", RegisterConnectorInput{
		Name: "prod-docs",
		Type: "confluence",
		Config: ConnectorConfig{
			BaseURL:   "https://wiki.example.com",
			Region:    "EU",
			SecretRef: "keyring://confluence-prod-eu",
		},
	})
	if err != nil {
		t.Fatalf("UpdateConnectorConfig: %v", err)
	}
	if updated.Config.Region != "EU" {
		t.Fatalf("expected region EU, got %q", updated.Config.Region)
	}

	if err := c.RevokeConnector(context.Background(), "conn-1", "revoked by test"); err != nil {
		t.Fatalf("RevokeConnector: %v", err)
	}
	if _, err := c.GetConnector(context.Background(), "conn-1"); !IsNotFound(err) {
		t.Fatalf("expected not found after revoke, got %v", err)
	}
}

func TestAgentLifecycle(t *testing.T) {
	c, _ := testClient(t)

	a, err := c.CreateAgent(context.Background(), CreateAgentInput{
		Name:             "support-agent",
		RiskTier:         "medium",
		Environment:      "production",
		BusinessPurpose:  "customer support triage",
		OwnerPrincipalID: "team-support",
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if a.ID == "" || a.LifecycleState != "pending" {
		t.Fatalf("unexpected agent: %+v", a)
	}

	if err := c.AddAgentVersion(context.Background(), a.ID, AddAgentVersionInput{
		Version:        "v1.0.0",
		ModelProvider:  "anthropic",
		ModelName:      "claude-sonnet-4-5",
		PromptDigest:   "sha256:abc",
		ArtifactDigest: "sha256:def",
	}); err != nil {
		t.Fatalf("AddAgentVersion: %v", err)
	}

	if _, err := c.ActivateAgent(context.Background(), a.ID, "activated by test"); err != nil {
		t.Fatalf("ActivateAgent: %v", err)
	}
	if fakeState := testClientLifecycle(t, c, a.ID); fakeState != "active" {
		t.Fatalf("expected active, got %q", fakeState)
	}

	if err := c.RevokeAgent(context.Background(), a.ID, "revoked by test"); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
	if _, err := c.GetAgent(context.Background(), a.ID); !IsNotFound(err) {
		t.Fatalf("expected not found after revoke, got %v", err)
	}
}

func testClientLifecycle(t *testing.T, c *Client, agentID string) string {
	t.Helper()
	a, err := c.GetAgent(context.Background(), agentID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	return a.LifecycleState
}

func TestUnauthorizedFailsClosed(t *testing.T) {
	fake := NewFakeRuntime()
	c, err := New(Config{BaseURL: fake.URL(t), APIKey: "wrong-key"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.GetTenant(context.Background(), "acme-prod")
	var ae *Error
	if !errors.As(err, &ae) {
		t.Fatalf("expected client.Error, got %v", err)
	}
	if ae.StatusCode != http.StatusUnauthorized || ae.Code != "invalid_api_key" {
		t.Fatalf("unexpected error: %+v", ae)
	}
}
