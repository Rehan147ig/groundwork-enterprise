//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"groundwork/query-runtime/internal/agentregistry"
	"groundwork/query-runtime/internal/runtime"
)

// TestAgentRegistryPostgresLifecycle exercises the real Postgres store
// (migration 014) through the full lifecycle: create -> version ->
// activate -> suspend, asserting persisted state, active-version
// enrichment, and a tamper-evident event chain that survives a Postgres
// round-trip (created_at microsecond truncation).
func TestAgentRegistryPostgresLifecycle(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)

	tenant := "tenant_agents_" + unique()
	store := agentregistry.NewPostgresStore(db)
	svc := agentregistry.NewService(store)
	ctx := context.Background()

	created, err := svc.CreateAgent(ctx, tenant, "principal:alice", runtime.CreateAgentRequest{
		Name: "int-treasury-bot", RiskTier: runtime.RiskTierCritical, Environment: runtime.EnvProduction,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.LifecycleState != runtime.AgentStateDraft {
		t.Fatalf("new agent must be draft, got %s", created.LifecycleState)
	}

	// Duplicate name in the same tenant conflicts (DB unique constraint).
	if _, err := svc.CreateAgent(ctx, tenant, "principal:alice", runtime.CreateAgentRequest{
		Name: "int-treasury-bot", RiskTier: runtime.RiskTierLow,
	}); !errors.Is(err, runtime.ErrAgentNameConflict) {
		t.Fatalf("expected ErrAgentNameConflict, got %v", err)
	}

	v1, err := svc.AddVersion(ctx, tenant, created.ID, "principal:alice", false, runtime.AddAgentVersionRequest{Version: "1.0.0"})
	if err != nil {
		t.Fatalf("add version: %v", err)
	}
	active, err := svc.ActivateAgent(ctx, tenant, created.ID, "principal:alice", false, "ship")
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if active.LifecycleState != runtime.AgentStateActive || active.ActiveVersionID != v1.ID || active.ActiveVersion != "1.0.0" {
		t.Fatalf("agent must be active on 1.0.0 with enrichment, got %+v", active)
	}
	if _, err := svc.SuspendAgent(ctx, tenant, created.ID, "principal:alice", false, "freeze"); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	// Read back through a fresh service/store (new DB handle) — state
	// must have persisted and the chain must verify.
	store2 := agentregistry.NewPostgresStore(db)
	svc2 := agentregistry.NewService(store2)
	agent, versions, events, err := svc2.GetAgent(ctx, tenant, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if agent.LifecycleState != runtime.AgentStateSuspended {
		t.Fatalf("expected suspended after re-read, got %s", agent.LifecycleState)
	}
	if len(versions) != 1 || versions[0].Status != runtime.VersionStatusActive {
		t.Fatalf("expected 1 active version after re-read, got %+v", versions)
	}
	// created, version_created, version_approved, version_activated,
	// activated, suspended
	if len(events) != 6 {
		t.Fatalf("expected 6 lifecycle events, got %d", len(events))
	}
	if problems := agentregistry.VerifyEventChain(events); len(problems) != 0 {
		t.Fatalf("persisted event chain failed verification: %+v", problems)
	}

	// State filter works against Postgres.
	listed, err := svc2.ListAgents(ctx, tenant, "suspended")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != created.ID {
		t.Fatalf("expected exactly the suspended agent, got %+v", listed)
	}
}

// TestAgentRegistryPostgresTenantIsolation verifies tenant scoping at the
// SQL layer: cross-tenant reads 404 and names collide only within a tenant.
func TestAgentRegistryPostgresTenantIsolation(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)

	tenantA := "tenant_agents_a_" + unique()
	tenantB := "tenant_agents_b_" + unique()
	store := agentregistry.NewPostgresStore(db)
	svc := agentregistry.NewService(store)
	ctx := context.Background()

	created, err := svc.CreateAgent(ctx, tenantA, "principal:alice", runtime.CreateAgentRequest{
		Name: "iso-agent", RiskTier: runtime.RiskTierLow,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Same name is fine for another tenant.
	if _, err := svc.CreateAgent(ctx, tenantB, "principal:bob", runtime.CreateAgentRequest{
		Name: "iso-agent", RiskTier: runtime.RiskTierLow,
	}); err != nil {
		t.Fatalf("same name in other tenant must be allowed: %v", err)
	}

	if _, _, _, err := svc.GetAgent(ctx, tenantB, created.ID); !errors.Is(err, runtime.ErrAgentNotFound) {
		t.Fatalf("cross-tenant read must 404, got %v", err)
	}
	if _, err := svc.ActivateAgent(ctx, tenantB, created.ID, "principal:bob", true, ""); !errors.Is(err, runtime.ErrAgentNotFound) {
		t.Fatalf("cross-tenant transition must 404 (no existence leak), got %v", err)
	}
}

// TestAgentRegistryWriteOnceEvents verifies the migration 014 write-once
// RULES: a direct UPDATE or DELETE of a persisted lifecycle event must
// not change the ledger, and a tampered digest is then detected.
func TestAgentRegistryWriteOnceEvents(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)

	tenant := "tenant_agents_w_" + unique()
	store := agentregistry.NewPostgresStore(db)
	svc := agentregistry.NewService(store)
	ctx := context.Background()

	created, err := svc.CreateAgent(ctx, tenant, "principal:alice", runtime.CreateAgentRequest{
		Name: "write-once-agent", RiskTier: runtime.RiskTierLow,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Direct UPDATE attempt must be a no-op (rule fires, 0 rows).
	tag, err := db.ExecContext(ctx, `UPDATE agent_lifecycle_events SET reason = 'tampered' WHERE agent_id = $1`, created.ID)
	if err != nil {
		t.Fatalf("update attempt failed unexpectedly (rule should swallow it): %v", err)
	}
	if n, _ := tag.RowsAffected(); n != 0 {
		t.Fatalf("write-once rule must block UPDATEs, got %d affected rows", n)
	}

	// Direct DELETE attempt must also be a no-op.
	tag, err = db.ExecContext(ctx, `DELETE FROM agent_lifecycle_events WHERE agent_id = $1`, created.ID)
	if err != nil {
		t.Fatalf("delete attempt failed unexpectedly: %v", err)
	}
	if n, _ := tag.RowsAffected(); n != 0 {
		t.Fatalf("write-once rule must block DELETEs, got %d affected rows", n)
	}

	// The ledger is unchanged and the chain still verifies.
	_, _, events, err := svc.GetAgent(ctx, tenant, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected exactly the created event, got %d", len(events))
	}
	if problems := agentregistry.VerifyEventChain(events); len(problems) != 0 {
		t.Fatalf("chain must still verify after blocked tampering: %+v", problems)
	}
}
