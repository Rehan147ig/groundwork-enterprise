package relationship

import (
	"context"
	"testing"
)

// TestMemoryBackendContract runs the shared conformance suite against
// the reference implementation.
func TestMemoryBackendContract(t *testing.T) {
	m := NewMemoryBackend()
	ContractSuite(t, Backend{
		Name:            "memory",
		Auth:            m,
		Store:           m,
		TenantIsolation: true,
	})
}

// TestMemoryBackendGroupToolSemantics pins the tool-relation semantics
// that are NOT covered by the shared suite: the model only accepts
// direct-user grants on tool relations, so the reference store rejects
// group grants at Write time and a group member is never granted tool
// use.
func TestMemoryBackendGroupToolSemantics(t *testing.T) {
	m := NewMemoryBackend()
	ctx := context.Background()
	eng := ResourceRef{Type: TypeGroup, ID: "eng"}
	tool := ToolRef("github")
	if err := m.Write(ctx, "t", []Relationship{
		{Resource: eng, Relation: RelationMember, Subject: UserRef("bob")},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := m.Write(ctx, "t", []Relationship{
		{Resource: tool, Relation: RelationUse, Subject: GroupRef("eng")},
	}); err == nil {
		t.Fatal("group grant on a tool relation must be rejected (direct users only)")
	}
	allowed, err := m.Check(ctx, CheckRequest{TenantID: "t", Subject: UserRef("bob"), Permission: PermissionUse, Resource: tool})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if allowed {
		t.Fatal("group membership must not grant tool use; only direct users may hold tool relations")
	}
}

// TestMemoryBackendNoPanicOnConcurrentUse is a light race guard: the
// reference implementation must be safe for concurrent checks and writes
// (the runtime checks documents and the acl-sync writer share it).
func TestMemoryBackendNoPanicOnConcurrentUse(t *testing.T) {
	m := NewMemoryBackend()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_ = m.Write(context.Background(), "t", []Relationship{
				{Resource: DocumentRef("d"), Relation: RelationViewer, Subject: UserRef("u")},
			})
		}
	}()
	for i := 0; i < 200; i++ {
		_, _ = m.Check(context.Background(), CheckRequest{TenantID: "t", Subject: UserRef("u"), Permission: PermissionView, Resource: DocumentRef("d")})
	}
	<-done
}
