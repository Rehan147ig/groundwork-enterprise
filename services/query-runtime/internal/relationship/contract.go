package relationship

import (
	"context"
	"testing"
)

// Backend is the fixture the contract suite exercises: a pairing of
// Authorizer + Store that MUST be backed by the same data (checks see
// what the store writes).
type Backend struct {
	Name  string
	Auth  Authorizer
	Store Store
	// TenantIsolation reports whether the backend physically scopes
	// tuples per tenant. The in-memory backend is intentionally
	// tenant-agnostic at the tuple layer (isolation comes from caller
	// guards + ID composition), so that capability is off for it and
	// on for SpiceDB (tenant-prefixed, escaped IDs).
	TenantIsolation bool
}

// ContractSuite is the shared conformance suite every authorization
// backend must pass. It is the acceptance gate for the SpiceDB adapter
// and the guard against regressions for the in-memory backend.
func ContractSuite(t *testing.T, b Backend) {
	t.Helper()
	t.Run(b.Name, func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		const tenantA = "tenant_a"
		const tenantB = "tenant_b"

		alice := UserRef("alice")
		bob := UserRef("bob")
		charlie := UserRef("charlie")
		dave := UserRef("dave")
		eng := GroupRef("eng")
		finance := GroupRef("finance")
		hr := GroupRef("hr")
		doc := DocumentRef("budget-2026")
		otherDoc := DocumentRef("roadmap-2026")
		folder := FolderRef("finance-folder")
		tool := ToolRef("github")
		action := ToolActionRef("github", "create_issue")

		seed := []Relationship{
			{Resource: doc, Relation: RelationViewer, Subject: alice},
			{Resource: doc, Relation: RelationViewer, Subject: eng},
			{Resource: folder, Relation: RelationViewer, Subject: alice},
			{Resource: folder, Relation: RelationViewer, Subject: finance},
			{Resource: otherDoc, Relation: RelationParent, Subject: SubjectRef{Type: TypeFolder, ID: "finance-folder"}},
			{Resource: ResourceRef{Type: TypeGroup, ID: "eng"}, Relation: RelationMember, Subject: bob},
			{Resource: ResourceRef{Type: TypeGroup, ID: "finance"}, Relation: RelationMember, Subject: hr},
			{Resource: ResourceRef{Type: TypeGroup, ID: "hr"}, Relation: RelationMember, Subject: alice},
			{Resource: tool, Relation: RelationUse, Subject: alice},
			{Resource: action, Relation: RelationExecute, Subject: alice},
		}

		// --- Store: write + list ---
		t.Run("write_idempotent_and_list", func(t *testing.T) {
			if err := b.Store.Write(ctx, tenantA, seed); err != nil {
				t.Fatalf("write: %v", err)
			}
			all, err := b.Store.List(ctx, tenantA, Filter{})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(all) < len(seed) {
				t.Fatalf("list: got %d relationships, want at least %d", len(all), len(seed))
			}
			// Idempotence: a second write of the same tuples must not
			// change the stored set. (Backends may hold additional
			// managed tuples — e.g. seeded default
			// memberships — so the check is relative, not absolute.)
			if err := b.Store.Write(ctx, tenantA, seed); err != nil {
				t.Fatalf("rewrite (idempotent): %v", err)
			}
			again, err := b.Store.List(ctx, tenantA, Filter{})
			if err != nil {
				t.Fatalf("list after rewrite: %v", err)
			}
			if len(again) != len(all) {
				t.Fatalf("list after idempotent double-write: got %d relationships, want %d", len(again), len(all))
			}
		})

		// --- Store: filters ---
		t.Run("list_filter", func(t *testing.T) {
			docs, err := b.Store.List(ctx, tenantA, Filter{ResourceType: TypeDocument})
			if err != nil {
				t.Fatalf("list documents: %v", err)
			}
			// 3 document tuples: 2 viewer grants on budget-2026 and the
			// folder-parent tuple on roadmap-2026.
			if len(docs) != 3 {
				t.Fatalf("document filter: got %d, want 3", len(docs))
			}
			viewers, err := b.Store.List(ctx, tenantA, Filter{ResourceType: TypeDocument, ResourceID: "budget-2026"})
			if err != nil {
				t.Fatalf("list doc viewers: %v", err)
			}
			if len(viewers) != 2 {
				t.Fatalf("doc viewer filter: got %d, want 2 (alice, eng)", len(viewers))
			}
			groupSubjects, err := b.Store.List(ctx, tenantA, Filter{SubjectType: TypeGroup})
			if err != nil {
				t.Fatalf("list group subjects: %v", err)
			}
			// eng (doc viewer), finance (folder viewer), hr (member of finance).
			if len(groupSubjects) != 3 {
				t.Fatalf("group-subject filter: got %d, want 3", len(groupSubjects))
			}
		})

		// --- Store: delete ---
		t.Run("delete_removes", func(t *testing.T) {
			grant := []Relationship{{Resource: doc, Relation: RelationViewer, Subject: dave}}
			if err := b.Store.Write(ctx, tenantA, grant); err != nil {
				t.Fatalf("write extra grant: %v", err)
			}
			if allowed, err := b.Auth.Check(ctx, CheckRequest{TenantID: tenantA, Subject: dave, Permission: PermissionView, Resource: doc}); err != nil || !allowed {
				t.Fatalf("dave should see document after grant (allowed=%v err=%v)", allowed, err)
			}
			if err := b.Store.Delete(ctx, tenantA, grant); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if allowed, _ := b.Auth.Check(ctx, CheckRequest{TenantID: tenantA, Subject: dave, Permission: PermissionView, Resource: doc}); allowed {
				t.Fatal("dave must not see document after delete")
			}
			if err := b.Store.Delete(ctx, tenantA, grant); err != nil {
				t.Fatalf("idempotent delete of missing tuple: %v", err)
			}
		})

		// --- Authorizer: direct grant ---
		t.Run("check_direct_grant", func(t *testing.T) {
			allowed, err := b.Auth.Check(ctx, CheckRequest{TenantID: tenantA, Subject: alice, Permission: PermissionView, Resource: doc})
			if err != nil || !allowed {
				t.Fatalf("alice viewer document: allowed=%v err=%v", allowed, err)
			}
		})

		// --- Authorizer: deny ---
		t.Run("check_deny", func(t *testing.T) {
			allowed, err := b.Auth.Check(ctx, CheckRequest{TenantID: tenantA, Subject: charlie, Permission: PermissionView, Resource: doc})
			if err != nil || allowed {
				t.Fatalf("charlie must not view document: allowed=%v err=%v", allowed, err)
			}
		})

		// --- Authorizer: group membership ---
		t.Run("check_group_member", func(t *testing.T) {
			// bob is a member of eng; eng#member is a viewer of the doc.
			allowed, err := b.Auth.Check(ctx, CheckRequest{TenantID: tenantA, Subject: bob, Permission: PermissionView, Resource: doc})
			if err != nil || !allowed {
				t.Fatalf("bob (eng member) viewer document: allowed=%v err=%v", allowed, err)
			}
		})

		// --- Authorizer: nested group membership ---
		t.Run("check_nested_group_member", func(t *testing.T) {
			// alice ∈ hr, hr ∈ finance, finance#member views the folder.
			allowed, err := b.Auth.Check(ctx, CheckRequest{TenantID: tenantA, Subject: alice, Permission: PermissionView, Resource: folder})
			if err != nil || !allowed {
				t.Fatalf("alice (hr⊂finance) viewer folder: allowed=%v err=%v", allowed, err)
			}
		})

		// --- Authorizer: folder inheritance ---
		t.Run("check_folder_inheritance", func(t *testing.T) {
			// otherDoc's parent folder grants alice viewer.
			allowed, err := b.Auth.Check(ctx, CheckRequest{TenantID: tenantA, Subject: alice, Permission: PermissionView, Resource: otherDoc})
			if err != nil || !allowed {
				t.Fatalf("alice viewer document via folder parent: allowed=%v err=%v", allowed, err)
			}
			// bob is not a folder viewer.
			allowed, err = b.Auth.Check(ctx, CheckRequest{TenantID: tenantA, Subject: bob, Permission: PermissionView, Resource: otherDoc})
			if err != nil || allowed {
				t.Fatalf("bob must not view document via folder parent: allowed=%v err=%v", allowed, err)
			}
		})

		// --- Authorizer: tool use / tool-action execute ---
		t.Run("check_tool_use_and_execute", func(t *testing.T) {
			allowed, err := b.Auth.Check(ctx, CheckRequest{TenantID: tenantA, Subject: alice, Permission: PermissionUse, Resource: tool})
			if err != nil || !allowed {
				t.Fatalf("alice use tool: allowed=%v err=%v", allowed, err)
			}
			allowed, err = b.Auth.Check(ctx, CheckRequest{TenantID: tenantA, Subject: alice, Permission: PermissionExecute, Resource: action})
			if err != nil || !allowed {
				t.Fatalf("alice execute action: allowed=%v err=%v", allowed, err)
			}
			allowed, err = b.Auth.Check(ctx, CheckRequest{TenantID: tenantA, Subject: bob, Permission: PermissionExecute, Resource: action})
			if err != nil || allowed {
				t.Fatalf("bob must not execute action: allowed=%v err=%v", allowed, err)
			}
		})

		// --- Authorizer: fail closed on empty/invalid requests ---
		t.Run("check_fails_closed_on_empty", func(t *testing.T) {
			cases := []CheckRequest{
				{TenantID: tenantA, Subject: SubjectRef{}, Permission: PermissionView, Resource: doc},
				{TenantID: tenantA, Subject: alice, Permission: "", Resource: doc},
				{TenantID: tenantA, Subject: alice, Permission: PermissionView, Resource: ResourceRef{}},
			}
			for i, c := range cases {
				allowed, _ := b.Auth.Check(ctx, c)
				if allowed {
					t.Fatalf("case %d: empty/invalid check must fail closed, got allowed", i)
				}
			}
		})

		// --- Authorizer: unknown permission denies ---
		t.Run("check_unknown_permission_denies", func(t *testing.T) {
			allowed, err := b.Auth.Check(ctx, CheckRequest{TenantID: tenantA, Subject: alice, Permission: "sudo", Resource: doc})
			if allowed {
				t.Fatalf("unknown permission must not grant (err=%v)", err)
			}
		})

		// --- Authorizer: permission alias view/viewer ---
		t.Run("check_permission_alias", func(t *testing.T) {
			allowed, err := b.Auth.Check(ctx, CheckRequest{TenantID: tenantA, Subject: alice, Permission: PermissionView, Resource: doc})
			if err != nil || !allowed {
				t.Fatalf("view permission on viewer grant: allowed=%v err=%v", allowed, err)
			}
		})

		// --- Tenant isolation ---
		t.Run("tenant_isolation", func(t *testing.T) {
			// Write a grant for tenant B; tenant A must never see it.
			intruder := UserRef("mallory")
			bGrant := []Relationship{{Resource: doc, Relation: RelationViewer, Subject: intruder}}
			if err := b.Store.Write(ctx, tenantB, bGrant); err != nil {
				t.Fatalf("write tenant B grant: %v", err)
			}
			allowed, err := b.Auth.Check(ctx, CheckRequest{TenantID: tenantA, Subject: intruder, Permission: PermissionView, Resource: doc})
			if err != nil {
				t.Fatalf("cross-tenant check error: %v", err)
			}
			if allowed && b.TenantIsolation {
				t.Fatal("cross-tenant grant must be invisible in tenant A")
			}
			// Within tenant B the grant works.
			allowed, err = b.Auth.Check(ctx, CheckRequest{TenantID: tenantB, Subject: intruder, Permission: PermissionView, Resource: doc})
			if err != nil || !allowed {
				t.Fatalf("same-tenant check: allowed=%v err=%v", allowed, err)
			}
		})

		// --- Ready ---
		t.Run("ready", func(t *testing.T) {
			if err := b.Auth.Ready(ctx); err != nil {
				t.Fatalf("ready: %v", err)
			}
		})
	})
}
