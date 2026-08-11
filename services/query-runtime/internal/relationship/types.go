// Package relationship defines the neutral authorization surface the
// Groundwork business logic consumes: typed subject/resource references,
// permission checks (Authorizer) and tuple persistence (Store).
//
// The package intentionally knows NOTHING about the concrete backend.
// Concrete backends live behind adapters (internal/relationship/spicedb
// today; an in-memory reference backend for dev/tests) and are wired only
// from the binaries (cmd/*). This is the seam that makes swapping the
// backend a wiring change: swapping means changing the adapter
// construction in cmd/*, not touching business logic.
//
// Semantics shared by every backend (enforced by the contract suite,
// contract_test.go):
//
//   - Authorizer.Check fails CLOSED: an empty/invalid request, an
//     unknown permission, or a backend error never grants access.
//   - Permissions are abstracted from storage relations: PermissionView
//     maps to the "viewer" relation, "use" and "execute" are identity
//     mappings. PermissionToRelation documents this 1:1.
//   - Store methods are tenant-scoped (tenantID is an explicit
//     parameter, so cross-tenant access is structurally impossible
//     through this API). Whether the backend enforces the scope
//     physically (SpiceDB tenant-prefixed IDs) or logically (memory
//     store with caller guards) is a backend capability divergence
//     documented in each adapter.
package relationship

import (
	"context"
	"errors"
)

// Type constants for subject and resource references.
const (
	TypeUser       = "user"
	TypeGroup      = "group"
	TypeFolder     = "folder"
	TypeDocument   = "document"
	TypeTool       = "tool"
	TypeToolAction = "tool_action"
)

// Relation constants are storage-relation names (SpiceDB today).
const (
	RelationMember  = "member"
	RelationViewer  = "viewer"
	RelationParent  = "parent"
	RelationUse     = "use"
	RelationExecute = "execute"
)

// Permission constants are the neutral permissions business logic asks
// about. They map 1:1 onto storage relations (see PermissionToRelation):
//
//	view    -> viewer   (document/folder viewer grant)
//	use     -> use      (delegated principal may invoke a tool)
//	execute -> execute  (delegated principal may run a write/destructive action)
const (
	PermissionView    = "view"
	PermissionUse     = "use"
	PermissionExecute = "execute"
)

// SubjectRef identifies a principal (or set of principals) that may hold
// a relation: a direct user ("user:abc") or a group set ("group:eng#member").
// Relation is empty for direct subjects; for group sets it is the
// computed userset relation (RelationMember).
type SubjectRef struct {
	Type     string
	ID       string
	Relation string
}

// ResourceRef identifies the object a relation is attached to. For
// tool actions the ID is the composite "<toolID>:<action>".
type ResourceRef struct {
	Type string
	ID   string
}

// CheckRequest asks whether subject holds permission on resource within
// a tenant. TenantID is always the caller's verified tenant — never a
// request-supplied identifier.
type CheckRequest struct {
	TenantID   string
	Subject    SubjectRef
	Permission string
	Resource   ResourceRef
}

// Relationship is a single grant tuple. Tenant scoping is a Store-method
// parameter (see Store), not a field, so a relationship cannot wander
// across tenants.
type Relationship struct {
	Resource ResourceRef
	Relation string
	Subject  SubjectRef
}

// Filter narrows a Store.List. Zero-value fields are wildcards; every
// non-empty field must match.
type Filter struct {
	ResourceType string
	ResourceID   string
	Relation     string
	SubjectType  string
	SubjectID    string
}

// Authorizer answers permission checks. Implementations must fail closed:
// errors and unknown permissions deny. Ready reports whether the backend
// is provisioned and reachable.
type Authorizer interface {
	Check(ctx context.Context, req CheckRequest) (bool, error)
	Ready(ctx context.Context) error
}

// Store persists and enumerates relationships. Write and Delete are
// idempotent (writing an existing tuple is a no-op; deleting a missing
// tuple is a no-op). Implementations must not invent cross-tenant
// behavior: tenantID scopes every operation.
type Store interface {
	Write(ctx context.Context, tenantID string, rels []Relationship) error
	Delete(ctx context.Context, tenantID string, rels []Relationship) error
	List(ctx context.Context, tenantID string, f Filter) ([]Relationship, error)
}

// Sentinel errors. Backend adapters wrap their transport errors with
// these so business logic and the contract suite can classify failures
// without knowing the backend.
var (
	// ErrBackendUnavailable means the backend could not be reached or
	// rejected the request; checks fail closed.
	ErrBackendUnavailable = errors.New("relationship: authorization backend unavailable")
	// ErrBackendTimeout means the backend did not answer in time.
	ErrBackendTimeout = errors.New("relationship: authorization backend timed out")
	// ErrModelMissing means the backend is reachable but the
	// authorization model/store is missing or stale.
	ErrModelMissing = errors.New("relationship: authorization model missing")
)

// UserRef builds a direct-user subject.
func UserRef(id string) SubjectRef { return SubjectRef{Type: TypeUser, ID: id} }

// GroupRef builds a group-set subject ("group:<id>#member").
func GroupRef(id string) SubjectRef {
	return SubjectRef{Type: TypeGroup, ID: id, Relation: RelationMember}
}

// DocumentRef builds a document resource reference.
func DocumentRef(id string) ResourceRef { return ResourceRef{Type: TypeDocument, ID: id} }

// FolderRef builds a folder resource reference.
func FolderRef(id string) ResourceRef { return ResourceRef{Type: TypeFolder, ID: id} }

// ToolRef builds a governed-tool resource reference.
func ToolRef(id string) ResourceRef { return ResourceRef{Type: TypeTool, ID: id} }

// ToolActionRef builds a tool-action resource reference. The ID is the
// composite "<toolID>:<action>" the authorization model uses.
func ToolActionRef(toolID, action string) ResourceRef {
	return ResourceRef{Type: TypeToolAction, ID: toolID + ":" + action}
}
