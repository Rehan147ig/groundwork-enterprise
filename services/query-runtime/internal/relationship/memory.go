package relationship

import (
	"context"
	"fmt"
	"sync"
)

// tupleKey is the deduplicated storage form of a relationship. Subject
// and object are kept in tuple format so the memory backend's
// Check semantics match the production model byte-for-byte at the wire
// level.
type tupleKey struct {
	object   string
	relation string
	subject  string
}

// MemoryBackend is the reference Authorizer+Store implementation. It
// exists for three purposes:
//
//  1. The contract test target: the shared suite (contract_test.go)
//     asserts these exact semantics, and every real backend adapter must
//     pass the same suite.
//  2. The local/dev double used when no authorization backend is
//     configured (wired from cmd/* like a real backend).
//  3. A fixture for tests of business logic (governance, engine, ...)
//     that consume the neutral interfaces.
//
// It intentionally mirrors the SpiceDB authorization model so behavior
// matches production: group membership (with nesting), folder-parent
// inheritance of document viewers, and direct grants for tool use and
// tool-action execute.
type MemoryBackend struct {
	mu       sync.RWMutex
	byTenant map[string]map[tupleKey]struct{}
}

// NewMemoryBackend builds an empty MemoryBackend.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{byTenant: map[string]map[tupleKey]struct{}{}}
}

// Ready reports that the in-memory backend is always provisioned.
func (m *MemoryBackend) Ready(ctx context.Context) error { return nil }

// Check implements Authorizer. It fails closed on empty or invalid
// components, unknown permissions, and never panics. Tenant scoping is
// enforced at the map level. The read lock guards the recursive
// subjectHolds descent against concurrent Write/Delete mutation.
func (m *MemoryBackend) Check(ctx context.Context, req CheckRequest) (bool, error) {
	if err := ValidateSubject(req.Subject); err != nil {
		return false, nil
	}
	if err := ValidateResource(req.Resource); err != nil {
		return false, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.subjectHolds(req.TenantID, req.Subject, PermissionToRelation(req.Permission), req.Resource), nil
}

func (m *MemoryBackend) Write(ctx context.Context, tenantID string, rels []Relationship) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tenant := m.tenant(tenantID)
	for _, rel := range rels {
		if err := validateTuple(rel); err != nil {
			return err
		}
		tenant[tupleKey{EncodeObject(rel.Resource), rel.Relation, EncodeSubject(rel.Subject)}] = struct{}{}
	}
	return nil
}

// validateTuple mirrors the SpiceDB authorization model's
// directly_related_user_types constraints: tool and tool_action
// relations only accept direct users; group "member" accepts users and
// nested group sets; document "parent" accepts folders; viewer relations
// accept users and group sets. A backend that stores tuples outside
// these constraints would be impossible to check in the model.
func validateTuple(rel Relationship) error {
	if err := ValidateSubject(rel.Subject); err != nil {
		return err
	}
	if err := ValidateResource(rel.Resource); err != nil {
		return err
	}
	userOrGroupSet := func(s SubjectRef) bool {
		return s.Type == TypeUser || (s.Type == TypeGroup && s.Relation == RelationMember)
	}
	switch rel.Resource.Type {
	case TypeGroup:
		if rel.Relation != RelationMember || !userOrGroupSet(rel.Subject) {
			return fmt.Errorf("relationship: group %q accepts only %q relations from users/group sets", rel.Resource.ID, RelationMember)
		}
	case TypeDocument:
		switch rel.Relation {
		case RelationParent:
			if rel.Subject.Type != TypeFolder {
				return fmt.Errorf("relationship: document %q parent must be a folder subject", rel.Resource.ID)
			}
		case RelationViewer:
			if !userOrGroupSet(rel.Subject) {
				return fmt.Errorf("relationship: document %q viewer must be a user or group set", rel.Resource.ID)
			}
		default:
			return fmt.Errorf("relationship: unsupported relation %q on document %q", rel.Relation, rel.Resource.ID)
		}
	case TypeFolder:
		if rel.Relation != RelationViewer || !userOrGroupSet(rel.Subject) {
			return fmt.Errorf("relationship: folder %q accepts only viewer relations from users/group sets", rel.Resource.ID)
		}
	case TypeTool:
		if rel.Relation != RelationUse || rel.Subject.Type != TypeUser {
			return fmt.Errorf("relationship: tool %q accepts only use relations from direct users", rel.Resource.ID)
		}
	case TypeToolAction:
		if rel.Relation != RelationExecute || rel.Subject.Type != TypeUser {
			return fmt.Errorf("relationship: tool_action %q accepts only execute relations from direct users", rel.Resource.ID)
		}
	default:
		return fmt.Errorf("relationship: unsupported resource type %q", rel.Resource.Type)
	}
	return nil
}

func (m *MemoryBackend) Delete(ctx context.Context, tenantID string, rels []Relationship) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tenant, ok := m.byTenant[tenantID]
	if !ok {
		return nil
	}
	for _, rel := range rels {
		delete(tenant, tupleKey{EncodeObject(rel.Resource), rel.Relation, EncodeSubject(rel.Subject)})
	}
	return nil
}

func (m *MemoryBackend) List(ctx context.Context, tenantID string, f Filter) ([]Relationship, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tenant := m.byTenant[tenantID]
	var out []Relationship
	for key := range tenant {
		rel, err := key.relationship()
		if err != nil {
			continue
		}
		if f.ResourceType != "" && rel.Resource.Type != f.ResourceType {
			continue
		}
		if f.ResourceID != "" && rel.Resource.ID != f.ResourceID {
			continue
		}
		if f.Relation != "" && rel.Relation != f.Relation {
			continue
		}
		if f.SubjectType != "" && rel.Subject.Type != f.SubjectType {
			continue
		}
		if f.SubjectID != "" && rel.Subject.ID != f.SubjectID {
			continue
		}
		out = append(out, rel)
	}
	return out, nil
}

func (m *MemoryBackend) tenant(tenantID string) map[tupleKey]struct{} {
	tenant := m.byTenant[tenantID]
	if tenant == nil {
		tenant = map[tupleKey]struct{}{}
		m.byTenant[tenantID] = tenant
	}
	return tenant
}

func (k tupleKey) relationship() (Relationship, error) {
	res, err := ParseObject(k.object)
	if err != nil {
		return Relationship{}, err
	}
	subj, err := ParseSubject(k.subject)
	if err != nil {
		return Relationship{}, err
	}
	return Relationship{Resource: res, Relation: k.relation, Subject: subj}, nil
}

// subjectHolds implements the SpiceDB-model semantics for a single
// user-typed subject:
//
//   - direct: a tuple (subject, relation, object) exists;
//   - group set: a tuple (group:G#member, relation, object) exists and
//     the subject is a member of group G (nesting resolved recursively);
//   - folder inheritance: the object is a document with a
//     (folder:F, parent, document) tuple, and the subject holds the
//     relation on folder F.
//
// Subject types other than user/group (e.g. a folder used as a parent
// subject) can never satisfy a user check and are handled by the object
// side of inheritance instead.
func (m *MemoryBackend) subjectHolds(tenantID string, subj SubjectRef, relation string, res ResourceRef) bool {
	if subj.Type != TypeUser {
		return false
	}
	return m.userHolds(tenantID, subj.ID, relation, res, map[string]bool{})
}

func (m *MemoryBackend) userHolds(tenantID, userID, relation string, res ResourceRef, visited map[string]bool) bool {
	// Direct grant or group-set grant on the object itself.
	if m.subjectMatchesUser(tenantID, res, relation, userID, visited) {
		return true
	}
	// Folder-parent inheritance: document viewers are the union of the
	// document's own grants and its parent folder's grants.
	if res.Type == TypeDocument {
		for _, parent := range m.parents(tenantID, res.ID) {
			if m.userHolds(tenantID, userID, relation, parent, visited) {
				return true
			}
		}
	}
	return false
}

// subjectMatchesUser reports whether any tuple (subject S, relation R,
// object O) exists where S is the user or a group the user belongs to.
// Tool and tool_action relations only match direct-user subjects
// (mirroring the model's directly_related_user_types), so group grants
// can never leak tool permissions.
func (m *MemoryBackend) subjectMatchesUser(tenantID string, res ResourceRef, relation, userID string, visited map[string]bool) bool {
	tenant := m.byTenant[tenantID]
	object := EncodeObject(res)
	for key := range tenant {
		if key.object != object || key.relation != relation {
			continue
		}
		subj, err := ParseSubject(key.subject)
		if err != nil {
			continue
		}
		switch subj.Type {
		case TypeUser:
			if subj.ID == userID {
				return true
			}
		case TypeGroup:
			if res.Type == TypeTool || res.Type == TypeToolAction {
				continue
			}
			if subj.Relation == RelationMember && m.userIsMember(tenant, userID, subj.ID, visited) {
				return true
			}
		}
	}
	return false
}

// parents returns the folders that are direct parents of the document.
func (m *MemoryBackend) parents(tenantID, documentID string) []ResourceRef {
	tenant := m.byTenant[tenantID]
	docObject := EncodeObject(ResourceRef{Type: TypeDocument, ID: documentID})
	var out []ResourceRef
	for key := range tenant {
		if key.object != docObject || key.relation != RelationParent {
			continue
		}
		subj, err := ParseSubject(key.subject)
		if err != nil || subj.Type != TypeFolder {
			continue
		}
		out = append(out, FolderRef(subj.ID))
	}
	return out
}

// userIsMember reports whether the user is a member of the group,
// directly ("user:U member group:G") or transitively
// ("group:H#member member group:G" with the user a member of H).
func (m *MemoryBackend) userIsMember(tenant map[tupleKey]struct{}, userID, groupID string, visited map[string]bool) bool {
	key := userID + "@" + groupID
	if visited[key] {
		return false
	}
	visited[key] = true
	groupObject := EncodeObject(ResourceRef{Type: TypeGroup, ID: groupID})
	for k := range tenant {
		if k.object != groupObject || k.relation != RelationMember {
			continue
		}
		subj, err := ParseSubject(k.subject)
		if err != nil {
			continue
		}
		switch subj.Type {
		case TypeUser:
			if subj.ID == userID {
				return true
			}
		case TypeGroup:
			if subj.Relation == RelationMember && m.userIsMember(tenant, userID, subj.ID, visited) {
				return true
			}
		}
	}
	return false
}

var (
	_ Authorizer = (*MemoryBackend)(nil)
	_ Store      = (*MemoryBackend)(nil)
)
