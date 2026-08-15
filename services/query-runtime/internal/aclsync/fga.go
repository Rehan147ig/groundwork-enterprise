package aclsync

import (
	"context"
	"strings"
	"sync"
)

// TupleSink is the write target for synced permissions. Production writes
// through the neutral relationship.Store sink (SpiceDB adapter); tests and
// local dev use MemoryTupleSink.
type TupleSink interface {
	ListTuples(ctx context.Context, tenantID string) ([]Tuple, error)
	WriteTuples(ctx context.Context, tenantID string, tuples []Tuple) error
	DeleteTuples(ctx context.Context, tenantID string, tuples []Tuple) error
}

// --- MemoryTupleSink: in-memory sink + checker (dev/test double) ---

// MemoryTupleSink is an in-memory tuple store that mirrors the Groundwork relationship model's
// resolution semantics (nested group membership + folder→document viewer inheritance).
// It is a development/test double: production feeds the\r?\n// relationship backend (SpiceDB) and enforces with the engine ACL adapter.\r?\n// MemoryTupleSink additionally implements runtime.ACLChecker so tests can\r?\n// drive the real engine.Execute path against synced tuples.
type MemoryTupleSink struct {
	mu       sync.RWMutex
	byTenant map[string]map[Tuple]bool
}

func NewMemoryTupleSink() *MemoryTupleSink {
	return &MemoryTupleSink{byTenant: map[string]map[Tuple]bool{}}
}

func (m *MemoryTupleSink) tenant(tenantID string) map[Tuple]bool {
	if m.byTenant[tenantID] == nil {
		m.byTenant[tenantID] = map[Tuple]bool{}
	}
	return m.byTenant[tenantID]
}

func (m *MemoryTupleSink) ListTuples(_ context.Context, tenantID string) ([]Tuple, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	set := m.byTenant[tenantID]
	out := make([]Tuple, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	return out, nil
}

func (m *MemoryTupleSink) WriteTuples(_ context.Context, tenantID string, tuples []Tuple) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := m.tenant(tenantID)
	for _, t := range tuples {
		set[t] = true
	}
	return nil
}

func (m *MemoryTupleSink) DeleteTuples(_ context.Context, tenantID string, tuples []Tuple) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := m.tenant(tenantID)
	for _, t := range tuples {
		delete(set, t)
	}
	return nil
}

// Check answers a relation query (mirrors the relationship model). Supported objects:
//
//	viewer document:D — direct viewer, group viewer, or inherited from parent folder
//	viewer folder:F   — direct viewer or group viewer
//	member group:G    — direct or nested group membership
func (m *MemoryTupleSink) Check(tenantID, user, relation, object string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	set := m.byTenant[tenantID]
	if set == nil {
		return false
	}
	switch {
	case relation == "viewer" && strings.HasPrefix(object, "document:"):
		return viewerDocument(set, user, object)
	case relation == "viewer" && strings.HasPrefix(object, "folder:"):
		return viewerFolder(set, user, object)
	case relation == "member" && strings.HasPrefix(object, "group:"):
		return memberOf(set, user, object, map[string]bool{})
	default:
		return false
	}
}

// CanAccess is provided separately (not on MemoryTupleSink) so this package
// keeps zero dependency on the runtime package: engine tests wrap
// MemoryTupleSink.Check with engine.ACLCheckFunc.

func memberOf(set map[Tuple]bool, user, group string, seen map[string]bool) bool {
	if seen[group] {
		return false
	}
	seen[group] = true
	if set[Tuple{user, "member", group}] {
		return true
	}
	// Nested: group:H#member member group  AND  user is a member of H.
	for t := range set {
		if t.Relation == "member" && t.Object == group && strings.HasPrefix(t.User, "group:") && strings.HasSuffix(t.User, "#member") {
			h := "group:" + strings.TrimSuffix(strings.TrimPrefix(t.User, "group:"), "#member")
			if memberOf(set, user, h, seen) {
				return true
			}
		}
	}
	return false
}

func viewerFolder(set map[Tuple]bool, user, folder string) bool {
	if set[Tuple{user, "viewer", folder}] {
		return true
	}
	for t := range set {
		if t.Relation == "viewer" && t.Object == folder && strings.HasSuffix(t.User, "#member") {
			g := "group:" + strings.TrimSuffix(strings.TrimPrefix(t.User, "group:"), "#member")
			if memberOf(set, user, g, map[string]bool{}) {
				return true
			}
		}
	}
	return false
}

func viewerDocument(set map[Tuple]bool, user, document string) bool {
	if set[Tuple{user, "viewer", document}] {
		return true
	}
	for t := range set {
		if t.Relation == "viewer" && t.Object == document && strings.HasSuffix(t.User, "#member") {
			g := "group:" + strings.TrimSuffix(strings.TrimPrefix(t.User, "group:"), "#member")
			if memberOf(set, user, g, map[string]bool{}) {
				return true
			}
		}
	}
	// Inherit viewers from the parent folder(s).
	for t := range set {
		if t.Relation == "parent" && t.Object == document && strings.HasPrefix(t.User, "folder:") {
			if viewerFolder(set, user, t.User) {
				return true
			}
		}
	}
	return false
}
