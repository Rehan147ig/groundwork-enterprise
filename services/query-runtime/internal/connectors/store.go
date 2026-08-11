package connectors

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// Store is the tenant-scoped connector registry: connectors, immutable
// config versions, manifest actions, and the hash-chained lifecycle
// audit trail. Invocation outcome evidence is owned by the governance
// service (single evidence chain), not this store.
type Store interface {
	CreateConnector(ctx context.Context, c runtime.Connector, version runtime.ConnectorVersion, actions []runtime.ConnectorActionManifest, event runtime.ConnectorLifecycleEvent) error
	ListConnectors(ctx context.Context, tenantID string) ([]runtime.Connector, error)
	// ListAllConnectors spans tenants (operator/observability only:
	// the Phase 8.5 credential-expiry monitor iterates the whole
	// registry). Never exposed through tenant-scoped handlers.
	ListAllConnectors(ctx context.Context) ([]runtime.Connector, error)
	GetConnector(ctx context.Context, tenantID, connectorID string) (runtime.Connector, error)
	GetConnectorByName(ctx context.Context, tenantID, name string) (runtime.Connector, error)
	// TransitionConnector moves lifecycle from -> to atomically (serialized
	// per connector) and appends the hash-chained lifecycle event.
	TransitionConnector(ctx context.Context, tenantID, connectorID, from, to, actor, reason string) (runtime.Connector, error)
	// UpdateVersion appends a new immutable config version + action set,
	// repoints the connector, and records the config_update event.
	UpdateVersion(ctx context.Context, c runtime.Connector, version runtime.ConnectorVersion, actions []runtime.ConnectorActionManifest, event runtime.ConnectorLifecycleEvent) error
	GetCurrentVersion(ctx context.Context, tenantID, connectorID string) (runtime.ConnectorVersion, error)
	GetActions(ctx context.Context, tenantID, connectorID, versionID string) ([]runtime.ConnectorActionManifest, error)
	ListLifecycleEvents(ctx context.Context, tenantID, connectorID string) ([]runtime.ConnectorLifecycleEvent, error)
}

// memoryConnector is the in-memory registry row (runtime.Connector plus
// version + actions kept together for atomic access under the mutex).
type memoryConnector struct {
	conn     runtime.Connector
	versions []runtime.ConnectorVersion
	actions  map[string][]runtime.ConnectorActionManifest // versionID -> actions
	events   []runtime.ConnectorLifecycleEvent
}

// MemoryStore is the dev/test registry. Transitions are serialized by
// the store mutex.
type MemoryStore struct {
	mu    sync.Mutex
	now   func() time.Time
	conns map[string]map[string]*memoryConnector // tenantID -> id -> connector
}

// NewMemoryStore builds an empty in-memory registry.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{now: time.Now, conns: map[string]map[string]*memoryConnector{}}
}

func (m *MemoryStore) CreateConnector(_ context.Context, c runtime.Connector, v runtime.ConnectorVersion, actions []runtime.ConnectorActionManifest, ev runtime.ConnectorLifecycleEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conns[c.TenantID] == nil {
		m.conns[c.TenantID] = map[string]*memoryConnector{}
	}
	for _, other := range m.conns[c.TenantID] {
		if other.conn.Name == c.Name {
			return runtime.ErrConnectorNameConflict
		}
	}
	mc := &memoryConnector{conn: c, actions: map[string][]runtime.ConnectorActionManifest{}}
	mc.versions = []runtime.ConnectorVersion{v}
	mc.actions[v.ID] = SortedActions(actions)
	ev = makeLifecycleEvent(c, "create", "", runtime.ConnectorLifecycleDraft, ev.ActorPrincipalID, ev.Reason, ev.CreatedAt, "")
	mc.events = []runtime.ConnectorLifecycleEvent{ev}
	m.conns[c.TenantID][c.ID] = mc
	return nil
}

func (m *MemoryStore) ListConnectors(_ context.Context, tenantID string) ([]runtime.Connector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []runtime.Connector
	for _, mc := range m.conns[tenantID] {
		out = append(out, mc.conn)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *MemoryStore) ListAllConnectors(_ context.Context) ([]runtime.Connector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []runtime.Connector
	for _, byID := range m.conns {
		for _, mc := range byID {
			out = append(out, mc.conn)
		}
	}
	return out, nil
}

func (m *MemoryStore) GetConnector(_ context.Context, tenantID, connectorID string) (runtime.Connector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mc, ok := m.conns[tenantID][connectorID]
	if !ok {
		return runtime.Connector{}, runtime.ErrConnectorNotFound
	}
	return mc.conn, nil
}

func (m *MemoryStore) GetConnectorByName(_ context.Context, tenantID, name string) (runtime.Connector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, mc := range m.conns[tenantID] {
		if mc.conn.Name == name {
			return mc.conn, nil
		}
	}
	return runtime.Connector{}, runtime.ErrConnectorNotFound
}

func (m *MemoryStore) TransitionConnector(_ context.Context, tenantID, connectorID, from, to, actor, reason string) (runtime.Connector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mc, ok := m.conns[tenantID][connectorID]
	if !ok {
		return runtime.Connector{}, runtime.ErrConnectorNotFound
	}
	if mc.conn.Lifecycle != from {
		return runtime.Connector{}, runtime.ErrConnectorInvalidState
	}
	if !isValidTransition(from, to) {
		return runtime.Connector{}, runtime.ErrConnectorInvalidState
	}
	mc.conn.Lifecycle = to
	mc.conn.UpdatedAt = m.now().UTC()
	ev := makeLifecycleEvent(mc.conn, lifecycleActionType(from, to), from, to, actor, reason, m.now().UTC(), lastDigest(mc.events))
	mc.events = append(mc.events, ev)
	return mc.conn, nil
}

func (m *MemoryStore) UpdateVersion(_ context.Context, c runtime.Connector, v runtime.ConnectorVersion, actions []runtime.ConnectorActionManifest, ev runtime.ConnectorLifecycleEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	mc, ok := m.conns[c.TenantID][c.ID]
	if !ok {
		return runtime.ErrConnectorNotFound
	}
	mc.versions = append(mc.versions, v)
	mc.actions[v.ID] = SortedActions(actions)
	mc.conn = c
	mc.conn.UpdatedAt = m.now().UTC()
	mc.events = append(mc.events, makeLifecycleEvent(mc.conn, "config_update", mc.conn.Lifecycle, mc.conn.Lifecycle, ev.ActorPrincipalID, ev.Reason, m.now().UTC(), lastDigest(mc.events)))
	return nil
}

func (m *MemoryStore) GetCurrentVersion(_ context.Context, tenantID, connectorID string) (runtime.ConnectorVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mc, ok := m.conns[tenantID][connectorID]
	if !ok {
		return runtime.ConnectorVersion{}, runtime.ErrConnectorNotFound
	}
	if len(mc.versions) == 0 {
		return runtime.ConnectorVersion{}, runtime.ErrConnectorNoManifest
	}
	return mc.versions[len(mc.versions)-1], nil
}

func (m *MemoryStore) GetActions(_ context.Context, tenantID, connectorID, versionID string) ([]runtime.ConnectorActionManifest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mc, ok := m.conns[tenantID][connectorID]
	if !ok {
		return nil, runtime.ErrConnectorNotFound
	}
	actions, ok := mc.actions[versionID]
	if !ok {
		return nil, runtime.ErrConnectorNoManifest
	}
	return actions, nil
}

func (m *MemoryStore) ListLifecycleEvents(_ context.Context, tenantID, connectorID string) ([]runtime.ConnectorLifecycleEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mc, ok := m.conns[tenantID][connectorID]
	if !ok {
		return nil, runtime.ErrConnectorNotFound
	}
	out := make([]runtime.ConnectorLifecycleEvent, len(mc.events))
	copy(out, mc.events)
	return out, nil
}

// makeLifecycleEvent builds a hash-chained lifecycle event: the digest
// covers the event's security-relevant fields plus the previous event's
// digest, so edits, deletion, reordering, or insertion break the chain.
func makeLifecycleEvent(conn runtime.Connector, actionType, from, to, actor, reason string, at time.Time, prevDigest string) runtime.ConnectorLifecycleEvent {
	ev := runtime.ConnectorLifecycleEvent{
		ID:               fmt.Sprintf("cle-%s-%d", conn.ID[:8], at.UnixNano()),
		TenantID:         conn.TenantID,
		ConnectorID:      conn.ID,
		ActionType:       actionType,
		FromState:        from,
		ToState:          to,
		ActorPrincipalID: actor,
		Reason:           reason,
		CreatedAt:        at,
	}
	ev.ImmutableDigest = ConnectorLifecycleDigest(ev.TenantID, ev.ConnectorID, ev.ActionType, ev.FromState, ev.ToState, ev.ActorPrincipalID, ev.Reason, prevDigest)
	return ev
}

func lastDigest(events []runtime.ConnectorLifecycleEvent) string {
	if len(events) > 0 {
		return events[len(events)-1].ImmutableDigest
	}
	return ""
}

func lifecycleActionType(from, to string) string {
	switch {
	case from == runtime.ConnectorLifecycleDraft && to == runtime.ConnectorLifecycleActive:
		return "activate"
	case from == runtime.ConnectorLifecycleActive && to == runtime.ConnectorLifecycleSuspended:
		return "suspend"
	case from == runtime.ConnectorLifecycleSuspended && to == runtime.ConnectorLifecycleActive:
		return "activate"
	case to == runtime.ConnectorLifecycleRevoked:
		return "revoke"
	case to == runtime.ConnectorLifecycleRetired:
		return "retire"
	}
	return "transition"
}
