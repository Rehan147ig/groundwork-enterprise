package agentregistry

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"groundwork/query-runtime/internal/runtime"

	"github.com/jackc/pgx/v5/pgconn"
)

// TxStore is the set of agent-registry operations that mutate state or
// must observe state consistently with writes. Implementations run
// inside a transaction (Postgres) or a store-wide lock (memory) so a
// service multi-step transition (read state -> validate -> update ->
// append event) is atomic and the event chain cannot fork.
type TxStore interface {
	CreateAgent(ctx context.Context, a runtime.Agent) (runtime.Agent, error)
	CreateVersion(ctx context.Context, v runtime.AgentVersion) (runtime.AgentVersion, error)
	UpdateAgentState(ctx context.Context, tenantID, agentID, expectedState, newState string, activatedAt, revokedAt *time.Time) error
	UpdateVersionStatus(ctx context.Context, tenantID, versionID, expectedStatus, newStatus string, approvedAt *time.Time) error
	AppendEvent(ctx context.Context, e runtime.LifecycleEvent) (runtime.LifecycleEvent, error)
	GetAgent(ctx context.Context, tenantID, agentID string) (runtime.Agent, error)
	ListVersions(ctx context.Context, tenantID, agentID string) ([]runtime.AgentVersion, error)
	ListEvents(ctx context.Context, tenantID, agentID string) ([]runtime.LifecycleEvent, error)
	// EnqueueOutbox buffers a security-relevant lifecycle event for the
	// transactional outbox. Implementations flush the buffer atomically
	// with the surrounding transaction, so a lifecycle transition and its
	// delivery event can never diverge.
	EnqueueOutbox(ctx context.Context, e runtime.OutboxEvent) error
}

// Store is the registry entry point: tenant-scoped reads plus Transact,
// which provides the mutation surface (TxStore) inside an atomic,
// per-agent-serialized unit of work.
type Store interface {
	Reader
	// Transact runs fn atomically, serialized per agent (advisory lock
	// in Postgres, store mutex in memory). lockKey is the agent id for
	// existing agents; "new:"+tenantID for creates (which have no id yet).
	Transact(ctx context.Context, lockKey string, fn func(tx TxStore) error) error
}

// Reader is the read-only surface of the registry.
type Reader interface {
	GetAgent(ctx context.Context, tenantID, agentID string) (runtime.Agent, error)
	ListVersions(ctx context.Context, tenantID, agentID string) ([]runtime.AgentVersion, error)
	ListEvents(ctx context.Context, tenantID, agentID string) ([]runtime.LifecycleEvent, error)
	// ListAgents returns the tenant's agents newest-first with active
	// version + version count populated. state filters by lifecycle
	// state ("" = no filter).
	ListAgents(ctx context.Context, tenantID, state string) ([]runtime.Agent, error)
}

// ---------------------------------------------------------------------
// Memory store (tests / local mode). Also serves as the TxStore itself:
// Transact holds the store mutex and fn runs against the same instance.
// ---------------------------------------------------------------------

type MemoryStore struct {
	mu            sync.Mutex
	agents        map[string]map[string]runtime.Agent            // tenantID -> agentID -> agent
	versions      map[string]map[string][]runtime.AgentVersion   // tenantID -> agentID -> versions (oldest first)
	events        map[string]map[string][]runtime.LifecycleEvent // tenantID -> agentID -> events (oldest first)
	outbox        map[string]map[string]runtime.OutboxEvent      // tenantID -> eventID -> event
	delivery      map[string]runtime.OutboxEvent                 // outbox row ID -> event
	deliveryOrder []string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		agents:   map[string]map[string]runtime.Agent{},
		versions: map[string]map[string][]runtime.AgentVersion{},
		events:   map[string]map[string][]runtime.LifecycleEvent{},
		outbox:   map[string]map[string]runtime.OutboxEvent{},
		delivery: map[string]runtime.OutboxEvent{},
	}
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (m *MemoryStore) Transact(_ context.Context, _ string, fn func(tx TxStore) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(m)
}

// EnqueueOutbox stores an outbox event under the store mutex; in memory
// mode the transaction IS the store, so the enqueue is atomic with the
// business writes by construction.
func (m *MemoryStore) EnqueueOutbox(_ context.Context, e runtime.OutboxEvent) error {
	if _, ok := m.outbox[e.TenantID][e.EventID]; ok {
		return nil // idempotent: first writer wins
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if e.ID == "" {
		e.ID = newID()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = now
	}
	e.Status = runtime.OutboxStatusPending
	e.NextAttemptAt = now
	if m.outbox[e.TenantID] == nil {
		m.outbox[e.TenantID] = map[string]runtime.OutboxEvent{}
	}
	m.outbox[e.TenantID][e.EventID] = e
	m.delivery[e.ID] = e
	m.deliveryOrder = append(m.deliveryOrder, e.ID)
	return nil
}

// ListOutboxEvents returns the tenant's outbox events newest-first
// (test and local-mode inspection surface).
func (m *MemoryStore) ListOutboxEvents(_ context.Context, tenantID string) ([]runtime.OutboxEvent, error) {
	out := make([]runtime.OutboxEvent, 0)
	for _, id := range m.deliveryOrder {
		e, ok := m.delivery[id]
		if !ok || e.TenantID != tenantID {
			continue
		}
		out = append(out, e)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func (m *MemoryStore) CreateAgent(_ context.Context, a runtime.Agent) (runtime.Agent, error) {
	if a.ID == "" {
		a.ID = newID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
	}
	a.UpdatedAt = a.CreatedAt
	for _, existing := range m.agents[a.TenantID] {
		if existing.Name == a.Name {
			return runtime.Agent{}, runtime.ErrAgentNameConflict
		}
	}
	if m.agents[a.TenantID] == nil {
		m.agents[a.TenantID] = map[string]runtime.Agent{}
	}
	m.agents[a.TenantID][a.ID] = a
	return a, nil
}

func (m *MemoryStore) CreateVersion(_ context.Context, v runtime.AgentVersion) (runtime.AgentVersion, error) {
	// Locate the agent's tenant: the version record itself is
	// tenant-agnostic, the agent owns the tenant scope.
	var tenantID string
	for _, agents := range m.agents {
		if _, ok := agents[v.AgentID]; ok {
			tenantID = agents[v.AgentID].TenantID
			break
		}
	}
	if tenantID == "" {
		return runtime.AgentVersion{}, runtime.ErrAgentNotFound
	}
	if v.ID == "" {
		v.ID = newID()
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
	}
	if m.versions[tenantID] == nil {
		m.versions[tenantID] = map[string][]runtime.AgentVersion{}
	}
	for _, existing := range m.versions[tenantID][v.AgentID] {
		if existing.Version == v.Version {
			return runtime.AgentVersion{}, runtime.ErrAgentVersionConflict
		}
	}
	m.versions[tenantID][v.AgentID] = append(m.versions[tenantID][v.AgentID], v)
	return v, nil
}

func (m *MemoryStore) UpdateAgentState(_ context.Context, tenantID, agentID, expectedState, newState string, activatedAt, revokedAt *time.Time) error {
	a, ok := m.agents[tenantID][agentID]
	if !ok {
		return runtime.ErrAgentNotFound
	}
	if a.LifecycleState != expectedState {
		return runtime.ErrAgentInvalidTransition
	}
	a.LifecycleState = newState
	a.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
	if activatedAt != nil && a.ActivatedAt.IsZero() {
		a.ActivatedAt = activatedAt.UTC()
	}
	if revokedAt != nil {
		a.RevokedAt = revokedAt.UTC()
	}
	m.agents[tenantID][agentID] = a
	return nil
}

func (m *MemoryStore) UpdateVersionStatus(_ context.Context, tenantID, versionID, expectedStatus, newStatus string, approvedAt *time.Time) error {
	for agentID, list := range m.versions[tenantID] {
		for i, v := range list {
			if v.ID != versionID {
				continue
			}
			if v.Status != expectedStatus {
				return runtime.ErrAgentInvalidTransition
			}
			v.Status = newStatus
			if approvedAt != nil {
				v.ApprovedAt = approvedAt.UTC()
			}
			m.versions[tenantID][agentID][i] = v
			return nil
		}
	}
	return runtime.ErrAgentVersionNotFound
}

func (m *MemoryStore) AppendEvent(_ context.Context, e runtime.LifecycleEvent) (runtime.LifecycleEvent, error) {
	if e.ID == "" {
		e.ID = newID()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
	}
	events := m.events[e.TenantID][e.AgentID]
	prev := ""
	if len(events) > 0 {
		prev = events[len(events)-1].ImmutableDigest
	}
	e.ImmutableDigest = ComputeEventDigest(e, prev)
	if m.events[e.TenantID] == nil {
		m.events[e.TenantID] = map[string][]runtime.LifecycleEvent{}
	}
	m.events[e.TenantID][e.AgentID] = append(m.events[e.TenantID][e.AgentID], e)
	return e, nil
}

func (m *MemoryStore) GetAgent(_ context.Context, tenantID, agentID string) (runtime.Agent, error) {
	a, ok := m.agents[tenantID][agentID]
	if !ok {
		return runtime.Agent{}, runtime.ErrAgentNotFound
	}
	return m.enrichAgent(tenantID, a), nil
}

// enrichAgent fills ActiveVersionID/ActiveVersion/VersionCount, matching
// the Postgres getAgent/listAgents lateral joins.
func (m *MemoryStore) enrichAgent(tenantID string, a runtime.Agent) runtime.Agent {
	for _, v := range m.versions[tenantID][a.ID] {
		if v.Status == runtime.VersionStatusActive {
			a.ActiveVersionID = v.ID
			a.ActiveVersion = v.Version
			break
		}
	}
	a.VersionCount = len(m.versions[tenantID][a.ID])
	return a
}

func (m *MemoryStore) ListVersions(_ context.Context, tenantID, agentID string) ([]runtime.AgentVersion, error) {
	versions := m.versions[tenantID][agentID]
	out := make([]runtime.AgentVersion, len(versions))
	copy(out, versions)
	return out, nil
}

func (m *MemoryStore) ListEvents(_ context.Context, tenantID, agentID string) ([]runtime.LifecycleEvent, error) {
	events := m.events[tenantID][agentID]
	out := make([]runtime.LifecycleEvent, len(events))
	copy(out, events)
	return out, nil
}

func (m *MemoryStore) ListAgents(_ context.Context, tenantID, state string) ([]runtime.Agent, error) {
	var agents []runtime.Agent
	for _, a := range m.agents[tenantID] {
		if state != "" && a.LifecycleState != state {
			continue
		}
		agents = append(agents, m.enrichAgent(tenantID, a))
	}
	// newest first, stable ordering
	for i := 0; i < len(agents); i++ {
		for j := i + 1; j < len(agents); j++ {
			if agents[j].CreatedAt.After(agents[i].CreatedAt) {
				agents[i], agents[j] = agents[j], agents[i]
			}
		}
	}
	return agents, nil
}

// ---------------------------------------------------------------------
// Postgres store (production). Migration 014 owns the schema.
// ---------------------------------------------------------------------

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// postgresTx is the transaction-bound store. It implements TxStore over
// one *sql.Tx; the surrounding Transact holds a per-agent advisory lock
// so state reads and chain appends serialize per agent.
type postgresTx struct {
	tx            *sql.Tx
	outboxPending []runtime.OutboxEvent
}

// queryer abstracts *sql.DB and *sql.Tx for the shared row scans.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// execer abstracts *sql.DB and *sql.Tx for the shared mutations.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func (p *PostgresStore) Transact(ctx context.Context, lockKey string, fn func(tx TxStore) error) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Serialize per agent: the state read, the conditional updates, and
	// the chain append are one atomic step. Same pattern as the query
	// audit writer's pg_advisory_xact_lock(hashtext(tenant)).
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		return err
	}
	ptx := &postgresTx{tx: tx}
	if err := fn(ptx); err != nil {
		return err
	}
	if err := ptx.flushOutbox(ctx); err != nil {
		return err
	}
	return tx.Commit()
}

// EnqueueOutbox buffers an event; flushOutbox persists it atomically
// with the transaction. Same event_id within one transaction is
// idempotent (the first writer wins).
func (p *postgresTx) EnqueueOutbox(_ context.Context, e runtime.OutboxEvent) error {
	for _, pending := range p.outboxPending {
		if pending.TenantID == e.TenantID && pending.EventID == e.EventID {
			return nil
		}
	}
	e.Status = runtime.OutboxStatusPending
	e.Attempts = 0
	p.outboxPending = append(p.outboxPending, e)
	return nil
}

func (p *postgresTx) flushOutbox(ctx context.Context) error {
	if len(p.outboxPending) == 0 {
		return nil
	}
	for _, e := range p.outboxPending {
		payload := []byte(e.Payload)
		if len(payload) == 0 {
			payload = []byte("{}")
		}
		if _, err := p.tx.ExecContext(ctx, `
			INSERT INTO outbox_events (tenant_id, event_id, event_type, schema_version, occurred_at, payload, status, next_attempt_at)
			VALUES ($1, $2, $3, $4, $5, $6::jsonb, 'pending', now())
			ON CONFLICT (tenant_id, event_id) DO NOTHING
		`, e.TenantID, e.EventID, e.EventType, e.SchemaVersion, e.OccurredAt, string(payload)); err != nil {
			return err
		}
	}
	return nil
}

func (p *PostgresStore) GetAgent(ctx context.Context, tenantID, agentID string) (runtime.Agent, error) {
	return getAgent(ctx, p.db, tenantID, agentID)
}

func (p *PostgresStore) ListAgents(ctx context.Context, tenantID, state string) ([]runtime.Agent, error) {
	return listAgents(ctx, p.db, tenantID, state)
}

func (p *PostgresStore) ListVersions(ctx context.Context, tenantID, agentID string) ([]runtime.AgentVersion, error) {
	return listVersions(ctx, p.db, tenantID, agentID)
}

func (p *PostgresStore) ListEvents(ctx context.Context, tenantID, agentID string) ([]runtime.LifecycleEvent, error) {
	return listEvents(ctx, p.db, tenantID, agentID)
}

func (t *postgresTx) GetAgent(ctx context.Context, tenantID, agentID string) (runtime.Agent, error) {
	return getAgent(ctx, t.tx, tenantID, agentID)
}

func (t *postgresTx) ListVersions(ctx context.Context, tenantID, agentID string) ([]runtime.AgentVersion, error) {
	return listVersions(ctx, t.tx, tenantID, agentID)
}

func (t *postgresTx) ListEvents(ctx context.Context, tenantID, agentID string) ([]runtime.LifecycleEvent, error) {
	return listEvents(ctx, t.tx, tenantID, agentID)
}

func (t *postgresTx) CreateAgent(ctx context.Context, a runtime.Agent) (runtime.Agent, error) {
	row := t.tx.QueryRowContext(ctx, `
		INSERT INTO agents (tenant_id, name, description, owner_principal_id, business_purpose,
		                    risk_tier, lifecycle_state, environment, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now())
		RETURNING id, created_at, updated_at
	`, a.TenantID, a.Name, a.Description, a.OwnerPrincipalID, a.BusinessPurpose,
		a.RiskTier, a.LifecycleState, a.Environment)
	if err := row.Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt); err != nil {
		if isUniqueViolation(err, "agents") {
			return runtime.Agent{}, runtime.ErrAgentNameConflict
		}
		return runtime.Agent{}, err
	}
	return a, nil
}

func (t *postgresTx) CreateVersion(ctx context.Context, v runtime.AgentVersion) (runtime.AgentVersion, error) {
	row := t.tx.QueryRowContext(ctx, `
		INSERT INTO agent_versions (agent_id, version, model_provider, model_name,
		                            prompt_digest, tool_manifest_digest, policy_bundle_version,
		                            artifact_digest, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
		RETURNING id, created_at
	`, v.AgentID, v.Version, v.ModelProvider, v.ModelName, v.PromptDigest,
		v.ToolManifestDigest, v.PolicyBundleVersion, v.ArtifactDigest, v.Status)
	if err := row.Scan(&v.ID, &v.CreatedAt); err != nil {
		if isUniqueViolation(err, "agent_versions") {
			return runtime.AgentVersion{}, runtime.ErrAgentVersionConflict
		}
		return runtime.AgentVersion{}, err
	}
	return v, nil
}

func (t *postgresTx) UpdateAgentState(ctx context.Context, tenantID, agentID, expectedState, newState string, activatedAt, revokedAt *time.Time) error {
	var activated, revoked any
	if activatedAt != nil {
		activated = *activatedAt
	}
	if revokedAt != nil {
		revoked = *revokedAt
	}
	tag, err := t.tx.ExecContext(ctx, `
		UPDATE agents
		SET lifecycle_state = $3, updated_at = now(),
		    activated_at = COALESCE($4, activated_at),
		    revoked_at = COALESCE($5, revoked_at)
		WHERE tenant_id = $1 AND id = $2 AND lifecycle_state = $6
	`, tenantID, agentID, newState, activated, revoked, expectedState)
	if err != nil {
		return err
	}
	if n, err2 := tag.RowsAffected(); err2 != nil {
		return err2
	} else if n == 0 {
		if _, err := getAgent(ctx, t.tx, tenantID, agentID); errors.Is(err, runtime.ErrAgentNotFound) {
			return runtime.ErrAgentNotFound
		}
		return runtime.ErrAgentInvalidTransition
	}
	return nil
}

func (t *postgresTx) UpdateVersionStatus(ctx context.Context, tenantID, versionID, expectedStatus, newStatus string, approvedAt *time.Time) error {
	var approved any
	if approvedAt != nil {
		approved = *approvedAt
	}
	tag, err := t.tx.ExecContext(ctx, `
		UPDATE agent_versions v
		SET status = $4, approved_at = COALESCE($5, approved_at)
		WHERE v.id = $1 AND v.status = $3
		  AND EXISTS (SELECT 1 FROM agents a WHERE a.id = v.agent_id AND a.tenant_id = $2)
	`, versionID, tenantID, expectedStatus, newStatus, approved)
	if err != nil {
		return err
	}
	if n, err2 := tag.RowsAffected(); err2 != nil {
		return err2
	} else if n == 0 {
		var exists bool
		if err := t.tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM agent_versions v
				JOIN agents a ON a.id = v.agent_id
				WHERE v.id = $1 AND a.tenant_id = $2
			)
		`, versionID, tenantID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return runtime.ErrAgentVersionNotFound
		}
		return runtime.ErrAgentInvalidTransition
	}
	return nil
}

func (t *postgresTx) AppendEvent(ctx context.Context, e runtime.LifecycleEvent) (runtime.LifecycleEvent, error) {
	var prev sql.NullString
	if err := t.tx.QueryRowContext(ctx, `
		SELECT immutable_digest FROM agent_lifecycle_events
		WHERE tenant_id = $1 AND agent_id = $2
		ORDER BY created_at DESC, id DESC LIMIT 1
	`, e.TenantID, e.AgentID).Scan(&prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return runtime.LifecycleEvent{}, err
	}
	if e.ID == "" {
		e.ID = newID()
	}
	e.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
	e.ImmutableDigest = ComputeEventDigest(e, prev.String)
	_, err := t.tx.ExecContext(ctx, `
		INSERT INTO agent_lifecycle_events (id, tenant_id, agent_id, agent_version_id,
		                                    actor_principal_id, event_type, previous_state,
		                                    new_state, reason, immutable_digest, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, e.ID, e.TenantID, e.AgentID, nullUUID(e.AgentVersionID), e.ActorPrincipal,
		e.EventType, e.PreviousState, e.NewState, e.Reason, e.ImmutableDigest, e.CreatedAt)
	if err != nil {
		return runtime.LifecycleEvent{}, err
	}
	return e, nil
}

// --- shared query implementations (work over *sql.DB or *sql.Tx) ---

const agentColumns = `a.id, a.tenant_id, a.name, a.description, a.owner_principal_id,
	a.business_purpose, a.risk_tier, a.lifecycle_state, a.environment,
	a.created_at, a.updated_at, a.activated_at, a.revoked_at`

func getAgent(ctx context.Context, q queryer, tenantID, agentID string) (runtime.Agent, error) {
	row := q.QueryRowContext(ctx, `
		SELECT `+agentColumns+`,
		       v.id, v.version,
		       (SELECT count(*) FROM agent_versions vv WHERE vv.agent_id = a.id)
		FROM agents a
		LEFT JOIN LATERAL (
			SELECT id, version FROM agent_versions
			WHERE agent_id = a.id AND status = 'active'
			ORDER BY created_at DESC LIMIT 1
		) v ON TRUE
		WHERE a.tenant_id = $1 AND a.id = $2
	`, tenantID, agentID)
	a, err := scanAgent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return runtime.Agent{}, runtime.ErrAgentNotFound
	}
	return a, err
}

func listAgents(ctx context.Context, q queryer, tenantID, state string) ([]runtime.Agent, error) {
	query := `
		SELECT ` + agentColumns + `,
		       v.id, v.version,
		       (SELECT count(*) FROM agent_versions vv WHERE vv.agent_id = a.id)
		FROM agents a
		LEFT JOIN LATERAL (
			SELECT id, version FROM agent_versions
			WHERE agent_id = a.id AND status = 'active'
			ORDER BY created_at DESC LIMIT 1
		) v ON TRUE
		WHERE a.tenant_id = $1`
	args := []any{tenantID}
	if state != "" {
		query += ` AND a.lifecycle_state = $2`
		args = append(args, state)
	}
	query += ` ORDER BY a.created_at DESC`
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var agents []runtime.Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

// rowScanner abstracts *sql.Row and *sql.Rows for shared scans.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAgent(row rowScanner) (runtime.Agent, error) {
	var a runtime.Agent
	var activatedAt, revokedAt sql.NullTime
	var versionID, version sql.NullString
	var versionCount sql.NullInt64
	err := row.Scan(&a.ID, &a.TenantID, &a.Name, &a.Description, &a.OwnerPrincipalID,
		&a.BusinessPurpose, &a.RiskTier, &a.LifecycleState, &a.Environment,
		&a.CreatedAt, &a.UpdatedAt, &activatedAt, &revokedAt,
		&versionID, &version, &versionCount)
	if err != nil {
		return runtime.Agent{}, err
	}
	if activatedAt.Valid {
		a.ActivatedAt = activatedAt.Time.UTC()
	}
	if revokedAt.Valid {
		a.RevokedAt = revokedAt.Time.UTC()
	}
	if versionID.Valid {
		a.ActiveVersionID = versionID.String
		a.ActiveVersion = version.String
	}
	if versionCount.Valid {
		a.VersionCount = int(versionCount.Int64)
	}
	a.CreatedAt = a.CreatedAt.UTC()
	a.UpdatedAt = a.UpdatedAt.UTC()
	return a, nil
}

func listVersions(ctx context.Context, q queryer, tenantID, agentID string) ([]runtime.AgentVersion, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT v.id, v.agent_id, v.version, v.model_provider, v.model_name,
		       v.prompt_digest, v.tool_manifest_digest, v.policy_bundle_version,
		       v.artifact_digest, v.status, v.created_at, v.approved_at
		FROM agent_versions v
		JOIN agents a ON a.id = v.agent_id
		WHERE a.tenant_id = $1 AND v.agent_id = $2
		ORDER BY v.created_at ASC, v.id ASC
	`, tenantID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var versions []runtime.AgentVersion
	for rows.Next() {
		var v runtime.AgentVersion
		var approvedAt sql.NullTime
		if err := rows.Scan(&v.ID, &v.AgentID, &v.Version, &v.ModelProvider, &v.ModelName,
			&v.PromptDigest, &v.ToolManifestDigest, &v.PolicyBundleVersion,
			&v.ArtifactDigest, &v.Status, &v.CreatedAt, &approvedAt); err != nil {
			return nil, err
		}
		if approvedAt.Valid {
			v.ApprovedAt = approvedAt.Time.UTC()
		}
		v.CreatedAt = v.CreatedAt.UTC()
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

func listEvents(ctx context.Context, q queryer, tenantID, agentID string) ([]runtime.LifecycleEvent, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT e.id, e.tenant_id, e.agent_id, e.agent_version_id, e.actor_principal_id,
		       e.event_type, e.previous_state, e.new_state, e.reason,
		       e.immutable_digest, e.created_at
		FROM agent_lifecycle_events e
		JOIN agents a ON a.id = e.agent_id
		WHERE a.tenant_id = $1 AND e.agent_id = $2
		ORDER BY e.created_at ASC, e.id ASC
	`, tenantID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []runtime.LifecycleEvent
	for rows.Next() {
		var e runtime.LifecycleEvent
		var versionID sql.NullString
		if err := rows.Scan(&e.ID, &e.TenantID, &e.AgentID, &versionID, &e.ActorPrincipal,
			&e.EventType, &e.PreviousState, &e.NewState, &e.Reason,
			&e.ImmutableDigest, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.AgentVersionID = versionID.String
		e.CreatedAt = e.CreatedAt.UTC()
		events = append(events, e)
	}
	return events, rows.Err()
}

// nullUUID returns SQL NULL for an empty UUID string.
func nullUUID(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

// isUniqueViolation reports whether err is a Postgres unique violation
// on a constraint owned by the named table (pgconn.PgError code 23505).
// Each of agents / agent_versions has exactly one unique constraint
// (the per-tenant name and the per-agent version), so the table-name
// prefix disambiguates them.
func isUniqueViolation(err error, table string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}
	return strings.HasPrefix(pgErr.ConstraintName, table+"_")
}
