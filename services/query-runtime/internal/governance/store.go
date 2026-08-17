package governance

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"groundwork/query-runtime/internal/connectors"
	"groundwork/query-runtime/internal/runtime"
)

// TxStore is the set of governance operations that mutate state or must
// observe state consistently with writes. Implementations run inside a
// transaction (Postgres) or a store-wide lock (memory) so multi-step
// evaluator decisions (read state -> validate -> append evidence ->
// consume approval) are atomic and evidence chains cannot fork.
type TxStore interface {
	Reader
	// Tools & actions.
	CreateTool(ctx context.Context, t runtime.Tool) (runtime.Tool, error)
	TransitionTool(ctx context.Context, tenantID, toolID, expectedLifecycle, newLifecycle string) error
	CreateToolAction(ctx context.Context, a runtime.ToolAction) (runtime.ToolAction, error)
	UpdateActionStatus(ctx context.Context, tenantID, actionID, expectedStatus, newStatus string) error

	// Grants.
	CreateGrant(ctx context.Context, g runtime.AgentToolGrant) (runtime.AgentToolGrant, error)
	RevokeGrant(ctx context.Context, tenantID, grantID string) error

	// Delegations.
	CreateDelegationGrant(ctx context.Context, g runtime.DelegationGrant) error
	GetDelegationGrantByJTI(ctx context.Context, tenantID, jti string) (runtime.DelegationGrant, error)
	// ConsumeGrantForRun atomically binds the grant to the server-generated
	// run: SET used_at = now(), run_id = $run WHERE token_jti = $jti AND
	// run_id IS NULL AND revoked_at IS NULL AND expires_at > now(). A grant
	// that is already bound (replay) or revoked/expired does NOT transition
	// and the method returns the matching sentinel error.
	ConsumeGrantForRun(ctx context.Context, tenantID, jti, runID string) error
	RevokeGrantByJTI(ctx context.Context, tenantID, jti string) error

	// Runs.
	CreateRun(ctx context.Context, r runtime.AgentRun) (runtime.AgentRun, error)
	GetRun(ctx context.Context, tenantID, runID string) (runtime.AgentRun, error)
	UpdateRunStatus(ctx context.Context, tenantID, runID, expectedStatus, newStatus string, completedAt *time.Time, errorCode string) error
	CountAllowedActions(ctx context.Context, tenantID, runID, toolID, actionID string) (int, error)

	// Evidence.
	AppendDecision(ctx context.Context, d runtime.ActionDecision) (runtime.ActionDecision, error)
	AppendApproval(ctx context.Context, a runtime.ActionApproval) (runtime.ActionApproval, error)
	// AppendConnectorInvocation records immutable outcome evidence of one
	// authorized connector call (Phase 5). decision_id is unique per
	// tenant: a duplicate is an idempotency conflict.
	AppendConnectorInvocation(ctx context.Context, inv runtime.ConnectorInvocation) (runtime.ConnectorInvocation, error)
	GetApprovalForConsume(ctx context.Context, tenantID, runID, toolID, actionID, resourceRef string) (runtime.ActionApproval, error)
	GetDeniedApproval(ctx context.Context, tenantID, runID, toolID, actionID, resourceRef string) (runtime.ActionApproval, error)
	ConsumeApproval(ctx context.Context, tenantID, approvalID string) error
	GetApprovalByIdempotencyKey(ctx context.Context, tenantID, runID, toolID, actionID, resourceRef, idempotencyKey string) (runtime.ActionApproval, error)

	// Phase 3: emergency controls.
	// SetEmergencyControl upserts the control state row for an entity.
	SetEmergencyControl(ctx context.Context, c runtime.EmergencyControl) (runtime.EmergencyControl, error)
	GetEmergencyControl(ctx context.Context, tenantID, entityType, entityID string) (runtime.EmergencyControl, error)
	ListEmergencyControls(ctx context.Context, tenantID string) ([]runtime.EmergencyControl, error)
	// AppendEmergencyAction records immutable hash-chained evidence of a
	// control mutation (chained per tenant, oldest-first).
	AppendEmergencyAction(ctx context.Context, a runtime.EmergencyControlAction) (runtime.EmergencyControlAction, error)
	ListEmergencyActions(ctx context.Context, tenantID string) ([]runtime.EmergencyControlAction, error)

	// Phase 3: delegation revocation by grant id (irreversible).
	RevokeDelegationGrantByID(ctx context.Context, tenantID, grantID string) error

	// Phase 3: budgets (narrowest applicable scope wins).
	UpsertBudgetPolicy(ctx context.Context, b runtime.BudgetPolicy) (runtime.BudgetPolicy, error)
	GetBudgetPolicy(ctx context.Context, tenantID, scopeType, agentVersionID, grantID string) (runtime.BudgetPolicy, error)
	ListBudgetPolicies(ctx context.Context, tenantID string) ([]runtime.BudgetPolicy, error)
	// IncrementBudgetCounter atomically increments one counter for a run
	// (or run+action) and returns the NEW value. Transaction-safe: in
	// Postgres this is INSERT ... ON CONFLICT DO UPDATE ... RETURNING
	// inside the same tx as the decision evidence; in memory it runs
	// under the store mutex.
	IncrementBudgetCounter(ctx context.Context, tenantID, runID, actionID, counterType string) (int, error)
	// IncrementBudgetCounterN adds delta (>= 1) to a run-level counter
	// (used for citation counts reported by the retrieval engine).
	IncrementBudgetCounterN(ctx context.Context, tenantID, runID, actionID, counterType string, delta int) (int, error)
	GetBudgetCounter(ctx context.Context, tenantID, runID, actionID, counterType string) (int, error)
	GetBudgetCounters(ctx context.Context, tenantID, runID string) (map[string]int, error)

	// Phase 3: transactional outbox. EnqueueOutbox buffers the event in
	// the current transaction; the store flushes all pending events to
	// outbox_events atomically on commit (or immediately under the
	// memory store mutex). Delivery state transitions are single
	// guarded statements (see OutboxDeliveryStore), so concurrent
	// workers cannot double-deliver.
	EnqueueOutbox(ctx context.Context, e runtime.OutboxEvent) error

	// Phase 6: trust graph, external agents, consent, transfer policy.
	CreateTrustRelationship(ctx context.Context, r runtime.AgentTrustRelationship) (runtime.AgentTrustRelationship, error)
	UpdateTrustRelationshipStatus(ctx context.Context, tenantID, relationshipID, expectedState, newState, reason string) error
	AppendTrustEvent(ctx context.Context, e runtime.TrustEvent) (runtime.TrustEvent, error)
	CreateExternalAgent(ctx context.Context, a runtime.ExternalAgent) (runtime.ExternalAgent, error)
	UpdateExternalAgentState(ctx context.Context, tenantID, externalAgentID, expectedState, newState string) error
	// ConsumeExternalNonce fails (replay) when the jti was already used
	// for this external agent; nonces expire and are pruned by TTL.
	ConsumeExternalNonce(ctx context.Context, tenantID, externalAgentID, jti string) error
	UpsertTransferPolicy(ctx context.Context, p runtime.TransferPolicy) (runtime.TransferPolicy, error)
	CreateConsentRecord(ctx context.Context, c runtime.ConsentRecord) (runtime.ConsentRecord, error)
	// UpdateConsentStatus performs the single active->revoked transition
	// (write-once semantics: a revoked consent cannot be re-activated).
	UpdateConsentStatus(ctx context.Context, tenantID, consentID, expectedStatus, newStatus, actor, reason string) (runtime.ConsentRecord, error)
	SetTransferPolicyEnabled(ctx context.Context, tenantID, policyID string, enabled bool) (runtime.TransferPolicy, error)
	// Chain reads (delegation trees).
	ListChildGrants(ctx context.Context, tenantID, parentGrantID string) ([]runtime.DelegationGrant, error)
	ListDescendantGrantIDs(ctx context.Context, tenantID, rootGrantID string) ([]string, error)
	// Phase 6: external-agent budgets (counters across many runs).
	UpsertExternalBudget(ctx context.Context, b runtime.ExternalBudgetPolicy) (runtime.ExternalBudgetPolicy, error)
	IncrementExternalBudgetCounters(ctx context.Context, tenantID, scopeType, externalAgentID, organizationID, customerPrincipalID string, actions, denied, approvals, toolCalls int) error
}

// OutboxDeliveryStore is the cross-tenant worker surface of the outbox
// (claim → deliver → ack/dead-letter). Only the outbox worker uses it —
// every tenant-facing read stays tenant-scoped.
type OutboxDeliveryStore interface {
	ListPendingOutbox(ctx context.Context, limit int) ([]runtime.OutboxEvent, error)
	ClaimOutboxEvent(ctx context.Context, eventID string) error
	MarkOutboxDelivered(ctx context.Context, eventID string) error
	MarkOutboxDeadLetter(ctx context.Context, eventID, lastError string) error
	// RescheduleOutboxEvent returns a 'delivering' event to 'pending'
	// with an explicit next attempt time (exponential backoff).
	RescheduleOutboxEvent(ctx context.Context, eventID string, nextAttemptAt time.Time) error
}

// Store is the governance entry point: tenant-scoped reads plus
// Transact, which provides the mutation surface (TxStore) inside an
// atomic, serialized unit of work.
type Store interface {
	Reader
	// Transact runs fn atomically, serialized per lockKey (agent id for
	// grant/delegation/run operations, run id for evidence operations).
	Transact(ctx context.Context, lockKey string, fn func(tx TxStore) error) error
}

// Reader is the read-only surface of governance.
type Reader interface {
	ListTools(ctx context.Context, tenantID string) ([]runtime.Tool, error)
	GetTool(ctx context.Context, tenantID, toolID string) (runtime.Tool, error)
	GetToolByName(ctx context.Context, tenantID, name string) (runtime.Tool, error)
	ListToolActions(ctx context.Context, tenantID, toolID string) ([]runtime.ToolAction, error)
	GetToolAction(ctx context.Context, tenantID, actionID string) (runtime.ToolAction, error)
	GetToolActionByName(ctx context.Context, tenantID, toolID, action string) (runtime.ToolAction, error)
	ListGrants(ctx context.Context, tenantID, agentID string) ([]runtime.AgentToolGrant, error)
	GetGrantsForTuple(ctx context.Context, tenantID, agentID, versionID, toolID, actionID string) ([]runtime.AgentToolGrant, error)
	GetGrant(ctx context.Context, tenantID, grantID string) (runtime.AgentToolGrant, error)
	GetDelegationGrantByIdempotencyKey(ctx context.Context, tenantID, idempotencyKey string) (runtime.DelegationGrant, error)
	GetDelegationGrantByID(ctx context.Context, tenantID, grantID string) (runtime.DelegationGrant, error)
	ListRuns(ctx context.Context, tenantID string) ([]runtime.AgentRun, error)
	GetRun(ctx context.Context, tenantID, runID string) (runtime.AgentRun, error)
	GetRunByIdempotencyKey(ctx context.Context, tenantID, idempotencyKey string) (runtime.AgentRun, error)
	ListDecisions(ctx context.Context, tenantID, runID string) ([]runtime.ActionDecision, error)
	ListApprovals(ctx context.Context, tenantID, runID string) ([]runtime.ActionApproval, error)

	// Phase 3: tenant-wide evidence + verification reads.
	ListDecisionsByTenant(ctx context.Context, tenantID string) ([]runtime.ActionDecision, error)
	ListApprovalsByTenant(ctx context.Context, tenantID string) ([]runtime.ActionApproval, error)
	ListDelegationGrants(ctx context.Context, tenantID string) ([]runtime.DelegationGrant, error)
	ListRunsByTenant(ctx context.Context, tenantID string) ([]runtime.AgentRun, error)
	ListEmergencyControls(ctx context.Context, tenantID string) ([]runtime.EmergencyControl, error)
	ListEmergencyActions(ctx context.Context, tenantID string) ([]runtime.EmergencyControlAction, error)
	GetBudgetPolicy(ctx context.Context, tenantID, scopeType, agentVersionID, grantID string) (runtime.BudgetPolicy, error)
	ListBudgetPolicies(ctx context.Context, tenantID string) ([]runtime.BudgetPolicy, error)
	QueryEvidence(ctx context.Context, tenantID string, filter runtime.EvidenceFilter) ([]runtime.EvidenceEvent, error)
	GetEvidenceEvent(ctx context.Context, tenantID, eventID string) (runtime.EvidenceEvent, error)
	GetRunEvidence(ctx context.Context, tenantID, runID string) ([]runtime.EvidenceEvent, error)
	GetAgentEvidence(ctx context.Context, tenantID, agentID string, filter runtime.EvidenceFilter) ([]runtime.EvidenceEvent, error)
	ListOutboxEvents(ctx context.Context, tenantID, status string, limit int, cursor string) ([]runtime.OutboxEvent, error)
	GetOutboxEventByID(ctx context.Context, tenantID, eventID string) (runtime.OutboxEvent, error)
	RetryOutboxEvent(ctx context.Context, tenantID, eventID string) error
	CreateCheckpoint(ctx context.Context, c runtime.EvidenceCheckpoint) (runtime.EvidenceCheckpoint, error)
	ListCheckpoints(ctx context.Context, tenantID string) ([]runtime.EvidenceCheckpoint, error)
	GetCheckpoint(ctx context.Context, tenantID, checkpointID string) (runtime.EvidenceCheckpoint, error)
	// Phase 5: connector invocation evidence reads.
	ListConnectorInvocations(ctx context.Context, tenantID, connectorID string, limit int) ([]runtime.ConnectorInvocation, error)
	// Phase 8.2: returns the most recent invocation recorded for the
	// semantic idempotency key (empty key queries nothing). ok=false
	// when no row exists yet.
	GetConnectorInvocationByDedupKey(ctx context.Context, tenantID, idempotencyKey string) (runtime.ConnectorInvocation, bool, error)
	// Phase 6: trust graph, external agents, consent, transfer policy.
	GetTrustRelationship(ctx context.Context, tenantID, relationshipID string) (runtime.AgentTrustRelationship, error)
	GetTrustRelationshipByPair(ctx context.Context, tenantID, parentAgentID, childAgentID, externalAgentID string) (runtime.AgentTrustRelationship, error)
	ListTrustRelationships(ctx context.Context, tenantID string) ([]runtime.AgentTrustRelationship, error)
	ListTrustEvents(ctx context.Context, tenantID string, limit int) ([]runtime.TrustEvent, error)
	GetExternalAgent(ctx context.Context, tenantID, externalAgentID string) (runtime.ExternalAgent, error)
	GetExternalAgentByAgentID(ctx context.Context, tenantID, agentID string) (runtime.ExternalAgent, error)
	GetExternalAgentByIssuer(ctx context.Context, tenantID, issuer string) (runtime.ExternalAgent, error)
	ListExternalAgents(ctx context.Context, tenantID string) ([]runtime.ExternalAgent, error)
	GetTransferPolicy(ctx context.Context, tenantID, sourceRegion, targetRegion, purpose string) (runtime.TransferPolicy, error)
	GetTransferPolicyByID(ctx context.Context, tenantID, policyID string) (runtime.TransferPolicy, error)
	ListTransferPolicies(ctx context.Context, tenantID string) ([]runtime.TransferPolicy, error)
	GetConsentRecord(ctx context.Context, tenantID, consentID string) (runtime.ConsentRecord, error)
	FindConsent(ctx context.Context, tenantID, organizationID, externalAgentID, customerPrincipalID, purpose, resourceRef string) (runtime.ConsentRecord, error)
	ListConsentRecords(ctx context.Context, tenantID string) ([]runtime.ConsentRecord, error)
	GetExternalBudget(ctx context.Context, tenantID, scopeType, externalAgentID, organizationID, customerPrincipalID string) (runtime.ExternalBudgetPolicy, error)
	ListExternalBudgets(ctx context.Context, tenantID string) ([]runtime.ExternalBudgetPolicy, error)
}

// ---------------------------------------------------------------------
// Memory store (tests / local mode). Transact holds the store mutex and
// fn runs against the same instance.
// ---------------------------------------------------------------------

type MemoryStore struct {
	mu          sync.Mutex
	now         func() time.Time
	tools       map[string]map[string]runtime.Tool             // tenantID -> id -> tool
	actions     map[string]map[string]runtime.ToolAction       // tenantID -> id -> action
	grants      map[string]map[string]runtime.AgentToolGrant   // tenantID -> id -> grant
	delegations map[string]map[string]runtime.DelegationGrant  // tenantID -> jti -> grant
	runs        map[string]map[string]runtime.AgentRun         // tenantID -> id -> run
	decisions   map[string]map[string][]runtime.ActionDecision // tenantID -> runID -> oldest first
	approvals   map[string]map[string][]runtime.ActionApproval // tenantID -> runID -> oldest first
	// Phase 3.
	controls    map[string]map[string]runtime.EmergencyControl  // tenantID -> entity_type+"|"+entity_id -> control
	controlActs map[string][]runtime.EmergencyControlAction     // tenantID -> oldest first (chained)
	budgets     map[string][]runtime.BudgetPolicy               // tenantID -> policies
	budgetUsage map[string]map[string]map[string]map[string]int // tenantID -> runID -> actionID("" for run-level) -> counterType -> count
	checkpoints map[string][]runtime.EvidenceCheckpoint         // tenantID -> oldest first
	// Phase 5.
	invocations      map[string]map[string]runtime.ConnectorInvocation // tenantID -> decisionID -> invocation
	invocationsByKey map[string]map[string]runtime.ConnectorInvocation // tenantID -> idempotencyKey -> latest invocation (Phase 8.2)
	outbox           map[string]map[string]runtime.OutboxEvent         // tenantID -> eventID -> event
	delivery         map[string]runtime.OutboxEvent                    // eventID -> event (cross-tenant worker view)
	deliveryOrder    []string                                          // eventID insertion order for deterministic pending scans
	// Phase 6.
	relationships  map[string]map[string]runtime.AgentTrustRelationship // tenantID -> relationshipID
	externalAgents map[string]map[string]runtime.ExternalAgent          // tenantID -> externalAgentID
	transferPolic  map[string]map[string]runtime.TransferPolicy         // tenantID -> regionPairKey -> policy
	consents       map[string]map[string]runtime.ConsentRecord          // tenantID -> consentID
	trustEvents    map[string][]runtime.TrustEvent                      // tenantID -> oldest first (chained)
	externalNonces map[string]map[string]map[string]time.Time           // tenantID -> agentID -> jti -> issued
	externalBudget map[string]map[string]runtime.ExternalBudgetPolicy   // tenantID -> scopeKey -> policy
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		now:              time.Now,
		tools:            map[string]map[string]runtime.Tool{},
		actions:          map[string]map[string]runtime.ToolAction{},
		grants:           map[string]map[string]runtime.AgentToolGrant{},
		delegations:      map[string]map[string]runtime.DelegationGrant{},
		runs:             map[string]map[string]runtime.AgentRun{},
		decisions:        map[string]map[string][]runtime.ActionDecision{},
		approvals:        map[string]map[string][]runtime.ActionApproval{},
		controls:         map[string]map[string]runtime.EmergencyControl{},
		controlActs:      map[string][]runtime.EmergencyControlAction{},
		budgets:          map[string][]runtime.BudgetPolicy{},
		budgetUsage:      map[string]map[string]map[string]map[string]int{},
		checkpoints:      map[string][]runtime.EvidenceCheckpoint{},
		invocations:      map[string]map[string]runtime.ConnectorInvocation{},
		invocationsByKey: map[string]map[string]runtime.ConnectorInvocation{},
		outbox:           map[string]map[string]runtime.OutboxEvent{},
		delivery:         map[string]runtime.OutboxEvent{},
		relationships:    map[string]map[string]runtime.AgentTrustRelationship{},
		externalAgents:   map[string]map[string]runtime.ExternalAgent{},
		transferPolic:    map[string]map[string]runtime.TransferPolicy{},
		consents:         map[string]map[string]runtime.ConsentRecord{},
		trustEvents:      map[string][]runtime.TrustEvent{},
		externalNonces:   map[string]map[string]map[string]time.Time{},
		externalBudget:   map[string]map[string]runtime.ExternalBudgetPolicy{},
	}
}

// SetClock overrides the time source (tests).
func (m *MemoryStore) SetClock(now func() time.Time) { m.now = now }

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

func (m *MemoryStore) CreateTool(_ context.Context, t runtime.Tool) (runtime.Tool, error) {
	if t.ID == "" {
		t.ID = newID()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = m.now().UTC().Truncate(time.Microsecond)
	}
	t.UpdatedAt = t.CreatedAt
	for _, existing := range m.tools[t.TenantID] {
		if existing.Name == t.Name {
			return runtime.Tool{}, runtime.ErrToolNameConflict
		}
	}
	if m.tools[t.TenantID] == nil {
		m.tools[t.TenantID] = map[string]runtime.Tool{}
	}
	m.tools[t.TenantID][t.ID] = t
	return t, nil
}

func (m *MemoryStore) TransitionTool(_ context.Context, tenantID, toolID, expectedLifecycle, newLifecycle string) error {
	t, ok := m.tools[tenantID][toolID]
	if !ok {
		return runtime.ErrToolNotFound
	}
	if t.Lifecycle != expectedLifecycle {
		return runtime.ErrToolInvalidState
	}
	t.Lifecycle = newLifecycle
	t.UpdatedAt = m.now().UTC().Truncate(time.Microsecond)
	m.tools[tenantID][toolID] = t
	return nil
}

func (m *MemoryStore) CreateToolAction(_ context.Context, a runtime.ToolAction) (runtime.ToolAction, error) {
	tool, ok := m.tools[a.TenantID][a.ToolID]
	if !ok {
		return runtime.ToolAction{}, runtime.ErrToolNotFound
	}
	if tool.Transport != "" && a.TenantID != tool.TenantID {
		return runtime.ToolAction{}, runtime.ErrToolNotFound
	}
	if a.ID == "" {
		a.ID = newID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = m.now().UTC().Truncate(time.Microsecond)
	}
	for _, existing := range m.actions[a.TenantID] {
		if existing.ToolID == a.ToolID && existing.Action == a.Action {
			return runtime.ToolAction{}, runtime.ErrActionConflict
		}
	}
	if m.actions[a.TenantID] == nil {
		m.actions[a.TenantID] = map[string]runtime.ToolAction{}
	}
	m.actions[a.TenantID][a.ID] = a
	return a, nil
}

func (m *MemoryStore) UpdateActionStatus(_ context.Context, tenantID, actionID, expectedStatus, newStatus string) error {
	a, ok := m.actions[tenantID][actionID]
	if !ok {
		return runtime.ErrActionNotFound
	}
	if a.Status != expectedStatus {
		return runtime.ErrInvalidRequest
	}
	a.Status = newStatus
	m.actions[tenantID][actionID] = a
	return nil
}

func (m *MemoryStore) CreateGrant(_ context.Context, g runtime.AgentToolGrant) (runtime.AgentToolGrant, error) {
	if g.ID == "" {
		g.ID = newID()
	}
	if g.GrantedAt.IsZero() {
		g.GrantedAt = m.now().UTC().Truncate(time.Microsecond)
	}
	for _, existing := range m.grants[g.TenantID] {
		if existing.AgentID == g.AgentID && existing.VersionID == g.VersionID &&
			existing.ToolID == g.ToolID && existing.ActionID == g.ActionID &&
			existing.ResourceScope == g.ResourceScope && existing.RevokedAt.IsZero() {
			return runtime.AgentToolGrant{}, runtime.ErrGrantConflict
		}
	}
	if m.grants[g.TenantID] == nil {
		m.grants[g.TenantID] = map[string]runtime.AgentToolGrant{}
	}
	m.grants[g.TenantID][g.ID] = g
	return g, nil
}

func (m *MemoryStore) RevokeGrant(_ context.Context, tenantID, grantID string) error {
	g, ok := m.grants[tenantID][grantID]
	if !ok {
		return runtime.ErrGrantNotFound
	}
	if !g.RevokedAt.IsZero() {
		return runtime.ErrGrantRevoked
	}
	g.RevokedAt = m.now().UTC().Truncate(time.Microsecond)
	m.grants[tenantID][grantID] = g
	return nil
}

func (m *MemoryStore) CreateDelegationGrant(_ context.Context, g runtime.DelegationGrant) error {
	if g.ID == "" {
		g.ID = newID()
	}
	for _, existing := range m.delegations[g.TenantID] {
		if existing.TokenJTI == g.TokenJTI {
			return fmt.Errorf("%w: token_jti", runtime.ErrIdempotencyConflict)
		}
	}
	if m.delegations[g.TenantID] == nil {
		m.delegations[g.TenantID] = map[string]runtime.DelegationGrant{}
	}
	m.delegations[g.TenantID][g.TokenJTI] = g
	return nil
}

func (m *MemoryStore) GetDelegationGrantByJTI(_ context.Context, tenantID, jti string) (runtime.DelegationGrant, error) {
	g, ok := m.delegations[tenantID][jti]
	if !ok {
		return runtime.DelegationGrant{}, fmt.Errorf("%w: grant for jti not found", runtime.ErrDelegationInvalid)
	}
	return g, nil
}

func (m *MemoryStore) GetDelegationGrantByIdempotencyKey(_ context.Context, tenantID, idempotencyKey string) (runtime.DelegationGrant, error) {
	for _, g := range m.delegations[tenantID] {
		if g.IdempotencyKey == idempotencyKey {
			return g, nil
		}
	}
	return runtime.DelegationGrant{}, fmt.Errorf("%w: no grant for idempotency key", runtime.ErrDelegationInvalid)
}

func (m *MemoryStore) ConsumeGrantForRun(_ context.Context, tenantID, jti, runID string) error {
	g, ok := m.delegations[tenantID][jti]
	if !ok {
		return runtime.ErrDelegationInvalid
	}
	if !g.RevokedAt.IsZero() {
		return runtime.ErrDelegationRevoked
	}
	if g.RunID != "" {
		return runtime.ErrDelegationReused
	}
	now := m.now().UTC()
	if !now.Before(g.ExpiresAt) {
		return runtime.ErrDelegationExpired
	}
	g.RunID = runID
	g.UsedAt = now
	m.delegations[tenantID][jti] = g
	return nil
}

func (m *MemoryStore) RevokeGrantByJTI(_ context.Context, tenantID, jti string) error {
	g, ok := m.delegations[tenantID][jti]
	if !ok {
		return runtime.ErrDelegationInvalid
	}
	if g.RevokedAt.IsZero() {
		g.RevokedAt = m.now().UTC().Truncate(time.Microsecond)
		m.delegations[tenantID][jti] = g
	}
	return nil
}

func (m *MemoryStore) CreateRun(_ context.Context, r runtime.AgentRun) (runtime.AgentRun, error) {
	if r.ID == "" {
		r.ID = newID()
	}
	if r.StartedAt.IsZero() {
		r.StartedAt = m.now().UTC().Truncate(time.Microsecond)
	}
	if m.runs[r.TenantID] == nil {
		m.runs[r.TenantID] = map[string]runtime.AgentRun{}
	}
	m.runs[r.TenantID][r.ID] = r
	return r, nil
}

func (m *MemoryStore) GetRun(_ context.Context, tenantID, runID string) (runtime.AgentRun, error) {
	r, ok := m.runs[tenantID][runID]
	if !ok {
		return runtime.AgentRun{}, runtime.ErrRunNotFound
	}
	return r, nil
}

func (m *MemoryStore) GetRunByIdempotencyKey(_ context.Context, tenantID, idempotencyKey string) (runtime.AgentRun, error) {
	for _, r := range m.runs[tenantID] {
		if r.IdempotencyKey == idempotencyKey {
			return r, nil
		}
	}
	return runtime.AgentRun{}, runtime.ErrRunNotFound
}

func (m *MemoryStore) UpdateRunStatus(_ context.Context, tenantID, runID, expectedStatus, newStatus string, completedAt *time.Time, errorCode string) error {
	r, ok := m.runs[tenantID][runID]
	if !ok {
		return runtime.ErrRunNotFound
	}
	if r.Status != expectedStatus {
		return runtime.ErrRunNotActive
	}
	r.Status = newStatus
	if completedAt != nil {
		r.CompletedAt = completedAt.UTC()
	}
	if errorCode != "" {
		r.ErrorCode = errorCode
	}
	m.runs[tenantID][runID] = r
	return nil
}

func (m *MemoryStore) CountAllowedActions(_ context.Context, tenantID, runID, toolID, actionID string) (int, error) {
	count := 0
	for _, d := range m.decisions[tenantID][runID] {
		if d.Decision == runtime.DecisionAllowed && d.ToolID == toolID && d.ActionID == actionID {
			count++
		}
	}
	return count, nil
}

func (m *MemoryStore) AppendDecision(_ context.Context, d runtime.ActionDecision) (runtime.ActionDecision, error) {
	if d.ID == "" {
		d.ID = newID()
	}
	if d.CreatedAt.IsZero() {
		d.CreatedAt = m.now().UTC().Truncate(time.Microsecond)
	}
	chain := m.decisions[d.TenantID][d.RunID]
	prev := ""
	if len(chain) > 0 {
		prev = chain[len(chain)-1].ImmutableDigest
	}
	d.ImmutableDigest = ComputeDecisionDigest(d, prev)
	if m.decisions[d.TenantID] == nil {
		m.decisions[d.TenantID] = map[string][]runtime.ActionDecision{}
	}
	m.decisions[d.TenantID][d.RunID] = append(m.decisions[d.TenantID][d.RunID], d)
	return d, nil
}

func (m *MemoryStore) AppendApproval(_ context.Context, a runtime.ActionApproval) (runtime.ActionApproval, error) {
	if a.ID == "" {
		a.ID = newID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = m.now().UTC().Truncate(time.Microsecond)
	}
	a.ImmutableDigest = ComputeApprovalDigest(a)
	if m.approvals[a.TenantID] == nil {
		m.approvals[a.TenantID] = map[string][]runtime.ActionApproval{}
	}
	m.approvals[a.TenantID][a.RunID] = append(m.approvals[a.TenantID][a.RunID], a)
	return a, nil
}

func (m *MemoryStore) AppendConnectorInvocation(_ context.Context, inv runtime.ConnectorInvocation) (runtime.ConnectorInvocation, error) {
	if inv.ID == "" {
		inv.ID = newID()
	}
	if inv.OccurredAt.IsZero() {
		inv.OccurredAt = m.now().UTC().Truncate(time.Microsecond)
	}
	// Write-once evidence: compute the digest over the outcome fields
	// exactly as the Postgres store does (parity contract).
	if inv.ImmutableDigest == "" {
		inv.ImmutableDigest = connectors.ConnectorInvocationDigest(inv)
	}
	if m.invocations[inv.TenantID] == nil {
		m.invocations[inv.TenantID] = map[string]runtime.ConnectorInvocation{}
	}
	if _, exists := m.invocations[inv.TenantID][inv.DecisionID]; exists {
		return runtime.ConnectorInvocation{}, runtime.ErrIdempotencyConflict
	}
	m.invocations[inv.TenantID][inv.DecisionID] = inv
	// Phase 8.2: index by the semantic idempotency key (latest wins).
	if inv.IdempotencyKey != "" {
		if m.invocationsByKey[inv.TenantID] == nil {
			m.invocationsByKey[inv.TenantID] = map[string]runtime.ConnectorInvocation{}
		}
		m.invocationsByKey[inv.TenantID][inv.IdempotencyKey] = inv
	}
	return inv, nil
}

// GetConnectorInvocationByDedupKey returns the latest invocation
// recorded under the semantic idempotency key (Phase 8.2 replay check).
// The caller decides replayability from the outcome.
func (m *MemoryStore) GetConnectorInvocationByDedupKey(_ context.Context, tenantID, idempotencyKey string) (runtime.ConnectorInvocation, bool, error) {
	if idempotencyKey == "" {
		return runtime.ConnectorInvocation{}, false, nil
	}
	inv, ok := m.invocationsByKey[tenantID][idempotencyKey]
	return inv, ok, nil
}

func (m *MemoryStore) ListConnectorInvocations(_ context.Context, tenantID, connectorID string, limit int) ([]runtime.ConnectorInvocation, error) {
	if limit <= 0 {
		limit = 20
	}
	var out []runtime.ConnectorInvocation
	for _, inv := range m.invocations[tenantID] {
		if inv.ConnectorID == connectorID {
			out = append(out, inv)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OccurredAt.After(out[j].OccurredAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemoryStore) GetApprovalForConsume(_ context.Context, tenantID, runID, toolID, actionID, resourceRef string) (runtime.ActionApproval, error) {
	now := m.now().UTC()
	for _, a := range m.approvals[tenantID][runID] {
		if a.ToolID == toolID && a.ActionID == actionID && a.ResourceRef == resourceRef &&
			a.Decision == runtime.ApprovalApproved && a.ConsumedAt.IsZero() && now.Before(a.ExpiresAt) {
			return a, nil
		}
	}
	return runtime.ActionApproval{}, runtime.ErrApprovalNotFound
}

func (m *MemoryStore) ConsumeApproval(_ context.Context, tenantID, approvalID string) error {
	for _, list := range m.approvals[tenantID] {
		for i := range list {
			if list[i].ID == approvalID && list[i].ConsumedAt.IsZero() {
				list[i].ConsumedAt = m.now().UTC().Truncate(time.Microsecond)
				return nil
			}
		}
	}
	return runtime.ErrApprovalConsumed
}

func (m *MemoryStore) GetDeniedApproval(_ context.Context, tenantID, runID, toolID, actionID, resourceRef string) (runtime.ActionApproval, error) {
	var latest runtime.ActionApproval
	found := false
	for _, a := range m.approvals[tenantID][runID] {
		if a.ToolID == toolID && a.ActionID == actionID && a.ResourceRef == resourceRef && a.Decision == runtime.ApprovalDenied {
			if !found || a.CreatedAt.After(latest.CreatedAt) {
				latest = a
				found = true
			}
		}
	}
	if !found {
		return runtime.ActionApproval{}, runtime.ErrApprovalNotFound
	}
	return latest, nil
}

func (m *MemoryStore) GetApprovalByIdempotencyKey(_ context.Context, tenantID, runID, toolID, actionID, resourceRef, idempotencyKey string) (runtime.ActionApproval, error) {
	for _, a := range m.approvals[tenantID][runID] {
		if a.IdempotencyKey == idempotencyKey && a.ToolID == toolID && a.ActionID == actionID && a.ResourceRef == resourceRef {
			return a, nil
		}
	}
	return runtime.ActionApproval{}, runtime.ErrApprovalNotFound
}

func (m *MemoryStore) ListTools(_ context.Context, tenantID string) ([]runtime.Tool, error) {
	out := make([]runtime.Tool, 0, len(m.tools[tenantID]))
	for _, t := range m.tools[tenantID] {
		out = append(out, t)
	}
	return out, nil
}

func (m *MemoryStore) GetTool(_ context.Context, tenantID, toolID string) (runtime.Tool, error) {
	t, ok := m.tools[tenantID][toolID]
	if !ok {
		return runtime.Tool{}, runtime.ErrToolNotFound
	}
	return t, nil
}

func (m *MemoryStore) GetToolByName(_ context.Context, tenantID, name string) (runtime.Tool, error) {
	for _, t := range m.tools[tenantID] {
		if t.Name == name {
			return t, nil
		}
	}
	return runtime.Tool{}, runtime.ErrToolNotFound
}

func (m *MemoryStore) ListToolActions(_ context.Context, tenantID, toolID string) ([]runtime.ToolAction, error) {
	out := make([]runtime.ToolAction, 0)
	for _, a := range m.actions[tenantID] {
		if a.ToolID == toolID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *MemoryStore) GetToolAction(_ context.Context, tenantID, actionID string) (runtime.ToolAction, error) {
	a, ok := m.actions[tenantID][actionID]
	if !ok {
		return runtime.ToolAction{}, runtime.ErrActionNotFound
	}
	return a, nil
}

func (m *MemoryStore) GetToolActionByName(_ context.Context, tenantID, toolID, action string) (runtime.ToolAction, error) {
	for _, a := range m.actions[tenantID] {
		if a.ToolID == toolID && a.Action == action {
			return a, nil
		}
	}
	return runtime.ToolAction{}, runtime.ErrActionNotFound
}

func (m *MemoryStore) ListGrants(_ context.Context, tenantID, agentID string) ([]runtime.AgentToolGrant, error) {
	out := make([]runtime.AgentToolGrant, 0)
	for _, g := range m.grants[tenantID] {
		if g.AgentID == agentID {
			out = append(out, g)
		}
	}
	return out, nil
}

func (m *MemoryStore) GetGrantsForTuple(_ context.Context, tenantID, agentID, versionID, toolID, actionID string) ([]runtime.AgentToolGrant, error) {
	out := make([]runtime.AgentToolGrant, 0)
	for _, g := range m.grants[tenantID] {
		if g.AgentID == agentID && g.VersionID == versionID && g.ToolID == toolID && g.ActionID == actionID {
			out = append(out, g)
		}
	}
	return out, nil
}

func (m *MemoryStore) GetGrant(_ context.Context, tenantID, grantID string) (runtime.AgentToolGrant, error) {
	g, ok := m.grants[tenantID][grantID]
	if !ok {
		return runtime.AgentToolGrant{}, runtime.ErrGrantNotFound
	}
	return g, nil
}

func (m *MemoryStore) ListRuns(_ context.Context, tenantID string) ([]runtime.AgentRun, error) {
	out := make([]runtime.AgentRun, 0, len(m.runs[tenantID]))
	for _, r := range m.runs[tenantID] {
		out = append(out, r)
	}
	return out, nil
}

func (m *MemoryStore) ListDecisions(_ context.Context, tenantID, runID string) ([]runtime.ActionDecision, error) {
	return m.decisions[tenantID][runID], nil
}

func (m *MemoryStore) ListApprovals(_ context.Context, tenantID, runID string) ([]runtime.ActionApproval, error) {
	return m.approvals[tenantID][runID], nil
}

// ---------------------------------------------------------------------
// Postgres store.
// ---------------------------------------------------------------------

// queryer is satisfied by both *sql.DB and *sql.Tx so the read surface
// can be shared between the store and its transactions.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// PostgresStore is the durable implementation. Evidence tables
// (agent_action_decisions, agent_action_approvals) are write-once at the
// schema level (migration 015 rules); the grant consume and approval
// consume are the only state transitions and are performed atomically by
// single UPDATEs guarded by RowsAffected.
type PostgresStore struct {
	pgReader
	db  *sql.DB
	now func() time.Time
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{pgReader: pgReader{q: db}, db: db, now: time.Now}
}

func (p *PostgresStore) Transact(ctx context.Context, lockKey string, fn func(tx TxStore) error) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Serialize mutations per entity (the state read, the conditional
	// updates, and the chain append are one atomic step), keyed by a
	// short UTC time bucket so concurrent writers for the same entity
	// proceed in parallel instead of stacking on a single global lock
	// (same striping pattern as the query audit writer). One-time
	// operations stay safe: grant/run consumes are guarded single
	// UPDATEs keyed on RowsAffected, and idempotency keys are unique.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1 || ':' || floor(extract(epoch from now()))))`, lockKey); err != nil {
		return err
	}
	ptx := &postgresTx{pgReader: pgReader{q: tx}, tx: tx}
	if err := fn(ptx); err != nil {
		return err
	}
	if err := ptx.flushOutbox(ctx); err != nil {
		return err
	}
	return tx.Commit()
}

type postgresTx struct {
	pgReader
	tx *sql.Tx
	// outboxPending collects EnqueueOutbox calls during the transaction;
	// flushOutbox inserts them all right before commit so outbox events
	// land in the same transaction as the business + evidence rows.
	outboxPending []runtime.OutboxEvent
}

// pgReader implements the read surface against a *sql.DB or *sql.Tx.
type pgReader struct {
	q queryer
}

func scanTool(row interface{ Scan(...any) error }) (runtime.Tool, error) {
	var t runtime.Tool
	err := row.Scan(&t.ID, &t.TenantID, &t.Name, &t.Description, &t.Transport, &t.EndpointOrServer,
		&t.OwnerPrincipalID, &t.Region, &t.ManifestDigest, &t.Lifecycle, &t.CreatedAt, &t.UpdatedAt)
	return t, err
}

const toolColumns = `id::text, tenant_id, name, description, transport, endpoint_or_server, owner_principal_id, region, manifest_digest, lifecycle, created_at, updated_at`

func (p *postgresTx) CreateTool(ctx context.Context, t runtime.Tool) (runtime.Tool, error) {
	row := p.tx.QueryRowContext(ctx, `
		INSERT INTO tools (tenant_id, name, description, transport, endpoint_or_server, owner_principal_id, region, manifest_digest, lifecycle)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING `+toolColumns,
		t.TenantID, t.Name, t.Description, t.Transport, t.EndpointOrServer, t.OwnerPrincipalID, t.Region, t.ManifestDigest, t.Lifecycle)
	created, err := scanTool(row)
	if err != nil && isUniqueViolation(err) {
		return runtime.Tool{}, runtime.ErrToolNameConflict
	}
	return created, err
}

func (p *postgresTx) TransitionTool(ctx context.Context, tenantID, toolID, expectedLifecycle, newLifecycle string) error {
	tag, err := p.tx.ExecContext(ctx, `
		UPDATE tools SET lifecycle = $3, updated_at = now()
		WHERE id::text = $1 AND tenant_id = $2 AND lifecycle = $4
	`, toolID, tenantID, newLifecycle, expectedLifecycle)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		var exists int
		if err := p.tx.QueryRowContext(ctx, `SELECT 1 FROM tools WHERE id::text = $1 AND tenant_id = $2`, toolID, tenantID).Scan(&exists); err != nil {
			return runtime.ErrToolNotFound
		}
		return runtime.ErrToolInvalidState
	}
	return nil
}

const actionColumns = `id::text, tenant_id, tool_id::text, action, resource_type, risk_level, read_only, requires_human_approval, status, created_at`

func (p *postgresTx) CreateToolAction(ctx context.Context, a runtime.ToolAction) (runtime.ToolAction, error) {
	row := p.tx.QueryRowContext(ctx, `
		INSERT INTO tool_actions (tenant_id, tool_id, action, resource_type, risk_level, read_only, requires_human_approval, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+actionColumns,
		a.TenantID, a.ToolID, a.Action, a.ResourceType, a.RiskLevel, a.ReadOnly, a.RequiresHumanApproval, a.Status)
	var created runtime.ToolAction
	err := row.Scan(&created.ID, &created.TenantID, &created.ToolID, &created.Action, &created.ResourceType,
		&created.RiskLevel, &created.ReadOnly, &created.RequiresHumanApproval, &created.Status, &created.CreatedAt)
	if err != nil && isUniqueViolation(err) {
		return runtime.ToolAction{}, runtime.ErrActionConflict
	}
	return created, err
}

func (p *postgresTx) UpdateActionStatus(ctx context.Context, tenantID, actionID, expectedStatus, newStatus string) error {
	tag, err := p.tx.ExecContext(ctx, `
		UPDATE tool_actions SET status = $3
		WHERE id::text = $1 AND tenant_id = $2 AND status = $4
	`, actionID, tenantID, newStatus, expectedStatus)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		var exists int
		if err := p.tx.QueryRowContext(ctx, `SELECT 1 FROM tool_actions WHERE id::text = $1 AND tenant_id = $2`, actionID, tenantID).Scan(&exists); err != nil {
			return runtime.ErrActionNotFound
		}
		return runtime.ErrInvalidRequest
	}
	return nil
}

const grantColumns = `id::text, tenant_id, agent_id::text, version_id::text, tool_id::text, action_id::text, resource_scope, region_constraint, call_limit_per_run, requires_approval, granted_by, granted_at, revoked_at`

func scanToolGrant(row interface{ Scan(...any) error }) (runtime.AgentToolGrant, error) {
	var g runtime.AgentToolGrant
	var revokedAt sql.NullTime
	err := row.Scan(&g.ID, &g.TenantID, &g.AgentID, &g.VersionID, &g.ToolID, &g.ActionID,
		&g.ResourceScope, &g.RegionConstraint, &g.CallLimitPerRun, &g.RequiresApproval,
		&g.GrantedBy, &g.GrantedAt, &revokedAt)
	if revokedAt.Valid {
		g.RevokedAt = revokedAt.Time
	}
	return g, err
}

func (p *postgresTx) CreateGrant(ctx context.Context, g runtime.AgentToolGrant) (runtime.AgentToolGrant, error) {
	row := p.tx.QueryRowContext(ctx, `
		INSERT INTO agent_tool_grants (tenant_id, agent_id, version_id, tool_id, action_id, resource_scope, region_constraint, call_limit_per_run, requires_approval, granted_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING `+grantColumns,
		g.TenantID, g.AgentID, g.VersionID, g.ToolID, g.ActionID, g.ResourceScope, g.RegionConstraint,
		g.CallLimitPerRun, g.RequiresApproval, g.GrantedBy)
	created, err := scanToolGrant(row)
	if err != nil && isUniqueViolation(err) {
		return runtime.AgentToolGrant{}, runtime.ErrGrantConflict
	}
	return created, err
}

func (p *postgresTx) RevokeGrant(ctx context.Context, tenantID, grantID string) error {
	tag, err := p.tx.ExecContext(ctx, `
		UPDATE agent_tool_grants SET revoked_at = now()
		WHERE id::text = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`, grantID, tenantID)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		var exists int
		if err := p.tx.QueryRowContext(ctx, `SELECT 1 FROM agent_tool_grants WHERE id::text = $1 AND tenant_id = $2`, grantID, tenantID).Scan(&exists); err != nil {
			return runtime.ErrGrantNotFound
		}
		return runtime.ErrGrantRevoked
	}
	return nil
}

const delegationColumns = `id::text, tenant_id, agent_id::text, agent_version_id::text, token_jti, delegator_principal_id, subject_principal_id, purpose, region, permitted_actions, permitted_actions_digest, issued_at, expires_at, used_at, run_id::text, revoked_at, idempotency_key, immutable_digest, delegation_depth, parent_grant_id::text, root_grant_id::text, delegator_agent_id, delegatee_agent_id, authority_scope_digest, parent_scope_digest, attenuation_digest, external_agent_id::text, issued_via`

func scanDelegation(row interface{ Scan(...any) error }) (runtime.DelegationGrant, error) {
	var g runtime.DelegationGrant
	var runID, parentGrantID, rootGrantID, externalAgentID, permittedActions, delegatorAgentID, delegateeAgentID, idempotencyKey sql.NullString
	var usedAt, revokedAt sql.NullTime
	err := row.Scan(&g.ID, &g.TenantID, &g.AgentID, &g.AgentVersionID, &g.TokenJTI,
		&g.DelegatorPrincipalID, &g.SubjectPrincipalID, &g.Purpose, &g.Region, &permittedActions,
		&g.PermittedActionsDigest, &g.IssuedAt, &g.ExpiresAt, &usedAt, &runID,
		&revokedAt, &idempotencyKey, &g.ImmutableDigest, &g.DelegationDepth, &parentGrantID,
		&rootGrantID, &delegatorAgentID, &delegateeAgentID, &g.AuthorityScopeDigest,
		&g.ParentScopeDigest, &g.AttenuationDigest, &externalAgentID, &g.IssuedVia)
	if idempotencyKey.Valid {
		g.IdempotencyKey = idempotencyKey.String
	}
	if usedAt.Valid {
		g.UsedAt = usedAt.Time
	}
	if revokedAt.Valid {
		g.RevokedAt = revokedAt.Time
	}
	if runID.Valid {
		g.RunID = runID.String
	}
	if parentGrantID.Valid {
		g.ParentGrantID = parentGrantID.String
	}
	if rootGrantID.Valid {
		g.RootGrantID = rootGrantID.String
	}
	if delegatorAgentID.Valid {
		g.DelegatorAgentID = delegatorAgentID.String
	}
	if delegateeAgentID.Valid {
		g.DelegateeAgentID = delegateeAgentID.String
	}
	g.IsAgentDelegation = delegateeAgentID.Valid
	if externalAgentID.Valid {
		g.ExternalAgentID = externalAgentID.String
	}
	if permittedActions.Valid && permittedActions.String != "" {
		g.PermittedActions = strings.Split(permittedActions.String, ",")
	}
	return g, err
}

func (p *postgresTx) CreateDelegationGrant(ctx context.Context, g runtime.DelegationGrant) error {
	_, err := p.tx.ExecContext(ctx, `
		INSERT INTO delegated_authority_grants
			(id, tenant_id, agent_id, agent_version_id, token_jti, delegator_principal_id, subject_principal_id,
			 purpose, region, permitted_actions, permitted_actions_digest, issued_at, expires_at, idempotency_key,
			 immutable_digest, delegation_depth, parent_grant_id, root_grant_id, delegator_agent_id,
			 delegatee_agent_id, authority_scope_digest, parent_scope_digest, attenuation_digest,
			 external_agent_id, issued_via)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::uuid, $18::uuid,
		        $19, $20, $21, $22, $23, $24, $25)
	`, g.ID, g.TenantID, g.AgentID, g.AgentVersionID, g.TokenJTI, g.DelegatorPrincipalID, g.SubjectPrincipalID,
		g.Purpose, g.Region, joinAllowed(g.PermittedActions), g.PermittedActionsDigest, g.IssuedAt, g.ExpiresAt,
		nullString(g.IdempotencyKey), g.ImmutableDigest, g.DelegationDepth, nullString(g.ParentGrantID),
		nullString(g.RootGrantID), nullString(g.DelegatorAgentID), nullString(g.DelegateeAgentID), g.AuthorityScopeDigest,
		g.ParentScopeDigest, g.AttenuationDigest, notNullString(g.ExternalAgentID), g.IssuedVia)
	if err != nil && isUniqueViolation(err) {
		return runtime.ErrIdempotencyConflict
	}
	return err
}

func (p *postgresTx) GetDelegationGrantByJTI(ctx context.Context, tenantID, jti string) (runtime.DelegationGrant, error) {
	return scanDelegation(p.tx.QueryRowContext(ctx, `
		SELECT `+delegationColumns+` FROM delegated_authority_grants
		WHERE tenant_id = $1 AND token_jti = $2
	`, tenantID, jti))
}

func (r pgReader) GetDelegationGrantByIdempotencyKey(ctx context.Context, tenantID, idempotencyKey string) (runtime.DelegationGrant, error) {
	return scanDelegation(r.q.QueryRowContext(ctx, `
		SELECT `+delegationColumns+` FROM delegated_authority_grants
		WHERE tenant_id = $1 AND idempotency_key = $2
	`, tenantID, idempotencyKey))
}

func (p *postgresTx) ConsumeGrantForRun(ctx context.Context, tenantID, jti, runID string) error {
	tag, err := p.tx.ExecContext(ctx, `
		UPDATE delegated_authority_grants
		SET used_at = now(), run_id = $3::uuid
		WHERE tenant_id = $1 AND token_jti = $2
		  AND run_id IS NULL AND revoked_at IS NULL AND expires_at > now()
	`, tenantID, jti, runID)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		g, getErr := scanDelegation(p.tx.QueryRowContext(ctx, `
			SELECT `+delegationColumns+` FROM delegated_authority_grants
			WHERE tenant_id = $1 AND token_jti = $2
		`, tenantID, jti))
		if getErr != nil {
			return runtime.ErrDelegationInvalid
		}
		if !g.RevokedAt.IsZero() {
			return runtime.ErrDelegationRevoked
		}
		if g.RunID != "" {
			return runtime.ErrDelegationReused
		}
		if time.Now().UTC().After(g.ExpiresAt) {
			return runtime.ErrDelegationExpired
		}
		return runtime.ErrDelegationInvalid
	}
	return nil
}

func (p *postgresTx) RevokeGrantByJTI(ctx context.Context, tenantID, jti string) error {
	tag, err := p.tx.ExecContext(ctx, `
		UPDATE delegated_authority_grants SET revoked_at = now()
		WHERE tenant_id = $1 AND token_jti = $2 AND revoked_at IS NULL
	`, tenantID, jti)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		if _, err := scanDelegation(p.tx.QueryRowContext(ctx, `
			SELECT `+delegationColumns+` FROM delegated_authority_grants
			WHERE tenant_id = $1 AND token_jti = $2
		`, tenantID, jti)); err != nil {
			return runtime.ErrDelegationInvalid
		}
		return runtime.ErrDelegationRevoked
	}
	return nil
}

const runColumns = `id::text, tenant_id, agent_id::text, delegation_grant_id::text, idempotency_key, user_id, purpose, region, status, trace_id, started_at, completed_at, error_code, delegation_depth, chain_verified, root_grant_id::text, parent_grant_id::text, external_agent_id, organization_id, customer_principal_id, consent_id`

func scanRun(row interface{ Scan(...any) error }) (runtime.AgentRun, error) {
	var r runtime.AgentRun
	var idem, root, parent, ext, org, cust, consent sql.NullString
	var completedAt sql.NullTime
	err := row.Scan(&r.ID, &r.TenantID, &r.AgentID, &r.DelegationGrantID, &idem, &r.UserID,
		&r.Purpose, &r.Region, &r.Status, &r.TraceID, &r.StartedAt, &completedAt, &r.ErrorCode,
		&r.DelegationDepth, &r.ChainVerified, &root, &parent, &ext, &org, &cust, &consent)
	if completedAt.Valid {
		r.CompletedAt = completedAt.Time
	}
	if idem.Valid {
		r.IdempotencyKey = idem.String
	}
	if root.Valid {
		r.RootGrantID = root.String
	}
	if parent.Valid {
		r.ParentGrantID = parent.String
	}
	if ext.Valid {
		r.ExternalAgentID = ext.String
	}
	if org.Valid {
		r.OrganizationID = org.String
	}
	if cust.Valid {
		r.CustomerPrincipalID = cust.String
	}
	if consent.Valid {
		r.ConsentID = consent.String
	}
	return r, err
}

func (p *postgresTx) CreateRun(ctx context.Context, r runtime.AgentRun) (runtime.AgentRun, error) {
	row := p.tx.QueryRowContext(ctx, `
		INSERT INTO agent_runs (tenant_id, agent_id, delegation_grant_id, idempotency_key, user_id, purpose, region, status, delegation_depth, chain_verified, root_grant_id, parent_grant_id, external_agent_id, organization_id, customer_principal_id, consent_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING `+runColumns,
		r.TenantID, r.AgentID, r.DelegationGrantID, nullString(r.IdempotencyKey), r.UserID, r.Purpose, r.Region, r.Status,
		r.DelegationDepth, r.ChainVerified, nullString(r.RootGrantID), nullString(r.ParentGrantID),
		notNullString(r.ExternalAgentID), notNullString(r.OrganizationID), notNullString(r.CustomerPrincipalID), notNullString(r.ConsentID))
	created, err := scanRun(row)
	if err != nil && isUniqueViolation(err) {
		return runtime.AgentRun{}, runtime.ErrIdempotencyConflict
	}
	return created, err
}

func (p *postgresTx) GetRun(ctx context.Context, tenantID, runID string) (runtime.AgentRun, error) {
	return scanRun(p.tx.QueryRowContext(ctx, `
		SELECT `+runColumns+` FROM agent_runs WHERE tenant_id = $1 AND id::text = $2
	`, tenantID, runID))
}

func (r pgReader) GetRunByIdempotencyKey(ctx context.Context, tenantID, idempotencyKey string) (runtime.AgentRun, error) {
	return scanRun(r.q.QueryRowContext(ctx, `
		SELECT `+runColumns+` FROM agent_runs
		WHERE tenant_id = $1 AND idempotency_key = $2
	`, tenantID, idempotencyKey))
}

func (r pgReader) GetRun(ctx context.Context, tenantID, runID string) (runtime.AgentRun, error) {
	run, err := scanRun(r.q.QueryRowContext(ctx, `
		SELECT `+runColumns+` FROM agent_runs WHERE tenant_id = $1 AND id::text = $2
	`, tenantID, runID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.AgentRun{}, runtime.ErrRunNotFound
	}
	return run, err
}

func (p *postgresTx) UpdateRunStatus(ctx context.Context, tenantID, runID, expectedStatus, newStatus string, completedAt *time.Time, errorCode string) error {
	tag, err := p.tx.ExecContext(ctx, `
		UPDATE agent_runs SET status = $3, completed_at = $4, error_code = $5
		WHERE tenant_id = $1 AND id::text = $2 AND status = $6
	`, tenantID, runID, newStatus, completedAt, errorCode, expectedStatus)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		var exists int
		if err := p.tx.QueryRowContext(ctx, `SELECT 1 FROM agent_runs WHERE tenant_id = $1 AND id::text = $2`, tenantID, runID).Scan(&exists); err != nil {
			return runtime.ErrRunNotFound
		}
		return runtime.ErrRunNotActive
	}
	return nil
}

func (p *postgresTx) CountAllowedActions(ctx context.Context, tenantID, runID, toolID, actionID string) (int, error) {
	var count int
	err := p.tx.QueryRowContext(ctx, `
		SELECT count(*) FROM agent_action_decisions
		WHERE tenant_id = $1 AND run_id = $2::uuid AND tool_id = $3::uuid AND action_id = $4::uuid
		  AND decision = 'allowed'
	`, tenantID, runID, toolID, actionID).Scan(&count)
	return count, err
}

const decisionColumns = `id::text, tenant_id, agent_id::text, run_id::text, delegation_grant_id::text, tool_id::text, action_id::text, resource_ref, decision, reason, reason_code, policy_version, immutable_digest, created_at, delegation_depth, chain_verified`

func scanDecision(row interface{ Scan(...any) error }) (runtime.ActionDecision, error) {
	var d runtime.ActionDecision
	var toolID, actionID sql.NullString
	err := row.Scan(&d.ID, &d.TenantID, &d.AgentID, &d.RunID, &d.DelegationGrantID,
		&toolID, &actionID, &d.ResourceRef, &d.Decision, &d.Reason, &d.ReasonCode, &d.PolicyVersion,
		&d.ImmutableDigest, &d.CreatedAt, &d.DelegationDepth, &d.ChainVerified)
	if toolID.Valid {
		d.ToolID = toolID.String
	}
	if actionID.Valid {
		d.ActionID = actionID.String
	}
	return d, err
}

func (p *postgresTx) AppendDecision(ctx context.Context, d runtime.ActionDecision) (runtime.ActionDecision, error) {
	var prev string
	if err := p.tx.QueryRowContext(ctx, `
		SELECT immutable_digest FROM agent_action_decisions
		WHERE tenant_id = $1 AND run_id = $2::uuid
		ORDER BY created_at DESC, id DESC LIMIT 1
	`, d.TenantID, d.RunID).Scan(&prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return runtime.ActionDecision{}, err
	}
	d.ImmutableDigest = ComputeDecisionDigest(d, prev)
	row := p.tx.QueryRowContext(ctx, `
		INSERT INTO agent_action_decisions
			(tenant_id, agent_id, run_id, delegation_grant_id, tool_id, action_id, resource_ref, decision, reason, reason_code, policy_version, immutable_digest, delegation_depth, chain_verified)
		VALUES ($1, $2, $3::uuid, $4::uuid, $5::uuid, $6::uuid, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING `+decisionColumns,
		d.TenantID, d.AgentID, d.RunID, d.DelegationGrantID, nullString(d.ToolID), nullString(d.ActionID),
		d.ResourceRef, d.Decision, d.Reason, d.ReasonCode, d.PolicyVersion, d.ImmutableDigest,
		d.DelegationDepth, d.ChainVerified)
	created, err := scanDecision(row)
	if err != nil {
		return runtime.ActionDecision{}, err
	}
	return created, nil
}

const approvalColumns = `id::text, tenant_id, run_id::text, tool_id::text, action_id::text, resource_ref, approving_principal_id, decision, expires_at, consumed_at, idempotency_key, immutable_digest, created_at`

func scanApproval(row interface{ Scan(...any) error }) (runtime.ActionApproval, error) {
	var a runtime.ActionApproval
	var idem sql.NullString
	err := row.Scan(&a.ID, &a.TenantID, &a.RunID, &a.ToolID, &a.ActionID, &a.ResourceRef,
		&a.ApprovingPrincipalID, &a.Decision, &a.ExpiresAt, &a.ConsumedAt, &idem, &a.ImmutableDigest, &a.CreatedAt)
	if idem.Valid {
		a.IdempotencyKey = idem.String
	}
	return a, err
}

func (p *postgresTx) AppendApproval(ctx context.Context, a runtime.ActionApproval) (runtime.ActionApproval, error) {
	a.ImmutableDigest = ComputeApprovalDigest(a)
	row := p.tx.QueryRowContext(ctx, `
		INSERT INTO agent_action_approvals
			(tenant_id, run_id, tool_id, action_id, resource_ref, approving_principal_id, decision, expires_at, idempotency_key, immutable_digest)
		VALUES ($1, $2::uuid, $3::uuid, $4::uuid, $5, $6, $7, $8, $9, $10)
		RETURNING `+approvalColumns,
		a.TenantID, a.RunID, a.ToolID, a.ActionID, a.ResourceRef, a.ApprovingPrincipalID,
		a.Decision, a.ExpiresAt, nullString(a.IdempotencyKey), a.ImmutableDigest)
	created, err := scanApproval(row)
	if err != nil && isUniqueViolation(err) {
		return runtime.ActionApproval{}, runtime.ErrIdempotencyConflict
	}
	return created, err
}

func (p *postgresTx) GetApprovalForConsume(ctx context.Context, tenantID, runID, toolID, actionID, resourceRef string) (runtime.ActionApproval, error) {
	approval, err := scanApproval(p.tx.QueryRowContext(ctx, `
		SELECT `+approvalColumns+` FROM agent_action_approvals
		WHERE tenant_id = $1 AND run_id = $2::uuid AND tool_id = $3::uuid AND action_id = $4::uuid
		  AND resource_ref = $5 AND decision = 'approved' AND consumed_at IS NULL AND expires_at > now()
		ORDER BY created_at DESC LIMIT 1
	`, tenantID, runID, toolID, actionID, resourceRef))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.ActionApproval{}, runtime.ErrApprovalNotFound
	}
	return approval, err
}

func (p *postgresTx) ConsumeApproval(ctx context.Context, tenantID, approvalID string) error {
	tag, err := p.tx.ExecContext(ctx, `
		UPDATE agent_action_approvals SET consumed_at = now()
		WHERE tenant_id = $1 AND id::text = $2 AND consumed_at IS NULL
	`, tenantID, approvalID)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return runtime.ErrApprovalConsumed
	}
	return nil
}

func (p *postgresTx) GetDeniedApproval(ctx context.Context, tenantID, runID, toolID, actionID, resourceRef string) (runtime.ActionApproval, error) {
	approval, err := scanApproval(p.tx.QueryRowContext(ctx, `
		SELECT `+approvalColumns+` FROM agent_action_approvals
		WHERE tenant_id = $1 AND run_id = $2::uuid AND tool_id = $3::uuid AND action_id = $4::uuid
		  AND resource_ref = $5 AND decision = 'denied'
		ORDER BY created_at DESC LIMIT 1
	`, tenantID, runID, toolID, actionID, resourceRef))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.ActionApproval{}, runtime.ErrApprovalNotFound
	}
	return approval, err
}

func (p *postgresTx) GetApprovalByIdempotencyKey(ctx context.Context, tenantID, runID, toolID, actionID, resourceRef, idempotencyKey string) (runtime.ActionApproval, error) {
	approval, err := scanApproval(p.tx.QueryRowContext(ctx, `
		SELECT `+approvalColumns+` FROM agent_action_approvals
		WHERE tenant_id = $1 AND run_id = $2::uuid AND tool_id = $3::uuid AND action_id = $4::uuid
		  AND resource_ref = $5 AND idempotency_key = $6
	`, tenantID, runID, toolID, actionID, resourceRef, idempotencyKey))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.ActionApproval{}, runtime.ErrApprovalNotFound
	}
	return approval, err
}

// --- Postgres readers (shared by PostgresStore and postgresTx) ---

func (r pgReader) ListTools(ctx context.Context, tenantID string) ([]runtime.Tool, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT `+toolColumns+` FROM tools WHERE tenant_id = $1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.Tool
	for rows.Next() {
		t, err := scanTool(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r pgReader) GetTool(ctx context.Context, tenantID, toolID string) (runtime.Tool, error) {
	t, err := scanTool(r.q.QueryRowContext(ctx, `SELECT `+toolColumns+` FROM tools WHERE tenant_id = $1 AND id::text = $2`, tenantID, toolID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.Tool{}, runtime.ErrToolNotFound
	}
	return t, err
}

func (r pgReader) GetToolByName(ctx context.Context, tenantID, name string) (runtime.Tool, error) {
	t, err := scanTool(r.q.QueryRowContext(ctx, `SELECT `+toolColumns+` FROM tools WHERE tenant_id = $1 AND name = $2`, tenantID, name))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.Tool{}, runtime.ErrToolNotFound
	}
	return t, err
}

func (r pgReader) ListToolActions(ctx context.Context, tenantID, toolID string) ([]runtime.ToolAction, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT `+actionColumns+` FROM tool_actions WHERE tenant_id = $1 AND tool_id = $2::uuid ORDER BY action`, tenantID, toolID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.ToolAction
	for rows.Next() {
		var a runtime.ToolAction
		if err := rows.Scan(&a.ID, &a.TenantID, &a.ToolID, &a.Action, &a.ResourceType, &a.RiskLevel,
			&a.ReadOnly, &a.RequiresHumanApproval, &a.Status, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r pgReader) GetToolAction(ctx context.Context, tenantID, actionID string) (runtime.ToolAction, error) {
	var a runtime.ToolAction
	err := r.q.QueryRowContext(ctx, `SELECT `+actionColumns+` FROM tool_actions WHERE tenant_id = $1 AND id::text = $2`, tenantID, actionID).
		Scan(&a.ID, &a.TenantID, &a.ToolID, &a.Action, &a.ResourceType, &a.RiskLevel,
			&a.ReadOnly, &a.RequiresHumanApproval, &a.Status, &a.CreatedAt)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.ToolAction{}, runtime.ErrActionNotFound
	}
	return a, err
}

func (r pgReader) GetToolActionByName(ctx context.Context, tenantID, toolID, action string) (runtime.ToolAction, error) {
	var a runtime.ToolAction
	err := r.q.QueryRowContext(ctx, `SELECT `+actionColumns+` FROM tool_actions WHERE tenant_id = $1 AND tool_id = $2::uuid AND action = $3`, tenantID, toolID, action).
		Scan(&a.ID, &a.TenantID, &a.ToolID, &a.Action, &a.ResourceType, &a.RiskLevel,
			&a.ReadOnly, &a.RequiresHumanApproval, &a.Status, &a.CreatedAt)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.ToolAction{}, runtime.ErrActionNotFound
	}
	return a, err
}

func (r pgReader) ListGrants(ctx context.Context, tenantID, agentID string) ([]runtime.AgentToolGrant, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT `+grantColumns+` FROM agent_tool_grants WHERE tenant_id = $1 AND agent_id = $2::uuid ORDER BY granted_at DESC`, tenantID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.AgentToolGrant
	for rows.Next() {
		var g runtime.AgentToolGrant
		if err := rows.Scan(&g.ID, &g.TenantID, &g.AgentID, &g.VersionID, &g.ToolID, &g.ActionID,
			&g.ResourceScope, &g.RegionConstraint, &g.CallLimitPerRun, &g.RequiresApproval,
			&g.GrantedBy, &g.GrantedAt, &g.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (r pgReader) GetGrantsForTuple(ctx context.Context, tenantID, agentID, versionID, toolID, actionID string) ([]runtime.AgentToolGrant, error) {
	rows, err := r.q.QueryContext(ctx, `
		SELECT `+grantColumns+` FROM agent_tool_grants
		WHERE tenant_id = $1 AND agent_id = $2::uuid AND version_id = $3::uuid AND tool_id = $4::uuid AND action_id = $5::uuid
		ORDER BY granted_at DESC
	`, tenantID, agentID, versionID, toolID, actionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.AgentToolGrant
	for rows.Next() {
		g, err := scanToolGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (r pgReader) GetGrant(ctx context.Context, tenantID, grantID string) (runtime.AgentToolGrant, error) {
	g, err := scanToolGrant(r.q.QueryRowContext(ctx, `SELECT `+grantColumns+` FROM agent_tool_grants WHERE tenant_id = $1 AND id::text = $2`, tenantID, grantID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.AgentToolGrant{}, runtime.ErrGrantNotFound
	}
	return g, err
}

func (r pgReader) ListRuns(ctx context.Context, tenantID string) ([]runtime.AgentRun, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT `+runColumns+` FROM agent_runs WHERE tenant_id = $1 ORDER BY started_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.AgentRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (r pgReader) ListDecisions(ctx context.Context, tenantID, runID string) ([]runtime.ActionDecision, error) {
	rows, err := r.q.QueryContext(ctx, `
		SELECT `+decisionColumns+` FROM agent_action_decisions
		WHERE tenant_id = $1 AND run_id = $2::uuid ORDER BY created_at ASC, id ASC
	`, tenantID, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.ActionDecision
	for rows.Next() {
		d, err := scanDecision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r pgReader) ListApprovals(ctx context.Context, tenantID, runID string) ([]runtime.ActionApproval, error) {
	rows, err := r.q.QueryContext(ctx, `
		SELECT `+approvalColumns+` FROM agent_action_approvals
		WHERE tenant_id = $1 AND run_id = $2::uuid ORDER BY created_at ASC, id ASC
	`, tenantID, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.ActionApproval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") || strings.Contains(msg, "unique_violation") || strings.Contains(msg, "sqlstate 23505")
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// notNullString maps an empty value to ” (NOT NULL DEFAULT ” columns)
// instead of SQL NULL — the Phase 6 tables store empty text as ”.
func notNullString(value string) string {
	if value == "" {
		return ""
	}
	return value
}
