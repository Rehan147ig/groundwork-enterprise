package governance

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"groundwork/query-runtime/internal/connectors"
	"groundwork/query-runtime/internal/runtime"
)

// ---------------------------------------------------------------------
// Shared helpers (memory + Postgres).
// ---------------------------------------------------------------------

// outboxLease is how long a claimed outbox event stays in "delivering"
// before a reaper may reset it to "pending" (crash recovery).
const outboxLease = 60 * time.Second

// encodeEvidenceCursor builds the opaque, stable cursor for one evidence
// event: base64("occurredAtRFC3339Nano\x1feventID").
func encodeEvidenceCursor(occurredAt time.Time, eventID string) string {
	raw := occurredAt.UTC().Format(time.RFC3339Nano) + "\x1f" + eventID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeEvidenceCursor parses an opaque cursor into its sort tuple.
func decodeEvidenceCursor(cursor string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", runtime.ErrInvalidRequest
	}
	parts := strings.SplitN(string(raw), "\x1f", 2)
	if len(parts) != 2 {
		return time.Time{}, "", runtime.ErrInvalidRequest
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", runtime.ErrInvalidRequest
	}
	return t, parts[1], nil
}

// computeCheckpointDigest hashes the verified stream boundary: the
// tenant, the last verified event id, the total events checked, and the
// tail digest of every verified chain (sorted by chain name) so a
// forged or edited checkpoint is rejected at resume time. tails maps
// chain name -> digest of the last verified event in that chain.
func computeCheckpointDigest(tenantID, lastEventID string, eventsChecked int, tails map[string]string) string {
	names := make([]string, 0, len(tails))
	for name := range tails {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := []string{tenantID, lastEventID, fmt.Sprintf("%d", eventsChecked)}
	for _, name := range names {
		parts = append(parts, name+"\x1e"+tails[name])
	}
	payload := strings.Join(parts, "\x1f")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// emergencyControlKey is the memory-store key for one entity's control.
func emergencyControlKey(entityType, entityID string) string { return entityType + "|" + entityID }

// ---------------------------------------------------------------------
// Emergency controls — memory store.
// ---------------------------------------------------------------------

func (m *MemoryStore) SetEmergencyControl(_ context.Context, c runtime.EmergencyControl) (runtime.EmergencyControl, error) {
	now := m.now().UTC().Truncate(time.Microsecond)
	key := emergencyControlKey(c.EntityType, c.EntityID)
	existing, ok := m.controls[c.TenantID][key]
	if c.ID == "" {
		c.ID = existing.ID
	}
	if c.ID == "" {
		c.ID = newID()
	}
	c.CreatedAt = now
	c.UpdatedAt = now
	if ok {
		// Preserve the original creation time; only state fields move.
		c.CreatedAt = existing.CreatedAt
	}
	if m.controls[c.TenantID] == nil {
		m.controls[c.TenantID] = map[string]runtime.EmergencyControl{}
	}
	m.controls[c.TenantID][key] = c
	return c, nil
}

func (m *MemoryStore) GetEmergencyControl(_ context.Context, tenantID, entityType, entityID string) (runtime.EmergencyControl, error) {
	c, ok := m.controls[tenantID][emergencyControlKey(entityType, entityID)]
	if !ok {
		return runtime.EmergencyControl{}, runtime.ErrControlNotFound
	}
	return c, nil
}

func (m *MemoryStore) ListEmergencyControls(_ context.Context, tenantID string) ([]runtime.EmergencyControl, error) {
	out := make([]runtime.EmergencyControl, 0, len(m.controls[tenantID]))
	for _, c := range m.controls[tenantID] {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EntityType+out[i].EntityID < out[j].EntityType+out[j].EntityID })
	return out, nil
}

func (m *MemoryStore) AppendEmergencyAction(_ context.Context, a runtime.EmergencyControlAction) (runtime.EmergencyControlAction, error) {
	if a.ID == "" {
		a.ID = newID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = m.now().UTC().Truncate(time.Microsecond)
	}
	chain := m.controlActs[a.TenantID]
	prev := ""
	if len(chain) > 0 {
		prev = chain[len(chain)-1].ImmutableDigest
	}
	a.ImmutableDigest = ComputeEmergencyActionDigest(a, prev)
	m.controlActs[a.TenantID] = append(chain, a)
	return a, nil
}

func (m *MemoryStore) ListEmergencyActions(_ context.Context, tenantID string) ([]runtime.EmergencyControlAction, error) {
	out := make([]runtime.EmergencyControlAction, 0, len(m.controlActs[tenantID]))
	out = append(out, m.controlActs[tenantID]...)
	return out, nil
}

// ---------------------------------------------------------------------
// Delegation revocation — memory store.
// ---------------------------------------------------------------------

func (m *MemoryStore) RevokeDelegationGrantByID(_ context.Context, tenantID, grantID string) error {
	for _, g := range m.delegations[tenantID] {
		if g.ID == grantID {
			if !g.RevokedAt.IsZero() {
				return nil // already revoked: idempotent
			}
			g.RevokedAt = m.now().UTC().Truncate(time.Microsecond)
			m.delegations[tenantID][g.TokenJTI] = g
			return nil
		}
	}
	return runtime.ErrDelegationInvalid
}

// ---------------------------------------------------------------------
// Budgets — memory store.
// ---------------------------------------------------------------------

func (m *MemoryStore) UpsertBudgetPolicy(_ context.Context, b runtime.BudgetPolicy) (runtime.BudgetPolicy, error) {
	now := m.now().UTC().Truncate(time.Microsecond)
	var existing *runtime.BudgetPolicy
	for i := range m.budgets[b.TenantID] {
		p := &m.budgets[b.TenantID][i]
		if p.ScopeType == b.ScopeType && p.AgentVersionID == b.AgentVersionID && p.GrantID == b.GrantID {
			existing = p
			break
		}
	}
	if existing == nil {
		if b.ID == "" {
			b.ID = newID()
		}
		b.CreatedAt = now
		b.UpdatedAt = now
		m.budgets[b.TenantID] = append(m.budgets[b.TenantID], b)
		return b, nil
	}
	existing.AgentVersionID = b.AgentVersionID
	existing.GrantID = b.GrantID
	existing.MaxActionsPerRun = b.MaxActionsPerRun
	existing.MaxDeniedPerRun = b.MaxDeniedPerRun
	existing.MaxApprovalRequiredPerRun = b.MaxApprovalRequiredPerRun
	existing.MaxToolCallsPerActionPerRun = b.MaxToolCallsPerActionPerRun
	existing.MaxRunDurationSeconds = b.MaxRunDurationSeconds
	existing.MaxCitationsPerQuery = b.MaxCitationsPerQuery
	existing.CreatedBy = b.CreatedBy
	existing.UpdatedAt = now
	return *existing, nil
}

func (m *MemoryStore) GetBudgetPolicy(_ context.Context, tenantID, scopeType, agentVersionID, grantID string) (runtime.BudgetPolicy, error) {
	for _, p := range m.budgets[tenantID] {
		if p.ScopeType == scopeType && p.AgentVersionID == agentVersionID && p.GrantID == grantID {
			return p, nil
		}
	}
	return runtime.BudgetPolicy{}, runtime.ErrInvalidRequest
}

func (m *MemoryStore) ListBudgetPolicies(_ context.Context, tenantID string) ([]runtime.BudgetPolicy, error) {
	out := make([]runtime.BudgetPolicy, 0, len(m.budgets[tenantID]))
	out = append(out, m.budgets[tenantID]...)
	sort.Slice(out, func(i, j int) bool { return out[i].ScopeType < out[j].ScopeType })
	return out, nil
}

// budgetCounterPath is tenantID/runID/actionID/counterType; actionID is
// "" for run-level counters.
func (m *MemoryStore) budgetCounter(tenantID, runID, actionID, counterType string) int {
	if usage, ok := m.budgetUsage[tenantID][runID][actionID]; ok {
		return usage[counterType]
	}
	return 0
}

func (m *MemoryStore) IncrementBudgetCounter(_ context.Context, tenantID, runID, actionID, counterType string) (int, error) {
	return m.IncrementBudgetCounterN(context.Background(), tenantID, runID, actionID, counterType, 1)
}

func (m *MemoryStore) IncrementBudgetCounterN(_ context.Context, tenantID, runID, actionID, counterType string, delta int) (int, error) {
	if delta < 1 {
		return 0, runtime.ErrInvalidRequest
	}
	if m.budgetUsage[tenantID] == nil {
		m.budgetUsage[tenantID] = map[string]map[string]map[string]int{}
	}
	if m.budgetUsage[tenantID][runID] == nil {
		m.budgetUsage[tenantID][runID] = map[string]map[string]int{}
	}
	if m.budgetUsage[tenantID][runID][actionID] == nil {
		m.budgetUsage[tenantID][runID][actionID] = map[string]int{}
	}
	m.budgetUsage[tenantID][runID][actionID][counterType] += delta
	return m.budgetUsage[tenantID][runID][actionID][counterType], nil
}

func (m *MemoryStore) GetBudgetCounter(_ context.Context, tenantID, runID, actionID, counterType string) (int, error) {
	return m.budgetCounter(tenantID, runID, actionID, counterType), nil
}

func (m *MemoryStore) GetBudgetCounters(_ context.Context, tenantID, runID string) (map[string]int, error) {
	out := map[string]int{}
	for actionID, usage := range m.budgetUsage[tenantID][runID] {
		for counterType, count := range usage {
			out[actionID+":"+counterType] = count
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------
// Outbox — memory store.
// ---------------------------------------------------------------------

func (m *MemoryStore) EnqueueOutbox(_ context.Context, e runtime.OutboxEvent) error {
	now := m.now().UTC().Truncate(time.Microsecond)
	if existing, ok := m.outbox[e.TenantID][e.EventID]; ok {
		// Idempotent: same event id, same event. Keep the original.
		_ = existing
		return nil
	}
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

func (m *MemoryStore) ListPendingOutbox(_ context.Context, limit int) ([]runtime.OutboxEvent, error) {
	now := m.now().UTC()
	out := make([]runtime.OutboxEvent, 0)
	for _, id := range m.deliveryOrder {
		e, ok := m.delivery[id]
		if !ok || e.Status != runtime.OutboxStatusPending {
			continue
		}
		if e.NextAttemptAt.After(now) {
			continue
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemoryStore) ClaimOutboxEvent(_ context.Context, eventID string) error {
	e, ok := m.delivery[eventID]
	if !ok || e.Status != runtime.OutboxStatusPending {
		return nil
	}
	e.Status = runtime.OutboxStatusDelivering
	e.Attempts++
	e.NextAttemptAt = m.now().UTC().Add(outboxLease)
	m.delivery[eventID] = e
	if m.outbox[e.TenantID] != nil {
		cur := m.outbox[e.TenantID][e.EventID]
		cur.Status, cur.Attempts, cur.NextAttemptAt = e.Status, e.Attempts, e.NextAttemptAt
		m.outbox[e.TenantID][e.EventID] = cur
	}
	return nil
}

func (m *MemoryStore) ReapExpiredLeases(_ context.Context) error {
	now := m.now().UTC()
	for id, e := range m.delivery {
		if e.Status != runtime.OutboxStatusDelivering || e.NextAttemptAt.After(now) {
			continue
		}
		e.Status = runtime.OutboxStatusPending
		e.NextAttemptAt = now
		m.delivery[id] = e
		if m.outbox[e.TenantID] != nil {
			cur := m.outbox[e.TenantID][e.EventID]
			cur.Status, cur.NextAttemptAt = e.Status, e.NextAttemptAt
			m.outbox[e.TenantID][e.EventID] = cur
		}
	}
	return nil
}

func (m *MemoryStore) MarkOutboxDelivered(_ context.Context, eventID string) error {
	e, ok := m.delivery[eventID]
	if !ok || e.Status != runtime.OutboxStatusDelivering {
		return nil
	}
	e.Status = runtime.OutboxStatusDelivered
	e.DeliveredAt = m.now().UTC().Truncate(time.Microsecond)
	m.delivery[eventID] = e
	if m.outbox[e.TenantID] != nil {
		cur := m.outbox[e.TenantID][e.EventID]
		cur.Status, cur.DeliveredAt = e.Status, e.DeliveredAt
		m.outbox[e.TenantID][e.EventID] = cur
	}
	return nil
}

func (m *MemoryStore) MarkOutboxDeadLetter(_ context.Context, eventID, lastError string) error {
	e, ok := m.delivery[eventID]
	if !ok {
		return nil
	}
	e.Status = runtime.OutboxStatusDeadLetter
	e.LastError = lastError
	m.delivery[eventID] = e
	if m.outbox[e.TenantID] != nil {
		cur := m.outbox[e.TenantID][e.EventID]
		cur.Status, cur.LastError = e.Status, e.LastError
		m.outbox[e.TenantID][e.EventID] = cur
	}
	return nil
}

func (m *MemoryStore) RescheduleOutboxEvent(_ context.Context, eventID string, nextAttemptAt time.Time) error {
	e, ok := m.delivery[eventID]
	if !ok || e.Status != runtime.OutboxStatusDelivering {
		return nil
	}
	e.Status = runtime.OutboxStatusPending
	e.NextAttemptAt = nextAttemptAt.UTC()
	m.delivery[eventID] = e
	if m.outbox[e.TenantID] != nil {
		cur := m.outbox[e.TenantID][e.EventID]
		cur.Status, cur.NextAttemptAt = e.Status, e.NextAttemptAt
		m.outbox[e.TenantID][e.EventID] = cur
	}
	return nil
}

func (m *MemoryStore) ListOutboxEvents(_ context.Context, tenantID, status string, limit int, _ string) ([]runtime.OutboxEvent, error) {
	out := make([]runtime.OutboxEvent, 0)
	ids := make([]string, 0)
	for id := range m.outbox[tenantID] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := m.outbox[tenantID][id]
		if status != "" && e.Status != status {
			continue
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemoryStore) GetOutboxEventByID(_ context.Context, tenantID, eventID string) (runtime.OutboxEvent, error) {
	e, ok := m.outbox[tenantID][eventID]
	if !ok {
		return runtime.OutboxEvent{}, runtime.ErrOutboxEventNotFound
	}
	return e, nil
}

func (m *MemoryStore) RetryOutboxEvent(_ context.Context, tenantID, eventID string) error {
	e, ok := m.outbox[tenantID][eventID]
	if !ok {
		return runtime.ErrOutboxEventNotFound
	}
	if e.Status == runtime.OutboxStatusDelivered {
		return runtime.ErrInvalidRequest
	}
	e.Status = runtime.OutboxStatusPending
	e.LastError = ""
	e.NextAttemptAt = m.now().UTC().Truncate(time.Microsecond)
	m.outbox[tenantID][eventID] = e
	if cur, ok := m.delivery[e.ID]; ok {
		cur.Status, cur.LastError, cur.NextAttemptAt = e.Status, e.LastError, e.NextAttemptAt
		m.delivery[e.ID] = cur
	}
	return nil
}

func (m *MemoryStore) OutboxPendingStats(_ context.Context) ([]runtime.OutboxTenantStats, error) {
	out := make([]runtime.OutboxTenantStats, 0, len(m.outbox))
	for tenantID, events := range m.outbox {
		stat := runtime.OutboxTenantStats{TenantID: tenantID}
		for _, e := range events {
			switch e.Status {
			case runtime.OutboxStatusDeadLetter:
				stat.DeadLetterCount++
			case runtime.OutboxStatusPending:
				stat.PendingCount++
				if stat.OldestPendingAt.IsZero() || e.CreatedAt.Before(stat.OldestPendingAt) {
					stat.OldestPendingAt = e.CreatedAt
				}
			}
		}
		out = append(out, stat)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out, nil
}

// CountPendingOutbox reports the tenant's pending outbox depth (Phase
// 8.2 backpressure). Backing the outbox.Backpressure gate.
func (m *MemoryStore) CountPendingOutbox(_ context.Context, tenantID string) (int, error) {
	n := 0
	for _, e := range m.outbox[tenantID] {
		if e.Status == runtime.OutboxStatusPending {
			n++
		}
	}
	return n, nil
}

// ---------------------------------------------------------------------
// Evidence readers — memory store.
// ---------------------------------------------------------------------

func (m *MemoryStore) ListDecisionsByTenant(_ context.Context, tenantID string) ([]runtime.ActionDecision, error) {
	out := make([]runtime.ActionDecision, 0)
	for _, runDecisions := range m.decisions[tenantID] {
		out = append(out, runDecisions...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (m *MemoryStore) ListApprovalsByTenant(_ context.Context, tenantID string) ([]runtime.ActionApproval, error) {
	out := make([]runtime.ActionApproval, 0)
	for _, runApprovals := range m.approvals[tenantID] {
		out = append(out, runApprovals...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (m *MemoryStore) ListDelegationGrants(_ context.Context, tenantID string) ([]runtime.DelegationGrant, error) {
	out := make([]runtime.DelegationGrant, 0, len(m.delegations[tenantID]))
	for _, g := range m.delegations[tenantID] {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IssuedAt.Equal(out[j].IssuedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].IssuedAt.Before(out[j].IssuedAt)
	})
	return out, nil
}

func (m *MemoryStore) ListRunsByTenant(_ context.Context, tenantID string) ([]runtime.AgentRun, error) {
	out := make([]runtime.AgentRun, 0, len(m.runs[tenantID]))
	for _, r := range m.runs[tenantID] {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].StartedAt.Before(out[j].StartedAt)
	})
	return out, nil
}

// buildMemoryEvidence assembles the read model for one tenant by
// merging the authoritative evidence tables. Every branch mirrors the
// Postgres UNION below (same kinds, same fields).
func (m *MemoryStore) buildMemoryEvidence(tenantID string) []runtime.EvidenceEvent {
	events := make([]runtime.EvidenceEvent, 0)

	for _, runDecisions := range m.decisions[tenantID] {
		for _, d := range runDecisions {
			events = append(events, runtime.EvidenceEvent{
				EventID:           d.ID,
				Kind:              runtime.EvidenceKindDecision,
				TenantID:          d.TenantID,
				OccurredAt:        d.CreatedAt,
				ActorPrincipalID:  m.subjectForGrant(d.DelegationGrantID),
				AgentID:           d.AgentID,
				AgentVersionID:    m.versionForGrant(d.DelegationGrantID),
				DelegationGrantID: d.DelegationGrantID,
				RunID:             d.RunID,
				RunStatus:         m.runStatus(d.RunID),
				ToolID:            d.ToolID,
				ActionID:          d.ActionID,
				ResourceRef:       d.ResourceRef,
				Decision:          d.Decision,
				Reason:            d.Reason,
				ReasonCode:        d.ReasonCode,
				PolicyVersion:     d.PolicyVersion,
				TraceID:           m.runTrace(d.RunID),
				ImmutableDigest:   d.ImmutableDigest,
				// Phase 6: chain context of the deciding grant.
				RootGrantID:       m.rootForGrant(d.DelegationGrantID),
				ParentGrantID:     m.parentForGrant(d.DelegationGrantID),
				DelegationDepth:   d.DelegationDepth,
				ChainVerification: d.ChainVerified,
			})
		}
	}

	for _, runApprovals := range m.approvals[tenantID] {
		for _, a := range runApprovals {
			events = append(events, runtime.EvidenceEvent{
				EventID:           a.ID,
				Kind:              runtime.EvidenceKindApproval,
				TenantID:          a.TenantID,
				OccurredAt:        a.CreatedAt,
				ActorPrincipalID:  a.ApprovingPrincipalID,
				AgentID:           m.agentForRun(a.RunID),
				DelegationGrantID: m.grantForRun(a.RunID),
				RunID:             a.RunID,
				RunStatus:         m.runStatus(a.RunID),
				ToolID:            a.ToolID,
				ActionID:          a.ActionID,
				ResourceRef:       a.ResourceRef,
				Decision:          a.Decision,
				TraceID:           m.runTrace(a.RunID),
				ImmutableDigest:   a.ImmutableDigest,
			})
		}
	}

	for _, g := range m.delegations[tenantID] {
		events = append(events, runtime.EvidenceEvent{
			EventID:           g.ID,
			Kind:              runtime.EvidenceKindDelegationMint,
			TenantID:          g.TenantID,
			OccurredAt:        g.IssuedAt,
			ActorPrincipalID:  g.DelegatorPrincipalID,
			AgentID:           g.AgentID,
			AgentVersionID:    g.AgentVersionID,
			DelegationGrantID: g.ID,
			RunID:             g.RunID,
			Reason:            g.Purpose,
			ImmutableDigest:   g.ImmutableDigest,
			// Phase 6: chain bindings.
			SubjectPrincipalID: g.SubjectPrincipalID,
			RootGrantID:        g.RootGrantID,
			ParentGrantID:      g.ParentGrantID,
			DelegationDepth:    g.DelegationDepth,
			DelegatorAgentID:   g.DelegatorAgentID,
			DelegateeAgentID:   g.DelegateeAgentID,
			ScopeDigest:        g.AuthorityScopeDigest,
			AttenuationDigest:  g.AttenuationDigest,
		})
	}

	for _, r := range m.runs[tenantID] {
		runChain := runtime.EvidenceEvent{
			RootGrantID:       r.RootGrantID,
			ParentGrantID:     r.ParentGrantID,
			DelegationDepth:   r.DelegationDepth,
			ChainVerification: r.ChainVerified,
			OrganizationID:    r.OrganizationID,
		}
		events = append(events, runtime.EvidenceEvent{
			EventID:           r.ID + ":start",
			Kind:              runtime.EvidenceKindRunStart,
			TenantID:          r.TenantID,
			OccurredAt:        r.StartedAt,
			AgentID:           r.AgentID,
			DelegationGrantID: r.DelegationGrantID,
			UserID:            r.UserID,
			RunID:             r.ID,
			RunStatus:         r.Status,
			Reason:            r.Purpose,
			TraceID:           r.TraceID,
			RootGrantID:       runChain.RootGrantID,
			ParentGrantID:     runChain.ParentGrantID,
			DelegationDepth:   runChain.DelegationDepth,
			ChainVerification: runChain.ChainVerification,
			OrganizationID:    runChain.OrganizationID,
		})
		if !r.CompletedAt.IsZero() {
			events = append(events, runtime.EvidenceEvent{
				EventID:           r.ID + ":end",
				Kind:              runtime.EvidenceKindRunEnd,
				TenantID:          r.TenantID,
				OccurredAt:        r.CompletedAt,
				AgentID:           r.AgentID,
				DelegationGrantID: r.DelegationGrantID,
				UserID:            r.UserID,
				RunID:             r.ID,
				RunStatus:         r.Status,
				Reason:            r.ErrorCode,
				TraceID:           r.TraceID,
				RootGrantID:       runChain.RootGrantID,
				ParentGrantID:     runChain.ParentGrantID,
				DelegationDepth:   runChain.DelegationDepth,
				ChainVerification: runChain.ChainVerification,
				OrganizationID:    runChain.OrganizationID,
			})
		}
	}

	for _, a := range m.controlActs[tenantID] {
		kind := runtime.EvidenceKindEmergencyControl
		if a.EntityType == runtime.ControlEntityDelegation {
			kind = runtime.EvidenceKindDelegationRevoke
		}
		events = append(events, runtime.EvidenceEvent{
			EventID:           a.ID,
			Kind:              kind,
			TenantID:          a.TenantID,
			OccurredAt:        a.CreatedAt,
			ActorPrincipalID:  a.ActorPrincipalID,
			AgentID:           m.agentForControl(a.EntityType, a.EntityID),
			AgentVersionID:    controlVersionID(a.EntityType, a.EntityID),
			DelegationGrantID: controlDelegationID(a.EntityType, a.EntityID),
			RunID:             controlRunID(a.EntityType, a.EntityID),
			ToolID:            controlToolID(a.EntityType, a.EntityID),
			RunStatus:         m.controlRunStatus(a.EntityType, a.EntityID),
			Reason:            a.Reason,
			EntityType:        a.EntityType,
			EntityID:          a.EntityID,
			PreviousState:     a.PreviousState,
			NewState:          a.NewState,
			ImmutableDigest:   a.ImmutableDigest,
		})
	}

	// Phase 5: connector invocation outcomes (immutable evidence).
	for _, inv := range m.invocations[tenantID] {
		events = append(events, runtime.EvidenceEvent{
			EventID:    inv.ID,
			Kind:       runtime.EvidenceKindConnectorInvocation,
			TenantID:   inv.TenantID,
			OccurredAt: inv.OccurredAt,
			AgentID:    m.agentForDecision(inv.DecisionID),
			RunID:      inv.RunID,
			RunStatus:  m.runStatus(inv.RunID),
			ToolID:     inv.ToolID,
			ActionID:   inv.ToolActionID,
			Decision:   inv.Outcome,
			Reason:     inv.ErrorCode,
			ReasonCode: inv.Kind,
			TraceID:    inv.TraceID,
			EntityType: "connector",
			EntityID:   inv.ConnectorID,
		})
	}

	// Phase 6: hash-chained trust/chain/external events.
	for _, e := range m.trustEvents[tenantID] {
		events = append(events, runtime.EvidenceEvent{
			EventID:            e.ID,
			Kind:               runtime.EvidenceKindTrustEvent,
			TenantID:           e.TenantID,
			OccurredAt:         e.OccurredAt,
			ActorPrincipalID:   e.ActorPrincipalID,
			DelegationGrantID:  e.GrantID,
			Reason:             e.Reason,
			EntityType:         e.EntityType,
			EntityID:           e.EntityID,
			PreviousState:      e.PreviousState,
			NewState:           e.NewState,
			RootGrantID:        e.RootGrantID,
			ParentGrantID:      e.ParentGrantID,
			DelegationDepth:    e.DelegationDepth,
			TrustDomain:        e.TrustDomain,
			OrganizationID:     e.OrganizationID,
			SubjectPrincipalID: e.SubjectPrincipalID,
			ScopeDigest:        e.ScopeDigest,
			AttenuationDigest:  e.AttenuationDigest,
			RevocationSource:   e.RevocationSource,
			ImmutableDigest:    e.ImmutableDigest,
		})
	}

	sort.Slice(events, func(i, j int) bool {
		if events[i].OccurredAt.Equal(events[j].OccurredAt) {
			return events[i].EventID < events[j].EventID
		}
		return events[i].OccurredAt.Before(events[j].OccurredAt)
	})
	return events
}

func (m *MemoryStore) subjectForGrant(grantID string) string {
	for _, grants := range m.delegations {
		for _, g := range grants {
			if g.ID == grantID {
				return g.SubjectPrincipalID
			}
		}
	}
	return ""
}

func (m *MemoryStore) versionForGrant(grantID string) string {
	for _, grants := range m.delegations {
		for _, g := range grants {
			if g.ID == grantID {
				return g.AgentVersionID
			}
		}
	}
	return ""
}

func (m *MemoryStore) rootForGrant(grantID string) string {
	for _, grants := range m.delegations {
		for _, g := range grants {
			if g.ID == grantID {
				if g.RootGrantID != "" {
					return g.RootGrantID
				}
				return g.ID
			}
		}
	}
	return ""
}

func (m *MemoryStore) parentForGrant(grantID string) string {
	for _, grants := range m.delegations {
		for _, g := range grants {
			if g.ID == grantID {
				return g.ParentGrantID
			}
		}
	}
	return ""
}

func (m *MemoryStore) grantForRun(runID string) string {
	for _, runs := range m.runs {
		for _, r := range runs {
			if r.ID == runID {
				return r.DelegationGrantID
			}
		}
	}
	return ""
}

func (m *MemoryStore) agentForRun(runID string) string {
	for _, runs := range m.runs {
		for _, r := range runs {
			if r.ID == runID {
				return r.AgentID
			}
		}
	}
	return ""
}

func (m *MemoryStore) runStatus(runID string) string {
	for _, runs := range m.runs {
		for _, r := range runs {
			if r.ID == runID {
				return r.Status
			}
		}
	}
	return ""
}

func (m *MemoryStore) runTrace(runID string) string {
	for _, runs := range m.runs {
		for _, r := range runs {
			if r.ID == runID {
				return r.TraceID
			}
		}
	}
	return ""
}

// agentForDecision resolves the agent id recorded on the decision that
// an invocation outcome references (Phase 5 evidence enrichment).
func (m *MemoryStore) agentForDecision(decisionID string) string {
	for _, runDecisions := range m.decisions {
		for _, list := range runDecisions {
			for _, d := range list {
				if d.ID == decisionID {
					return d.AgentID
				}
			}
		}
	}
	return ""
}

func (m *MemoryStore) agentForControl(entityType, entityID string) string {
	switch entityType {
	case runtime.ControlEntityAgent:
		return entityID
	case runtime.ControlEntityAgentVersion, runtime.ControlEntityToolGrant, runtime.ControlEntityDelegation:
		return m.controlAgentID(entityType, entityID)
	case runtime.ControlEntityRun:
		return m.agentForRun(entityID)
	}
	return ""
}

func (m *MemoryStore) controlAgentID(entityType, entityID string) string {
	for _, grants := range m.delegations {
		for _, g := range grants {
			if entityType == runtime.ControlEntityDelegation && g.ID == entityID {
				return g.AgentID
			}
		}
	}
	for _, runs := range m.runs {
		for _, r := range runs {
			if entityType == runtime.ControlEntityRun && r.ID == entityID {
				return r.AgentID
			}
		}
	}
	return ""
}

func controlVersionID(entityType, entityID string) string {
	if entityType == runtime.ControlEntityAgentVersion {
		return entityID
	}
	return ""
}

func controlDelegationID(entityType, entityID string) string {
	if entityType == runtime.ControlEntityDelegation {
		return entityID
	}
	return ""
}

func controlRunID(entityType, entityID string) string {
	if entityType == runtime.ControlEntityRun {
		return entityID
	}
	return ""
}

func controlToolID(entityType, entityID string) string {
	if entityType == runtime.ControlEntityTool {
		return entityID
	}
	return ""
}

func (m *MemoryStore) controlRunStatus(entityType, entityID string) string {
	if entityType == runtime.ControlEntityRun {
		return m.runStatus(entityID)
	}
	return ""
}

// applyEvidenceFilter narrows events by the tenant-scoped filter. The
// cursor boundary is applied by the caller (memory and Postgres share
// the pagination rule: strictly after (occurred_at, event_id)).
func applyEvidenceFilter(events []runtime.EvidenceEvent, f runtime.EvidenceFilter) []runtime.EvidenceEvent {
	from, _ := time.Parse(time.RFC3339, f.From)
	to, _ := time.Parse(time.RFC3339, f.To)
	out := make([]runtime.EvidenceEvent, 0, len(events))
	for _, e := range events {
		if !from.IsZero() && e.OccurredAt.Before(from) {
			continue
		}
		if !to.IsZero() && !e.OccurredAt.Before(to) {
			continue
		}
		if f.AgentID != "" && e.AgentID != f.AgentID {
			continue
		}
		if f.AgentVersionID != "" && e.AgentVersionID != f.AgentVersionID {
			continue
		}
		if f.OwnerPrincipal != "" && e.OwnerPrincipalID != f.OwnerPrincipal {
			continue
		}
		if f.UserID != "" && e.UserID != f.UserID {
			continue
		}
		if f.ToolID != "" && e.ToolID != f.ToolID {
			continue
		}
		if f.ActionID != "" && e.ActionID != f.ActionID {
			continue
		}
		if f.RunStatus != "" && e.RunStatus != f.RunStatus {
			continue
		}
		if f.Decision != "" && e.Decision != f.Decision {
			continue
		}
		if f.ReasonCode != "" && e.ReasonCode != f.ReasonCode {
			continue
		}
		if f.TraceID != "" && e.TraceID != f.TraceID {
			continue
		}
		if len(f.Kinds) > 0 && !containsString(f.Kinds, e.Kind) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (m *MemoryStore) QueryEvidence(_ context.Context, tenantID string, f runtime.EvidenceFilter) ([]runtime.EvidenceEvent, error) {
	return m.evidencePage(m.buildMemoryEvidence(tenantID), f), nil
}

func (m *MemoryStore) GetEvidenceEvent(_ context.Context, tenantID, eventID string) (runtime.EvidenceEvent, error) {
	for _, e := range m.buildMemoryEvidence(tenantID) {
		if e.EventID == eventID {
			return e, nil
		}
	}
	return runtime.EvidenceEvent{}, runtime.ErrEvidenceNotFound
}

func (m *MemoryStore) GetRunEvidence(_ context.Context, tenantID, runID string) ([]runtime.EvidenceEvent, error) {
	out := make([]runtime.EvidenceEvent, 0)
	for _, e := range m.buildMemoryEvidence(tenantID) {
		if e.RunID == runID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *MemoryStore) GetAgentEvidence(ctx context.Context, tenantID, agentID string, f runtime.EvidenceFilter) ([]runtime.EvidenceEvent, error) {
	f.AgentID = agentID
	return m.QueryEvidence(ctx, tenantID, f)
}

// evidencePage applies cursor pagination to a sorted event stream.
func (m *MemoryStore) evidencePage(events []runtime.EvidenceEvent, f runtime.EvidenceFilter) []runtime.EvidenceEvent {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	// Apply the cursor boundary first so filters cannot be skipped.
	var after time.Time
	var afterID string
	if f.Cursor != "" {
		after, afterID, _ = decodeEvidenceCursor(f.Cursor)
	}
	start := 0
	if f.Cursor != "" {
		start = len(events)
		for i, e := range events {
			if e.OccurredAt.After(after) || (e.OccurredAt.Equal(after) && e.EventID > afterID) {
				start = i
				break
			}
		}
	}
	events = applyEvidenceFilter(events[start:], f)
	if len(events) > limit {
		events = events[:limit]
	}
	return events
}

func (m *MemoryStore) GetDelegationGrantByID(_ context.Context, tenantID, grantID string) (runtime.DelegationGrant, error) {
	for _, g := range m.delegations[tenantID] {
		if g.ID == grantID {
			return g, nil
		}
	}
	return runtime.DelegationGrant{}, runtime.ErrDelegationInvalid
}

// ---------------------------------------------------------------------
// Checkpoints — memory store.
// ---------------------------------------------------------------------

func (m *MemoryStore) CreateCheckpoint(_ context.Context, c runtime.EvidenceCheckpoint) (runtime.EvidenceCheckpoint, error) {
	if c.ID == "" {
		c.ID = newID()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = m.now().UTC().Truncate(time.Microsecond)
	}
	m.checkpoints[c.TenantID] = append(m.checkpoints[c.TenantID], c)
	return c, nil
}

func (m *MemoryStore) ListCheckpoints(_ context.Context, tenantID string) ([]runtime.EvidenceCheckpoint, error) {
	out := make([]runtime.EvidenceCheckpoint, 0, len(m.checkpoints[tenantID]))
	out = append(out, m.checkpoints[tenantID]...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastVerifiedAt.Equal(out[j].LastVerifiedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].LastVerifiedAt.Before(out[j].LastVerifiedAt)
	})
	return out, nil
}

func (m *MemoryStore) GetCheckpoint(_ context.Context, tenantID, checkpointID string) (runtime.EvidenceCheckpoint, error) {
	for _, c := range m.checkpoints[tenantID] {
		if c.ID == checkpointID {
			return c, nil
		}
	}
	return runtime.EvidenceCheckpoint{}, runtime.ErrCheckpointNotFound
}

// ---------------------------------------------------------------------
// Emergency controls — Postgres store.
// ---------------------------------------------------------------------

const emergencyControlColumns = `id::text, tenant_id, entity_type, entity_id, control_state, reason, scope, actor_principal_id, created_at, updated_at`

func scanEmergencyControl(row interface{ Scan(...any) error }) (runtime.EmergencyControl, error) {
	var c runtime.EmergencyControl
	err := row.Scan(&c.ID, &c.TenantID, &c.EntityType, &c.EntityID, &c.ControlState,
		&c.Reason, &c.Scope, &c.ActorPrincipalID, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func (p *postgresTx) SetEmergencyControl(ctx context.Context, c runtime.EmergencyControl) (runtime.EmergencyControl, error) {
	row := p.tx.QueryRowContext(ctx, `
		INSERT INTO emergency_controls (tenant_id, entity_type, entity_id, control_state, reason, scope, actor_principal_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, entity_type, entity_id)
		DO UPDATE SET control_state = EXCLUDED.control_state,
		              reason = EXCLUDED.reason,
		              scope = EXCLUDED.scope,
		              actor_principal_id = EXCLUDED.actor_principal_id,
		              updated_at = now()
		RETURNING `+emergencyControlColumns,
		c.TenantID, c.EntityType, c.EntityID, c.ControlState, c.Reason, c.Scope, c.ActorPrincipalID)
	return scanEmergencyControl(row)
}

func (p *pgReader) GetEmergencyControl(ctx context.Context, tenantID, entityType, entityID string) (runtime.EmergencyControl, error) {
	c, err := scanEmergencyControl(p.q.QueryRowContext(ctx, `
		SELECT `+emergencyControlColumns+` FROM emergency_controls
		WHERE tenant_id = $1 AND entity_type = $2 AND entity_id = $3
	`, tenantID, entityType, entityID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.EmergencyControl{}, runtime.ErrControlNotFound
	}
	return c, err
}

func (p *pgReader) ListEmergencyControls(ctx context.Context, tenantID string) ([]runtime.EmergencyControl, error) {
	rows, err := p.q.QueryContext(ctx, `
		SELECT `+emergencyControlColumns+` FROM emergency_controls
		WHERE tenant_id = $1
		ORDER BY entity_type, entity_id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.EmergencyControl, 0)
	for rows.Next() {
		c, err := scanEmergencyControl(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

const emergencyActionColumns = `id::text, tenant_id, entity_type, entity_id, action_type, actor_principal_id, reason, scope, previous_state, new_state, immutable_digest, created_at`

func scanEmergencyAction(row interface{ Scan(...any) error }) (runtime.EmergencyControlAction, error) {
	var a runtime.EmergencyControlAction
	err := row.Scan(&a.ID, &a.TenantID, &a.EntityType, &a.EntityID, &a.ActionType,
		&a.ActorPrincipalID, &a.Reason, &a.Scope, &a.PreviousState, &a.NewState,
		&a.ImmutableDigest, &a.CreatedAt)
	return a, err
}

func (p *postgresTx) AppendEmergencyAction(ctx context.Context, a runtime.EmergencyControlAction) (runtime.EmergencyControlAction, error) {
	var prev string
	if err := p.tx.QueryRowContext(ctx, `
		SELECT immutable_digest FROM emergency_control_actions
		WHERE tenant_id = $1
		ORDER BY created_at DESC, id DESC LIMIT 1
	`, a.TenantID).Scan(&prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return runtime.EmergencyControlAction{}, err
	}
	a.ImmutableDigest = ComputeEmergencyActionDigest(a, prev)
	row := p.tx.QueryRowContext(ctx, `
		INSERT INTO emergency_control_actions
			(tenant_id, entity_type, entity_id, action_type, actor_principal_id, reason, scope, previous_state, new_state, immutable_digest)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING `+emergencyActionColumns,
		a.TenantID, a.EntityType, a.EntityID, a.ActionType, a.ActorPrincipalID,
		a.Reason, a.Scope, a.PreviousState, a.NewState, a.ImmutableDigest)
	return scanEmergencyAction(row)
}

func (p *pgReader) ListEmergencyActions(ctx context.Context, tenantID string) ([]runtime.EmergencyControlAction, error) {
	rows, err := p.q.QueryContext(ctx, `
		SELECT `+emergencyActionColumns+` FROM emergency_control_actions
		WHERE tenant_id = $1
		ORDER BY created_at, id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.EmergencyControlAction, 0)
	for rows.Next() {
		a, err := scanEmergencyAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------
// Delegation revocation — Postgres store.
// ---------------------------------------------------------------------

func (p *postgresTx) RevokeDelegationGrantByID(ctx context.Context, tenantID, grantID string) error {
	tag, err := p.tx.ExecContext(ctx, `
		UPDATE delegated_authority_grants SET revoked_at = now()
		WHERE tenant_id = $1 AND id::text = $2 AND revoked_at IS NULL
	`, tenantID, grantID)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		var exists int
		if err := p.tx.QueryRowContext(ctx, `
			SELECT 1 FROM delegated_authority_grants WHERE tenant_id = $1 AND id::text = $2
		`, tenantID, grantID).Scan(&exists); err != nil {
			return runtime.ErrDelegationInvalid
		}
		return nil // already revoked: idempotent
	}
	return nil
}

// ---------------------------------------------------------------------
// Budgets — Postgres store.
// ---------------------------------------------------------------------

const budgetPolicyColumns = `id::text, tenant_id, scope_type, COALESCE(agent_version_id::text, ''), COALESCE(grant_id::text, ''), max_actions_per_run, max_denied_per_run, max_approval_required_per_run, max_tool_calls_per_action_per_run, max_run_duration_seconds, max_citations_per_query, created_by, created_at, updated_at`

func scanBudgetPolicy(row interface{ Scan(...any) error }) (runtime.BudgetPolicy, error) {
	var b runtime.BudgetPolicy
	err := row.Scan(&b.ID, &b.TenantID, &b.ScopeType, &b.AgentVersionID, &b.GrantID,
		&b.MaxActionsPerRun, &b.MaxDeniedPerRun, &b.MaxApprovalRequiredPerRun,
		&b.MaxToolCallsPerActionPerRun, &b.MaxRunDurationSeconds, &b.MaxCitationsPerQuery,
		&b.CreatedBy, &b.CreatedAt, &b.UpdatedAt)
	return b, err
}

func (p *postgresTx) UpsertBudgetPolicy(ctx context.Context, b runtime.BudgetPolicy) (runtime.BudgetPolicy, error) {
	var versionID, grantID any
	if b.ScopeType == runtime.BudgetScopeAgentVersion {
		versionID = b.AgentVersionID
	}
	if b.ScopeType == runtime.BudgetScopeGrant {
		grantID = b.GrantID
	}
	// Update first; if no row matched, insert. Budget writes run inside
	// the tenant advisory lock, so the check-then-act cannot race.
	tag, err := p.tx.ExecContext(ctx, `
		UPDATE agent_action_budgets SET
			max_actions_per_run = $5, max_denied_per_run = $6,
			max_approval_required_per_run = $7, max_tool_calls_per_action_per_run = $8,
			max_run_duration_seconds = $9, max_citations_per_query = $10,
			created_by = $11, updated_at = now()
		WHERE tenant_id = $1 AND scope_type = $2
		  AND COALESCE(agent_version_id::text, '') = COALESCE($3::uuid::text, '')
		  AND COALESCE(grant_id::text, '') = COALESCE($4::uuid::text, '')
	`, b.TenantID, b.ScopeType, versionID, grantID, b.MaxActionsPerRun, b.MaxDeniedPerRun,
		b.MaxApprovalRequiredPerRun, b.MaxToolCallsPerActionPerRun, b.MaxRunDurationSeconds,
		b.MaxCitationsPerQuery, b.CreatedBy)
	if err != nil {
		return runtime.BudgetPolicy{}, err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return runtime.BudgetPolicy{}, err
	}
	if affected > 0 {
		return scanBudgetPolicy(p.tx.QueryRowContext(ctx, `
			SELECT `+budgetPolicyColumns+` FROM agent_action_budgets
			WHERE tenant_id = $1 AND scope_type = $2
			  AND COALESCE(agent_version_id::text, '') = COALESCE($3::uuid::text, '')
			  AND COALESCE(grant_id::text, '') = COALESCE($4::uuid::text, '')
		`, b.TenantID, b.ScopeType, versionID, grantID))
	}
	created, err := scanBudgetPolicy(p.tx.QueryRowContext(ctx, `
		INSERT INTO agent_action_budgets
			(tenant_id, scope_type, agent_version_id, grant_id, max_actions_per_run, max_denied_per_run,
			 max_approval_required_per_run, max_tool_calls_per_action_per_run, max_run_duration_seconds,
			 max_citations_per_query, created_by)
		VALUES ($1, $2, $3::uuid, $4::uuid, $5, $6, $7, $8, $9, $10, $11)
		RETURNING `+budgetPolicyColumns,
		b.TenantID, b.ScopeType, versionID, grantID, b.MaxActionsPerRun, b.MaxDeniedPerRun,
		b.MaxApprovalRequiredPerRun, b.MaxToolCallsPerActionPerRun, b.MaxRunDurationSeconds,
		b.MaxCitationsPerQuery, b.CreatedBy))
	if err != nil && isUniqueViolation(err) {
		// Concurrent insert won the unique index; return the winner.
		return scanBudgetPolicy(p.tx.QueryRowContext(ctx, `
			SELECT `+budgetPolicyColumns+` FROM agent_action_budgets
			WHERE tenant_id = $1 AND scope_type = $2
			  AND COALESCE(agent_version_id::text, '') = COALESCE($3::uuid::text, '')
			  AND COALESCE(grant_id::text, '') = COALESCE($4::uuid::text, '')
		`, b.TenantID, b.ScopeType, versionID, grantID))
	}
	return created, err
}

func (p *pgReader) GetBudgetPolicy(ctx context.Context, tenantID, scopeType, agentVersionID, grantID string) (runtime.BudgetPolicy, error) {
	b, err := scanBudgetPolicy(p.q.QueryRowContext(ctx, `
		SELECT `+budgetPolicyColumns+` FROM agent_action_budgets
		WHERE tenant_id = $1 AND scope_type = $2
		  AND COALESCE(agent_version_id::text, '') = COALESCE($3::uuid::text, '')
		  AND COALESCE(grant_id::text, '') = COALESCE($4::uuid::text, '')
	`, tenantID, scopeType, nullUUID(agentVersionID), nullUUID(grantID)))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.BudgetPolicy{}, runtime.ErrInvalidRequest
	}
	return b, err
}

func (p *pgReader) ListBudgetPolicies(ctx context.Context, tenantID string) ([]runtime.BudgetPolicy, error) {
	rows, err := p.q.QueryContext(ctx, `
		SELECT `+budgetPolicyColumns+` FROM agent_action_budgets
		WHERE tenant_id = $1
		ORDER BY scope_type, id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.BudgetPolicy, 0)
	for rows.Next() {
		b, err := scanBudgetPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (p *postgresTx) IncrementBudgetCounter(ctx context.Context, tenantID, runID, actionID, counterType string) (int, error) {
	return p.IncrementBudgetCounterN(ctx, tenantID, runID, actionID, counterType, 1)
}

func (p *postgresTx) IncrementBudgetCounterN(ctx context.Context, tenantID, runID, actionID, counterType string, delta int) (int, error) {
	if delta < 1 {
		return 0, runtime.ErrInvalidRequest
	}
	var count int
	var err error
	if actionID == "" {
		err = p.tx.QueryRowContext(ctx, `
			INSERT INTO agent_run_budget_usage (tenant_id, run_id, counter_type, "count")
			VALUES ($1, $2::uuid, $3, $4)
			ON CONFLICT (run_id, counter_type) WHERE action_id IS NULL
			DO UPDATE SET "count" = agent_run_budget_usage."count" + $4, updated_at = now()
			RETURNING "count"
		`, tenantID, runID, counterType, delta).Scan(&count)
	} else {
		err = p.tx.QueryRowContext(ctx, `
			INSERT INTO agent_run_budget_usage (tenant_id, run_id, action_id, counter_type, "count")
			VALUES ($1, $2::uuid, $3, $4, $5)
			ON CONFLICT (run_id, action_id, counter_type) WHERE action_id IS NOT NULL
			DO UPDATE SET "count" = agent_run_budget_usage."count" + $5, updated_at = now()
			RETURNING "count"
		`, tenantID, runID, actionID, counterType, delta).Scan(&count)
	}
	return count, err
}

func (p *pgReader) GetBudgetCounter(ctx context.Context, tenantID, runID, actionID, counterType string) (int, error) {
	var count int
	err := p.q.QueryRowContext(ctx, `
		SELECT "count" FROM agent_run_budget_usage
		WHERE tenant_id = $1 AND run_id = $2::uuid
		  AND COALESCE(action_id, '') = COALESCE($3, '')
		  AND counter_type = $4
	`, tenantID, runID, actionID, counterType).Scan(&count)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return count, err
}

func (p *pgReader) GetBudgetCounters(ctx context.Context, tenantID, runID string) (map[string]int, error) {
	rows, err := p.q.QueryContext(ctx, `
		SELECT COALESCE(action_id::text, ''), counter_type, "count" FROM agent_run_budget_usage
		WHERE tenant_id = $1 AND run_id = $2::uuid
	`, tenantID, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var actionID, counterType string
		var count int
		if err := rows.Scan(&actionID, &counterType, &count); err != nil {
			return nil, err
		}
		out[actionID+":"+counterType] = count
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------
// Outbox — Postgres store.
// ---------------------------------------------------------------------

const outboxEventColumns = `id::text, tenant_id, event_id, event_type, schema_version, occurred_at, payload::text, status, attempts, next_attempt_at, last_error, created_at, delivered_at`

func scanOutboxEvent(row interface{ Scan(...any) error }) (runtime.OutboxEvent, error) {
	var e runtime.OutboxEvent
	var payload string
	var deliveredAt sql.NullTime
	err := row.Scan(&e.ID, &e.TenantID, &e.EventID, &e.EventType, &e.SchemaVersion,
		&e.OccurredAt, &payload, &e.Status, &e.Attempts, &e.NextAttemptAt,
		&e.LastError, &e.CreatedAt, &deliveredAt)
	if payload != "" {
		e.Payload = json.RawMessage(payload)
	}
	if deliveredAt.Valid {
		e.DeliveredAt = deliveredAt.Time
	}
	return e, err
}

func (p *postgresTx) EnqueueOutbox(ctx context.Context, e runtime.OutboxEvent) error {
	for _, pending := range p.outboxPending {
		if pending.TenantID == e.TenantID && pending.EventID == e.EventID {
			return nil // idempotent within the transaction
		}
	}
	e.Status = runtime.OutboxStatusPending
	e.Attempts = 0
	p.outboxPending = append(p.outboxPending, e)
	return nil
}

// flushOutbox inserts every buffered event atomically in this tx. On
// conflict (event_id already delivered), the original row wins: event
// IDs are idempotent by design.
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

func (p *pgReader) ListOutboxEvents(ctx context.Context, tenantID, status string, limit int, cursor string) ([]runtime.OutboxEvent, error) {
	args := []any{tenantID}
	where := `WHERE tenant_id = $1`
	if status != "" {
		args = append(args, status)
		where += fmt.Sprintf(" AND status = $%d", len(args))
	}
	args = append(args, limit)
	rows, err := p.q.QueryContext(ctx, `
		SELECT `+outboxEventColumns+` FROM outbox_events `+where+`
		ORDER BY occurred_at DESC, event_id
		LIMIT $`+fmt.Sprintf("%d", len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.OutboxEvent, 0)
	for rows.Next() {
		e, err := scanOutboxEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *pgReader) GetOutboxEventByID(ctx context.Context, tenantID, eventID string) (runtime.OutboxEvent, error) {
	e, err := scanOutboxEvent(p.q.QueryRowContext(ctx, `
		SELECT `+outboxEventColumns+` FROM outbox_events
		WHERE tenant_id = $1 AND event_id = $2
	`, tenantID, eventID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.OutboxEvent{}, runtime.ErrOutboxEventNotFound
	}
	return e, err
}

func (p *pgReader) RetryOutboxEvent(ctx context.Context, tenantID, eventID string) error {
	if _, err := p.q.QueryContext(ctx, `
		UPDATE outbox_events SET status = 'pending', next_attempt_at = now(), last_error = ''
		WHERE tenant_id = $1 AND event_id = $2 AND status <> 'delivered'
	`, tenantID, eventID); err != nil {
		return err
	}
	var exists int
	if err := p.q.QueryRowContext(ctx, `
		SELECT 1 FROM outbox_events WHERE tenant_id = $1 AND event_id = $2
	`, tenantID, eventID).Scan(&exists); err != nil {
		return runtime.ErrOutboxEventNotFound
	}
	return nil
}

func (p *pgReader) ListPendingOutbox(ctx context.Context, limit int) ([]runtime.OutboxEvent, error) {
	rows, err := p.q.QueryContext(ctx, `
		SELECT `+outboxEventColumns+` FROM outbox_events
		WHERE status = 'pending' AND next_attempt_at <= now()
		ORDER BY next_attempt_at, occurred_at, id
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.OutboxEvent, 0)
	for rows.Next() {
		e, err := scanOutboxEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *pgReader) ClaimOutboxEvent(ctx context.Context, eventID string) error {
	_, err := p.q.QueryContext(ctx, `
		UPDATE outbox_events SET status = 'delivering', attempts = attempts + 1, next_attempt_at = now() + interval '60 seconds'
		WHERE id::text = $1 AND status = 'pending'
	`, eventID)
	return err
}

func (p *pgReader) ReapExpiredLeases(ctx context.Context) error {
	_, err := p.q.QueryContext(ctx, `
		UPDATE outbox_events SET status = 'pending', next_attempt_at = now()
		WHERE status = 'delivering' AND next_attempt_at <= now()
	`)
	return err
}

func (p *pgReader) MarkOutboxDelivered(ctx context.Context, eventID string) error {
	_, err := p.q.QueryContext(ctx, `
		UPDATE outbox_events SET status = 'delivered', delivered_at = now()
		WHERE id::text = $1 AND status = 'delivering'
	`, eventID)
	return err
}

func (p *pgReader) MarkOutboxDeadLetter(ctx context.Context, eventID, lastError string) error {
	_, err := p.q.QueryContext(ctx, `
		UPDATE outbox_events SET status = 'dead_letter', last_error = $2
		WHERE id::text = $1 AND status = 'delivering'
	`, eventID, lastError)
	return err
}

func (p *pgReader) RescheduleOutboxEvent(ctx context.Context, eventID string, nextAttemptAt time.Time) error {
	_, err := p.q.QueryContext(ctx, `
		UPDATE outbox_events SET status = 'pending', next_attempt_at = $2, last_error = NULL
		WHERE id::text = $1 AND status = 'delivering'
	`, eventID, nextAttemptAt.UTC())
	return err
}

func (p *pgReader) OutboxPendingStats(ctx context.Context) ([]runtime.OutboxTenantStats, error) {
	rows, err := p.q.QueryContext(ctx, `
		SELECT tenant_id,
		       COUNT(*) FILTER (WHERE status = 'dead_letter'),
		       MIN(created_at) FILTER (WHERE status = 'pending'),
		       COUNT(*) FILTER (WHERE status = 'pending')
		FROM outbox_events
		GROUP BY tenant_id
		ORDER BY tenant_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.OutboxTenantStats, 0)
	for rows.Next() {
		var stat runtime.OutboxTenantStats
		var oldest *time.Time
		if err := rows.Scan(&stat.TenantID, &stat.DeadLetterCount, &oldest, &stat.PendingCount); err != nil {
			return nil, err
		}
		if oldest != nil {
			stat.OldestPendingAt = oldest.UTC()
		}
		out = append(out, stat)
	}
	return out, rows.Err()
}

// CountPendingOutbox reports one tenant's pending outbox depth (Phase
// 8.2 backpressure), backing the outbox.Backpressure gate.
func (p *pgReader) CountPendingOutbox(ctx context.Context, tenantID string) (int, error) {
	var n int
	err := p.q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM outbox_events WHERE tenant_id = $1 AND status = 'pending'`, tenantID,
	).Scan(&n)
	return n, err
}

// ---------------------------------------------------------------------
// Evidence — Postgres store.
// ---------------------------------------------------------------------

func (p *pgReader) ListDecisionsByTenant(ctx context.Context, tenantID string) ([]runtime.ActionDecision, error) {
	rows, err := p.q.QueryContext(ctx, `
		SELECT `+decisionColumns+` FROM agent_action_decisions
		WHERE tenant_id = $1
		ORDER BY created_at, id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.ActionDecision, 0)
	for rows.Next() {
		d, err := scanDecision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (p *pgReader) ListApprovalsByTenant(ctx context.Context, tenantID string) ([]runtime.ActionApproval, error) {
	rows, err := p.q.QueryContext(ctx, `
		SELECT `+approvalColumns+` FROM agent_action_approvals
		WHERE tenant_id = $1
		ORDER BY created_at, id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.ActionApproval, 0)
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *pgReader) ListDelegationGrants(ctx context.Context, tenantID string) ([]runtime.DelegationGrant, error) {
	rows, err := p.q.QueryContext(ctx, `
		SELECT `+delegationColumns+` FROM delegated_authority_grants
		WHERE tenant_id = $1
		ORDER BY issued_at, id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.DelegationGrant, 0)
	for rows.Next() {
		g, err := scanDelegation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (p *pgReader) GetDelegationGrantByID(ctx context.Context, tenantID, grantID string) (runtime.DelegationGrant, error) {
	g, err := scanDelegation(p.q.QueryRowContext(ctx, `
		SELECT `+delegationColumns+` FROM delegated_authority_grants
		WHERE tenant_id = $1 AND id::text = $2
	`, tenantID, grantID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.DelegationGrant{}, runtime.ErrDelegationInvalid
	}
	return g, err
}

func (p *pgReader) ListRunsByTenant(ctx context.Context, tenantID string) ([]runtime.AgentRun, error) {
	rows, err := p.q.QueryContext(ctx, `
		SELECT `+runColumns+` FROM agent_runs
		WHERE tenant_id = $1
		ORDER BY started_at, id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.AgentRun, 0)
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// evidenceUnion is the tenant-scoped read model over the authoritative
// evidence tables. Every branch emits the same 40-column shape; kinds,
// joins, and filters mirror the memory buildMemoryEvidence.
const evidenceUnion = `
SELECT * FROM (
	SELECT d.id::text AS event_id, 'decision' AS kind, d.tenant_id, d.created_at AS occurred_at,
	       COALESCE(g.subject_principal_id, '') AS actor_principal_id,
	       d.agent_id::text AS agent_id, a.name AS agent_name,
	       COALESCE(g.agent_version_id::text, '') AS agent_version_id,
	       COALESCE(a.owner_principal_id, '') AS owner_principal_id,
	       d.delegation_grant_id::text AS delegation_grant_id, '' AS user_id,
	       d.run_id::text AS run_id, r.status AS run_status,
	       COALESCE(d.tool_id::text, '') AS tool_id, COALESCE(t.name, '') AS tool_name,
	       COALESCE(d.action_id::text, '') AS action_id, d.resource_ref,
	       d.decision, d.reason, d.reason_code, d.policy_version, COALESCE(r.trace_id, '') AS trace_id,
	       '' AS entity_type, '' AS entity_id, '' AS previous_state, '' AS new_state,
	       d.immutable_digest,
	       COALESCE(g.root_grant_id::text, '') AS root_grant_id,
	       COALESCE(g.parent_grant_id::text, '') AS parent_grant_id,
	       '' AS child_grant_id,
	       d.delegation_depth,
	       COALESCE(g.delegator_agent_id::text, '') AS delegator_agent_id,
	       COALESCE(g.delegatee_agent_id::text, '') AS delegatee_agent_id,
	       COALESCE(tr.trust_domain, '') AS trust_domain,
	       COALESCE(g.external_agent_id::text, '') AS organization_id,
	       COALESCE(g.subject_principal_id, '') AS subject_principal_id,
	       COALESCE(g.authority_scope_digest, '') AS scope_digest,
	       COALESCE(g.attenuation_digest, '') AS attenuation_digest,
	       d.chain_verified AS chain_verification,
	       '' AS revocation_source
	FROM agent_action_decisions d
	LEFT JOIN agents a ON a.id = d.agent_id
	LEFT JOIN tools t ON t.id = d.tool_id
	LEFT JOIN delegated_authority_grants g ON g.id = d.delegation_grant_id
	LEFT JOIN agent_runs r ON r.id = d.run_id
	LEFT JOIN agent_trust_relationships tr ON tr.id::text = g.trust_relationship_id::text
	WHERE d.tenant_id = $1

	UNION ALL

	SELECT ap.id::text, 'approval', ap.tenant_id, ap.created_at,
	       ap.approving_principal_id,
	       r.agent_id::text, a.name, COALESCE(gr.agent_version_id::text, ''), COALESCE(a.owner_principal_id, ''),
	       COALESCE(r.delegation_grant_id::text, ''), '', ap.run_id::text, r.status,
	       ap.tool_id::text, COALESCE(t.name, ''), ap.action_id::text, ap.resource_ref,
	       ap.decision, '', '', '', COALESCE(r.trace_id, ''),
	       '', '', '', '', ap.immutable_digest,
	       COALESCE(gr.root_grant_id::text, ''), COALESCE(gr.parent_grant_id::text, ''),
	       '', r.delegation_depth, COALESCE(gr.delegator_agent_id::text, ''),
	       COALESCE(gr.delegatee_agent_id::text, ''), COALESCE(tr.trust_domain, ''),
	       COALESCE(gr.external_agent_id::text, ''), COALESCE(gr.subject_principal_id, ''),
	       COALESCE(gr.authority_scope_digest, ''), COALESCE(gr.attenuation_digest, ''),
	       r.chain_verified, ''
	FROM agent_action_approvals ap
	LEFT JOIN agent_runs r ON r.id = ap.run_id
	LEFT JOIN agents a ON a.id = r.agent_id
	LEFT JOIN delegated_authority_grants gr ON gr.id = r.delegation_grant_id
	LEFT JOIN agent_trust_relationships tr ON tr.id::text = gr.trust_relationship_id::text
	LEFT JOIN tools t ON t.id = ap.tool_id
	WHERE ap.tenant_id = $1

	UNION ALL

	SELECT g.id::text, 'delegation_mint', g.tenant_id, g.created_at,
	       g.delegator_principal_id, g.agent_id::text, a.name, g.agent_version_id::text,
	       COALESCE(a.owner_principal_id, ''), g.id::text, '', COALESCE(g.run_id::text, ''), '',
	       '', '', '', '', 'minted', g.purpose, '', '', NULL,
	       '', '', '', '', g.immutable_digest,
	       COALESCE(g.root_grant_id::text, ''), COALESCE(g.parent_grant_id::text, ''),
	       '', g.delegation_depth, COALESCE(g.delegator_agent_id::text, ''),
	       COALESCE(g.delegatee_agent_id::text, ''), COALESCE(tr.trust_domain, ''),
	       COALESCE(g.external_agent_id::text, ''), COALESCE(g.subject_principal_id, ''),
	       COALESCE(g.authority_scope_digest, ''), COALESCE(g.attenuation_digest, ''),
	       '', ''
	FROM delegated_authority_grants g
	LEFT JOIN agents a ON a.id = g.agent_id
	LEFT JOIN agent_trust_relationships tr ON tr.id::text = g.trust_relationship_id::text
	WHERE g.tenant_id = $1

	UNION ALL

	SELECT r.id::text || ':start', 'run_start', r.tenant_id, r.started_at,
	       '', r.agent_id::text, a.name, '', COALESCE(a.owner_principal_id, ''),
	       COALESCE(r.delegation_grant_id::text, ''), r.user_id, r.id::text, r.status,
	       '', '', '', '', '', '', '', '', COALESCE(r.trace_id, ''),
	       '', '', '', '', '',
	       COALESCE(r.root_grant_id::text, ''), COALESCE(r.parent_grant_id::text, ''),
	       '', r.delegation_depth, '', '', '',
	       COALESCE(r.organization_id, ''), COALESCE(r.customer_principal_id, ''),
	       '', '', r.chain_verified, ''
	FROM agent_runs r
	LEFT JOIN agents a ON a.id = r.agent_id
	WHERE r.tenant_id = $1

	UNION ALL

	SELECT r.id::text || ':end', 'run_end', r.tenant_id, r.completed_at,
	       '', r.agent_id::text, a.name, '', COALESCE(a.owner_principal_id, ''),
	       COALESCE(r.delegation_grant_id::text, ''), r.user_id, r.id::text, r.status,
	       '', '', '', '', '', r.error_code, '', '', COALESCE(r.trace_id, ''),
	       '', '', '', '', '',
	       COALESCE(r.root_grant_id::text, ''), COALESCE(r.parent_grant_id::text, ''),
	       '', r.delegation_depth, '', '', '',
	       COALESCE(r.organization_id, ''), COALESCE(r.customer_principal_id, ''),
	       '', '', r.chain_verified, ''
	FROM agent_runs r
	LEFT JOIN agents a ON a.id = r.agent_id
	WHERE r.tenant_id = $1 AND r.completed_at IS NOT NULL

	UNION ALL

	SELECT eca.id::text,
	       CASE WHEN eca.entity_type = 'delegation_grant' THEN 'delegation_revoke' ELSE 'emergency_control' END,
	       eca.tenant_id, eca.created_at, eca.actor_principal_id,
	       CASE WHEN eca.entity_type = 'agent' THEN eca.entity_id
	            WHEN eca.entity_type = 'agent_version' THEN COALESCE(av.agent_id::text, '')
	            WHEN eca.entity_type = 'agent_tool_grant' THEN COALESCE(gt.agent_id::text, '')
	            WHEN eca.entity_type = 'delegation_grant' THEN COALESCE(dg.agent_id::text, '')
	            WHEN eca.entity_type = 'run' THEN COALESCE(er.agent_id::text, '') END,
	       CASE WHEN eca.entity_type = 'agent' THEN ag.name
	            WHEN eca.entity_type = 'agent_version' THEN ava.name
	            WHEN eca.entity_type = 'agent_tool_grant' THEN gta.name
	            WHEN eca.entity_type = 'delegation_grant' THEN dga.name
	            WHEN eca.entity_type = 'run' THEN era.name END,
	       CASE WHEN eca.entity_type = 'agent_version' THEN eca.entity_id ELSE '' END,
	       '',
	       CASE WHEN eca.entity_type = 'delegation_grant' THEN eca.entity_id ELSE '' END,
	       '', CASE WHEN eca.entity_type = 'run' THEN eca.entity_id ELSE '' END,
	       CASE WHEN eca.entity_type = 'run' THEN er.status ELSE '' END,
	       CASE WHEN eca.entity_type = 'tool' THEN eca.entity_id ELSE '' END, COALESCE(tl.name, ''),
	       '', '', '', eca.reason, '', '', NULL,
	       eca.entity_type, eca.entity_id, eca.previous_state, eca.new_state, eca.immutable_digest,
	       COALESCE(dg.root_grant_id::text, ''), COALESCE(dg.parent_grant_id::text, ''),
	       '', COALESCE(dg.delegation_depth, 0), COALESCE(dg.delegator_agent_id::text, ''),
	       COALESCE(dg.delegatee_agent_id::text, ''), COALESCE(tr.trust_domain, ''),
	       COALESCE(dg.external_agent_id::text, ''), COALESCE(dg.subject_principal_id, ''),
	       COALESCE(dg.authority_scope_digest, ''), COALESCE(dg.attenuation_digest, ''),
	       '', ''
	FROM emergency_control_actions eca
	LEFT JOIN agent_versions av ON eca.entity_type = 'agent_version' AND av.id::text = eca.entity_id
	LEFT JOIN agents ava ON ava.id = av.agent_id
	LEFT JOIN agents ag ON eca.entity_type = 'agent' AND ag.id::text = eca.entity_id
	LEFT JOIN agent_tool_grants gt ON eca.entity_type = 'agent_tool_grant' AND gt.id::text = eca.entity_id
	LEFT JOIN agents gta ON gta.id = gt.agent_id
	LEFT JOIN delegated_authority_grants dg ON eca.entity_type = 'delegation_grant' AND dg.id::text = eca.entity_id
	LEFT JOIN agent_trust_relationships tr ON tr.id::text = dg.trust_relationship_id::text
	LEFT JOIN agents dga ON dga.id = dg.agent_id
	LEFT JOIN agent_runs er ON eca.entity_type = 'run' AND er.id::text = eca.entity_id
	LEFT JOIN agents era ON era.id = er.agent_id
	LEFT JOIN tools tl ON eca.entity_type = 'tool' AND tl.id::text = eca.entity_id
	WHERE eca.tenant_id = $1

	UNION ALL

	SELECT ci.id::text, 'connector_invocation', ci.tenant_id, ci.occurred_at,
	       '', COALESCE(d.agent_id::text, ''), COALESCE(a.name, ''), '', COALESCE(a.owner_principal_id, ''),
	       COALESCE(d.delegation_grant_id::text, ''), '', COALESCE(ci.run_id::text, ''),
	       COALESCE(r.status, ''), COALESCE(ci.tool_id::text, ''), COALESCE(t.name, ''),
	       COALESCE(ci.tool_action_id::text, ''), '', ci.outcome, ci.error_code, ci.kind, '',
	       COALESCE(ci.trace_id, ''),
	       'connector', ci.connector_id::text, '', '', ci.immutable_digest,
	       COALESCE(g.root_grant_id::text, ''), COALESCE(g.parent_grant_id::text, ''),
	       '', COALESCE(d.delegation_depth, 0), COALESCE(g.delegator_agent_id::text, ''),
	       COALESCE(g.delegatee_agent_id::text, ''), COALESCE(tr.trust_domain, ''),
	       COALESCE(g.external_agent_id::text, ''), COALESCE(g.subject_principal_id, ''),
	       COALESCE(g.authority_scope_digest, ''), COALESCE(g.attenuation_digest, ''),
	       COALESCE(d.chain_verified, ''), ''
	FROM connector_invocations ci
	LEFT JOIN agent_action_decisions d ON d.id::text = ci.decision_id
	LEFT JOIN agents a ON a.id = d.agent_id
	LEFT JOIN agent_runs r ON r.id = ci.run_id
	LEFT JOIN tools t ON t.id = ci.tool_id
	LEFT JOIN delegated_authority_grants g ON g.id = d.delegation_grant_id
	LEFT JOIN agent_trust_relationships tr ON tr.id::text = g.trust_relationship_id::text
	WHERE ci.tenant_id = $1

	UNION ALL

	SELECT cle.id::text, 'connector_lifecycle', cle.tenant_id, cle.created_at,
	       cle.actor_principal_id, '', '', '', '',
	       '', '', '', '',
	       COALESCE(c.tool_id::text, ''), COALESCE(tl.name, ''),
	       '', '', cle.action_type, cle.reason, '', '',
	       NULL,
	       'connector', cle.connector_id::text, cle.from_state, cle.to_state, cle.immutable_digest,
	       '', '', '', 0, '', '', '', '', '', '', '', '', ''
	FROM connector_lifecycle_events cle
	LEFT JOIN connectors c ON c.id = cle.connector_id
	LEFT JOIN tools tl ON tl.id = c.tool_id
	WHERE cle.tenant_id = $1

	UNION ALL

	SELECT te.id::text, 'trust', te.tenant_id, te.occurred_at,
	       te.actor_principal_id, '', '', '', '',
	       COALESCE(te.grant_id::text, ''), '', '', '',
	       '', '', '', '', '', te.reason, '', '', NULL,
	       te.entity_type, te.entity_id, te.previous_state, te.new_state, te.immutable_digest,
	       COALESCE(te.root_grant_id::text, ''), COALESCE(te.parent_grant_id::text, ''),
	       '', te.delegation_depth, '', '',
	       COALESCE(te.trust_domain, ''), COALESCE(te.organization_id, ''),
	       COALESCE(te.subject_principal_id, ''),
	       COALESCE(te.scope_digest, ''), COALESCE(te.attenuation_digest, ''),
	       '', COALESCE(te.revocation_source, '')
	FROM trust_events te
	WHERE te.tenant_id = $1
) e
`

// scanEvidenceRow scans one union row into an EvidenceEvent. trace_id
// is NULL for delegation-mint and emergency-control branches.
func scanEvidenceRow(row interface{ Scan(...any) error }) (runtime.EvidenceEvent, error) {
	var e runtime.EvidenceEvent
	var traceID sql.NullString
	err := row.Scan(&e.EventID, &e.Kind, &e.TenantID, &e.OccurredAt,
		&e.ActorPrincipalID, &e.AgentID, &e.AgentName, &e.AgentVersionID,
		&e.OwnerPrincipalID, &e.DelegationGrantID, &e.UserID, &e.RunID,
		&e.RunStatus, &e.ToolID, &e.ToolName, &e.ActionID, &e.ResourceRef,
		&e.Decision, &e.Reason, &e.ReasonCode, &e.PolicyVersion, &traceID,
		&e.EntityType, &e.EntityID, &e.PreviousState, &e.NewState, &e.ImmutableDigest,
		&e.RootGrantID, &e.ParentGrantID, &e.ChildGrantID, &e.DelegationDepth,
		&e.DelegatorAgentID, &e.DelegateeAgentID, &e.TrustDomain, &e.OrganizationID,
		&e.SubjectPrincipalID, &e.ScopeDigest, &e.AttenuationDigest,
		&e.ChainVerification, &e.RevocationSource)
	if traceID.Valid {
		e.TraceID = traceID.String
	}
	return e, err
}

// evidenceWhere builds tenant + filter + cursor predicates over the
// union. All filters operate on the aliased output columns.
func (p *pgReader) evidenceWhere(tenantID string, f runtime.EvidenceFilter) (string, []any) {
	clauses := []string{"e.tenant_id = $1"}
	args := []any{tenantID}
	add := func(cond string, arg any) {
		args = append(args, arg)
		clauses = append(clauses, fmt.Sprintf("e.%s = $%d", cond, len(args)))
	}
	if f.From != "" {
		args = append(args, f.From)
		clauses = append(clauses, fmt.Sprintf("e.occurred_at >= $%d", len(args)))
	}
	if f.To != "" {
		args = append(args, f.To)
		clauses = append(clauses, fmt.Sprintf("e.occurred_at < $%d", len(args)))
	}
	if f.AgentID != "" {
		add("agent_id", f.AgentID)
	}
	if f.AgentVersionID != "" {
		add("agent_version_id", f.AgentVersionID)
	}
	if f.OwnerPrincipal != "" {
		add("owner_principal_id", f.OwnerPrincipal)
	}
	if f.UserID != "" {
		add("user_id", f.UserID)
	}
	if f.ToolID != "" {
		add("tool_id", f.ToolID)
	}
	if f.ActionID != "" {
		add("action_id", f.ActionID)
	}
	if f.RunStatus != "" {
		add("run_status", f.RunStatus)
	}
	if f.Decision != "" {
		add("decision", f.Decision)
	}
	if f.ReasonCode != "" {
		add("reason_code", f.ReasonCode)
	}
	if f.TraceID != "" {
		add("trace_id", f.TraceID)
	}
	if len(f.Kinds) > 0 {
		args = append(args, f.Kinds)
		clauses = append(clauses, fmt.Sprintf("e.kind = ANY($%d)", len(args)))
	}
	if f.Cursor != "" {
		after, afterID, err := decodeEvidenceCursor(f.Cursor)
		if err != nil {
			// An invalid cursor must fail the query, not skip it.
			clauses = append(clauses, "FALSE")
		} else {
			args = append(args, after, afterID)
			clauses = append(clauses, fmt.Sprintf("(e.occurred_at, e.event_id) > ($%d, $%d)", len(args)-1, len(args)))
		}
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func (p *pgReader) QueryEvidence(ctx context.Context, tenantID string, f runtime.EvidenceFilter) ([]runtime.EvidenceEvent, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	where, args := p.evidenceWhere(tenantID, f)
	args = append(args, limit)
	rows, err := p.q.QueryContext(ctx, `
		SELECT e.event_id, e.kind, e.tenant_id, e.occurred_at, e.actor_principal_id,
		       e.agent_id, e.agent_name, e.agent_version_id, e.owner_principal_id,
		       e.delegation_grant_id, e.user_id, e.run_id, e.run_status,
		       e.tool_id, e.tool_name, e.action_id, e.resource_ref,
		       e.decision, e.reason, e.reason_code, e.policy_version, e.trace_id,
		       e.entity_type, e.entity_id, e.previous_state, e.new_state, e.immutable_digest,
		       e.root_grant_id, e.parent_grant_id, e.child_grant_id, e.delegation_depth,
		       e.delegator_agent_id, e.delegatee_agent_id, e.trust_domain, e.organization_id,
		       e.subject_principal_id, e.scope_digest, e.attenuation_digest,
		       e.chain_verification, e.revocation_source
		FROM (`+evidenceUnion+`) e
		`+where+`
		ORDER BY e.occurred_at, e.event_id
		LIMIT $`+fmt.Sprintf("%d", len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.EvidenceEvent, 0)
	for rows.Next() {
		e, err := scanEvidenceRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *pgReader) GetEvidenceEvent(ctx context.Context, tenantID, eventID string) (runtime.EvidenceEvent, error) {
	e, err := scanEvidenceRow(p.q.QueryRowContext(ctx, `
		SELECT e.event_id, e.kind, e.tenant_id, e.occurred_at, e.actor_principal_id,
		       e.agent_id, e.agent_name, e.agent_version_id, e.owner_principal_id,
		       e.delegation_grant_id, e.user_id, e.run_id, e.run_status,
		       e.tool_id, e.tool_name, e.action_id, e.resource_ref,
		       e.decision, e.reason, e.reason_code, e.policy_version, e.trace_id,
		       e.entity_type, e.entity_id, e.previous_state, e.new_state, e.immutable_digest,
		       e.root_grant_id, e.parent_grant_id, e.child_grant_id, e.delegation_depth,
		       e.delegator_agent_id, e.delegatee_agent_id, e.trust_domain, e.organization_id,
		       e.subject_principal_id, e.scope_digest, e.attenuation_digest,
		       e.chain_verification, e.revocation_source
		FROM (`+evidenceUnion+`) e
		WHERE e.tenant_id = $1 AND e.event_id = $2
	`, tenantID, eventID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.EvidenceEvent{}, runtime.ErrEvidenceNotFound
	}
	return e, err
}

func (p *pgReader) GetRunEvidence(ctx context.Context, tenantID, runID string) ([]runtime.EvidenceEvent, error) {
	rows, err := p.q.QueryContext(ctx, `
		SELECT e.event_id, e.kind, e.tenant_id, e.occurred_at, e.actor_principal_id,
		       e.agent_id, e.agent_name, e.agent_version_id, e.owner_principal_id,
		       e.delegation_grant_id, e.user_id, e.run_id, e.run_status,
		       e.tool_id, e.tool_name, e.action_id, e.resource_ref,
		       e.decision, e.reason, e.reason_code, e.policy_version, e.trace_id,
		       e.entity_type, e.entity_id, e.previous_state, e.new_state, e.immutable_digest,
		       e.root_grant_id, e.parent_grant_id, e.child_grant_id, e.delegation_depth,
		       e.delegator_agent_id, e.delegatee_agent_id, e.trust_domain, e.organization_id,
		       e.subject_principal_id, e.scope_digest, e.attenuation_digest,
		       e.chain_verification, e.revocation_source
		FROM (`+evidenceUnion+`) e
		WHERE e.tenant_id = $1 AND e.run_id = $2
		ORDER BY e.occurred_at, e.event_id
	`, tenantID, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.EvidenceEvent, 0)
	for rows.Next() {
		e, err := scanEvidenceRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *pgReader) GetAgentEvidence(ctx context.Context, tenantID, agentID string, f runtime.EvidenceFilter) ([]runtime.EvidenceEvent, error) {
	f.AgentID = agentID
	return p.QueryEvidence(ctx, tenantID, f)
}

// ---------------------------------------------------------------------
// Checkpoints — Postgres store.
// ---------------------------------------------------------------------

const checkpointColumns = `id::text, tenant_id, last_event_id, last_verified_at, events_checked, chain_digest, created_at`

func scanCheckpoint(row interface{ Scan(...any) error }) (runtime.EvidenceCheckpoint, error) {
	var c runtime.EvidenceCheckpoint
	err := row.Scan(&c.ID, &c.TenantID, &c.LastEventID, &c.LastVerifiedAt,
		&c.EventsChecked, &c.ChainDigest, &c.CreatedAt)
	return c, err
}

func (p *pgReader) CreateCheckpoint(ctx context.Context, c runtime.EvidenceCheckpoint) (runtime.EvidenceCheckpoint, error) {
	// The service computes ChainDigest over the authoritative chain tails
	// at the boundary; the store records it verbatim so verification can
	// recompute it from current state (trust = the chains themselves).
	row := p.q.QueryRowContext(ctx, `
		INSERT INTO evidence_checkpoints (tenant_id, last_event_id, last_verified_at, events_checked, chain_digest)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+checkpointColumns,
		c.TenantID, c.LastEventID, c.LastVerifiedAt, c.EventsChecked, c.ChainDigest)
	return scanCheckpoint(row)
}

func (p *pgReader) ListCheckpoints(ctx context.Context, tenantID string) ([]runtime.EvidenceCheckpoint, error) {
	rows, err := p.q.QueryContext(ctx, `
		SELECT `+checkpointColumns+` FROM evidence_checkpoints
		WHERE tenant_id = $1
		ORDER BY last_verified_at DESC, id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.EvidenceCheckpoint, 0)
	for rows.Next() {
		c, err := scanCheckpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *pgReader) GetCheckpoint(ctx context.Context, tenantID, checkpointID string) (runtime.EvidenceCheckpoint, error) {
	c, err := scanCheckpoint(p.q.QueryRowContext(ctx, `
		SELECT `+checkpointColumns+` FROM evidence_checkpoints
		WHERE tenant_id = $1 AND id::text = $2
	`, tenantID, checkpointID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.EvidenceCheckpoint{}, runtime.ErrCheckpointNotFound
	}
	return c, err
}

// ---------------------------------------------------------------------
// Phase 5: connector invocation evidence — Postgres store.
// ---------------------------------------------------------------------

func (p *postgresTx) AppendConnectorInvocation(ctx context.Context, inv runtime.ConnectorInvocation) (runtime.ConnectorInvocation, error) {
	// Write-once evidence: compute the digest over the outcome fields
	// before the row is inserted (same digest the memory store mints).
	if inv.ImmutableDigest == "" {
		inv.ImmutableDigest = connectors.ConnectorInvocationDigest(inv)
	}
	_, err := p.tx.ExecContext(ctx, `
		INSERT INTO connector_invocations
			(tenant_id, connector_id, tool_id, tool_action_id, run_id, decision_id, kind,
			 outcome, status_code, error_code, duration_ms, response_bytes, region, trace_id,
			 immutable_digest, idempotency_key)
		VALUES ($1, $2, $3::uuid, $4::uuid, $5::uuid, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		inv.TenantID, inv.ConnectorID, nullUUID(inv.ToolID), nullUUID(inv.ToolActionID),
		nullUUID(inv.RunID), inv.DecisionID, inv.Kind, inv.Outcome, inv.StatusCode,
		inv.ErrorCode, inv.DurationMS, inv.ResponseBytes, inv.Region, inv.TraceID,
		inv.ImmutableDigest, nullStr(inv.IdempotencyKey))
	if err != nil {
		if isUniqueViolation(err) {
			return runtime.ConnectorInvocation{}, runtime.ErrIdempotencyConflict
		}
		return runtime.ConnectorInvocation{}, err
	}
	inv.ID = newID()
	return inv, nil
}

// GetConnectorInvocationByDedupKey returns the latest success recorded
// under the semantic idempotency key (Phase 8.2 replay check). The
// partial unique index guarantees at most one success per key; failures
// are excluded so retries after a failed attempt stay retryable.
func (p *pgReader) GetConnectorInvocationByDedupKey(ctx context.Context, tenantID, idempotencyKey string) (runtime.ConnectorInvocation, bool, error) {
	if idempotencyKey == "" {
		return runtime.ConnectorInvocation{}, false, nil
	}
	row := p.q.QueryRowContext(ctx, `
		SELECT id::text, tenant_id, connector_id::text, COALESCE(tool_id::text, ''),
			COALESCE(tool_action_id::text, ''), COALESCE(run_id::text, ''), decision_id,
			kind, outcome, status_code, error_code, duration_ms, response_bytes, region,
			trace_id, immutable_digest, occurred_at, COALESCE(idempotency_key, '')
		FROM connector_invocations
		WHERE tenant_id = $1 AND idempotency_key = $2 AND outcome = 'success'
		ORDER BY occurred_at DESC
		LIMIT 1`, tenantID, idempotencyKey)
	var inv runtime.ConnectorInvocation
	if err := row.Scan(&inv.ID, &inv.TenantID, &inv.ConnectorID, &inv.ToolID,
		&inv.ToolActionID, &inv.RunID, &inv.DecisionID, &inv.Kind, &inv.Outcome,
		&inv.StatusCode, &inv.ErrorCode, &inv.DurationMS, &inv.ResponseBytes,
		&inv.Region, &inv.TraceID, &inv.ImmutableDigest, &inv.OccurredAt, &inv.IdempotencyKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return runtime.ConnectorInvocation{}, false, nil
		}
		return runtime.ConnectorInvocation{}, false, err
	}
	return inv, true, nil
}

// nullStr returns nil for an empty string so pgx encodes SQL NULL.
func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (p *pgReader) ListConnectorInvocations(ctx context.Context, tenantID, connectorID string, limit int) ([]runtime.ConnectorInvocation, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := p.q.QueryContext(ctx, `
		SELECT id::text, tenant_id, connector_id::text, COALESCE(tool_id::text, ''),
			COALESCE(tool_action_id::text, ''), COALESCE(run_id::text, ''), decision_id,
			kind, outcome, status_code, error_code, duration_ms, response_bytes, region,
			trace_id, immutable_digest, occurred_at
		FROM connector_invocations
		WHERE tenant_id = $1 AND connector_id = $2
		ORDER BY occurred_at DESC
		LIMIT $3`, tenantID, connectorID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runtime.ConnectorInvocation, 0)
	for rows.Next() {
		var inv runtime.ConnectorInvocation
		if err := rows.Scan(&inv.ID, &inv.TenantID, &inv.ConnectorID, &inv.ToolID,
			&inv.ToolActionID, &inv.RunID, &inv.DecisionID, &inv.Kind, &inv.Outcome,
			&inv.StatusCode, &inv.ErrorCode, &inv.DurationMS, &inv.ResponseBytes,
			&inv.Region, &inv.TraceID, &inv.ImmutableDigest, &inv.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// nullUUID returns nil for an empty string so pgx encodes SQL NULL.
func nullUUID(s string) any {
	if s == "" {
		return nil
	}
	return s
}
