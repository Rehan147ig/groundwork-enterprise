// Phase 6 store layer: trust relationships, trust-event chains,
// external agents (+ replay-proof nonces), consent records, transfer
// policies, delegation-tree reads, and external-agent budgets.
//
// Memory and Postgres implementations are kept behaviorally identical;
// the Postgres schema lives in the repo-root migrations directory
// (015_create_delegated_authority, 019_create_agent_trust,
// 020_phase6_trust_schema_fix).

package governance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// ---------------------------------------------------------------------
// Memory store
// ---------------------------------------------------------------------

const externalNonceTTL = 10 * time.Minute

func trustScopeKey(scopeType, externalAgentID, organizationID, customerPrincipalID string) string {
	return scopeType + "|" + externalAgentID + "|" + organizationID + "|" + customerPrincipalID
}

func (m *MemoryStore) CreateTrustRelationship(_ context.Context, r runtime.AgentTrustRelationship) (runtime.AgentTrustRelationship, error) {
	if r.ID == "" {
		r.ID = newID()
	}
	if _, err := m.GetTrustRelationshipByPair(context.Background(), r.TenantID, r.ParentAgentID, r.ChildAgentID, r.ExternalAgentID); err == nil {
		return runtime.AgentTrustRelationship{}, runtime.ErrTrustConflict
	}
	r.ImmutableDigest = ComputeTrustRelationshipDigest(r)
	now := m.now().UTC().Truncate(time.Microsecond)
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.UpdatedAt = now
	if m.relationships[r.TenantID] == nil {
		m.relationships[r.TenantID] = map[string]runtime.AgentTrustRelationship{}
	}
	m.relationships[r.TenantID][r.ID] = r
	return r, nil
}

func (m *MemoryStore) GetTrustRelationship(_ context.Context, tenantID, relationshipID string) (runtime.AgentTrustRelationship, error) {
	r, ok := m.relationships[tenantID][relationshipID]
	if !ok {
		return runtime.AgentTrustRelationship{}, runtime.ErrTrustNotFound
	}
	return r, nil
}

func (m *MemoryStore) GetTrustRelationshipByPair(_ context.Context, tenantID, parentAgentID, childAgentID, externalAgentID string) (runtime.AgentTrustRelationship, error) {
	for _, r := range m.relationships[tenantID] {
		if r.ParentAgentID != parentAgentID {
			continue
		}
		if r.ExternalAgentID != "" {
			if r.ExternalAgentID == externalAgentID && externalAgentID != "" {
				return r, nil
			}
			continue
		}
		if r.ChildAgentID == childAgentID {
			return r, nil
		}
	}
	return runtime.AgentTrustRelationship{}, runtime.ErrTrustNotFound
}

func (m *MemoryStore) ListTrustRelationships(_ context.Context, tenantID string) ([]runtime.AgentTrustRelationship, error) {
	out := make([]runtime.AgentTrustRelationship, 0, len(m.relationships[tenantID]))
	for _, r := range m.relationships[tenantID] {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) UpdateTrustRelationshipStatus(_ context.Context, tenantID, relationshipID, expectedState, newState, reason string) error {
	r, ok := m.relationships[tenantID][relationshipID]
	if !ok {
		return runtime.ErrTrustNotFound
	}
	if r.Status != expectedState {
		return runtime.ErrTrustInvalidState
	}
	r.Status = newState
	r.Reason = reason
	r.UpdatedAt = m.now().UTC().Truncate(time.Microsecond)
	m.relationships[tenantID][relationshipID] = r
	return nil
}

func (m *MemoryStore) AppendTrustEvent(_ context.Context, e runtime.TrustEvent) (runtime.TrustEvent, error) {
	prevDigest := ""
	if tail := m.trustEvents[e.TenantID]; len(tail) > 0 {
		last := tail[len(tail)-1]
		// previous_event_id is the prior event's ID; the digest chain
		// hashes the prior event's DIGEST (parity with the Postgres
		// store and ComputeTrustEventDigest).
		e.PreviousEventID = last.ID
		prevDigest = last.ImmutableDigest
	}
	e.ImmutableDigest = ComputeTrustEventDigest(e, prevDigest)
	if e.OccurredAt.IsZero() {
		e.OccurredAt = m.now().UTC().Truncate(time.Microsecond)
	}
	m.trustEvents[e.TenantID] = append(m.trustEvents[e.TenantID], e)
	return e, nil
}

func (m *MemoryStore) ListTrustEvents(_ context.Context, tenantID string, limit int) ([]runtime.TrustEvent, error) {
	events := m.trustEvents[tenantID]
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	out := make([]runtime.TrustEvent, len(events))
	copy(out, events)
	return out, nil
}

func (m *MemoryStore) CreateExternalAgent(_ context.Context, a runtime.ExternalAgent) (runtime.ExternalAgent, error) {
	if a.ID == "" {
		a.ID = newID()
	}
	if _, err := m.GetExternalAgentByAgentID(context.Background(), a.TenantID, a.AgentID); err == nil {
		return runtime.ExternalAgent{}, runtime.ErrExternalConflict
	}
	if _, err := m.GetExternalAgentByIssuer(context.Background(), a.TenantID, a.VerifiedIssuer); err == nil {
		return runtime.ExternalAgent{}, runtime.ErrExternalConflict
	}
	a.ManifestDigest = ComputeExternalAgentDigest(a)
	now := m.now().UTC().Truncate(time.Microsecond)
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	a.UpdatedAt = now
	if m.externalAgents[a.TenantID] == nil {
		m.externalAgents[a.TenantID] = map[string]runtime.ExternalAgent{}
	}
	m.externalAgents[a.TenantID][a.ID] = a
	return a, nil
}

func (m *MemoryStore) GetExternalAgent(_ context.Context, tenantID, externalAgentID string) (runtime.ExternalAgent, error) {
	for _, a := range m.externalAgents[tenantID] {
		if a.ID == externalAgentID || a.ExternalAgentID == externalAgentID {
			return a, nil
		}
	}
	return runtime.ExternalAgent{}, runtime.ErrExternalNotFound
}

func (m *MemoryStore) GetExternalAgentByAgentID(_ context.Context, tenantID, agentID string) (runtime.ExternalAgent, error) {
	for _, a := range m.externalAgents[tenantID] {
		if a.AgentID == agentID {
			return a, nil
		}
	}
	return runtime.ExternalAgent{}, runtime.ErrExternalNotFound
}

func (m *MemoryStore) GetExternalAgentByIssuer(_ context.Context, tenantID, issuer string) (runtime.ExternalAgent, error) {
	for _, a := range m.externalAgents[tenantID] {
		if a.VerifiedIssuer == issuer {
			return a, nil
		}
	}
	return runtime.ExternalAgent{}, runtime.ErrExternalNotFound
}

func (m *MemoryStore) ListExternalAgents(_ context.Context, tenantID string) ([]runtime.ExternalAgent, error) {
	out := make([]runtime.ExternalAgent, 0, len(m.externalAgents[tenantID]))
	for _, a := range m.externalAgents[tenantID] {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) UpdateExternalAgentState(_ context.Context, tenantID, externalAgentID, expectedState, newState string) error {
	for id, a := range m.externalAgents[tenantID] {
		if a.ID != externalAgentID && a.ExternalAgentID != externalAgentID {
			continue
		}
		if a.LifecycleState != expectedState {
			return runtime.ErrExternalInvalid
		}
		a.LifecycleState = newState
		a.UpdatedAt = m.now().UTC().Truncate(time.Microsecond)
		m.externalAgents[tenantID][id] = a
		return nil
	}
	return runtime.ErrExternalNotFound
}

func (m *MemoryStore) ConsumeExternalNonce(_ context.Context, tenantID, externalAgentID, jti string) error {
	now := m.now().UTC()
	if m.externalNonces[tenantID] == nil {
		m.externalNonces[tenantID] = map[string]map[string]time.Time{}
	}
	if m.externalNonces[tenantID][externalAgentID] == nil {
		m.externalNonces[tenantID][externalAgentID] = map[string]time.Time{}
	}
	for used, at := range m.externalNonces[tenantID][externalAgentID] {
		if now.Sub(at) > externalNonceTTL {
			delete(m.externalNonces[tenantID][externalAgentID], used)
		}
	}
	if _, seen := m.externalNonces[tenantID][externalAgentID][jti]; seen {
		return runtime.ErrNonceReplay
	}
	m.externalNonces[tenantID][externalAgentID][jti] = now
	return nil
}

func (m *MemoryStore) GetTransferPolicy(_ context.Context, tenantID, sourceRegion, targetRegion, purpose string) (runtime.TransferPolicy, error) {
	if m.transferPolic[tenantID] == nil {
		return runtime.TransferPolicy{}, runtime.ErrTransferDenied
	}
	for key, p := range m.transferPolic[tenantID] {
		if strings.HasPrefix(key, sourceRegion+"|"+targetRegion+"|") && (p.PurposePattern == "*" || p.PurposePattern == purpose) && p.Enabled {
			return p, nil
		}
	}
	return runtime.TransferPolicy{}, runtime.ErrTransferDenied
}

func (m *MemoryStore) ListTransferPolicies(_ context.Context, tenantID string) ([]runtime.TransferPolicy, error) {
	out := make([]runtime.TransferPolicy, 0, len(m.transferPolic[tenantID]))
	for _, p := range m.transferPolic[tenantID] {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) UpsertTransferPolicy(_ context.Context, p runtime.TransferPolicy) (runtime.TransferPolicy, error) {
	if m.transferPolic[p.TenantID] == nil {
		m.transferPolic[p.TenantID] = map[string]runtime.TransferPolicy{}
	}
	key := p.SourceRegion + "|" + p.TargetRegion + "|" + p.PurposePattern
	if existing, ok := m.transferPolic[p.TenantID][key]; ok {
		p.ID = existing.ID
		p.CreatedAt = existing.CreatedAt
		p.CreatedBy = existing.CreatedBy
	} else {
		if p.ID == "" {
			p.ID = newID()
		}
		if p.CreatedAt.IsZero() {
			p.CreatedAt = m.now().UTC().Truncate(time.Microsecond)
		}
	}
	m.transferPolic[p.TenantID][key] = p
	return p, nil
}

func (m *MemoryStore) GetTransferPolicyByID(_ context.Context, tenantID, policyID string) (runtime.TransferPolicy, error) {
	for _, p := range m.transferPolic[tenantID] {
		if p.ID == policyID {
			return p, nil
		}
	}
	return runtime.TransferPolicy{}, runtime.ErrTransferPolicyNotFound
}

func (m *MemoryStore) SetTransferPolicyEnabled(_ context.Context, tenantID, policyID string, enabled bool) (runtime.TransferPolicy, error) {
	for key, p := range m.transferPolic[tenantID] {
		if p.ID == policyID {
			p.Enabled = enabled
			m.transferPolic[tenantID][key] = p
			return p, nil
		}
	}
	return runtime.TransferPolicy{}, runtime.ErrTransferPolicyNotFound
}

func (m *MemoryStore) CreateConsentRecord(_ context.Context, c runtime.ConsentRecord) (runtime.ConsentRecord, error) {
	if c.ID == "" {
		c.ID = newID()
	}
	c.ImmutableDigest = ComputeConsentDigest(c)
	if c.GrantedAt.IsZero() {
		c.GrantedAt = m.now().UTC().Truncate(time.Microsecond)
	}
	// Mirror the Postgres partial unique index: at most one ACTIVE consent
	// per (tenant, org, external agent, customer, purpose). Re-granting
	// after a revoke creates a fresh row.
	if c.Status == "active" {
		for _, existing := range m.consents[c.TenantID] {
			if existing.Status == "active" && existing.OrganizationID == c.OrganizationID &&
				existing.ExternalAgentID == c.ExternalAgentID &&
				existing.CustomerPrincipalID == c.CustomerPrincipalID && existing.Purpose == c.Purpose {
				return runtime.ConsentRecord{}, runtime.ErrConsentConflict
			}
		}
	}
	if m.consents[c.TenantID] == nil {
		m.consents[c.TenantID] = map[string]runtime.ConsentRecord{}
	}
	m.consents[c.TenantID][c.ID] = c
	return c, nil
}

func (m *MemoryStore) UpdateConsentStatus(_ context.Context, tenantID, consentID, expectedStatus, newStatus, actor, reason string) (runtime.ConsentRecord, error) {
	c, ok := m.consents[tenantID][consentID]
	if !ok {
		return runtime.ConsentRecord{}, runtime.ErrConsentNotFound
	}
	if c.Status != expectedStatus {
		return runtime.ConsentRecord{}, runtime.ErrConsentRevoked
	}
	c.Status = newStatus
	c.ImmutableDigest = ComputeConsentDigest(c)
	m.consents[tenantID][consentID] = c
	return c, nil
}

func (m *MemoryStore) GetConsentRecord(_ context.Context, tenantID, consentID string) (runtime.ConsentRecord, error) {
	c, ok := m.consents[tenantID][consentID]
	if !ok {
		return runtime.ConsentRecord{}, runtime.ErrConsentNotFound
	}
	return c, nil
}

func (m *MemoryStore) FindConsent(_ context.Context, tenantID, organizationID, externalAgentID, customerPrincipalID, purpose, resourceRef string) (runtime.ConsentRecord, error) {
	var best runtime.ConsentRecord
	found := false
	for _, c := range m.consents[tenantID] {
		if c.OrganizationID != organizationID || c.ExternalAgentID != externalAgentID ||
			c.CustomerPrincipalID != customerPrincipalID || c.Purpose != purpose || c.Status != "active" {
			continue
		}
		if !scopeMatches(c.ResourceRefPattern, resourceRef) {
			continue
		}
		if m.now().UTC().After(c.ExpiresAt) {
			continue
		}
		if !found || c.ExpiresAt.After(best.ExpiresAt) {
			best = c
			found = true
		}
	}
	if !found {
		return runtime.ConsentRecord{}, runtime.ErrConsentNotFound
	}
	return best, nil
}

func (m *MemoryStore) ListConsentRecords(_ context.Context, tenantID string) ([]runtime.ConsentRecord, error) {
	out := make([]runtime.ConsentRecord, 0, len(m.consents[tenantID]))
	for _, c := range m.consents[tenantID] {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GrantedAt.Before(out[j].GrantedAt) })
	return out, nil
}

func (m *MemoryStore) ListChildGrants(_ context.Context, tenantID, parentGrantID string) ([]runtime.DelegationGrant, error) {
	var out []runtime.DelegationGrant
	for _, g := range m.delegations[tenantID] {
		if g.ParentGrantID == parentGrantID {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.Before(out[j].IssuedAt) })
	return out, nil
}

func (m *MemoryStore) ListDescendantGrantIDs(_ context.Context, tenantID, rootGrantID string) ([]string, error) {
	children := map[string][]string{}
	for _, g := range m.delegations[tenantID] {
		children[g.ParentGrantID] = append(children[g.ParentGrantID], g.ID)
	}
	var walk func(parent string) []string
	walk = func(parent string) []string {
		var out []string
		for _, id := range children[parent] {
			out = append(out, id)
			out = append(out, walk(id)...)
		}
		return out
	}
	return walk(rootGrantID), nil
}

func (m *MemoryStore) UpsertExternalBudget(_ context.Context, b runtime.ExternalBudgetPolicy) (runtime.ExternalBudgetPolicy, error) {
	if m.externalBudget[b.TenantID] == nil {
		m.externalBudget[b.TenantID] = map[string]runtime.ExternalBudgetPolicy{}
	}
	key := trustScopeKey(b.ScopeType, b.ExternalAgentID, b.OrganizationID, b.CustomerPrincipalID)
	if existing, ok := m.externalBudget[b.TenantID][key]; ok {
		b.ID = existing.ID
		b.CreatedAt = existing.CreatedAt
		b.CreatedBy = existing.CreatedBy
		b.ActionsCount = existing.ActionsCount
		b.DeniedCount = existing.DeniedCount
		b.ApprovalRequiredCount = existing.ApprovalRequiredCount
		b.ToolCallsCount = existing.ToolCallsCount
	} else {
		if b.ID == "" {
			b.ID = newID()
		}
		b.CreatedAt = m.now().UTC().Truncate(time.Microsecond)
	}
	b.UpdatedAt = m.now().UTC().Truncate(time.Microsecond)
	m.externalBudget[b.TenantID][key] = b
	return b, nil
}

func (m *MemoryStore) GetExternalBudget(_ context.Context, tenantID, scopeType, externalAgentID, organizationID, customerPrincipalID string) (runtime.ExternalBudgetPolicy, error) {
	b, ok := m.externalBudget[tenantID][trustScopeKey(scopeType, externalAgentID, organizationID, customerPrincipalID)]
	if !ok {
		return runtime.ExternalBudgetPolicy{}, fmt.Errorf("%w: no external budget for scope %q", runtime.ErrDelegationNotAllowed, scopeType)
	}
	return b, nil
}

func (m *MemoryStore) ListExternalBudgets(_ context.Context, tenantID string) ([]runtime.ExternalBudgetPolicy, error) {
	out := make([]runtime.ExternalBudgetPolicy, 0, len(m.externalBudget[tenantID]))
	for _, b := range m.externalBudget[tenantID] {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) IncrementExternalBudgetCounters(_ context.Context, tenantID, scopeType, externalAgentID, organizationID, customerPrincipalID string, actions, denied, approvals, toolCalls int) error {
	b, err := m.GetExternalBudget(context.Background(), tenantID, scopeType, externalAgentID, organizationID, customerPrincipalID)
	if err != nil {
		return err
	}
	key := trustScopeKey(scopeType, externalAgentID, organizationID, customerPrincipalID)
	b.ActionsCount += actions
	b.DeniedCount += denied
	b.ApprovalRequiredCount += approvals
	b.ToolCallsCount += toolCalls
	b.UpdatedAt = m.now().UTC().Truncate(time.Microsecond)
	m.externalBudget[tenantID][key] = b
	return nil
}

// ---------------------------------------------------------------------
// Postgres
// ---------------------------------------------------------------------

const trustRelationshipColumns = `id::text, tenant_id, parent_agent_id::text, child_agent_id::text, external_agent_id::text, trust_domain, owner_principal_id, purpose, max_delegation_depth, allowed_tools_actions, region, expires_at, status, approval_required, reason, immutable_digest, created_at, updated_at`

func scanTrustRelationship(row interface{ Scan(...any) error }) (runtime.AgentTrustRelationship, error) {
	var r runtime.AgentTrustRelationship
	var childID, extID, allowed sql.NullString
	err := row.Scan(&r.ID, &r.TenantID, &r.ParentAgentID, &childID, &extID, &r.TrustDomain,
		&r.OwnerPrincipalID, &r.Purpose, &r.MaxDelegationDepth, &allowed, &r.Region, &r.ExpiresAt,
		&r.Status, &r.ApprovalRequired, &r.Reason, &r.ImmutableDigest, &r.CreatedAt, &r.UpdatedAt)
	if childID.Valid {
		r.ChildAgentID = childID.String
	}
	if extID.Valid {
		r.ExternalAgentID = extID.String
	}
	if allowed.Valid && allowed.String != "" {
		r.AllowedToolsActions = strings.Split(allowed.String, ",")
	}
	return r, err
}

func (p *postgresTx) CreateTrustRelationship(ctx context.Context, r runtime.AgentTrustRelationship) (runtime.AgentTrustRelationship, error) {
	if r.ID == "" {
		r.ID = newID()
	}
	r.ImmutableDigest = ComputeTrustRelationshipDigest(r)
	row := p.tx.QueryRowContext(ctx, `
		INSERT INTO agent_trust_relationships
			(id, tenant_id, parent_agent_id, child_agent_id, external_agent_id, trust_domain, owner_principal_id,
			 purpose, max_delegation_depth, allowed_tools_actions, region, expires_at, status, approval_required,
			 reason, immutable_digest)
		VALUES ($1, $2, $3::uuid, $4::uuid, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING `+trustRelationshipColumns,
		r.ID, r.TenantID, r.ParentAgentID, nullString(r.ChildAgentID), nullString(r.ExternalAgentID), r.TrustDomain,
		r.OwnerPrincipalID, r.Purpose, r.MaxDelegationDepth, joinAllowed(r.AllowedToolsActions), r.Region,
		r.ExpiresAt, r.Status, r.ApprovalRequired, r.Reason, r.ImmutableDigest)
	if err := row.Scan(&r.ID, &r.TenantID, &r.ParentAgentID, new(sql.NullString), new(sql.NullString), &r.TrustDomain,
		&r.OwnerPrincipalID, &r.Purpose, &r.MaxDelegationDepth, new(sql.NullString), &r.Region, &r.ExpiresAt,
		&r.Status, &r.ApprovalRequired, &r.Reason, &r.ImmutableDigest, &r.CreatedAt, &r.UpdatedAt); err != nil {
		if isUniqueViolation(err) {
			return runtime.AgentTrustRelationship{}, runtime.ErrTrustConflict
		}
		return runtime.AgentTrustRelationship{}, err
	}
	return r, nil
}

func joinAllowed(entries []string) sql.NullString {
	// The columns are NOT NULL in the schema; empty scope is stored as
	// an empty string (never NULL) and reads back as an empty slice.
	if len(entries) == 0 {
		return sql.NullString{String: "", Valid: true}
	}
	return sql.NullString{String: strings.Join(entries, ","), Valid: true}
}

func (r pgReader) GetTrustRelationship(ctx context.Context, tenantID, relationshipID string) (runtime.AgentTrustRelationship, error) {
	rel, err := scanTrustRelationship(r.q.QueryRowContext(ctx, `
		SELECT `+trustRelationshipColumns+` FROM agent_trust_relationships
		WHERE tenant_id = $1 AND id::text = $2
	`, tenantID, relationshipID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.AgentTrustRelationship{}, runtime.ErrTrustNotFound
	}
	return rel, err
}

func (r pgReader) GetTrustRelationshipByPair(ctx context.Context, tenantID, parentAgentID, childAgentID, externalAgentID string) (runtime.AgentTrustRelationship, error) {
	rel, err := scanTrustRelationship(r.q.QueryRowContext(ctx, `
		SELECT `+trustRelationshipColumns+` FROM agent_trust_relationships
		WHERE tenant_id = $1 AND parent_agent_id = $2
		  AND COALESCE(child_agent_id::text, '') = $3 AND COALESCE(external_agent_id::text, '') = $4
	`, tenantID, parentAgentID, childAgentID, externalAgentID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.AgentTrustRelationship{}, runtime.ErrTrustNotFound
	}
	return rel, err
}

func (r pgReader) ListTrustRelationships(ctx context.Context, tenantID string) ([]runtime.AgentTrustRelationship, error) {
	rows, err := r.q.QueryContext(ctx, `
		SELECT `+trustRelationshipColumns+` FROM agent_trust_relationships
		WHERE tenant_id = $1 ORDER BY created_at ASC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.AgentTrustRelationship
	for rows.Next() {
		rel, err := scanTrustRelationship(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, rows.Err()
}

func (p *postgresTx) UpdateTrustRelationshipStatus(ctx context.Context, tenantID, relationshipID, expectedState, newState, reason string) error {
	tag, err := p.tx.ExecContext(ctx, `
		UPDATE agent_trust_relationships
		SET status = $4, reason = $5, updated_at = now()
		WHERE tenant_id = $1 AND id::text = $2 AND status = $3
	`, tenantID, relationshipID, expectedState, newState, reason)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		if _, err := scanTrustRelationship(p.tx.QueryRowContext(ctx, `
			SELECT `+trustRelationshipColumns+` FROM agent_trust_relationships
			WHERE tenant_id = $1 AND id::text = $2
		`, tenantID, relationshipID)); err != nil {
			return runtime.ErrTrustNotFound
		}
		return runtime.ErrTrustInvalidState
	}
	return nil
}

const trustEventColumns = `id::text, tenant_id, event_type, entity_type, entity_id, actor_principal_id, previous_state, new_state, reason, grant_id::text, parent_grant_id::text, root_grant_id::text, delegation_depth, subject_principal_id, trust_domain, organization_id, scope_digest, attenuation_digest, revocation_source, immutable_digest, previous_event_id, occurred_at`

func scanTrustEvent(row interface{ Scan(...any) error }) (runtime.TrustEvent, error) {
	var e runtime.TrustEvent
	var grantID, parentGrantID, rootGrantID sql.NullString
	err := row.Scan(&e.ID, &e.TenantID, &e.EventType, &e.EntityType, &e.EntityID, &e.ActorPrincipalID,
		&e.PreviousState, &e.NewState, &e.Reason, &grantID, &parentGrantID, &rootGrantID, &e.DelegationDepth,
		&e.SubjectPrincipalID, &e.TrustDomain, &e.OrganizationID, &e.ScopeDigest, &e.AttenuationDigest,
		&e.RevocationSource, &e.ImmutableDigest, &e.PreviousEventID, &e.OccurredAt)
	if grantID.Valid {
		e.GrantID = grantID.String
	}
	if parentGrantID.Valid {
		e.ParentGrantID = parentGrantID.String
	}
	if rootGrantID.Valid {
		e.RootGrantID = rootGrantID.String
	}
	return e, err
}

func (p *postgresTx) AppendTrustEvent(ctx context.Context, e runtime.TrustEvent) (runtime.TrustEvent, error) {
	var prevID, prevDigest string
	err := p.tx.QueryRowContext(ctx, `
		SELECT id::text, immutable_digest FROM trust_events
		WHERE tenant_id = $1 ORDER BY occurred_at DESC, id DESC LIMIT 1
	`, e.TenantID).Scan(&prevID, &prevDigest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return runtime.TrustEvent{}, err
	}
	// previous_event_id is the prior event's ID; the digest chain hashes
	// the prior event's DIGEST (ComputeTrustEventDigest).
	e.PreviousEventID = prevID
	e.ImmutableDigest = ComputeTrustEventDigest(e, prevDigest)
	row := p.tx.QueryRowContext(ctx, `
		INSERT INTO trust_events
			(id, tenant_id, event_type, entity_type, entity_id, actor_principal_id, previous_state, new_state, reason,
			 grant_id, parent_grant_id, root_grant_id, delegation_depth, subject_principal_id, trust_domain,
			 organization_id, scope_digest, attenuation_digest, revocation_source, immutable_digest, previous_event_id,
			 occurred_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
		RETURNING `+trustEventColumns,
		e.ID, e.TenantID, e.EventType, e.EntityType, e.EntityID, e.ActorPrincipalID, e.PreviousState, e.NewState, e.Reason,
		notNullString(e.GrantID), notNullString(e.ParentGrantID), notNullString(e.RootGrantID), e.DelegationDepth,
		notNullString(e.SubjectPrincipalID), notNullString(e.TrustDomain), notNullString(e.OrganizationID),
		notNullString(e.ScopeDigest), notNullString(e.AttenuationDigest), notNullString(e.RevocationSource),
		e.ImmutableDigest, notNullString(e.PreviousEventID), e.OccurredAt)
	return scanTrustEvent(row)
}

func (r pgReader) ListTrustEvents(ctx context.Context, tenantID string, limit int) ([]runtime.TrustEvent, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := r.q.QueryContext(ctx, `
		SELECT `+trustEventColumns+` FROM trust_events
		WHERE tenant_id = $1 ORDER BY occurred_at ASC, id ASC LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.TrustEvent
	for rows.Next() {
		e, err := scanTrustEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const externalAgentColumns = `id::text, external_agent_id, agent_id::text, organization_id, tenant_id, owner_principal_id, verified_issuer, allowed_audiences, auth_method, trust_tier, region, allowed_tools_actions, public_key_jwks_ref, manifest_digest, security_contact, lifecycle_state, expires_at, created_at, updated_at`

func scanExternalAgent(row interface{ Scan(...any) error }) (runtime.ExternalAgent, error) {
	var a runtime.ExternalAgent
	var audiences, allowed sql.NullString
	err := row.Scan(&a.ID, &a.ExternalAgentID, &a.AgentID, &a.OrganizationID, &a.TenantID, &a.OwnerPrincipalID,
		&a.VerifiedIssuer, &audiences, &a.AuthMethod, &a.TrustTier, &a.Region, &allowed, &a.PublicKeyJWKSRef,
		&a.ManifestDigest, &a.SecurityContact, &a.LifecycleState, &a.ExpiresAt, &a.CreatedAt, &a.UpdatedAt)
	if audiences.Valid && audiences.String != "" {
		a.AllowedAudiences = strings.Split(audiences.String, ",")
	}
	if allowed.Valid && allowed.String != "" {
		a.AllowedToolsActions = strings.Split(allowed.String, ",")
	}
	return a, err
}

func (p *postgresTx) CreateExternalAgent(ctx context.Context, a runtime.ExternalAgent) (runtime.ExternalAgent, error) {
	a.ManifestDigest = ComputeExternalAgentDigest(a)
	row := p.tx.QueryRowContext(ctx, `
		INSERT INTO external_agents
			(external_agent_id, agent_id, organization_id, tenant_id, owner_principal_id, verified_issuer,
			 allowed_audiences, auth_method, trust_tier, region, allowed_tools_actions, public_key_jwks_ref,
			 manifest_digest, security_contact, lifecycle_state, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING `+externalAgentColumns,
		a.ExternalAgentID, a.AgentID, a.OrganizationID, a.TenantID, a.OwnerPrincipalID, a.VerifiedIssuer,
		joinAllowed(a.AllowedAudiences), a.AuthMethod, a.TrustTier, a.Region, joinAllowed(a.AllowedToolsActions),
		notNullString(a.PublicKeyJWKSRef), notNullString(a.ManifestDigest), notNullString(a.SecurityContact), a.LifecycleState, a.ExpiresAt)
	if err := row.Scan(&a.ID, &a.ExternalAgentID, &a.AgentID, &a.OrganizationID, &a.TenantID, &a.OwnerPrincipalID,
		&a.VerifiedIssuer, new(sql.NullString), &a.AuthMethod, &a.TrustTier, &a.Region, new(sql.NullString),
		&a.PublicKeyJWKSRef, &a.ManifestDigest, &a.SecurityContact, &a.LifecycleState, &a.ExpiresAt, &a.CreatedAt, &a.UpdatedAt); err != nil {
		if isUniqueViolation(err) {
			return runtime.ExternalAgent{}, runtime.ErrExternalConflict
		}
		return runtime.ExternalAgent{}, err
	}
	return a, nil
}

func (r pgReader) GetExternalAgent(ctx context.Context, tenantID, externalAgentID string) (runtime.ExternalAgent, error) {
	a, err := scanExternalAgent(r.q.QueryRowContext(ctx, `
		SELECT `+externalAgentColumns+` FROM external_agents
		WHERE tenant_id = $1 AND (id::text = $2 OR external_agent_id = $2)
	`, tenantID, externalAgentID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.ExternalAgent{}, runtime.ErrExternalNotFound
	}
	return a, err
}

func (r pgReader) GetExternalAgentByAgentID(ctx context.Context, tenantID, agentID string) (runtime.ExternalAgent, error) {
	a, err := scanExternalAgent(r.q.QueryRowContext(ctx, `
		SELECT `+externalAgentColumns+` FROM external_agents
		WHERE tenant_id = $1 AND agent_id = $2
	`, tenantID, agentID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.ExternalAgent{}, runtime.ErrExternalNotFound
	}
	return a, err
}

func (r pgReader) GetExternalAgentByIssuer(ctx context.Context, tenantID, issuer string) (runtime.ExternalAgent, error) {
	a, err := scanExternalAgent(r.q.QueryRowContext(ctx, `
		SELECT `+externalAgentColumns+` FROM external_agents
		WHERE tenant_id = $1 AND verified_issuer = $2 LIMIT 1
	`, tenantID, issuer))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.ExternalAgent{}, runtime.ErrExternalNotFound
	}
	return a, err
}

func (r pgReader) ListExternalAgents(ctx context.Context, tenantID string) ([]runtime.ExternalAgent, error) {
	rows, err := r.q.QueryContext(ctx, `
		SELECT `+externalAgentColumns+` FROM external_agents
		WHERE tenant_id = $1 ORDER BY created_at ASC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.ExternalAgent
	for rows.Next() {
		a, err := scanExternalAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *postgresTx) UpdateExternalAgentState(ctx context.Context, tenantID, externalAgentID, expectedState, newState string) error {
	tag, err := p.tx.ExecContext(ctx, `
		UPDATE external_agents
		SET lifecycle_state = $4, updated_at = now()
		WHERE tenant_id = $1 AND (id::text = $2 OR external_agent_id = $2) AND lifecycle_state = $3
	`, tenantID, externalAgentID, expectedState, newState)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		if _, err := scanExternalAgent(p.tx.QueryRowContext(ctx, `
			SELECT `+externalAgentColumns+` FROM external_agents
			WHERE tenant_id = $1 AND (id::text = $2 OR external_agent_id = $2)
		`, tenantID, externalAgentID)); err != nil {
			return runtime.ErrExternalNotFound
		}
		return runtime.ErrExternalInvalid
	}
	return nil
}

func (p *postgresTx) ConsumeExternalNonce(ctx context.Context, tenantID, externalAgentID, jti string) error {
	tag, err := p.tx.ExecContext(ctx, `
		INSERT INTO external_nonces (tenant_id, external_agent_id, jti) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, external_agent_id, jti) DO NOTHING
	`, tenantID, externalAgentID, jti)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return runtime.ErrNonceReplay
	}
	_, _ = p.tx.ExecContext(ctx, `
		DELETE FROM external_nonces WHERE tenant_id = $1 AND used_at < now() - interval '10 minutes'
	`, tenantID)
	return nil
}

const transferPolicyColumns = `id::text, tenant_id, source_region, target_region, purpose_pattern, enabled, created_by, created_at`

func scanTransferPolicy(row interface{ Scan(...any) error }) (runtime.TransferPolicy, error) {
	var p runtime.TransferPolicy
	err := row.Scan(&p.ID, &p.TenantID, &p.SourceRegion, &p.TargetRegion, &p.PurposePattern, &p.Enabled, &p.CreatedBy, &p.CreatedAt)
	return p, err
}

func (r pgReader) GetTransferPolicy(ctx context.Context, tenantID, sourceRegion, targetRegion, purpose string) (runtime.TransferPolicy, error) {
	p, err := scanTransferPolicy(r.q.QueryRowContext(ctx, `
		SELECT `+transferPolicyColumns+` FROM transfer_policies
		WHERE tenant_id = $1 AND source_region = $2 AND target_region = $3
		  AND (purpose_pattern = '*' OR purpose_pattern = $4) AND enabled
		ORDER BY purpose_pattern DESC LIMIT 1
	`, tenantID, sourceRegion, targetRegion, purpose))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.TransferPolicy{}, runtime.ErrTransferDenied
	}
	return p, err
}

func (r pgReader) ListTransferPolicies(ctx context.Context, tenantID string) ([]runtime.TransferPolicy, error) {
	rows, err := r.q.QueryContext(ctx, `
		SELECT `+transferPolicyColumns+` FROM transfer_policies
		WHERE tenant_id = $1 ORDER BY created_at ASC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.TransferPolicy
	for rows.Next() {
		p, err := scanTransferPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r pgReader) GetTransferPolicyByID(ctx context.Context, tenantID, policyID string) (runtime.TransferPolicy, error) {
	p, err := scanTransferPolicy(r.q.QueryRowContext(ctx, `
		SELECT `+transferPolicyColumns+` FROM transfer_policies
		WHERE tenant_id = $1 AND id::text = $2
	`, tenantID, policyID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.TransferPolicy{}, runtime.ErrTransferPolicyNotFound
	}
	return p, err
}

func (p *postgresTx) SetTransferPolicyEnabled(ctx context.Context, tenantID, policyID string, enabled bool) (runtime.TransferPolicy, error) {
	row := p.tx.QueryRowContext(ctx, `
		UPDATE transfer_policies SET enabled = $3
		WHERE tenant_id = $1 AND id::text = $2
		RETURNING `+transferPolicyColumns,
		tenantID, policyID, enabled)
	policy, err := scanTransferPolicy(row)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.TransferPolicy{}, runtime.ErrTransferPolicyNotFound
	}
	return policy, err
}

func (p *postgresTx) UpsertTransferPolicy(ctx context.Context, req runtime.TransferPolicy) (runtime.TransferPolicy, error) {
	row := p.tx.QueryRowContext(ctx, `
		INSERT INTO transfer_policies (tenant_id, source_region, target_region, purpose_pattern, enabled, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, source_region, target_region, purpose_pattern)
		DO UPDATE SET enabled = EXCLUDED.enabled
		RETURNING `+transferPolicyColumns,
		req.TenantID, req.SourceRegion, req.TargetRegion, req.PurposePattern, req.Enabled, req.CreatedBy)
	return scanTransferPolicy(row)
}

const consentColumns = `id::text, tenant_id, organization_id, external_agent_id, customer_principal_id, purpose, resource_ref_pattern, status, granted_by, granted_at, expires_at, immutable_digest`

func scanConsent(row interface{ Scan(...any) error }) (runtime.ConsentRecord, error) {
	var c runtime.ConsentRecord
	err := row.Scan(&c.ID, &c.TenantID, &c.OrganizationID, &c.ExternalAgentID, &c.CustomerPrincipalID,
		&c.Purpose, &c.ResourceRefPattern, &c.Status, &c.GrantedBy, &c.GrantedAt, &c.ExpiresAt, &c.ImmutableDigest)
	return c, err
}

func (p *postgresTx) CreateConsentRecord(ctx context.Context, c runtime.ConsentRecord) (runtime.ConsentRecord, error) {
	if c.ID == "" {
		c.ID = newID()
	}
	c.ImmutableDigest = ComputeConsentDigest(c)
	row := p.tx.QueryRowContext(ctx, `
		INSERT INTO consent_records
			(id, tenant_id, organization_id, external_agent_id, customer_principal_id, purpose, resource_ref_pattern,
			 status, granted_by, granted_at, expires_at, immutable_digest)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING `+consentColumns,
		c.ID, c.TenantID, c.OrganizationID, c.ExternalAgentID, c.CustomerPrincipalID, c.Purpose,
		c.ResourceRefPattern, c.Status, c.GrantedBy, c.GrantedAt, c.ExpiresAt, c.ImmutableDigest)
	created, err := scanConsent(row)
	if err != nil && isUniqueViolation(err) {
		// Partial unique index (status = 'active'): one active grant per
		// (tenant, org, external agent, customer, purpose).
		return runtime.ConsentRecord{}, runtime.ErrConsentConflict
	}
	return created, err
}

// UpdateConsentStatus performs the single active->revoked transition.
// The trust-events rule makes the revocation itself immutable evidence;
// the consent row is updated in the same tx as the event.
func (p *postgresTx) UpdateConsentStatus(ctx context.Context, tenantID, consentID, expectedStatus, newStatus, actor, reason string) (runtime.ConsentRecord, error) {
	row := p.tx.QueryRowContext(ctx, `
		UPDATE consent_records SET status = $4
		WHERE tenant_id = $1 AND id::text = $2 AND status = $3
		RETURNING `+consentColumns,
		tenantID, consentID, expectedStatus, newStatus)
	c, err := scanConsent(row)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		if _, gerr := scanConsent(p.tx.QueryRowContext(ctx, `
			SELECT `+consentColumns+` FROM consent_records
			WHERE tenant_id = $1 AND id::text = $2
		`, tenantID, consentID)); gerr != nil {
			return runtime.ConsentRecord{}, runtime.ErrConsentNotFound
		}
		return runtime.ConsentRecord{}, runtime.ErrConsentRevoked
	}
	return c, err
}

func (r pgReader) GetConsentRecord(ctx context.Context, tenantID, consentID string) (runtime.ConsentRecord, error) {
	c, err := scanConsent(r.q.QueryRowContext(ctx, `
		SELECT `+consentColumns+` FROM consent_records
		WHERE tenant_id = $1 AND id::text = $2
	`, tenantID, consentID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.ConsentRecord{}, runtime.ErrConsentNotFound
	}
	return c, err
}

func (r pgReader) FindConsent(ctx context.Context, tenantID, organizationID, externalAgentID, customerPrincipalID, purpose, resourceRef string) (runtime.ConsentRecord, error) {
	c, err := scanConsent(r.q.QueryRowContext(ctx, `
		SELECT `+consentColumns+` FROM consent_records
		WHERE tenant_id = $1 AND organization_id = $2 AND external_agent_id = $3
		  AND customer_principal_id = $4 AND purpose = $5 AND status = 'active'
		  AND (resource_ref_pattern = '*' OR $6 LIKE resource_ref_pattern || '%')
		  AND expires_at > now()
		ORDER BY expires_at DESC LIMIT 1
	`, tenantID, organizationID, externalAgentID, customerPrincipalID, purpose, resourceRef))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.ConsentRecord{}, runtime.ErrConsentNotFound
	}
	return c, err
}

func (r pgReader) ListConsentRecords(ctx context.Context, tenantID string) ([]runtime.ConsentRecord, error) {
	rows, err := r.q.QueryContext(ctx, `
		SELECT `+consentColumns+` FROM consent_records
		WHERE tenant_id = $1 ORDER BY granted_at ASC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.ConsentRecord
	for rows.Next() {
		c, err := scanConsent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r pgReader) ListChildGrants(ctx context.Context, tenantID, parentGrantID string) ([]runtime.DelegationGrant, error) {
	rows, err := r.q.QueryContext(ctx, `
		SELECT `+delegationColumns+` FROM delegated_authority_grants
		WHERE tenant_id = $1 AND parent_grant_id::text = $2
		ORDER BY issued_at ASC
	`, tenantID, parentGrantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.DelegationGrant
	for rows.Next() {
		g, err := scanDelegation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (r pgReader) ListDescendantGrantIDs(ctx context.Context, tenantID, rootGrantID string) ([]string, error) {
	rows, err := r.q.QueryContext(ctx, `
		WITH RECURSIVE descendants AS (
			SELECT id FROM delegated_authority_grants WHERE tenant_id = $1 AND parent_grant_id::text = $2
			UNION ALL
			SELECT g.id FROM delegated_authority_grants g
			JOIN descendants d ON g.parent_grant_id = d.id
			WHERE g.tenant_id = $1
		)
		SELECT id::text FROM descendants
	`, tenantID, rootGrantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

const externalBudgetColumns = `id::text, tenant_id, scope_type, external_agent_id, organization_id, customer_principal_id, max_total_actions, max_actions_per_run, max_denied_per_run, max_approval_required_per_run, max_tool_calls_per_action_per_run, actions_count, denied_count, approval_required_count, tool_calls_count, created_by, created_at, updated_at`

func scanExternalBudget(row interface{ Scan(...any) error }) (runtime.ExternalBudgetPolicy, error) {
	var b runtime.ExternalBudgetPolicy
	err := row.Scan(&b.ID, &b.TenantID, &b.ScopeType, &b.ExternalAgentID, &b.OrganizationID, &b.CustomerPrincipalID,
		&b.MaxTotalActions, &b.MaxActionsPerRun, &b.MaxDeniedPerRun, &b.MaxApprovalRequiredPerRun,
		&b.MaxToolCallsPerActionPerRun, &b.ActionsCount, &b.DeniedCount, &b.ApprovalRequiredCount,
		&b.ToolCallsCount, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt)
	return b, err
}

func (p *postgresTx) UpsertExternalBudget(ctx context.Context, b runtime.ExternalBudgetPolicy) (runtime.ExternalBudgetPolicy, error) {
	row := p.tx.QueryRowContext(ctx, `
		INSERT INTO external_budget_policies
			(tenant_id, scope_type, external_agent_id, organization_id, customer_principal_id,
			 max_total_actions, max_actions_per_run, max_denied_per_run, max_approval_required_per_run,
			 max_tool_calls_per_action_per_run, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id, scope_type, external_agent_id, organization_id, customer_principal_id)
		DO UPDATE SET
			max_total_actions = EXCLUDED.max_total_actions,
			max_actions_per_run = EXCLUDED.max_actions_per_run,
			max_denied_per_run = EXCLUDED.max_denied_per_run,
			max_approval_required_per_run = EXCLUDED.max_approval_required_per_run,
			max_tool_calls_per_action_per_run = EXCLUDED.max_tool_calls_per_action_per_run,
			created_by = EXCLUDED.created_by,
			updated_at = now()
		RETURNING `+externalBudgetColumns,
		b.TenantID, b.ScopeType, nullString(b.ExternalAgentID), notNullString(b.OrganizationID), notNullString(b.CustomerPrincipalID),
		b.MaxTotalActions, b.MaxActionsPerRun, b.MaxDeniedPerRun, b.MaxApprovalRequiredPerRun,
		b.MaxToolCallsPerActionPerRun, b.CreatedBy)
	return scanExternalBudget(row)
}

func (r pgReader) GetExternalBudget(ctx context.Context, tenantID, scopeType, externalAgentID, organizationID, customerPrincipalID string) (runtime.ExternalBudgetPolicy, error) {
	b, err := scanExternalBudget(r.q.QueryRowContext(ctx, `
		SELECT `+externalBudgetColumns+` FROM external_budget_policies
		WHERE tenant_id = $1 AND scope_type = $2 AND COALESCE(external_agent_id, '') = $3
		  AND COALESCE(organization_id, '') = $4 AND COALESCE(customer_principal_id, '') = $5
	`, tenantID, scopeType, externalAgentID, organizationID, customerPrincipalID))
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return runtime.ExternalBudgetPolicy{}, fmt.Errorf("%w: no external budget for scope %q", runtime.ErrDelegationNotAllowed, scopeType)
	}
	return b, err
}

func (r pgReader) ListExternalBudgets(ctx context.Context, tenantID string) ([]runtime.ExternalBudgetPolicy, error) {
	rows, err := r.q.QueryContext(ctx, `
		SELECT `+externalBudgetColumns+` FROM external_budget_policies
		WHERE tenant_id = $1 ORDER BY created_at ASC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runtime.ExternalBudgetPolicy
	for rows.Next() {
		b, err := scanExternalBudget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (p *postgresTx) IncrementExternalBudgetCounters(ctx context.Context, tenantID, scopeType, externalAgentID, organizationID, customerPrincipalID string, actions, denied, approvals, toolCalls int) error {
	tag, err := p.tx.ExecContext(ctx, `
		UPDATE external_budget_policies
		SET actions_count = actions_count + $6, denied_count = denied_count + $7,
		    approval_required_count = approval_required_count + $8, tool_calls_count = tool_calls_count + $9,
		    updated_at = now()
		WHERE tenant_id = $1 AND scope_type = $2 AND COALESCE(external_agent_id, '') = $3
		  AND COALESCE(organization_id, '') = $4 AND COALESCE(customer_principal_id, '') = $5
	`, tenantID, scopeType, externalAgentID, organizationID, customerPrincipalID, actions, denied, approvals, toolCalls)
	if err != nil {
		return err
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("%w: no external budget for scope %q", runtime.ErrDelegationNotAllowed, scopeType)
	}
	return nil
}
