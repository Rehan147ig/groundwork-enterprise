// Phase 6 service layer: trust relationships, agent-to-agent
// delegation chains, external-agent onboarding + authentication, consent
// records, cross-region transfer policies, external-agent budgets, and
// evidence provenance.
//
// Central rule: a child agent may never receive more authority than its
// parent agent possesses. Every child delegation requires an explicit,
// active trust relationship; cross-region delegation requires an
// explicit enabled transfer policy; external agents are untrusted by
// default and every run requires a validated identity + active trust
// relationship + customer consent.

package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"groundwork/query-runtime/internal/runtime"

	"github.com/golang-jwt/jwt/v5"
)

// delegationMaxDepth returns the configured chain depth cap, clamped to
// [1,10] (default runtime.DefaultDelegationMaxDepth).
func delegationMaxDepth() int {
	raw := envOr("GROUNDWORK_DELEGATION_MAX_DEPTH", "")
	if raw == "" {
		return runtime.DefaultDelegationMaxDepth
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return runtime.DefaultDelegationMaxDepth
	}
	if n < 1 {
		return 1
	}
	if n > 10 {
		return 10
	}
	return n
}

// externalDemoEnabled allows self-issued demo external identities
// (internal_demo auth method). Always off by default.
func externalDemoEnabled() bool {
	return envOr("GROUNDWORK_EXTERNAL_INTERNAL_DEMO", "") == "true"
}

// appendTrustEvent records one hash-chained trust event and enqueues
// its safe outbox counterpart (same transaction).
func (s *Service) appendTrustEvent(ctx context.Context, tx TxStore, tenantID string, e runtime.TrustEvent) (runtime.TrustEvent, error) {
	if e.ID == "" {
		e.ID = newID()
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = s.now().UTC().Truncate(time.Microsecond)
	}
	created, err := tx.AppendTrustEvent(ctx, e)
	if err != nil {
		return runtime.TrustEvent{}, err
	}
	s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventTrustLifecycle, created.ID, created.OccurredAt, map[string]string{
		"trust_event_id":     created.ID,
		"tenant_id":          tenantID,
		"event_type":         created.EventType,
		"entity_type":        created.EntityType,
		"entity_id":          created.EntityID,
		"actor_principal_id": created.ActorPrincipalID,
		"previous_state":     created.PreviousState,
		"new_state":          created.NewState,
		"reason":             created.Reason,
		"immutable_digest":   created.ImmutableDigest,
	})
	return created, nil
}

// verifyChainStatus verifies every ancestor link of an agent-delegated
// grant in the same tx (digest continuity + scope attenuation). Root
// grants are always "unchecked" (nothing to verify). Broken chains are
// stamped so every decision of the run is visibly untrusted.
func (s *Service) verifyChainStatus(ctx context.Context, tx TxStore, tenantID string, grant runtime.DelegationGrant) string {
	if !grant.IsAgentDelegation || grant.ParentGrantID == "" {
		return "unchecked"
	}
	_, chain, err := s.buildChainTx(ctx, tx, tenantID, grant)
	if err != nil {
		return "broken"
	}
	if chain.Verified {
		return "verified"
	}
	return "broken"
}

// buildChainTx walks the parent links from the leaf grant up to the
// root, then verifies every link root-first. Both the ordered grant
// list (root first) and the chain view are returned.
func (s *Service) buildChainTx(ctx context.Context, tx TxStore, tenantID string, leaf runtime.DelegationGrant) ([]runtime.DelegationGrant, runtime.DelegationChain, error) {
	var grants []runtime.DelegationGrant
	current := leaf
	for {
		grants = append(grants, current)
		if current.ParentGrantID == "" {
			break
		}
		parent, err := tx.GetDelegationGrantByID(ctx, tenantID, current.ParentGrantID)
		if err != nil {
			return nil, runtime.DelegationChain{}, fmt.Errorf("%w: %v", runtime.ErrChainBroken, err)
		}
		current = parent
	}
	// Reverse to root-first.
	for i, j := 0, len(grants)-1; i < j; i, j = i+1, j-1 {
		grants[i], grants[j] = grants[j], grants[i]
	}

	chain := runtime.DelegationChain{
		RootGrantID: grants[0].ID,
		LeafGrantID: leaf.ID,
		Depth:       leaf.DelegationDepth,
	}
	verified := true
	for i, g := range grants {
		node := runtime.DelegationChainNode{
			Grant:            g,
			DelegatorAgentID: g.DelegatorAgentID,
			DelegateeAgentID: g.DelegateeAgentID,
			Verified:         true,
		}
		if i > 0 {
			parent := grants[i-1]
			if err := VerifyGrantChainLink(parent, g); err != nil {
				verified = false
				node.Verified = false
				node.Problem = err.Error()
				if chain.Problem == "" {
					chain.Problem = err.Error()
				}
			}
		}
		chain.Nodes = append(chain.Nodes, node)
	}
	if !leaf.RevokedAt.IsZero() {
		verified = false
		chain.Problem = "delegation revoked"
	}
	chain.Verified = verified
	return grants, chain, nil
}

// ---------------------------------------------------------------------
// Trust relationships
// ---------------------------------------------------------------------

func (s *Service) CreateTrustRelationship(ctx context.Context, tenantID, actor string, admin bool, req runtime.TrustRelationshipRequest) (runtime.AgentTrustRelationship, error) {
	if actor == "" {
		return runtime.AgentTrustRelationship{}, runtime.ErrInvalidRequest
	}
	if s.agents == nil {
		return runtime.AgentTrustRelationship{}, runtime.ErrGovernanceUnavailable
	}
	if (req.ChildAgentID == "") == (req.ExternalAgentID == "") {
		return runtime.AgentTrustRelationship{}, fmt.Errorf("%w: exactly one of child_agent_id or external_agent_id required", runtime.ErrInvalidRequest)
	}
	domain := strings.TrimSpace(req.TrustDomain)
	purpose := strings.TrimSpace(req.Purpose)
	region := strings.TrimSpace(req.Region)
	if domain == "" || purpose == "" || region == "" {
		return runtime.AgentTrustRelationship{}, fmt.Errorf("%w: trust_domain, purpose, region required", runtime.ErrInvalidRequest)
	}
	maxDepth := req.MaxDelegationDepth
	if maxDepth == 0 {
		maxDepth = runtime.DefaultDelegationMaxDepth
	}
	if maxDepth < 1 || maxDepth > 10 {
		return runtime.AgentTrustRelationship{}, fmt.Errorf("%w: max_delegation_depth must be in [1,10]", runtime.ErrInvalidRequest)
	}
	expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		return runtime.AgentTrustRelationship{}, fmt.Errorf("%w: expires_at must be RFC3339", runtime.ErrInvalidRequest)
	}
	if !s.now().UTC().Before(expiresAt) {
		return runtime.AgentTrustRelationship{}, fmt.Errorf("%w: expires_at must be in the future", runtime.ErrInvalidRequest)
	}
	parentAgentID := strings.TrimSpace(req.ParentAgentID)
	if parentAgentID == "" {
		return runtime.AgentTrustRelationship{}, fmt.Errorf("%w: parent_agent_id (source-of-authority agent) required", runtime.ErrInvalidRequest)
	}
	// Parent agent must exist and be active; the relationship owner is
	// the parent agent's owner principal (owner-or-admin).
	parentAgent, _, _, err := s.agents.GetAgent(ctx, tenantID, parentAgentID)
	if err != nil {
		return runtime.AgentTrustRelationship{}, err
	}
	if parentAgent.LifecycleState != runtime.AgentStateActive {
		return runtime.AgentTrustRelationship{}, runtime.ErrDelegationInactive
	}
	if actor != parentAgent.OwnerPrincipalID && !admin {
		return runtime.AgentTrustRelationship{}, runtime.ErrGovernanceNotAuthorized
	}
	owner := parentAgent.OwnerPrincipalID
	if req.ExternalAgentID == "" {
		if req.ChildAgentID == parentAgent.ID {
			return runtime.AgentTrustRelationship{}, runtime.ErrTrustConflict
		}
		childAgent, _, _, err := s.agents.GetAgent(ctx, tenantID, req.ChildAgentID)
		if err != nil {
			return runtime.AgentTrustRelationship{}, err
		}
		if childAgent.LifecycleState != runtime.AgentStateActive {
			return runtime.AgentTrustRelationship{}, runtime.ErrDelegationInactive
		}
	}
	allowed := normalizePermittedActions(req.AllowedToolsActions)
	if len(allowed) > 0 {
		if _, err := s.resolvePermittedActions(ctx, tenantID, allowed); err != nil {
			return runtime.AgentTrustRelationship{}, err
		}
	}
	status := runtime.TrustStateApproved
	if req.ApprovalRequired {
		status = runtime.TrustStateRequested
	}

	var relationship runtime.AgentTrustRelationship
	err = s.store.Transact(ctx, "trust:"+tenantID, func(tx TxStore) error {
		relationship = runtime.AgentTrustRelationship{
			TenantID:            tenantID,
			ParentAgentID:       parentAgent.ID,
			ChildAgentID:        strings.TrimSpace(req.ChildAgentID),
			ExternalAgentID:     strings.TrimSpace(req.ExternalAgentID),
			TrustDomain:         domain,
			OwnerPrincipalID:    owner,
			Purpose:             purpose,
			MaxDelegationDepth:  maxDepth,
			AllowedToolsActions: allowed,
			Region:              region,
			ExpiresAt:           expiresAt,
			Status:              status,
			ApprovalRequired:    req.ApprovalRequired,
		}
		created, err := tx.CreateTrustRelationship(ctx, relationship)
		if err != nil {
			return err
		}
		relationship = created
		eventType := runtime.TrustEventRequested
		if status == runtime.TrustStateApproved {
			eventType = runtime.TrustEventApproved
		}
		_, err = s.appendTrustEvent(ctx, tx, tenantID, runtime.TrustEvent{
			TenantID:         tenantID,
			EventType:        eventType,
			EntityType:       "relationship",
			EntityID:         created.ID,
			ActorPrincipalID: actor,
			PreviousState:    "",
			NewState:         status,
			TrustDomain:      domain,
		})
		return err
	})
	if err != nil {
		return runtime.AgentTrustRelationship{}, err
	}
	return relationship, nil
}

func (s *Service) ListTrustRelationships(ctx context.Context, tenantID string) ([]runtime.AgentTrustRelationship, error) {
	return s.store.ListTrustRelationships(ctx, tenantID)
}

func (s *Service) GetTrustRelationship(ctx context.Context, tenantID, relationshipID string) (runtime.AgentTrustRelationship, error) {
	relationship, err := s.store.GetTrustRelationship(ctx, tenantID, relationshipID)
	if err != nil {
		return runtime.AgentTrustRelationship{}, err
	}
	if !relationship.ExpiresAt.IsZero() && !s.now().UTC().Before(relationship.ExpiresAt) &&
		relationship.Status != runtime.TrustStateRevoked {
		relationship.Status = runtime.TrustStateExpired
	}
	return relationship, nil
}

func (s *Service) TransitionTrustRelationship(ctx context.Context, tenantID, relationshipID, actor string, admin bool, action string, req runtime.TrustTransitionRequest) (runtime.AgentTrustRelationship, error) {
	if actor == "" {
		return runtime.AgentTrustRelationship{}, runtime.ErrInvalidRequest
	}
	reason := strings.TrimSpace(req.Reason)
	var relationship runtime.AgentTrustRelationship
	err := s.store.Transact(ctx, "trust:"+tenantID, func(tx TxStore) error {
		current, err := tx.GetTrustRelationship(ctx, tenantID, relationshipID)
		if err != nil {
			return err
		}
		if current.OwnerPrincipalID != actor && !admin {
			return runtime.ErrGovernanceNotAuthorized
		}
		next := ""
		eventType := ""
		switch action {
		case "approve":
			if current.Status != runtime.TrustStateRequested {
				return runtime.ErrTrustInvalidState
			}
			next, eventType = runtime.TrustStateApproved, runtime.TrustEventApproved
		case "activate":
			if current.Status != runtime.TrustStateApproved {
				return runtime.ErrTrustInvalidState
			}
			next, eventType = runtime.TrustStateActive, runtime.TrustEventActivated
		case "suspend":
			if current.Status != runtime.TrustStateActive {
				return runtime.ErrTrustInvalidState
			}
			next, eventType = runtime.TrustStateSuspended, runtime.TrustEventSuspended
		case "resume":
			if current.Status != runtime.TrustStateSuspended {
				return runtime.ErrTrustInvalidState
			}
			next, eventType = runtime.TrustStateActive, runtime.TrustEventResumed
		case "revoke":
			if current.Status == runtime.TrustStateRevoked {
				return runtime.ErrTrustInvalidState
			}
			next, eventType = runtime.TrustStateRevoked, runtime.TrustEventRevoked
		default:
			return fmt.Errorf("%w: unknown action %q", runtime.ErrInvalidRequest, action)
		}
		if !s.now().UTC().Before(current.ExpiresAt) && next != runtime.TrustStateRevoked {
			return runtime.ErrTrustExpired
		}
		if err := tx.UpdateTrustRelationshipStatus(ctx, tenantID, relationshipID, current.Status, next, reason); err != nil {
			return err
		}
		updated, err := tx.GetTrustRelationship(ctx, tenantID, relationshipID)
		if err != nil {
			return err
		}
		relationship = updated
		_, err = s.appendTrustEvent(ctx, tx, tenantID, runtime.TrustEvent{
			TenantID:         tenantID,
			EventType:        eventType,
			EntityType:       "relationship",
			EntityID:         relationshipID,
			ActorPrincipalID: actor,
			PreviousState:    current.Status,
			NewState:         next,
			Reason:           reason,
			TrustDomain:      current.TrustDomain,
		})
		return err
	})
	if err != nil {
		return runtime.AgentTrustRelationship{}, err
	}
	return relationship, nil
}

func (s *Service) ListTrustEvents(ctx context.Context, tenantID string, limit int) ([]runtime.TrustEvent, error) {
	return s.store.ListTrustEvents(ctx, tenantID, limit)
}

// ---------------------------------------------------------------------
// Agent-to-agent delegation
// ---------------------------------------------------------------------

func (s *Service) DelegateToChildAgent(ctx context.Context, tenantID, region, parentAgentID string, actor string, admin bool, idempotencyKey string, req runtime.ChildDelegationRequest) (runtime.MintDelegationResponse, error) {
	if s.agents == nil {
		return runtime.MintDelegationResponse{}, runtime.ErrGovernanceUnavailable
	}
	childAgentID := strings.TrimSpace(req.ChildAgentID)
	if childAgentID == "" || req.ParentGrantID == "" || req.TrustRelationshipID == "" {
		return runtime.MintDelegationResponse{}, fmt.Errorf("%w: parent_grant_id, child_agent_id, trust_relationship_id required", runtime.ErrInvalidRequest)
	}
	purpose := strings.TrimSpace(req.Purpose)
	if purpose == "" {
		return runtime.MintDelegationResponse{}, fmt.Errorf("%w: purpose required", runtime.ErrInvalidRequest)
	}
	permitted := normalizePermittedActions(req.PermittedActions)
	if len(permitted) == 0 {
		return runtime.MintDelegationResponse{}, fmt.Errorf("%w: permitted_actions required", runtime.ErrInvalidRequest)
	}
	if _, err := s.resolvePermittedActions(ctx, tenantID, permitted); err != nil {
		return runtime.MintDelegationResponse{}, err
	}
	childAgent, _, _, err := s.agents.GetAgent(ctx, tenantID, childAgentID)
	if err != nil {
		return runtime.MintDelegationResponse{}, err
	}
	if childAgent.LifecycleState != runtime.AgentStateActive || childAgent.ActiveVersionID == "" {
		return runtime.MintDelegationResponse{}, runtime.ErrDelegationInactive
	}

	if idempotencyKey != "" {
		if existing, err := s.store.GetDelegationGrantByIdempotencyKey(ctx, tenantID, idempotencyKey); err == nil {
			return runtime.MintDelegationResponse{Grant: existing, TokenAlreadyIssued: true}, nil
		}
	}

	jti := newID()
	issuedAt := s.now().UTC().Truncate(time.Microsecond)
	var grant runtime.DelegationGrant
	var token string
	var relationship runtime.AgentTrustRelationship

	err = s.store.Transact(ctx, "agent:"+parentAgentID, func(tx TxStore) error {
		// Parent grant must be live; the acting agent must hold it.
		parent, err := tx.GetDelegationGrantByID(ctx, tenantID, req.ParentGrantID)
		if err != nil {
			return err
		}
		if parent.AgentID != parentAgentID {
			return runtime.ErrDelegationInvalid
		}
		if !parent.RevokedAt.IsZero() {
			return runtime.ErrParentRevoked
		}
		if !s.now().UTC().Before(parent.ExpiresAt) {
			return runtime.ErrDelegationExpired
		}
		// Owner-or-admin of the parent agent.
		if actor != parent.DelegatorPrincipalID {
			ownerAgent, _, _, getErr := s.agents.GetAgent(ctx, tenantID, parent.AgentID)
			if getErr != nil || (actor != ownerAgent.OwnerPrincipalID && !admin) {
				return runtime.ErrGovernanceNotAuthorized
			}
		}
		if err := s.assertControlUsable(ctx, tx, tenantID, runtime.ControlEntityDelegation, parent.ID); err != nil {
			return err
		}

		// The explicit, active trust relationship between the parent
		// agent and the child agent is the ONLY basis for delegation.
		relationship, err = tx.GetTrustRelationship(ctx, tenantID, req.TrustRelationshipID)
		if err != nil {
			return err
		}
		if relationship.ParentAgentID != parent.AgentID || relationship.ChildAgentID != childAgentID {
			return runtime.ErrTrustNotActive
		}
		if relationship.Status != runtime.TrustStateActive {
			return runtime.ErrTrustNotActive
		}
		if !s.now().UTC().Before(relationship.ExpiresAt) {
			return runtime.ErrTrustExpired
		}
		// Cross-region delegation is denied unless an explicit, enabled
		// transfer policy allows it (source = parent grant region).
		if relationship.Region != parent.Region {
			if _, err := tx.GetTransferPolicy(ctx, tenantID, parent.Region, relationship.Region, purpose); err != nil {
				return runtime.ErrCrossRegionDenied
			}
		}
		if region != relationship.Region {
			return runtime.ErrDelegationRegion
		}

		// Depth: bounded by the chain cap and the relationship cap.
		nextDepth := parent.DelegationDepth + 1
		if nextDepth > delegationMaxDepth() {
			return runtime.ErrChainTooDeep
		}
		if relationship.MaxDelegationDepth > 0 && nextDepth > relationship.MaxDelegationDepth {
			return runtime.ErrChainTooDeep
		}

		// Attenuation: the child's scope must be a subset of the
		// parent's stored scope and of the relationship scope; the
		// child expiry must not exceed the parent's.
		if !actionsSubset(permitted, parent.PermittedActions) {
			return runtime.ErrScopeExceedsParent
		}
		if len(relationship.AllowedToolsActions) > 0 && !actionsSubset(permitted, relationship.AllowedToolsActions) {
			return runtime.ErrScopeExceedsParent
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = runtime.DefaultDelegationTTL
		}
		if ttl > runtime.MaxDelegationTTL {
			ttl = runtime.MaxDelegationTTL
		}
		expiresAt := issuedAt.Add(ttl).Truncate(time.Microsecond)
		if expiresAt.After(parent.ExpiresAt) {
			expiresAt = parent.ExpiresAt
		}
		if expiresAt.After(relationship.ExpiresAt) {
			expiresAt = relationship.ExpiresAt
		}

		permittedDigest := ComputePermittedActionsDigest(permitted)
		rootGrantID := parent.RootGrantID
		if rootGrantID == "" {
			rootGrantID = parent.ID
		}
		authorityScopeDigest := ComputeAuthorityScopeDigest(permittedDigest, region, purpose)
		parentScopeDigest := parent.AuthorityScopeDigest
		attenuationDigest := ComputeAttenuationDigest(
			parentScopeDigest, authorityScopeDigest,
			parent.ExpiresAt.UTC().Format(time.RFC3339Nano),
			expiresAt.UTC().Format(time.RFC3339Nano),
		)
		grant = runtime.DelegationGrant{
			ID:                     newID(),
			TenantID:               tenantID,
			AgentID:                childAgentID,
			AgentVersionID:         childAgent.ActiveVersionID,
			TokenJTI:               jti,
			DelegatorPrincipalID:   parent.DelegatorPrincipalID,
			SubjectPrincipalID:     req.SubjectPrincipalID,
			Purpose:                purpose,
			Region:                 region,
			PermittedActions:       permitted,
			PermittedActionsDigest: permittedDigest,
			IssuedAt:               issuedAt,
			ExpiresAt:              expiresAt,
			IdempotencyKey:         idempotencyKey,
			IsAgentDelegation:      true,
			ParentGrantID:          parent.ID,
			RootGrantID:            rootGrantID,
			DelegatorAgentID:       parent.AgentID,
			DelegateeAgentID:       childAgentID,
			DelegationDepth:        nextDepth,
			AuthorityScopeDigest:   authorityScopeDigest,
			ParentScopeDigest:      parentScopeDigest,
			AttenuationDigest:      attenuationDigest,
			TrustRelationshipID:    relationship.ID,
			IssuedVia:              "agent",
		}
		if req.SubjectPrincipalID == "" {
			grant.SubjectPrincipalID = parent.SubjectPrincipalID
		}
		grant.ImmutableDigest = ComputeGrantDigest(grant)
		if err := tx.CreateDelegationGrant(ctx, grant); err != nil {
			return err
		}
		_, err = s.appendTrustEvent(ctx, tx, tenantID, runtime.TrustEvent{
			TenantID:           tenantID,
			EventType:          runtime.TrustEventChildMinted,
			EntityType:         "grant",
			EntityID:           grant.ID,
			ActorPrincipalID:   actor,
			GrantID:            grant.ID,
			ParentGrantID:      parent.ID,
			RootGrantID:        rootGrantID,
			DelegationDepth:    nextDepth,
			SubjectPrincipalID: grant.SubjectPrincipalID,
			TrustDomain:        relationship.TrustDomain,
			ScopeDigest:        authorityScopeDigest,
			AttenuationDigest:  attenuationDigest,
		})
		return err
	})
	if err != nil {
		return runtime.MintDelegationResponse{}, err
	}

	// Mint AFTER the grant is persisted (same as root minting).
	chain := Claims{
		ParentGrantID:        grant.ParentGrantID,
		RootGrantID:          grant.RootGrantID,
		DelegatorAgentID:     grant.DelegatorAgentID,
		DelegateeAgentID:     grant.DelegateeAgentID,
		DelegationDepth:      grant.DelegationDepth,
		AuthorityScopeDigest: grant.AuthorityScopeDigest,
		ParentScopeDigest:    grant.ParentScopeDigest,
		AttenuationDigest:    grant.AttenuationDigest,
	}
	token, err = s.authority.MintChild(tenantID, grant.AgentID, grant.AgentVersionID,
		grant.DelegatorPrincipalID, grant.SubjectPrincipalID, grant.Purpose, grant.Region,
		grant.PermittedActions, grant.PermittedActionsDigest, jti, grant.IssuedAt, grant.ExpiresAt, chain)
	if err != nil {
		return runtime.MintDelegationResponse{}, fmt.Errorf("%w: %v", runtime.ErrDelegationInvalid, err)
	}
	return runtime.MintDelegationResponse{Grant: grant, Token: token}, nil
}

// actionsSubset reports whether every entry of want is present in have.
func actionsSubset(want, have []string) bool {
	set := map[string]bool{}
	for _, entry := range have {
		set[entry] = true
	}
	for _, entry := range want {
		if !set[entry] {
			return false
		}
	}
	return true
}

func (s *Service) ListChildDelegations(ctx context.Context, tenantID, parentAgentID string) ([]runtime.DelegationGrant, error) {
	grants, err := s.store.ListDelegationGrants(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var out []runtime.DelegationGrant
	for _, g := range grants {
		if g.IsAgentDelegation && g.DelegatorAgentID == parentAgentID {
			out = append(out, g)
		}
	}
	return out, nil
}

func (s *Service) GetDelegationChain(ctx context.Context, tenantID, grantID string) (runtime.DelegationChain, error) {
	var chain runtime.DelegationChain
	err := s.store.Transact(ctx, "agent:"+grantID, func(tx TxStore) error {
		grant, err := tx.GetDelegationGrantByID(ctx, tenantID, grantID)
		if err != nil {
			return err
		}
		_, chain, err = s.buildChainTx(ctx, tx, tenantID, grant)
		return err
	})
	if err != nil {
		return runtime.DelegationChain{}, err
	}
	return chain, nil
}

func (s *Service) GetRunDelegationChain(ctx context.Context, tenantID, runID string) (runtime.DelegationChain, error) {
	run, err := s.store.GetRun(ctx, tenantID, runID)
	if err != nil {
		return runtime.DelegationChain{}, err
	}
	return s.GetDelegationChain(ctx, tenantID, run.DelegationGrantID)
}

// chainScopeAction applies revoke/suspend/resume to the grant and every
// descendant grant in one transaction. Revoke is irreversible; suspend
// terminates descendant runs and blocks new ones until resume.
func (s *Service) chainScopeAction(ctx context.Context, tenantID, grantID, actor string, admin bool, actionType, targetState, reason string, eventType string) (int, error) {
	if !admin {
		return 0, runtime.ErrGovernanceNotAuthorized
	}
	if actor == "" {
		return 0, runtime.ErrInvalidRequest
	}
	if strings.TrimSpace(reason) == "" {
		return 0, fmt.Errorf("%w: reason required", runtime.ErrInvalidRequest)
	}
	changed := 0
	err := s.store.Transact(ctx, "control:"+tenantID, func(tx TxStore) error {
		if _, err := tx.GetDelegationGrantByID(ctx, tenantID, grantID); err != nil {
			return err
		}
		descendants, err := tx.ListDescendantGrantIDs(ctx, tenantID, grantID)
		if err != nil {
			return err
		}
		ids := append([]string{grantID}, descendants...)
		for _, id := range ids {
			control := runtime.EmergencyControl{
				TenantID:         tenantID,
				EntityType:       runtime.ControlEntityDelegation,
				EntityID:         id,
				ControlState:     targetState,
				Reason:           reason,
				ActorPrincipalID: actor,
			}
			if _, err := tx.SetEmergencyControl(ctx, control); err != nil && !errors.Is(err, runtime.ErrControlNotFound) {
				return err
			}
			if actionType == runtime.ControlActionRevoke {
				if err := tx.RevokeDelegationGrantByID(ctx, tenantID, id); err != nil && !errors.Is(err, runtime.ErrGrantRevoked) {
					return err
				}
			}
			// Terminate any active run bound to this grant.
			runs, err := tx.ListRuns(ctx, tenantID)
			if err != nil {
				return err
			}
			for _, run := range runs {
				if run.DelegationGrantID == id && run.Status == runtime.RunStatusRunning {
					completed := s.now().UTC().Truncate(time.Microsecond)
					if err := tx.UpdateRunStatus(ctx, tenantID, run.ID, runtime.RunStatusRunning, runtime.RunStatusRevoked, &completed, "chain_revoked"); err != nil {
						return err
					}
					s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventRunEnded, run.ID+":chain", completed, map[string]string{
						"run_id": run.ID, "tenant_id": tenantID, "status": runtime.RunStatusRevoked, "error_code": "chain_revoked",
					})
				}
			}
			if _, err := s.appendTrustEvent(ctx, tx, tenantID, runtime.TrustEvent{
				TenantID:         tenantID,
				EventType:        eventType,
				EntityType:       "grant",
				EntityID:         id,
				ActorPrincipalID: actor,
				PreviousState:    "",
				NewState:         targetState,
				Reason:           reason,
				GrantID:          id,
				RootGrantID:      grantID,
				RevocationSource: grantID,
			}); err != nil {
				return err
			}
			changed++
		}
		s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventChainRevoked, grantID+":chain", s.now().UTC().Truncate(time.Microsecond), map[string]string{
			"tenant_id": tenantID, "root_grant_id": grantID, "action_type": actionType, "grants_changed": strconv.Itoa(changed),
		})
		return nil
	})
	return changed, err
}

func (s *Service) RevokeDelegationChain(ctx context.Context, tenantID, grantID, actor string, admin bool, req runtime.ControlRequest) (int, error) {
	return s.chainScopeAction(ctx, tenantID, grantID, actor, admin, runtime.ControlActionRevoke, runtime.ControlStateRevoked, strings.TrimSpace(req.Reason), runtime.TrustEventChainRevoked)
}

func (s *Service) SuspendDelegationChain(ctx context.Context, tenantID, grantID, actor string, admin bool, req runtime.ControlRequest) (int, error) {
	return s.chainScopeAction(ctx, tenantID, grantID, actor, admin, runtime.ControlActionSuspend, runtime.ControlStateSuspended, strings.TrimSpace(req.Reason), runtime.TrustEventChainPaused)
}

func (s *Service) ResumeDelegationChain(ctx context.Context, tenantID, grantID, actor string, admin bool, req runtime.ControlRequest) (int, error) {
	return s.chainScopeAction(ctx, tenantID, grantID, actor, admin, runtime.ControlActionResume, runtime.ControlStateActive, strings.TrimSpace(req.Reason), runtime.TrustEventChainResumed)
}

// ---------------------------------------------------------------------
// External agents
// ---------------------------------------------------------------------

func (s *Service) OnboardExternalAgent(ctx context.Context, tenantID, actor string, admin bool, req runtime.ExternalAgentRequest) (runtime.ExternalAgent, error) {
	if !admin {
		return runtime.ExternalAgent{}, runtime.ErrGovernanceNotAuthorized
	}
	if actor == "" {
		return runtime.ExternalAgent{}, runtime.ErrInvalidRequest
	}
	if strings.TrimSpace(req.ExternalAgentID) == "" || strings.TrimSpace(req.OrganizationID) == "" {
		return runtime.ExternalAgent{}, fmt.Errorf("%w: external_agent_id and organization_id required", runtime.ErrInvalidRequest)
	}
	issuer := strings.TrimSpace(req.VerifiedIssuer)
	if issuer == "" {
		return runtime.ExternalAgent{}, fmt.Errorf("%w: verified_issuer required", runtime.ErrInvalidRequest)
	}
	if len(req.AllowedAudiences) == 0 {
		return runtime.ExternalAgent{}, fmt.Errorf("%w: allowed_audiences required", runtime.ErrInvalidRequest)
	}
	switch req.AuthMethod {
	case runtime.ExternalAuthOIDC, runtime.ExternalAuthJWKS, runtime.ExternalAuthMTLS, runtime.ExternalAuthInternalDemo:
	default:
		return runtime.ExternalAgent{}, fmt.Errorf("%w: invalid auth_method", runtime.ErrInvalidRequest)
	}
	if req.AuthMethod == runtime.ExternalAuthInternalDemo && !externalDemoEnabled() {
		return runtime.ExternalAgent{}, runtime.ErrExternalDemoDenied
	}
	switch req.TrustTier {
	case "", runtime.TrustTierVerified, runtime.TrustTierPartner, runtime.TrustTierCustomer:
	default:
		return runtime.ExternalAgent{}, fmt.Errorf("%w: invalid trust_tier", runtime.ErrInvalidRequest)
	}
	if req.TrustTier == "" {
		req.TrustTier = runtime.TrustTierVerified
	}
	if strings.TrimSpace(req.Region) == "" {
		return runtime.ExternalAgent{}, fmt.Errorf("%w: region required", runtime.ErrInvalidRequest)
	}
	// The paired agent identity must be a registered, active agent; the
	// external agent acts under exactly that identity in evaluations.
	agentID := strings.TrimSpace(req.AgentID)
	if agentID == "" {
		return runtime.ExternalAgent{}, fmt.Errorf("%w: agent_id (paired registry identity) required", runtime.ErrInvalidRequest)
	}
	if s.agents == nil {
		return runtime.ExternalAgent{}, runtime.ErrGovernanceUnavailable
	}
	paired, _, _, err := s.agents.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return runtime.ExternalAgent{}, err
	}
	if paired.LifecycleState != runtime.AgentStateActive {
		return runtime.ExternalAgent{}, runtime.ErrDelegationInactive
	}
	ttl := runtime.DefaultDelegationTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if ttl > runtime.MaxDelegationTTL {
		ttl = runtime.MaxDelegationTTL
	}
	expiresAt := s.now().UTC().Add(ttl).Truncate(time.Microsecond)

	var external runtime.ExternalAgent
	err = s.store.Transact(ctx, "external:"+tenantID, func(tx TxStore) error {
		external = runtime.ExternalAgent{
			ExternalAgentID:     strings.TrimSpace(req.ExternalAgentID),
			AgentID:             agentID,
			OrganizationID:      strings.TrimSpace(req.OrganizationID),
			TenantID:            tenantID,
			OwnerPrincipalID:    actor,
			VerifiedIssuer:      issuer,
			AllowedAudiences:    req.AllowedAudiences,
			AuthMethod:          req.AuthMethod,
			TrustTier:           req.TrustTier,
			Region:              strings.TrimSpace(req.Region),
			AllowedToolsActions: normalizePermittedActions(req.AllowedToolsActions),
			PublicKeyJWKSRef:    strings.TrimSpace(req.PublicKeyJWKSRef),
			ManifestDigest:      strings.TrimSpace(req.ManifestDigest),
			SecurityContact:     strings.TrimSpace(req.SecurityContact),
			LifecycleState:      runtime.ExternalStateActive,
			ExpiresAt:           expiresAt,
		}
		created, err := tx.CreateExternalAgent(ctx, external)
		if err != nil {
			return err
		}
		external = created
		_, err = s.appendTrustEvent(ctx, tx, tenantID, runtime.TrustEvent{
			TenantID:         tenantID,
			EventType:        runtime.TrustEventExternal,
			EntityType:       "external_agent",
			EntityID:         external.ExternalAgentID,
			ActorPrincipalID: actor,
			NewState:         runtime.ExternalStateActive,
			OrganizationID:   external.OrganizationID,
			TrustDomain:      "external",
		})
		s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventExternalAgent, external.ID, external.CreatedAt, map[string]string{
			"external_agent_id": external.ExternalAgentID,
			"tenant_id":         tenantID,
			"agent_id":          external.AgentID,
			"organization_id":   external.OrganizationID,
			"auth_method":       external.AuthMethod,
			"trust_tier":        external.TrustTier,
			"region":            external.Region,
			"manifest_digest":   external.ManifestDigest,
		})
		return nil
	})
	if err != nil {
		return runtime.ExternalAgent{}, err
	}
	return external, nil
}

func (s *Service) ListExternalAgents(ctx context.Context, tenantID string) ([]runtime.ExternalAgent, error) {
	return s.store.ListExternalAgents(ctx, tenantID)
}

func (s *Service) GetExternalAgent(ctx context.Context, tenantID, externalAgentID string) (runtime.ExternalAgent, error) {
	external, err := s.store.GetExternalAgent(ctx, tenantID, externalAgentID)
	if err != nil {
		return runtime.ExternalAgent{}, err
	}
	if !external.ExpiresAt.IsZero() && !s.now().UTC().Before(external.ExpiresAt) &&
		external.LifecycleState != runtime.ExternalStateRevoked {
		external.LifecycleState = runtime.ExternalStateExpired
	}
	return external, nil
}

func (s *Service) TransitionExternalAgent(ctx context.Context, tenantID, externalAgentID, actor string, admin bool, action string, req runtime.TrustTransitionRequest) (runtime.ExternalAgent, error) {
	if !admin {
		return runtime.ExternalAgent{}, runtime.ErrGovernanceNotAuthorized
	}
	reason := strings.TrimSpace(req.Reason)
	var external runtime.ExternalAgent
	err := s.store.Transact(ctx, "external:"+tenantID, func(tx TxStore) error {
		current, err := tx.GetExternalAgent(ctx, tenantID, externalAgentID)
		if err != nil {
			return err
		}
		next := ""
		eventType := ""
		switch action {
		case "activate":
			if current.LifecycleState != runtime.ExternalStatePending && current.LifecycleState != runtime.ExternalStateSuspended {
				return runtime.ErrExternalInvalid
			}
			next, eventType = runtime.ExternalStateActive, runtime.TrustEventExternal
		case "suspend":
			if current.LifecycleState != runtime.ExternalStateActive {
				return runtime.ErrExternalInvalid
			}
			next, eventType = runtime.ExternalStateSuspended, runtime.TrustEventSuspended
		case "revoke":
			if current.LifecycleState == runtime.ExternalStateRevoked {
				return runtime.ErrExternalInvalid
			}
			next, eventType = runtime.ExternalStateRevoked, runtime.TrustEventRevoked
		default:
			return fmt.Errorf("%w: unknown action %q", runtime.ErrInvalidRequest, action)
		}
		if err := tx.UpdateExternalAgentState(ctx, tenantID, externalAgentID, current.LifecycleState, next); err != nil {
			return err
		}
		external = current
		external.LifecycleState = next
		_, err = s.appendTrustEvent(ctx, tx, tenantID, runtime.TrustEvent{
			TenantID:         tenantID,
			EventType:        eventType,
			EntityType:       "external_agent",
			EntityID:         externalAgentID,
			ActorPrincipalID: actor,
			PreviousState:    current.LifecycleState,
			NewState:         next,
			Reason:           reason,
			OrganizationID:   current.OrganizationID,
			TrustDomain:      "external",
		})
		s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventExternalAgent, external.ID, s.now().UTC().Truncate(time.Microsecond), map[string]string{
			"external_agent_id": external.ExternalAgentID,
			"tenant_id":         tenantID,
			"previous_state":    current.LifecycleState,
			"new_state":         next,
			"reason":            reason,
		})
		return nil
	})
	if err != nil {
		return runtime.ExternalAgent{}, err
	}
	return external, nil
}

// externalClaims is the validated external identity token payload. The
// customer principal (cid) and purpose (pur) claims are bound into the
// token by the issuer; they gate consent and run attribution and are
// never accepted from request bodies.
type externalClaims struct {
	jwt.RegisteredClaims
	CustomerPrincipalID string `json:"cid,omitempty"`
	Purpose             string `json:"pur,omitempty"`
}

// verifyExternalToken validates an external identity token against the
// onboarding record. internal_demo uses the gateway's own signing key;
// other methods fail closed (this build does not fetch remote JWKS).
func (s *Service) verifyExternalToken(ctx context.Context, tenantID string, external runtime.ExternalAgent, raw string) (externalClaims, error) {
	var claims externalClaims
	if external.LifecycleState != runtime.ExternalStateActive {
		return claims, runtime.ErrExternalNotActive
	}
	if !s.now().UTC().Before(external.ExpiresAt) {
		return claims, runtime.ErrExternalExpired
	}
	switch external.AuthMethod {
	case runtime.ExternalAuthInternalDemo:
		if !externalDemoEnabled() {
			return claims, runtime.ErrExternalDemoDenied
		}
		token, err := jwt.ParseWithClaims(raw, &claims, hmacKey(s.authority.hsSecret), jwt.WithValidMethods([]string{"HS256"}))
		if err != nil {
			return claims, runtime.ErrExternalInvalid
		}
		if !token.Valid {
			return claims, runtime.ErrExternalInvalid
		}
	default:
		// Remote JWKS / OIDC verification is a gateway extension point;
		// this build fails closed rather than trusting unverified claims.
		return claims, fmt.Errorf("%w: auth method %q verification not enabled in this build", runtime.ErrExternalInvalid, external.AuthMethod)
	}
	issuerOK, err := claims.GetIssuer()
	if err != nil || issuerOK != external.VerifiedIssuer {
		return claims, runtime.ErrExternalInvalid
	}
	audOK, err := claims.GetAudience()
	if err != nil {
		return claims, runtime.ErrExternalInvalid
	}
	allowed := map[string]bool{}
	for _, a := range external.AllowedAudiences {
		allowed[a] = true
	}
	matched := false
	for _, a := range audOK {
		if allowed[a] {
			matched = true
			break
		}
	}
	if !matched {
		return claims, runtime.ErrExternalInvalid
	}
	if claims.Subject == "" || claims.ID == "" || claims.ExpiresAt == nil {
		return claims, runtime.ErrExternalInvalid
	}
	if !s.now().UTC().Before(claims.ExpiresAt.Time) {
		return claims, runtime.ErrExternalExpired
	}
	return claims, nil
}

func (s *Service) VerifyExternalSession(ctx context.Context, tenantID, region string, req runtime.ExternalSessionRequest) (runtime.ExternalSession, error) {
	if strings.TrimSpace(req.Token) == "" {
		return runtime.ExternalSession{}, fmt.Errorf("%w: token required", runtime.ErrInvalidRequest)
	}
	issuer := issuerOfToken(req.Token)
	if issuer == "" {
		return runtime.ExternalSession{}, runtime.ErrExternalInvalid
	}
	external, err := s.store.GetExternalAgentByIssuer(ctx, tenantID, issuer)
	if err != nil {
		return runtime.ExternalSession{}, err
	}
	claims, err := s.verifyExternalToken(ctx, tenantID, external, req.Token)
	if err != nil {
		return runtime.ExternalSession{}, err
	}
	if claims.Subject != external.ExternalAgentID {
		return runtime.ExternalSession{}, runtime.ErrExternalInvalid
	}
	if external.Region != region {
		return runtime.ExternalSession{}, runtime.ErrDelegationRegion
	}
	return runtime.ExternalSession{
		ExternalAgentID:     external.ExternalAgentID,
		AgentID:             external.AgentID,
		OrganizationID:      external.OrganizationID,
		TenantID:            external.TenantID,
		TrustTier:           external.TrustTier,
		VerifiedIssuer:      external.VerifiedIssuer,
		Subject:             claims.Subject,
		JTI:                 claims.ID,
		Region:              external.Region,
		CustomerPrincipalID: claims.CustomerPrincipalID,
		Purpose:             claims.Purpose,
		AuthMethod:          external.AuthMethod,
	}, nil
}

// issuerOfToken extracts the issuer claim from an unsigned token so the
// agent record can be selected before verification. The issuer is
// public metadata; verification happens after selection.
func issuerOfToken(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := jwt.NewParser().DecodeSegment(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Issuer
}

func (s *Service) CreateExternalRun(ctx context.Context, tenantID, region, idempotencyKey string, req runtime.CreateExternalRunRequest) (runtime.CreateRunResponse, error) {
	if strings.TrimSpace(req.ExternalToken) == "" {
		return runtime.CreateRunResponse{}, fmt.Errorf("%w: external_token required", runtime.ErrInvalidRequest)
	}
	session, err := s.VerifyExternalSession(ctx, tenantID, region, runtime.ExternalSessionRequest{Token: req.ExternalToken})
	if err != nil {
		return runtime.CreateRunResponse{}, err
	}
	if session.CustomerPrincipalID == "" || session.Purpose == "" {
		return runtime.CreateRunResponse{}, fmt.Errorf("%w: external token must bind customer_principal_id (cid) and purpose (pur)", runtime.ErrInvalidRequest)
	}
	if idempotencyKey != "" {
		if existing, err := s.store.GetRunByIdempotencyKey(ctx, tenantID, idempotencyKey); err == nil {
			decisions, _ := s.store.ListDecisions(ctx, tenantID, existing.ID)
			return runtime.CreateRunResponse{Run: existing, Decisions: decisions}, nil
		}
	}

	var run runtime.AgentRun
	var decisions []runtime.ActionDecision
	err = s.store.Transact(ctx, "external:"+session.ExternalAgentID, func(tx TxStore) error {
		// Replay protection: the external identity token is single-use.
		if err := tx.ConsumeExternalNonce(ctx, tenantID, session.ExternalAgentID, session.JTI); err != nil {
			return err
		}
		external, err := tx.GetExternalAgent(ctx, tenantID, session.ExternalAgentID)
		if err != nil {
			return err
		}
		// The delegation token (when supplied) must be a grant minted
		// for exactly this external agent.
		var grant runtime.DelegationGrant
		var permitted []string
		if strings.TrimSpace(req.DelegationToken) != "" {
			claims, err := s.authority.Verify(ctx, req.DelegationToken)
			if err != nil {
				return err
			}
			if claims.TenantID != tenantID || claims.Region != region {
				return runtime.ErrDelegationInvalid
			}
			grant, err = tx.GetDelegationGrantByJTI(ctx, tenantID, claims.ID)
			if err != nil {
				return err
			}
			if grant.ExternalAgentID != session.ExternalAgentID || grant.IssuedVia != "external" {
				return runtime.ErrExternalInvalid
			}
			if grant.AgentID != external.AgentID {
				return runtime.ErrExternalInvalid
			}
			if grant.SubjectPrincipalID != session.CustomerPrincipalID {
				return runtime.ErrDelegationInvalid
			}
			permitted = grant.PermittedActions
		} else {
			// Demo path: mint the delegation grant server-side, bound
			// to the external agent's paired identity.
			grant, permitted, err = s.mintExternalGrant(ctx, tx, tenantID, region, session, external, req.Actions)
			if err != nil {
				return err
			}
		}
		if !grant.RevokedAt.IsZero() {
			return runtime.ErrDelegationRevoked
		}
		if !s.now().UTC().Before(grant.ExpiresAt) {
			return runtime.ErrDelegationExpired
		}
		if grant.RunID != "" {
			return runtime.ErrDelegationReused
		}
		// The trust relationship between the tenant agent and the
		// external agent must be active and cover the requested scope.
		relationship, err := tx.GetTrustRelationshipByPair(ctx, tenantID, grant.DelegatorAgentID, "", session.ExternalAgentID)
		if err != nil {
			return runtime.ErrExternalNoTrust
		}
		if relationship.Status != runtime.TrustStateActive {
			return runtime.ErrTrustNotActive
		}
		if !s.now().UTC().Before(relationship.ExpiresAt) {
			return runtime.ErrTrustExpired
		}
		if len(relationship.AllowedToolsActions) > 0 {
			for _, a := range req.Actions {
				if !actionsSubset([]string{strings.TrimSpace(a.ToolName) + ":" + strings.TrimSpace(a.Action)}, relationship.AllowedToolsActions) {
					return runtime.ErrScopeExceedsParent
				}
			}
		}
		// Customer consent gates the run (purpose-level).
		consent, err := tx.FindConsent(ctx, tenantID, external.OrganizationID, session.ExternalAgentID,
			session.CustomerPrincipalID, session.Purpose, "*")
		if err != nil {
			return runtime.ErrConsentRequired
		}
		if !s.now().UTC().Before(consent.ExpiresAt) {
			return runtime.ErrConsentExpired
		}
		// External budget: narrowest applicable scope wins; total budget
		// checked pre-run, per-run dimensions in the loop below.
		policy, _ := s.effectiveExternalBudget(ctx, tx, tenantID, session.ExternalAgentID, external.OrganizationID, session.CustomerPrincipalID)
		if policy.MaxTotalActions > 0 && policy.ActionsCount+len(req.Actions) > policy.MaxTotalActions {
			return runtime.ErrExternalUntrusted // no budget-specific sentinel; denied pre-run
		}
		if policy.MaxActionsPerRun > 0 && len(req.Actions) > policy.MaxActionsPerRun {
			return fmt.Errorf("%w: external budget max_actions_per_run exceeded", runtime.ErrDelegationNotAllowed)
		}
		if err := s.assertControlUsable(ctx, tx, tenantID, runtime.ControlEntityDelegation, grant.ID); err != nil {
			return err
		}
		run = runtime.AgentRun{
			TenantID:            tenantID,
			AgentID:             grant.AgentID,
			DelegationGrantID:   grant.ID,
			IdempotencyKey:      idempotencyKey,
			UserID:              session.CustomerPrincipalID,
			Purpose:             session.Purpose,
			Region:              region,
			Status:              runtime.RunStatusPending,
			DelegationDepth:     0,
			ChainVerified:       "unchecked",
			ExternalAgentID:     session.ExternalAgentID,
			OrganizationID:      external.OrganizationID,
			CustomerPrincipalID: session.CustomerPrincipalID,
			ConsentID:           consent.ID,
		}
		run, err = tx.CreateRun(ctx, run)
		if err != nil {
			return err
		}
		if err := tx.ConsumeGrantForRun(ctx, tenantID, grant.TokenJTI, run.ID); err != nil {
			return err
		}
		grant.RunID = run.ID

		// Evaluate every requested action with external consent +
		// budget checks layered on the shared evaluator.
		deniedCount, approvalCount, allowedCount := 0, 0, 0
		for _, action := range req.Actions {
			if policy.MaxDeniedPerRun > 0 && deniedCount >= policy.MaxDeniedPerRun {
				decisions = append(decisions, s.externalDeny(ctx, tx, tenantID, grant, run, action, "external budget denied per run", "external_budget:max_denied_per_run"))
				deniedCount++
				continue
			}
			if policy.MaxApprovalRequiredPerRun > 0 && approvalCount >= policy.MaxApprovalRequiredPerRun {
				decisions = append(decisions, s.externalDeny(ctx, tx, tenantID, grant, run, action, "external budget approval required per run", "external_budget:max_approval_required_per_run"))
				deniedCount++
				continue
			}
			if policy.MaxToolCallsPerActionPerRun > 0 && allowedCount >= policy.MaxToolCallsPerActionPerRun {
				decisions = append(decisions, s.externalDeny(ctx, tx, tenantID, grant, run, action, "external budget tool calls per run", "external_budget:max_tool_calls_per_action_per_run"))
				deniedCount++
				continue
			}
			if _, err := tx.FindConsent(ctx, tenantID, external.OrganizationID, session.ExternalAgentID,
				session.CustomerPrincipalID, session.Purpose, action.ResourceRef); err != nil {
				decision := s.externalDeny(ctx, tx, tenantID, grant, run, action, "customer consent required", "consent:required")
				decisions = append(decisions, decision)
				deniedCount++
				continue
			}
			decision := s.evaluateInTx(ctx, tx, tenantID, region, grant, run, permitted, action)
			decisions = append(decisions, decision)
			switch decision.Decision {
			case runtime.DecisionAllowed:
				allowedCount++
			case runtime.DecisionDenied, runtime.DecisionFailClosed:
				deniedCount++
			case runtime.DecisionApprovalRequired:
				approvalCount++
			}
		}
		if policy.MaxTotalActions > 0 {
			if err := tx.IncrementExternalBudgetCounters(ctx, tenantID, policy.ScopeType, policy.ExternalAgentID, policy.OrganizationID, policy.CustomerPrincipalID,
				len(decisions), deniedCount, approvalCount, allowedCount); err != nil {
				return err
			}
		}
		switch {
		case len(req.Actions) == 0:
		case allowedCount > 0:
			if err := tx.UpdateRunStatus(ctx, tenantID, run.ID, runtime.RunStatusPending, runtime.RunStatusRunning, nil, ""); err != nil {
				return err
			}
		case deniedCount > 0:
			completed := s.now().UTC().Truncate(time.Microsecond)
			if err := tx.UpdateRunStatus(ctx, tenantID, run.ID, runtime.RunStatusPending, runtime.RunStatusDenied, &completed, "all_actions_denied"); err != nil {
				return err
			}
		default:
			if err := tx.UpdateRunStatus(ctx, tenantID, run.ID, runtime.RunStatusPending, runtime.RunStatusRunning, nil, ""); err != nil {
				return err
			}
		}
		run, err = tx.GetRun(ctx, tenantID, run.ID)
		if err != nil {
			return err
		}
		s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventRunStarted, run.ID+":start", run.StartedAt, map[string]string{
			"run_id": run.ID, "tenant_id": tenantID, "agent_id": run.AgentID,
			"delegation_grant_id": run.DelegationGrantID, "status": run.Status,
			"external_agent_id": run.ExternalAgentID, "organization_id": run.OrganizationID,
		})
		_, err = s.appendTrustEvent(ctx, tx, tenantID, runtime.TrustEvent{
			TenantID:           tenantID,
			EventType:          runtime.TrustEventChainVerified,
			EntityType:         "external_agent",
			EntityID:           session.ExternalAgentID,
			ActorPrincipalID:   session.CustomerPrincipalID,
			GrantID:            grant.ID,
			RootGrantID:        grant.RootGrantID,
			SubjectPrincipalID: session.CustomerPrincipalID,
			OrganizationID:     external.OrganizationID,
			ScopeDigest:        grant.AuthorityScopeDigest,
		})
		return err
	})
	if err != nil {
		return runtime.CreateRunResponse{}, err
	}
	return runtime.CreateRunResponse{Run: run, Decisions: decisions}, nil
}

// mintExternalGrant creates the delegation grant for an external agent
// (demo path) inside the run transaction, bound to the trust
// relationship scope and the paired registry identity. Exactly one
// active relationship for the external agent is required — with
// multiple relationships the source of authority is ambiguous.
func (s *Service) mintExternalGrant(ctx context.Context, tx TxStore, tenantID, region string, session runtime.ExternalSession, external runtime.ExternalAgent, actions []runtime.RunActionRequest) (runtime.DelegationGrant, []string, error) {
	relationships, err := tx.ListTrustRelationships(ctx, tenantID)
	if err != nil {
		return runtime.DelegationGrant{}, nil, err
	}
	var relationship runtime.AgentTrustRelationship
	found := false
	for _, r := range relationships {
		if r.ExternalAgentID != session.ExternalAgentID || r.Status != runtime.TrustStateActive {
			continue
		}
		if !s.now().UTC().Before(r.ExpiresAt) {
			continue
		}
		if found {
			return runtime.DelegationGrant{}, nil, runtime.ErrExternalNoTrust
		}
		relationship = r
		found = true
	}
	if !found {
		return runtime.DelegationGrant{}, nil, runtime.ErrExternalNoTrust
	}
	if relationship.Region != region {
		return runtime.DelegationGrant{}, nil, runtime.ErrDelegationRegion
	}
	// The paired registry identity must be active with a bound version.
	if s.agents == nil {
		return runtime.DelegationGrant{}, nil, runtime.ErrGovernanceUnavailable
	}
	paired, _, _, err := s.agents.GetAgent(ctx, tenantID, external.AgentID)
	if err != nil {
		return runtime.DelegationGrant{}, nil, err
	}
	if paired.LifecycleState != runtime.AgentStateActive || paired.ActiveVersionID == "" {
		return runtime.DelegationGrant{}, nil, runtime.ErrDelegationInactive
	}
	// The scope of the minted grant comes ONLY from the trust
	// relationship (never from the request body).
	permitted := normalizePermittedActions(relationship.AllowedToolsActions)
	if len(permitted) == 0 {
		return runtime.DelegationGrant{}, nil, runtime.ErrExternalNoTrust
	}
	if _, err := s.resolvePermittedActions(ctx, tenantID, permitted); err != nil {
		return runtime.DelegationGrant{}, nil, err
	}
	permittedDigest := ComputePermittedActionsDigest(permitted)
	issuedAt := s.now().UTC().Truncate(time.Microsecond)
	expiresAt := relationship.ExpiresAt
	if !s.now().UTC().Before(expiresAt) {
		return runtime.DelegationGrant{}, nil, runtime.ErrTrustExpired
	}
	jti := newID()
	grant := runtime.DelegationGrant{
		ID:                     newID(),
		TenantID:               tenantID,
		AgentID:                external.AgentID,
		AgentVersionID:         paired.ActiveVersionID,
		TokenJTI:               jti,
		DelegatorPrincipalID:   relationship.OwnerPrincipalID,
		SubjectPrincipalID:     session.CustomerPrincipalID,
		Purpose:                session.Purpose,
		Region:                 region,
		PermittedActions:       permitted,
		PermittedActionsDigest: permittedDigest,
		IssuedAt:               issuedAt,
		ExpiresAt:              expiresAt,
		IsAgentDelegation:      false,
		DelegatorAgentID:       relationship.ParentAgentID,
		DelegationDepth:        0,
		AuthorityScopeDigest:   ComputeAuthorityScopeDigest(permittedDigest, region, session.Purpose),
		TrustRelationshipID:    relationship.ID,
		ExternalAgentID:        external.ExternalAgentID,
		IssuedVia:              "external",
	}
	grant.ImmutableDigest = ComputeGrantDigest(grant)
	if err := tx.CreateDelegationGrant(ctx, grant); err != nil {
		return runtime.DelegationGrant{}, nil, err
	}
	return grant, permitted, nil
}

// externalDeny records a denied decision for an external-budget or
// consent failure inside the run transaction.
func (s *Service) externalDeny(ctx context.Context, tx TxStore, tenantID string, grant runtime.DelegationGrant, run runtime.AgentRun, action runtime.RunActionRequest, reason, reasonCode string) runtime.ActionDecision {
	decision, _ := tx.AppendDecision(ctx, runtime.ActionDecision{
		TenantID:          tenantID,
		AgentID:           grant.AgentID,
		RunID:             run.ID,
		DelegationGrantID: grant.ID,
		ResourceRef:       action.ResourceRef,
		Decision:          runtime.DecisionDenied,
		Reason:            reason,
		ReasonCode:        reasonCode,
		PolicyVersion:     s.policyVersion,
		DelegationDepth:   grant.DelegationDepth,
		ChainVerified:     run.ChainVerified,
	})
	s.recordCounters(ctx, tx, run, decision, "", "")
	s.enqueueDecision(ctx, tx, run, decision)
	return decision
}

// effectiveExternalBudget returns the narrowest applicable external
// budget policy (customer > organization > agent), or zero-value when
// none exists.
func (s *Service) effectiveExternalBudget(ctx context.Context, tx TxStore, tenantID, externalAgentID, organizationID, customerPrincipalID string) (runtime.ExternalBudgetPolicy, error) {
	scopes := []struct {
		scopeType, agentID, orgID, custID string
	}{
		{runtime.ExternalBudgetScopeCustomer, externalAgentID, organizationID, customerPrincipalID},
		{runtime.ExternalBudgetScopeOrganization, externalAgentID, organizationID, ""},
		{runtime.ExternalBudgetScopeAgent, externalAgentID, "", ""},
	}
	for _, sc := range scopes {
		if b, err := tx.GetExternalBudget(ctx, tenantID, sc.scopeType, sc.agentID, sc.orgID, sc.custID); err == nil {
			return b, nil
		}
	}
	return runtime.ExternalBudgetPolicy{}, nil
}

// ---------------------------------------------------------------------
// External-run reads + termination (external-only, fail closed on
// internal runs)
// ---------------------------------------------------------------------

// ListExternalRuns returns only AgentRun rows stamped with an
// ExternalAgentID — internal runs are never exposed on the external
// surface.
func (s *Service) ListExternalRuns(ctx context.Context, tenantID string) ([]runtime.AgentRun, error) {
	runs, err := s.store.ListRuns(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]runtime.AgentRun, 0, len(runs))
	for _, r := range runs {
		if r.ExternalAgentID != "" {
			out = append(out, r)
		}
	}
	return out, nil
}

// GetExternalRun reads one external run with its decisions; internal
// runs return ErrRunNotFound so the surface never leaks them.
func (s *Service) GetExternalRun(ctx context.Context, tenantID, runID string) (runtime.AgentRun, []runtime.ActionDecision, error) {
	run, err := s.store.GetRun(ctx, tenantID, runID)
	if err != nil {
		return runtime.AgentRun{}, nil, err
	}
	if run.ExternalAgentID == "" {
		return runtime.AgentRun{}, nil, runtime.ErrRunNotFound
	}
	decisions, err := s.store.ListDecisions(ctx, tenantID, runID)
	if err != nil {
		return runtime.AgentRun{}, nil, err
	}
	return run, decisions, nil
}

// TerminateExternalRun terminates an external run through the shared
// TerminateRun control path (evidence + outbox recorded there).
func (s *Service) TerminateExternalRun(ctx context.Context, tenantID, runID, actor string, admin bool, req runtime.ControlRequest) (runtime.EmergencyControl, error) {
	run, err := s.store.GetRun(ctx, tenantID, runID)
	if err != nil {
		return runtime.EmergencyControl{}, err
	}
	if run.ExternalAgentID == "" {
		return runtime.EmergencyControl{}, runtime.ErrRunNotFound
	}
	return s.TerminateRun(ctx, tenantID, runID, actor, admin, req)
}

// ListDelegationGrants lists every delegation grant of the tenant
// (root, agent, and external-issued) for the console chain view.
func (s *Service) ListDelegationGrants(ctx context.Context, tenantID string) ([]runtime.DelegationGrant, error) {
	return s.store.ListDelegationGrants(ctx, tenantID)
}

// ---------------------------------------------------------------------
// Consent, transfer policies, external budgets
// ---------------------------------------------------------------------

func (s *Service) CreateConsentRecord(ctx context.Context, tenantID, actor string, admin bool, req runtime.ConsentRequest) (runtime.ConsentRecord, error) {
	if !admin {
		return runtime.ConsentRecord{}, runtime.ErrGovernanceNotAuthorized
	}
	if actor == "" {
		return runtime.ConsentRecord{}, runtime.ErrInvalidRequest
	}
	if strings.TrimSpace(req.OrganizationID) == "" || strings.TrimSpace(req.ExternalAgentID) == "" ||
		strings.TrimSpace(req.CustomerPrincipalID) == "" || strings.TrimSpace(req.Purpose) == "" {
		return runtime.ConsentRecord{}, fmt.Errorf("%w: organization_id, external_agent_id, customer_principal_id, purpose required", runtime.ErrInvalidRequest)
	}
	external, err := s.store.GetExternalAgent(ctx, tenantID, req.ExternalAgentID)
	if err != nil {
		return runtime.ConsentRecord{}, err
	}
	if external.OrganizationID != req.OrganizationID {
		return runtime.ConsentRecord{}, runtime.ErrExternalInvalid
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if ttl > 365*24*time.Hour {
		ttl = 365 * 24 * time.Hour
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var consent runtime.ConsentRecord
	err = s.store.Transact(ctx, "consent:"+tenantID, func(tx TxStore) error {
		consent = runtime.ConsentRecord{
			TenantID:            tenantID,
			OrganizationID:      strings.TrimSpace(req.OrganizationID),
			ExternalAgentID:     strings.TrimSpace(req.ExternalAgentID),
			CustomerPrincipalID: strings.TrimSpace(req.CustomerPrincipalID),
			Purpose:             strings.TrimSpace(req.Purpose),
			ResourceRefPattern:  strings.TrimSpace(req.ResourceRefPattern),
			Status:              "active",
			GrantedBy:           actor,
			GrantedAt:           now,
			ExpiresAt:           now.Add(ttl).Truncate(time.Microsecond),
		}
		if consent.ResourceRefPattern == "" {
			consent.ResourceRefPattern = "*"
		}
		created, err := tx.CreateConsentRecord(ctx, consent)
		if err != nil {
			return err
		}
		consent = created
		_, err = s.appendTrustEvent(ctx, tx, tenantID, runtime.TrustEvent{
			TenantID:           tenantID,
			EventType:          runtime.TrustEventConsent,
			EntityType:         "consent",
			EntityID:           consent.ID,
			ActorPrincipalID:   actor,
			NewState:           "active",
			OrganizationID:     consent.OrganizationID,
			SubjectPrincipalID: consent.CustomerPrincipalID,
		})
		s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventConsentRecorded, consent.ID, consent.GrantedAt, map[string]string{
			"consent_id": consent.ID, "tenant_id": tenantID, "organization_id": consent.OrganizationID,
			"external_agent_id": consent.ExternalAgentID, "customer_principal_id": consent.CustomerPrincipalID,
			"purpose": consent.Purpose, "immutable_digest": consent.ImmutableDigest,
		})
		return nil
	})
	if err != nil {
		return runtime.ConsentRecord{}, err
	}
	return consent, nil
}

func (s *Service) ListConsentRecords(ctx context.Context, tenantID string) ([]runtime.ConsentRecord, error) {
	return s.store.ListConsentRecords(ctx, tenantID)
}

// GetConsentRecord reads one tenant-scoped consent record (lazy
// expiry is not stamped here: reads are passthrough; enforcement uses
// FindConsent at run time).
func (s *Service) GetConsentRecord(ctx context.Context, tenantID, consentID string) (runtime.ConsentRecord, error) {
	return s.store.GetConsentRecord(ctx, tenantID, consentID)
}

// RevokeConsentRecord is the single active->revoked consent transition
// (admin-only). Revocation is write-once, appended to the trust-event
// evidence chain, and surfaced through the outbox.
func (s *Service) RevokeConsentRecord(ctx context.Context, tenantID, consentID, actor string, admin bool, reason string) (runtime.ConsentRecord, error) {
	if !admin {
		return runtime.ConsentRecord{}, runtime.ErrGovernanceNotAuthorized
	}
	if actor == "" {
		return runtime.ConsentRecord{}, runtime.ErrInvalidRequest
	}
	current, err := s.store.GetConsentRecord(ctx, tenantID, consentID)
	if err != nil {
		return runtime.ConsentRecord{}, err
	}
	if current.Status != "active" {
		return runtime.ConsentRecord{}, runtime.ErrConsentRevoked
	}
	var revoked runtime.ConsentRecord
	err = s.store.Transact(ctx, "consent:"+tenantID, func(tx TxStore) error {
		updated, err := tx.UpdateConsentStatus(ctx, tenantID, consentID, "active", "revoked", actor, reason)
		if err != nil {
			return err
		}
		revoked = updated
		_, err = s.appendTrustEvent(ctx, tx, tenantID, runtime.TrustEvent{
			TenantID:           tenantID,
			EventType:          runtime.TrustEventConsentRevoked,
			EntityType:         "consent",
			EntityID:           consentID,
			ActorPrincipalID:   actor,
			PreviousState:      "active",
			NewState:           "revoked",
			Reason:             reason,
			OrganizationID:     current.OrganizationID,
			SubjectPrincipalID: current.CustomerPrincipalID,
		})
		if err != nil {
			return err
		}
		s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventConsentRevoked, consentID, revoked.GrantedAt, map[string]string{
			"consent_id": consentID, "tenant_id": tenantID, "organization_id": current.OrganizationID,
			"external_agent_id": current.ExternalAgentID, "customer_principal_id": current.CustomerPrincipalID,
			"purpose": current.Purpose, "immutable_digest": revoked.ImmutableDigest,
		})
		return nil
	})
	if err != nil {
		return runtime.ConsentRecord{}, err
	}
	return revoked, nil
}

func (s *Service) UpsertTransferPolicy(ctx context.Context, tenantID, actor string, admin bool, req runtime.TransferPolicyRequest) (runtime.TransferPolicy, error) {
	if !admin {
		return runtime.TransferPolicy{}, runtime.ErrGovernanceNotAuthorized
	}
	source := strings.TrimSpace(req.SourceRegion)
	target := strings.TrimSpace(req.TargetRegion)
	purpose := strings.TrimSpace(req.PurposePattern)
	if source == "" || target == "" || purpose == "" {
		return runtime.TransferPolicy{}, fmt.Errorf("%w: source_region, target_region, purpose_pattern required", runtime.ErrInvalidRequest)
	}
	if source == target {
		return runtime.TransferPolicy{}, fmt.Errorf("%w: source and target regions must differ", runtime.ErrInvalidRequest)
	}
	if purpose != "*" && strings.ContainsAny(purpose, "*?") {
		return runtime.TransferPolicy{}, fmt.Errorf("%w: purpose_pattern must be '*' or an exact purpose", runtime.ErrInvalidRequest)
	}
	var policy runtime.TransferPolicy
	err := s.store.Transact(ctx, "transfer:"+tenantID, func(tx TxStore) error {
		created, err := tx.UpsertTransferPolicy(ctx, runtime.TransferPolicy{
			TenantID:       tenantID,
			SourceRegion:   source,
			TargetRegion:   target,
			PurposePattern: purpose,
			Enabled:        req.Enabled,
			CreatedBy:      actor,
		})
		if err != nil {
			return err
		}
		policy = created
		_, err = s.appendTrustEvent(ctx, tx, tenantID, runtime.TrustEvent{
			TenantID:         tenantID,
			EventType:        runtime.TrustEventExternal,
			EntityType:       "transfer_policy",
			EntityID:         policy.ID,
			ActorPrincipalID: actor,
			NewState:         "enabled",
		})
		return err
	})
	if err != nil {
		return runtime.TransferPolicy{}, err
	}
	return policy, nil
}

func (s *Service) ListTransferPolicies(ctx context.Context, tenantID string) ([]runtime.TransferPolicy, error) {
	return s.store.ListTransferPolicies(ctx, tenantID)
}

// TransitionTransferPolicy toggles a transfer policy's enabled state
// (admin-only). "activate" enables; "suspend" and "revoke" disable.
// Revoke and suspend differ only in the evidence record — the policy
// row carries a single boolean, and every transition is hash-chained.
func (s *Service) TransitionTransferPolicy(ctx context.Context, tenantID, policyID, actor string, admin bool, action string, req runtime.TrustTransitionRequest) (runtime.TransferPolicy, error) {
	if !admin {
		return runtime.TransferPolicy{}, runtime.ErrGovernanceNotAuthorized
	}
	if actor == "" {
		return runtime.TransferPolicy{}, runtime.ErrInvalidRequest
	}
	current, err := s.store.GetTransferPolicyByID(ctx, tenantID, policyID)
	if err != nil {
		return runtime.TransferPolicy{}, err
	}
	var enabled bool
	var newState string
	switch action {
	case "activate":
		enabled, newState = true, "enabled"
	case "suspend":
		enabled, newState = false, "disabled"
	case "revoke":
		enabled, newState = false, "revoked"
	default:
		return runtime.TransferPolicy{}, fmt.Errorf("%w: unknown action %q", runtime.ErrTransferPolicyStateInvalid, action)
	}
	// Idempotent no-op: the policy is already in the requested state.
	if current.Enabled == enabled {
		return current, nil
	}
	var policy runtime.TransferPolicy
	err = s.store.Transact(ctx, "transfer:"+tenantID, func(tx TxStore) error {
		updated, err := tx.SetTransferPolicyEnabled(ctx, tenantID, policyID, enabled)
		if err != nil {
			return err
		}
		policy = updated
		prev := "disabled"
		if current.Enabled {
			prev = "enabled"
		}
		_, err = s.appendTrustEvent(ctx, tx, tenantID, runtime.TrustEvent{
			TenantID:         tenantID,
			EventType:        runtime.TrustEventTransferPolicy,
			EntityType:       "transfer_policy",
			EntityID:         policyID,
			ActorPrincipalID: actor,
			PreviousState:    prev,
			NewState:         newState,
			Reason:           req.Reason,
		})
		return err
	})
	if err != nil {
		return runtime.TransferPolicy{}, err
	}
	return policy, nil
}

func (s *Service) UpsertExternalBudget(ctx context.Context, tenantID, actor string, admin bool, req runtime.ExternalBudgetRequest) (runtime.ExternalBudgetPolicy, error) {
	if !admin {
		return runtime.ExternalBudgetPolicy{}, runtime.ErrGovernanceNotAuthorized
	}
	switch req.ScopeType {
	case runtime.ExternalBudgetScopeAgent, runtime.ExternalBudgetScopeOrganization, runtime.ExternalBudgetScopeCustomer:
	default:
		return runtime.ExternalBudgetPolicy{}, fmt.Errorf("%w: invalid scope_type", runtime.ErrInvalidRequest)
	}
	if strings.TrimSpace(req.ExternalAgentID) == "" {
		return runtime.ExternalBudgetPolicy{}, fmt.Errorf("%w: external_agent_id required", runtime.ErrInvalidRequest)
	}
	if _, err := s.store.GetExternalAgent(ctx, tenantID, req.ExternalAgentID); err != nil {
		return runtime.ExternalBudgetPolicy{}, err
	}
	if req.ScopeType == runtime.ExternalBudgetScopeCustomer && strings.TrimSpace(req.CustomerPrincipalID) == "" {
		return runtime.ExternalBudgetPolicy{}, fmt.Errorf("%w: customer_principal_id required for customer scope", runtime.ErrInvalidRequest)
	}
	if req.ScopeType == runtime.ExternalBudgetScopeOrganization && strings.TrimSpace(req.OrganizationID) == "" {
		return runtime.ExternalBudgetPolicy{}, fmt.Errorf("%w: organization_id required for organization scope", runtime.ErrInvalidRequest)
	}
	var budget runtime.ExternalBudgetPolicy
	err := s.store.Transact(ctx, "external:"+tenantID, func(tx TxStore) error {
		created, err := tx.UpsertExternalBudget(ctx, runtime.ExternalBudgetPolicy{
			TenantID:                    tenantID,
			ScopeType:                   req.ScopeType,
			ExternalAgentID:             strings.TrimSpace(req.ExternalAgentID),
			OrganizationID:              strings.TrimSpace(req.OrganizationID),
			CustomerPrincipalID:         strings.TrimSpace(req.CustomerPrincipalID),
			MaxTotalActions:             req.MaxTotalActions,
			MaxActionsPerRun:            req.MaxActionsPerRun,
			MaxDeniedPerRun:             req.MaxDeniedPerRun,
			MaxApprovalRequiredPerRun:   req.MaxApprovalRequiredPerRun,
			MaxToolCallsPerActionPerRun: req.MaxToolCallsPerActionPerRun,
			CreatedBy:                   actor,
		})
		if err != nil {
			return err
		}
		budget = created
		_, err = s.appendTrustEvent(ctx, tx, tenantID, runtime.TrustEvent{
			TenantID:         tenantID,
			EventType:        runtime.TrustEventExternal,
			EntityType:       "external_budget",
			EntityID:         budget.ID,
			ActorPrincipalID: actor,
			NewState:         "configured",
			OrganizationID:   budget.OrganizationID,
		})
		return err
	})
	if err != nil {
		return runtime.ExternalBudgetPolicy{}, err
	}
	return budget, nil
}

func (s *Service) ListExternalBudgets(ctx context.Context, tenantID string) ([]runtime.ExternalBudgetPolicy, error) {
	return s.store.ListExternalBudgets(ctx, tenantID)
}

// ---------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------

func (s *Service) GetEvidenceProvenance(ctx context.Context, tenantID, eventID string) (runtime.ProvenanceView, error) {
	event, err := s.store.GetEvidenceEvent(ctx, tenantID, eventID)
	if err != nil {
		return runtime.ProvenanceView{}, err
	}
	view := runtime.ProvenanceView{
		EventID:            event.EventID,
		Kind:               event.Kind,
		TenantID:           event.TenantID,
		OccurredAt:         event.OccurredAt,
		Region:             event.Region,
		ResourceRef:        event.ResourceRef,
		Reason:             event.Reason,
		ReasonCode:         event.ReasonCode,
		TraceID:            event.TraceID,
		ImmutableDigest:    event.ImmutableDigest,
		PolicyVersion:      event.PolicyVersion,
		FinalDecision:      event.Decision,
		ConnectorAction:    event.ActionID,
		ToolID:             event.ToolID,
		ToolName:           event.ToolName,
		ActionID:           event.ActionID,
		SubjectPrincipalID: event.SubjectPrincipalID,
	}
	switch event.Kind {
	case runtime.EvidenceKindDecision:
		grantID := event.DelegationGrantID
		if grantID != "" {
			grant, gerr := s.store.GetDelegationGrantByID(ctx, tenantID, grantID)
			if gerr == nil {
				view.RootGrantID = grant.RootGrantID
				if view.RootGrantID == "" {
					view.RootGrantID = grant.ID
				}
				view.ParentGrantID = grant.ParentGrantID
				view.DelegationDepth = grant.DelegationDepth
				view.DelegatorAgentID = grant.DelegatorAgentID
				view.DelegateeAgentID = grant.DelegateeAgentID
				view.SubjectPrincipalID = grant.SubjectPrincipalID
				view.ScopeDigest = grant.AuthorityScopeDigest
				view.AttenuationDigest = grant.AttenuationDigest
				view.Region = grant.Region
				if grant.TrustRelationshipID != "" {
					if rel, rerr := s.store.GetTrustRelationship(ctx, tenantID, grant.TrustRelationshipID); rerr == nil {
						view.TrustDomain = rel.TrustDomain
					}
				}
				if grant.ExternalAgentID != "" {
					if ext, eerr := s.store.GetExternalAgent(ctx, tenantID, grant.ExternalAgentID); eerr == nil {
						view.OrganizationID = ext.OrganizationID
					}
				}
				if grant.IsAgentDelegation {
					chain, cerr := s.GetDelegationChain(ctx, tenantID, grant.ID)
					if cerr == nil {
						view.ChainVerification = "verified"
						if !chain.Verified {
							view.ChainVerification = "broken"
							view.RevocationSource = chain.Problem
						}
					} else {
						view.ChainVerification = "broken"
					}
				}
			}
		}
	case runtime.EvidenceKindTrustEvent:
		view.TrustDomain = event.TrustDomain
		view.OrganizationID = event.OrganizationID
		view.RootGrantID = event.RootGrantID
		view.ParentGrantID = event.ParentGrantID
		view.DelegationDepth = event.DelegationDepth
		view.ScopeDigest = event.ScopeDigest
		view.AttenuationDigest = event.AttenuationDigest
		view.RevocationSource = event.RevocationSource
		view.ChainVerification = event.ChainVerification
	}
	return view, nil
}
