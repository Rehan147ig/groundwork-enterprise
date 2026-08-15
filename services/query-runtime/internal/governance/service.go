package governance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	gwmetrics "groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/outbox"
	"groundwork/query-runtime/internal/relationship"
	"groundwork/query-runtime/internal/runtime"
	"groundwork/query-runtime/internal/usage"
)

// AgentReader is the minimal Phase 1 registry surface the evaluator
// needs: agent lifecycle state + version status. Implemented by the
// agentregistry service (wired from cmd/query-runtime).
type AgentReader interface {
	GetAgent(ctx context.Context, tenantID, agentID string) (runtime.Agent, []runtime.AgentVersion, []runtime.LifecycleEvent, error)
	ListVersions(ctx context.Context, tenantID, agentID string) ([]runtime.AgentVersion, error)
}

const policyVersion = "2026-08-delegated-authority-v1"

// Compile-time conformance: Service implements the full governance contract.
var _ runtime.GovernanceService = (*Service)(nil)

// Service is the governance implementation: tool/action/grant
// management, delegation minting, run creation, and the single shared
// evaluator used by the REST action path, the query gate, and MCP.
type Service struct {
	store     Store
	authority *Authority
	// authorizer is the relationship authorization backend (the SpiceDB
	// adapter via relationship.Authorizer). The checked subject is ALWAYS
	// the verified delegated principal — never a body-supplied identifier,
	// never the agent.
	authorizer    relationship.Authorizer
	agents        AgentReader
	now           func() time.Time
	policyVersion string
	// regionResolver (Phase 4) enriches evidence records with the
	// tenant's trusted region and jurisdiction at read time. Nil-safe:
	// without it, evidence records carry no region/jurisdiction.
	regionResolver runtime.TenantRegionResolver
	// dispatcher (Phase 5) is the connector gateway. DispatchAction
	// calls it ONLY after the evaluator has recorded an allowed
	// decision; the gateway re-validates connector lifecycle/region and
	// fails closed before any outbound connection. Nil-safe: connector
	// dispatch fails closed (no external call) when unset.
	dispatcher runtime.ConnectorDispatcher
	// usageMeter (Phase 8.1) enforces the connector_calls quota
	// fail-closed inside DispatchAction, immediately before the
	// outbound call. Nil-safe: dispatch is unconstrained when unset.
	usageMeter UsageMeter
	// backpressure (Phase 8.2) is the outbox high-water gate. Checked
	// at the top of every evidence-producing action (evaluate,
	// dispatch, delegated query): when the tenant's pending outbox is
	// at/above the mark, the action is denied fail-closed
	// (ErrOutboxBackpressure, HTTP 503) instead of deepening the
	// backlog. Nil-safe: unconstrained when unset.
	backpressure BackpressureGate
	// dispatchMu guards dispatchLocks, the Phase 8.2 in-process per-key
	// locks. Two concurrent dispatches with the same semantic
	// idempotency key serialize so the connector is never called twice;
	// the PG partial unique index covers the cross-instance window.
	dispatchMu    sync.Mutex
	dispatchLocks map[string]*dispatchKeyLock
}

// dispatchKeyLock serializes concurrent dispatches with the same
// semantic idempotency key (Phase 8.2). refs is a refcount: the lock is
// removed from the registry when the last holder releases it.
type dispatchKeyLock struct {
	mu   sync.Mutex
	refs int
}

// lockDispatch returns the per-key lock, registering it refcounted so a
// second goroutine with the same key waits behind the first caller.
func (s *Service) lockDispatch(key string) *dispatchKeyLock {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	lk := s.dispatchLocks[key]
	if lk == nil {
		lk = &dispatchKeyLock{}
		s.dispatchLocks[key] = lk
	}
	lk.refs++
	return lk
}

// unlockDispatch releases a per-key lock and unregisters it once the
// last holder is done (keyed on the pointer to tolerate re-entry).
func (s *Service) unlockDispatch(key string, lk *dispatchKeyLock) {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	lk.refs--
	if lk.refs <= 0 {
		delete(s.dispatchLocks, key)
	}
}

// BackpressureGate is the Phase 8.2 outbox backpressure check. It is
// implemented by outbox.Backpressure and wired from cmd/query-runtime;
// nil-safe.
type BackpressureGate interface {
	Allow(ctx context.Context, tenantID string) error
}

// SetBackpressure wires the outbox backpressure gate (Phase 8.2).
func (s *Service) SetBackpressure(g BackpressureGate) { s.backpressure = g }

// NewService constructs the governance service. authority must be
// non-nil (fatal at startup otherwise); authorizer and agents may be nil, in
// which case every evaluation fails closed with evidence.
func NewService(store Store, authority *Authority, authorizer relationship.Authorizer, agents AgentReader) *Service {
	return &Service{
		store:         store,
		authority:     authority,
		authorizer:    authorizer,
		agents:        agents,
		now:           time.Now,
		policyVersion: policyVersion,
		dispatchLocks: map[string]*dispatchKeyLock{},
	}
}

// SetConnectorDispatcher wires the Phase 5 connector gateway (from
// internal/connectors). Without it, http/mcp tool dispatch fails
// closed instead of reaching an external system.
func (s *Service) SetConnectorDispatcher(d runtime.ConnectorDispatcher) { s.dispatcher = d }

// UsageMeter is the optional per-tenant usage metering surface
// DispatchAction uses to enforce the connector_calls quota fail-closed
// before any outbound connection opens (Phase 8.1). Implemented by
// internal/usage.Service and wired from cmd/query-runtime. Nil-safe:
// without a meter, connector dispatch is unconstrained.
type UsageMeter interface {
	Record(ctx context.Context, tenantID, metric string, delta int64) error
}

// SetUsageMeter wires the optional usage meter for fail-closed
// connector_calls enforcement.
func (s *Service) SetUsageMeter(m UsageMeter) { s.usageMeter = m }

// SetRegionResolver wires the trusted tenant->region/jurisdiction
// configuration used to enrich evidence records (Phase 4). The region
// and jurisdiction come only from this trusted configuration — never
// from request bodies.
func (s *Service) SetRegionResolver(resolver runtime.TenantRegionResolver) {
	s.regionResolver = resolver
}

// enrichEvidence stamps each event with the tenant's trusted region and
// jurisdiction from the configured resolver (no-op when unwired).
func (s *Service) enrichEvidence(tenantID string, events []runtime.EvidenceEvent) {
	if s.regionResolver == nil || len(events) == 0 {
		return
	}
	region, jurisdiction, ok := s.regionResolver.Resolve(tenantID)
	if !ok {
		return
	}
	for i := range events {
		events[i].Region = region
		events[i].Jurisdiction = jurisdiction
	}
}

// SetClock overrides the time source (tests).
func (s *Service) SetClock(now func() time.Time) {
	s.now = now
	s.authority.SetClock(now)
}

// ---------------------------------------------------------------------
// Tools & actions
// ---------------------------------------------------------------------

func (s *Service) RegisterTool(ctx context.Context, tenantID, actor string, admin bool, req runtime.RegisterToolRequest) (runtime.Tool, error) {
	if !admin {
		return runtime.Tool{}, runtime.ErrGovernanceNotAuthorized
	}
	if actor == "" {
		return runtime.Tool{}, runtime.ErrInvalidRequest
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return runtime.Tool{}, fmt.Errorf("%w: tool name required", runtime.ErrInvalidRequest)
	}
	transport := strings.TrimSpace(req.Transport)
	if transport == "" {
		transport = runtime.ToolTransportInternal
	}
	if !isValidTransport(transport) {
		return runtime.Tool{}, fmt.Errorf("%w: invalid transport", runtime.ErrInvalidRequest)
	}
	owner := strings.TrimSpace(req.OwnerPrincipalID)
	if owner == "" {
		return runtime.Tool{}, fmt.Errorf("%w: owner principal required", runtime.ErrInvalidRequest)
	}
	region := strings.TrimSpace(req.Region)
	if region == "" {
		return runtime.Tool{}, fmt.Errorf("%w: region required", runtime.ErrInvalidRequest)
	}
	tool := runtime.Tool{
		TenantID:         tenantID,
		Name:             name,
		Description:      strings.TrimSpace(req.Description),
		Transport:        transport,
		EndpointOrServer: strings.TrimSpace(req.EndpointOrServer),
		OwnerPrincipalID: owner,
		Region:           region,
		ManifestDigest:   strings.TrimSpace(req.ManifestDigest),
		Lifecycle:        runtime.ToolLifecycleDraft,
	}
	var created runtime.Tool
	err := s.store.Transact(ctx, "new:"+tenantID, func(tx TxStore) error {
		var err error
		created, err = tx.CreateTool(ctx, tool)
		return err
	})
	return created, err
}

func (s *Service) ListTools(ctx context.Context, tenantID string) ([]runtime.Tool, error) {
	return s.store.ListTools(ctx, tenantID)
}

func (s *Service) GetTool(ctx context.Context, tenantID, toolID string) (runtime.Tool, []runtime.ToolAction, error) {
	tool, err := s.store.GetTool(ctx, tenantID, toolID)
	if err != nil {
		return runtime.Tool{}, nil, err
	}
	actions, err := s.store.ListToolActions(ctx, tenantID, toolID)
	if err != nil {
		return runtime.Tool{}, nil, err
	}
	return tool, actions, nil
}

func (s *Service) RegisterToolAction(ctx context.Context, tenantID, toolID, actor string, admin bool, req runtime.RegisterToolActionRequest) (runtime.ToolAction, error) {
	if !admin {
		return runtime.ToolAction{}, runtime.ErrGovernanceNotAuthorized
	}
	if actor == "" {
		return runtime.ToolAction{}, runtime.ErrInvalidRequest
	}
	action := strings.TrimSpace(req.Action)
	if action == "" {
		return runtime.ToolAction{}, fmt.Errorf("%w: action name required", runtime.ErrInvalidRequest)
	}
	riskLevel := strings.TrimSpace(req.RiskLevel)
	if riskLevel == "" {
		riskLevel = runtime.RiskLevelLow
	}
	if !isValidRiskLevel(riskLevel) {
		return runtime.ToolAction{}, fmt.Errorf("%w: invalid risk level", runtime.ErrInvalidRequest)
	}
	resourceType := strings.TrimSpace(req.ResourceType)
	if resourceType == "" {
		resourceType = "document"
	}
	record := runtime.ToolAction{
		TenantID:              tenantID,
		ToolID:                toolID,
		Action:                action,
		ResourceType:          resourceType,
		RiskLevel:             riskLevel,
		ReadOnly:              req.ReadOnly,
		RequiresHumanApproval: req.RequiresHumanApproval,
		Status:                runtime.ActionStatusActive,
	}
	var created runtime.ToolAction
	err := s.store.Transact(ctx, "tool:"+toolID, func(tx TxStore) error {
		var err error
		created, err = tx.CreateToolAction(ctx, record)
		return err
	})
	return created, err
}

func (s *Service) ListToolActions(ctx context.Context, tenantID, toolID string) ([]runtime.ToolAction, error) {
	return s.store.ListToolActions(ctx, tenantID, toolID)
}

// toolTransitions are the allowed lifecycle transitions (revoked is
// terminal, like agents).
var toolTransitions = map[string]map[string]bool{
	runtime.ToolLifecycleDraft:     {runtime.ToolLifecycleActive: true, runtime.ToolLifecycleSuspended: true, runtime.ToolLifecycleRevoked: true},
	runtime.ToolLifecycleActive:    {runtime.ToolLifecycleSuspended: true, runtime.ToolLifecycleRevoked: true},
	runtime.ToolLifecycleSuspended: {runtime.ToolLifecycleActive: true, runtime.ToolLifecycleRevoked: true},
	runtime.ToolLifecycleRevoked:   {},
}

func (s *Service) TransitionTool(ctx context.Context, tenantID, toolID, actor string, admin bool, req runtime.TransitionToolRequest) (runtime.Tool, error) {
	if !admin {
		return runtime.Tool{}, runtime.ErrGovernanceNotAuthorized
	}
	if actor == "" {
		return runtime.Tool{}, runtime.ErrInvalidRequest
	}
	newLifecycle := strings.TrimSpace(req.Lifecycle)
	if !isValidToolLifecycle(newLifecycle) {
		return runtime.Tool{}, fmt.Errorf("%w: invalid lifecycle", runtime.ErrInvalidRequest)
	}
	var tool runtime.Tool
	err := s.store.Transact(ctx, "tool:"+toolID, func(tx TxStore) error {
		current, err := tx.GetTool(ctx, tenantID, toolID)
		if err != nil {
			return err
		}
		if !toolTransitions[current.Lifecycle][newLifecycle] {
			return runtime.ErrToolInvalidState
		}
		if err := tx.TransitionTool(ctx, tenantID, toolID, current.Lifecycle, newLifecycle); err != nil {
			return err
		}
		tool, err = tx.GetTool(ctx, tenantID, toolID)
		return err
	})
	return tool, err
}

// ---------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------

func (s *Service) GrantToolAccess(ctx context.Context, tenantID, actor string, admin bool, req runtime.GrantToolRequest) (runtime.AgentToolGrant, error) {
	if !admin {
		return runtime.AgentToolGrant{}, runtime.ErrGovernanceNotAuthorized
	}
	if actor == "" {
		return runtime.AgentToolGrant{}, runtime.ErrInvalidRequest
	}
	if req.AgentID == "" || req.VersionID == "" || req.ToolID == "" || req.ActionID == "" {
		return runtime.AgentToolGrant{}, fmt.Errorf("%w: agent, version, tool, and action are required", runtime.ErrInvalidRequest)
	}
	resourceScope := strings.TrimSpace(req.ResourceScope)
	if resourceScope == "" {
		resourceScope = "*"
	}
	regionConstraint := strings.TrimSpace(req.RegionConstraint)
	if regionConstraint == "" {
		regionConstraint = "*"
	}
	// The version must belong to the agent, and the tool/action must exist.
	if s.agents != nil {
		versions, err := s.agents.ListVersions(ctx, tenantID, req.AgentID)
		if err != nil {
			return runtime.AgentToolGrant{}, err
		}
		versionOK := false
		for _, v := range versions {
			if v.ID == req.VersionID {
				versionOK = true
				break
			}
		}
		if !versionOK {
			return runtime.AgentToolGrant{}, runtime.ErrInvalidRequest
		}
	}
	if _, err := s.store.GetTool(ctx, tenantID, req.ToolID); err != nil {
		return runtime.AgentToolGrant{}, err
	}
	if _, err := s.store.GetToolAction(ctx, tenantID, req.ActionID); err != nil {
		return runtime.AgentToolGrant{}, err
	}
	grant := runtime.AgentToolGrant{
		TenantID:         tenantID,
		AgentID:          req.AgentID,
		VersionID:        req.VersionID,
		ToolID:           req.ToolID,
		ActionID:         req.ActionID,
		ResourceScope:    resourceScope,
		RegionConstraint: regionConstraint,
		CallLimitPerRun:  req.CallLimitPerRun,
		RequiresApproval: req.RequiresApproval,
		GrantedBy:        actor,
	}
	var created runtime.AgentToolGrant
	err := s.store.Transact(ctx, "grant:"+req.AgentID, func(tx TxStore) error {
		var err error
		created, err = tx.CreateGrant(ctx, grant)
		return err
	})
	return created, err
}

func (s *Service) RevokeToolGrant(ctx context.Context, tenantID, grantID, actor string, admin bool, reason string) (runtime.AgentToolGrant, error) {
	if !admin {
		return runtime.AgentToolGrant{}, runtime.ErrGovernanceNotAuthorized
	}
	if actor == "" {
		return runtime.AgentToolGrant{}, runtime.ErrInvalidRequest
	}
	var grant runtime.AgentToolGrant
	err := s.store.Transact(ctx, "grant:"+grantID, func(tx TxStore) error {
		if err := tx.RevokeGrant(ctx, tenantID, grantID); err != nil {
			return err
		}
		var err error
		grant, err = tx.GetGrant(ctx, tenantID, grantID)
		return err
	})
	return grant, err
}

func (s *Service) ListToolGrants(ctx context.Context, tenantID, agentID string) ([]runtime.AgentToolGrant, error) {
	return s.store.ListGrants(ctx, tenantID, agentID)
}

// ---------------------------------------------------------------------
// Delegation minting
// ---------------------------------------------------------------------

func (s *Service) MintDelegation(ctx context.Context, tenantID, region, agentID, actor string, admin bool, idempotencyKey string, req runtime.MintDelegationRequest) (runtime.MintDelegationResponse, error) {
	if s.agents == nil {
		return runtime.MintDelegationResponse{}, runtime.ErrGovernanceUnavailable
	}
	subject := strings.TrimSpace(req.SubjectPrincipalID)
	if subject == "" {
		return runtime.MintDelegationResponse{}, fmt.Errorf("%w: subject_principal_id required (the verified delegated principal)", runtime.ErrInvalidRequest)
	}
	purpose := strings.TrimSpace(req.Purpose)
	if purpose == "" {
		return runtime.MintDelegationResponse{}, fmt.Errorf("%w: purpose required", runtime.ErrInvalidRequest)
	}
	permitted := normalizePermittedActions(req.PermittedActions)
	if len(permitted) == 0 {
		return runtime.MintDelegationResponse{}, fmt.Errorf("%w: permitted_actions required (e.g. \"groundwork_search:search\")", runtime.ErrInvalidRequest)
	}
	// Owner-or-admin, like Phase 1 lifecycle transitions.
	agent, _, _, err := s.agents.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return runtime.MintDelegationResponse{}, err
	}
	if actor != agent.OwnerPrincipalID && !admin {
		return runtime.MintDelegationResponse{}, runtime.ErrGovernanceNotAuthorized
	}
	if agent.LifecycleState != runtime.AgentStateActive {
		return runtime.MintDelegationResponse{}, runtime.ErrDelegationInactive
	}
	if agent.ActiveVersionID == "" {
		return runtime.MintDelegationResponse{}, fmt.Errorf("%w: agent has no active version", runtime.ErrDelegationInactive)
	}
	// Every permitted action must resolve to a registered, active tool+action.
	if _, err := s.resolvePermittedActions(ctx, tenantID, permitted); err != nil {
		return runtime.MintDelegationResponse{}, err
	}
	permittedDigest := ComputePermittedActionsDigest(permitted)

	ttl := runtime.DefaultDelegationTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if ttl > runtime.MaxDelegationTTL {
		ttl = runtime.MaxDelegationTTL
	}
	issuedAt := s.now().UTC().Truncate(time.Microsecond)
	expiresAt := issuedAt.Add(ttl).Truncate(time.Microsecond)

	// Idempotent replay: same tenant + idempotency key returns the
	// existing grant WITHOUT the raw token (single-delivery by design).
	// The stored permitted-actions list is returned for convenience.
	if idempotencyKey != "" {
		if existing, err := s.store.GetDelegationGrantByIdempotencyKey(ctx, tenantID, idempotencyKey); err == nil {
			return runtime.MintDelegationResponse{Grant: existing, TokenAlreadyIssued: true}, nil
		}
	}

	jti := newID()
	grant := runtime.DelegationGrant{
		ID:                     newID(),
		TenantID:               tenantID,
		AgentID:                agentID,
		AgentVersionID:         agent.ActiveVersionID,
		TokenJTI:               jti,
		DelegatorPrincipalID:   actor,
		SubjectPrincipalID:     subject,
		Purpose:                purpose,
		Region:                 region,
		PermittedActions:       permitted,
		PermittedActionsDigest: permittedDigest,
		IssuedAt:               issuedAt,
		ExpiresAt:              expiresAt,
		IdempotencyKey:         idempotencyKey,
		IssuedVia:              "root",
	}
	grant.ImmutableDigest = ComputeGrantDigest(grant)
	if err := s.store.Transact(ctx, "agent:"+agentID, func(tx TxStore) error {
		// Emergency gate: kill-switched or suspended agents/versions
		// cannot mint new delegations.
		if err := s.assertControlUsable(ctx, tx, tenantID, runtime.ControlEntityAgent, agentID); err != nil {
			return err
		}
		if err := s.assertControlUsable(ctx, tx, tenantID, runtime.ControlEntityAgentVersion, agent.ActiveVersionID); err != nil {
			return err
		}
		if err := tx.CreateDelegationGrant(ctx, grant); err != nil {
			return err
		}
		s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventDelegationMinted, grant.ID+":minted", issuedAt, map[string]string{
			"delegation_grant_id":  grant.ID,
			"tenant_id":            tenantID,
			"agent_id":             agentID,
			"agent_version_id":     agent.ActiveVersionID,
			"subject_principal_id": subject,
			"purpose":              purpose,
			"expires_at":           expiresAt.Format(time.RFC3339Nano),
			"immutable_digest":     grant.ImmutableDigest,
		})
		gwmetrics.RecordEvidenceEvent(tenantID, runtime.EvidenceKindDelegationMint)
		return nil
	}); err != nil {
		return runtime.MintDelegationResponse{}, err
	}

	token, err := s.authority.Mint(tenantID, agentID, agent.ActiveVersionID, actor, subject, purpose, region, permitted, permittedDigest, jti, issuedAt, expiresAt)
	if err != nil {
		return runtime.MintDelegationResponse{}, fmt.Errorf("%w: %v", runtime.ErrDelegationInvalid, err)
	}
	return runtime.MintDelegationResponse{Grant: grant, Token: token}, nil
}

// resolvePermittedActions validates every "tool:action" entry resolves
// to a registered active tool + active action.
func (s *Service) resolvePermittedActions(ctx context.Context, tenantID string, permitted []string) (map[string]bool, error) {
	resolved := map[string]bool{}
	for _, entry := range permitted {
		toolName, actionName := splitToolAction(entry)
		tool, err := s.store.GetToolByName(ctx, tenantID, toolName)
		if err != nil {
			return nil, fmt.Errorf("%w: unknown tool %q", runtime.ErrDelegationNotAllowed, toolName)
		}
		if tool.Lifecycle != runtime.ToolLifecycleActive {
			return nil, fmt.Errorf("%w: tool %q is not active", runtime.ErrDelegationNotAllowed, toolName)
		}
		if _, err := s.store.GetToolActionByName(ctx, tenantID, tool.ID, actionName); err != nil {
			return nil, fmt.Errorf("%w: unknown action %q on %q", runtime.ErrDelegationNotAllowed, actionName, toolName)
		}
		resolved[entry] = true
	}
	return resolved, nil
}

// ---------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------

func (s *Service) CreateRun(ctx context.Context, tenantID, region, idempotencyKey string, req runtime.CreateRunRequest) (runtime.CreateRunResponse, error) {
	claims, err := s.authority.Verify(ctx, req.DelegationToken)
	if err != nil {
		return runtime.CreateRunResponse{}, err
	}
	if claims.TenantID != tenantID {
		return runtime.CreateRunResponse{}, runtime.ErrDelegationInvalid
	}
	if claims.Region != region {
		return runtime.CreateRunResponse{}, runtime.ErrDelegationRegion
	}

	// Idempotent replay: same tenant + idempotency key returns the
	// existing run with its recorded decisions.
	if idempotencyKey != "" {
		if existing, err := s.store.GetRunByIdempotencyKey(ctx, tenantID, idempotencyKey); err == nil {
			decisions, _ := s.store.ListDecisions(ctx, tenantID, existing.ID)
			return runtime.CreateRunResponse{Run: existing, Decisions: decisions}, nil
		}
	}

	var run runtime.AgentRun
	var decisions []runtime.ActionDecision
	err = s.store.Transact(ctx, "agent:"+claims.AgentID, func(tx TxStore) error {
		grant, err := tx.GetDelegationGrantByJTI(ctx, tenantID, claims.ID)
		if err != nil {
			return err
		}
		if !grant.RevokedAt.IsZero() {
			return runtime.ErrDelegationRevoked
		}
		if !s.now().UTC().Before(grant.ExpiresAt) {
			return runtime.ErrDelegationExpired
		}
		if grant.AgentID != claims.AgentID || grant.AgentVersionID != claims.AgentVersionID ||
			grant.SubjectPrincipalID != claims.SubjectPrincipalID || grant.Purpose != claims.Purpose ||
			grant.Region != claims.Region {
			return runtime.ErrDelegationInvalid
		}
		// The signed permitted-actions list must match the stored digest.
		if ComputePermittedActionsDigest(claims.PermittedActions) != grant.PermittedActionsDigest {
			return runtime.ErrDelegationInvalid
		}
		if grant.RunID != "" {
			return runtime.ErrDelegationReused
		}
		// Emergency gates: a kill-switched or suspended agent, version,
		// or delegation cannot start a new run (checked in the same tx
		// as the run creation).
		if err := s.assertControlUsable(ctx, tx, tenantID, runtime.ControlEntityAgent, grant.AgentID); err != nil {
			return err
		}
		if err := s.assertControlUsable(ctx, tx, tenantID, runtime.ControlEntityAgentVersion, grant.AgentVersionID); err != nil {
			return err
		}
		if err := s.assertControlUsable(ctx, tx, tenantID, runtime.ControlEntityDelegation, grant.ID); err != nil {
			return err
		}

		run = runtime.AgentRun{
			TenantID:          tenantID,
			AgentID:           grant.AgentID,
			DelegationGrantID: grant.ID,
			IdempotencyKey:    idempotencyKey,
			UserID:            grant.SubjectPrincipalID,
			Purpose:           grant.Purpose,
			Region:            grant.Region,
			Status:            runtime.RunStatusPending,
		}
		// Phase 6: stamp the delegation chain context of the grant that
		// authorized this run (verified here, in the same tx as the run).
		run.DelegationDepth = grant.DelegationDepth
		run.ChainVerified = s.verifyChainStatus(ctx, tx, tenantID, grant)
		run.RootGrantID = grant.RootGrantID
		if grant.IsAgentDelegation {
			run.ParentGrantID = grant.ParentGrantID
		}
		run.ExternalAgentID = grant.ExternalAgentID
		run, err = tx.CreateRun(ctx, run)
		if err != nil {
			return err
		}
		// Atomic one-time consume: the server-generated run is bound to
		// the grant exactly once (replay returns ErrDelegationReused).
		if err := tx.ConsumeGrantForRun(ctx, tenantID, claims.ID, run.ID); err != nil {
			return err
		}
		// Reflect the binding in the in-memory grant copy so in-run
		// evaluation sees grant.RunID == run.ID.
		grant.RunID = run.ID
		// Evaluate the requested actions inside the same unit of work.
		anyAllowed := false
		anyDenied := false
		for _, action := range req.Actions {
			decision := s.evaluateInTx(ctx, tx, tenantID, region, grant, run, claims.PermittedActions, action)
			decisions = append(decisions, decision)
			switch decision.Decision {
			case runtime.DecisionAllowed:
				anyAllowed = true
			case runtime.DecisionDenied, runtime.DecisionFailClosed:
				anyDenied = true
			}
		}
		// pending -> running once actions are assessed; all-denied runs
		// land in denied so the terminal state is observable.
		switch {
		case len(req.Actions) == 0:
		case anyAllowed:
			if err := tx.UpdateRunStatus(ctx, tenantID, run.ID, runtime.RunStatusPending, runtime.RunStatusRunning, nil, ""); err != nil {
				return err
			}
		case anyDenied:
			completed := s.now().UTC().Truncate(time.Microsecond)
			if err := tx.UpdateRunStatus(ctx, tenantID, run.ID, runtime.RunStatusPending, runtime.RunStatusDenied, &completed, "all_actions_denied"); err != nil {
				return err
			}
		default:
			if err := tx.UpdateRunStatus(ctx, tenantID, run.ID, runtime.RunStatusPending, runtime.RunStatusRunning, nil, ""); err != nil {
				return err
			}
		}
		// Re-read so the response reflects the terminal status.
		run, err = tx.GetRun(ctx, tenantID, run.ID)
		if err != nil {
			return err
		}
		// Run lifecycle outbox events (safe payloads, same tx).
		s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventRunStarted, run.ID+":start", run.StartedAt, map[string]string{
			"run_id": run.ID, "tenant_id": tenantID, "agent_id": run.AgentID,
			"delegation_grant_id": run.DelegationGrantID, "status": run.Status,
		})
		if run.Status == runtime.RunStatusDenied || run.Status == runtime.RunStatusCompleted ||
			run.Status == runtime.RunStatusFailed || run.Status == runtime.RunStatusRevoked {
			s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventRunEnded, run.ID+":end", run.CompletedAt, map[string]string{
				"run_id": run.ID, "tenant_id": tenantID, "agent_id": run.AgentID,
				"status": run.Status, "error_code": run.ErrorCode,
			})
		}
		return nil
	})
	if err != nil {
		return runtime.CreateRunResponse{}, err
	}
	return runtime.CreateRunResponse{Run: run, Decisions: decisions}, nil
}

func (s *Service) GetRun(ctx context.Context, tenantID, runID string) (runtime.AgentRun, []runtime.ActionDecision, error) {
	run, err := s.store.GetRun(ctx, tenantID, runID)
	if err != nil {
		return runtime.AgentRun{}, nil, err
	}
	decisions, err := s.store.ListDecisions(ctx, tenantID, runID)
	if err != nil {
		return runtime.AgentRun{}, nil, err
	}
	return run, decisions, nil
}

func (s *Service) ListRuns(ctx context.Context, tenantID string) ([]runtime.AgentRun, error) {
	return s.store.ListRuns(ctx, tenantID)
}

// ---------------------------------------------------------------------
// The shared evaluator (single source of truth for governed decisions)
// ---------------------------------------------------------------------

func (s *Service) EvaluateAction(ctx context.Context, tenantID, region string, req runtime.EvaluateActionRequest) (runtime.EvaluateActionResponse, error) {
	if req.RunID == "" || strings.TrimSpace(req.ToolName) == "" || strings.TrimSpace(req.Action) == "" {
		return runtime.EvaluateActionResponse{}, fmt.Errorf("%w: run_id, tool_name, and action are required", runtime.ErrInvalidRequest)
	}
	// Phase 8.2: the evidence pipeline must be able to absorb this
	// decision. A backed-up outbox refuses new work fail-closed.
	if s.backpressure != nil {
		if err := s.backpressure.Allow(ctx, tenantID); err != nil {
			if errors.Is(err, outbox.ErrBackpressureExceeded) {
				return runtime.EvaluateActionResponse{}, runtime.ErrOutboxBackpressure
			}
			return runtime.EvaluateActionResponse{}, err
		}
	}
	claims, err := s.authority.Verify(ctx, req.DelegationToken)
	if err != nil {
		return runtime.EvaluateActionResponse{}, err
	}
	if claims.TenantID != tenantID {
		return runtime.EvaluateActionResponse{}, runtime.ErrDelegationInvalid
	}
	if claims.Region != region {
		return runtime.EvaluateActionResponse{}, runtime.ErrDelegationRegion
	}
	var decision runtime.ActionDecision
	err = s.store.Transact(ctx, "run:"+req.RunID, func(tx TxStore) error {
		grant, err := tx.GetDelegationGrantByJTI(ctx, tenantID, claims.ID)
		if err != nil {
			return err
		}
		run, err := tx.GetRun(ctx, tenantID, req.RunID)
		if err != nil {
			return err
		}
		if ComputePermittedActionsDigest(claims.PermittedActions) != grant.PermittedActionsDigest {
			return runtime.ErrDelegationInvalid
		}
		decision = s.evaluateInTx(ctx, tx, tenantID, region, grant, run, claims.PermittedActions, runtime.RunActionRequest{
			ToolName:    req.ToolName,
			Action:      req.Action,
			ResourceRef: req.ResourceRef,
		})
		return nil
	})
	if err != nil {
		return runtime.EvaluateActionResponse{}, err
	}
	return runtime.EvaluateActionResponse{Decision: decision, Allowed: decision.Decision == runtime.DecisionAllowed}, nil
}

// evaluateInTx evaluates ONE action under the delegation grant for the
// run, appending evidence and consuming approvals. It implements the
// governing invariant; every non-allowed path records its reason.
// permitted is the signed permitted-actions list from the verified
// token claims (only its digest is persisted on the grant row).
//
//  0. emergency controls (kill switch / suspension / revocation)
//  1. delegation live (verified token, unrevoked, unexpired, run-bound)
//  2. active agent + active agent version (emergency states checked)
//  3. action permitted by the delegation (signed permitted-actions list)
//  4. registered active tool + action (emergency states checked)
//  5. unrevoked agent-tool grant honoring scope, region, call limit,
//     budget policies (narrowest scope wins, fail closed on exhaustion)
//  6. Relationship permission for the VERIFIED subject principal
//  7. required one-time human approval consumed
//
// Every outcome increments the run budget counters and enqueues an
// action.decision outbox event in the SAME transaction as the evidence.
func (s *Service) evaluateInTx(ctx context.Context, tx TxStore, tenantID, region string, grant runtime.DelegationGrant, run runtime.AgentRun, permitted []string, action runtime.RunActionRequest) runtime.ActionDecision {
	finalize := func(d runtime.ActionDecision, toolID, actionID string) runtime.ActionDecision {
		s.recordCounters(ctx, tx, run, d, toolID, actionID)
		s.enqueueDecision(ctx, tx, run, d)
		return d
	}
	fail := func(reason, reasonCode string) runtime.ActionDecision {
		decision, _ := tx.AppendDecision(ctx, runtime.ActionDecision{
			TenantID:          tenantID,
			AgentID:           grant.AgentID,
			RunID:             run.ID,
			DelegationGrantID: grant.ID,
			ResourceRef:       action.ResourceRef,
			Decision:          runtime.DecisionFailClosed,
			Reason:            reason,
			ReasonCode:        reasonCode,
			PolicyVersion:     s.policyVersion,
			DelegationDepth:   grant.DelegationDepth,
			ChainVerified:     run.ChainVerified,
		})
		return finalize(decision, "", "")
	}
	deny := func(reason, reasonCode string) runtime.ActionDecision {
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
		return finalize(decision, "", "")
	}
	// denyBudget records a denied decision caused by budget exhaustion
	// and enqueues the budget.exhaustion outbox event.
	denyBudget := func(reason, reasonCode string) runtime.ActionDecision {
		decision := deny(reason, reasonCode)
		gwmetrics.RecordBudgetExhaustion(tenantID, reasonCode)
		s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventBudgetExhaustion, decision.ID+":budget", decision.CreatedAt, map[string]string{
			"run_id": run.ID, "tenant_id": tenantID, "reason_code": reasonCode,
		})
		return decision
	}
	// controlBlocked reports an emergency-state denial for one entity.
	controlBlocked := func(state, reason, reasonCode string) runtime.ActionDecision {
		switch state {
		case runtime.ControlStateKillSwitched, runtime.ControlStateRevoked, runtime.ControlStateSuspended:
			return deny(reason, reasonCode)
		}
		return runtime.ActionDecision{}
	}

	// gateResult carries one evaluation gate's outcome: the decision to
	// short-circuit with (stop=true) or zero to continue.
	type gateResult struct {
		decision runtime.ActionDecision
		stop     bool
	}
	// gate times one evaluation gate and records its latency for
	// decision latency decomposition (Phase 8.5), including
	// short-circuit paths, so every gate's cost is attributable.
	gate := func(name string, fn func() gateResult) (runtime.ActionDecision, bool) {
		start := time.Now()
		out := fn()
		gwmetrics.RecordDecisionGate(tenantID, name, time.Since(start))
		return out.decision, out.stop
	}

	// 0. Emergency controls are checked BEFORE every governed action:
	//    a kill switch denies the very next action, a suspension blocks
	//    it, and a revoked/terminated entity stays closed forever.
	if d, stop := gate("controls", func() gateResult {
		if c, err := tx.GetEmergencyControl(ctx, tenantID, runtime.ControlEntityRun, run.ID); err == nil {
			if d := controlBlocked(c.ControlState, "run terminated", "run:terminated"); !d.CreatedAt.IsZero() {
				return gateResult{decision: d, stop: true}
			}
		} else if !errors.Is(err, runtime.ErrControlNotFound) {
			return gateResult{decision: fail("emergency control lookup failed", ""), stop: true}
		}
		if c, err := tx.GetEmergencyControl(ctx, tenantID, runtime.ControlEntityDelegation, grant.ID); err == nil {
			if d := controlBlocked(c.ControlState, "delegation revoked", "emergency:kill_switch"); !d.CreatedAt.IsZero() {
				return gateResult{decision: d, stop: true}
			}
		} else if !errors.Is(err, runtime.ErrControlNotFound) {
			return gateResult{decision: fail("emergency control lookup failed", ""), stop: true}
		}
		if c, err := tx.GetEmergencyControl(ctx, tenantID, runtime.ControlEntityAgent, grant.AgentID); err == nil {
			if d := controlBlocked(c.ControlState, "agent kill-switched", "emergency:kill_switch"); !d.CreatedAt.IsZero() {
				return gateResult{decision: d, stop: true}
			}
		} else if !errors.Is(err, runtime.ErrControlNotFound) {
			return gateResult{decision: fail("emergency control lookup failed", ""), stop: true}
		}
		return gateResult{}
	}); stop {
		return d
	}

	// 1. The grant must be live and bound to THIS run.
	if d, stop := gate("grant_binding", func() gateResult {
		if !grant.RevokedAt.IsZero() {
			return gateResult{decision: deny("delegation revoked", ""), stop: true}
		}
		if !s.now().UTC().Before(grant.ExpiresAt) {
			return gateResult{decision: deny("delegation expired", ""), stop: true}
		}
		if grant.RunID != run.ID {
			return gateResult{decision: deny("delegation not bound to run", ""), stop: true}
		}
		if run.Status == runtime.RunStatusCompleted || run.Status == runtime.RunStatusDenied ||
			run.Status == runtime.RunStatusFailed || run.Status == runtime.RunStatusRevoked {
			return gateResult{decision: deny("run is terminal", ""), stop: true}
		}
		if run.TenantID != tenantID || run.Region != region || grant.Region != region {
			return gateResult{decision: deny("tenant or region mismatch", ""), stop: true}
		}
		return gateResult{}
	}); stop {
		return d
	}

	// 2. Active agent + active bound version (emergency states checked).
	if d, stop := gate("agent", func() gateResult {
		if s.agents == nil {
			return gateResult{decision: fail("agent registry unavailable", ""), stop: true}
		}
		agent, versions, _, err := s.agents.GetAgent(ctx, tenantID, grant.AgentID)
		if err != nil {
			return gateResult{decision: fail("agent lookup failed", ""), stop: true}
		}
		agentOK := agent.LifecycleState == runtime.AgentStateActive
		versionOK := false
		for _, v := range versions {
			if v.ID == grant.AgentVersionID && v.Status == runtime.VersionStatusActive {
				versionOK = true
				break
			}
		}
		if !agentOK {
			return gateResult{decision: deny("agent not active", ""), stop: true}
		}
		if !versionOK {
			return gateResult{decision: deny("agent version not active", ""), stop: true}
		}
		if c, err := tx.GetEmergencyControl(ctx, tenantID, runtime.ControlEntityAgentVersion, grant.AgentVersionID); err == nil {
			if d := controlBlocked(c.ControlState, "agent version kill-switched", "emergency:kill_switch"); !d.CreatedAt.IsZero() {
				return gateResult{decision: d, stop: true}
			}
		} else if !errors.Is(err, runtime.ErrControlNotFound) {
			return gateResult{decision: fail("emergency control lookup failed", ""), stop: true}
		}
		return gateResult{}
	}); stop {
		return d
	}

	// 3. The requested action must be in the delegation's permitted set.
	toolName := strings.TrimSpace(action.ToolName)
	actionName := strings.TrimSpace(action.Action)
	if d, stop := gate("permitted", func() gateResult {
		if toolName == "" || actionName == "" {
			return gateResult{decision: deny("missing tool or action", ""), stop: true}
		}
		entry := toolName + ":" + actionName
		for _, p := range permitted {
			if p == entry {
				return gateResult{}
			}
		}
		return gateResult{decision: deny("action not permitted by delegation", ""), stop: true}
	}); stop {
		return d
	}

	// 4. Registered, active tool + action (emergency states checked).
	var tool runtime.Tool
	var toolAction runtime.ToolAction
	if d, stop := gate("tool", func() gateResult {
		t, err := tx.GetToolByName(ctx, tenantID, toolName)
		if err != nil {
			return gateResult{decision: deny("tool not found", ""), stop: true}
		}
		ta, err := tx.GetToolActionByName(ctx, tenantID, t.ID, actionName)
		if err != nil {
			return gateResult{decision: deny("tool action not found", ""), stop: true}
		}
		tool, toolAction = t, ta
		if t.Lifecycle != runtime.ToolLifecycleActive {
			return gateResult{decision: deny("tool not active", ""), stop: true}
		}
		if ta.Status != runtime.ActionStatusActive {
			return gateResult{decision: deny("tool action not active", ""), stop: true}
		}
		if c, err := tx.GetEmergencyControl(ctx, tenantID, runtime.ControlEntityTool, t.ID); err == nil {
			if d := controlBlocked(c.ControlState, "tool kill-switched", "emergency:kill_switch"); !d.CreatedAt.IsZero() {
				return gateResult{decision: d, stop: true}
			}
		} else if !errors.Is(err, runtime.ErrControlNotFound) {
			return gateResult{decision: fail("emergency control lookup failed", ""), stop: true}
		}
		if grant.AgentVersionID == "" {
			return gateResult{decision: fail("delegation missing version binding", ""), stop: true}
		}
		return gateResult{}
	}); stop {
		return d
	}

	// 5. Unrevoked grant honoring scope, region, call limit, and budget.
	var matched *runtime.AgentToolGrant
	if d, stop := gate("grant", func() gateResult {
		grants, err := tx.GetGrantsForTuple(ctx, tenantID, grant.AgentID, grant.AgentVersionID, tool.ID, toolAction.ID)
		if err != nil {
			return gateResult{decision: fail("grant lookup failed", ""), stop: true}
		}
		for i := range grants {
			if !grants[i].RevokedAt.IsZero() {
				continue
			}
			if !scopeMatches(grants[i].ResourceScope, action.ResourceRef) {
				continue
			}
			if !regionMatches(grants[i].RegionConstraint, region) {
				continue
			}
			matched = &grants[i]
			break
		}
		if matched == nil {
			return gateResult{decision: deny("no active grant for tool action", ""), stop: true}
		}
		if c, err := tx.GetEmergencyControl(ctx, tenantID, runtime.ControlEntityToolGrant, matched.ID); err == nil {
			if d := controlBlocked(c.ControlState, "grant kill-switched", "emergency:kill_switch"); !d.CreatedAt.IsZero() {
				return gateResult{decision: d, stop: true}
			}
		} else if !errors.Is(err, runtime.ErrControlNotFound) {
			return gateResult{decision: fail("emergency control lookup failed", ""), stop: true}
		}
		if matched.CallLimitPerRun > 0 {
			used, err := tx.CountAllowedActions(ctx, tenantID, run.ID, tool.ID, toolAction.ID)
			if err != nil {
				return gateResult{decision: fail("call budget lookup failed", ""), stop: true}
			}
			if used >= matched.CallLimitPerRun {
				return gateResult{decision: deny("per-run call limit exceeded", ""), stop: true}
			}
		}
		return gateResult{}
	}); stop {
		return d
	}

	// 6. Budget policies: narrowest applicable scope (grant > version >
	// tenant) wins per dimension; any exhaustion fails closed with an
	// auditable reason code.
	if d, stop := gate("budget", func() gateResult {
		policy, err := s.GetEffectiveBudgetTx(ctx, tx, tenantID, grant.AgentVersionID, matched.ID)
		if err != nil {
			return gateResult{decision: fail("budget lookup failed", ""), stop: true}
		}
		if policy.MaxRunDurationSeconds > 0 &&
			s.now().UTC().Sub(run.StartedAt) > time.Duration(policy.MaxRunDurationSeconds)*time.Second {
			return gateResult{decision: denyBudget("run duration budget exceeded", "budget_exhausted:max_run_duration_seconds"), stop: true}
		}
		if policy.MaxActionsPerRun > 0 {
			used, err := tx.GetBudgetCounter(ctx, tenantID, run.ID, "", runtime.BudgetCounterActions)
			if err != nil {
				return gateResult{decision: fail("budget lookup failed", ""), stop: true}
			}
			if used >= policy.MaxActionsPerRun {
				return gateResult{decision: denyBudget("per-run action budget exceeded", "budget_exhausted:max_actions_per_run"), stop: true}
			}
		}
		if policy.MaxDeniedPerRun > 0 {
			used, err := tx.GetBudgetCounter(ctx, tenantID, run.ID, "", runtime.BudgetCounterDenied)
			if err != nil {
				return gateResult{decision: fail("budget lookup failed", ""), stop: true}
			}
			if used >= policy.MaxDeniedPerRun {
				return gateResult{decision: denyBudget("per-run denied budget exceeded", "budget_exhausted:max_denied_per_run"), stop: true}
			}
		}
		if policy.MaxApprovalRequiredPerRun > 0 {
			used, err := tx.GetBudgetCounter(ctx, tenantID, run.ID, "", runtime.BudgetCounterApprovalRequired)
			if err != nil {
				return gateResult{decision: fail("budget lookup failed", ""), stop: true}
			}
			if used >= policy.MaxApprovalRequiredPerRun {
				return gateResult{decision: denyBudget("per-run approval-required budget exceeded", "budget_exhausted:max_approval_required_per_run"), stop: true}
			}
		}
		if policy.MaxToolCallsPerActionPerRun > 0 {
			used, err := tx.GetBudgetCounter(ctx, tenantID, run.ID, budgetKey(tool.ID, toolAction.ID), runtime.BudgetCounterToolCalls)
			if err != nil {
				return gateResult{decision: fail("budget lookup failed", ""), stop: true}
			}
			if used >= policy.MaxToolCallsPerActionPerRun {
				return gateResult{decision: denyBudget("per-tool-call budget exceeded", "budget_exhausted:max_tool_calls_per_action_per_run"), stop: true}
			}
		}
		if actionName == runtime.BuiltinSearchAction && policy.MaxCitationsPerQuery > 0 {
			used, err := tx.GetBudgetCounter(ctx, tenantID, run.ID, "", runtime.BudgetCounterCitations)
			if err != nil {
				return gateResult{decision: fail("budget lookup failed", ""), stop: true}
			}
			if used >= policy.MaxCitationsPerQuery {
				return gateResult{decision: denyBudget("citation budget exhausted", "budget_exhausted:max_citations_per_query"), stop: true}
			}
		}
		return gateResult{}
	}); stop {
		return d
	}

	// 7. Relationship authorization: the checked subject is the VERIFIED
	// delegated principal (subject_principal_id) — never a
	// body-supplied identifier, never the agent.
	if d, stop := gate("relationship", func() gateResult {
		if s.authorizer == nil {
			return gateResult{decision: fail("permission backend unavailable", ""), stop: true}
		}
		req := relationship.CheckRequest{
			TenantID:   tenantID,
			Subject:    relationship.UserRef(grant.SubjectPrincipalID),
			Permission: relationship.PermissionUse,
			Resource:   relationship.ToolRef(tool.ID),
		}
		if !toolAction.ReadOnly {
			req.Permission = relationship.PermissionExecute
			req.Resource = relationship.ToolActionRef(tool.ID, toolAction.Action)
		}
		allowed, err := s.authorizer.Check(ctx, req)
		if err != nil || !allowed {
			return gateResult{decision: deny("relationship permission denied", ""), stop: true}
		}
		return gateResult{}
	}); stop {
		return d
	}

	// 8. Required one-time human approval.
	if d, stop := gate("approval", func() gateResult {
		requiresApproval := matched.RequiresApproval || toolAction.RequiresHumanApproval
		if !requiresApproval {
			return gateResult{}
		}
		approval, err := tx.GetApprovalForConsume(ctx, tenantID, run.ID, tool.ID, toolAction.ID, action.ResourceRef)
		if err == nil {
			if err := tx.ConsumeApproval(ctx, tenantID, approval.ID); err != nil {
				return gateResult{decision: fail("approval consume failed", ""), stop: true}
			}
		} else if errors.Is(err, runtime.ErrApprovalNotFound) {
			if denied, err := tx.GetDeniedApproval(ctx, tenantID, run.ID, tool.ID, toolAction.ID, action.ResourceRef); err == nil && !denied.CreatedAt.IsZero() {
				return gateResult{decision: deny("human approval denied", ""), stop: true}
			}
			decision, _ := tx.AppendDecision(ctx, runtime.ActionDecision{
				TenantID:          tenantID,
				AgentID:           grant.AgentID,
				RunID:             run.ID,
				DelegationGrantID: grant.ID,
				ToolID:            tool.ID,
				ActionID:          toolAction.ID,
				ResourceRef:       action.ResourceRef,
				Decision:          runtime.DecisionApprovalRequired,
				Reason:            "human approval required",
				PolicyVersion:     s.policyVersion,
				DelegationDepth:   grant.DelegationDepth,
				ChainVerified:     run.ChainVerified,
			})
			return gateResult{decision: finalize(decision, tool.ID, toolAction.ID), stop: true}
		} else {
			return gateResult{decision: fail("approval lookup failed", ""), stop: true}
		}
		return gateResult{}
	}); stop {
		return d
	}

	decision, _ := tx.AppendDecision(ctx, runtime.ActionDecision{
		TenantID:          tenantID,
		AgentID:           grant.AgentID,
		RunID:             run.ID,
		DelegationGrantID: grant.ID,
		ToolID:            tool.ID,
		ActionID:          toolAction.ID,
		ResourceRef:       action.ResourceRef,
		Decision:          runtime.DecisionAllowed,
		Reason:            "allowed",
		PolicyVersion:     s.policyVersion,
		DelegationDepth:   grant.DelegationDepth,
		ChainVerified:     run.ChainVerified,
	})
	return finalize(decision, tool.ID, toolAction.ID)
}

// EvaluateDelegatedQuery gates the retrieval path under a delegation.
// It is the single enforcement point shared by /v1/query and MCP
// groundwork_search: the builtin groundwork_search:search action is
// evaluated for the run; on allow, the returned subject is the verified
// delegated principal the engine runs the query as.
func (s *Service) EvaluateDelegatedQuery(ctx context.Context, tenantID, region, token, runID, question string) (runtime.DelegatedQueryResult, error) {
	// Phase 8.2: the evidence pipeline must be able to absorb this
	// decision. A backed-up outbox refuses new work fail-closed.
	if s.backpressure != nil {
		if err := s.backpressure.Allow(ctx, tenantID); err != nil {
			if errors.Is(err, outbox.ErrBackpressureExceeded) {
				return runtime.DelegatedQueryResult{}, runtime.ErrOutboxBackpressure
			}
			return runtime.DelegatedQueryResult{}, err
		}
	}
	claims, err := s.authority.Verify(ctx, token)
	if err != nil {
		return runtime.DelegatedQueryResult{}, err
	}
	if claims.TenantID != tenantID {
		return runtime.DelegatedQueryResult{}, runtime.ErrDelegationInvalid
	}
	if claims.Region != region {
		return runtime.DelegatedQueryResult{}, runtime.ErrDelegationRegion
	}
	var result runtime.DelegatedQueryResult
	err = s.store.Transact(ctx, "run:"+runID, func(tx TxStore) error {
		grant, err := tx.GetDelegationGrantByJTI(ctx, tenantID, claims.ID)
		if err != nil {
			return err
		}
		run, err := tx.GetRun(ctx, tenantID, runID)
		if err != nil {
			return err
		}
		if ComputePermittedActionsDigest(claims.PermittedActions) != grant.PermittedActionsDigest {
			return runtime.ErrDelegationInvalid
		}
		decision := s.evaluateInTx(ctx, tx, tenantID, region, grant, run, claims.PermittedActions, runtime.RunActionRequest{
			ToolName:    runtime.BuiltinSearchTool,
			Action:      runtime.BuiltinSearchAction,
			ResourceRef: "*",
		})
		result = runtime.DelegatedQueryResult{
			UserID:   grant.SubjectPrincipalID,
			Run:      run,
			Decision: decision,
			Allowed:  decision.Decision == runtime.DecisionAllowed,
		}
		return nil
	})
	if err != nil {
		return runtime.DelegatedQueryResult{}, err
	}
	return result, nil
}

// ---------------------------------------------------------------------
// Approval
// ---------------------------------------------------------------------

func (s *Service) ApproveAction(ctx context.Context, tenantID, runID, actionID, actor string, idempotencyKey string, req runtime.ApproveActionRequest) (runtime.ApproveActionResponse, error) {
	decision := runtime.ApprovalApproved
	return s.recordApproval(ctx, tenantID, runID, actionID, actor, idempotencyKey, decision, req)
}

func (s *Service) DenyAction(ctx context.Context, tenantID, runID, actionID, actor string, idempotencyKey string, req runtime.ApproveActionRequest) (runtime.ApproveActionResponse, error) {
	decision := runtime.ApprovalDenied
	return s.recordApproval(ctx, tenantID, runID, actionID, actor, idempotencyKey, decision, req)
}

func (s *Service) recordApproval(ctx context.Context, tenantID, runID, actionID, actor string, idempotencyKey string, decision string, req runtime.ApproveActionRequest) (runtime.ApproveActionResponse, error) {
	if actor == "" {
		return runtime.ApproveActionResponse{}, runtime.ErrInvalidRequest
	}
	resourceRef := strings.TrimSpace(req.ResourceRef)
	if resourceRef == "" {
		resourceRef = "*"
	}
	var approval runtime.ActionApproval
	err := s.store.Transact(ctx, "run:"+runID, func(tx TxStore) error {
		run, err := tx.GetRun(ctx, tenantID, runID)
		if err != nil {
			return err
		}
		if run.Status == runtime.RunStatusCompleted || run.Status == runtime.RunStatusDenied ||
			run.Status == runtime.RunStatusFailed || run.Status == runtime.RunStatusRevoked {
			return runtime.ErrRunNotActive
		}
		toolAction, err := tx.GetToolAction(ctx, tenantID, actionID)
		if err != nil {
			return err
		}
		// Idempotent replay: same tenant/run/action/key returns the
		// existing approval record instead of appending duplicate
		// evidence.
		if idempotencyKey != "" {
			if existing, err := tx.GetApprovalByIdempotencyKey(ctx, tenantID, runID, toolAction.ToolID, actionID, resourceRef, idempotencyKey); err == nil {
				approval = existing
				return nil
			}
		}
		approval = runtime.ActionApproval{
			TenantID:             tenantID,
			RunID:                runID,
			ToolID:               toolAction.ToolID,
			ActionID:             actionID,
			ResourceRef:          resourceRef,
			ApprovingPrincipalID: actor,
			Decision:             decision,
			ExpiresAt:            s.now().UTC().Add(runtime.ApprovalTTL).Truncate(time.Microsecond),
			IdempotencyKey:       idempotencyKey,
		}
		approval, err = tx.AppendApproval(ctx, approval)
		if err != nil {
			return err
		}
		gwmetrics.RecordEvidenceEvent(tenantID, runtime.EvidenceKindApproval)
		s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventApprovalRecorded, approval.ID+":approval", approval.CreatedAt, map[string]string{
			"approval_id": approval.ID, "run_id": runID, "tenant_id": tenantID,
			"tool_id": approval.ToolID, "action_id": actionID, "resource_ref": approval.ResourceRef,
			"decision": approval.Decision, "approving_principal_id": actor,
			"immutable_digest": approval.ImmutableDigest,
		})
		return nil
	})
	if err != nil {
		return runtime.ApproveActionResponse{}, err
	}
	return runtime.ApproveActionResponse{Approval: approval, Denied: approval.Decision == runtime.ApprovalDenied}, nil
}

// ---------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------

// DispatchAction runs the FULL shared pipeline: evaluate (in-tx,
// evidence + budgets + outbox), then — only for an ALLOWED decision on
// an http/mcp connector-backed tool — the connector gateway
// (Phase 5). The gateway re-validates connector lifecycle, region, and
// manifest with a fresh read and fails closed before opening any
// outbound connection. The invocation outcome is recorded as immutable
// evidence (connector_invocations) in its own transaction.
func (s *Service) DispatchAction(ctx context.Context, tenantID, region string, req runtime.EvaluateActionRequest) (runtime.DispatchResponse, error) {
	evaluated, err := s.EvaluateAction(ctx, tenantID, region, req)
	if err != nil {
		return runtime.DispatchResponse{}, err
	}
	if !evaluated.Allowed {
		return runtime.DispatchResponse{Decision: evaluated.Decision, Allowed: false}, nil
	}
	tool, err := s.store.GetToolByName(ctx, tenantID, strings.TrimSpace(req.ToolName))
	if err != nil {
		return runtime.DispatchResponse{Decision: evaluated.Decision, Allowed: false}, err
	}
	// Builtin/internal tools are governed end-to-end (the call path is
	// the query gate); there is no external surface to reach.
	if tool.Transport != runtime.ToolTransportHTTP && tool.Transport != runtime.ToolTransportMCP {
		return runtime.DispatchResponse{Decision: evaluated.Decision, Allowed: true, DispatchMode: "dispatched"}, nil
	}
	// Connector-backed tool: fail closed if the gateway is not wired.
	if s.dispatcher == nil {
		return s.recordConnectorDispatch(ctx, tenantID, region, evaluated.Decision, tool, req, runtime.ConnectorDispatchResult{
			Outcome: runtime.InvocationFailure, ErrorCode: "connector_dispatcher_unavailable",
		}), nil
	}
	// Phase 8.2 idempotency: the semantic key covers the client-retry
	// window where the previous call already executed and was recorded.
	// A success under this key is replayed from evidence — no quota
	// consumed, no connector call, no second invocation row. Failure
	// outcomes never replay: the retry is a fresh attempt. The
	// in-process lock serializes same-key goroutines so the connector
	// is called at most once per key; the PG partial unique index
	// (migration 028) closes the cross-instance window.
	key := s.dispatchDedupKey(tenantID, evaluated.Decision, req)
	lk := s.lockDispatch(key)
	defer s.unlockDispatch(key, lk)
	lk.mu.Lock()
	defer lk.mu.Unlock()
	if inv, ok, err := s.store.GetConnectorInvocationByDedupKey(ctx, tenantID, key); err != nil {
		return runtime.DispatchResponse{Decision: evaluated.Decision, Allowed: false}, err
	} else if ok && inv.Outcome == runtime.InvocationSuccess {
		gwmetrics.RecordConnectorDispatchReplay(tenantID)
		inv.ConnectorName = tool.Name
		return runtime.DispatchResponse{
			Decision:     evaluated.Decision,
			Allowed:      true,
			DispatchMode: "replayed",
			Invocation:   &inv,
		}, nil
	}
	// Phase 8.1: the connector_calls quota is enforced fail-closed HERE,
	// before any outbound connection opens. An over-quota tenant never
	// reaches the gateway; the denial is recorded as immutable
	// invocation evidence (error code quota_exceeded:connector_calls).
	if s.usageMeter != nil {
		if err := s.usageMeter.Record(ctx, tenantID, usage.MetricConnectorCalls, 1); err != nil {
			var qe *usage.QuotaError
			if errors.As(err, &qe) {
				return s.recordConnectorDispatch(ctx, tenantID, region, evaluated.Decision, tool, req, runtime.ConnectorDispatchResult{
					Outcome: runtime.InvocationFailure, ErrorCode: "quota_exceeded:" + qe.Metric,
				}), nil
			}
			// A non-quota metering failure never blocks the operation:
			// the call proceeds unconstrained (metering is
			// best-effort, the quota check is what is strict).
		}
	}
	result, dispatchErr := s.dispatcher.Dispatch(ctx, runtime.ConnectorDispatchRequest{
		TenantID:       tenantID,
		Region:         region,
		ConnectorName:  strings.TrimSpace(req.ToolName),
		ToolID:         evaluated.Decision.ToolID,
		ToolActionID:   evaluated.Decision.ActionID,
		Action:         strings.TrimSpace(req.Action),
		ResourceRef:    req.ResourceRef,
		RunID:          req.RunID,
		DecisionID:     evaluated.Decision.ID,
		Arguments:      req.Arguments,
		TraceID:        req.TraceID,
		PrincipalID:    evaluated.Decision.AgentID,
		IdempotencyKey: key,
	})
	if dispatchErr != nil {
		if result.Outcome == "" {
			result = runtime.ConnectorDispatchResult{
				Outcome: runtime.InvocationFailure, ErrorCode: "connector_dispatch_failed",
			}
		}
	}
	resp := s.recordConnectorDispatch(ctx, tenantID, region, evaluated.Decision, tool, req, result)
	if resp.DispatchMode == "connector_evidence_failed" {
		// The invocation row lost the insert race (another instance
		// recorded the same key between our read and our write): the
		// other side won, so answer from its recorded evidence. A
		// genuine storage failure also returns here fail-closed; both
		// paths fall back to the replay read.
		if inv, ok, rerr := s.store.GetConnectorInvocationByDedupKey(ctx, tenantID, key); rerr != nil {
			return resp, rerr
		} else if ok && inv.Outcome == runtime.InvocationSuccess {
			gwmetrics.RecordConnectorDispatchReplay(tenantID)
			inv.ConnectorName = tool.Name
			return runtime.DispatchResponse{
				Decision:     evaluated.Decision,
				Allowed:      true,
				DispatchMode: "replayed",
				Invocation:   &inv,
			}, nil
		}
	}
	return resp, nil
}

// dispatchDedupKey derives the semantic idempotency key for a logical
// mutation: tenant + run + tool + action + resource + canonicalized
// arguments. json.Marshal sorts map keys, so the same logical call
// always hashes to the same key even when the gateway mints a new
// decision id on retry.
func (s *Service) dispatchDedupKey(tenantID string, decision runtime.ActionDecision, req runtime.EvaluateActionRequest) string {
	argsJSON, err := json.Marshal(req.Arguments)
	if err != nil {
		argsJSON = []byte("unmarshalable-args")
	}
	h := sha256.New()
	h.Write([]byte(tenantID))
	h.Write([]byte{0})
	h.Write([]byte(decision.RunID))
	h.Write([]byte{0})
	h.Write([]byte(decision.ToolID))
	h.Write([]byte{0})
	h.Write([]byte(decision.ActionID))
	h.Write([]byte{0})
	h.Write([]byte(req.ResourceRef))
	h.Write([]byte{0})
	h.Write(argsJSON)
	return hex.EncodeToString(h.Sum(nil))
}

// recordConnectorDispatch persists the invocation outcome as immutable
// evidence + outbox event and returns the dispatch response with the
// size-limited redacted payload (success only).
func (s *Service) recordConnectorDispatch(ctx context.Context, tenantID, region string, decision runtime.ActionDecision, tool runtime.Tool, req runtime.EvaluateActionRequest, result runtime.ConnectorDispatchResult) runtime.DispatchResponse {
	inv := runtime.ConnectorInvocation{
		TenantID:      tenantID,
		ConnectorID:   result.ConnectorID,
		ToolID:        decision.ToolID,
		ToolActionID:  decision.ActionID,
		RunID:         decision.RunID,
		DecisionID:    decision.ID,
		Kind:          runtime.InvocationKindAgentAction,
		Outcome:       result.Outcome,
		StatusCode:    result.StatusCode,
		ErrorCode:     result.ErrorCode,
		DurationMS:    result.DurationMS,
		ResponseBytes: result.ResponseBytes,
		Region:        region,
		TraceID:       req.TraceID,
		OccurredAt:    s.now().UTC(),
		// Phase 8.2: the semantic key lets later retries of the same
		// logical mutation be replayed from evidence instead of
		// re-calling the connector. Deliberately excluded from the
		// immutable digest (old rows stay verifiable).
		IdempotencyKey: s.dispatchDedupKey(tenantID, decision, req),
	}
	if inv.Outcome == "" {
		inv.Outcome = runtime.InvocationFailure
	}
	if inv.ConnectorID == "" {
		// The gateway failed before resolving the connector: record the
		// tool id so the chain still shows where the call stopped.
		inv.ConnectorID = "tool:" + tool.ID
	}
	err := s.store.Transact(ctx, "connector:"+decision.ID, func(tx TxStore) error {
		if _, err := tx.AppendConnectorInvocation(ctx, inv); err != nil {
			return err
		}
		s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventConnectorInvocation, inv.DecisionID+":connector", inv.OccurredAt, map[string]string{
			"connector_id": inv.ConnectorID, "tool_id": inv.ToolID, "run_id": inv.RunID,
			"decision_id": inv.DecisionID, "outcome": inv.Outcome, "error_code": inv.ErrorCode,
			"region": region, "trace_id": inv.TraceID,
		})
		return nil
	})
	if err != nil {
		return runtime.DispatchResponse{Decision: decision, Allowed: true, DispatchMode: "connector_evidence_failed"}
	}
	mode := "dispatched"
	if inv.Outcome != runtime.InvocationSuccess {
		mode = "connector_failed"
	}
	inv.ConnectorName = tool.Name
	return runtime.DispatchResponse{
		Decision:     decision,
		Allowed:      true,
		DispatchMode: mode,
		Invocation:   &inv,
		Response:     result.Response,
	}
}

// RecordConnectorInvocation persists a non-agent connector outcome
// (health checks) as immutable evidence. decision_id must be unique
// per tenant; health probes use "health:<connector_id>:<ts>".
func (s *Service) RecordConnectorInvocation(ctx context.Context, tenantID, region string, inv runtime.ConnectorInvocation) error {
	inv.TenantID = tenantID
	if inv.Region == "" {
		inv.Region = region
	}
	if inv.OccurredAt.IsZero() {
		inv.OccurredAt = s.now().UTC()
	}
	return s.store.Transact(ctx, "connector:"+inv.DecisionID, func(tx TxStore) error {
		if _, err := tx.AppendConnectorInvocation(ctx, inv); err != nil {
			return err
		}
		s.enqueueOutbox(ctx, tx, tenantID, runtime.OutboxEventConnectorInvocation, inv.DecisionID+":connector", inv.OccurredAt, map[string]string{
			"connector_id": inv.ConnectorID, "tool_id": inv.ToolID, "run_id": inv.RunID,
			"decision_id": inv.DecisionID, "outcome": inv.Outcome, "error_code": inv.ErrorCode,
			"region": inv.Region, "trace_id": inv.TraceID, "kind": inv.Kind,
		})
		return nil
	})
}

// ListConnectorInvocations returns the recent immutable invocation
// outcomes for one connector (newest first, capped at limit).
func (s *Service) ListConnectorInvocations(ctx context.Context, tenantID, connectorID string, limit int) ([]runtime.ConnectorInvocation, error) {
	return s.store.ListConnectorInvocations(ctx, tenantID, connectorID, limit)
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

func isValidTransport(transport string) bool {
	switch transport {
	case runtime.ToolTransportHTTP, runtime.ToolTransportMCP, runtime.ToolTransportBuiltin, runtime.ToolTransportInternal:
		return true
	}
	return false
}

func isValidRiskLevel(level string) bool {
	switch level {
	case runtime.RiskLevelLow, runtime.RiskLevelMedium, runtime.RiskLevelHigh, runtime.RiskLevelCritical:
		return true
	}
	return false
}

func isValidToolLifecycle(lifecycle string) bool {
	switch lifecycle {
	case runtime.ToolLifecycleDraft, runtime.ToolLifecycleActive, runtime.ToolLifecycleSuspended, runtime.ToolLifecycleRevoked:
		return true
	}
	return false
}

// splitToolAction splits a "tool:action" entry on the LAST colon so tool
// names containing ":" still resolve.
func splitToolAction(entry string) (string, string) {
	index := strings.LastIndex(entry, ":")
	if index < 0 {
		return entry, ""
	}
	return entry[:index], entry[index+1:]
}

func normalizePermittedActions(actions []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, action := range actions {
		action = strings.TrimSpace(action)
		if action == "" || seen[action] {
			continue
		}
		seen[action] = true
		out = append(out, action)
	}
	return out
}

// scopeMatches reports whether a resource reference falls inside a
// grant's resource scope: "*" matches everything, "prefix" matches any
// reference starting with it (resource scopes are hierarchical).
func scopeMatches(scope, ref string) bool {
	if scope == "" || scope == "*" {
		return true
	}
	return strings.HasPrefix(ref, scope)
}

func regionMatches(constraint, region string) bool {
	if constraint == "" || constraint == "*" {
		return true
	}
	return constraint == region
}
