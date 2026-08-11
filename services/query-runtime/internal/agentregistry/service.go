package agentregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// Service implements runtime.AgentRegistry on top of a Store. It owns
// the security invariants of the Agent Registry:
//
//   - tenant scoping: every operation takes tenantID from the caller's
//     verified API-key context and every store call filters by it;
//   - fail-closed creation: agents always start in draft and never
//     auto-activate;
//   - authorization: lifecycle transitions require the agent owner or a
//     tenant administrator (admin-scoped key);
//   - irreversible revocation: revoked agents and versions accept no
//     further transitions;
//   - tamper-evident audit: every lifecycle change appends a
//     hash-chained, write-once event.
//
// Multi-step transitions run inside Store.Transact so the state read,
// the state updates, and the event chain append are one atomic,
// per-agent-serialized step.
type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

var validRiskTiers = map[string]bool{
	runtime.RiskTierLow: true, runtime.RiskTierMedium: true,
	runtime.RiskTierHigh: true, runtime.RiskTierCritical: true,
}

var validEnvironments = map[string]bool{
	runtime.EnvDevelopment: true, runtime.EnvStaging: true, runtime.EnvProduction: true,
}

var validStates = map[string]bool{
	runtime.AgentStateDraft: true, runtime.AgentStatePendingApproval: true,
	runtime.AgentStateActive: true, runtime.AgentStateSuspended: true,
	runtime.AgentStateRevoked: true, runtime.AgentStateRetired: true,
}

func isTerminalState(state string) bool {
	return state == runtime.AgentStateRevoked || state == runtime.AgentStateRetired
}

// authorize returns nil when actor is the agent owner or a tenant
// administrator (admin-scoped API key).
func authorize(agent runtime.Agent, actor string, admin bool) error {
	if admin {
		return nil
	}
	if actor != "" && actor == agent.OwnerPrincipalID {
		return nil
	}
	return runtime.ErrAgentNotAuthorized
}

func nowTime() time.Time {
	return time.Now().UTC().Truncate(time.Microsecond)
}

// lifecycleOutboxEvent maps a hash-chained LifecycleEvent to a safe
// outbox event (agent.lifecycle). The payload carries metadata ONLY —
// never prompts, digests, or other sensitive content.
func lifecycleOutboxEvent(e runtime.LifecycleEvent) runtime.OutboxEvent {
	payload, _ := json.Marshal(struct {
		AgentID        string `json:"agent_id,omitempty"`
		AgentVersionID string `json:"agent_version_id,omitempty"`
		Event          string `json:"event,omitempty"`
		From           string `json:"from,omitempty"`
		To             string `json:"to,omitempty"`
		ActorPrincipal string `json:"actor_principal_id,omitempty"`
	}{
		AgentID: e.AgentID, AgentVersionID: e.AgentVersionID, Event: e.EventType,
		From: e.PreviousState, To: e.NewState, ActorPrincipal: e.ActorPrincipal,
	})
	return runtime.OutboxEvent{
		TenantID:      e.TenantID,
		EventID:       e.ID,
		EventType:     runtime.OutboxEventAgentLifecycle,
		SchemaVersion: 1,
		OccurredAt:    e.CreatedAt,
		Payload:       payload,
	}
}

func enqueueLifecycle(ctx context.Context, tx TxStore, e runtime.LifecycleEvent) error {
	return tx.EnqueueOutbox(ctx, lifecycleOutboxEvent(e))
}

// CreateAgent registers a new agent. The agent always lands in
// lifecycle_state=draft (never auto-activates). owner_principal_id
// defaults to the authenticated actor; the body is never a security
// authority.
func (s *Service) CreateAgent(ctx context.Context, tenantID, actor string, req runtime.CreateAgentRequest) (runtime.Agent, error) {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return runtime.Agent{}, fmt.Errorf("%w: name is required", runtime.ErrAgentInvalidRequest)
	}
	if len(req.Name) > 100 {
		return runtime.Agent{}, fmt.Errorf("%w: name exceeds 100 characters", runtime.ErrAgentInvalidRequest)
	}
	req.RiskTier = strings.ToLower(strings.TrimSpace(req.RiskTier))
	if !validRiskTiers[req.RiskTier] {
		return runtime.Agent{}, fmt.Errorf("%w: risk_tier must be one of low, medium, high, critical", runtime.ErrAgentInvalidRequest)
	}
	req.Environment = strings.ToLower(strings.TrimSpace(req.Environment))
	if req.Environment == "" {
		req.Environment = runtime.EnvDevelopment
	}
	if !validEnvironments[req.Environment] {
		return runtime.Agent{}, fmt.Errorf("%w: environment must be one of development, staging, production", runtime.ErrAgentInvalidRequest)
	}
	owner := strings.TrimSpace(req.OwnerPrincipalID)
	if owner == "" {
		owner = actor
	}
	if owner == "" {
		return runtime.Agent{}, fmt.Errorf("%w: no actor identity and no owner_principal_id supplied", runtime.ErrAgentInvalidRequest)
	}

	a := runtime.Agent{
		TenantID:         tenantID,
		Name:             req.Name,
		Description:      strings.TrimSpace(req.Description),
		OwnerPrincipalID: owner,
		BusinessPurpose:  strings.TrimSpace(req.BusinessPurpose),
		RiskTier:         req.RiskTier,
		LifecycleState:   runtime.AgentStateDraft,
		Environment:      req.Environment,
	}
	err := s.store.Transact(ctx, "new:"+tenantID, func(tx TxStore) error {
		created, err := tx.CreateAgent(ctx, a)
		if err != nil {
			return err
		}
		a = created
		ev, err := tx.AppendEvent(ctx, runtime.LifecycleEvent{
			TenantID: tenantID, AgentID: created.ID, ActorPrincipal: actor,
			EventType: runtime.EventCreated, NewState: runtime.AgentStateDraft,
		})
		if err != nil {
			return err
		}
		return enqueueLifecycle(ctx, tx, ev)
	})
	if err != nil {
		return runtime.Agent{}, err
	}
	return a, nil
}

// ListAgents lists the tenant's agents, optionally filtered by state.
func (s *Service) ListAgents(ctx context.Context, tenantID, state string) ([]runtime.Agent, error) {
	state = strings.ToLower(strings.TrimSpace(state))
	if state != "" && !validStates[state] {
		return nil, fmt.Errorf("%w: state must be one of draft, pending_approval, active, suspended, revoked, retired", runtime.ErrAgentInvalidRequest)
	}
	return s.store.ListAgents(ctx, tenantID, state)
}

// GetAgent returns the agent with its versions and lifecycle events.
func (s *Service) GetAgent(ctx context.Context, tenantID, agentID string) (runtime.Agent, []runtime.AgentVersion, []runtime.LifecycleEvent, error) {
	agent, err := s.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return runtime.Agent{}, nil, nil, err
	}
	versions, err := s.store.ListVersions(ctx, tenantID, agentID)
	if err != nil {
		return runtime.Agent{}, nil, nil, err
	}
	events, err := s.store.ListEvents(ctx, tenantID, agentID)
	if err != nil {
		return runtime.Agent{}, nil, nil, err
	}
	return agent, versions, events, nil
}

// ListVersions returns the agent's version stream. This is the
// read-only surface the governance evaluator (Phase 2) needs to check
// that a delegation is minted for — and executed by — an active agent
// version; it is also exposed by the agents API consumers as needed.
func (s *Service) ListVersions(ctx context.Context, tenantID, agentID string) ([]runtime.AgentVersion, error) {
	return s.store.ListVersions(ctx, tenantID, agentID)
}

// AddVersion registers a new draft version of an agent. Only the owner
// or a tenant administrator can add versions. A version cannot be added
// to a revoked or retired agent (their version streams are frozen).
// When the agent is active, adding a version supersedes the current
// active version (the new version stays draft until activation).
func (s *Service) AddVersion(ctx context.Context, tenantID, agentID, actor string, admin bool, req runtime.AddAgentVersionRequest) (runtime.AgentVersion, error) {
	agent, err := s.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return runtime.AgentVersion{}, err
	}
	if err := authorize(agent, actor, admin); err != nil {
		return runtime.AgentVersion{}, err
	}
	req.Version = strings.TrimSpace(req.Version)
	if req.Version == "" {
		return runtime.AgentVersion{}, fmt.Errorf("%w: version is required", runtime.ErrAgentInvalidRequest)
	}
	if len(req.Version) > 64 {
		return runtime.AgentVersion{}, fmt.Errorf("%w: version exceeds 64 characters", runtime.ErrAgentInvalidRequest)
	}

	var version runtime.AgentVersion
	err = s.store.Transact(ctx, agentID, func(tx TxStore) error {
		current, err := tx.GetAgent(ctx, tenantID, agentID)
		if err != nil {
			return err
		}
		if isTerminalState(current.LifecycleState) {
			return fmt.Errorf("%w: cannot add a version to a %s agent", runtime.ErrAgentInvalidTransition, current.LifecycleState)
		}
		versions, err := tx.ListVersions(ctx, tenantID, agentID)
		if err != nil {
			return err
		}
		// Active agent + active version: the new version supersedes it.
		if current.LifecycleState == runtime.AgentStateActive {
			for _, v := range versions {
				if v.Status != runtime.VersionStatusActive {
					continue
				}
				if err := tx.UpdateVersionStatus(ctx, tenantID, v.ID, runtime.VersionStatusActive, runtime.VersionStatusSuperseded, nil); err != nil {
					return err
				}
				superseded, err := tx.AppendEvent(ctx, runtime.LifecycleEvent{
					TenantID: tenantID, AgentID: agentID, AgentVersionID: v.ID,
					ActorPrincipal: actor, EventType: runtime.EventVersionSuperseded,
					PreviousState: runtime.VersionStatusActive, NewState: runtime.VersionStatusSuperseded,
				})
				if err != nil {
					return err
				}
				if err := enqueueLifecycle(ctx, tx, superseded); err != nil {
					return err
				}
				break
			}
		}
		version, err = tx.CreateVersion(ctx, runtime.AgentVersion{
			AgentID: agentID, Version: req.Version,
			ModelProvider: strings.TrimSpace(req.ModelProvider), ModelName: strings.TrimSpace(req.ModelName),
			PromptDigest: strings.TrimSpace(req.PromptDigest), ToolManifestDigest: strings.TrimSpace(req.ToolManifestDigest),
			PolicyBundleVersion: strings.TrimSpace(req.PolicyBundleVersion), ArtifactDigest: strings.TrimSpace(req.ArtifactDigest),
			Status: runtime.VersionStatusDraft,
		})
		if err != nil {
			return err
		}
		created, err := tx.AppendEvent(ctx, runtime.LifecycleEvent{
			TenantID: tenantID, AgentID: agentID, AgentVersionID: version.ID,
			ActorPrincipal: actor, EventType: runtime.EventVersionCreated,
			NewState: runtime.VersionStatusDraft,
		})
		if err != nil {
			return err
		}
		return enqueueLifecycle(ctx, tx, created)
	})
	if err != nil {
		return runtime.AgentVersion{}, err
	}
	return version, nil
}

// ActivateAgent transitions draft | pending_approval | suspended ->
// active. Only the owner or a tenant administrator can activate. The
// agent must have at least one usable (non-revoked, non-superseded)
// version; activation promotes the newest such version draft ->
// approved -> active and supersedes any other draft/approved versions,
// so exactly one version is active. Suspended agents resume with their
// existing active version. Agents never auto-activate on creation.
func (s *Service) ActivateAgent(ctx context.Context, tenantID, agentID, actor string, admin bool, reason string) (runtime.Agent, error) {
	return s.transition(ctx, tenantID, agentID, actor, admin, reason,
		func(current runtime.Agent) error {
			switch current.LifecycleState {
			case runtime.AgentStateDraft, runtime.AgentStatePendingApproval, runtime.AgentStateSuspended:
				return nil
			case runtime.AgentStateActive:
				return fmt.Errorf("%w: agent is already active", runtime.ErrAgentInvalidTransition)
			default:
				return fmt.Errorf("%w: activation is not permitted from state %s", runtime.ErrAgentInvalidTransition, current.LifecycleState)
			}
		},
		func(ctx context.Context, tx TxStore, agent runtime.Agent) ([]runtime.LifecycleEvent, error) {
			versions, err := tx.ListVersions(ctx, tenantID, agentID)
			if err != nil {
				return nil, err
			}
			if agent.LifecycleState == runtime.AgentStateSuspended {
				// Resume: keep the existing active version if one exists.
				for _, v := range versions {
					if v.Status == runtime.VersionStatusActive {
						return nil, nil
					}
				}
			}
			// Promote the newest usable version to active.
			var pick *runtime.AgentVersion
			for i := range versions {
				v := &versions[i]
				if v.Status == runtime.VersionStatusRevoked || v.Status == runtime.VersionStatusSuperseded {
					continue
				}
				if pick == nil || v.CreatedAt.After(pick.CreatedAt) {
					pick = v
				}
			}
			if pick == nil {
				return nil, fmt.Errorf("%w: agent has no usable version to activate; create one first", runtime.ErrAgentInvalidTransition)
			}
			var events []runtime.LifecycleEvent
			// Supersede any other non-active, non-revoked versions so
			// exactly one version is active.
			for i := range versions {
				v := &versions[i]
				if v.ID == pick.ID || v.Status == runtime.VersionStatusActive ||
					v.Status == runtime.VersionStatusSuperseded || v.Status == runtime.VersionStatusRevoked {
					continue
				}
				if err := tx.UpdateVersionStatus(ctx, tenantID, v.ID, v.Status, runtime.VersionStatusSuperseded, nil); err != nil {
					return nil, err
				}
				events = append(events, runtime.LifecycleEvent{
					TenantID: tenantID, AgentID: agentID, AgentVersionID: v.ID,
					ActorPrincipal: actor, EventType: runtime.EventVersionSuperseded,
					PreviousState: v.Status, NewState: runtime.VersionStatusSuperseded,
				})
			}
			// draft -> approved -> active (approval by the activating
			// authority, recorded as its own event in the chain).
			expected := pick.Status
			if pick.Status == runtime.VersionStatusDraft {
				approvalTime := nowTime()
				if err := tx.UpdateVersionStatus(ctx, tenantID, pick.ID, runtime.VersionStatusDraft, runtime.VersionStatusApproved, &approvalTime); err != nil {
					return nil, err
				}
				expected = runtime.VersionStatusApproved
				events = append(events, runtime.LifecycleEvent{
					TenantID: tenantID, AgentID: agentID, AgentVersionID: pick.ID,
					ActorPrincipal: actor, EventType: runtime.EventVersionApproved,
					PreviousState: runtime.VersionStatusDraft, NewState: runtime.VersionStatusApproved,
				})
			}
			activationTime := nowTime()
			if err := tx.UpdateVersionStatus(ctx, tenantID, pick.ID, expected, runtime.VersionStatusActive, &activationTime); err != nil {
				return nil, err
			}
			events = append(events, runtime.LifecycleEvent{
				TenantID: tenantID, AgentID: agentID, AgentVersionID: pick.ID,
				ActorPrincipal: actor, EventType: runtime.EventVersionActivated,
				PreviousState: expected, NewState: runtime.VersionStatusActive,
			})
			return events, nil
		},
		runtime.AgentStateActive, runtime.EventActivated, true,
	)
}

// SuspendAgent transitions active -> suspended. Only the owner or a
// tenant administrator can suspend. Versions are preserved; resuming
// reactivates the same active version.
func (s *Service) SuspendAgent(ctx context.Context, tenantID, agentID, actor string, admin bool, reason string) (runtime.Agent, error) {
	return s.transition(ctx, tenantID, agentID, actor, admin, reason,
		func(current runtime.Agent) error {
			if current.LifecycleState != runtime.AgentStateActive {
				return fmt.Errorf("%w: only an active agent can be suspended (current state %s)", runtime.ErrAgentInvalidTransition, current.LifecycleState)
			}
			return nil
		},
		nil,
		runtime.AgentStateSuspended, runtime.EventSuspended, false,
	)
}

// RevokeAgent irreversibly revokes the agent and every non-revoked
// version. Only the owner or a tenant administrator can revoke. A
// revoked agent accepts no further transitions: no activation, no
// suspension, no retirement, no new versions — and no un-revocation.
func (s *Service) RevokeAgent(ctx context.Context, tenantID, agentID, actor string, admin bool, reason string) (runtime.Agent, error) {
	return s.transition(ctx, tenantID, agentID, actor, admin, reason,
		func(current runtime.Agent) error {
			switch current.LifecycleState {
			case runtime.AgentStateRevoked:
				return fmt.Errorf("%w: agent is already revoked", runtime.ErrAgentInvalidTransition)
			case runtime.AgentStateRetired:
				return fmt.Errorf("%w: a retired agent cannot be revoked", runtime.ErrAgentInvalidTransition)
			default:
				return nil
			}
		},
		func(ctx context.Context, tx TxStore, agent runtime.Agent) ([]runtime.LifecycleEvent, error) {
			versions, err := tx.ListVersions(ctx, tenantID, agentID)
			if err != nil {
				return nil, err
			}
			var events []runtime.LifecycleEvent
			for _, v := range versions {
				if v.Status == runtime.VersionStatusRevoked {
					continue
				}
				if err := tx.UpdateVersionStatus(ctx, tenantID, v.ID, v.Status, runtime.VersionStatusRevoked, nil); err != nil {
					return nil, err
				}
				events = append(events, runtime.LifecycleEvent{
					TenantID: tenantID, AgentID: agentID, AgentVersionID: v.ID,
					ActorPrincipal: actor, EventType: runtime.EventVersionRevoked,
					PreviousState: v.Status, NewState: runtime.VersionStatusRevoked,
				})
			}
			return events, nil
		},
		runtime.AgentStateRevoked, runtime.EventRevoked, true,
	)
}

// RetireAgent transitions any non-terminal state -> retired. Only the
// owner or a tenant administrator can retire. Retirement is terminal.
func (s *Service) RetireAgent(ctx context.Context, tenantID, agentID, actor string, admin bool, reason string) (runtime.Agent, error) {
	return s.transition(ctx, tenantID, agentID, actor, admin, reason,
		func(current runtime.Agent) error {
			switch current.LifecycleState {
			case runtime.AgentStateRevoked:
				return fmt.Errorf("%w: a revoked agent cannot be retired", runtime.ErrAgentInvalidTransition)
			case runtime.AgentStateRetired:
				return fmt.Errorf("%w: agent is already retired", runtime.ErrAgentInvalidTransition)
			default:
				return nil
			}
		},
		nil,
		runtime.AgentStateRetired, runtime.EventRetired, false,
	)
}

// transition is the shared driver for lifecycle transitions. It:
//  1. reads the agent (tenant-scoped) and authorizes the actor;
//  2. re-reads under the per-agent lock and validates the source state;
//  3. runs the state-specific version side-effects (versionEvents);
//  4. updates the agent state and appends the agent event — all in one
//     transaction.
func (s *Service) transition(
	ctx context.Context,
	tenantID, agentID, actor string,
	admin bool,
	reason string,
	validate func(current runtime.Agent) error,
	versionEvents func(ctx context.Context, tx TxStore, agent runtime.Agent) ([]runtime.LifecycleEvent, error),
	newState string,
	eventType string,
	activated bool,
) (runtime.Agent, error) {
	agent, err := s.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return runtime.Agent{}, err
	}
	if err := authorize(agent, actor, admin); err != nil {
		return runtime.Agent{}, err
	}

	err = s.store.Transact(ctx, agentID, func(tx TxStore) error {
		current, err := tx.GetAgent(ctx, tenantID, agentID)
		if err != nil {
			return err
		}
		if err := validate(current); err != nil {
			return err
		}
		if versionEvents != nil {
			events, err := versionEvents(ctx, tx, current)
			if err != nil {
				return err
			}
			for _, e := range events {
				stored, err := tx.AppendEvent(ctx, e)
				if err != nil {
					return err
				}
				if err := enqueueLifecycle(ctx, tx, stored); err != nil {
					return err
				}
			}
		}
		var activatedAt, revokedAt *time.Time
		if activated {
			t := nowTime()
			activatedAt = &t
		}
		if newState == runtime.AgentStateRevoked {
			t := nowTime()
			revokedAt = &t
		}
		if err := tx.UpdateAgentState(ctx, tenantID, agentID, current.LifecycleState, newState, activatedAt, revokedAt); err != nil {
			return err
		}
		stored, err := tx.AppendEvent(ctx, runtime.LifecycleEvent{
			TenantID: tenantID, AgentID: agentID, ActorPrincipal: actor,
			EventType: eventType, PreviousState: current.LifecycleState,
			NewState: newState, Reason: strings.TrimSpace(reason),
		})
		if err != nil {
			return err
		}
		return enqueueLifecycle(ctx, tx, stored)
	})
	if err != nil {
		return runtime.Agent{}, err
	}
	return s.store.GetAgent(ctx, tenantID, agentID)
}

// compile-time check: Service satisfies runtime.AgentRegistry.
var _ runtime.AgentRegistry = (*Service)(nil)
