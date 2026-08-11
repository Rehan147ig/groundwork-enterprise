package runtime

import (
	"context"
	"errors"
	"time"
)

// ---------------------------------------------------------------------
// Agent Registry (Phase 1: Agent Trust and Control Plane).
//
// Every AI agent is a first-class, tenant-scoped identity with an
// accountable owner, declared purpose, lifecycle state, version history,
// and a tamper-evident audit trail of every lifecycle change.
//
// Package layering mirrors the Audit Read API: the runtime package
// defines the AgentRegistry interface, the model types, and the JSON
// DTOs. The implementation lives in internal/agentregistry (Postgres
// store + transition service) and is wired into Server via
// SetAgentRegistry from cmd/query-runtime. This keeps runtime free of a
// package dependency on the registry implementation.
//
// Security invariants (enforced by the service, verified by tests):
//   - Every table and every query is tenant-scoped. tenant_id comes only
//     from the verified API-key context, never from bodies or URLs.
//   - Agents never auto-activate on creation; creation always lands in
//     lifecycle_state=draft.
//   - Lifecycle transitions require the agent owner OR a key with the
//     admin scope (hasScope's existing admin override).
//   - Revocation is irreversible for both agents and versions.
//   - Every lifecycle change appends a hash-chained, write-once event to
//     agent_lifecycle_events.
//   - Missing auth/tenant/identity/authorization fails closed (401/403).
// ---------------------------------------------------------------------

// Agent lifecycle states.
const (
	AgentStateDraft           = "draft"
	AgentStatePendingApproval = "pending_approval"
	AgentStateActive          = "active"
	AgentStateSuspended       = "suspended"
	AgentStateRevoked         = "revoked"
	AgentStateRetired         = "retired"
)

// Agent version statuses.
const (
	VersionStatusDraft      = "draft"
	VersionStatusApproved   = "approved"
	VersionStatusActive     = "active"
	VersionStatusSuperseded = "superseded"
	VersionStatusRevoked    = "revoked"
)

// Risk tiers and environments.
const (
	RiskTierLow      = "low"
	RiskTierMedium   = "medium"
	RiskTierHigh     = "high"
	RiskTierCritical = "critical"

	EnvDevelopment = "development"
	EnvStaging     = "staging"
	EnvProduction  = "production"
)

// Lifecycle event types recorded on agent_lifecycle_events. Version
// events carry agent_version_id and previous_state/new_state refer to the
// version status; agent events refer to the agent lifecycle_state.
const (
	EventCreated           = "created"
	EventActivated         = "activated"
	EventSuspended         = "suspended"
	EventRevoked           = "revoked"
	EventRetired           = "retired"
	EventVersionCreated    = "version_created"
	EventVersionApproved   = "version_approved"
	EventVersionActivated  = "version_activated"
	EventVersionSuperseded = "version_superseded"
	EventVersionRevoked    = "version_revoked"
)

// Agent is a tenant-scoped agent identity in the registry.
type Agent struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	OwnerPrincipalID string    `json:"owner_principal_id"`
	BusinessPurpose  string    `json:"business_purpose"`
	RiskTier         string    `json:"risk_tier"`
	LifecycleState   string    `json:"lifecycle_state"`
	Environment      string    `json:"environment"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	ActivatedAt      time.Time `json:"activated_at,omitempty"`
	RevokedAt        time.Time `json:"revoked_at,omitempty"`
	ActiveVersionID  string    `json:"active_version_id,omitempty"`
	ActiveVersion    string    `json:"active_version,omitempty"`
	VersionCount     int       `json:"version_count"`
}

// AgentVersion is one deployable version of an agent.
type AgentVersion struct {
	ID                  string    `json:"id"`
	AgentID             string    `json:"agent_id"`
	Version             string    `json:"version"`
	ModelProvider       string    `json:"model_provider"`
	ModelName           string    `json:"model_name"`
	PromptDigest        string    `json:"prompt_digest"`
	ToolManifestDigest  string    `json:"tool_manifest_digest"`
	PolicyBundleVersion string    `json:"policy_bundle_version"`
	ArtifactDigest      string    `json:"artifact_digest"`
	Status              string    `json:"status"`
	CreatedAt           time.Time `json:"created_at"`
	ApprovedAt          time.Time `json:"approved_at,omitempty"`
}

// LifecycleEvent is one append-only, hash-chained lifecycle event.
type LifecycleEvent struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	AgentID         string    `json:"agent_id"`
	AgentVersionID  string    `json:"agent_version_id,omitempty"`
	ActorPrincipal  string    `json:"actor_principal_id"`
	EventType       string    `json:"event_type"`
	PreviousState   string    `json:"previous_state"`
	NewState        string    `json:"new_state"`
	Reason          string    `json:"reason"`
	ImmutableDigest string    `json:"immutable_digest"`
	CreatedAt       time.Time `json:"created_at"`
}

// AgentRegistry is the control-plane contract the /v1/agents endpoints
// dispatch through. Implementations (internal/agentregistry) own tenant
// scoping, state-transition validation, owner/admin authorization, and
// the tamper-evident event chain. tenantID/actor always come from the
// request context resolved in the HTTP layer — never from bodies.
type AgentRegistry interface {
	CreateAgent(ctx context.Context, tenantID string, actor string, req CreateAgentRequest) (Agent, error)
	ListAgents(ctx context.Context, tenantID string, state string) ([]Agent, error)
	GetAgent(ctx context.Context, tenantID string, agentID string) (Agent, []AgentVersion, []LifecycleEvent, error)
	AddVersion(ctx context.Context, tenantID, agentID, actor string, admin bool, req AddAgentVersionRequest) (AgentVersion, error)
	ActivateAgent(ctx context.Context, tenantID, agentID, actor string, admin bool, reason string) (Agent, error)
	SuspendAgent(ctx context.Context, tenantID, agentID, actor string, admin bool, reason string) (Agent, error)
	RevokeAgent(ctx context.Context, tenantID, agentID, actor string, admin bool, reason string) (Agent, error)
	RetireAgent(ctx context.Context, tenantID, agentID, actor string, admin bool, reason string) (Agent, error)
}

// ErrAgentNotFound is returned when the agent_id does not exist in the
// caller's tenant. Handlers map it to 404. Same sentinel for version and
// event lookups attached to a tenant-scoped agent.
var ErrAgentNotFound = errors.New("agent_not_found")

// ErrAgentNameConflict is returned when creating an agent whose name
// already exists in the tenant. Handlers map it to 409.
var ErrAgentNameConflict = errors.New("agent_name_conflict")

// ErrAgentNotAuthorized is returned when the actor is neither the agent
// owner nor a tenant administrator (admin-scoped key). Handlers map it
// to 403.
var ErrAgentNotAuthorized = errors.New("agent_operation_not_authorized")

// ErrAgentInvalidTransition is returned when a lifecycle transition is
// not permitted from the agent's current state (or a version operation
// violates a version status rule, e.g. activating an agent with no
// usable version). Handlers map it to 400.
var ErrAgentInvalidTransition = errors.New("invalid_agent_state_transition")

// ErrAgentVersionNotFound is returned for version-level lookups that do
// not exist in the tenant's agent. Handlers map it to 404.
var ErrAgentVersionNotFound = errors.New("agent_version_not_found")

// ErrAgentVersionConflict is returned when creating a version whose
// version string already exists for the agent. Handlers map it to 409.
var ErrAgentVersionConflict = errors.New("agent_version_conflict")

// ErrAgentInvalidRequest is returned when a request body is structurally
// invalid (empty name, unknown risk tier/environment/state filter).
// Handlers map it to 400.
var ErrAgentInvalidRequest = errors.New("invalid_agent_request")

// ErrAgentUnavailable is returned when the registry is not wired
// (in-memory/local mode without a database). Handlers map it to 503.
var ErrAgentUnavailable = errors.New("agent_registry_unavailable")

// ---------------------------------------------------------------------
// JSON contract: request/response DTOs. Separate from the in-process
// model so the wire format is stable.
// ---------------------------------------------------------------------

// CreateAgentRequest is the POST /v1/agents body. Tenant-affecting and
// authority-affecting fields are NOT accepted: tenant_id always comes
// from the API key; lifecycle_state is always draft on creation (agents
// never auto-activate); owner_principal_id, when omitted, defaults to
// the authenticated actor's principal. The body is never a source of
// security authority.
type CreateAgentRequest struct {
	Name             string `json:"name"`
	Description      string `json:"description,omitempty"`
	OwnerPrincipalID string `json:"owner_principal_id,omitempty"`
	BusinessPurpose  string `json:"business_purpose,omitempty"`
	RiskTier         string `json:"risk_tier"`
	Environment      string `json:"environment,omitempty"`
}

// AddAgentVersionRequest is the POST /v1/agents/{id}/versions body.
type AddAgentVersionRequest struct {
	Version             string `json:"version"`
	ModelProvider       string `json:"model_provider,omitempty"`
	ModelName           string `json:"model_name,omitempty"`
	PromptDigest        string `json:"prompt_digest,omitempty"`
	ToolManifestDigest  string `json:"tool_manifest_digest,omitempty"`
	PolicyBundleVersion string `json:"policy_bundle_version,omitempty"`
	ArtifactDigest      string `json:"artifact_digest,omitempty"`
}

// LifecycleActionRequest is the body for the action endpoints
// (activate/suspend/revoke/retire). Only a human-readable reason is
// accepted; state is derived from the agent, never from the body.
type LifecycleActionRequest struct {
	Reason string `json:"reason,omitempty"`
}

// AgentResponse wraps a single agent (POST create, action endpoints).
type AgentResponse struct {
	Agent Agent `json:"agent"`
}

// AgentListResponse is the GET /v1/agents shape.
type AgentListResponse struct {
	Agents []Agent `json:"agents"`
	Count  int     `json:"count"`
}

// AgentVersionResponse wraps a single version (POST versions).
type AgentVersionResponse struct {
	Version AgentVersion `json:"version"`
}

// AgentDetailResponse is the GET /v1/agents/{agent_id} shape.
type AgentDetailResponse struct {
	Agent           Agent            `json:"agent"`
	Versions        []AgentVersion   `json:"versions"`
	LifecycleEvents []LifecycleEvent `json:"lifecycle_events"`
}

// AgentAPIError is the consistent error envelope for /v1/agents.
type AgentAPIError struct {
	Error string `json:"error"`
}

// SetAgentRegistry wires the registry the /v1/agents endpoints dispatch
// through. Nil-safe: when unset, the endpoints return 503
// agent_registry_unavailable.
func (s *Server) SetAgentRegistry(r AgentRegistry) { s.agentRegistry = r }

// agentScope is the API-key scope required for /v1/agents endpoints.
// hasScope's existing "admin" override grants access too, so bootstrap
// and admin keys work unchanged.
const agentScope = "agents"
