package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// ---------------------------------------------------------------------
// Delegated Authority & Governed Agent Execution (Phase 2).
//
// Package layering mirrors the Agent Registry and Audit Read API: the
// runtime package defines the GovernanceService interface, the model
// types, and the JSON DTOs. The implementation lives in
// internal/governance (Postgres/memory stores + the shared evaluator)
// and is wired into Server via SetGovernanceService from
// cmd/query-runtime. This keeps runtime free of a package dependency on
// the governance implementation.
//
// The core invariant (enforced by the evaluator, verified by tests):
//
//	A tool or retrieval action is allowed only when
//	  - the agent version bound to the delegation is active,
//	  - the delegation token belongs to a verified delegated principal
//	    (subject_principal_id), never a user-controlled identifier,
//	  - the delegation grant is live (signed, unexpired, unrevoked,
//	    bound to the current run),
//	  - the tool + action are registered and active and covered by an
//	    unrevoked agent-tool grant honoring region/purpose constraints
//	    and the per-run call limit,
//	  - the relationship backend confirms the resource permission for
//	    the verified subject (use on the tool for read-only/retrieval
//	    actions, execute on tool_action:<tool>:<action> for write
//	    actions, plus the existing document viewer check for
//	    retrieval), and
//	  - any required one-time human approval exists and is consumed.
//
//	Everything else fails closed and produces tamper-evident evidence
//	on agent_action_decisions. Raw delegation tokens are never logged,
//	stored (only the jti is), or returned after issuance.
//
// Security invariants:
//   - Every table and every query is tenant-scoped; tenant_id and region
//     come only from the verified API-key context.
//   - Delegation minting requires a VERIFIED end-user identity (demo
//     identity can never mint a delegation), and the delegator is the
//     canonicalized verified principal.
//   - Tokens are signed by a dedicated delegation authority (separate
//     issuer/audience/key from the end-user identity verifier), with
//     issuer/audience validation, an algorithm allow-list, and rotation
//     support. Claims bind agent_id, agent_version_id, delegator,
//     subject, purpose, region, and the permitted actions digest.
//   - A token creates exactly one server-generated run (atomic
//     consume); actions inside the run stay valid until expiry or
//     revocation. Idempotency keys make mint/run/approval retries safe.
// ---------------------------------------------------------------------

// Tool transports and lifecycle states.
const (
	ToolTransportHTTP     = "http"
	ToolTransportMCP      = "mcp"
	ToolTransportBuiltin  = "builtin"
	ToolTransportInternal = "internal"

	ToolLifecycleDraft     = "draft"
	ToolLifecycleActive    = "active"
	ToolLifecycleSuspended = "suspended"
	ToolLifecycleRevoked   = "revoked"
)

// Risk levels and action statuses.
const (
	RiskLevelLow      = "low"
	RiskLevelMedium   = "medium"
	RiskLevelHigh     = "high"
	RiskLevelCritical = "critical"

	ActionStatusActive  = "active"
	ActionStatusRetired = "retired"
)

// Delegation TTL constants. The default is the maximum a mint request
// may ask for; the mint request may ask for less, never more.
const (
	DefaultDelegationTTL = 15 * time.Minute
	MaxDelegationTTL     = 15 * time.Minute
	ApprovalTTL          = 15 * time.Minute
)

// Builtin governed retrieval tool: the single tool through which the
// query engine and MCP groundwork_search run under a delegation.
const (
	BuiltinSearchTool   = "groundwork_search"
	BuiltinSearchAction = "search"
)

// Decision outcomes recorded on agent_action_decisions.
const (
	DecisionAllowed          = "allowed"
	DecisionDenied           = "denied"
	DecisionApprovalRequired = "approval_required"
	DecisionFailClosed       = "fail_closed"
)

// Approval decisions recorded on agent_action_approvals.
const (
	ApprovalApproved = "approved"
	ApprovalDenied   = "denied"
)

// Sentinel errors. The HTTP layer maps these to status codes; unknown
// errors never leak DB internals.
var (
	ErrGovernanceUnavailable   = errors.New("governance unavailable")
	ErrGovernanceNotAuthorized = errors.New("governance not authorized")
	ErrInvalidRequest          = errors.New("invalid request")
	ErrIdempotencyConflict     = errors.New("idempotency conflict")

	ErrToolNotFound      = errors.New("tool not found")
	ErrToolNameConflict  = errors.New("tool name already exists")
	ErrToolInactive      = errors.New("tool is not active")
	ErrToolInvalidState  = errors.New("tool lifecycle transition invalid")
	ErrActionNotFound    = errors.New("tool action not found")
	ErrActionConflict    = errors.New("tool action already exists")
	ErrActionInactive    = errors.New("tool action is not active")
	ErrGrantNotFound     = errors.New("agent tool grant not found")
	ErrGrantConflict     = errors.New("agent tool grant already exists")
	ErrGrantRevoked      = errors.New("agent tool grant is revoked")
	ErrGrantRegion       = errors.New("region constraint violation")
	ErrCallLimitExceeded = errors.New("per-run call limit exceeded")

	// Phase 8.2: the tenant's pending outbox is at/above the high-water
	// mark, so new evidence-producing work is refused fail-closed (503
	// outbox_backpressure) instead of deepening the backlog.
	ErrOutboxBackpressure = errors.New("outbox backpressure exceeded")

	ErrDelegationInvalid    = errors.New("invalid delegation token")
	ErrDelegationExpired    = errors.New("delegation expired")
	ErrDelegationRevoked    = errors.New("delegation revoked")
	ErrDelegationReused     = errors.New("delegation already used")
	ErrDelegationRegion     = errors.New("delegation region mismatch")
	ErrDelegationRun        = errors.New("delegation not bound to run")
	ErrDelegationInactive   = errors.New("delegation not usable")
	ErrDelegationPurpose    = errors.New("delegation purpose required")
	ErrDelegationNotAllowed = errors.New("action not permitted by delegation")

	ErrRunNotFound      = errors.New("agent run not found")
	ErrRunNotActive     = errors.New("agent run is not active")
	ErrApprovalRequired = errors.New("human approval required")
	ErrApprovalDenied   = errors.New("human approval denied")
	ErrApprovalNotFound = errors.New("approval not found")
	ErrApprovalConsumed = errors.New("approval already consumed")

	// Phase 3 sentinels.
	ErrControlNotFound     = errors.New("emergency control not found")
	ErrControlIrreversible = errors.New("control state is irreversible")
	ErrControlInvalidState = errors.New("control state transition invalid")
	ErrControlKillSwitched = errors.New("entity is kill-switched")
	ErrControlSuspended    = errors.New("entity is suspended")
	ErrBudgetExhausted     = errors.New("run budget exhausted")
	ErrEvidenceNotFound    = errors.New("evidence event not found")
	ErrCheckpointNotFound  = errors.New("evidence checkpoint not found")
	ErrOutboxEventNotFound = errors.New("outbox event not found")
	ErrRunTerminated       = errors.New("agent run terminated")
)

// Tool is a registered governed capability.
type Tool struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	Transport        string    `json:"transport"`
	EndpointOrServer string    `json:"endpoint_or_server,omitempty"`
	OwnerPrincipalID string    `json:"owner_principal_id"`
	Region           string    `json:"region"`
	ManifestDigest   string    `json:"manifest_digest,omitempty"`
	Lifecycle        string    `json:"lifecycle"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// ToolAction is one action a tool exposes.
type ToolAction struct {
	ID                    string    `json:"id"`
	TenantID              string    `json:"tenant_id"`
	ToolID                string    `json:"tool_id"`
	Action                string    `json:"action"`
	ResourceType          string    `json:"resource_type"`
	RiskLevel             string    `json:"risk_level"`
	ReadOnly              bool      `json:"read_only"`
	RequiresHumanApproval bool      `json:"requires_human_approval"`
	Status                string    `json:"status"`
	CreatedAt             time.Time `json:"created_at"`
}

// AgentToolGrant is the authorization for one agent version to invoke
// one tool action over a resource scope.
type AgentToolGrant struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	AgentID          string    `json:"agent_id"`
	VersionID        string    `json:"version_id"`
	ToolID           string    `json:"tool_id"`
	ActionID         string    `json:"action_id"`
	ResourceScope    string    `json:"resource_scope"`
	RegionConstraint string    `json:"region_constraint"`
	CallLimitPerRun  int       `json:"call_limit_per_run"`
	RequiresApproval bool      `json:"requires_approval"`
	GrantedBy        string    `json:"granted_by"`
	GrantedAt        time.Time `json:"granted_at"`
	RevokedAt        time.Time `json:"revoked_at,omitempty"`
}

// DelegationGrant is one short-lived delegation. Only the jti (never
// the raw token) and safe metadata are stored.
type DelegationGrant struct {
	ID                     string    `json:"id"`
	TenantID               string    `json:"tenant_id"`
	AgentID                string    `json:"agent_id"`
	AgentVersionID         string    `json:"agent_version_id"`
	TokenJTI               string    `json:"token_jti"`
	DelegatorPrincipalID   string    `json:"delegator_principal_id"`
	SubjectPrincipalID     string    `json:"subject_principal_id"`
	Purpose                string    `json:"purpose"`
	Region                 string    `json:"region"`
	PermittedActions       []string  `json:"permitted_actions,omitempty"`
	PermittedActionsDigest string    `json:"permitted_actions_digest"`
	IssuedAt               time.Time `json:"issued_at"`
	ExpiresAt              time.Time `json:"expires_at"`
	UsedAt                 time.Time `json:"used_at,omitempty"`
	RunID                  string    `json:"run_id,omitempty"`
	RevokedAt              time.Time `json:"revoked_at,omitempty"`
	IdempotencyKey         string    `json:"-"`
	ImmutableDigest        string    `json:"immutable_digest"`

	// Phase 6: multi-agent chain bindings. Zero values for root grants
	// minted by a human/service principal.
	IsAgentDelegation    bool   `json:"is_agent_delegation,omitempty"`
	ParentGrantID        string `json:"parent_grant_id,omitempty"`
	RootGrantID          string `json:"root_grant_id,omitempty"`
	DelegatorAgentID     string `json:"delegator_agent_id,omitempty"`
	DelegateeAgentID     string `json:"delegatee_agent_id,omitempty"`
	DelegationDepth      int    `json:"delegation_depth"`
	AuthorityScopeDigest string `json:"authority_scope_digest,omitempty"`
	ParentScopeDigest    string `json:"parent_scope_digest,omitempty"`
	AttenuationDigest    string `json:"attenuation_digest,omitempty"`
	TrustRelationshipID  string `json:"trust_relationship_id,omitempty"`
	RevocationSource     string `json:"revocation_source,omitempty"`
	// ExternalAgentID is set for grants minted on behalf of an external
	// agent identity (Phase 6); IssuedVia records the mint path
	// ("root" | "agent" | "external").
	ExternalAgentID string `json:"external_agent_id,omitempty"`
	IssuedVia       string `json:"issued_via,omitempty"`
}

// AgentRun is one governed run, always server-generated.
type AgentRun struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	AgentID           string    `json:"agent_id"`
	DelegationGrantID string    `json:"delegation_grant_id"`
	IdempotencyKey    string    `json:"-"`
	UserID            string    `json:"user_id"`
	Purpose           string    `json:"purpose"`
	Region            string    `json:"region"`
	Status            string    `json:"status"`
	TraceID           string    `json:"trace_id,omitempty"`
	StartedAt         time.Time `json:"started_at"`
	CompletedAt       time.Time `json:"completed_at,omitempty"`
	ErrorCode         string    `json:"error_code,omitempty"`

	// Phase 6: chain + external binding (empty for root runs).
	RootGrantID         string `json:"root_grant_id,omitempty"`
	ParentGrantID       string `json:"parent_grant_id,omitempty"`
	DelegationDepth     int    `json:"delegation_depth"`
	ChainVerified       string `json:"chain_verification,omitempty"` // verified | broken | unchecked
	ExternalAgentID     string `json:"external_agent_id,omitempty"`
	OrganizationID      string `json:"organization_id,omitempty"`
	CustomerPrincipalID string `json:"customer_principal_id,omitempty"`
	ConsentID           string `json:"consent_id,omitempty"`
}

// Run statuses.
const (
	RunStatusPending   = "pending"
	RunStatusRunning   = "running"
	RunStatusCompleted = "completed"
	RunStatusDenied    = "denied"
	RunStatusFailed    = "failed"
	RunStatusRevoked   = "revoked"
)

// ActionDecision is one tamper-evident evaluator outcome.
type ActionDecision struct {
	ID                string `json:"id"`
	TenantID          string `json:"tenant_id"`
	AgentID           string `json:"agent_id"`
	RunID             string `json:"run_id"`
	DelegationGrantID string `json:"delegation_grant_id"`
	ToolID            string `json:"tool_id,omitempty"`
	ActionID          string `json:"action_id,omitempty"`
	ResourceRef       string `json:"resource_ref"`
	Decision          string `json:"decision"`
	Reason            string `json:"reason"`
	// ReasonCode is a machine-readable cause for policy denials
	// (budget_exhausted:*, emergency:*, run:terminated); empty for
	// ordinary outcomes.
	ReasonCode      string    `json:"reason_code,omitempty"`
	PolicyVersion   string    `json:"policy_version"`
	ImmutableDigest string    `json:"immutable_digest"`
	CreatedAt       time.Time `json:"created_at"`

	// Phase 6: chain context of the grant that produced this decision.
	DelegationDepth int    `json:"delegation_depth"`
	ChainVerified   string `json:"chain_verification,omitempty"` // verified | broken | unchecked
}

// ActionApproval is one-time human approval evidence.
type ActionApproval struct {
	ID                   string    `json:"id"`
	TenantID             string    `json:"tenant_id"`
	RunID                string    `json:"run_id"`
	ToolID               string    `json:"tool_id"`
	ActionID             string    `json:"action_id"`
	ResourceRef          string    `json:"resource_ref"`
	ApprovingPrincipalID string    `json:"approving_principal_id"`
	Decision             string    `json:"decision"`
	ExpiresAt            time.Time `json:"expires_at"`
	ConsumedAt           time.Time `json:"consumed_at,omitempty"`
	IdempotencyKey       string    `json:"-"`
	ImmutableDigest      string    `json:"immutable_digest"`
	CreatedAt            time.Time `json:"created_at"`
}

// ---------------------------------------------------------------------
// Requests / responses
// ---------------------------------------------------------------------

type RegisterToolRequest struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	Transport        string `json:"transport"`
	EndpointOrServer string `json:"endpoint_or_server,omitempty"`
	OwnerPrincipalID string `json:"owner_principal_id"`
	Region           string `json:"region"`
	ManifestDigest   string `json:"manifest_digest,omitempty"`
}

type RegisterToolActionRequest struct {
	Action                string `json:"action"`
	ResourceType          string `json:"resource_type"`
	RiskLevel             string `json:"risk_level"`
	ReadOnly              bool   `json:"read_only"`
	RequiresHumanApproval bool   `json:"requires_human_approval"`
}

type TransitionToolRequest struct {
	Lifecycle string `json:"lifecycle"`
	Reason    string `json:"reason,omitempty"`
}

type GrantToolRequest struct {
	AgentID          string `json:"agent_id"`
	VersionID        string `json:"version_id"`
	ToolID           string `json:"tool_id"`
	ActionID         string `json:"action_id"`
	ResourceScope    string `json:"resource_scope"`
	RegionConstraint string `json:"region_constraint"`
	CallLimitPerRun  int    `json:"call_limit_per_run"`
	RequiresApproval bool   `json:"requires_approval"`
}

type MintDelegationRequest struct {
	SubjectPrincipalID string   `json:"subject_principal_id"`
	Purpose            string   `json:"purpose"`
	PermittedActions   []string `json:"permitted_actions"`
	TTLSeconds         int      `json:"ttl_seconds,omitempty"`
}

type MintDelegationResponse struct {
	Grant DelegationGrant `json:"grant"`
	// Token is returned exactly once at mint time and is never stored
	// server-side; only token_jti is persisted. On an idempotent replay
	// (same Idempotency-Key) Token is empty and TokenAlreadyIssued is
	// true — the raw token is single-delivery by design.
	Token              string `json:"token,omitempty"`
	TokenAlreadyIssued bool   `json:"token_already_issued,omitempty"`
}

type RunActionRequest struct {
	ToolName    string `json:"tool_name"`
	Action      string `json:"action"`
	ResourceRef string `json:"resource_ref"`
}

type CreateRunRequest struct {
	DelegationToken string             `json:"delegation_token"`
	Actions         []RunActionRequest `json:"actions"`
}

type CreateRunResponse struct {
	Run       AgentRun         `json:"run"`
	Decisions []ActionDecision `json:"decisions"`
}

type EvaluateActionRequest struct {
	DelegationToken string `json:"delegation_token"`
	RunID           string `json:"run_id"`
	ToolName        string `json:"tool_name"`
	Action          string `json:"action"`
	ResourceRef     string `json:"resource_ref"`
	// Arguments are the agent-supplied action arguments. They are IGNORED
	// by the evaluator (never used for authorization); the connector
	// gateway validates them against the manifest's argument allowlist
	// and path template. URL/host/port/method can never come from here.
	Arguments map[string]any `json:"arguments,omitempty"`
	// TraceID propagates the W3C-style correlation id to the connector.
	TraceID string `json:"trace_id,omitempty"`
}

type EvaluateActionResponse struct {
	Decision ActionDecision `json:"decision"`
	Allowed  bool           `json:"allowed"`
}

type ApproveActionRequest struct {
	ResourceRef string `json:"resource_ref"`
}

type ApproveActionResponse struct {
	Approval ActionApproval `json:"approval"`
	Denied   bool           `json:"denied"`
}

type DispatchResponse struct {
	Decision ActionDecision `json:"decision"`
	Allowed  bool           `json:"allowed"`
	// DispatchMode is "dispatched" when the authorized call was actually
	// forwarded to the external connector through the gateway, or
	// "connector_failed" when the decision was allowed but the connector
	// layer failed closed before the outbound call (unreachable registry,
	// suspended/revoked connector, region mismatch, dispatcher missing).
	// Builtin/internal tools are governed end-to-end.
	DispatchMode string `json:"dispatch_mode"`
	// Invocation is the immutable outcome evidence of the outbound call.
	Invocation *ConnectorInvocation `json:"invocation,omitempty"`
	// Response is the size-limited, redacted, policy-compliant response
	// (present only on success).
	Response any `json:"response,omitempty"`
}

type DelegatedQueryResult struct {
	UserID   string         `json:"user_id"`
	Run      AgentRun       `json:"run"`
	Decision ActionDecision `json:"decision"`
	Allowed  bool           `json:"allowed"`
}

// ---------------------------------------------------------------------
// Policy simulator & decision explainer (Phase 7)
// ---------------------------------------------------------------------

// GateStatus reports one simulated gate outcome.
const (
	GateStatusPassed      = "passed"      // gate satisfied
	GateStatusFailed      = "failed"      // gate blocks the action
	GateStatusSkipped     = "skipped"     // not applicable to simulation input
	GateStatusUnavailable = "unavailable" // dependency missing: fail closed
	GateStatusRequired    = "required"    // gate needs human action (approval)
)

// GateCheck is one explainable gate result. Gate/Name order mirrors the
// shared evaluator's gate pipeline in evaluateInTx; a divergence between
// the simulator and the evaluator is a correctness bug.
type GateCheck struct {
	Gate       string `json:"gate"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	ReasonCode string `json:"reason_code,omitempty"`
}

// SimulateActionRequest is the read-only policy simulation input. It is
// an ANALYSIS body: tenant and region come from the API-key context only.
// AgentID, ToolName and Action are required; VersionID defaults to the
// agent's active version; PrincipalID (optional) enables the relationship
// gate. No delegation token is accepted — runtime
// evaluation always requires a live delegation; the simulator reports
// that gate as skipped.
type SimulateActionRequest struct {
	AgentID     string `json:"agent_id"`
	VersionID   string `json:"version_id,omitempty"`
	ToolName    string `json:"tool_name"`
	Action      string `json:"action"`
	ResourceRef string `json:"resource_ref"`
	PrincipalID string `json:"principal_id,omitempty"`
}

// SimulateActionResponse explains what WOULD happen for one action under
// the current authorization state. Simulated is always true: this is
// analysis, never an authoritative decision record, and nothing is
// written (no evidence, no counters, no approvals).
type SimulateActionResponse struct {
	Decision    string      `json:"decision"`
	Allowed     bool        `json:"allowed"`
	Reason      string      `json:"reason"`
	ReasonCode  string      `json:"reason_code,omitempty"`
	Checks      []GateCheck `json:"checks"`
	Simulated   bool        `json:"simulated"`
	SimulatedAt time.Time   `json:"simulated_at"`
}

// ---------------------------------------------------------------------
// Phase 3: Emergency controls, budgets, evidence, verification, outbox
// ---------------------------------------------------------------------

// Emergency control states. Absence of a control row means 'active'.
const (
	ControlStateActive       = "active"
	ControlStateSuspended    = "suspended"
	ControlStateRevoked      = "revoked"
	ControlStateKillSwitched = "kill_switched"
)

// Entity types a control can apply to.
const (
	ControlEntityAgent        = "agent"
	ControlEntityAgentVersion = "agent_version"
	ControlEntityTool         = "tool"
	ControlEntityToolGrant    = "agent_tool_grant"
	ControlEntityDelegation   = "delegation_grant"
	ControlEntityRun          = "run"
)

// Control action types recorded as evidence.
const (
	ControlActionKillSwitch = "kill_switch"
	ControlActionSuspend    = "suspend"
	ControlActionResume     = "resume"
	ControlActionRevoke     = "revoke"
	ControlActionTerminate  = "terminate"
)

// EmergencyControl is the current control state of one entity.
type EmergencyControl struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	EntityType       string    `json:"entity_type"`
	EntityID         string    `json:"entity_id"`
	ControlState     string    `json:"control_state"`
	Reason           string    `json:"reason"`
	Scope            string    `json:"scope"`
	ActorPrincipalID string    `json:"actor_principal_id"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// EmergencyControlAction is the immutable, hash-chained evidence of one
// control mutation (actor, reason, scope, previous state, new state).
type EmergencyControlAction struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	EntityType       string    `json:"entity_type"`
	EntityID         string    `json:"entity_id"`
	ActionType       string    `json:"action_type"`
	ActorPrincipalID string    `json:"actor_principal_id"`
	Reason           string    `json:"reason"`
	Scope            string    `json:"scope"`
	PreviousState    string    `json:"previous_state"`
	NewState         string    `json:"new_state"`
	ImmutableDigest  string    `json:"immutable_digest"`
	CreatedAt        time.Time `json:"created_at"`
}

// ControlRequest is the mutation body: reason (required) and an
// optional scope. Identity and tenant never come from the body.
type ControlRequest struct {
	Reason string `json:"reason"`
	Scope  string `json:"scope,omitempty"`
}

// Budget scope types.
const (
	BudgetScopeTenant       = "tenant"
	BudgetScopeAgentVersion = "agent_version"
	BudgetScopeGrant        = "grant"
)

// BudgetPolicy is one budget policy row at one scope. A 0 value means
// "no limit from this scope"; the effective budget is the narrowest
// applicable policy (grant > agent_version > tenant), with Phase 2
// grant.call_limit_per_run honored in addition.
type BudgetPolicy struct {
	ID                          string    `json:"id"`
	TenantID                    string    `json:"tenant_id"`
	ScopeType                   string    `json:"scope_type"`
	AgentVersionID              string    `json:"agent_version_id,omitempty"`
	GrantID                     string    `json:"grant_id,omitempty"`
	MaxActionsPerRun            int       `json:"max_actions_per_run"`
	MaxDeniedPerRun             int       `json:"max_denied_per_run"`
	MaxApprovalRequiredPerRun   int       `json:"max_approval_required_per_run"`
	MaxToolCallsPerActionPerRun int       `json:"max_tool_calls_per_action_per_run"`
	MaxRunDurationSeconds       int       `json:"max_run_duration_seconds"`
	MaxCitationsPerQuery        int       `json:"max_citations_per_query"`
	CreatedBy                   string    `json:"created_by"`
	CreatedAt                   time.Time `json:"created_at"`
	UpdatedAt                   time.Time `json:"updated_at"`
}

// BudgetPolicyRequest is the upsert body for a budget policy.
type BudgetPolicyRequest struct {
	MaxActionsPerRun            int `json:"max_actions_per_run"`
	MaxDeniedPerRun             int `json:"max_denied_per_run"`
	MaxApprovalRequiredPerRun   int `json:"max_approval_required_per_run"`
	MaxToolCallsPerActionPerRun int `json:"max_tool_calls_per_action_per_run"`
	MaxRunDurationSeconds       int `json:"max_run_duration_seconds"`
	MaxCitationsPerQuery        int `json:"max_citations_per_query"`
}

// BudgetCounter types recorded on agent_run_budget_usage.
const (
	BudgetCounterActions          = "actions"
	BudgetCounterDenied           = "denied"
	BudgetCounterApprovalRequired = "approval_required"
	BudgetCounterToolCalls        = "tool_calls"
	BudgetCounterCitations        = "citations"
)

// Evidence kinds exposed by the evidence read model.
const (
	EvidenceKindDecision         = "decision"
	EvidenceKindApproval         = "approval"
	EvidenceKindDelegationMint   = "delegation_mint"
	EvidenceKindDelegationRevoke = "delegation_revoke"
	EvidenceKindEmergencyControl = "emergency_control"
	EvidenceKindRunStart         = "run_start"
	EvidenceKindRunEnd           = "run_end"
	// Phase 5: connector gateway evidence.
	EvidenceKindConnectorInvocation = "connector_invocation"
	EvidenceKindConnectorLifecycle  = "connector_lifecycle"
	// Phase 6: trust/chain/external evidence.
	EvidenceKindTrustEvent  = "trust"
	EvidenceKindChainRevoke = "chain_revoke"
)

// EvidenceEvent is one read-model row joining the authoritative
// evidence tables. Never exposes tokens, secrets, assertions, or
// sensitive payloads — only identifiers, digests, and safe metadata.
type EvidenceEvent struct {
	EventID    string    `json:"event_id"`
	Kind       string    `json:"kind"`
	TenantID   string    `json:"tenant_id"`
	OccurredAt time.Time `json:"occurred_at"`
	// Region and Jurisdiction are the trusted tenant region/jurisdiction
	// (from deployment configuration) resolved at read time. They are
	// never parsed from request bodies.
	Region            string `json:"region,omitempty"`
	Jurisdiction      string `json:"jurisdiction,omitempty"`
	ActorPrincipalID  string `json:"actor_principal_id,omitempty"`
	AgentID           string `json:"agent_id,omitempty"`
	AgentName         string `json:"agent_name,omitempty"`
	AgentVersionID    string `json:"agent_version_id,omitempty"`
	OwnerPrincipalID  string `json:"owner_principal_id,omitempty"`
	DelegationGrantID string `json:"delegation_grant_id,omitempty"`
	UserID            string `json:"user_id,omitempty"`
	RunID             string `json:"run_id,omitempty"`
	RunStatus         string `json:"run_status,omitempty"`
	ToolID            string `json:"tool_id,omitempty"`
	ToolName          string `json:"tool_name,omitempty"`
	ActionID          string `json:"action_id,omitempty"`
	ResourceRef       string `json:"resource_ref,omitempty"`
	Decision          string `json:"decision,omitempty"`
	Reason            string `json:"reason,omitempty"`
	ReasonCode        string `json:"reason_code,omitempty"`
	PolicyVersion     string `json:"policy_version,omitempty"`
	TraceID           string `json:"trace_id,omitempty"`
	EntityType        string `json:"entity_type,omitempty"`
	EntityID          string `json:"entity_id,omitempty"`
	PreviousState     string `json:"previous_state,omitempty"`
	NewState          string `json:"new_state,omitempty"`
	ImmutableDigest   string `json:"immutable_digest"`

	// Phase 6: delegation-chain columns on the evidence read model
	// (empty for pre-chain events).
	RootGrantID        string `json:"root_grant_id,omitempty"`
	ParentGrantID      string `json:"parent_grant_id,omitempty"`
	ChildGrantID       string `json:"child_grant_id,omitempty"`
	DelegationDepth    int    `json:"delegation_depth"`
	DelegatorAgentID   string `json:"delegator_agent_id,omitempty"`
	DelegateeAgentID   string `json:"delegatee_agent_id,omitempty"`
	TrustDomain        string `json:"trust_domain,omitempty"`
	OrganizationID     string `json:"organization_id,omitempty"`
	SubjectPrincipalID string `json:"subject_principal_id,omitempty"`
	ScopeDigest        string `json:"scope_digest,omitempty"`
	AttenuationDigest  string `json:"attenuation_digest,omitempty"`
	ChainVerification  string `json:"chain_verification,omitempty"` // verified | broken | unchecked
	RevocationSource   string `json:"revocation_source,omitempty"`
}

// EvidenceFilter is the tenant-scoped filter set for evidence queries.
// Cursor pagination is stable and deterministic ((occurred_at,
// event_id) tuples). Cursor is opaque base64.
type EvidenceFilter struct {
	From           string // RFC3339; inclusive
	To             string // RFC3339; exclusive
	AgentID        string
	AgentVersionID string
	OwnerPrincipal string
	UserID         string
	ToolID         string
	ActionID       string
	RunStatus      string
	Decision       string
	ReasonCode     string
	TraceID        string
	Kinds          []string
	Limit          int // default 50, max 200
	Cursor         string
}

// EvidencePage is one page of evidence events.
type EvidencePage struct {
	Events     []EvidenceEvent `json:"events"`
	NextCursor string          `json:"next_cursor,omitempty"`
	Count      int             `json:"count"`
}

// EvidenceVerifyResult reports the integrity state of one tenant's
// governance evidence chains. The first broken record (if any) is
// reported with its exact location; verification is read-only and never
// repairs. Distinct from audit_api.AuditVerifyResult, which verifies the
// Phase 1 query audit chain.
type EvidenceVerifyResult struct {
	TenantID          string    `json:"tenant_id"`
	Verified          bool      `json:"verified"`
	ChainsChecked     int       `json:"chains_checked"`
	EventsChecked     int       `json:"events_checked"`
	FirstBrokenKind   string    `json:"first_broken_kind,omitempty"`
	FirstBrokenID     string    `json:"first_broken_id,omitempty"`
	FirstBrokenAt     time.Time `json:"first_broken_at,omitempty"`
	FirstBrokenDetail string    `json:"first_broken_detail,omitempty"`
	FromCheckpoint    bool      `json:"from_checkpoint,omitempty"`
	CheckedAt         time.Time `json:"checked_at"`
}

// EvidenceCheckpoint is a verified digest of the evidence stream up to
// last_verified_at, enabling incremental verification.
type EvidenceCheckpoint struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	LastEventID    string    `json:"last_event_id"`
	LastVerifiedAt time.Time `json:"last_verified_at"`
	EventsChecked  int       `json:"events_checked"`
	ChainDigest    string    `json:"chain_digest"`
	CreatedAt      time.Time `json:"created_at"`
}

// Outbox delivery states.
const (
	OutboxStatusPending    = "pending"
	OutboxStatusDelivering = "delivering"
	OutboxStatusDelivered  = "delivered"
	OutboxStatusDeadLetter = "dead_letter"
)

// OutboxEvent is one security-relevant event queued for delivery.
// Payload carries safe fields ONLY (never tokens, secrets, assertions,
// or document text).
type OutboxEvent struct {
	ID            string          `json:"id"`
	TenantID      string          `json:"tenant_id"`
	EventID       string          `json:"event_id"`
	EventType     string          `json:"event_type"`
	SchemaVersion int             `json:"schema_version"`
	OccurredAt    time.Time       `json:"occurred_at"`
	Payload       json.RawMessage `json:"payload,omitempty"`
	Status        string          `json:"status"`
	Attempts      int             `json:"attempts"`
	NextAttemptAt time.Time       `json:"next_attempt_at"`
	LastError     string          `json:"last_error,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	DeliveredAt   time.Time       `json:"delivered_at,omitempty"`
}

// OutboxTenantStats is one tenant's outbox health snapshot used for
// observability (Phase 8.5): pending event count, oldest pending event
// age, and the number of dead-lettered events awaiting manual
// inspection.
type OutboxTenantStats struct {
	TenantID        string    `json:"tenant_id"`
	PendingCount    int       `json:"pending_count"`
	OldestPendingAt time.Time `json:"oldest_pending_at,omitempty"`
	DeadLetterCount int       `json:"dead_letter_count"`
}

// OutboxStatsSource is implemented by stores that can report outbox
// health per tenant; the delivery worker probes it on a cadence to keep
// the pending-age and dead-letter gauges fresh.
type OutboxStatsSource interface {
	OutboxPendingStats(ctx context.Context) ([]OutboxTenantStats, error)
}

// OutboxEnqueuer writes a security-relevant event into the transactional
// outbox. Governance and agent registry implementations flush pending
// events in the same transaction as their business + evidence records.
type OutboxEnqueuer interface {
	EnqueueOutbox(ctx context.Context, e OutboxEvent) error
}

// OutboxEventType names (safe, stable identifiers for consumers).
const (
	OutboxEventAgentLifecycle     = "agent.lifecycle"
	OutboxEventDelegationMinted   = "delegation.minted"
	OutboxEventDelegationRevoked  = "delegation.revoked"
	OutboxEventRunStarted         = "run.started"
	OutboxEventRunEnded           = "run.ended"
	OutboxEventActionDecision     = "action.decision"
	OutboxEventApprovalRecorded   = "approval.recorded"
	OutboxEventBudgetExhaustion   = "budget.exhaustion"
	OutboxEventEmergencyControl   = "emergency.control"
	OutboxEventAuditVerifyFailure = "audit.verify_failure"
	// Phase 5: connector gateway outcomes.
	OutboxEventConnectorInvocation = "connector.invocation"
	// Phase 6: trust, chain, and external-agent outcomes.
	OutboxEventTrustLifecycle  = "trust.lifecycle"
	OutboxEventChainRevoked    = "delegation.chain_revoked"
	OutboxEventExternalAgent   = "external.agent"
	OutboxEventConsentRecorded = "consent.recorded"
	OutboxEventConsentRevoked  = "consent.revoked"
)

// QueryCitationBudget reports the citation budget state for a run at
// evaluation time (used by the retrieval gate).
type QueryCitationBudget struct {
	Allowed    bool   `json:"allowed"`
	Budget     int    `json:"budget"`
	Used       int    `json:"used"`
	DenyReason string `json:"deny_reason,omitempty"`
}

// ---------------------------------------------------------------------
// GovernanceService
// ---------------------------------------------------------------------

type GovernanceService interface {
	// Tools & actions (admin scope + verified identity).
	RegisterTool(ctx context.Context, tenantID, actor string, admin bool, req RegisterToolRequest) (Tool, error)
	ListTools(ctx context.Context, tenantID string) ([]Tool, error)
	GetTool(ctx context.Context, tenantID, toolID string) (Tool, []ToolAction, error)
	RegisterToolAction(ctx context.Context, tenantID, toolID, actor string, admin bool, req RegisterToolActionRequest) (ToolAction, error)
	ListToolActions(ctx context.Context, tenantID, toolID string) ([]ToolAction, error)
	TransitionTool(ctx context.Context, tenantID, toolID, actor string, admin bool, req TransitionToolRequest) (Tool, error)

	// Grants (admin scope + verified identity).
	GrantToolAccess(ctx context.Context, tenantID, actor string, admin bool, req GrantToolRequest) (AgentToolGrant, error)
	RevokeToolGrant(ctx context.Context, tenantID, grantID, actor string, admin bool, reason string) (AgentToolGrant, error)
	ListToolGrants(ctx context.Context, tenantID, agentID string) ([]AgentToolGrant, error)

	// Delegations (verified identity only — demo can never mint).
	// region comes from the API-key TenantContext, never from the body.
	MintDelegation(ctx context.Context, tenantID, region, agentID, actor string, admin bool, idempotencyKey string, req MintDelegationRequest) (MintDelegationResponse, error)

	// Runs (evaluated against the presented delegation token).
	CreateRun(ctx context.Context, tenantID, region, idempotencyKey string, req CreateRunRequest) (CreateRunResponse, error)
	GetRun(ctx context.Context, tenantID, runID string) (AgentRun, []ActionDecision, error)
	ListRuns(ctx context.Context, tenantID string) ([]AgentRun, error)
	EvaluateAction(ctx context.Context, tenantID, region string, req EvaluateActionRequest) (EvaluateActionResponse, error)
	// SimulateAction is the read-only policy simulator: it walks the same
	// gate pipeline as EvaluateAction against current state and explains
	// each gate, WITHOUT writing evidence, counters, or approvals.
	// Tenant and region come from the trusted API-key context.
	SimulateAction(ctx context.Context, tenantID, region string, req SimulateActionRequest) (SimulateActionResponse, error)

	// Human approval (verified identity only).
	ApproveAction(ctx context.Context, tenantID, runID, actionID, actor string, idempotencyKey string, req ApproveActionRequest) (ApproveActionResponse, error)
	DenyAction(ctx context.Context, tenantID, runID, actionID, actor string, idempotencyKey string, req ApproveActionRequest) (ApproveActionResponse, error)

	// Dispatch: full evaluation + evidence, then actual connector
	// dispatch for builtin/internal transports; http/mcp transports
	// return connector_dispatch_deferred (documented deferral).
	DispatchAction(ctx context.Context, tenantID, region string, req EvaluateActionRequest) (DispatchResponse, error)

	// EvaluateDelegatedQuery gates the retrieval path (/v1/query, MCP
	// groundwork_search) under a delegation. Returns the verified
	// subject to run the query as, the run, and the evidence.
	EvaluateDelegatedQuery(ctx context.Context, tenantID, region, token, runID, question string) (DelegatedQueryResult, error)

	// RecordQueryCitations records the actual citation count of a
	// completed governed query against the run's citation budget
	// (deterministic, transaction-safe counter).
	RecordQueryCitations(ctx context.Context, tenantID, runID string, count int) error

	// Phase 3: emergency controls (admin + verified identity). Kill
	// switch denies the next action immediately and terminates active
	// runs; resume is allowed only where reversal is safe (agents,
	// versions, tools); revocation and termination are irreversible.
	KillSwitchAgent(ctx context.Context, tenantID, agentID, actor string, admin bool, req ControlRequest) (EmergencyControl, error)
	ResumeAgent(ctx context.Context, tenantID, agentID, actor string, admin bool, req ControlRequest) (EmergencyControl, error)
	KillSwitchAgentVersion(ctx context.Context, tenantID, versionID, actor string, admin bool, req ControlRequest) (EmergencyControl, error)
	ResumeAgentVersion(ctx context.Context, tenantID, versionID, actor string, admin bool, req ControlRequest) (EmergencyControl, error)
	KillSwitchTool(ctx context.Context, tenantID, toolID, actor string, admin bool, req ControlRequest) (EmergencyControl, error)
	ResumeTool(ctx context.Context, tenantID, toolID, actor string, admin bool, req ControlRequest) (EmergencyControl, error)
	RevokeDelegationGrant(ctx context.Context, tenantID, grantID, actor string, admin bool, req ControlRequest) (EmergencyControl, error)
	TerminateRun(ctx context.Context, tenantID, runID, actor string, admin bool, req ControlRequest) (EmergencyControl, error)
	ListEmergencyControls(ctx context.Context, tenantID string) ([]EmergencyControl, error)

	// Phase 3: budgets (admin + verified identity for writes).
	UpsertBudget(ctx context.Context, tenantID, actor string, admin bool, scopeType, agentVersionID, grantID string, req BudgetPolicyRequest) (BudgetPolicy, error)
	GetEffectiveBudget(ctx context.Context, tenantID, agentVersionID, grantID string) (BudgetPolicy, error)
	ListBudgets(ctx context.Context, tenantID string) ([]BudgetPolicy, error)

	// Phase 3: evidence read model (governance scope, read-only).
	QueryEvidence(ctx context.Context, tenantID string, filter EvidenceFilter) (EvidencePage, error)
	GetEvidenceEvent(ctx context.Context, tenantID, eventID string) (EvidenceEvent, error)
	GetRunTimeline(ctx context.Context, tenantID, runID string) ([]EvidenceEvent, error)
	GetAgentActivity(ctx context.Context, tenantID, agentID string, filter EvidenceFilter) ([]EvidenceEvent, error)

	// Phase 3: tamper-evident audit verification + checkpoints.
	VerifyAuditChain(ctx context.Context, tenantID string, checkpointID string, createCheckpoint bool) (EvidenceVerifyResult, error)
	ListCheckpoints(ctx context.Context, tenantID string) ([]EvidenceCheckpoint, error)

	// Phase 3: outbox surface (health, failures, retries).
	ListOutboxEvents(ctx context.Context, tenantID, status string, limit int, cursor string) ([]OutboxEvent, string, error)
	RetryOutboxEvent(ctx context.Context, tenantID, eventID string) (OutboxEvent, error)

	// Phase 5: connector invocation evidence (outcomes + list).
	RecordConnectorInvocation(ctx context.Context, tenantID, region string, inv ConnectorInvocation) error
	ListConnectorInvocations(ctx context.Context, tenantID, connectorID string, limit int) ([]ConnectorInvocation, error)

	// Phase 6: agent trust relationships (verified identity; owner-or-admin).
	CreateTrustRelationship(ctx context.Context, tenantID, actor string, admin bool, req TrustRelationshipRequest) (AgentTrustRelationship, error)
	ListTrustRelationships(ctx context.Context, tenantID string) ([]AgentTrustRelationship, error)
	GetTrustRelationship(ctx context.Context, tenantID, relationshipID string) (AgentTrustRelationship, error)
	TransitionTrustRelationship(ctx context.Context, tenantID, relationshipID, actor string, admin bool, action string, req TrustTransitionRequest) (AgentTrustRelationship, error)
	ListTrustEvents(ctx context.Context, tenantID string, limit int) ([]TrustEvent, error)

	// Phase 6: agent-to-agent delegation.
	DelegateToChildAgent(ctx context.Context, tenantID, region string, parentAgentID string, actor string, admin bool, idempotencyKey string, req ChildDelegationRequest) (MintDelegationResponse, error)
	ListChildDelegations(ctx context.Context, tenantID, parentAgentID string) ([]DelegationGrant, error)
	GetDelegationChain(ctx context.Context, tenantID, grantID string) (DelegationChain, error)
	GetRunDelegationChain(ctx context.Context, tenantID, runID string) (DelegationChain, error)
	RevokeDelegationChain(ctx context.Context, tenantID, grantID, actor string, admin bool, req ControlRequest) (int, error)
	SuspendDelegationChain(ctx context.Context, tenantID, grantID, actor string, admin bool, req ControlRequest) (int, error)
	ResumeDelegationChain(ctx context.Context, tenantID, grantID, actor string, admin bool, req ControlRequest) (int, error)

	// Phase 6: external-agent onboarding + authentication.
	OnboardExternalAgent(ctx context.Context, tenantID, actor string, admin bool, req ExternalAgentRequest) (ExternalAgent, error)
	ListExternalAgents(ctx context.Context, tenantID string) ([]ExternalAgent, error)
	GetExternalAgent(ctx context.Context, tenantID, externalAgentID string) (ExternalAgent, error)
	TransitionExternalAgent(ctx context.Context, tenantID, externalAgentID, actor string, admin bool, action string, req TrustTransitionRequest) (ExternalAgent, error)
	VerifyExternalSession(ctx context.Context, tenantID, region string, req ExternalSessionRequest) (ExternalSession, error)
	CreateExternalRun(ctx context.Context, tenantID, region, idempotencyKey string, req CreateExternalRunRequest) (CreateRunResponse, error)

	// Phase 6: customer consent + transfer policies + external budgets.
	CreateConsentRecord(ctx context.Context, tenantID, actor string, admin bool, req ConsentRequest) (ConsentRecord, error)                // :880
	ListConsentRecords(ctx context.Context, tenantID string) ([]ConsentRecord, error)                                                      // :881
	UpsertTransferPolicy(ctx context.Context, tenantID, actor string, admin bool, req TransferPolicyRequest) (TransferPolicy, error)       // :882
	ListTransferPolicies(ctx context.Context, tenantID string) ([]TransferPolicy, error)                                                   // :883
	UpsertExternalBudget(ctx context.Context, tenantID, actor string, admin bool, req ExternalBudgetRequest) (ExternalBudgetPolicy, error) // :884
	ListExternalBudgets(ctx context.Context, tenantID string) ([]ExternalBudgetPolicy, error)                                              // :885

	// Phase 6: provenance.
	GetEvidenceProvenance(ctx context.Context, tenantID, eventID string) (ProvenanceView, error) // :888

	// Phase 6 API surface: external runs are AgentRun rows stamped with
	// ExternalAgentID; reads and termination below are external-only and
	// fail closed (ErrRunNotFound) for internal runs.
	ListExternalRuns(ctx context.Context, tenantID string) ([]AgentRun, error)
	GetExternalRun(ctx context.Context, tenantID, runID string) (AgentRun, []ActionDecision, error)
	TerminateExternalRun(ctx context.Context, tenantID, runID, actor string, admin bool, req ControlRequest) (EmergencyControl, error)

	// Phase 6 API surface: consent + transfer-policy lifecycle.
	GetConsentRecord(ctx context.Context, tenantID, consentID string) (ConsentRecord, error)
	RevokeConsentRecord(ctx context.Context, tenantID, consentID, actor string, admin bool, reason string) (ConsentRecord, error)
	TransitionTransferPolicy(ctx context.Context, tenantID, policyID, actor string, admin bool, action string, req TrustTransitionRequest) (TransferPolicy, error)

	// Phase 6 API surface: delegation-grant listing (console chain view).
	ListDelegationGrants(ctx context.Context, tenantID string) ([]DelegationGrant, error)
}

// GovernanceAPIError is the /v1/governance error envelope.
type GovernanceAPIError struct {
	Error string `json:"error"`
}

// GovernanceSimulateResponse is the POST /v1/governance/simulate shape.
type GovernanceSimulateResponse struct {
	Simulation SimulateActionResponse `json:"simulation"`
}
