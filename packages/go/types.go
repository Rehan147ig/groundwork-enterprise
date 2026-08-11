package sdk

import "time"

// ---------------------------------------------------------------------
// Agents (Phase 1)
// ---------------------------------------------------------------------

type Agent struct {
	ID               string     `json:"id"`
	TenantID         string     `json:"tenant_id"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	OwnerPrincipalID string     `json:"owner_principal_id"`
	BusinessPurpose  string     `json:"business_purpose"`
	RiskTier         string     `json:"risk_tier"`
	LifecycleState   string     `json:"lifecycle_state"`
	Environment      string     `json:"environment"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	ActivatedAt      *time.Time `json:"activated_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	ActiveVersionID  *string    `json:"active_version_id,omitempty"`
	ActiveVersion    *string    `json:"active_version,omitempty"`
	VersionCount     *int       `json:"version_count,omitempty"`
}

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
	ApprovedAt          *string   `json:"approved_at,omitempty"`
}

type LifecycleEvent struct {
	ID          string    `json:"id"`
	AgentID     string    `json:"agent_id"`
	EventType   string    `json:"event_type"`
	PrincipalID string    `json:"principal_id"`
	FromState   string    `json:"from_state"`
	ToState     string    `json:"to_state"`
	Reason      *string   `json:"reason,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type AgentListResponse struct {
	Agents []Agent `json:"agents"`
	Count  int     `json:"count"`
}

type AgentResponse struct {
	Agent Agent `json:"agent"`
}

type AgentDetailResponse struct {
	Agent           Agent            `json:"agent"`
	Versions        []AgentVersion   `json:"versions"`
	LifecycleEvents []LifecycleEvent `json:"lifecycle_events"`
}

type AgentVersionResponse struct {
	Version AgentVersion `json:"version"`
}

type CreateAgentRequest struct {
	Name            string  `json:"name"`
	Description     string  `json:"description,omitempty"`
	BusinessPurpose string  `json:"business_purpose"`
	RiskTier        *string `json:"risk_tier,omitempty"`
	Environment     *string `json:"environment,omitempty"`
}

type UpdateAgentRequest struct {
	Name            *string `json:"name,omitempty"`
	Description     *string `json:"description,omitempty"`
	BusinessPurpose *string `json:"business_purpose,omitempty"`
	RiskTier        *string `json:"risk_tier,omitempty"`
}

type AddAgentVersionRequest struct {
	Version             string `json:"version"`
	ModelProvider       string `json:"model_provider"`
	ModelName           string `json:"model_name"`
	PromptDigest        string `json:"prompt_digest"`
	ToolManifestDigest  string `json:"tool_manifest_digest"`
	PolicyBundleVersion string `json:"policy_bundle_version"`
	ArtifactDigest      string `json:"artifact_digest"`
}

// ---------------------------------------------------------------------
// Governance: tools, actions, grants
// ---------------------------------------------------------------------

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

type AgentToolGrant struct {
	ID               string     `json:"id"`
	TenantID         string     `json:"tenant_id"`
	AgentID          string     `json:"agent_id"`
	VersionID        string     `json:"version_id"`
	ToolID           string     `json:"tool_id"`
	ActionID         string     `json:"action_id"`
	ResourceScope    string     `json:"resource_scope"`
	RegionConstraint string     `json:"region_constraint"`
	CallLimitPerRun  int        `json:"call_limit_per_run"`
	RequiresApproval bool       `json:"requires_approval"`
	GrantedBy        string     `json:"granted_by"`
	GrantedAt        time.Time  `json:"granted_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
}

type RegisterToolRequest struct {
	Name             string `json:"name"`
	Description      string `json:"description,omitempty"`
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
	VersionID        string `json:"version_id,omitempty"`
	ToolID           string `json:"tool_id"`
	ActionID         string `json:"action_id,omitempty"`
	ResourceScope    string `json:"resource_scope,omitempty"`
	RegionConstraint string `json:"region_constraint,omitempty"`
	CallLimitPerRun  *int   `json:"call_limit_per_run,omitempty"`
	RequiresApproval *bool  `json:"requires_approval,omitempty"`
}

type ToolListResponse struct {
	Tools []Tool `json:"tools"`
	Count int    `json:"count"`
}

type ToolResponse struct {
	Tool Tool `json:"tool"`
}

type ToolDetailResponse struct {
	Tool    Tool         `json:"tool"`
	Actions []ToolAction `json:"actions"`
}

type ToolActionListResponse struct {
	Actions []ToolAction `json:"actions"`
	Count   int          `json:"count"`
}

type ToolActionResponse struct {
	Action ToolAction `json:"action"`
}

type GrantResponse struct {
	Grant AgentToolGrant `json:"grant"`
}

type GrantListResponse struct {
	Grants []AgentToolGrant `json:"grants"`
	Count  int              `json:"count"`
}

// ---------------------------------------------------------------------
// Governance: delegations, runs, evaluation, simulation
// ---------------------------------------------------------------------

type DelegationGrant struct {
	ID                     string     `json:"id"`
	TenantID               string     `json:"tenant_id"`
	AgentID                string     `json:"agent_id"`
	AgentVersionID         string     `json:"agent_version_id"`
	TokenJTI               string     `json:"token_jti"`
	DelegatorPrincipalID   string     `json:"delegator_principal_id"`
	SubjectPrincipalID     string     `json:"subject_principal_id"`
	Purpose                string     `json:"purpose"`
	Region                 string     `json:"region"`
	PermittedActions       []string   `json:"permitted_actions,omitempty"`
	PermittedActionsDigest string     `json:"permitted_actions_digest"`
	IssuedAt               time.Time  `json:"issued_at"`
	ExpiresAt              time.Time  `json:"expires_at"`
	UsedAt                 *time.Time `json:"used_at,omitempty"`
	RunID                  string     `json:"run_id,omitempty"`
	RevokedAt              *time.Time `json:"revoked_at,omitempty"`
	ImmutableDigest        string     `json:"immutable_digest"`
	IsAgentDelegation      *bool      `json:"is_agent_delegation,omitempty"`
	ParentGrantID          string     `json:"parent_grant_id,omitempty"`
	RootGrantID            string     `json:"root_grant_id,omitempty"`
	DelegatorAgentID       string     `json:"delegator_agent_id,omitempty"`
	DelegateeAgentID       string     `json:"delegatee_agent_id,omitempty"`
	DelegationDepth        *int       `json:"delegation_depth,omitempty"`
	ExternalAgentID        string     `json:"external_agent_id,omitempty"`
	IssuedVia              string     `json:"issued_via,omitempty"`
}

type MintDelegationRequest struct {
	SubjectPrincipalID string   `json:"subject_principal_id"`
	Purpose            string   `json:"purpose"`
	PermittedActions   []string `json:"permitted_actions"`
	TTLSeconds         *int     `json:"ttl_seconds,omitempty"`
}

type MintDelegationResponse struct {
	Grant              DelegationGrant `json:"grant"`
	Token              string          `json:"token,omitempty"`
	TokenAlreadyIssued bool            `json:"token_already_issued,omitempty"`
}

type AgentRun struct {
	ID                  string     `json:"id"`
	TenantID            string     `json:"tenant_id"`
	AgentID             string     `json:"agent_id"`
	DelegationGrantID   string     `json:"delegation_grant_id"`
	UserID              string     `json:"user_id"`
	Purpose             string     `json:"purpose"`
	Region              string     `json:"region"`
	Status              string     `json:"status"`
	TraceID             string     `json:"trace_id,omitempty"`
	StartedAt           time.Time  `json:"started_at"`
	CompletedAt         *time.Time `json:"completed_at,omitempty"`
	ErrorCode           *string    `json:"error_code,omitempty"`
	RootGrantID         string     `json:"root_grant_id,omitempty"`
	ParentGrantID       string     `json:"parent_grant_id,omitempty"`
	DelegationDepth     *int       `json:"delegation_depth,omitempty"`
	ChainVerification   string     `json:"chain_verification,omitempty"`
	ExternalAgentID     string     `json:"external_agent_id,omitempty"`
	OrganizationID      string     `json:"organization_id,omitempty"`
	CustomerPrincipalID string     `json:"customer_principal_id,omitempty"`
	ConsentID           string     `json:"consent_id,omitempty"`
}

type ActionDecision struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	AgentID           string    `json:"agent_id"`
	RunID             string    `json:"run_id"`
	DelegationGrantID string    `json:"delegation_grant_id"`
	ToolID            string    `json:"tool_id,omitempty"`
	ActionID          string    `json:"action_id,omitempty"`
	ResourceRef       string    `json:"resource_ref"`
	Decision          string    `json:"decision"`
	Reason            string    `json:"reason"`
	ReasonCode        string    `json:"reason_code,omitempty"`
	PolicyVersion     string    `json:"policy_version"`
	ImmutableDigest   string    `json:"immutable_digest"`
	CreatedAt         time.Time `json:"created_at"`
	DelegationDepth   int       `json:"delegation_depth"`
	ChainVerification string    `json:"chain_verification,omitempty"`
}

type ActionApproval struct {
	ID                   string     `json:"id"`
	TenantID             string     `json:"tenant_id"`
	RunID                string     `json:"run_id"`
	ToolID               string     `json:"tool_id"`
	ActionID             string     `json:"action_id"`
	ResourceRef          string     `json:"resource_ref"`
	ApprovingPrincipalID string     `json:"approving_principal_id"`
	Decision             string     `json:"decision"`
	ExpiresAt            time.Time  `json:"expires_at"`
	ConsumedAt           *time.Time `json:"consumed_at,omitempty"`
	ImmutableDigest      string     `json:"immutable_digest"`
	CreatedAt            time.Time  `json:"created_at"`
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

type RunListResponse struct {
	Runs  []AgentRun `json:"runs"`
	Count int        `json:"count"`
}

type RunDetailResponse struct {
	Run       AgentRun         `json:"run"`
	Decisions []ActionDecision `json:"decisions"`
}

type EvaluateActionRequest struct {
	DelegationToken string         `json:"delegation_token"`
	RunID           string         `json:"run_id"`
	ToolName        string         `json:"tool_name"`
	Action          string         `json:"action"`
	ResourceRef     string         `json:"resource_ref"`
	Arguments       map[string]any `json:"arguments,omitempty"`
	TraceID         string         `json:"trace_id,omitempty"`
}

type EvaluateActionResponse struct {
	Decision ActionDecision `json:"decision"`
	Allowed  bool           `json:"allowed"`
}

type GateCheck struct {
	Gate       string `json:"gate"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	ReasonCode string `json:"reason_code,omitempty"`
}

type SimulateActionRequest struct {
	AgentID     string `json:"agent_id"`
	VersionID   string `json:"version_id,omitempty"`
	ToolName    string `json:"tool_name"`
	Action      string `json:"action"`
	ResourceRef string `json:"resource_ref"`
	PrincipalID string `json:"principal_id,omitempty"`
}

type SimulateActionResponse struct {
	Decision    string      `json:"decision"`
	Allowed     bool        `json:"allowed"`
	Reason      string      `json:"reason"`
	ReasonCode  string      `json:"reason_code,omitempty"`
	Checks      []GateCheck `json:"checks"`
	Simulated   bool        `json:"simulated"`
	SimulatedAt time.Time   `json:"simulated_at"`
}

type GovernanceSimulateResponse struct {
	Simulation SimulateActionResponse `json:"simulation"`
}

type ApproveActionRequest struct {
	ResourceRef string `json:"resource_ref"`
}

type ApproveActionResponse struct {
	Approval ActionApproval `json:"approval"`
	Denied   bool           `json:"denied"`
}

type DispatchResponse struct {
	Decision     ActionDecision `json:"decision"`
	Allowed      bool           `json:"allowed"`
	DispatchMode string         `json:"dispatch_mode,omitempty"`
	Invocation   any            `json:"invocation,omitempty"`
	Response     any            `json:"response,omitempty"`
}

type ControlRequest struct {
	Reason string `json:"reason"`
	Scope  string `json:"scope,omitempty"`
}

type ControlResponse struct {
	Control EmergencyControl `json:"control"`
}

// ---------------------------------------------------------------------
// Governance: emergency controls, budgets, evidence, outbox
// ---------------------------------------------------------------------

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

type ControlsResponse struct {
	Controls []EmergencyControl `json:"controls"`
	Count    int                `json:"count"`
}

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

type BudgetUpsertRequest struct {
	ScopeType                   string `json:"scope_type"`
	AgentVersionID              string `json:"agent_version_id,omitempty"`
	GrantID                     string `json:"grant_id,omitempty"`
	MaxActionsPerRun            *int   `json:"max_actions_per_run,omitempty"`
	MaxDeniedPerRun             *int   `json:"max_denied_per_run,omitempty"`
	MaxApprovalRequiredPerRun   *int   `json:"max_approval_required_per_run,omitempty"`
	MaxToolCallsPerActionPerRun *int   `json:"max_tool_calls_per_action_per_run,omitempty"`
	MaxRunDurationSeconds       *int   `json:"max_run_duration_seconds,omitempty"`
	MaxCitationsPerQuery        *int   `json:"max_citations_per_query,omitempty"`
}

type BudgetResponse struct {
	Budget BudgetPolicy `json:"budget"`
}

type BudgetsResponse struct {
	Budgets []BudgetPolicy `json:"budgets"`
	Count   int            `json:"count"`
}

type EvidenceEvent struct {
	ID              string         `json:"id"`
	TenantID        string         `json:"tenant_id"`
	Kind            string         `json:"kind"`
	EntityID        string         `json:"entity_id"`
	Data            map[string]any `json:"data"`
	ImmutableDigest string         `json:"immutable_digest"`
	PreviousHash    string         `json:"previous_hash,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
}

type EvidencePage struct {
	Events     []EvidenceEvent `json:"events"`
	NextCursor string          `json:"next_cursor,omitempty"`
	Count      int             `json:"count"`
}

type EvidenceEventResponse struct {
	Event EvidenceEvent `json:"event"`
}

type TimelineResponse struct {
	Events []EvidenceEvent `json:"events"`
	Count  int             `json:"count"`
}

type ActivityResponse struct {
	Events []EvidenceEvent `json:"events"`
	Count  int             `json:"count"`
}

type Checkpoint struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	BlockHash   string    `json:"block_hash"`
	EventsCount int       `json:"events_count"`
	CreatedAt   time.Time `json:"created_at"`
}

type CheckpointsResponse struct {
	Checkpoints []Checkpoint `json:"checkpoints"`
	Count       int          `json:"count"`
}

type OutboxEvent struct {
	ID            string         `json:"id"`
	EventType     string         `json:"event_type"`
	EntityID      string         `json:"entity_id"`
	Payload       map[string]any `json:"payload"`
	Status        string         `json:"status"`
	Attempts      int            `json:"attempts"`
	LastError     *string        `json:"last_error,omitempty"`
	NextAttemptAt *time.Time     `json:"next_attempt_at,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     *time.Time     `json:"updated_at,omitempty"`
}

type OutboxResponse struct {
	Events     []OutboxEvent `json:"events"`
	NextCursor string        `json:"next_cursor,omitempty"`
	Count      int           `json:"count"`
}

type OutboxEventResponse struct {
	Event OutboxEvent `json:"event"`
}

// ---------------------------------------------------------------------
// Governance: connectors (Phase 5)
// ---------------------------------------------------------------------

type ConnectorConfig struct {
	BaseURL             string   `json:"base_url"`
	Region              string   `json:"region"`
	TimeoutMs           *int     `json:"timeout_ms,omitempty"`
	RetryMax            *int     `json:"retry_max,omitempty"`
	RetryIdempotentOnly *bool    `json:"retry_idempotent_only,omitempty"`
	MaxResponseBytes    *int     `json:"max_response_bytes,omitempty"`
	TLSVerify           *bool    `json:"tls_verify,omitempty"`
	SecretRef           string   `json:"secret_ref,omitempty"`
	ClientCertRef       string   `json:"client_cert_ref,omitempty"`
	AllowedContentTypes []string `json:"allowed_content_types,omitempty"`
	RedactionFields     []string `json:"redaction_fields,omitempty"`
}

type ConnectorActionManifest struct {
	Name                   string   `json:"name"`
	TransportMethod        string   `json:"transport_method"`
	PathTemplate           string   `json:"path_template,omitempty"`
	ResourceType           string   `json:"resource_type,omitempty"`
	Risk                   string   `json:"risk"`
	ReadOnly               *bool    `json:"read_only,omitempty"`
	RequiresApproval       *bool    `json:"requires_approval,omitempty"`
	MaxRequestBytes        *int     `json:"max_request_bytes,omitempty"`
	MaxResponseBytes       *int     `json:"max_response_bytes,omitempty"`
	AllowedAgentVersionIDs []string `json:"allowed_agent_version_ids,omitempty"`
	Args                   []string `json:"args,omitempty"`
}

type ConnectorRegisterRequest struct {
	Name        string                    `json:"name"`
	Type        string                    `json:"type"`
	Config      ConnectorConfig           `json:"config"`
	Actions     []ConnectorActionManifest `json:"actions"`
	Description string                    `json:"description,omitempty"`
}

type ConnectorDetail struct {
	ID             string                    `json:"id"`
	Name           string                    `json:"name"`
	Type           string                    `json:"type"`
	Description    *string                   `json:"description,omitempty"`
	Config         ConnectorConfig           `json:"config"`
	Actions        []ConnectorActionManifest `json:"actions"`
	ConfigDigest   string                    `json:"config_digest"`
	ManifestDigest string                    `json:"manifest_digest"`
	Status         string                    `json:"status"`
	CreatedBy      string                    `json:"created_by"`
	CreatedAt      time.Time                 `json:"created_at"`
	UpdatedAt      time.Time                 `json:"updated_at"`
}

type ConnectorHealth struct {
	ConnectorID string    `json:"connector_id"`
	Healthy     bool      `json:"healthy"`
	StatusCode  *int      `json:"status_code,omitempty"`
	ErrorCode   *string   `json:"error_code,omitempty"`
	LatencyMs   *int      `json:"latency_ms,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
}

type ConnectorsResponse struct {
	Connectors []ConnectorDetail `json:"connectors"`
	Count      int               `json:"count"`
}

type ConnectorDetailResponse struct {
	Detail ConnectorDetail `json:"detail"`
}

type ConnectorManifestResponse struct {
	Actions        []ConnectorActionManifest `json:"actions"`
	ManifestDigest string                    `json:"manifest_digest"`
}

type ConnectorHealthResponse struct {
	Health ConnectorHealth `json:"health"`
}

type ConnectorConfigUpdateRequest struct {
	TimeoutMs           *int     `json:"timeout_ms,omitempty"`
	RetryMax            *int     `json:"retry_max,omitempty"`
	RetryIdempotentOnly *bool    `json:"retry_idempotent_only,omitempty"`
	MaxResponseBytes    *int     `json:"max_response_bytes,omitempty"`
	TLSVerify           *bool    `json:"tls_verify,omitempty"`
	SecretRef           string   `json:"secret_ref,omitempty"`
	ClientCertRef       string   `json:"client_cert_ref,omitempty"`
	AllowedContentTypes []string `json:"allowed_content_types,omitempty"`
	RedactionFields     []string `json:"redaction_fields,omitempty"`
}

// ---------------------------------------------------------------------
// Governance: trust, external agents, consents, transfers, budgets (Phase 6)
// ---------------------------------------------------------------------

type AgentTrustRelationship struct {
	ID                  string              `json:"id"`
	TenantID            string              `json:"tenant_id"`
	ParentAgentID       string              `json:"parent_agent_id"`
	ChildAgentID        *string             `json:"child_agent_id,omitempty"`
	ExternalAgentID     *string             `json:"external_agent_id,omitempty"`
	TrustDomain         string              `json:"trust_domain"`
	OwnerPrincipalID    string              `json:"owner_principal_id"`
	Purpose             string              `json:"purpose"`
	MaxDelegationDepth  int                 `json:"max_delegation_depth"`
	AllowedToolsActions map[string][]string `json:"allowed_tools_actions,omitempty"`
	Region              string              `json:"region"`
	ExpiresAt           time.Time           `json:"expires_at"`
	Status              string              `json:"status"`
	ApprovalRequired    bool                `json:"approval_required"`
	Reason              *string             `json:"reason,omitempty"`
	ImmutableDigest     string              `json:"immutable_digest"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
}

type CreateTrustRelationshipRequest struct {
	ChildAgentID        string              `json:"child_agent_id"`
	TrustDomain         string              `json:"trust_domain"`
	Purpose             string              `json:"purpose"`
	MaxDelegationDepth  int                 `json:"max_delegation_depth"`
	AllowedToolsActions map[string][]string `json:"allowed_tools_actions,omitempty"`
	Region              string              `json:"region"`
	ExpiresAt           time.Time           `json:"expires_at"`
	ApprovalRequired    *bool               `json:"approval_required,omitempty"`
}

type ExternalAgent struct {
	ID                  string              `json:"id"`
	ExternalAgentID     string              `json:"external_agent_id"`
	AgentID             string              `json:"agent_id"`
	OrganizationID      string              `json:"organization_id"`
	TenantID            string              `json:"tenant_id"`
	OwnerPrincipalID    string              `json:"owner_principal_id"`
	VerifiedIssuer      string              `json:"verified_issuer"`
	AllowedAudiences    []string            `json:"allowed_audiences"`
	AuthMethod          string              `json:"auth_method"`
	TrustTier           string              `json:"trust_tier"`
	Region              string              `json:"region"`
	AllowedToolsActions map[string][]string `json:"allowed_tools_actions,omitempty"`
	PublicKeyJWKSRef    string              `json:"public_key_jwks_ref"`
	ManifestDigest      string              `json:"manifest_digest"`
	SecurityContact     *string             `json:"security_contact,omitempty"`
	LifecycleState      string              `json:"lifecycle_state"`
	ExpiresAt           *time.Time          `json:"expires_at,omitempty"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
}

type CreateExternalAgentRequest struct {
	ExternalAgentID     string              `json:"external_agent_id"`
	AgentID             string              `json:"agent_id"`
	OrganizationID      string              `json:"organization_id"`
	VerifiedIssuer      string              `json:"verified_issuer"`
	AllowedAudiences    []string            `json:"allowed_audiences"`
	AuthMethod          string              `json:"auth_method"`
	TrustTier           string              `json:"trust_tier"`
	Region              string              `json:"region"`
	AllowedToolsActions map[string][]string `json:"allowed_tools_actions,omitempty"`
	PublicKeyJWKSRef    string              `json:"public_key_jwks_ref"`
	ManifestDigest      string              `json:"manifest_digest,omitempty"`
	SecurityContact     string              `json:"security_contact,omitempty"`
	TTLSeconds          *int                `json:"ttl_seconds,omitempty"`
}

type ConsentRecord struct {
	ID                  string     `json:"id"`
	TenantID            string     `json:"tenant_id"`
	OrganizationID      string     `json:"organization_id"`
	ExternalAgentID     string     `json:"external_agent_id"`
	CustomerPrincipalID string     `json:"customer_principal_id"`
	Purpose             string     `json:"purpose"`
	ResourceRefPattern  string     `json:"resource_ref_pattern"`
	Status              string     `json:"status"`
	GrantedBy           string     `json:"granted_by"`
	GrantedAt           time.Time  `json:"granted_at"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	ImmutableDigest     string     `json:"immutable_digest"`
}

type CreateConsentRequest struct {
	OrganizationID      string `json:"organization_id"`
	ExternalAgentID     string `json:"external_agent_id"`
	CustomerPrincipalID string `json:"customer_principal_id"`
	Purpose             string `json:"purpose"`
	ResourceRefPattern  string `json:"resource_ref_pattern"`
	TTLSeconds          *int   `json:"ttl_seconds,omitempty"`
}

type TransferPolicy struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	SourceRegion   string    `json:"source_region"`
	TargetRegion   string    `json:"target_region"`
	PurposePattern string    `json:"purpose_pattern"`
	Enabled        bool      `json:"enabled"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
}

type UpsertTransferPolicyRequest struct {
	SourceRegion   string `json:"source_region"`
	TargetRegion   string `json:"target_region"`
	PurposePattern string `json:"purpose_pattern"`
	Enabled        bool   `json:"enabled"`
}

type DelegationChainNode struct {
	Grant               DelegationGrant `json:"grant"`
	DelegatorAgentID    *string         `json:"delegator_agent_id,omitempty"`
	DelegatorAgentName  *string         `json:"delegator_agent_name,omitempty"`
	DelegateeAgentID    *string         `json:"delegatee_agent_id,omitempty"`
	DelegateeAgentName  *string         `json:"delegatee_agent_name,omitempty"`
	TrustRelationshipID string          `json:"trust_relationship_id"`
	Verified            bool            `json:"verified"`
	Problem             *string         `json:"problem,omitempty"`
}

type DelegationChain struct {
	RootGrantID string                `json:"root_grant_id"`
	LeafGrantID string                `json:"leaf_grant_id"`
	Depth       int                   `json:"depth"`
	Verified    bool                  `json:"verified"`
	Problem     *string               `json:"problem,omitempty"`
	Nodes       []DelegationChainNode `json:"nodes"`
}

type TrustRelationshipResponse struct {
	Relationship AgentTrustRelationship `json:"relationship"`
}

type TrustRelationshipsResponse struct {
	Relationships []AgentTrustRelationship `json:"relationships"`
	Count         int                      `json:"count"`
}

type DelegationChainResponse struct {
	Chain DelegationChain `json:"chain"`
}

type ChainControlResponse struct {
	GrantsChanged int `json:"grants_changed"`
}

type ExternalAgentResponse struct {
	Agent ExternalAgent `json:"agent"`
}

type ExternalAgentsResponse struct {
	Agents []ExternalAgent `json:"agents"`
	Count  int             `json:"count"`
}

type ExternalAgentHealthResponse struct {
	ExternalAgentID string    `json:"external_agent_id"`
	LifecycleState  string    `json:"lifecycle_state"`
	TrustTier       string    `json:"trust_tier"`
	Region          string    `json:"region"`
	ExpiresAt       time.Time `json:"expires_at"`
	Healthy         bool      `json:"healthy"`
	Reason          string    `json:"reason,omitempty"`
}

type ConsentResponse struct {
	Consent ConsentRecord `json:"consent"`
}

type ConsentsResponse struct {
	Consents []ConsentRecord `json:"consents"`
	Count    int             `json:"count"`
}

type TransferPolicyResponse struct {
	Policy TransferPolicy `json:"policy"`
}

type TransferPoliciesResponse struct {
	Policies []TransferPolicy `json:"policies"`
	Count    int              `json:"count"`
}

type ExternalBudgetPolicy struct {
	ID                          string    `json:"id"`
	TenantID                    string    `json:"tenant_id"`
	ScopeType                   string    `json:"scope_type"`
	ExternalAgentID             *string   `json:"external_agent_id,omitempty"`
	OrganizationID              *string   `json:"organization_id,omitempty"`
	CustomerPrincipalID         *string   `json:"customer_principal_id,omitempty"`
	MaxTotalActions             int       `json:"max_total_actions"`
	MaxActionsPerRun            int       `json:"max_actions_per_run"`
	MaxDeniedPerRun             int       `json:"max_denied_per_run"`
	MaxApprovalRequiredPerRun   int       `json:"max_approval_required_per_run"`
	MaxToolCallsPerActionPerRun int       `json:"max_tool_calls_per_action_per_run"`
	ActionsCount                int       `json:"actions_count"`
	DeniedCount                 int       `json:"denied_count"`
	ApprovalRequiredCount       int       `json:"approval_required_count"`
	ToolCallsCount              int       `json:"tool_calls_count"`
	CreatedBy                   string    `json:"created_by"`
	CreatedAt                   time.Time `json:"created_at"`
	UpdatedAt                   time.Time `json:"updated_at"`
}

type ExternalBudgetResponse struct {
	Budget ExternalBudgetPolicy `json:"budget"`
}

type ExternalBudgetsResponse struct {
	Budgets []ExternalBudgetPolicy `json:"budgets"`
	Count   int                    `json:"count"`
}

type UpsertExternalBudgetRequest struct {
	MaxTotalActions             *int `json:"max_total_actions,omitempty"`
	MaxActionsPerRun            *int `json:"max_actions_per_run,omitempty"`
	MaxDeniedPerRun             *int `json:"max_denied_per_run,omitempty"`
	MaxApprovalRequiredPerRun   *int `json:"max_approval_required_per_run,omitempty"`
	MaxToolCallsPerActionPerRun *int `json:"max_tool_calls_per_action_per_run,omitempty"`
}

type UsageLimit struct {
	Metric string `json:"metric"`
	Period string `json:"period"`
	Limit  int64  `json:"limit"`
}

type MetricUsage struct {
	Metric    string `json:"metric"`
	Period    string `json:"period"`
	Count     int64  `json:"count"`
	Limit     int64  `json:"limit"`
	Remaining int64  `json:"remaining"`
}

type UsageResponse struct {
	TenantID string        `json:"tenant_id"`
	Period   string        `json:"period"`
	Usage    []MetricUsage `json:"usage"`
}

type UsageLimitsResponse struct {
	TenantID string       `json:"tenant_id"`
	Limits   []UsageLimit `json:"limits"`
}

type PutUsageLimitsRequest struct {
	Limits []UsageLimit `json:"limits"`
}

type ExternalRunAction struct {
	Action      string            `json:"action"`
	ResourceRef string            `json:"resource_ref"`
	Args        map[string]string `json:"args"`
}

type CreateExternalRunRequest struct {
	ExternalToken   string              `json:"external_token"`
	DelegationToken string              `json:"delegation_token"`
	Actions         []ExternalRunAction `json:"actions"`
}

type ExternalRun struct {
	ID                  string     `json:"id"`
	TenantID            string     `json:"tenant_id"`
	ExternalAgentID     string     `json:"external_agent_id"`
	OrganizationID      string     `json:"organization_id"`
	CustomerPrincipalID string     `json:"customer_principal_id,omitempty"`
	ConsentID           string     `json:"consent_id"`
	Status              string     `json:"status"`
	StartedAt           time.Time  `json:"started_at"`
	CompletedAt         *time.Time `json:"completed_at,omitempty"`
	ErrorCode           *string    `json:"error_code,omitempty"`
	TraceID             string     `json:"trace_id,omitempty"`
}

// ---------------------------------------------------------------------
// Audit, admin, health, query
// ---------------------------------------------------------------------

type AccessDecisionSummary struct {
	Action      string `json:"action"`
	ResourceRef string `json:"resource_ref,omitempty"`
	Decision    string `json:"decision"`
	Reason      string `json:"reason,omitempty"`
}

type AuditEntryRead struct {
	TraceID             string                  `json:"trace_id"`
	TimestampUTC        time.Time               `json:"timestamp_utc"`
	TenantID            string                  `json:"tenant_id"`
	UserID              *string                 `json:"user_id,omitempty"`
	Region              string                  `json:"region"`
	AgentKeyID          string                  `json:"agent_key_id"`
	AgentKeyName        string                  `json:"agent_key_name"`
	DecisionMode        string                  `json:"decision_mode"`
	ACLDecision         string                  `json:"acl_decision"`
	Reason              string                  `json:"reason"`
	FailClosed          bool                    `json:"fail_closed"`
	FailStage           *string                 `json:"fail_stage,omitempty"`
	ErrorCode           *string                 `json:"error_code,omitempty"`
	ErrorMessage        *string                 `json:"error_message,omitempty"`
	CandidatesRetrieved int                     `json:"candidates_retrieved"`
	CandidatesAllowed   int                     `json:"candidates_allowed"`
	CandidatesBlocked   int                     `json:"candidates_blocked"`
	TotalLatencyMs      int                     `json:"total_latency_ms"`
	OpenFGALatencyMs    int                     `json:"openfga_latency_ms"`
	QdrantLatencyMs     int                     `json:"qdrant_latency_ms"`
	CircuitBreakerState string                  `json:"circuit_breaker_state"`
	IdentityResolution  string                  `json:"identity_resolution"`
	PrincipalID         *string                 `json:"principal_id,omitempty"`
	QueryHash           string                  `json:"query_hash"`
	ImmutableDigest     string                  `json:"immutable_digest"`
	PreviousHash        string                  `json:"previous_hash"`
	AccessDecisions     []AccessDecisionSummary `json:"access_decisions,omitempty"`
}

type AuditListResponse struct {
	Entries    []AuditEntryRead `json:"entries"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

type ApiKeySummary struct {
	ID         string     `json:"id"`
	KeyPrefix  string     `json:"key_prefix"`
	Name       *string    `json:"name,omitempty"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Revoked    bool       `json:"revoked"`
}

type ApiKeyListResponse struct {
	APIKeys []ApiKeySummary `json:"api_keys"`
	Count   int             `json:"count"`
}

type CreateApiKeyRequest struct {
	Name      string   `json:"name,omitempty"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expires_at,omitempty"`
}

type CreateApiKeyResponse struct {
	APIKey struct {
		ID        string     `json:"id"`
		Name      *string    `json:"name,omitempty"`
		Scopes    []string   `json:"scopes"`
		CreatedAt time.Time  `json:"created_at"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	} `json:"api_key"`
	Secret string `json:"secret"`
}

type HealthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
}

type QueryResponse struct {
	Answer     string   `json:"answer"`
	TraceID    string   `json:"trace_id"`
	QueryHash  string   `json:"query_hash,omitempty"`
	Sources    []string `json:"sources,omitempty"`
	Candidates *int     `json:"candidates,omitempty"`
}

type QueryRequest struct {
	Query   string `json:"query"`
	AgentID string `json:"agent_id,omitempty"`
	TopK    *int   `json:"top_k,omitempty"`
}
