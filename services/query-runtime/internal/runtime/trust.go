// Phase 6: Multi-Agent Delegation & External-Agent Trust — runtime contract.
//
// Central rule: a child agent may never receive more authority than its
// parent agent possesses. Delegation chains (human or service principal
// -> parent agent -> child agent -> tool/action/resource) are bounded,
// attenuated, auditable, and revocable end to end.
//
// Trust is never implicit from shared tenant membership: every child
// delegation requires an explicit, active agent trust relationship.
// Cross-tenant delegation is denied by default; cross-region delegation
// is denied unless an explicit transfer policy allows it. A revoked
// parent immediately invalidates every descendant delegation. External
// agents are untrusted by default and must present a validated identity
// (issuer, audience, signature, jti) plus an explicit trust relationship
// before any action.
//
// No raw token is ever written to logs, evidence, console responses, or
// outbox payloads — only jti and digests.

package runtime

import (
	"errors"
	"time"
)

// Trust relationship lifecycle states.
const (
	TrustStateRequested = "requested"
	TrustStateApproved  = "approved"
	TrustStateActive    = "active"
	TrustStateSuspended = "suspended"
	TrustStateRevoked   = "revoked"
	TrustStateExpired   = "expired"
)

// Trust event types recorded as hash-chained evidence.
const (
	TrustEventRequested      = "trust.requested"
	TrustEventApproved       = "trust.approved"
	TrustEventActivated      = "trust.activated"
	TrustEventSuspended      = "trust.suspended"
	TrustEventResumed        = "trust.resumed"
	TrustEventRevoked        = "trust.revoked"
	TrustEventChildMinted    = "delegation.child_minted"
	TrustEventChainRevoked   = "chain.revoked"
	TrustEventChainPaused    = "chain.suspended"
	TrustEventChainResumed   = "chain.resumed"
	TrustEventExternal       = "external.agent"
	TrustEventConsent        = "consent.granted"
	TrustEventChainVerified  = "chain.verified"
	TrustEventConsentRevoked = "consent.revoked"
	TrustEventTransferPolicy = "transfer_policy.updated"
)

// Evidence kinds exposed for trust / chain / external activity are
// declared in governance.go (EvidenceKindTrustEvent, EvidenceKindChainRevoke).

// External-agent authentication methods.
const (
	ExternalAuthOIDC         = "oidc"
	ExternalAuthJWKS         = "jwt_jwks"
	ExternalAuthMTLS         = "mtls"
	ExternalAuthInternalDemo = "internal_demo"
)

// External-agent trust tiers. Default is untrusted.
const (
	TrustTierUntrusted = "untrusted"
	TrustTierVerified  = "verified"
	TrustTierPartner   = "partner"
	TrustTierCustomer  = "customer"
)

// External-agent lifecycle states.
const (
	ExternalStatePending   = "pending"
	ExternalStateActive    = "active"
	ExternalStateSuspended = "suspended"
	ExternalStateRevoked   = "revoked"
	ExternalStateExpired   = "expired"
)

// DefaultDelegationMaxDepth is the default cap on how deep an agent
// delegation chain may grow (configurable via
// GROUNDWORK_DELEGATION_MAX_DEPTH, clamped to [1,10]).
const DefaultDelegationMaxDepth = 3

// Sentinel errors for Phase 6. The HTTP layer maps these to status
// codes; unknown errors never leak DB internals.
var (
	ErrTrustNotFound         = errors.New("trust relationship not found")
	ErrTrustConflict         = errors.New("trust relationship already exists")
	ErrTrustInvalidState     = errors.New("trust relationship transition invalid")
	ErrTrustNotActive        = errors.New("trust relationship is not active")
	ErrTrustExpired          = errors.New("trust relationship is expired")
	ErrTrustRequiresApproval = errors.New("trust relationship requires approval")

	ErrChainTooDeep        = errors.New("delegation chain depth exceeded")
	ErrScopeExceedsParent  = errors.New("child scope exceeds parent scope")
	ErrExpiryExceedsParent = errors.New("child expiry exceeds parent expiry")
	ErrRegionExceedsParent = errors.New("child region exceeds parent region")
	ErrCrossTenantDenied   = errors.New("cross-tenant delegation denied")
	ErrCrossRegionDenied   = errors.New("cross-region delegation denied")
	ErrParentRevoked       = errors.New("parent delegation revoked")
	ErrParentSuspended     = errors.New("parent delegation suspended")
	ErrChildCannotDelegate = errors.New("child agent cannot delegate")
	ErrChainBroken         = errors.New("delegation chain invalid")
	ErrNoParentGrant       = errors.New("parent delegation not found")

	ErrExternalNotFound           = errors.New("external agent not found")
	ErrExternalConflict           = errors.New("external agent already exists")
	ErrExternalNotActive          = errors.New("external agent is not active")
	ErrExternalExpired            = errors.New("external agent identity expired")
	ErrExternalUntrusted          = errors.New("external agent is untrusted")
	ErrExternalInvalid            = errors.New("external agent identity invalid")
	ErrExternalNoTrust            = errors.New("external agent has no active trust relationship")
	ErrExternalDemoDenied         = errors.New("internal demo identity not allowed")
	ErrConsentRequired            = errors.New("customer consent required")
	ErrConsentNotFound            = errors.New("consent record not found")
	ErrConsentConflict            = errors.New("active consent record already exists")
	ErrConsentRevoked             = errors.New("consent record revoked")
	ErrConsentExpired             = errors.New("consent record expired")
	ErrNonceReplay                = errors.New("external token replay detected")
	ErrTransferDenied             = errors.New("cross-region transfer not permitted")
	ErrTransferPolicyNotFound     = errors.New("transfer policy not found")
	ErrTransferPolicyStateInvalid = errors.New("transfer policy transition invalid")
)

// ChildDelegationRequest creates a delegation grant for a child agent
// derived from a parent grant. All transport values come from the
// registry — never from the request body.
type ChildDelegationRequest struct {
	ParentGrantID       string   `json:"parent_grant_id"`
	ChildAgentID        string   `json:"child_agent_id"`
	TrustRelationshipID string   `json:"trust_relationship_id"`
	Purpose             string   `json:"purpose"`
	PermittedActions    []string `json:"permitted_actions"`
	TTLSeconds          int      `json:"ttl_seconds,omitempty"`
	// SubjectPrincipalID, when empty, is inherited from the parent
	// grant (the verified delegated principal).
	SubjectPrincipalID string `json:"subject_principal_id,omitempty"`
}

// CreateExternalRunRequest starts a governed run on behalf of a
// customer principal authenticated through an external agent identity
// plus a delegation token minted for that external agent.
type CreateExternalRunRequest struct {
	ExternalToken   string             `json:"external_token"`
	DelegationToken string             `json:"delegation_token"`
	Actions         []RunActionRequest `json:"actions"`
}

// AgentTrustRelationship is an explicit, attested trust edge between a
// parent agent and a child agent (or external agent). Nothing about
// shared tenant membership implies trust.
type AgentTrustRelationship struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	ParentAgentID       string    `json:"parent_agent_id"`
	ChildAgentID        string    `json:"child_agent_id,omitempty"`
	ExternalAgentID     string    `json:"external_agent_id,omitempty"`
	TrustDomain         string    `json:"trust_domain"`
	OwnerPrincipalID    string    `json:"owner_principal_id"`
	Purpose             string    `json:"purpose"`
	MaxDelegationDepth  int       `json:"max_delegation_depth"`
	AllowedToolsActions []string  `json:"allowed_tools_actions,omitempty"` // empty = parent's whole scope
	Region              string    `json:"region"`
	ExpiresAt           time.Time `json:"expires_at"`
	Status              string    `json:"status"`
	ApprovalRequired    bool      `json:"approval_required"`
	Reason              string    `json:"reason,omitempty"`
	ImmutableDigest     string    `json:"immutable_digest"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// TrustRelationshipRequest creates a relationship in 'requested'
// (approval_required) or 'approved' state; activation is explicit.
// ParentAgentID is the source-of-authority agent (registry identity).
type TrustRelationshipRequest struct {
	ParentAgentID       string   `json:"parent_agent_id"`
	ChildAgentID        string   `json:"child_agent_id,omitempty"`
	ExternalAgentID     string   `json:"external_agent_id,omitempty"`
	TrustDomain         string   `json:"trust_domain"`
	Purpose             string   `json:"purpose"`
	MaxDelegationDepth  int      `json:"max_delegation_depth"`
	AllowedToolsActions []string `json:"allowed_tools_actions,omitempty"`
	Region              string   `json:"region"`
	ExpiresAt           string   `json:"expires_at"` // RFC3339
	ApprovalRequired    bool     `json:"approval_required"`
}

// TrustTransitionRequest is the body for trust lifecycle transitions.
type TrustTransitionRequest struct {
	Reason string `json:"reason"`
}

// ExternalAgent is one onboarded external agent. External agents are
// never trusted merely because they can reach the gateway: the default
// trust tier is 'untrusted' (no data or tool access), and every action
// requires a validated identity plus an explicit active trust
// relationship.
type ExternalAgent struct {
	ID                  string    `json:"id"`
	ExternalAgentID     string    `json:"external_agent_id"`
	AgentID             string    `json:"agent_id"` // paired agent-registry identity
	OrganizationID      string    `json:"organization_id"`
	TenantID            string    `json:"tenant_id"`
	OwnerPrincipalID    string    `json:"owner_principal_id"`
	VerifiedIssuer      string    `json:"verified_issuer"`
	AllowedAudiences    []string  `json:"allowed_audiences"`
	AuthMethod          string    `json:"auth_method"`
	TrustTier           string    `json:"trust_tier"`
	Region              string    `json:"region"`
	AllowedToolsActions []string  `json:"allowed_tools_actions,omitempty"`
	PublicKeyJWKSRef    string    `json:"public_key_jwks_ref,omitempty"`
	ManifestDigest      string    `json:"manifest_digest,omitempty"`
	SecurityContact     string    `json:"security_contact,omitempty"`
	LifecycleState      string    `json:"lifecycle_state"`
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// ExternalAgentRequest is the onboarding body. AgentID is the paired
// agent-registry identity the external agent acts under (must be a
// registered, active agent of the tenant).
type ExternalAgentRequest struct {
	ExternalAgentID     string   `json:"external_agent_id"`
	AgentID             string   `json:"agent_id"`
	OrganizationID      string   `json:"organization_id"`
	VerifiedIssuer      string   `json:"verified_issuer"`
	AllowedAudiences    []string `json:"allowed_audiences"`
	AuthMethod          string   `json:"auth_method"`
	TrustTier           string   `json:"trust_tier"`
	Region              string   `json:"region"`
	AllowedToolsActions []string `json:"allowed_tools_actions,omitempty"`
	PublicKeyJWKSRef    string   `json:"public_key_jwks_ref,omitempty"`
	ManifestDigest      string   `json:"manifest_digest,omitempty"`
	SecurityContact     string   `json:"security_contact,omitempty"`
	TTLSeconds          int      `json:"ttl_seconds,omitempty"`
}

// ExternalSessionRequest authenticates an external agent and binds the
// customer principal + purpose for a run.
type ExternalSessionRequest struct {
	Token               string `json:"token"`
	CustomerPrincipalID string `json:"customer_principal_id,omitempty"`
	Purpose             string `json:"purpose,omitempty"`
}

// ExternalSession is the result of a validated external identity.
// Identities come ONLY from token validation against the registry —
// never from request bodies.
type ExternalSession struct {
	ExternalAgentID     string `json:"external_agent_id"`
	AgentID             string `json:"agent_id"`
	OrganizationID      string `json:"organization_id"`
	TenantID            string `json:"tenant_id"`
	TrustTier           string `json:"trust_tier"`
	VerifiedIssuer      string `json:"verified_issuer"`
	Subject             string `json:"subject"`
	JTI                 string `json:"jti"`
	Region              string `json:"region"`
	CustomerPrincipalID string `json:"customer_principal_id,omitempty"`
	Purpose             string `json:"purpose,omitempty"`
	AuthMethod          string `json:"auth_method"`
}

// TransferPolicy is an explicit, auditable cross-region delegation
// allowance. Cross-region delegation is denied unless a matching
// enabled policy exists.
type TransferPolicy struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	SourceRegion   string    `json:"source_region"`
	TargetRegion   string    `json:"target_region"`
	PurposePattern string    `json:"purpose_pattern"` // "*" or exact purpose
	Enabled        bool      `json:"enabled"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
}

// TransferPolicyRequest is the upsert body.
type TransferPolicyRequest struct {
	SourceRegion   string `json:"source_region"`
	TargetRegion   string `json:"target_region"`
	PurposePattern string `json:"purpose_pattern"`
	Enabled        bool   `json:"enabled"`
}

// ConsentRecord is a customer's explicit authorization for an external
// agent (organization) to act for them.
type ConsentRecord struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	OrganizationID      string    `json:"organization_id"`
	ExternalAgentID     string    `json:"external_agent_id"`
	CustomerPrincipalID string    `json:"customer_principal_id"`
	Purpose             string    `json:"purpose"`
	ResourceRefPattern  string    `json:"resource_ref_pattern"`
	Status              string    `json:"status"`
	GrantedBy           string    `json:"granted_by"`
	GrantedAt           time.Time `json:"granted_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	ImmutableDigest     string    `json:"immutable_digest"`
}

// ConsentRequest is the creation body.
type ConsentRequest struct {
	OrganizationID      string `json:"organization_id"`
	ExternalAgentID     string `json:"external_agent_id"`
	CustomerPrincipalID string `json:"customer_principal_id"`
	Purpose             string `json:"purpose"`
	ResourceRefPattern  string `json:"resource_ref_pattern,omitempty"`
	TTLSeconds          int    `json:"ttl_seconds,omitempty"`
}

// TrustEvent is one hash-chained trust/chain/external event.
type TrustEvent struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	EventType          string    `json:"event_type"`
	EntityType         string    `json:"entity_type"` // relationship | grant | external_agent | consent
	EntityID           string    `json:"entity_id"`
	ActorPrincipalID   string    `json:"actor_principal_id"`
	PreviousState      string    `json:"previous_state,omitempty"`
	NewState           string    `json:"new_state,omitempty"`
	Reason             string    `json:"reason,omitempty"`
	GrantID            string    `json:"grant_id,omitempty"`
	ParentGrantID      string    `json:"parent_grant_id,omitempty"`
	RootGrantID        string    `json:"root_grant_id,omitempty"`
	DelegationDepth    int       `json:"delegation_depth"`
	SubjectPrincipalID string    `json:"subject_principal_id,omitempty"`
	TrustDomain        string    `json:"trust_domain,omitempty"`
	OrganizationID     string    `json:"organization_id,omitempty"`
	ScopeDigest        string    `json:"scope_digest,omitempty"`
	AttenuationDigest  string    `json:"attenuation_digest,omitempty"`
	RevocationSource   string    `json:"revocation_source,omitempty"`
	ImmutableDigest    string    `json:"immutable_digest"`
	PreviousEventID    string    `json:"previous_event_id,omitempty"`
	OccurredAt         time.Time `json:"occurred_at"`
}

// DelegationChainNode is one verified link in a delegation chain.
type DelegationChainNode struct {
	Grant               DelegationGrant `json:"grant"`
	DelegatorAgentID    string          `json:"delegator_agent_id,omitempty"`
	DelegatorAgentName  string          `json:"delegator_agent_name,omitempty"`
	DelegateeAgentID    string          `json:"delegatee_agent_id,omitempty"`
	DelegateeAgentName  string          `json:"delegatee_agent_name,omitempty"`
	TrustRelationshipID string          `json:"trust_relationship_id,omitempty"`
	Verified            bool            `json:"verified"`
	Problem             string          `json:"problem,omitempty"`
}

// DelegationChain is the full verified path from the root grant down to
// (and including) the leaf grant.
type DelegationChain struct {
	RootGrantID string                `json:"root_grant_id"`
	LeafGrantID string                `json:"leaf_grant_id"`
	Depth       int                   `json:"depth"`
	Verified    bool                  `json:"verified"`
	Problem     string                `json:"problem,omitempty"`
	Nodes       []DelegationChainNode `json:"nodes"` // root first
}

// ProvenanceView answers, for one evidence event: who authorized the
// root action, which agent delegated, which child used it, what scope
// was inherited and whether it was attenuated, which tool/resource was
// accessed, which policy decided, whether the chain could be revoked,
// and the final outcome. No tokens or secrets are ever included.
type ProvenanceView struct {
	EventID            string    `json:"event_id"`
	Kind               string    `json:"kind"`
	TenantID           string    `json:"tenant_id"`
	OccurredAt         time.Time `json:"occurred_at"`
	RootGrantID        string    `json:"root_grant_id,omitempty"`
	ParentGrantID      string    `json:"parent_grant_id,omitempty"`
	ChildGrantID       string    `json:"child_grant_id,omitempty"`
	DelegationDepth    int       `json:"delegation_depth"`
	DelegatorAgentID   string    `json:"delegator_agent_id,omitempty"`
	DelegatorAgentName string    `json:"delegator_agent_name,omitempty"`
	DelegateeAgentID   string    `json:"delegatee_agent_id,omitempty"`
	DelegateeAgentName string    `json:"delegatee_agent_name,omitempty"`
	SubjectPrincipalID string    `json:"subject_principal_id,omitempty"`
	TrustDomain        string    `json:"trust_domain,omitempty"`
	OrganizationID     string    `json:"organization_id,omitempty"`
	Region             string    `json:"region,omitempty"`
	ScopeDigest        string    `json:"scope_digest,omitempty"`
	AttenuationDigest  string    `json:"attenuation_digest,omitempty"`
	ConnectorAction    string    `json:"connector_action,omitempty"`
	FinalDecision      string    `json:"final_decision,omitempty"`
	RevocationSource   string    `json:"revocation_source,omitempty"`
	ChainVerification  string    `json:"chain_verification,omitempty"`
	PolicyVersion      string    `json:"policy_version,omitempty"`
	ToolID             string    `json:"tool_id,omitempty"`
	ToolName           string    `json:"tool_name,omitempty"`
	ActionID           string    `json:"action_id,omitempty"`
	ResourceRef        string    `json:"resource_ref,omitempty"`
	Reason             string    `json:"reason,omitempty"`
	ReasonCode         string    `json:"reason_code,omitempty"`
	TraceID            string    `json:"trace_id,omitempty"`
	ImmutableDigest    string    `json:"immutable_digest"`
}

// ExternalBudgetScope types for external-agent budget policies.
const (
	ExternalBudgetScopeAgent        = "external_agent"
	ExternalBudgetScopeOrganization = "external_organization"
	ExternalBudgetScopeCustomer     = "customer"
)

// ExternalBudgetPolicy is one budget policy for an external scope.
// Narrowest applicable scope wins: customer > organization > agent.
type ExternalBudgetPolicy struct {
	ID                          string    `json:"id"`
	TenantID                    string    `json:"tenant_id"`
	ScopeType                   string    `json:"scope_type"`
	ExternalAgentID             string    `json:"external_agent_id,omitempty"`
	OrganizationID              string    `json:"organization_id,omitempty"`
	CustomerPrincipalID         string    `json:"customer_principal_id,omitempty"`
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

// ExternalBudgetRequest is the upsert body for an external budget.
type ExternalBudgetRequest struct {
	ScopeType                   string `json:"scope_type"`
	ExternalAgentID             string `json:"external_agent_id,omitempty"`
	OrganizationID              string `json:"organization_id,omitempty"`
	CustomerPrincipalID         string `json:"customer_principal_id,omitempty"`
	MaxTotalActions             int    `json:"max_total_actions"`
	MaxActionsPerRun            int    `json:"max_actions_per_run"`
	MaxDeniedPerRun             int    `json:"max_denied_per_run"`
	MaxApprovalRequiredPerRun   int    `json:"max_approval_required_per_run"`
	MaxToolCallsPerActionPerRun int    `json:"max_tool_calls_per_action_per_run"`
}
