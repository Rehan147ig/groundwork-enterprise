// Phase 5: Production Connector Gateway — runtime contract.
//
// The runtime owns the DTOs, sentinel errors, and the ConnectorService
// interface; the implementation lives in the leaf package
// (internal/connectors) to avoid import cycles — the same split used by
// connector_api.go/connectorsvc.
//
// Central rule: no registered tool call may reach an external system
// unless Groundwork authorizes that exact agent action first. The
// ConnectorDispatcher is invoked by governance.Service.DispatchAction
// AFTER the shared evaluator has recorded an allowed decision — and the
// gateway re-validates connector lifecycle, region, and manifest state
// immediately before opening the outbound connection. Any missing,
// unavailable, inconsistent, expired, or revoked dependency fails
// closed before the external call.

package runtime

import (
	"context"
	"errors"
	"time"
)

// Connector types and lifecycle states.
const (
	ConnectorTypeREST = "rest"
	ConnectorTypeMCP  = "mcp"

	ConnectorLifecycleDraft     = "draft"
	ConnectorLifecycleActive    = "active"
	ConnectorLifecycleSuspended = "suspended"
	ConnectorLifecycleRevoked   = "revoked"
	ConnectorLifecycleRetired   = "retired"
)

// ConnectorActionRisk mirrors the governance risk levels.
const (
	ConnectorRiskLow      = "low"
	ConnectorRiskMedium   = "medium"
	ConnectorRiskHigh     = "high"
	ConnectorRiskCritical = "critical"
)

// Invocation outcomes recorded as evidence after the outbound call.
const (
	InvocationSuccess         = "success"
	InvocationFailure         = "failure"
	InvocationTimeout         = "timeout"
	InvocationResponseBlocked = "response_blocked"

	InvocationKindAgentAction = "agent_action"
	InvocationKindHealthCheck = "health_check"
)

// Sentinel errors mapped by the HTTP layer to status codes; unknown
// errors never leak internals.
var (
	ErrConnectorUnavailable   = errors.New("connector service unavailable")
	ErrConnectorNotFound      = errors.New("connector not found")
	ErrConnectorNameConflict  = errors.New("connector name already exists")
	ErrConnectorNotActive     = errors.New("connector is not active")
	ErrConnectorInvalidState  = errors.New("connector lifecycle transition invalid")
	ErrConnectorRevoked       = errors.New("connector is revoked")
	ErrConnectorRegion        = errors.New("connector region mismatch")
	ErrConnectorNoManifest    = errors.New("connector has no manifest")
	ErrConnectorInvalidConfig = errors.New("connector configuration invalid")
	ErrConnectorDisabledTLS   = errors.New("connector disables TLS verification")
	ErrConnectorUnregistered  = errors.New("connector not registered")
)

// ConnectorActionManifest is the immutable manifest surface of one
// connector action. The agent can never supply URL, host, port,
// method, or unlisted arguments — transport-level values come only
// from here and from the connector configuration.
type ConnectorActionManifest struct {
	Name             string   `json:"name"`
	TransportMethod  string   `json:"transport_method"`        // HTTP method (rest) or MCP tool name (mcp)
	PathTemplate     string   `json:"path_template,omitempty"` // REST only: /path/{arg} — never raw agent URLs
	ResourceType     string   `json:"resource_type,omitempty"`
	Risk             string   `json:"risk"`
	ReadOnly         bool     `json:"read_only"`
	RequiresApproval bool     `json:"requires_approval"`
	MaxRequestBytes  int      `json:"max_request_bytes"`
	MaxResponseBytes int      `json:"max_response_bytes"`
	AllowedVersions  []string `json:"allowed_agent_version_ids,omitempty"` // empty = any active version
	Args             []string `json:"args,omitempty"`                      // allowlisted argument names
}

// ConnectorConfig is the transport-level configuration (immutable per
// version). base_url is operator-supplied; it is never derived from an
// agent request.
type ConnectorConfig struct {
	BaseURL             string   `json:"base_url"`
	Region              string   `json:"region"`
	TimeoutMS           int      `json:"timeout_ms"`
	RetryMax            int      `json:"retry_max"`
	RetryIdempotentOnly bool     `json:"retry_idempotent_only"`
	MaxResponseBytes    int      `json:"max_response_bytes"`
	TLSVerify           bool     `json:"tls_verify"`
	SecretRef           string   `json:"secret_ref,omitempty"`
	ClientCertRef       string   `json:"client_cert_ref,omitempty"`
	AllowedContentTypes []string `json:"allowed_content_types"`
	RedactionFields     []string `json:"redaction_fields"`
}

// Connector is the registry row.
type Connector struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	Name             string    `json:"name"`
	Type             string    `json:"type"`
	Lifecycle        string    `json:"lifecycle"`
	BaseURL          string    `json:"base_url"`
	Region           string    `json:"region"`
	ToolID           string    `json:"tool_id"`
	OwnerPrincipalID string    `json:"owner_principal_id"`
	ManifestDigest   string    `json:"manifest_digest"`
	VersionNumber    int       `json:"version_number"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`

	// Denormalized snapshot of the current ConnectorVersion config so
	// the gateway never needs a second read to dispatch.
	TimeoutMS           int64    `json:"timeout_ms"`
	RetryMax            int      `json:"retry_max"`
	RetryIdempotentOnly bool     `json:"retry_idempotent_only"`
	MaxResponseBytes    int64    `json:"max_response_bytes"`
	AllowedContentTypes []string `json:"allowed_content_types"`
	RedactionFields     []string `json:"redaction_fields"`
	SecretRef           string   `json:"secret_ref,omitempty"`
	ClientCertRef       string   `json:"client_cert_ref,omitempty"`
	TLSVerify           bool     `json:"tls_verify"`
}

// ConnectorVersion is one immutable configuration version.
type ConnectorVersion struct {
	ID             string          `json:"id"`
	ConnectorID    string          `json:"connector_id"`
	TenantID       string          `json:"tenant_id"`
	VersionNumber  int             `json:"version_number"`
	Config         ConnectorConfig `json:"config"`
	ManifestDigest string          `json:"manifest_digest"`
	CreatedBy      string          `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
}

// ConnectorDetail is the /{id} view: registry row + current version +
// manifest actions + lifecycle events.
type ConnectorDetail struct {
	Connector         Connector                 `json:"connector"`
	Config            ConnectorConfig           `json:"config"`
	Actions           []ConnectorActionManifest `json:"actions"`
	LifecycleEvents   []ConnectorLifecycleEvent `json:"lifecycle_events"`
	RecentInvocations []ConnectorInvocation     `json:"recent_invocations"`
}

// ConnectorLifecycleEvent is one hash-chained lifecycle transition.
type ConnectorLifecycleEvent struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	ConnectorID      string    `json:"connector_id"`
	ActionType       string    `json:"action_type"`
	FromState        string    `json:"from_state"`
	ToState          string    `json:"to_state"`
	ActorPrincipalID string    `json:"actor_principal_id"`
	Reason           string    `json:"reason"`
	ImmutableDigest  string    `json:"immutable_digest"`
	CreatedAt        time.Time `json:"created_at"`
}

// ConnectorInvocation is the immutable outcome evidence of one
// authorized call (agent action or health check).
type ConnectorInvocation struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ConnectorID   string    `json:"connector_id"`
	ConnectorName string    `json:"connector_name,omitempty"`
	ToolID        string    `json:"tool_id,omitempty"`
	ToolActionID  string    `json:"tool_action_id,omitempty"`
	RunID         string    `json:"run_id,omitempty"`
	DecisionID    string    `json:"decision_id"`
	Kind          string    `json:"kind"`
	Outcome       string    `json:"outcome"`
	StatusCode    int       `json:"status_code"`
	ErrorCode     string    `json:"error_code"`
	DurationMS    int64     `json:"duration_ms"`
	ResponseBytes int64     `json:"response_bytes"`
	Region        string    `json:"region"`
	TraceID       string    `json:"trace_id"`
	OccurredAt    time.Time `json:"occurred_at"`

	// ImmutableDigest is the write-once evidence digest over the
	// security-relevant fields (computed at append; never mutated).
	ImmutableDigest string `json:"immutable_digest,omitempty"`

	// Phase 6: chain context of the authorized call, propagated into
	// evidence and outbox payloads (ids only — never tokens).
	RootGrantID     string `json:"root_grant_id,omitempty"`
	ParentGrantID   string `json:"parent_grant_id,omitempty"`
	DelegationDepth int    `json:"delegation_depth"`

	// Phase 8.2: semantic idempotency key of the logical mutation
	// (tenant|run|tool|action|resource|canonical args hash). Correlation
	// metadata only — deliberately NOT part of ImmutableDigest.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// ConnectorRegisterRequest creates a connector in 'draft'. The
// governed tool and tool actions are registered together so grants and
// delegations bind to the same surface the evaluator enforces.
type ConnectorRegisterRequest struct {
	Name        string                    `json:"name"`
	Type        string                    `json:"type"`
	Config      ConnectorConfig           `json:"config"`
	Actions     []ConnectorActionManifest `json:"actions"`
	Description string                    `json:"description,omitempty"`
}

// ConnectorTransitionRequest is the body for lifecycle transitions.
type ConnectorTransitionRequest struct {
	Reason string `json:"reason"`
}

// ConnectorHealth is the result of an authorized, audited, read-only
// health probe (REST: safe GET/HEAD to the configured health path;
// MCP: initialize + ping).
type ConnectorHealth struct {
	ConnectorID string    `json:"connector_id"`
	Healthy     bool      `json:"healthy"`
	StatusCode  int       `json:"status_code"`
	ErrorCode   string    `json:"error_code"`
	LatencyMS   int64     `json:"latency_ms"`
	CheckedAt   time.Time `json:"checked_at"`
}

// ConnectorDispatchRequest is what the gateway receives from the
// governance service after an allowed decision. All identifiers come
// from the verified delegation/run context — never from the agent body.
type ConnectorDispatchRequest struct {
	TenantID       string
	Region         string
	ConnectorName  string
	ToolID         string
	ToolActionID   string
	Action         string
	ResourceRef    string
	RunID          string
	DecisionID     string
	AgentID        string
	AgentVersionID string
	Arguments      map[string]any
	TraceID        string
	PrincipalID    string

	// Phase 6: complete chain context of the authorized call. The
	// gateway propagates these into invocation evidence and traces so
	// the outbound call is attributable to the whole chain.
	RootGrantID     string
	ParentGrantID   string
	DelegationDepth int

	// Phase 8.2: semantic idempotency key of the logical mutation. The
	// gateway forwards it as the upstream Idempotency-Key header (REST)
	// so the tool provider can dedupe the crash window between an
	// executed call and its recorded evidence. Never sent to MCP.
	IdempotencyKey string
}

// ConnectorDispatchResult is the outcome of the outbound call.
type ConnectorDispatchResult struct {
	ConnectorID   string
	Outcome       string
	StatusCode    int
	ErrorCode     string
	DurationMS    int64
	ResponseBytes int64
	Response      any // size-limited, redacted, policy-compliant
}

// ConnectorDispatcher is implemented by internal/connectors.Gateway.
// governance.Service calls it only after an allowed decision; the
// gateway itself fails closed on any state/region/manifest problem
// before opening a connection.
type ConnectorDispatcher interface {
	Dispatch(ctx context.Context, req ConnectorDispatchRequest) (ConnectorDispatchResult, error)
}

// ConnectorService is the registry + lifecycle + health surface the
// HTTP layer drives. Implementation lives in internal/connectors.
type ConnectorService interface {
	Register(ctx context.Context, tenantID, actor string, admin bool, req ConnectorRegisterRequest) (ConnectorDetail, error)
	List(ctx context.Context, tenantID string) ([]Connector, error)
	Get(ctx context.Context, tenantID, connectorID string) (ConnectorDetail, error)
	GetManifest(ctx context.Context, tenantID, connectorID string) (ConnectorVersion, []ConnectorActionManifest, error)
	Transition(ctx context.Context, tenantID, connectorID, actor string, admin bool, action string, req ConnectorTransitionRequest) (Connector, error)
	UpdateConfig(ctx context.Context, tenantID, connectorID, actor string, admin bool, req ConnectorRegisterRequest) (ConnectorDetail, error)
	Health(ctx context.Context, tenantID, connectorID string) (ConnectorHealth, error)
	DispatchHealth(ctx context.Context, tenantID, region, connectorID string) (ConnectorDispatchResult, error)
}
