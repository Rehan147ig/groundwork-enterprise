package runtime

import (
	"time"

	"groundwork/query-runtime/internal/relationship"
)

type Config struct {
	Addr                 string
	QueryTimeout         time.Duration
	BackendHTTPTimeout   time.Duration
	EmbeddingTimeout     time.Duration
	CircuitOpenTimeout   time.Duration
	CircuitFailureLimit  int
	CircuitHalfOpenLimit int
	// Authorizer is the neutral relationship backend (SpiceDB in
	// production, in-memory in dev). aclCheckerForConfig wraps it in an
	// ACLAdapter; when nil, the engine falls back to the fail-closed
	// MemoryACLChecker.
	Authorizer            relationship.Authorizer
	DatabaseURL           string
	BootstrapAPIKey       string
	BootstrapTenantID     string
	BootstrapTenantRegion string
	IDKThreshold          float64
	VectorWeight          float64
	KeywordWeight         float64
}

type QueryRequest struct {
	TenantID     string   `json:"-"`
	UserID       string   `json:"user_id"`
	Region       string   `json:"-"`
	Question     string   `json:"question"`
	SourceScopes []string `json:"source_scopes,omitempty"`
	IDKThreshold float64  `json:"idk_threshold,omitempty"`

	// TraceID is the request's correlation id, stamped by the server
	// from the X-Groundwork-Correlation-Id header (Phase 8.5). The
	// engine prefers it over a freshly generated trace id so the audit
	// row matches the client-visible id. Never accepted from the body.
	TraceID string `json:"-"`

	// RunID is the agent run the caller is acting under. Required when
	// the request is authenticated with a delegation token
	// (X-Groundwork-Delegation-Token): the run is bound to the grant at
	// run creation, so a mismatched run_id fails closed
	// (ErrDelegationRun). Ignored on the ordinary identity path.
	RunID string `json:"run_id,omitempty"`

	// AgentKeyID is the STABLE foreign-key identity of the API key that
	// authenticated the call (sourced from TenantContext.KeyID =
	// api_keys.id by server.query before dispatching to the executor).
	// Used as the group-by key for the Dashboard L2 agent panel. Never
	// accepted from the request body (json:"-") so a client cannot
	// claim to be a different agent. Zero when no key context is
	// available (embedded use).
	AgentKeyID int64 `json:"-"`

	// AgentKeyName is the DISPLAY snapshot of the API key's name
	// (TenantContext.KeyName = api_keys.name) at request time. Set
	// alongside AgentKeyID by server.query. Audit-row write time
	// snapshot — historical rows preserve the name as it was when
	// the call landed, even if the key is renamed later. PR #21
	// plumbs both onto the audit row for Audit Read API + Dashboard.
	AgentKeyName string `json:"-"`
}

type CreateAPIKeyRequest struct {
	Name         string    `json:"name"`
	Scopes       []string  `json:"scopes"`
	RateLimitRPM int       `json:"rate_limit_rpm,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

type CreateAPIKeyResponse struct {
	ID           int64     `json:"id"`
	Key          string    `json:"key"`
	KeyPrefix    string    `json:"key_prefix"`
	Name         string    `json:"name"`
	TenantID     string    `json:"tenant_id"`
	Region       string    `json:"region"`
	Scopes       []string  `json:"scopes"`
	RateLimitRPM int       `json:"rate_limit_rpm"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type RevokeAPIKeyResponse struct {
	ID      int64  `json:"id"`
	Revoked bool   `json:"revoked"`
	Status  string `json:"status"`
}

type RotateAPIKeyResponse struct {
	ID        int64     `json:"id"`
	Key       string    `json:"key"`
	KeyPrefix string    `json:"key_prefix"`
	RotatedAt time.Time `json:"rotated_at"`
	Status    string    `json:"status"`
}

type QueryResponse struct {
	Answer     string       `json:"answer"`
	Confidence float64      `json:"confidence"`
	Citations  []Citation   `json:"citations"`
	Trace      RuntimeTrace `json:"trace"`
}

type Citation struct {
	DocumentID     string  `json:"document_id"`
	ChunkID        string  `json:"chunk_id"`
	ChunkHash      string  `json:"chunk_hash"`
	Page           int     `json:"page"`
	Offset         int     `json:"offset"`
	Text           string  `json:"text"`
	Score          float64 `json:"score"`
	FreshnessScore float64 `json:"freshness_score"`
	// Watermark is the context firewall's provenance signature for this
	// chunk (HMAC over tenant, chunk id, text). Verify with
	// firewall.VerifyWatermark; empty when no firewall key is set.
	Watermark string `json:"watermark,omitempty"`
}

type Chunk struct {
	TenantID       string
	Region         string
	DocumentID     string
	ChunkID        string
	ChunkHash      string
	Page           int
	Offset         int
	Text           string
	RequiredScope  string
	OwnerACLTags   []string
	FreshnessScore float64
	SoftDeleted    bool
	// Watermark is set by the context firewall (see Citation).
	Watermark string
}

type Candidate struct {
	Chunk Chunk
	Rank  int
	Score float64
}

type RuntimeTrace struct {
	TraceID            string           `json:"trace_id"`
	TenantID           string           `json:"tenant_id"`
	UserID             string           `json:"user_id"`
	Region             string           `json:"region"`
	StartedAt          time.Time        `json:"started_at"`
	LatencyMs          int64            `json:"latency_ms"`
	VectorCandidates   int              `json:"vector_candidates"`
	KeywordCandidates  int              `json:"keyword_candidates"`
	BlockedByACL       int              `json:"blocked_by_acl"`
	BlockedByResidency int              `json:"blocked_by_residency"`
	RerankedCandidates int              `json:"reranked_candidates"`
	DecisionMode       string           `json:"decision_mode"`
	ShadowMode         bool             `json:"shadow_mode,omitempty"`
	WouldBlockByACL    int              `json:"would_block_by_acl,omitempty"`
	FailureStage       string           `json:"failure_stage,omitempty"`
	ErrorCode          string           `json:"error_code,omitempty"`
	ErrorMessage       string           `json:"error_message,omitempty"`
	AccessDecisions    []AccessDecision `json:"access_decisions"`
	ImmutableDigest    string           `json:"immutable_digest"`

	// Zero-Trust Context Firewall outcomes (Phase 4 blueprint): PII
	// spans redacted, indirect prompt-injection hits, chunks excluded
	// from context in block mode, and chunks signed with a provenance
	// watermark before delivery to the model.
	FirewallRedactions    int `json:"firewall_redactions,omitempty"`
	FirewallInjectionHits int `json:"firewall_injection_hits,omitempty"`
	FirewallBlockedChunks int `json:"firewall_blocked_chunks,omitempty"`
	FirewallWatermarked   int `json:"firewall_watermarked,omitempty"`

	// L1 policy layer outcomes: decisions resolved by in-process rules
	// or the L1 cache vs. the L2 backend.
	PolicyL1Decisions int `json:"policy_l1_decisions,omitempty"`
	PolicyL2Fallbacks int `json:"policy_l2_fallbacks,omitempty"`
}

type AccessDecision struct {
	ChunkID       string `json:"chunk_id"`
	ChunkHash     string `json:"chunk_hash"`
	DocumentID    string `json:"document_id"`
	Allowed       bool   `json:"allowed"`
	Reason        string `json:"reason"`
	Region        string `json:"region"`
	RequiredScope string `json:"required_scope"`
}
