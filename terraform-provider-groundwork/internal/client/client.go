package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// UserAgent identifies provider traffic to the Groundwork API.
const UserAgent = "terraform-provider-groundwork"

// DefaultTimeout bounds every API call made by the provider.
const DefaultTimeout = 30 * time.Second

// apiError is the error envelope emitted by the Groundwork API
// (writeGovernanceError/writeAgentError/writeTenantError style handlers
// all respond with {"error": "<code>"}).
type apiError struct {
	Error string `json:"error"`
}

// Error is a failed Groundwork API call.
type Error struct {
	StatusCode int
	Code       string
	URL        string
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("groundwork API %s failed with status %d", e.URL, e.StatusCode)
	}
	return fmt.Sprintf("groundwork API %s failed with status %d (%s)", e.URL, e.StatusCode, e.Code)
}

// IsNotFound reports whether err is a 404 from the Groundwork API.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.StatusCode == http.StatusNotFound
}

// Config is the provider-level connection configuration.
type Config struct {
	// BaseURL is the Groundwork API base URL (https required).
	BaseURL string
	// APIKey authenticates every request (X-Groundwork-API-Key).
	APIKey string
	// Region defaults tenant-level operations to a region.
	Region string
	// Timeout bounds individual API calls; zero means DefaultTimeout.
	Timeout time.Duration
}

// Client is a hardened, pooled HTTP client for the Groundwork API.
type Client struct {
	baseURL string
	apiKey  string
	region  string
	http    *http.Client
}

// New builds a Client from cfg. It fails closed: an empty base URL or
// an API key that is missing fails configuration. TLS is mandatory
// except for loopback hosts (local development and tests).
func New(cfg Config) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, errors.New("api_base_url must be set")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("api_base_url is not a valid URL: %w", err)
	}
	if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		return nil, errors.New("api_base_url must be an https URL (loopback hosts may use plain http for local development)")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("api_key must be set")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		baseURL: base,
		apiKey:  strings.TrimSpace(cfg.APIKey),
		region:  strings.TrimSpace(cfg.Region),
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          10,
				MaxIdleConnsPerHost:   10,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: time.Second,
			},
		},
	}, nil
}

// IdempotencyKey derives a deterministic, stable idempotency key from
// the resource configuration so a Terraform retry replays the exact
// same mutation instead of creating a duplicate resource.
func IdempotencyKey(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// isLoopbackHost reports whether host is a loopback address, which is
// the only context where plain http is tolerated.
func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// do performs a JSON request. body may be nil. idemKey, when non-empty,
// is sent as the Idempotency-Key header (required by Phase 6 mutations
// and harmless elsewhere). out, when non-nil, decodes the 2xx body.
func (c *Client) do(ctx context.Context, method, path string, body, out any, idemKey string) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("X-Groundwork-API-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	if c.region != "" {
		req.Header.Set("X-Groundwork-Region", c.region)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("groundwork API %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read ground work API response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var ae apiError
		code := ""
		if json.Unmarshal(respBody, &ae) == nil {
			code = ae.Error
		}
		return &Error{StatusCode: resp.StatusCode, Code: code, URL: c.baseURL + path}
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode ground work API response: %w", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// Tenant
// ---------------------------------------------------------------------

// Tenant is the /v1/admin/tenants surface (subset used by the provider).
type Tenant struct {
	TenantID string `json:"tenant_id"`
	Region   string `json:"region"`
	Status   string `json:"status"`
	Tier     string `json:"capacity_tier,omitempty"`
	Reason   string `json:"reason"`
}

type provisionTenantRequest struct {
	TenantID     string `json:"tenant_id"`
	Region       string `json:"region"`
	Tier         string `json:"capacity_tier,omitempty"`
	Reason       string `json:"reason"`
	MintAdminKey bool   `json:"mint_admin_key"`
}

type provisionTenantResponse struct {
	Tenant Tenant `json:"tenant"`
}

type tenantTransitionRequest struct {
	Reason string `json:"reason"`
}

type tenantResponse struct {
	Tenant Tenant `json:"tenant"`
}

// ProvisionTenant creates or re-provisions a tenant. Provisioning an
// existing active tenant with the same region is idempotent server-side.
func (c *Client) ProvisionTenant(ctx context.Context, tenantID, region, tier, reason string) (Tenant, error) {
	var out provisionTenantResponse
	err := c.do(ctx, http.MethodPost, "/v1/admin/tenants", provisionTenantRequest{
		TenantID:     tenantID,
		Region:       region,
		Tier:         tier,
		Reason:       reason,
		MintAdminKey: false, // never mint raw keys into Terraform state
	}, &out, IdempotencyKey("tenant", tenantID, region, tier))
	return out.Tenant, err
}

// GetTenant reads a tenant directory entry.
func (c *Client) GetTenant(ctx context.Context, tenantID string) (Tenant, error) {
	var out tenantResponse
	err := c.do(ctx, http.MethodGet, "/v1/admin/tenants/"+tenantID, nil, &out, "")
	return out.Tenant, err
}

// DisableTenant suspends tenant traffic (non-destructive).
func (c *Client) DisableTenant(ctx context.Context, tenantID, reason string) (Tenant, error) {
	var out tenantResponse
	err := c.do(ctx, http.MethodPost, "/v1/admin/tenants/"+tenantID+"/disable", tenantTransitionRequest{Reason: reason}, &out, IdempotencyKey("tenant-disable", tenantID, reason))
	return out.Tenant, err
}

// EnableTenant resumes tenant traffic (non-destructive).
func (c *Client) EnableTenant(ctx context.Context, tenantID, reason string) (Tenant, error) {
	var out tenantResponse
	err := c.do(ctx, http.MethodPost, "/v1/admin/tenants/"+tenantID+"/enable", tenantTransitionRequest{Reason: reason}, &out, IdempotencyKey("tenant-enable", tenantID, reason))
	return out.Tenant, err
}

// DeprovisionTenant transitions a tenant to the terminal deprovisioned
// state. Terraform delete is intentionally non-destructive: the tenant
// record, evidence chain, and audit trail remain intact.
func (c *Client) DeprovisionTenant(ctx context.Context, tenantID, reason string) error {
	return c.do(ctx, http.MethodPost, "/v1/admin/tenants/"+tenantID+"/deprovision", tenantTransitionRequest{Reason: reason}, nil, IdempotencyKey("tenant-deprovision", tenantID, reason))
}

// ---------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------

// Agent is the /v1/agents surface (subset used by the provider).
type Agent struct {
	ID               string `json:"id"`
	TenantID         string `json:"tenant_id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	OwnerPrincipalID string `json:"owner_principal_id"`
	BusinessPurpose  string `json:"business_purpose"`
	RiskTier         string `json:"risk_tier"`
	LifecycleState   string `json:"lifecycle_state"`
	Environment      string `json:"environment"`
	ActiveVersion    string `json:"active_version,omitempty"`
}

type createAgentRequest struct {
	Name             string `json:"name"`
	Description      string `json:"description,omitempty"`
	OwnerPrincipalID string `json:"owner_principal_id,omitempty"`
	BusinessPurpose  string `json:"business_purpose,omitempty"`
	RiskTier         string `json:"risk_tier"`
	Environment      string `json:"environment,omitempty"`
}

type addAgentVersionRequest struct {
	Version             string `json:"version"`
	ModelProvider       string `json:"model_provider,omitempty"`
	ModelName           string `json:"model_name,omitempty"`
	PromptDigest        string `json:"prompt_digest,omitempty"`
	ToolManifestDigest  string `json:"tool_manifest_digest,omitempty"`
	PolicyBundleVersion string `json:"policy_bundle_version,omitempty"`
	ArtifactDigest      string `json:"artifact_digest,omitempty"`
}

type lifecycleActionRequest struct {
	Reason string `json:"reason,omitempty"`
}

type agentResponse struct {
	Agent Agent `json:"agent"`
}

// CreateAgent registers a new agent.
func (c *Client) CreateAgent(ctx context.Context, req CreateAgentInput) (Agent, error) {
	var out agentResponse
	err := c.do(ctx, http.MethodPost, "/v1/agents", createAgentRequest{
		Name:             req.Name,
		Description:      req.Description,
		OwnerPrincipalID: req.OwnerPrincipalID,
		BusinessPurpose:  req.BusinessPurpose,
		RiskTier:         req.RiskTier,
		Environment:      req.Environment,
	}, &out, IdempotencyKey("agent", req.Name, req.RiskTier, req.Environment))
	return out.Agent, err
}

// GetAgent reads an agent.
func (c *Client) GetAgent(ctx context.Context, agentID string) (Agent, error) {
	var out agentResponse
	err := c.do(ctx, http.MethodGet, "/v1/agents/"+agentID, nil, &out, "")
	return out.Agent, err
}

// AddAgentVersion publishes a new agent version (first version becomes
// active; the provider always calls it so version pinning is exact).
func (c *Client) AddAgentVersion(ctx context.Context, agentID string, req AddAgentVersionInput) error {
	return c.do(ctx, http.MethodPost, "/v1/agents/"+agentID+"/versions", addAgentVersionRequest{
		Version:             req.Version,
		ModelProvider:       req.ModelProvider,
		ModelName:           req.ModelName,
		PromptDigest:        req.PromptDigest,
		ToolManifestDigest:  req.ToolManifestDigest,
		PolicyBundleVersion: req.PolicyBundleVersion,
		ArtifactDigest:      req.ArtifactDigest,
	}, nil, IdempotencyKey("agent-version", agentID, req.Version))
}

// ActivateAgent moves an agent to active (non-destructive).
func (c *Client) ActivateAgent(ctx context.Context, agentID, reason string) (Agent, error) {
	var out agentResponse
	err := c.do(ctx, http.MethodPost, "/v1/agents/"+agentID+"/activate", lifecycleActionRequest{Reason: reason}, &out, IdempotencyKey("agent-activate", agentID, reason))
	return out.Agent, err
}

// SuspendAgent moves an agent to suspended (non-destructive).
func (c *Client) SuspendAgent(ctx context.Context, agentID, reason string) (Agent, error) {
	var out agentResponse
	err := c.do(ctx, http.MethodPost, "/v1/agents/"+agentID+"/suspend", lifecycleActionRequest{Reason: reason}, &out, IdempotencyKey("agent-suspend", agentID, reason))
	return out.Agent, err
}

// RetireAgent moves an agent to retired (non-destructive).
func (c *Client) RetireAgent(ctx context.Context, agentID, reason string) (Agent, error) {
	var out agentResponse
	err := c.do(ctx, http.MethodPost, "/v1/agents/"+agentID+"/retire", lifecycleActionRequest{Reason: reason}, &out, IdempotencyKey("agent-retire", agentID, reason))
	return out.Agent, err
}

// RevokeAgent moves an agent to the terminal revoked state. Terraform
// delete is non-destructive: the agent, its versions, and its evidence
// chain remain intact and audit-visible.
func (c *Client) RevokeAgent(ctx context.Context, agentID, reason string) error {
	return c.do(ctx, http.MethodPost, "/v1/agents/"+agentID+"/revoke", lifecycleActionRequest{Reason: reason}, nil, IdempotencyKey("agent-revoke", agentID, reason))
}

// ---------------------------------------------------------------------
// Governance grant
// ---------------------------------------------------------------------

// AgentToolGrant is the /v1/governance/grants surface.
type AgentToolGrant struct {
	ID               string `json:"id"`
	AgentID          string `json:"agent_id"`
	VersionID        string `json:"version_id"`
	ToolID           string `json:"tool_id"`
	ActionID         string `json:"action_id"`
	ResourceScope    string `json:"resource_scope"`
	RegionConstraint string `json:"region_constraint"`
	CallLimitPerRun  int    `json:"call_limit_per_run"`
	RequiresApproval bool   `json:"requires_approval"`
}

type grantToolRequest struct {
	AgentID          string `json:"agent_id"`
	VersionID        string `json:"version_id"`
	ToolID           string `json:"tool_id"`
	ActionID         string `json:"action_id"`
	ResourceScope    string `json:"resource_scope"`
	RegionConstraint string `json:"region_constraint"`
	CallLimitPerRun  int    `json:"call_limit_per_run"`
	RequiresApproval bool   `json:"requires_approval"`
}

type grantResponse struct {
	Grant AgentToolGrant `json:"grant"`
}

type grantListResponse struct {
	Grants []AgentToolGrant `json:"grants"`
	Count  int              `json:"count"`
}

type revokeGrantRequest struct {
	Reason string `json:"reason"`
}

// GrantToolAccess mints a tool grant for an agent version.
func (c *Client) GrantToolAccess(ctx context.Context, req GrantInput) (AgentToolGrant, error) {
	var out grantResponse
	err := c.do(ctx, http.MethodPost, "/v1/governance/grants", grantToolRequest{
		AgentID:          req.AgentID,
		VersionID:        req.VersionID,
		ToolID:           req.ToolID,
		ActionID:         req.ActionID,
		ResourceScope:    req.ResourceScope,
		RegionConstraint: req.RegionConstraint,
		CallLimitPerRun:  req.CallLimitPerRun,
		RequiresApproval: req.RequiresApproval,
	}, &out, IdempotencyKey("grant", req.AgentID, req.VersionID, req.ToolID, req.ActionID, req.ResourceScope, req.RegionConstraint))
	return out.Grant, err
}

// GetGrant reads a grant by agent id + grant id.
func (c *Client) GetGrant(ctx context.Context, agentID, grantID string) (AgentToolGrant, error) {
	var out grantListResponse
	err := c.do(ctx, http.MethodGet, "/v1/governance/agents/"+agentID+"/grants", nil, &out, "")
	if err != nil {
		return AgentToolGrant{}, err
	}
	for _, g := range out.Grants {
		if g.ID == grantID {
			return g, nil
		}
	}
	return AgentToolGrant{}, &Error{StatusCode: 404, Code: "grant_not_found", URL: "/v1/governance/agents/" + agentID + "/grants"}
}

// RevokeGrant revokes a tool grant (non-destructive, evidence retained).
func (c *Client) RevokeGrant(ctx context.Context, grantID, reason string) error {
	return c.do(ctx, http.MethodPost, "/v1/governance/grants/"+grantID+"/revoke", revokeGrantRequest{Reason: reason}, nil, IdempotencyKey("grant-revoke", grantID, reason))
}

// ---------------------------------------------------------------------
// Connector
// ---------------------------------------------------------------------

// ConnectorConfig is the runtime ConnectorConfig shape. Auth is by
// secret reference only — raw secrets never enter Terraform state.
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

// Connector is the registry row (subset used by the provider).
type Connector struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Lifecycle string `json:"lifecycle"`
	BaseURL   string `json:"base_url"`
	Region    string `json:"region"`
	ToolID    string `json:"tool_id"`
}

// ConnectorDetail is the full connector view returned by register/get.
type ConnectorDetail struct {
	Connector Connector         `json:"connector"`
	Config    ConnectorConfig   `json:"config"`
	Actions   []ConnectorAction `json:"actions"`
}

// ConnectorAction is one declarative action manifest entry. transport_method
// is the HTTP method (REST) or the MCP tool name (MCP); path_template is
// REST-only and never carries raw agent-supplied URLs.
type ConnectorAction struct {
	Name             string   `json:"name"`
	TransportMethod  string   `json:"transport_method"`
	PathTemplate     string   `json:"path_template,omitempty"`
	ResourceType     string   `json:"resource_type,omitempty"`
	Risk             string   `json:"risk"`
	ReadOnly         bool     `json:"read_only"`
	RequiresApproval bool     `json:"requires_approval"`
	MaxRequestBytes  int      `json:"max_request_bytes"`
	MaxResponseBytes int      `json:"max_response_bytes"`
	AllowedVersions  []string `json:"allowed_agent_version_ids,omitempty"`
	Args             []string `json:"args,omitempty"`
}

type connectorRegisterRequest struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Config      ConnectorConfig   `json:"config"`
	Actions     []ConnectorAction `json:"actions"`
	Description string            `json:"description,omitempty"`
}

type connectorDetailResponse struct {
	Detail ConnectorDetail `json:"detail"`
}

type connectorTransitionRequest struct {
	Reason string `json:"reason"`
}

// RegisterConnector registers a connector (REST or MCP). Config auth
// must be a secret_ref, never a raw credential.
func (c *Client) RegisterConnector(ctx context.Context, req RegisterConnectorInput) (ConnectorDetail, error) {
	var out connectorDetailResponse
	err := c.do(ctx, http.MethodPost, "/v1/governance/connectors", connectorRegisterRequest{
		Name:        req.Name,
		Type:        req.Type,
		Config:      req.Config,
		Actions:     req.Actions,
		Description: req.Description,
	}, &out, IdempotencyKey("connector", req.Name, req.Type))
	return out.Detail, err
}

// GetConnector reads a connector detail.
func (c *Client) GetConnector(ctx context.Context, connectorID string) (ConnectorDetail, error) {
	var out connectorDetailResponse
	err := c.do(ctx, http.MethodGet, "/v1/governance/connectors/"+connectorID, nil, &out, "")
	return out.Detail, err
}

// UpdateConnectorConfig publishes a new connector config version.
func (c *Client) UpdateConnectorConfig(ctx context.Context, connectorID string, req RegisterConnectorInput) (ConnectorDetail, error) {
	var out connectorDetailResponse
	err := c.do(ctx, http.MethodPost, "/v1/governance/connectors/"+connectorID+"/config", connectorRegisterRequest{
		Name:        req.Name,
		Type:        req.Type,
		Config:      req.Config,
		Actions:     req.Actions,
		Description: req.Description,
	}, &out, IdempotencyKey("connector-config", connectorID, req.Name, req.Type))
	return out.Detail, err
}

// ActivateConnector moves a connector to active (non-destructive).
func (c *Client) ActivateConnector(ctx context.Context, connectorID, reason string) error {
	return c.do(ctx, http.MethodPost, "/v1/governance/connectors/"+connectorID+"/activate", connectorTransitionRequest{Reason: reason}, nil, IdempotencyKey("connector-activate", connectorID, reason))
}

// SuspendConnector moves a connector to suspended (non-destructive).
func (c *Client) SuspendConnector(ctx context.Context, connectorID, reason string) error {
	return c.do(ctx, http.MethodPost, "/v1/governance/connectors/"+connectorID+"/suspend", connectorTransitionRequest{Reason: reason}, nil, IdempotencyKey("connector-suspend", connectorID, reason))
}

// RevokeConnector moves a connector to the terminal revoked state.
// Terraform delete is non-destructive: registry rows, versions, and
// evidence remain intact.
func (c *Client) RevokeConnector(ctx context.Context, connectorID, reason string) error {
	return c.do(ctx, http.MethodPost, "/v1/governance/connectors/"+connectorID+"/revoke", connectorTransitionRequest{Reason: reason}, nil, IdempotencyKey("connector-revoke", connectorID, reason))
}

// ---------------------------------------------------------------------
// Transfer policy
// ---------------------------------------------------------------------

// TransferPolicy is the /v1/governance/transfer-policies surface.
type TransferPolicy struct {
	ID             string `json:"id"`
	TenantID       string `json:"tenant_id"`
	SourceRegion   string `json:"source_region"`
	TargetRegion   string `json:"target_region"`
	PurposePattern string `json:"purpose_pattern"`
	Enabled        bool   `json:"enabled"`
}

type transferPolicyRequest struct {
	SourceRegion   string `json:"source_region"`
	TargetRegion   string `json:"target_region"`
	PurposePattern string `json:"purpose_pattern"`
	Enabled        bool   `json:"enabled"`
}

type transferPolicyResponse struct {
	Policy TransferPolicy `json:"policy"`
}

type transferPoliciesResponse struct {
	Policies []TransferPolicy `json:"policies"`
	Count    int              `json:"count"`
}

type transferPolicyTransitionRequest struct {
	Reason string `json:"reason"`
}

// UpsertTransferPolicy creates or replaces a transfer policy. The
// deterministic Idempotency-Key (required by this Phase 6 endpoint)
// makes replays safe.
func (c *Client) UpsertTransferPolicy(ctx context.Context, req PolicyInput) (TransferPolicy, error) {
	var out transferPolicyResponse
	err := c.do(ctx, http.MethodPost, "/v1/governance/transfer-policies", transferPolicyRequest{
		SourceRegion:   req.SourceRegion,
		TargetRegion:   req.TargetRegion,
		PurposePattern: req.PurposePattern,
		Enabled:        req.Enabled,
	}, &out, IdempotencyKey("transfer-policy", req.SourceRegion, req.TargetRegion, req.PurposePattern))
	return out.Policy, err
}

// GetTransferPolicy reads a transfer policy by id.
func (c *Client) GetTransferPolicy(ctx context.Context, policyID string) (TransferPolicy, error) {
	var out transferPoliciesResponse
	err := c.do(ctx, http.MethodGet, "/v1/governance/transfer-policies", nil, &out, "")
	if err != nil {
		return TransferPolicy{}, err
	}
	for _, p := range out.Policies {
		if p.ID == policyID {
			return p, nil
		}
	}
	return TransferPolicy{}, &Error{StatusCode: 404, Code: "transfer_policy_not_found", URL: "/v1/governance/transfer-policies"}
}

// SuspendTransferPolicy disables a transfer policy (non-destructive).
func (c *Client) SuspendTransferPolicy(ctx context.Context, policyID, reason string) error {
	return c.do(ctx, http.MethodPost, "/v1/governance/transfer-policies/"+policyID+"/suspend", transferPolicyTransitionRequest{Reason: reason}, nil, IdempotencyKey("transfer-policy-suspend", policyID, reason))
}

// ActivateTransferPolicy enables a transfer policy (non-destructive).
func (c *Client) ActivateTransferPolicy(ctx context.Context, policyID, reason string) error {
	return c.do(ctx, http.MethodPost, "/v1/governance/transfer-policies/"+policyID+"/activate", transferPolicyTransitionRequest{Reason: reason}, nil, IdempotencyKey("transfer-policy-activate", policyID, reason))
}

// RevokeTransferPolicy moves a transfer policy to the terminal revoked
// state (non-destructive; evidence retained).
func (c *Client) RevokeTransferPolicy(ctx context.Context, policyID, reason string) error {
	return c.do(ctx, http.MethodPost, "/v1/governance/transfer-policies/"+policyID+"/revoke", transferPolicyTransitionRequest{Reason: reason}, nil, IdempotencyKey("transfer-policy-revoke", policyID, reason))
}

// ---------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------

// BudgetPolicy is the /v1/governance/budgets surface.
type BudgetPolicy struct {
	ID                          string `json:"id"`
	ScopeType                   string `json:"scope_type"`
	AgentVersionID              string `json:"agent_version_id,omitempty"`
	GrantID                     string `json:"grant_id,omitempty"`
	MaxActionsPerRun            int    `json:"max_actions_per_run"`
	MaxDeniedPerRun             int    `json:"max_denied_per_run"`
	MaxApprovalRequiredPerRun   int    `json:"max_approval_required_per_run"`
	MaxToolCallsPerActionPerRun int    `json:"max_tool_calls_per_action_per_run"`
	MaxRunDurationSeconds       int    `json:"max_run_duration_seconds"`
	MaxCitationsPerQuery        int    `json:"max_citations_per_query"`
}

type upsertBudgetRequest struct {
	ScopeType                   string `json:"scope_type"`
	AgentVersionID              string `json:"agent_version_id"`
	GrantID                     string `json:"grant_id"`
	MaxActionsPerRun            int    `json:"max_actions_per_run"`
	MaxDeniedPerRun             int    `json:"max_denied_per_run"`
	MaxApprovalRequiredPerRun   int    `json:"max_approval_required_per_run"`
	MaxToolCallsPerActionPerRun int    `json:"max_tool_calls_per_action_per_run"`
	MaxRunDurationSeconds       int    `json:"max_run_duration_seconds"`
	MaxCitationsPerQuery        int    `json:"max_citations_per_query"`
}

type budgetResponse struct {
	Budget BudgetPolicy `json:"budget"`
}

type budgetsResponse struct {
	Budgets []BudgetPolicy `json:"budgets"`
	Count   int            `json:"count"`
}

// UpsertBudget creates or replaces a budget policy. Scope is one of
// tenant, agent_version, or grant.
func (c *Client) UpsertBudget(ctx context.Context, req BudgetInput) (BudgetPolicy, error) {
	var out budgetResponse
	err := c.do(ctx, http.MethodPost, "/v1/governance/budgets", upsertBudgetRequest{
		ScopeType:                   req.ScopeType,
		AgentVersionID:              req.AgentVersionID,
		GrantID:                     req.GrantID,
		MaxActionsPerRun:            req.MaxActionsPerRun,
		MaxDeniedPerRun:             req.MaxDeniedPerRun,
		MaxApprovalRequiredPerRun:   req.MaxApprovalRequiredPerRun,
		MaxToolCallsPerActionPerRun: req.MaxToolCallsPerActionPerRun,
		MaxRunDurationSeconds:       req.MaxRunDurationSeconds,
		MaxCitationsPerQuery:        req.MaxCitationsPerQuery,
	}, &out, IdempotencyKey("budget", req.ScopeType, req.AgentVersionID, req.GrantID))
	return out.Budget, err
}

// GetBudget reads a budget policy by id.
func (c *Client) GetBudget(ctx context.Context, budgetID string) (BudgetPolicy, error) {
	var out budgetsResponse
	err := c.do(ctx, http.MethodGet, "/v1/governance/budgets", nil, &out, "")
	if err != nil {
		return BudgetPolicy{}, err
	}
	for _, b := range out.Budgets {
		if b.ID == budgetID {
			return b, nil
		}
	}
	return BudgetPolicy{}, &Error{StatusCode: 404, Code: "budget_not_found", URL: "/v1/governance/budgets"}
}

// ZeroBudget neutralizes a budget policy (all limits zero) without
// destroying it. The runtime has no destructive budget endpoint, so
// Terraform delete deprovisions the policy to its least-privileged
// state: zero limits fail closed on every budget check.
func (c *Client) ZeroBudget(ctx context.Context, req BudgetInput) (BudgetPolicy, error) {
	var out budgetResponse
	err := c.do(ctx, http.MethodPost, "/v1/governance/budgets", upsertBudgetRequest{
		ScopeType:      req.ScopeType,
		AgentVersionID: req.AgentVersionID,
		GrantID:        req.GrantID,
	}, &out, IdempotencyKey("budget-zero", req.ScopeType, req.AgentVersionID, req.GrantID))
	return out.Budget, err
}

// ---------------------------------------------------------------------
// Input structs (provider-facing)
// ---------------------------------------------------------------------

type CreateAgentInput struct {
	Name             string
	Description      string
	OwnerPrincipalID string
	BusinessPurpose  string
	RiskTier         string
	Environment      string
}

type AddAgentVersionInput struct {
	Version             string
	ModelProvider       string
	ModelName           string
	PromptDigest        string
	ToolManifestDigest  string
	PolicyBundleVersion string
	ArtifactDigest      string
}

type GrantInput struct {
	AgentID          string
	VersionID        string
	ToolID           string
	ActionID         string
	ResourceScope    string
	RegionConstraint string
	CallLimitPerRun  int
	RequiresApproval bool
}

type RegisterConnectorInput struct {
	Name        string
	Type        string
	Config      ConnectorConfig
	Actions     []ConnectorAction
	Description string
}

type PolicyInput struct {
	SourceRegion   string
	TargetRegion   string
	PurposePattern string
	Enabled        bool
}

type BudgetInput struct {
	ScopeType                   string
	AgentVersionID              string
	GrantID                     string
	MaxActionsPerRun            int
	MaxDeniedPerRun             int
	MaxApprovalRequiredPerRun   int
	MaxToolCallsPerActionPerRun int
	MaxRunDurationSeconds       int
	MaxCitationsPerQuery        int
}
