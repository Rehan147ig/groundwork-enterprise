package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	gwmetrics "groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/usage"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	cfg                Config
	backend            Backend
	apiKeys            APIKeyResolver
	executor           QueryExecutor
	identity           IdentityVerifier
	allowDemoIdentity  bool
	resolver           PrincipalResolver
	canonicalIdentity  bool
	limiter            *RateLimiter
	tenantLimiter      *TenantRateLimiter
	concurrencyLimiter *TenantConcurrencyLimiter
	// capacityModel (Phase 8.2) maps the tenant's directory tier to its
	// per-tenant in-flight concurrency cap. Nil-safe: without a model
	// the concurrency limiter's own default applies.
	capacityModel   *CapacityModel
	overloadLimiter *OverloadLimiter
	// auditReader is the optional read-side implementation used by the
	// PR #22 Audit Read API endpoints. Nil-safe: when unset, /v1/audit*
	// returns 503 audit_unavailable. Wired via SetAuditReader from
	// cmd/query-runtime — the engine package supplies a Postgres impl
	// that internally reuses engine.LoadAuditChain / VerifyChain.
	auditReader AuditReader

	// githubSvc is the optional connector-backed service powering the
	// V1 console's Connect (POST /v1/connect/github) and Leak Report
	// (GET /v1/leak-report) endpoints. Nil-safe: when unset, those
	// endpoints return 503 connector_unavailable. Wired via
	// SetGitHubService from cmd/query-runtime (impl in connectorsvc).
	githubSvc GitHubService

	// readinessProbes is the optional set of dependency probes that
	// /readyz invokes on every call. PR #22 HA fix #3: today /readyz
	// only checks struct wiring, so a dead Postgres still reports 200
	// and k8s keeps routing /v1/query traffic to a pod that will
	// fail-closed on every request. Each probe returns nil on healthy,
	// non-nil on unhealthy. Wired via AddReadinessProbe from
	// cmd/query-runtime. Empty (the default for tests / local mode)
	// preserves the original behavior — struct-wiring check only.
	readinessProbes []ReadinessProbe

	// agentRegistry is the optional Agent Trust and Control Plane
	// registry powering the /v1/agents endpoints (Phase 1). Nil-safe:
	// when unset, those endpoints return 503 agent_registry_unavailable.
	// Wired via SetAgentRegistry from cmd/query-runtime (impl in
	// internal/agentregistry).
	agentRegistry AgentRegistry

	// governance is the optional Delegated Authority & Governed Agent
	// Execution service (Phase 2) powering /v1/governance* and the
	// delegation gate on /v1/query (X-Groundwork-Delegation-Token).
	// Nil-safe: when unset, those endpoints return 503
	// governance_unavailable and a delegation token on /v1/query fails
	// closed. Wired via SetGovernanceService from cmd/query-runtime
	// (impl in internal/governance).
	governance GovernanceService

	// regionResolver is the optional trusted tenant->region/jurisdiction
	// configuration (Phase 4). When wired, requireAPIKey rejects a
	// tenant whose key region differs from its configured region
	// (region mismatch fails closed) and rejects tenants absent from
	// the configuration (region_unprovisioned).
	regionResolver TenantRegionResolver

	// connectors is the optional Phase 5 connector gateway
	// (registry + lifecycle + dispatch preflight). Nil-safe: when
	// unset, /v1/governance/connectors* returns 503
	// connector_gateway_unavailable and an allowed external tool call
	// fails closed with connector_dispatcher_unavailable evidence.
	// Wired via SetConnectorService from cmd/query-runtime (impl in
	// internal/connectors).
	connectors ConnectorService

	// meter is the optional Phase 8.1 usage metering service. Nil-safe:
	// when unset, /v1/usage* returns 503 usage_unavailable and the
	// metering calls at the recording points are no-ops. Wired via
	// SetUsageMeter from cmd/query-runtime (impl in internal/usage).
	meter UsageService

	// breakGlass is the optional Phase 8.4 break-glass operator access
	// service. Nil-safe: when unset, /v1/security/break-glass* returns
	// 503 break_glass_unavailable. Wired via SetBreakGlassService from
	// cmd/query-runtime (impl in internal/breakglass).
	breakGlass BreakGlassService

	// supportBundle is the optional Phase 8.5 support bundle source.
	// Nil-safe: when unset, /v1/security/support-bundle returns 503
	// support_bundle_unavailable. Wired via SetSupportBundleSource from
	// cmd/query-runtime.
	supportBundle SupportBundleSource

	// tenantSvc is the optional Phase 8.1 tenant provisioning service
	// (operator-managed tenant directory with lifecycle evidence).
	// Nil-safe: when unset, /v1/admin/tenants* returns 503
	// tenant_management_unavailable and no directory check runs in
	// authenticate (tenants are governed by the region resolver only).
	// Wired via SetTenantService from cmd/query-runtime (impl in
	// internal/tenancy). The same service doubles as the auth-layer
	// TenantDirectory: a tenant that is disabled or deprovisioned in
	// the directory fails closed on its next request.
	tenantSvc TenantService

	// aclSyncWebhooks is the optional real-time IAM sync surface
	// (Entra ID lifecycle notifications + Okta system-log webhooks).
	// Signature-authenticated (shared secret, no API key): when
	// unset, /v1/security/acl-sync/* returns 503
	// acl_sync_webhook_unavailable. Wired via SetACLSyncWebhooks from
	// cmd/query-runtime (impl in internal/aclsync/webhook).
	aclSyncWebhooks *ACLSyncWebhookHandler
}

// ReadinessProbe is one /readyz dependency check. Implementations must
// return quickly (probes run synchronously inside the readyz handler
// with a short outer timeout); a probe that hangs blocks the entire
// readyz response, which Kubernetes interprets as failure on
// readinessProbe timeout. Name is rendered in the JSON response body
// when the probe fails.
type ReadinessProbe struct {
	Name  string
	Check func(ctx context.Context) error
}

// SetRateLimiter wires the per-API-key request/minute limiter. When set, authenticated
// requests that exceed their key's rate_limit_rpm budget are rejected with 429. When unset
// (nil), no limiting is applied — so local/demo and existing tests are unaffected.
func (s *Server) SetRateLimiter(rl *RateLimiter) { s.limiter = rl }

// SetTenantRateLimiter wires the per-tenant request/minute limiter. It
// complements the per-key limiter: a tenant's budget is shared across all
// of its keys, so many keys cannot be used to bypass the ceiling. When
// unset (nil), no tenant-level limiting is applied.
func (s *Server) SetTenantRateLimiter(rl *TenantRateLimiter) { s.tenantLimiter = rl }

// SetConcurrencyLimiter wires the per-tenant in-flight request cap. When
// a tenant is at its cap, further requests are rejected with 503
// (concurrency_limit_exceeded) instead of being queued. When unset (nil),
// no concurrency limiting is applied. With a capacity model wired, the
// tier-derived cap takes precedence over the limiter's default.
func (s *Server) SetConcurrencyLimiter(l *TenantConcurrencyLimiter) { s.concurrencyLimiter = l }

// SetCapacityModel wires the Phase 8.2 per-tenant capacity model (tier
// -> in-flight concurrency caps). Nil-safe: without a model, the
// concurrency limiter's default applies to every tenant.
func (s *Server) SetCapacityModel(m *CapacityModel) { s.capacityModel = m }

// SetOverloadLimiter wires the instance-wide in-flight request cap
// (Phase 8.2 overload protection). When the instance is at its cap,
// further requests are rejected with 503 (overload_exceeded) instead of
// being queued. When unset (nil), no global cap is applied.
func (s *Server) SetOverloadLimiter(l *OverloadLimiter) { s.overloadLimiter = l }

// AddReadinessProbe registers one dependency probe with /readyz. Probes
// are invoked sequentially on every readyz request with a short outer
// timeout; the first failure short-circuits and returns 503. PR #22 HA
// fix #3. Callers typically register a Postgres ping ("postgres") and
// relationship-backend reachability ("spicedb"); the actual probes live
// in cmd/query-runtime where the *sql.DB and authorizer handles are
// available. Order matters only insofar as the first failing probe is
// reported as the reason.
func (s *Server) AddReadinessProbe(p ReadinessProbe) {
	if p.Check == nil {
		return
	}
	s.readinessProbes = append(s.readinessProbes, p)
}

// SetIdentity wires the end-user identity verifier and the demo-identity switch.
// When allowDemo is false and no valid assertion is present, /v1/query fails closed.
func (s *Server) SetIdentity(verifier IdentityVerifier, allowDemo bool) {
	s.identity = verifier
	s.allowDemoIdentity = allowDemo
}

// SetCanonicalIdentity wires the canonical principal resolver and the feature flag
// (GROUNDWORK_CANONICAL_IDENTITY=true). When enabled, a verified end-user identity is
// resolved to a tenant-scoped canonical principal so the engine checks
// user:principal:<uuid>. A verified identity that resolves to no principal fails
// closed (identity_unresolved) — it never silently downgrades to the raw user id.
// Demo / unverified identities are always skipped (raw user id kept), so local mode
// keeps working whether or not the flag is set.
func (s *Server) SetCanonicalIdentity(resolver PrincipalResolver, canonical bool) {
	s.resolver = resolver
	s.canonicalIdentity = canonical
}

// SetRegionResolver wires the trusted tenant->region/jurisdiction
// configuration (Phase 4 sovereign deployment). When wired, every
// authenticated request's tenant region is checked against the
// configured region and a mismatch or an unprovisioned tenant fails
// closed with 403. The resolver is configuration only — request-body
// region fields are never consulted.
func (s *Server) SetRegionResolver(resolver TenantRegionResolver) {
	s.regionResolver = resolver
}

// SetTenantService wires the Phase 8.1 tenant provisioning service. When
// set, /v1/admin/tenants* endpoints are served and authenticate consults
// the service's TenantDirectory view after key resolution: a tenant that
// is disabled or deprovisioned in the directory fails closed with 403
// (ErrTenantNotActive), and a tenant whose key region differs from its
// directory region fails closed with ErrRegionMismatch. Tenants absent
// from the directory are unaffected (governed by the region resolver
// only). When nil (the default for existing tests), the endpoints return
// 503 tenant_management_unavailable and no directory check runs.
func (s *Server) SetTenantService(svc TenantService) {
	s.tenantSvc = svc
}

type QueryExecutor interface {
	Execute(ctx context.Context, req QueryRequest) QueryResponse
}

func NewServer(cfg Config, backend Backend) *Server {
	return NewServerWithAuth(cfg, backend, NewMemoryAPIKeyResolver("gw_test_key", TenantContext{TenantID: "tenant_demo", Region: "uk", KeyName: "test"}))
}

func NewServerWithAuth(cfg Config, backend Backend, apiKeys APIKeyResolver) *Server {
	return &Server{cfg: cfg, backend: backend, apiKeys: apiKeys}
}

func NewServerWithExecutor(cfg Config, backend Backend, apiKeys APIKeyResolver, executor QueryExecutor) *Server {
	return &Server{cfg: cfg, backend: backend, apiKeys: apiKeys, executor: executor}
}

// keyAdminScope is the Phase 8.4 platform-operator role for API-key
// management (create/rotate/revoke). It is deliberately narrower than
// "admin": a key-admin operator must not be able to open break-glass
// grants or provision tenants, and a break-glass operator must not be
// able to mint keys. The legacy "admin" scope still satisfies it via
// hasScope's override, so pre-existing operator keys keep working.
const keyAdminScope = "key_admin"

func (s *Server) Routes() http.Handler {
	gwmetrics.RegisterAll()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /livez", s.livez)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.HandleFunc("POST /v1/query", s.requireAPIKey("query", s.identityOrDelegation(s.query)))
	mux.HandleFunc("POST /v1/admin/api-keys", s.requireAPIKey(keyAdminScope, s.createAPIKey))
	mux.HandleFunc("POST /v1/admin/api-keys/{id}/rotate", s.requireAPIKey(keyAdminScope, s.rotateAPIKey))
	mux.HandleFunc("DELETE /v1/admin/api-keys/{id}", s.requireAPIKey(keyAdminScope, s.revokeAPIKey))
	// PR #22: Audit Read API. Read-only. Requires the new "audit" scope
	// (admin scope inherits via hasScope's existing override). All four
	// endpoints honor the tenant_id from the API-key context only —
	// never from the URL or body. /audit/verify is intentionally
	// unauthenticated WITH the audit scope; chain verification is a
	// SOC-2 observable surface for tenants who hold an audit-only key.
	mux.HandleFunc("GET /v1/audit", s.requireAPIKey(auditScope, s.auditList))
	mux.HandleFunc("GET /v1/audit/stats", s.requireAPIKey(auditScope, s.auditStats))
	mux.HandleFunc("GET /v1/audit/verify", s.requireAPIKey(auditScope, s.auditVerify))
	mux.HandleFunc("GET /v1/audit/{trace_id}", s.requireAPIKey(auditScope, s.auditGet))
	// Connector surface for the V1 console. Connect mutates the
	// relationship store (admin scope); leak-report is read-only (audit
	// scope, admin inherits).
	mux.HandleFunc("POST /v1/connect/github", s.requireAPIKey("admin", s.connectGitHub))
	mux.HandleFunc("GET /v1/leak-report", s.requireAPIKey(auditScope, s.leakReport))
	// Agent Registry (Phase 1: Agent Trust and Control Plane). Every
	// agent is a tenant-scoped identity with lifecycle state, versions,
	// and a tamper-evident event chain. Tenant comes from the API-key
	// context only; actor identity on mutations comes from the verified
	// identity middleware (demo identity honored only when enabled).
	// Reads require the "agents" scope (admin inherits); mutations
	// additionally require a verified identity and owner-or-admin
	// authorization, enforced by the registry service.
	mux.HandleFunc("POST /v1/agents", s.requireAPIKey(agentScope, s.requireVerifiedIdentity(s.createAgent)))
	mux.HandleFunc("GET /v1/agents", s.requireAPIKey(agentScope, s.listAgents))
	mux.HandleFunc("GET /v1/agents/{agent_id}", s.requireAPIKey(agentScope, s.getAgent))
	mux.HandleFunc("POST /v1/agents/{agent_id}/versions", s.requireAPIKey(agentScope, s.requireVerifiedIdentity(s.addAgentVersion)))
	mux.HandleFunc("POST /v1/agents/{agent_id}/activate", s.requireAPIKey(agentScope, s.requireVerifiedIdentity(s.activateAgent)))
	mux.HandleFunc("POST /v1/agents/{agent_id}/suspend", s.requireAPIKey(agentScope, s.requireVerifiedIdentity(s.suspendAgent)))
	mux.HandleFunc("POST /v1/agents/{agent_id}/revoke", s.requireAPIKey(agentScope, s.requireVerifiedIdentity(s.revokeAgent)))
	mux.HandleFunc("POST /v1/agents/{agent_id}/retire", s.requireAPIKey(agentScope, s.requireVerifiedIdentity(s.retireAgent)))
	// Governance (Phase 2: Delegated Authority & Governed Agent
	// Execution). Tenant/region come from the API-key context only;
	// reads require the "governance" scope (admin inherits); mutations
	// require a verified end-user identity. Minting delegations and
	// recording human approvals additionally reject demo identities
	// (enforced in the handlers — a demo actor can never mint a
	// delegation or approve an action). Run/evaluate/dispatch endpoints
	// authenticate via the delegation token itself and need no identity.
	mux.HandleFunc("POST /v1/governance/tools", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.createGovernanceTool)))
	mux.HandleFunc("GET /v1/governance/tools", s.requireAPIKey(governanceScope, s.listGovernanceTools))
	mux.HandleFunc("GET /v1/governance/tools/{tool_id}", s.requireAPIKey(governanceScope, s.getGovernanceTool))
	mux.HandleFunc("POST /v1/governance/tools/{tool_id}/actions", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.createGovernanceToolAction)))
	mux.HandleFunc("GET /v1/governance/tools/{tool_id}/actions", s.requireAPIKey(governanceScope, s.listGovernanceToolActions))
	mux.HandleFunc("POST /v1/governance/tools/{tool_id}/lifecycle", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.transitionGovernanceTool)))
	mux.HandleFunc("POST /v1/governance/grants", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.createGovernanceGrant)))
	mux.HandleFunc("POST /v1/governance/grants/{grant_id}/revoke", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.revokeGovernanceGrant)))
	mux.HandleFunc("GET /v1/governance/agents/{agent_id}/grants", s.requireAPIKey(governanceScope, s.listGovernanceGrants))
	mux.HandleFunc("POST /v1/governance/delegations", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.mintGovernanceDelegation)))
	mux.HandleFunc("POST /v1/governance/runs", s.requireAPIKey(governanceScope, s.createGovernanceRun))
	mux.HandleFunc("GET /v1/governance/runs", s.requireAPIKey(governanceScope, s.listGovernanceRuns))
	mux.HandleFunc("GET /v1/governance/runs/{run_id}", s.requireAPIKey(governanceScope, s.getGovernanceRun))
	mux.HandleFunc("POST /v1/governance/runs/{run_id}/evaluate", s.requireAPIKey(governanceScope, s.evaluateGovernanceAction))
	mux.HandleFunc("POST /v1/governance/simulate", s.requireAPIKey(governanceScope, s.simulateGovernanceAction))
	mux.HandleFunc("POST /v1/governance/runs/{run_id}/approve/{action_id}", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.approveGovernanceAction)))
	mux.HandleFunc("POST /v1/governance/runs/{run_id}/deny/{action_id}", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.denyGovernanceAction)))
	mux.HandleFunc("POST /v1/governance/dispatch", s.requireAPIKey(governanceScope, s.dispatchGovernanceAction))
	// Governance (Phase 3: Emergency Revocation & Evidence Operations).
	// Emergency control mutations require a verified end-user identity
	// and owner-or-admin authorization (enforced by the service); reads
	// need the governance scope. Reasons are mandatory and become part
	// of the immutable evidence chain. Verification is read-only and
	// never repairs; checkpoints enable incremental verification.
	mux.HandleFunc("POST /v1/governance/agents/{agent_id}/kill-switch", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.killSwitchGovernanceAgent)))
	mux.HandleFunc("POST /v1/governance/agents/{agent_id}/resume", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.resumeGovernanceAgent)))
	mux.HandleFunc("POST /v1/governance/agent-versions/{version_id}/kill-switch", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.killSwitchGovernanceAgentVersion)))
	mux.HandleFunc("POST /v1/governance/agent-versions/{version_id}/resume", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.resumeGovernanceAgentVersion)))
	mux.HandleFunc("POST /v1/governance/tools/{tool_id}/kill-switch", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.killSwitchGovernanceTool)))
	mux.HandleFunc("POST /v1/governance/tools/{tool_id}/resume", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.resumeGovernanceTool)))
	mux.HandleFunc("POST /v1/governance/delegations/{grant_id}/revoke", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.revokeGovernanceDelegation)))
	mux.HandleFunc("POST /v1/governance/runs/{run_id}/terminate", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.terminateGovernanceRun)))
	mux.HandleFunc("GET /v1/governance/emergency-controls", s.requireAPIKey(governanceScope, s.listGovernanceEmergencyControls))
	mux.HandleFunc("POST /v1/governance/budgets", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.upsertGovernanceBudget)))
	mux.HandleFunc("GET /v1/governance/budgets/effective", s.requireAPIKey(governanceScope, s.getGovernanceEffectiveBudget))
	mux.HandleFunc("GET /v1/governance/budgets", s.requireAPIKey(governanceScope, s.listGovernanceBudgets))
	mux.HandleFunc("GET /v1/governance/evidence", s.requireAPIKey(governanceScope, s.queryGovernanceEvidence))
	mux.HandleFunc("GET /v1/governance/evidence/{evidence_id}", s.requireAPIKey(governanceScope, s.getGovernanceEvidenceEvent))
	mux.HandleFunc("GET /v1/governance/runs/{run_id}/timeline", s.requireAPIKey(governanceScope, s.getGovernanceRunTimeline))
	mux.HandleFunc("GET /v1/governance/agents/{agent_id}/activity", s.requireAPIKey(governanceScope, s.getGovernanceAgentActivity))
	mux.HandleFunc("GET /v1/governance/audit/verify", s.requireAPIKey(governanceScope, s.verifyGovernanceAuditChain))
	mux.HandleFunc("GET /v1/governance/audit/checkpoints", s.requireAPIKey(governanceScope, s.listGovernanceCheckpoints))
	mux.HandleFunc("GET /v1/governance/outbox", s.requireAPIKey(governanceScope, s.listGovernanceOutbox))
	mux.HandleFunc("POST /v1/governance/outbox/{event_id}/retry", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.retryGovernanceOutbox)))
	mux.HandleFunc("GET /v1/governance/exports/{framework}", s.requireAPIKey(governanceScope, s.getGovernanceExport))
	// Governance (Phase 5: Production Connector Gateway). Registry
	// mutations require a verified identity (owner-or-admin); reads
	// need the governance scope. Dispatch is reached exclusively
	// through POST /v1/governance/dispatch after an allowed decision.
	mux.HandleFunc("POST /v1/governance/connectors", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.registerConnector)))
	mux.HandleFunc("GET /v1/governance/connectors", s.requireAPIKey(governanceScope, s.listConnectors))
	mux.HandleFunc("GET /v1/governance/connectors/{connector_id}", s.requireAPIKey(governanceScope, s.getConnector))
	mux.HandleFunc("GET /v1/governance/connectors/{connector_id}/manifest", s.requireAPIKey(governanceScope, s.getConnectorManifest))
	mux.HandleFunc("POST /v1/governance/connectors/{connector_id}/activate", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.activateConnector)))
	mux.HandleFunc("POST /v1/governance/connectors/{connector_id}/suspend", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.suspendConnector)))
	mux.HandleFunc("POST /v1/governance/connectors/{connector_id}/revoke", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.revokeConnector)))
	mux.HandleFunc("POST /v1/governance/connectors/{connector_id}/config", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.updateConnectorConfig)))
	mux.HandleFunc("GET /v1/governance/connectors/{connector_id}/health", s.requireAPIKey(governanceScope, s.connectorHealthProbe))
	// Governance (Phase 6: Multi-Agent Delegation & External-Agent
	// Trust). Tenant/region come from the API-key context only; reads
	// require the governance scope (admin inherits). Mutations require a
	// verified end-user identity AND an Idempotency-Key header; the
	// service enforces owner-or-admin (trust relationships) or
	// admin-only (external agents, consents, transfer policies, chain
	// controls, external budgets). External runs authenticate through
	// the external identity token itself (no end-user identity needed).
	mux.HandleFunc("POST /v1/governance/trust-relationships", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.createGovernanceTrustRelationship)))
	mux.HandleFunc("GET /v1/governance/trust-relationships", s.requireAPIKey(governanceScope, s.listGovernanceTrustRelationships))
	mux.HandleFunc("GET /v1/governance/trust-relationships/{relationship_id}", s.requireAPIKey(governanceScope, s.getGovernanceTrustRelationship))
	mux.HandleFunc("POST /v1/governance/trust-relationships/{relationship_id}/approve", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.governanceTrustTransition("approve"))))
	mux.HandleFunc("POST /v1/governance/trust-relationships/{relationship_id}/activate", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.governanceTrustTransition("activate"))))
	mux.HandleFunc("POST /v1/governance/trust-relationships/{relationship_id}/suspend", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.governanceTrustTransition("suspend"))))
	mux.HandleFunc("POST /v1/governance/trust-relationships/{relationship_id}/resume", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.governanceTrustTransition("resume"))))
	mux.HandleFunc("POST /v1/governance/trust-relationships/{relationship_id}/revoke", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.governanceTrustTransition("revoke"))))
	mux.HandleFunc("GET /v1/governance/delegations", s.requireAPIKey(governanceScope, s.listGovernanceDelegationGrants))
	mux.HandleFunc("GET /v1/governance/delegations/{grant_id}/chain", s.requireAPIKey(governanceScope, s.getGovernanceDelegationChain))
	mux.HandleFunc("POST /v1/governance/delegations/{grant_id}/chain/revoke", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.governanceChainControl("revoke"))))
	mux.HandleFunc("POST /v1/governance/delegations/{grant_id}/chain/suspend", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.governanceChainControl("suspend"))))
	mux.HandleFunc("POST /v1/governance/delegations/{grant_id}/chain/resume", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.governanceChainControl("resume"))))
	mux.HandleFunc("GET /v1/governance/runs/{run_id}/delegation-chain", s.requireAPIKey(governanceScope, s.getGovernanceRunDelegationChain))
	mux.HandleFunc("GET /v1/governance/evidence/{evidence_id}/provenance", s.requireAPIKey(governanceScope, s.getGovernanceEvidenceProvenance))
	mux.HandleFunc("POST /v1/governance/external-agents", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.createGovernanceExternalAgent)))
	mux.HandleFunc("GET /v1/governance/external-agents", s.requireAPIKey(governanceScope, s.listGovernanceExternalAgents))
	mux.HandleFunc("GET /v1/governance/external-agents/{external_agent_id}", s.requireAPIKey(governanceScope, s.getGovernanceExternalAgent))
	mux.HandleFunc("GET /v1/governance/external-agents/{external_agent_id}/health", s.requireAPIKey(governanceScope, s.governanceExternalAgentHealth))
	mux.HandleFunc("POST /v1/governance/external-agents/{external_agent_id}/activate", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.governanceExternalAgentTransition("activate"))))
	mux.HandleFunc("POST /v1/governance/external-agents/{external_agent_id}/suspend", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.governanceExternalAgentTransition("suspend"))))
	mux.HandleFunc("POST /v1/governance/external-agents/{external_agent_id}/revoke", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.governanceExternalAgentTransition("revoke"))))
	mux.HandleFunc("POST /v1/governance/external-runs", s.requireAPIKey(governanceScope, s.createGovernanceExternalRun))
	mux.HandleFunc("GET /v1/governance/external-runs", s.requireAPIKey(governanceScope, s.listGovernanceExternalRuns))
	mux.HandleFunc("GET /v1/governance/external-runs/{run_id}", s.requireAPIKey(governanceScope, s.getGovernanceExternalRun))
	mux.HandleFunc("POST /v1/governance/external-runs/{run_id}/terminate", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.terminateGovernanceExternalRun)))
	mux.HandleFunc("POST /v1/governance/consents", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.createGovernanceConsentRecord)))
	mux.HandleFunc("GET /v1/governance/consents", s.requireAPIKey(governanceScope, s.listGovernanceConsentRecords))
	mux.HandleFunc("GET /v1/governance/consents/{consent_id}", s.requireAPIKey(governanceScope, s.getGovernanceConsentRecord))
	mux.HandleFunc("POST /v1/governance/consents/{consent_id}/revoke", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.revokeGovernanceConsentRecord)))
	mux.HandleFunc("POST /v1/governance/transfer-policies", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.upsertGovernanceTransferPolicy)))
	mux.HandleFunc("GET /v1/governance/transfer-policies", s.requireAPIKey(governanceScope, s.listGovernanceTransferPolicies))
	mux.HandleFunc("POST /v1/governance/transfer-policies/{policy_id}/activate", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.governanceTransferPolicyTransition("activate"))))
	mux.HandleFunc("POST /v1/governance/transfer-policies/{policy_id}/suspend", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.governanceTransferPolicyTransition("suspend"))))
	mux.HandleFunc("POST /v1/governance/transfer-policies/{policy_id}/revoke", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.governanceTransferPolicyTransition("revoke"))))
	mux.HandleFunc("GET /v1/governance/external-budgets", s.requireAPIKey(governanceScope, s.listGovernanceExternalBudgets))
	mux.HandleFunc("PUT /v1/governance/external-budgets/{external_agent_id}", s.requireAPIKey(governanceScope, s.requireVerifiedIdentity(s.upsertGovernanceExternalBudget)))
	// Usage Metering (Phase 8.1): tenant-scoped usage snapshot and
	// quota rows. Reads need the "usage" scope (admin inherits); the
	// limits mutation requires a verified identity AND an
	// Idempotency-Key header (Phase 6 mutation convention).
	mux.HandleFunc("GET /v1/usage", s.requireAPIKey(usageScope, s.getUsage))
	mux.HandleFunc("GET /v1/usage/limits", s.requireAPIKey(usageScope, s.getUsageLimits))
	mux.HandleFunc("PUT /v1/usage/limits", s.requireAPIKey(usageScope, s.requireVerifiedIdentity(s.putUsageLimits)))
	// Break-Glass Operator Access (Phase 8.4): time-bounded emergency
	// admin access with mandatory reasons and hash-chained evidence.
	// Requires the "admin" scope; Open/Revoke additionally require a
	// verified operator identity.
	mux.HandleFunc("POST /v1/security/break-glass/grants", s.requireAPIKey(breakGlassScope, s.requireVerifiedIdentity(s.openBreakGlassGrant)))
	mux.HandleFunc("GET /v1/security/break-glass/grants", s.requireAPIKey(breakGlassScope, s.listBreakGlassGrants))
	mux.HandleFunc("GET /v1/security/break-glass/grants/{id}", s.requireAPIKey(breakGlassScope, s.getBreakGlassGrant))
	mux.HandleFunc("POST /v1/security/break-glass/grants/{id}/revoke", s.requireAPIKey(breakGlassScope, s.requireVerifiedIdentity(s.revokeBreakGlassGrant)))
	// Tenant provisioning (Phase 8.1): operator-managed tenant directory
	// with lifecycle evidence. Requires the "provision" scope (admin
	// inherits); mutations additionally require a verified identity.
	// There is NO delete route: deprovisioning is the terminal,
	// non-destructive lifecycle state (roadmap: "do not add destructive
	// delete by default").
	mux.HandleFunc("POST /v1/admin/tenants", s.requireAPIKey(tenantProvisionScope, s.requireVerifiedIdentity(s.provisionTenant)))
	mux.HandleFunc("GET /v1/admin/tenants", s.requireAPIKey(tenantProvisionScope, s.listTenants))
	mux.HandleFunc("GET /v1/admin/tenants/{tenant_id}", s.requireAPIKey(tenantProvisionScope, s.getTenant))
	mux.HandleFunc("GET /v1/admin/tenants/{tenant_id}/events", s.requireAPIKey(tenantProvisionScope, s.listTenantEvents))
	mux.HandleFunc("POST /v1/admin/tenants/{tenant_id}/disable", s.requireAPIKey(tenantProvisionScope, s.requireVerifiedIdentity(s.disableTenant)))
	mux.HandleFunc("POST /v1/admin/tenants/{tenant_id}/enable", s.requireAPIKey(tenantProvisionScope, s.requireVerifiedIdentity(s.enableTenant)))
	mux.HandleFunc("POST /v1/admin/tenants/{tenant_id}/deprovision", s.requireAPIKey(tenantProvisionScope, s.requireVerifiedIdentity(s.deprovisionTenant)))
	// Support Bundle (Phase 8.5): tenant-scoped diagnostics zip for
	// operator escalation. Admin scope + verified identity (same bar as
	// break-glass Open/Revoke); never contains secrets.
	mux.HandleFunc("GET /v1/security/support-bundle", s.requireAPIKey(supportBundleScope, s.requireVerifiedIdentity(s.serveSupportBundle)))
	// Real-time IAM sync webhooks (Entra ID lifecycle notifications,
	// Okta system-log events). Signature-authenticated with the shared
	// secret — the providers cannot hold API keys, so no API-key
	// middleware. The tenant is bound by the URL path.
	mux.HandleFunc("POST /v1/security/acl-sync/entra/{tenant_id}", s.handleEntraWebhook)
	mux.HandleFunc("POST /v1/security/acl-sync/okta/{tenant_id}", s.handleOktaWebhook)
	// Phase 8.5: correlation IDs on every response (echo) and request
	// (context) — the query handler stamps the id as the engine trace id.
	return s.correlationMiddleware(mux)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "groundwork-query-runtime"})
}

func (s *Server) livez(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if s.apiKeys == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "reason": "api_key_resolver_unavailable"})
		return
	}
	if s.executor == nil && (s.backend.Vector == nil || s.backend.ACL == nil || s.backend.Trace == nil) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "reason": "runtime_backend_unavailable"})
		return
	}
	// PR #22 HA fix #3: probe registered dependencies (Postgres,
	// SpiceDB) on every call. A dead dependency removes this pod from
	// the LB via k8s readiness; other pods continue to serve. Total
	// probe budget is bounded so a slow probe doesn't extend the readyz
	// response indefinitely (k8s would interpret a hung readyz as
	// failure on readinessProbe.timeoutSeconds anyway).
	if len(s.readinessProbes) > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		for _, probe := range s.readinessProbes {
			if err := probe.Check(ctx); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{
					"status": "not_ready",
					"reason": "dependency_unhealthy",
					"probe":  probe.Name,
				})
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) query(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	var req QueryRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	req.TenantID = tenant.TenantID
	req.Region = tenant.Region
	// Phase 8.5: stamp the request's correlation id as the engine trace
	// id so the audit row, trace log, and client share one identifier
	// for the whole request path. Never accepted from the body.
	req.TraceID = correlationIDFromContext(r.Context())
	// PR #21: stamp the verified API key identity onto the request
	// so the audit row carries both the stable FK (KeyID) and the
	// display snapshot (KeyName). Sourced from the TenantContext,
	// never from the body — QueryRequest's json:"-" tags enforce
	// that even if the fields are in the JSON body.
	req.AgentKeyID = tenant.KeyID
	req.AgentKeyName = tenant.KeyName

	// Effective end-user identity: a verified assertion always wins and the
	// body-supplied user_id is ignored. The body user_id is honored only in demo
	// mode (ALLOW_DEMO_IDENTITY=true). tenant_id/region above come solely from the
	// API key and are never taken from the request body. A delegation token
	// (X-Groundwork-Delegation-Token) supersedes both paths: the request runs as
	// the verified delegated principal, gated by EvaluateDelegatedQuery.
	delegationToken := strings.TrimSpace(r.Header.Get(DelegationTokenHeader))
	if delegationToken != "" {
		if !s.applyDelegatedQueryGate(w, r, tenant, &req, delegationToken) {
			return
		}
	} else if decision, ok := identityFromContext(r.Context()); ok && decision.identity.Verified {
		// Canonicalize the verified identity to a tenant-scoped principal when the
		// feature flag is on. When off (or for demo/unverified identities) this returns
		// the raw user id unchanged. A verified-but-unresolved identity fails closed.
		effectiveUserID, _, err := CanonicalizeIdentity(r.Context(), s.resolver, s.canonicalIdentity, tenant.TenantID, decision.identity)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "identity_unresolved"})
			return
		}
		req.UserID = effectiveUserID
	}
	if req.Question == "" || req.UserID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "question and a verified user identity are required"})
		return
	}
	if s.executor == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "engine_unavailable"})
		return
	}
	// Phase 8.1: meter query executions against the tenant's runs
	// quota (fail closed — quota_exceeded:runs denies the query).
	if !s.recordUsage(w, tenant.TenantID, usage.MetricRuns, 1) {
		return
	}
	response := s.executor.Execute(r.Context(), req)
	// Phase 3: charge the run's citation budget with the actual citation
	// count (transaction-safe counter + evidence in the same tx as the
	// denial, if any). Best-effort: an exhausted budget has already been
	// served, so the run's next action fails closed instead.
	if delegationToken != "" && req.RunID != "" && s.governance != nil && len(response.Citations) > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		if err := s.governance.RecordQueryCitations(ctx, tenant.TenantID, req.RunID, len(response.Citations)); err != nil {
			if errors.Is(err, ErrBudgetExhausted) {
				w.Header().Set("X-Groundwork-Citation-Budget", "exhausted")
			} else {
				log.Printf("record citations run %s: %v", req.RunID, err)
			}
		}
		cancel()
	}
	writeJSON(w, http.StatusOK, response)
}

// applyDelegatedQueryGate is the single enforcement point for the
// /v1/query delegation path (Phase 2): the presented delegation token
// is verified, bound to the run, and evaluated against the builtin
// groundwork_search:search action. On allow, req.UserID becomes the
// verified delegated principal (grant.subject_principal_id) the engine
// runs the query as. Every outcome — allowed, denied, or fail_closed —
// is recorded in the run's hash-chained evidence. Returns false when a
// response has already been written.
func (s *Server) applyDelegatedQueryGate(w http.ResponseWriter, r *http.Request, tenant TenantContext, req *QueryRequest, token string) bool {
	if s.governance == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "governance_unavailable"})
		return false
	}
	if req.RunID == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("run_id required for delegated query"))
		return false
	}
	if req.Question == "" {
		writeGovernanceError(w, http.StatusBadRequest, errors.New("invalid_question"))
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	// Phase 8.1: the delegation gate is a governed decision — meter it
	// against the tenant's decisions quota (fail closed).
	if !s.recordUsage(w, tenant.TenantID, usage.MetricDecisions, 1) {
		return false
	}
	result, err := s.governance.EvaluateDelegatedQuery(ctx, tenant.TenantID, tenant.Region, token, req.RunID, req.Question)
	if err != nil {
		writeGovernanceServiceError(w, err, "delegation_gate_failed")
		return false
	}
	if !result.Allowed {
		// Fail closed with the recorded decision outcome; the evidence
		// chain already carries the denial/approval-required reason.
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":    "delegated_query_denied",
			"decision": result.Decision.Decision,
			"reason":   result.Decision.Reason,
		})
		return false
	}
	req.UserID = result.UserID
	return true
}

// identityOrDelegation lets a delegation token substitute for the
// end-user identity middleware on /v1/query. When no delegation token
// is present, behavior is identical to requireVerifiedIdentity (fail
// closed without a verified assertion unless demo identity is enabled).
func (s *Server) identityOrDelegation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(r.Header.Get(DelegationTokenHeader)) == "" {
			s.requireVerifiedIdentity(next)(w, r)
			return
		}
		next(w, r)
	}
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	manager, ok := s.apiKeys.(APIKeyManager)
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrAPIKeyManagementUnavailable.Error()})
		return
	}
	var req CreateAPIKeyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 700*time.Millisecond)
	defer cancel()
	resp, err := manager.Create(ctx, tenant, req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "api_key_create_failed"})
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	manager, ok := s.apiKeys.(APIKeyManager)
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrAPIKeyManagementUnavailable.Error()})
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_api_key_id"})
		return
	}
	if id == tenant.KeyID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot_revoke_current_key"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 700*time.Millisecond)
	defer cancel()
	revoked, err := manager.Revoke(ctx, tenant, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "api_key_revoke_failed"})
		return
	}
	if !revoked {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "api_key_not_found"})
		return
	}
	writeJSON(w, http.StatusOK, RevokeAPIKeyResponse{ID: id, Revoked: true, Status: "revoked"})
}

func (s *Server) rotateAPIKey(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	manager, ok := s.apiKeys.(APIKeyManager)
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": ErrAPIKeyManagementUnavailable.Error()})
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_api_key_id"})
		return
	}
	if id == tenant.KeyID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot_rotate_current_key"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 700*time.Millisecond)
	defer cancel()
	resp, err := manager.Rotate(ctx, tenant, id)
	if err != nil {
		if errors.Is(err, ErrInvalidAPIKey) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "api_key_not_found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "api_key_rotate_failed"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) requireAPIKey(scope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// SLO HTTP telemetry (Phase 8.5): wrap the writer so the final
		// status class is recorded per tenant, including early 401/403/
		// 429/503 responses. Requests that fail before the API key is
		// resolved record with an empty tenant id.
		sw := &sloStatusWriter{ResponseWriter: w}
		tenantID := s.authenticate(sw, r, scope, next)
		gwmetrics.RecordHTTPRequest(tenantID, r.Method, statusClass(sw.status))
	}
}

// sloStatusWriter captures the first WriteHeader status (200 when the
// handler never writes one) for SLO telemetry.
type sloStatusWriter struct {
	http.ResponseWriter
	status int
}

func (s *sloStatusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *sloStatusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// statusClass buckets an HTTP status into the closed 2xx/3xx/4xx/5xx
// label set (a zero status means the handler wrote nothing = success).
func statusClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	default:
		return "2xx"
	}
}

// authenticate resolves the API key, enforces region/scope/limits, sets
// the tenant context, and invokes next. It returns the tenant id ("" for
// requests that failed before the key resolved) so callers can record
// SLO telemetry; failures after resolution are attributed to the tenant.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, scope string, next http.HandlerFunc) string {
	if s.apiKeys == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "api_key_resolver_unavailable"})
		return ""
	}
	rawKey := extractAPIKey(r)
	if rawKey == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_api_key"})
		return ""
	}
	authCtx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
	defer cancel()
	tenant, err := s.apiKeys.Resolve(authCtx, rawKey)
	if err != nil {
		if errors.Is(err, ErrAPIKeyExpired) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "api_key_expired"})
			return ""
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_api_key"})
		return ""
	}
	// Phase 4 sovereign deployment: the tenant's region comes only
	// from trusted configuration (API key + tenant mapping). When a
	// region resolver is wired, a mismatch or an unprovisioned
	// tenant fails closed — a request can never carry its tenant
	// region in a body or header.
	if s.regionResolver != nil {
		region, jurisdiction, ok := s.regionResolver.Resolve(tenant.TenantID)
		if !ok {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": ErrRegionUnprovisioned.Error()})
			return tenant.TenantID
		}
		if region != tenant.Region {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": ErrRegionMismatch.Error()})
			return tenant.TenantID
		}
		tenant.Jurisdiction = jurisdiction
	}
	// Phase 8.1 tenant directory: the operator-managed directory is
	// consulted after the region resolver. A tenant that is disabled or
	// deprovisioned fails closed (ErrTenantNotActive) — deprovisioning
	// is non-destructive and takes effect immediately. A tenant whose
	// key region differs from its directory region fails closed
	// (ErrRegionMismatch). Tenants absent from the directory are
	// unaffected (governed by the region resolver only) and fall back
	// to the capacity model's default tier.
	tier := CapacityTierStandard
	if directory, ok := s.tenantSvc.(TenantDirectory); ok && directory != nil {
		region, status, directoryTier, found := directory.Lookup(authCtx, tenant.TenantID)
		if found {
			if status != TenantStatusActive {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": ErrTenantNotActive.Error()})
				return tenant.TenantID
			}
			if region != tenant.Region {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": ErrRegionMismatch.Error()})
				return tenant.TenantID
			}
			tier = directoryTier
		}
	}
	if !hasScope(tenant, scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient_scope"})
		return tenant.TenantID
	}
	// Phase 8.2 overload protection: an instance-wide in-flight cap
	// rejects new work immediately (fail-closed 503, never queued) when
	// the whole process is saturated, before any per-key or per-tenant
	// accounting. Overloaded instances record and shed load rather than
	// park goroutines on a queue.
	if release, ok := s.overloadLimiter.Acquire(); !ok {
		gwmetrics.RecordOverloadRejection(tenant.TenantID)
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "overload_exceeded"})
		return tenant.TenantID
	} else {
		defer release()
	}
	if ok, retryAfter := s.limiter.Allow(tenant.KeyID, tenant.RateLimitRPM); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limit_exceeded"})
		return tenant.TenantID
	}
	if ok, retryAfter := s.tenantLimiter.Allow(tenant.TenantID); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limit_exceeded"})
		return tenant.TenantID
	}
	// Phase 8.2 capacity model: the per-tenant in-flight cap derives
	// from the tenant's directory tier (standard|plus|enterprise);
	// tenants outside the directory use the model default. Without a
	// model, the limiter's own default cap applies. Rejections are
	// fail-closed 503 (never queued) and counted per tenant so the
	// capacity model is observable.
	var release func()
	var acquired bool
	if s.capacityModel != nil {
		release, acquired = s.concurrencyLimiter.AcquireWithLimit(tenant.TenantID, s.capacityModel.ConcurrencyFor(tier))
	} else {
		release, acquired = s.concurrencyLimiter.Acquire(tenant.TenantID)
	}
	if !acquired {
		gwmetrics.RecordTenantCapacityRejection(tenant.TenantID)
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "concurrency_limit_exceeded"})
		return tenant.TenantID
	}
	defer release()
	next(w, r.WithContext(context.WithValue(r.Context(), tenantContextKey{}, tenant)))
	return tenant.TenantID
}

type tenantContextKey struct{}

func tenantFromContext(ctx context.Context) (TenantContext, bool) {
	tenant, ok := ctx.Value(tenantContextKey{}).(TenantContext)
	return tenant, ok
}

type identityContextKey struct{}

// identityDecision carries the outcome of identity middleware. A verified
// identity overrides any body-supplied user_id; demo==true means the request may
// fall back to the body user_id (dev only).
type identityDecision struct {
	identity Identity
	demo     bool
}

func identityFromContext(ctx context.Context) (identityDecision, bool) {
	decision, ok := ctx.Value(identityContextKey{}).(identityDecision)
	return decision, ok
}

// CorrelationIDHeader names the correlation id header (Phase 8.5). The
// middleware accepts an incoming X-Groundwork-Correlation-Id (or the
// generic X-Correlation-Id), generates one when absent, echoes it on
// every response, and stashes it on the context so handlers can stamp
// it onto downstream work (the query handler maps it to the engine
// trace id).
const CorrelationIDHeader = "X-Groundwork-Correlation-Id"

type correlationContextKey struct{}

func correlationIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(correlationContextKey{}).(string)
	return id
}

func (s *Server) correlationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get(CorrelationIDHeader))
		if id == "" {
			id = strings.TrimSpace(r.Header.Get("X-Correlation-Id"))
		}
		if id == "" {
			id = newCorrelationID()
		}
		w.Header().Set(CorrelationIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), correlationContextKey{}, id)))
	})
}

// newCorrelationID generates a fresh opaque correlation id (crypto-random
// hex, no user input, no PII).
func newCorrelationID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("gw-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func extractUserAssertion(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("X-Groundwork-User-Assertion"))
	const prefix = "Bearer "
	if strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)) {
		return strings.TrimSpace(value[len(prefix):])
	}
	return value
}

// requireVerifiedIdentity enforces that /v1/query carries a cryptographically
// verified end-user identity. A signed assertion (X-Groundwork-User-Assertion) is
// always verified and, on success, becomes the effective user. When no assertion
// is supplied the request fails closed unless demo identity is explicitly enabled.
func (s *Server) requireVerifiedIdentity(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractUserAssertion(r)
		if token != "" {
			if s.identity == nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "identity_verifier_unavailable"})
				return
			}
			id, err := s.identity.Verify(r.Context(), token)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_identity_assertion"})
				return
			}
			ctx := context.WithValue(r.Context(), identityContextKey{}, identityDecision{identity: id})
			next(w, r.WithContext(ctx))
			return
		}
		if !s.allowDemoIdentity {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "verified_identity_required"})
			return
		}
		ctx := context.WithValue(r.Context(), identityContextKey{}, identityDecision{demo: true})
		next(w, r.WithContext(ctx))
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
