package connectors

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	gwmetrics "groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/runtime"
)

// Gateway implements both runtime.ConnectorService (registry/lifecycle/
// health surface) and runtime.ConnectorDispatcher (the invocation
// pipeline called by governance after an allowed decision).
//
// Central rule: no registered tool call may reach an external system
// unless Groundwork authorizes that exact agent action first. The
// gateway therefore NEVER dispatches on its own: Dispatch() is reached
// only from governance.DispatchAction with an allowed decision — and
// it re-validates connector lifecycle, region, and manifest state with
// a fresh read immediately before opening the outbound connection.
type Gateway struct {
	store   Store
	rest    *RESTConnector
	mcp     *MCPConnector
	secrets SecretResolver
	now     func() time.Time
	// regionResolver validates that the call region is a provisioned
	// deployment region; nil skips deployment-level checks (dev).
	regionOK func(region string) bool
	// dispatchBreakers are per-(tenant,connector) circuits around the
	// outbound call (Phase 8.2). A dead connector fails fast with
	// connector_breaker_open evidence instead of burning its timeout +
	// retry budget on every dispatch; the half-open probe closes the
	// circuit on recovery. Config/lifecycle preflight failures happen
	// BEFORE the circuit and never count against it.
	dispatchBreakers *runtime.BreakerRegistry
}

// NewGateway wires the registry + transports + secret provider.
// regionOK optionally restricts invocations to provisioned deployment
// regions (main.go passes the deployment config's resolver).
func NewGateway(store Store, secrets SecretResolver, regionOK func(region string) bool) *Gateway {
	return &Gateway{
		store:    store,
		rest:     NewRESTConnector(secrets),
		mcp:      NewMCPConnector(),
		secrets:  secrets,
		now:      time.Now,
		regionOK: regionOK,
		dispatchBreakers: runtime.NewBreakerRegistry(runtime.CircuitBreakerSettings{
			Name: "connector_dispatch", FailureLimit: 3,
			OpenTimeout: 30 * time.Second, HalfOpenLimit: 1,
		}),
	}
}

// SetDispatchBreakerSettings replaces the dispatch circuit settings
// (tests shorten the open timeout; main.go could tune them from env).
// Existing per-connector circuits are discarded — acceptable only at
// startup or in tests, never mid-traffic.
func (g *Gateway) SetDispatchBreakerSettings(settings runtime.CircuitBreakerSettings) {
	g.dispatchBreakers = runtime.NewBreakerRegistry(settings)
}

// SecretResolver exposes the resolver wired at construction so the
// Phase 8.5 credential-expiry monitor can date the same references the
// gateway dispatches with (never secret material).
func (g *Gateway) SecretResolver() SecretResolver { return g.secrets }

// --- registry / lifecycle surface (runtime.ConnectorService) ---

func (g *Gateway) Register(ctx context.Context, tenantID, actor string, admin bool, req runtime.ConnectorRegisterRequest) (runtime.ConnectorDetail, error) {
	if !admin {
		return runtime.ConnectorDetail{}, runtime.ErrGovernanceNotAuthorized
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return runtime.ConnectorDetail{}, fmt.Errorf("%w: name is required", runtime.ErrConnectorInvalidConfig)
	}
	if req.Type != runtime.ConnectorTypeREST && req.Type != runtime.ConnectorTypeMCP {
		return runtime.ConnectorDetail{}, fmt.Errorf("%w: type must be rest or mcp", runtime.ErrConnectorInvalidConfig)
	}
	if strings.TrimSpace(req.Config.Region) == "" {
		return runtime.ConnectorDetail{}, fmt.Errorf("%w: region is required", runtime.ErrConnectorInvalidConfig)
	}
	if g.regionOK != nil && !g.regionOK(req.Config.Region) {
		return runtime.ConnectorDetail{}, fmt.Errorf("%w: region %q is not a provisioned deployment region", runtime.ErrConnectorRegion, req.Config.Region)
	}
	if err := ValidateConfig(req.Config); err != nil {
		return runtime.ConnectorDetail{}, err
	}
	if len(req.Actions) == 0 {
		return runtime.ConnectorDetail{}, fmt.Errorf("%w: at least one action is required", runtime.ErrConnectorInvalidConfig)
	}
	actions := SortedActions(req.Actions)
	for i := range actions {
		if err := ValidateManifest(req.Type, actions[i]); err != nil {
			return runtime.ConnectorDetail{}, err
		}
		actions[i] = defaultManifestLimits(actions[i])
	}
	digest, err := ManifestDigest(req.Config, actions)
	if err != nil {
		return runtime.ConnectorDetail{}, err
	}
	if req.Config.RedactionFields == nil {
		req.Config.RedactionFields = DefaultRedactionFields()
	}
	conn := runtime.Connector{
		ID:                  newID("conn"),
		TenantID:            tenantID,
		Name:                name,
		Type:                req.Type,
		Lifecycle:           runtime.ConnectorLifecycleDraft,
		BaseURL:             req.Config.BaseURL,
		Region:              req.Config.Region,
		OwnerPrincipalID:    actor,
		ManifestDigest:      digest,
		TimeoutMS:           int64(req.Config.TimeoutMS),
		RetryMax:            req.Config.RetryMax,
		RetryIdempotentOnly: req.Config.RetryIdempotentOnly,
		MaxResponseBytes:    int64(req.Config.MaxResponseBytes),
		AllowedContentTypes: req.Config.AllowedContentTypes,
		RedactionFields:     req.Config.RedactionFields,
		SecretRef:           req.Config.SecretRef,
		TLSVerify:           req.Config.TLSVerify,
		ClientCertRef:       req.Config.ClientCertRef,
		CreatedAt:           g.now().UTC(),
		UpdatedAt:           g.now().UTC(),
	}
	version := runtime.ConnectorVersion{
		ID: newID("cver"), ConnectorID: conn.ID, TenantID: tenantID,
		VersionNumber: 1, Config: req.Config, ManifestDigest: digest,
		CreatedBy: actor, CreatedAt: g.now().UTC(),
	}
	event := runtime.ConnectorLifecycleEvent{
		TenantID: tenantID, ConnectorID: conn.ID, ActionType: "create",
		ToState: runtime.ConnectorLifecycleDraft, ActorPrincipalID: actor,
		Reason: "connector registration", CreatedAt: g.now().UTC(),
	}
	if err := g.store.CreateConnector(ctx, conn, version, actions, event); err != nil {
		return runtime.ConnectorDetail{}, err
	}
	return g.Get(ctx, tenantID, conn.ID)
}

func (g *Gateway) List(ctx context.Context, tenantID string) ([]runtime.Connector, error) {
	return g.store.ListConnectors(ctx, tenantID)
}

func (g *Gateway) Get(ctx context.Context, tenantID, connectorID string) (runtime.ConnectorDetail, error) {
	conn, err := g.store.GetConnector(ctx, tenantID, connectorID)
	if err != nil {
		return runtime.ConnectorDetail{}, err
	}
	version, err := g.store.GetCurrentVersion(ctx, tenantID, connectorID)
	if err != nil {
		return runtime.ConnectorDetail{}, err
	}
	actions, err := g.store.GetActions(ctx, tenantID, connectorID, version.ID)
	if err != nil {
		return runtime.ConnectorDetail{}, err
	}
	events, err := g.store.ListLifecycleEvents(ctx, tenantID, connectorID)
	if err != nil {
		return runtime.ConnectorDetail{}, err
	}
	conn.VersionNumber = version.VersionNumber
	return runtime.ConnectorDetail{Connector: conn, Config: version.Config, Actions: actions, LifecycleEvents: events}, nil
}

func (g *Gateway) GetManifest(ctx context.Context, tenantID, connectorID string) (runtime.ConnectorVersion, []runtime.ConnectorActionManifest, error) {
	version, err := g.store.GetCurrentVersion(ctx, tenantID, connectorID)
	if err != nil {
		return runtime.ConnectorVersion{}, nil, err
	}
	actions, err := g.store.GetActions(ctx, tenantID, connectorID, version.ID)
	if err != nil {
		return runtime.ConnectorVersion{}, nil, err
	}
	return version, actions, nil
}

func (g *Gateway) Transition(ctx context.Context, tenantID, connectorID, actor string, admin bool, action string, req runtime.ConnectorTransitionRequest) (runtime.Connector, error) {
	if !admin {
		return runtime.Connector{}, runtime.ErrGovernanceNotAuthorized
	}
	conn, err := g.store.GetConnector(ctx, tenantID, connectorID)
	if err != nil {
		return runtime.Connector{}, err
	}
	var to string
	switch action {
	case "activate":
		to = runtime.ConnectorLifecycleActive
	case "suspend":
		to = runtime.ConnectorLifecycleSuspended
	case "revoke":
		to = runtime.ConnectorLifecycleRevoked
	case "retire":
		to = runtime.ConnectorLifecycleRetired
	default:
		return runtime.Connector{}, fmt.Errorf("%w: unknown transition %q", runtime.ErrConnectorInvalidState, action)
	}
	if !isValidTransition(conn.Lifecycle, to) {
		return runtime.Connector{}, runtime.ErrConnectorInvalidState
	}
	// Irreversible transitions require an explicit reason.
	if to == runtime.ConnectorLifecycleRevoked && strings.TrimSpace(req.Reason) == "" {
		return runtime.Connector{}, fmt.Errorf("%w: revoke requires a reason", runtime.ErrConnectorInvalidState)
	}
	return g.store.TransitionConnector(ctx, tenantID, connectorID, conn.Lifecycle, to, actor, req.Reason)
}

func (g *Gateway) UpdateConfig(ctx context.Context, tenantID, connectorID, actor string, admin bool, req runtime.ConnectorRegisterRequest) (runtime.ConnectorDetail, error) {
	if !admin {
		return runtime.ConnectorDetail{}, runtime.ErrGovernanceNotAuthorized
	}
	conn, err := g.store.GetConnector(ctx, tenantID, connectorID)
	if err != nil {
		return runtime.ConnectorDetail{}, err
	}
	// Active connectors cannot change their surface under traffic.
	if conn.Lifecycle == runtime.ConnectorLifecycleActive ||
		conn.Lifecycle == runtime.ConnectorLifecycleRevoked ||
		conn.Lifecycle == runtime.ConnectorLifecycleRetired {
		return runtime.ConnectorDetail{}, runtime.ErrConnectorInvalidState
	}
	if req.Config.Region != conn.Region {
		return runtime.ConnectorDetail{}, fmt.Errorf("%w: region cannot change on an existing connector", runtime.ErrConnectorInvalidConfig)
	}
	if err := ValidateConfig(req.Config); err != nil {
		return runtime.ConnectorDetail{}, err
	}
	if len(req.Actions) == 0 {
		return runtime.ConnectorDetail{}, fmt.Errorf("%w: at least one action is required", runtime.ErrConnectorInvalidConfig)
	}
	actions := SortedActions(req.Actions)
	for i := range actions {
		if err := ValidateManifest(conn.Type, actions[i]); err != nil {
			return runtime.ConnectorDetail{}, err
		}
		actions[i] = defaultManifestLimits(actions[i])
	}
	digest, err := ManifestDigest(req.Config, actions)
	if err != nil {
		return runtime.ConnectorDetail{}, err
	}
	current, err := g.store.GetCurrentVersion(ctx, tenantID, connectorID)
	if err != nil {
		return runtime.ConnectorDetail{}, err
	}
	conn.BaseURL = req.Config.BaseURL
	conn.ManifestDigest = digest
	conn.TimeoutMS = int64(req.Config.TimeoutMS)
	conn.RetryMax = req.Config.RetryMax
	conn.RetryIdempotentOnly = req.Config.RetryIdempotentOnly
	conn.MaxResponseBytes = int64(req.Config.MaxResponseBytes)
	conn.AllowedContentTypes = req.Config.AllowedContentTypes
	conn.RedactionFields = req.Config.RedactionFields
	conn.SecretRef = req.Config.SecretRef
	conn.TLSVerify = req.Config.TLSVerify
	conn.ClientCertRef = req.Config.ClientCertRef
	version := runtime.ConnectorVersion{
		ID: newID("cver"), ConnectorID: conn.ID, TenantID: tenantID,
		VersionNumber: current.VersionNumber + 1, Config: req.Config, ManifestDigest: digest,
		CreatedBy: actor, CreatedAt: g.now().UTC(),
	}
	event := runtime.ConnectorLifecycleEvent{
		TenantID: tenantID, ConnectorID: conn.ID, ActionType: "config_update",
		FromState: conn.Lifecycle, ToState: conn.Lifecycle,
		ActorPrincipalID: actor, Reason: req.Description, CreatedAt: g.now().UTC(),
	}
	if err := g.store.UpdateVersion(ctx, conn, version, actions, event); err != nil {
		return runtime.ConnectorDetail{}, err
	}
	return g.Get(ctx, tenantID, connectorID)
}

// Health performs the authorized, audited, read-only health probe and
// records its outcome (health_check evidence via the runtime layer).
func (g *Gateway) Health(ctx context.Context, tenantID, connectorID string) (runtime.ConnectorHealth, error) {
	conn, err := g.store.GetConnector(ctx, tenantID, connectorID)
	if err != nil {
		return runtime.ConnectorHealth{}, err
	}
	if conn.Lifecycle != runtime.ConnectorLifecycleActive &&
		conn.Lifecycle != runtime.ConnectorLifecycleDraft &&
		conn.Lifecycle != runtime.ConnectorLifecycleSuspended {
		return runtime.ConnectorHealth{}, runtime.ErrConnectorRevoked
	}
	version, err := g.store.GetCurrentVersion(ctx, tenantID, connectorID)
	if err != nil {
		return runtime.ConnectorHealth{}, err
	}
	authHeader, err := g.authHeader(ctx, tenantID, version.Config, false)
	if err != nil {
		return runtime.ConnectorHealth{ConnectorID: connectorID, Healthy: false, ErrorCode: err.Error()}, nil
	}
	start := time.Now()
	var result runtime.ConnectorDispatchResult
	switch conn.Type {
	case runtime.ConnectorTypeREST:
		result, err = g.rest.Health(ctx, version.Config)
	case runtime.ConnectorTypeMCP:
		result, err = g.mcp.Health(ctx, version.Config, authHeader)
	default:
		return runtime.ConnectorHealth{}, runtime.ErrConnectorInvalidState
	}
	latency := time.Since(start).Milliseconds()
	if err != nil {
		result = runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "health_probe_failed", DurationMS: latency}
	}
	return runtime.ConnectorHealth{
		ConnectorID: connectorID,
		Healthy:     result.Outcome == runtime.InvocationSuccess,
		StatusCode:  result.StatusCode,
		ErrorCode:   result.ErrorCode,
		LatencyMS:   latency,
		CheckedAt:   g.now().UTC(),
	}, nil
}

// --- invocation pipeline (runtime.ConnectorDispatcher) ---

// Dispatch implements the fail-closed preflight + outbound call. It is
// only ever reached from governance.DispatchAction with an allowed
// decision already on the evidence chain.
func (g *Gateway) Dispatch(ctx context.Context, req runtime.ConnectorDispatchRequest) (runtime.ConnectorDispatchResult, error) {
	result, err := g.dispatch(ctx, req)
	if result.Outcome != runtime.InvocationSuccess {
		connectorID := result.ConnectorID
		if connectorID == "" {
			connectorID = req.ConnectorName
		}
		gwmetrics.RecordConnectorError(req.TenantID, connectorID, result.ErrorCode)
	}
	return result, err
}

func (g *Gateway) dispatch(ctx context.Context, req runtime.ConnectorDispatchRequest) (runtime.ConnectorDispatchResult, error) {
	// Preflight with a FRESH read: a revocation/suspension that happened
	// after the decision must deny the call before any connection opens.
	conn, err := g.store.GetConnectorByName(ctx, req.TenantID, req.ConnectorName)
	if err != nil {
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "connector_not_registered"}, runtime.ErrConnectorUnregistered
	}
	if conn.Lifecycle == runtime.ConnectorLifecycleRevoked || conn.Lifecycle == runtime.ConnectorLifecycleRetired {
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "connector_revoked"}, runtime.ErrConnectorRevoked
	}
	if conn.Lifecycle == runtime.ConnectorLifecycleSuspended || conn.Lifecycle == runtime.ConnectorLifecycleDraft {
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "connector_not_active"}, runtime.ErrConnectorNotActive
	}
	if conn.Lifecycle != runtime.ConnectorLifecycleActive {
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "connector_not_active"}, runtime.ErrConnectorNotActive
	}
	if conn.Region != req.Region {
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "connector_region_mismatch"}, runtime.ErrConnectorRegion
	}
	if g.regionOK != nil && !g.regionOK(req.Region) {
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "region_unprovisioned"}, runtime.ErrConnectorRegion
	}
	version, err := g.store.GetCurrentVersion(ctx, req.TenantID, conn.ID)
	if err != nil {
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "no_manifest"}, runtime.ErrConnectorNoManifest
	}
	actions, err := g.store.GetActions(ctx, req.TenantID, conn.ID, version.ID)
	if err != nil {
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "no_manifest"}, err
	}
	var action *runtime.ConnectorActionManifest
	for i := range actions {
		if actions[i].Name == req.Action {
			action = &actions[i]
			break
		}
	}
	if action == nil {
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "action_not_in_manifest"}, fmt.Errorf("%w: action %q not in manifest", runtime.ErrConnectorNoManifest, req.Action)
	}
	if len(action.AllowedVersions) > 0 && !contains(action.AllowedVersions, req.AgentVersionID) {
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "agent_version_not_allowed"}, fmt.Errorf("%w: agent version not allowed by manifest", runtime.ErrConnectorNotActive)
	}
	authHeader, err := g.authHeader(ctx, req.TenantID, version.Config, true)
	if err != nil {
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "secret_resolution_failed"}, err
	}
	// Phase 8.2 dispatch circuit: every preflight gate above is now
	// satisfied, so the only remaining variable is the endpoint itself.
	// An open circuit fails fast here (connector_breaker_open evidence)
	// instead of spending the connector's timeout + retry budget on a
	// dependency that is already known to be down. Only transport-level
	// failures and 5xx responses trip the circuit; 4xx (per-request
	// client problems) never blackout a connector.
	breaker := g.dispatchBreakers.For(req.TenantID + "|" + conn.ID)
	if err := breaker.Allow(); err != nil {
		gwmetrics.SetConnectorBreakerState(req.TenantID, conn.ID, runtime.CircuitStateValue(breaker.State()))
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "connector_breaker_open"}, runtime.ErrConnectorUnavailable
	}
	args := FilterArguments(req.Arguments, action.Args)
	var res runtime.ConnectorDispatchResult
	switch conn.Type {
	case runtime.ConnectorTypeREST:
		res, err = g.rest.Dispatch(ctx, version.Config, *action, args, authHeader, req.TraceID, req.IdempotencyKey)
		res.ConnectorID = conn.ID
	case runtime.ConnectorTypeMCP:
		res, err = g.mcp.CallTool(ctx, version.Config, *action, args, authHeader, req.TraceID)
		res.ConnectorID = conn.ID
	default:
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "unknown_transport"}, runtime.ErrConnectorInvalidState
	}
	g.reportDispatch(req.TenantID, conn.ID, breaker, res, err)
	return res, err
}

// reportDispatch feeds one outbound-call outcome into the dispatch
// circuit and publishes the state gauge. Success closes the circuit; a
// transport error or 5xx response is a failure; everything else
// (blocked responses, 4xx) leaves the circuit untouched.
func (g *Gateway) reportDispatch(tenantID, connectorID string, breaker *runtime.CircuitBreaker, res runtime.ConnectorDispatchResult, err error) {
	if res.Outcome == runtime.InvocationSuccess {
		breaker.ReportSuccess()
	} else if err != nil || res.StatusCode >= 500 {
		breaker.ReportFailure()
		if breaker.State() == runtime.CircuitOpen {
			gwmetrics.RecordConnectorBreakerTrip(tenantID, connectorID)
		}
	}
	gwmetrics.SetConnectorBreakerState(tenantID, connectorID, runtime.CircuitStateValue(breaker.State()))
}

// DispatchHealth implements the runtime.ConnectorService surface used
// by the health endpoint to produce evidence-backed probes.
func (g *Gateway) DispatchHealth(ctx context.Context, tenantID, region, connectorID string) (runtime.ConnectorDispatchResult, error) {
	conn, err := g.store.GetConnector(ctx, tenantID, connectorID)
	if err != nil {
		return runtime.ConnectorDispatchResult{}, err
	}
	if conn.Region != region {
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "connector_region_mismatch"}, runtime.ErrConnectorRegion
	}
	version, err := g.store.GetCurrentVersion(ctx, tenantID, connectorID)
	if err != nil {
		return runtime.ConnectorDispatchResult{}, err
	}
	authHeader, err := g.authHeader(ctx, tenantID, version.Config, false)
	if err != nil {
		return runtime.ConnectorDispatchResult{Outcome: runtime.InvocationFailure, ErrorCode: "secret_resolution_failed"}, err
	}
	switch conn.Type {
	case runtime.ConnectorTypeREST:
		return g.rest.Health(ctx, version.Config)
	case runtime.ConnectorTypeMCP:
		return g.mcp.Health(ctx, version.Config, authHeader)
	}
	return runtime.ConnectorDispatchResult{}, runtime.ErrConnectorInvalidState
}

// authHeader resolves the connector secret reference into an
// Authorization header value. Material never leaves this layer and is
// never logged. Health probes (sendSecret=false) skip credentials
// entirely — a health check must be credential-free and side-effect-free.
func (g *Gateway) authHeader(ctx context.Context, tenantID string, cfg runtime.ConnectorConfig, sendSecret bool) (string, error) {
	if cfg.SecretRef == "" {
		return "", nil
	}
	if !sendSecret {
		return "", nil
	}
	raw, err := g.secrets.Resolve(ctx, tenantID, cfg.SecretRef)
	if err != nil {
		return "", err
	}
	ref := strings.ToLower(cfg.SecretRef)
	if strings.HasPrefix(ref, "env://") || strings.HasPrefix(ref, "keyring://") {
		// Reference types: the resolved material is used verbatim as a
		// bearer token, or in the form "Bearer <material>".
		v := string(raw)
		if strings.HasPrefix(v, "Bearer ") {
			return v, nil
		}
		return "Bearer " + v, nil
	}
	return "", fmt.Errorf("%w: unsupported secret reference %q", runtime.ErrConnectorInvalidConfig, cfg.SecretRef)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// newID is a small, dependency-free unique id (uuidgen-free so tests
// and memory mode stay hermetic). Prefix keeps evidence readable.
func newID(prefix string) string {
	var b [16]byte
	now := time.Now().UnixNano()
	// Mix time + counter into bytes (not cryptographically unique, but
	// unique enough per process; Postgres rows use gen_random_uuid()).
	b[0] = byte(now >> 56)
	b[1] = byte(now >> 48)
	b[2] = byte(now >> 40)
	b[3] = byte(now >> 32)
	b[4] = byte(now >> 24)
	b[5] = byte(now >> 16)
	b[6] = byte(now >> 8)
	b[7] = byte(now)
	b[8] = byte(len(prefix))
	for i, c := range prefix {
		b[9+i] = byte(c)
	}
	return prefix + "-" + base64.RawURLEncoding.EncodeToString(b[:])[:18]
}
