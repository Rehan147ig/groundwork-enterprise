package connectors

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gwmetrics "groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/runtime"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

type fakeSecretResolver struct {
	values  map[string]string
	expires map[string]time.Time
}

func (f *fakeSecretResolver) Resolve(_ context.Context, _, ref string) ([]byte, error) {
	if v, ok := f.values[ref]; ok {
		return []byte(v), nil
	}
	return nil, runtime.ErrConnectorUnavailable
}

func (f *fakeSecretResolver) Expiry(_ context.Context, _, ref string) time.Time {
	return f.expires[ref]
}

func (f *fakeSecretResolver) Health() string { return "fake" }

func gatewayTestHarness(t *testing.T) (*Gateway, *fakeSecretResolver) {
	t.Helper()
	secrets := &fakeSecretResolver{values: map[string]string{"env://PAYMENTS_TOKEN": "Bearer super-secret"}}
	g := NewGateway(NewMemoryStore(), secrets, nil)
	return g, secrets
}

func registerRESTConnector(t *testing.T, g *Gateway, tsURL string) runtime.ConnectorDetail {
	t.Helper()
	detail, err := g.Register(context.Background(), "tenant-acme", "principal:owner", true, runtime.ConnectorRegisterRequest{
		Name: "payments",
		Type: runtime.ConnectorTypeREST,
		Config: runtime.ConnectorConfig{
			BaseURL:             tsURL,
			Region:              "eu",
			TimeoutMS:           5000,
			RetryMax:            2,
			RetryIdempotentOnly: true,
			MaxResponseBytes:    262144,
			TLSVerify:           true,
			SecretRef:           "env://PAYMENTS_TOKEN",
			AllowedContentTypes: []string{"application/json"},
			RedactionFields:     DefaultRedactionFields(),
		},
		Actions: []runtime.ConnectorActionManifest{
			{Name: "get_balance", TransportMethod: "GET", PathTemplate: "/v1/balance", Risk: runtime.ConnectorRiskLow, ReadOnly: true},
			{Name: "pay", TransportMethod: "POST", PathTemplate: "/v1/pay", Risk: runtime.ConnectorRiskCritical, MaxRequestBytes: 4096},
		},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return detail
}

func TestGatewayLifecycle(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	g, _ := gatewayTestHarness(t)
	detail := registerRESTConnector(t, g, ts.URL)
	if detail.Connector.Lifecycle != runtime.ConnectorLifecycleDraft {
		t.Fatalf("new connector must be draft, got %s", detail.Connector.Lifecycle)
	}
	if detail.Connector.ManifestDigest == "" {
		t.Fatal("manifest digest missing")
	}
	if len(detail.Actions) != 2 {
		t.Fatalf("actions = %d", len(detail.Actions))
	}
	if detail.Config.TimeoutMS != 5000 {
		t.Fatalf("config = %+v", detail.Config)
	}

	// Draft cannot dispatch.
	_, err := g.Dispatch(context.Background(), runtime.ConnectorDispatchRequest{
		TenantID: "tenant-acme", Region: "eu", ConnectorName: "payments", Action: "get_balance",
		ToolID: detail.Connector.ToolID, ToolActionID: "action-balance",
		DecisionID: "dec-1", RunID: "run-1", AgentID: "agent-1", AgentVersionID: "version-1",
	})
	if !errors.Is(err, runtime.ErrConnectorNotActive) {
		t.Fatalf("draft dispatch must fail closed, got %v", err)
	}

	// Activate.
	conn, err := g.Transition(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		"activate", runtime.ConnectorTransitionRequest{Reason: "go live"})
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if conn.Lifecycle != runtime.ConnectorLifecycleActive {
		t.Fatalf("lifecycle = %s", conn.Lifecycle)
	}

	// Dispatch succeeds.
	res, err := g.Dispatch(context.Background(), runtime.ConnectorDispatchRequest{
		TenantID: "tenant-acme", Region: "eu", ConnectorName: "payments", Action: "get_balance",
		ToolID: detail.Connector.ToolID, ToolActionID: "action-balance",
		DecisionID: "dec-1", RunID: "run-1", AgentID: "agent-1", AgentVersionID: "version-1",
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if res.Outcome != runtime.InvocationSuccess {
		t.Fatalf("outcome = %+v", res)
	}
	if res.ConnectorID != detail.Connector.ID {
		t.Fatalf("connector id = %q", res.ConnectorID)
	}

	// Suspend then dispatch fails closed.
	if _, err := g.Transition(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		"suspend", runtime.ConnectorTransitionRequest{Reason: "incident"}); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	_, err = g.Dispatch(context.Background(), runtime.ConnectorDispatchRequest{
		TenantID: "tenant-acme", Region: "eu", ConnectorName: "payments", Action: "get_balance",
		ToolID: detail.Connector.ToolID, ToolActionID: "action-balance",
		DecisionID: "dec-1", RunID: "run-1", AgentID: "agent-1", AgentVersionID: "version-1",
	})
	if !errors.Is(err, runtime.ErrConnectorNotActive) {
		t.Fatalf("suspended dispatch must fail closed, got %v", err)
	}

	// Reactivate, then revoke — revoked is terminal.
	if _, err := g.Transition(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		"activate", runtime.ConnectorTransitionRequest{Reason: "resume"}); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if _, err := g.Transition(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		"revoke", runtime.ConnectorTransitionRequest{Reason: "policy violation"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := g.Transition(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		"activate", runtime.ConnectorTransitionRequest{Reason: "un-revoke"}); !errors.Is(err, runtime.ErrConnectorInvalidState) {
		t.Fatalf("revoked connector must be terminal, got %v", err)
	}
	_, err = g.Dispatch(context.Background(), runtime.ConnectorDispatchRequest{
		TenantID: "tenant-acme", Region: "eu", ConnectorName: "payments", Action: "get_balance",
		ToolID: detail.Connector.ToolID, ToolActionID: "action-balance",
		DecisionID: "dec-1", RunID: "run-1", AgentID: "agent-1", AgentVersionID: "version-1",
	})
	if !errors.Is(err, runtime.ErrConnectorRevoked) {
		t.Fatalf("revoked dispatch must fail closed, got %v", err)
	}
}

func TestGatewayDispatchRecordsErrorMetric(t *testing.T) {
	g, _ := gatewayTestHarness(t)
	detail := registerRESTConnector(t, g, "http://127.0.0.1:1")
	req := runtime.ConnectorDispatchRequest{
		TenantID: "tenant-acme", Region: "eu", ConnectorName: "payments", Action: "get_balance",
		ToolID: detail.Connector.ToolID, ToolActionID: "action-balance",
		DecisionID: "dec-1", RunID: "run-1", AgentID: "agent-1", AgentVersionID: "version-1",
	}

	// Draft connectors fail closed before any transport call; the SLO
	// connector-error counter records the closed error code.
	before := testutil.ToFloat64(gwmetrics.ConnectorErrorsTotal.WithLabelValues("tenant-acme", req.ConnectorName, "connector_not_active"))
	if _, err := g.Dispatch(context.Background(), req); !errors.Is(err, runtime.ErrConnectorNotActive) {
		t.Fatalf("draft dispatch must fail closed, got %v", err)
	}
	if got := testutil.ToFloat64(gwmetrics.ConnectorErrorsTotal.WithLabelValues("tenant-acme", req.ConnectorName, "connector_not_active")) - before; got != 1 {
		t.Fatalf("connector errors = %v, want 1 new", got)
	}
}

func TestGatewayDispatchFailClosed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	g, _ := gatewayTestHarness(t)
	detail := registerRESTConnector(t, g, ts.URL)
	if _, err := g.Transition(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		"activate", runtime.ConnectorTransitionRequest{Reason: "go live"}); err != nil {
		t.Fatal(err)
	}
	base := runtime.ConnectorDispatchRequest{
		TenantID: "tenant-acme", Region: "eu", ConnectorName: "payments", Action: "get_balance",
		ToolID: detail.Connector.ToolID, ToolActionID: "action-balance",
		DecisionID: "dec-1", RunID: "run-1", AgentID: "agent-1", AgentVersionID: "version-1",
	}

	// Unknown connector fails closed.
	req := base
	req.ConnectorName = "nope"
	if _, err := g.Dispatch(context.Background(), req); !errors.Is(err, runtime.ErrConnectorUnregistered) {
		t.Fatalf("unknown connector must fail closed, got %v", err)
	}

	// Region mismatch fails closed.
	req = base
	req.Region = "us"
	if _, err := g.Dispatch(context.Background(), req); !errors.Is(err, runtime.ErrConnectorRegion) {
		t.Fatalf("region mismatch must fail closed, got %v", err)
	}

	// Action not in manifest fails closed.
	req = base
	req.Action = "not_in_manifest"
	if _, err := g.Dispatch(context.Background(), req); !errors.Is(err, runtime.ErrConnectorNoManifest) {
		t.Fatalf("unlisted action must fail closed, got %v", err)
	}

	// Agent version not allowed by manifest fails closed. Config
	// changes require a non-active connector: suspend, pin versions,
	// reactivate.
	if _, err := g.Transition(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		"suspend", runtime.ConnectorTransitionRequest{Reason: "maintenance"}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.UpdateConfig(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		runtime.ConnectorRegisterRequest{
			Name: "payments", Type: runtime.ConnectorTypeREST,
			Config: runtime.ConnectorConfig{
				BaseURL: ts.URL, Region: "eu", TimeoutMS: 5000, MaxResponseBytes: 262144,
				TLSVerify: true, AllowedContentTypes: []string{"application/json"},
				RedactionFields: DefaultRedactionFields(),
			},
			Actions: []runtime.ConnectorActionManifest{
				{Name: "get_balance", TransportMethod: "GET", PathTemplate: "/v1/balance",
					Risk: runtime.ConnectorRiskLow, ReadOnly: true, AllowedVersions: []string{"version-2"}},
			},
			Description: "pin versions",
		}); err != nil {
		t.Fatalf("update config: %v", err)
	}
	if _, err := g.Transition(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		"activate", runtime.ConnectorTransitionRequest{Reason: "resume"}); err != nil {
		t.Fatal(err)
	}
	_, err := g.Dispatch(context.Background(), base)
	if !errors.Is(err, runtime.ErrConnectorNotActive) {
		t.Fatalf("disallowed agent version must fail closed, got %v", err)
	}

	// Secret resolution failure fails closed.
	req = base
	req.Action = "get_balance"
	conn, err := g.Get(context.Background(), "tenant-acme", detail.Connector.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Transition(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		"suspend", runtime.ConnectorTransitionRequest{Reason: "maintenance"}); err != nil {
		t.Fatal(err)
	}
	cfg := conn.Config
	cfg.SecretRef = "env://MISSING_TOKEN"
	if _, err := g.UpdateConfig(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		runtime.ConnectorRegisterRequest{
			Name: "payments", Type: runtime.ConnectorTypeREST, Config: cfg,
			Actions: []runtime.ConnectorActionManifest{
				{Name: "get_balance", TransportMethod: "GET", PathTemplate: "/v1/balance",
					Risk: runtime.ConnectorRiskLow, ReadOnly: true},
			},
		}); err != nil {
		t.Fatalf("update config: %v", err)
	}
	if _, err := g.Transition(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		"activate", runtime.ConnectorTransitionRequest{Reason: "resume"}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Dispatch(context.Background(), base); !errors.Is(err, runtime.ErrConnectorUnavailable) {
		t.Fatalf("missing secret must fail closed, got %v", err)
	}
}

func TestGatewayHealthProbe(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	g, _ := gatewayTestHarness(t)
	detail := registerRESTConnector(t, g, ts.URL)
	if _, err := g.Transition(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		"activate", runtime.ConnectorTransitionRequest{Reason: "go live"}); err != nil {
		t.Fatal(err)
	}
	health, err := g.Health(context.Background(), "tenant-acme", detail.Connector.ID)
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if !health.Healthy {
		t.Fatalf("health = %+v", health)
	}

	// Revoked connectors cannot be probed.
	if _, err := g.Transition(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		"revoke", runtime.ConnectorTransitionRequest{Reason: "revoke done"}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Health(context.Background(), "tenant-acme", detail.Connector.ID); !errors.Is(err, runtime.ErrConnectorRevoked) {
		t.Fatalf("revoked health probe must fail, got %v", err)
	}
}

func TestGatewayRegistrationChecks(t *testing.T) {
	g, _ := gatewayTestHarness(t)
	// Non-admin cannot register.
	if _, err := g.Register(context.Background(), "t", "principal:peon", false, runtime.ConnectorRegisterRequest{
		Name: "x", Type: runtime.ConnectorTypeREST,
		Config: runtime.ConnectorConfig{
			BaseURL: "https://api.example.com", Region: "eu", TimeoutMS: 5000,
			MaxResponseBytes: 262144, AllowedContentTypes: []string{"application/json"},
		},
		Actions: []runtime.ConnectorActionManifest{
			{Name: "a", TransportMethod: "GET", PathTemplate: "/a", Risk: runtime.ConnectorRiskLow, ReadOnly: true},
		},
	}); !errors.Is(err, runtime.ErrGovernanceNotAuthorized) {
		t.Fatalf("non-admin register must fail, got %v", err)
	}
	// Name conflict.
	req := runtime.ConnectorRegisterRequest{
		Name: "dup", Type: runtime.ConnectorTypeREST,
		Config: runtime.ConnectorConfig{
			BaseURL: "https://api.example.com", Region: "eu", TimeoutMS: 5000,
			MaxResponseBytes: 262144, AllowedContentTypes: []string{"application/json"},
		},
		Actions: []runtime.ConnectorActionManifest{
			{Name: "a", TransportMethod: "GET", PathTemplate: "/a", Risk: runtime.ConnectorRiskLow, ReadOnly: true},
		},
	}
	if _, err := g.Register(context.Background(), "t", "principal:owner", true, req); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := g.Register(context.Background(), "t", "principal:owner", true, req); !errors.Is(err, runtime.ErrConnectorNameConflict) {
		t.Fatalf("duplicate name must conflict, got %v", err)
	}
	// Region gating.
	g2 := NewGateway(NewMemoryStore(), &fakeSecretResolver{values: map[string]string{}}, func(region string) bool { return region == "eu" })
	if _, err := g2.Register(context.Background(), "t", "principal:owner", true, runtime.ConnectorRegisterRequest{
		Name: "x", Type: runtime.ConnectorTypeREST,
		Config: runtime.ConnectorConfig{
			BaseURL: "https://api.example.com", Region: "us", TimeoutMS: 5000,
			MaxResponseBytes: 262144, AllowedContentTypes: []string{"application/json"},
		},
		Actions: []runtime.ConnectorActionManifest{
			{Name: "a", TransportMethod: "GET", PathTemplate: "/a", Risk: runtime.ConnectorRiskLow, ReadOnly: true},
		},
	}); !errors.Is(err, runtime.ErrConnectorRegion) {
		t.Fatalf("unprovisioned region must fail, got %v", err)
	}
}
