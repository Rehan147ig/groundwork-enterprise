// Phase 8.2 dispatch circuit: a dead connector opens its circuit after
// 3 consecutive failures and dispatches fail fast with
// connector_breaker_open evidence instead of burning the connector's
// timeout + retry budget. Only transport errors and 5xx responses trip
// the circuit; config/lifecycle preflight failures happen before it and
// never count against it. Circuits are per (tenant, connector).

package connectors

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	gwmetrics "groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/runtime"
)

func dispatchRequest(connectorName string) runtime.ConnectorDispatchRequest {
	return runtime.ConnectorDispatchRequest{
		TenantID: "tenant-acme", Region: "eu", ConnectorName: connectorName,
		Action: "get_balance", ToolID: "tool", ToolActionID: "action",
		DecisionID: "dec-1", RunID: "run-1", AgentID: "agent-1", AgentVersionID: "version-1",
	}
}

// activateConnector registers + activates a REST connector on tsURL
// under the given name and returns its detail.
func activateConnector(t *testing.T, g *Gateway, name, tsURL string) runtime.ConnectorDetail {
	t.Helper()
	detail, err := g.Register(context.Background(), "tenant-acme", "principal:owner", true, runtime.ConnectorRegisterRequest{
		Name: name,
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
		},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	conn, err := g.Transition(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		"activate", runtime.ConnectorTransitionRequest{Reason: "go live"})
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if conn.Lifecycle != runtime.ConnectorLifecycleActive {
		t.Fatalf("lifecycle = %s", conn.Lifecycle)
	}
	return detail
}

func breakerGateway(t *testing.T) (*Gateway, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	t.Cleanup(ts.Close)
	g, _ := gatewayTestHarness(t)
	g.SetDispatchBreakerSettings(runtime.CircuitBreakerSettings{
		Name: "connector_dispatch", FailureLimit: 3, OpenTimeout: time.Hour, HalfOpenLimit: 1,
	})
	return g, ts
}

func TestGatewayBreakerFailsFastWhenOpen(t *testing.T) {
	g, ts := breakerGateway(t)
	detail := activateConnector(t, g, "payments", ts.URL)
	connID := detail.Connector.ID

	var refused uint32
	for i := 0; i < 6; i++ {
		res, err := g.Dispatch(context.Background(), dispatchRequest("payments"))
		if res.Outcome == runtime.InvocationSuccess {
			t.Fatalf("dispatch %d must fail closed, got res=%+v err=%v", i, res, err)
		}
		if res.ErrorCode == "connector_breaker_open" {
			refused++
		}
	}
	// 3 real attempts (each paying the 5xx) + 3 fail-fast refusals.
	if got := refused; got != 3 {
		t.Fatalf("breaker-open refusals = %d, want 3 (attempts 4-6)", got)
	}
	if state := testutil.ToFloat64(gwmetrics.ConnectorBreakerState.WithLabelValues("tenant-acme", connID)); state != 2 {
		t.Fatalf("breaker state = %v, want 2 (open)", state)
	}
	if tps := testutil.ToFloat64(gwmetrics.ConnectorBreakerTripsTotal.WithLabelValues("tenant-acme", connID)); tps != 1 {
		t.Fatalf("trip counter = %v, want 1", tps)
	}
}

func TestGatewayBreakerProbeClosesOnRecovery(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if hits.Load() <= 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	g, _ := gatewayTestHarness(t)
	g.SetDispatchBreakerSettings(runtime.CircuitBreakerSettings{
		Name: "connector_dispatch", FailureLimit: 3, OpenTimeout: 50 * time.Millisecond, HalfOpenLimit: 1,
	})
	detail := activateConnector(t, g, "payments", ts.URL)
	connID := detail.Connector.ID

	for i := 0; i < 3; i++ {
		if res, _ := g.Dispatch(context.Background(), dispatchRequest("payments")); res.Outcome == runtime.InvocationSuccess {
			t.Fatalf("dispatch %d must fail while endpoint is down", i)
		}
	}
	// Open: fail fast, endpoint untouched.
	if res, _ := g.Dispatch(context.Background(), dispatchRequest("payments")); res.ErrorCode != "connector_breaker_open" {
		t.Fatalf("dispatch while open must fail fast, got %+v", res)
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("hits while open = %d, want 3", got)
	}

	// Probe after the open timeout: endpoint recovered -> circuit closes.
	time.Sleep(70 * time.Millisecond)
	res, err := g.Dispatch(context.Background(), dispatchRequest("payments"))
	if err != nil || res.Outcome != runtime.InvocationSuccess {
		t.Fatalf("probe dispatch must succeed, got res=%+v err=%v", res, err)
	}
	state := testutil.ToFloat64(gwmetrics.ConnectorBreakerState.WithLabelValues("tenant-acme", connID))
	if state != 0 {
		t.Fatalf("breaker state after recovery = %v, want 0 (closed)", state)
	}
}

func TestGatewayBreakerIsPerConnector(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer good.Close()

	g, dead := breakerGateway(t)
	activateConnector(t, g, "payments", dead.URL)
	activateConnector(t, g, "treasury", good.URL)

	// Kill the payments circuit.
	for i := 0; i < 3; i++ {
		if res, _ := g.Dispatch(context.Background(), dispatchRequest("payments")); res.Outcome == runtime.InvocationSuccess {
			t.Fatalf("payments dispatch %d must fail", i)
		}
	}
	// The treasury connector's circuit is untouched: it must keep working.
	for i := 0; i < 2; i++ {
		res, err := g.Dispatch(context.Background(), dispatchRequest("treasury"))
		if err != nil || res.Outcome != runtime.InvocationSuccess {
			t.Fatalf("treasury dispatch %d must succeed while payments is blacked out, got %+v %v", i, res, err)
		}
	}
}

func TestGatewayBreakerPreflightStillRunsWhenOpen(t *testing.T) {
	g, ts := breakerGateway(t)
	detail := activateConnector(t, g, "payments", ts.URL)

	for i := 0; i < 3; i++ {
		if res, _ := g.Dispatch(context.Background(), dispatchRequest("payments")); res.Outcome == runtime.InvocationSuccess {
			t.Fatalf("dispatch %d must fail", i)
		}
	}
	// Circuit is open, but a revocation is preflight state, not endpoint
	// health: it must still fail closed with the lifecycle error.
	_, err := g.Transition(context.Background(), "tenant-acme", detail.Connector.ID, "principal:owner", true,
		"revoke", runtime.ConnectorTransitionRequest{Reason: "bad actor"})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err = g.Dispatch(context.Background(), dispatchRequest("payments"))
	if !errors.Is(err, runtime.ErrConnectorRevoked) {
		t.Fatalf("revoked dispatch must report connector_revoked even with the circuit open, got %v", err)
	}
}
