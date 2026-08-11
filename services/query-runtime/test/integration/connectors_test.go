//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundwork/query-runtime/internal/connectors"
	"groundwork/query-runtime/internal/governance"
	"groundwork/query-runtime/internal/runtime"
)

// fakeRESTBackend is a minimal controlled upstream for the connector
// pipeline: it records the Authorization header and returns JSON.
func fakeRESTBackend(t *testing.T, sawAuth *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/balance" {
			*sawAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"balance": 1234, "token": "never-leak-me"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// fakeMCPBackend is a minimal JSON-RPC 2.0 MCP upstream.
func fakeMCPBackend(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		req := string(body[:n])
		switch {
		case strings.Contains(req, "initialize"):
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"int-fake","version":"1"}}}`))
		case strings.Contains(req, "ping"):
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{}}`))
		case strings.Contains(req, "tools/call"):
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"mcpret"}]}}`))
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":4,"error":{"code":-32601,"message":"nope"}}`))
		}
	}))
}

// TestConnectorPostgresLifecycle exercises the real Postgres registry
// (migration 018) end to end: register (draft) -> activate -> dispatch
// through the REST transport against a live httptest upstream -> revoke
// -> dispatch fails closed, with invocation evidence persisted and
// visible in the governance evidence union.
func TestConnectorPostgresLifecycle(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)

	var sawAuth string
	backend := fakeRESTBackend(t, &sawAuth)
	defer backend.Close()
	// env://PAYMENTS_TOKEN resolves verbatim (see KeyringSecretResolver).
	t.Setenv("PAYMENTS_TOKEN", "Bearer integration-secret")

	tenant := "tenant_connector_" + unique()
	ctx := context.Background()

	store := connectors.NewPostgresStore(db)
	gateway := connectors.NewGateway(store, connectors.NewKeyringSecretResolver(nil), nil)

	detail, err := gateway.Register(ctx, tenant, "principal:owner", true, runtime.ConnectorRegisterRequest{
		Name: "payments",
		Type: runtime.ConnectorTypeREST,
		Config: runtime.ConnectorConfig{
			BaseURL:             backend.URL,
			Region:              testRegion,
			TimeoutMS:           5000,
			RetryMax:            1,
			RetryIdempotentOnly: true,
			MaxResponseBytes:    262144,
			TLSVerify:           true,
			SecretRef:           "env://PAYMENTS_TOKEN",
			AllowedContentTypes: []string{"application/json"},
			RedactionFields:     []string{"token"},
		},
		Actions: []runtime.ConnectorActionManifest{
			{Name: "get_balance", TransportMethod: "GET", PathTemplate: "/v1/balance",
				Risk: runtime.ConnectorRiskLow, ReadOnly: true, Args: []string{"account"}},
		},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if detail.Connector.Lifecycle != runtime.ConnectorLifecycleDraft {
		t.Fatalf("expected draft, got %s", detail.Connector.Lifecycle)
	}
	if detail.Connector.ManifestDigest == "" {
		t.Fatal("manifest digest missing")
	}

	// Re-read through a FRESH store handle: persisted state must
	// round-trip (columns, JSON arrays, version rows).
	gateway2 := connectors.NewGateway(connectors.NewPostgresStore(db), connectors.NewKeyringSecretResolver(nil), nil)
	got, err := gateway2.Get(ctx, tenant, detail.Connector.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Actions) != 1 || got.Config.BaseURL != backend.URL {
		t.Fatalf("re-read mismatch: %+v / %+v", got.Actions, got.Config)
	}
	if len(got.LifecycleEvents) != 1 {
		t.Fatalf("expected 1 lifecycle event after create, got %d", len(got.LifecycleEvents))
	}

	if _, err := gateway.Transition(ctx, tenant, detail.Connector.ID, "principal:owner", true,
		"activate", runtime.ConnectorTransitionRequest{Reason: "go live"}); err != nil {
		t.Fatalf("activate: %v", err)
	}

	req := runtime.ConnectorDispatchRequest{
		TenantID: tenant, Region: testRegion, ConnectorName: "payments",
		ToolID: detail.Connector.ToolID, ToolActionID: "action-balance",
		DecisionID: "dec-int-1", RunID: "run-int-1", AgentID: "agent-int-1",
		AgentVersionID: "version-int-1", Action: "get_balance", Arguments: map[string]any{"account": "42"},
		TraceID: "trace-int-1",
	}
	res, err := gateway.Dispatch(ctx, req)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if res.Outcome != runtime.InvocationSuccess {
		t.Fatalf("outcome = %+v", res)
	}
	if res.ConnectorID != detail.Connector.ID {
		t.Fatalf("connector id = %q", res.ConnectorID)
	}
	if sawAuth != "Bearer integration-secret" {
		t.Fatalf("upstream auth = %q", sawAuth)
	}
	if strings.Contains(fmt.Sprintf("%v", res.Response), "never-leak-me") {
		t.Fatalf("secret must be redacted from the response: %v", res.Response)
	}

	// Invocation evidence through the real Postgres governance store
	// (recorded via Transact, the same path the service uses). ToolID /
	// ToolActionID / RunID are FK-bound to real UUID rows in production;
	// these smoke rows have no backing rows, so they map to NULL.
	govStore := governance.NewPostgresStore(db)
	inv := runtime.ConnectorInvocation{
		TenantID: tenant, ConnectorID: res.ConnectorID,
		DecisionID: "dec-int-1",
		Kind:       runtime.InvocationKindAgentAction, Outcome: res.Outcome,
		StatusCode: 200, DurationMS: 5, ResponseBytes: 64,
		Region: testRegion, TraceID: "trace-int-1", OccurredAt: time.Now().UTC(),
	}
	if err := govStore.Transact(ctx, "connector:dec-int-1", func(tx governance.TxStore) error {
		_, err := tx.AppendConnectorInvocation(ctx, inv)
		return err
	}); err != nil {
		t.Fatalf("record invocation: %v", err)
	}
	events, err := govStore.QueryEvidence(ctx, tenant, runtime.EvidenceFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list evidence: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Kind == runtime.EvidenceKindConnectorInvocation && e.EntityID == detail.Connector.ID {
			found = true
			if e.TraceID != "trace-int-1" || e.ImmutableDigest == "" {
				t.Fatalf("evidence event = %+v", e)
			}
		}
	}
	if !found {
		t.Fatalf("connector_invocation evidence not in the union; events=%d", len(events))
	}
	invs, err := govStore.ListConnectorInvocations(ctx, tenant, detail.Connector.ID, 10)
	if err != nil {
		t.Fatalf("list invocations: %v", err)
	}
	if len(invs) != 1 || invs[0].Outcome != runtime.InvocationSuccess || invs[0].TraceID != "trace-int-1" {
		t.Fatalf("invocations = %+v", invs)
	}

	// Revoke, then dispatch fails closed BEFORE any connection opens.
	if _, err := gateway.Transition(ctx, tenant, detail.Connector.ID, "principal:owner", true,
		"revoke", runtime.ConnectorTransitionRequest{Reason: "integration smoke"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err = gateway.Dispatch(ctx, req)
	if !errors.Is(err, runtime.ErrConnectorRevoked) {
		t.Fatalf("revoked dispatch must fail closed, got %v", err)
	}
	if _, err := gateway.Transition(ctx, tenant, detail.Connector.ID, "principal:owner", true,
		"activate", runtime.ConnectorTransitionRequest{Reason: "no"}); !errors.Is(err, runtime.ErrConnectorInvalidState) {
		t.Fatalf("revoked must be terminal, got %v", err)
	}

	// Lifecycle chain persisted and verifiable.
	got, err = gateway.Get(ctx, tenant, detail.Connector.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.LifecycleEvents) != 3 { // create, activate, revoke
		t.Fatalf("expected 3 lifecycle events, got %d", len(got.LifecycleEvents))
	}
	if got.Connector.Lifecycle != runtime.ConnectorLifecycleRevoked {
		t.Fatalf("lifecycle = %s", got.Connector.Lifecycle)
	}
	for i, ev := range got.LifecycleEvents {
		if ev.ImmutableDigest == "" {
			t.Fatalf("event %d has no digest", i)
		}
		if i > 0 && ev.ImmutableDigest == got.LifecycleEvents[i-1].ImmutableDigest {
			t.Fatalf("chain digests must differ (event %d)", i)
		}
	}
}

// TestConnectorMCPPostgresDispatch drives the MCP transport through the
// real Postgres registry: initialize + tools/call against a fake JSON-
// RPC server, evidence recorded, then suspend fails closed.
func TestConnectorMCPPostgresDispatch(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)

	backend := fakeMCPBackend(t)
	defer backend.Close()

	tenant := "tenant_connector_mcp_" + unique()
	ctx := context.Background()

	gateway := connectors.NewGateway(connectors.NewPostgresStore(db), connectors.NewKeyringSecretResolver(nil), nil)
	detail, err := gateway.Register(ctx, tenant, "principal:owner", true, runtime.ConnectorRegisterRequest{
		Name: "crm",
		Type: runtime.ConnectorTypeMCP,
		Config: runtime.ConnectorConfig{
			BaseURL:             backend.URL,
			Region:              testRegion,
			TimeoutMS:           5000,
			MaxResponseBytes:    1 << 20,
			TLSVerify:           true,
			AllowedContentTypes: []string{"application/json"},
			RedactionFields:     []string{"token"},
		},
		Actions: []runtime.ConnectorActionManifest{
			{Name: "sync", TransportMethod: "crm_sync", Risk: runtime.ConnectorRiskMedium, Args: []string{"batch"}},
		},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := gateway.Transition(ctx, tenant, detail.Connector.ID, "principal:owner", true,
		"activate", runtime.ConnectorTransitionRequest{Reason: "go live"}); err != nil {
		t.Fatal(err)
	}
	res, err := gateway.Dispatch(ctx, runtime.ConnectorDispatchRequest{
		TenantID: tenant, Region: testRegion, ConnectorName: "crm",
		ToolID: detail.Connector.ToolID, ToolActionID: "action-sync",
		DecisionID: "dec-int-2", RunID: "run-int-2", AgentID: "agent-int-1",
		AgentVersionID: "version-int-1", Action: "sync", Arguments: map[string]any{"batch": "b1"},
		TraceID: "trace-int-2",
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if res.Outcome != runtime.InvocationSuccess || res.Response != "mcpret" {
		t.Fatalf("outcome = %+v / %v", res.Outcome, res.Response)
	}
	if res.ConnectorID != detail.Connector.ID {
		t.Fatalf("connector id = %q", res.ConnectorID)
	}

	// Health probe round-trip (initialize + ping), credential-free.
	health, err := gateway.Health(ctx, tenant, detail.Connector.ID)
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if !health.Healthy {
		t.Fatalf("health = %+v", health)
	}
	if health.LatencyMS < 0 || health.CheckedAt.IsZero() {
		t.Fatalf("health timings = %+v", health)
	}

	// Suspend fails closed with the invocation evidence intact.
	if _, err := gateway.Transition(ctx, tenant, detail.Connector.ID, "principal:owner", true,
		"suspend", runtime.ConnectorTransitionRequest{Reason: "freeze"}); err != nil {
		t.Fatal(err)
	}
	_, err = gateway.Dispatch(ctx, runtime.ConnectorDispatchRequest{
		TenantID: tenant, Region: testRegion, ConnectorName: "crm",
		ToolID: detail.Connector.ToolID, ToolActionID: "action-sync",
		DecisionID: "dec-int-3", RunID: "run-int-3", AgentID: "agent-int-1",
		AgentVersionID: "version-int-1", Action: "sync",
	})
	if !errors.Is(err, runtime.ErrConnectorNotActive) {
		t.Fatalf("suspended dispatch must fail closed, got %v", err)
	}
	if _, err := gateway.Health(ctx, tenant, detail.Connector.ID); err != nil {
		t.Fatalf("suspended connector should still probe: %v", err)
	}
}

// TestConnectorEvidenceLifecycleUnion asserts BOTH connector evidence
// branches (invocation + lifecycle) surface through the real Postgres
// evidence union, and that connector_invocation rows are idempotency-
// protected per decision id.
func TestConnectorEvidenceLifecycleUnion(t *testing.T) {
	requireIntegration(t)
	db := openDB(t)

	tenant := "tenant_connector_verify_" + unique()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	backend := fakeRESTBackend(t, new(string))
	defer backend.Close()

	gateway := connectors.NewGateway(connectors.NewPostgresStore(db), connectors.NewKeyringSecretResolver(nil), nil)
	detail, err := gateway.Register(ctx, tenant, "principal:owner", true, runtime.ConnectorRegisterRequest{
		Name: "verify-src",
		Type: runtime.ConnectorTypeREST,
		Config: runtime.ConnectorConfig{
			BaseURL: backend.URL, Region: testRegion, TimeoutMS: 5000, MaxResponseBytes: 262144,
			TLSVerify: true, AllowedContentTypes: []string{"application/json"},
			RedactionFields: []string{"token"},
		},
		Actions: []runtime.ConnectorActionManifest{
			{Name: "get_balance", TransportMethod: "GET", PathTemplate: "/v1/balance", Risk: runtime.ConnectorRiskLow, ReadOnly: true},
		},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := gateway.Transition(ctx, tenant, detail.Connector.ID, "principal:owner", true,
		"activate", runtime.ConnectorTransitionRequest{Reason: "go live"}); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.Dispatch(ctx, runtime.ConnectorDispatchRequest{
		TenantID: tenant, Region: testRegion, ConnectorName: "verify-src",
		ToolID: detail.Connector.ToolID, ToolActionID: "action-balance",
		DecisionID: "dec-verify", RunID: "run-verify", AgentID: "agent-int-1",
		AgentVersionID: "version-int-1", Action: "get_balance",
	}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	govStore := governance.NewPostgresStore(db)
	// FK-bound columns stay NULL here (see TestConnectorPostgresLifecycle).
	inv := runtime.ConnectorInvocation{
		TenantID: tenant, ConnectorID: detail.Connector.ID,
		DecisionID: "dec-verify",
		Kind:       runtime.InvocationKindAgentAction, Outcome: runtime.InvocationSuccess,
		StatusCode: 200, DurationMS: 10, ResponseBytes: 64, Region: testRegion,
		OccurredAt: time.Now().UTC(),
	}
	err = govStore.Transact(ctx, "connector:dec-verify", func(tx governance.TxStore) error {
		_, err := tx.AppendConnectorInvocation(ctx, inv)
		return err
	})
	if err != nil {
		t.Fatalf("record invocation: %v", err)
	}
	// Duplicate decision id must be an idempotency conflict (the unique
	// (tenant_id, decision_id) constraint).
	err = govStore.Transact(ctx, "connector:dec-verify", func(tx governance.TxStore) error {
		_, err := tx.AppendConnectorInvocation(ctx, inv)
		return err
	})
	if err == nil {
		t.Fatal("duplicate decision_id must be rejected")
	}

	events, err := govStore.QueryEvidence(ctx, tenant, runtime.EvidenceFilter{Limit: 50})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	var invocation, lifecycle bool
	for _, e := range events {
		switch e.Kind {
		case runtime.EvidenceKindConnectorInvocation:
			if e.EntityID == detail.Connector.ID && e.ImmutableDigest != "" {
				invocation = true
			}
		case runtime.EvidenceKindConnectorLifecycle:
			if e.EntityID == detail.Connector.ID && e.ImmutableDigest != "" {
				lifecycle = true
			}
		}
	}
	if !invocation || !lifecycle {
		t.Fatalf("expected both evidence branches, got invocation=%v lifecycle=%v (events=%d)",
			invocation, lifecycle, len(events))
	}
}
