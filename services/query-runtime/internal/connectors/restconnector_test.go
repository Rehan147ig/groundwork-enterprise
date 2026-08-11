package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundwork/query-runtime/internal/runtime"
)

func restTestConfig(ts *httptest.Server) runtime.ConnectorConfig {
	return runtime.ConnectorConfig{
		BaseURL:             ts.URL,
		TimeoutMS:           5000,
		MaxResponseBytes:    1 << 20,
		TLSVerify:           true,
		AllowedContentTypes: []string{"application/json"},
		RedactionFields:     DefaultRedactionFields(),
	}
}

func TestRESTDispatchHappyPath(t *testing.T) {
	var gotPath, gotAuth, gotTrace, gotIdem string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotTrace = r.Header.Get("X-Groundwork-Trace")
		gotIdem = r.Header.Get("Idempotency-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"balance": 42, "token": "super-secret-value"}`))
	}))
	defer ts.Close()

	c := NewRESTConnector(nil)
	action := runtime.ConnectorActionManifest{
		Name: "balance", TransportMethod: "GET", PathTemplate: "/v1/accounts/{id}",
		Risk: runtime.ConnectorRiskLow, ReadOnly: true, Args: []string{"id"},
	}
	res, err := c.Dispatch(context.Background(), restTestConfig(ts), action,
		map[string]any{"id": "acc-1", "dropped": "x"}, "Bearer secret-token", "trace-123", "dedup-key-1")
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if gotPath != "/v1/accounts/acc-1" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotTrace != "trace-123" {
		t.Errorf("trace = %q", gotTrace)
	}
	// Phase 8.2: the semantic idempotency key is forwarded so the
	// upstream can dedupe the crash window before evidence is recorded.
	if gotIdem != "dedup-key-1" {
		t.Errorf("idempotency key header = %q", gotIdem)
	}
	if res.Outcome != runtime.InvocationSuccess {
		t.Fatalf("outcome = %s", res.Outcome)
	}
	body, _ := json.Marshal(res.Response)
	s := string(body)
	if s == "" {
		t.Fatal("no response")
	}
	if len(s) >= len(`{"balance": 42, "token": "super-secret-value"}`) {
		t.Fatal("response must be redacted/decoded")
	}
}

func TestRESTDispatchRedirectRejected(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer ts.Close()

	c := NewRESTConnector(nil)
	action := runtime.ConnectorActionManifest{
		Name: "ping", TransportMethod: "GET", PathTemplate: "/ping",
		Risk: runtime.ConnectorRiskLow, ReadOnly: true,
	}
	res, err := c.Dispatch(context.Background(), restTestConfig(ts), action, nil, "", "", "")
	if res.Outcome != runtime.InvocationFailure {
		t.Fatalf("redirect must fail closed, got %+v", res)
	}
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect rejection error, got %v", err)
	}
}

func TestRESTDispatchResponseSizeBlocked(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		big := make([]byte, 4096)
		for i := range big {
			big[i] = 'a'
		}
		_, _ = w.Write([]byte(`"` + string(big) + `"`))
	}))
	defer ts.Close()

	cfg := restTestConfig(ts)
	cfg.MaxResponseBytes = 1024
	c := NewRESTConnector(nil)
	action := runtime.ConnectorActionManifest{
		Name: "big", TransportMethod: "GET", PathTemplate: "/big",
		Risk: runtime.ConnectorRiskLow, ReadOnly: true,
	}
	res, err := c.Dispatch(context.Background(), cfg, action, nil, "", "", "")
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if res.Outcome != runtime.InvocationResponseBlocked {
		t.Fatalf("oversized response must be blocked, got %+v", res)
	}
	if res.ErrorCode != "response_size_exceeded" {
		t.Errorf("error code = %q", res.ErrorCode)
	}
}

func TestRESTDispatchContentTypeBlocked(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>phish</html>"))
	}))
	defer ts.Close()

	c := NewRESTConnector(nil)
	action := runtime.ConnectorActionManifest{
		Name: "html", TransportMethod: "GET", PathTemplate: "/page",
		Risk: runtime.ConnectorRiskLow, ReadOnly: true,
	}
	res, err := c.Dispatch(context.Background(), restTestConfig(ts), action, nil, "", "", "")
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if res.Outcome != runtime.InvocationResponseBlocked {
		t.Fatalf("disallowed content type must be blocked, got %+v", res)
	}
	if res.ErrorCode != "content_type_blocked" {
		t.Errorf("error code = %q", res.ErrorCode)
	}
}

func TestRESTDispatchNoRetryOnWrite(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := restTestConfig(ts)
	cfg.RetryMax = 3
	cfg.RetryIdempotentOnly = true
	c := NewRESTConnector(nil)
	action := runtime.ConnectorActionManifest{
		Name: "write", TransportMethod: "POST", PathTemplate: "/write",
		Risk: runtime.ConnectorRiskCritical, MaxRequestBytes: 1024,
	}
	_, err := c.Dispatch(context.Background(), cfg, action, map[string]any{"x": 1}, "", "", "")
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("write action retried: attempts = %d", attempts)
	}
}

func TestRESTDispatchRetryOnNetworkError(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	cfg := restTestConfig(ts)
	cfg.TimeoutMS = 30000 // matches NewRESTConnector's default so the same client is used
	cfg.RetryMax = 3
	cfg.RetryIdempotentOnly = true
	c := NewRESTConnector(nil)
	// Force the first attempt through a transport that returns a
	// network-level error, then fall back to the real server.
	c.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return nil, fmt.Errorf("connection refused")
		}
		return http.DefaultTransport.RoundTrip(req)
	})
	action := runtime.ConnectorActionManifest{
		Name: "ping", TransportMethod: "GET", PathTemplate: "/ping",
		Risk: runtime.ConnectorRiskLow, ReadOnly: true,
	}
	res, err := c.Dispatch(context.Background(), cfg, action, nil, "", "", "")
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if res.Outcome != runtime.InvocationSuccess {
		t.Fatalf("expected success after retry, got %+v", res)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestRESTHealthCredentialFree(t *testing.T) {
	var auth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := NewRESTConnector(nil)
	res, err := c.Health(context.Background(), restTestConfig(ts))
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if res.Outcome != runtime.InvocationSuccess {
		t.Fatalf("outcome = %+v", res)
	}
	if auth != "" {
		t.Fatalf("health probe must be credential-free, got auth %q", auth)
	}
}
