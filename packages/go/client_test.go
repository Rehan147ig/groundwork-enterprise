package sdk

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stubServer returns an httptest server whose handler records the last
// request and replies with the given status/body. It mirrors the TS
// stubFetch helper.
func stubServer(status int, body string) (*httptest.Server, func() *http.Request) {
	var last *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = r
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	return srv, func() *http.Request { return last }
}

func headerGet(t *testing.T, last func() *http.Request, key string) string {
	t.Helper()
	r := last()
	if r == nil {
		t.Fatalf("no request recorded")
	}
	return r.Header.Get(key)
}

func TestSendsAPIKeyHeaderAndParsesAgentsListWithCount(t *testing.T) {
	srv, last := stubServer(200, `{"agents":[],"count":0}`)
	defer srv.Close()

	client := NewClient(ClientOptions{BaseURL: srv.URL, APIKey: "gw_test_key"})
	list, err := client.ListAgents(context.Background(), "", "")
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if list.Count != 0 || len(list.Agents) != 0 {
		t.Fatalf("unexpected list: %+v", list)
	}
	if got := headerGet(t, last, "X-Groundwork-API-Key"); got != "gw_test_key" {
		t.Fatalf("api key header = %q", got)
	}
}

func TestSendsUserAssertionWhenProvidedAsProvider(t *testing.T) {
	srv, last := stubServer(201, `{"agent":{}}`)
	defer srv.Close()

	client := NewClient(ClientOptions{
		BaseURL:  srv.URL,
		APIKey:   "gw_test_key",
		Provider: func() (string, error) { return "assertion-token-123", nil },
	})
	if _, err := client.CreateAgent(context.Background(), CreateAgentRequest{
		Name: "research-agent", BusinessPurpose: "read-only research",
	}); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if got := headerGet(t, last, "X-Groundwork-User-Assertion"); got != "assertion-token-123" {
		t.Fatalf("assertion header = %q", got)
	}
	if got := headerGet(t, last, "Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}
}

func TestPostsJSONBodyWithQueryEndpoint(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answer":"ok","trace_id":"t1"}`))
	}))
	defer srv.Close()

	client := NewClient(ClientOptions{BaseURL: srv.URL, APIKey: "gw_test_key"})
	topK := 3
	if _, err := client.Query(context.Background(), QueryRequest{Query: "summarize incidents", TopK: &topK}); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got["query"] != "summarize incidents" || got["top_k"] != float64(3) {
		t.Fatalf("body = %v", got)
	}
}

func TestErrorEnvelopeSurfacesCodeAndStatus(t *testing.T) {
	srv, _ := stubServer(503, `{"error":"audit_unavailable"}`)
	defer srv.Close()

	client := NewClient(ClientOptions{BaseURL: srv.URL, APIKey: "gw_test_key"})
	_, err := client.Audit(context.Background(), AuditFilters{Limit: 10})
	var gwErr *GroundworkError
	if !errors.As(err, &gwErr) {
		t.Fatalf("expected GroundworkError, got %T: %v", err, err)
	}
	if gwErr.Code != "audit_unavailable" || gwErr.Status != 503 {
		t.Fatalf("code/status = %q/%d", gwErr.Code, gwErr.Status)
	}
}

func TestNetworkFailureWrapsIntoGroundworkError(t *testing.T) {
	// Reserved-but-closed port: deterministic connection refusal.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	client := NewClient(ClientOptions{BaseURL: "http://" + addr, APIKey: "gw_test_key", Timeout: time.Second})
	_, err = client.Health(context.Background())
	var gwErr *GroundworkError
	if !errors.As(err, &gwErr) {
		t.Fatalf("expected GroundworkError, got %T: %v", err, err)
	}
	if gwErr.Code != "network" || gwErr.Status != 0 {
		t.Fatalf("code/status = %q/%d", gwErr.Code, gwErr.Status)
	}
}

func TestTrailingSlashOnBaseURLIsNormalized(t *testing.T) {
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"query-runtime"}`))
	}))
	defer srv.Close()

	client := NewClient(ClientOptions{BaseURL: srv.URL + "/", APIKey: "gw_test_key"})
	if _, err := client.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if seenPath != "/healthz" {
		t.Fatalf("path = %q", seenPath)
	}
}

func TestMintUserAssertionProducesVerifiableHS256JWT(t *testing.T) {
	secret := "test-secret-at-least-32-chars-long!!"
	token, err := MintUserAssertion(secret, "user-1", "tenant-acme", nil, 0)
	if err != nil {
		t.Fatalf("MintUserAssertion: %v", err)
	}
	header, payload, signature, ok := splitAssertionParts(token)
	if !ok {
		t.Fatalf("token has three parts")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(header + "." + payload)); err != nil {
		t.Fatal(err)
	}
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if signature != expected {
		t.Fatalf("signature mismatch: %q != %q", signature, expected)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims["sub"] != "user-1" || claims["tenant_id"] != "tenant-acme" {
		t.Fatalf("claims = %v", claims)
	}
	if exp, ok := claims["exp"].(float64); !ok || exp <= float64(time.Now().Unix()) {
		t.Fatalf("exp = %v", claims["exp"])
	}
	if strings.TrimSpace(token) != token || len(token) < 30 {
		t.Fatalf("token too short: %q", token)
	}
}

func TestUsageMethodsHitTheUsageEndpoints(t *testing.T) {
	type call struct {
		method, path string
		body         map[string]any
		key          string
	}
	var calls []call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := call{method: r.Method, path: r.URL.Path, key: r.Header.Get("Idempotency-Key")}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&c.body)
		}
		calls = append(calls, c)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"tenant_id":"tenant-acme","limits":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"tenant_id":"tenant-acme","limits":[{"metric":"runs","period":"monthly","limit":1000}]}`))
	}))
	defer srv.Close()

	client := NewClient(ClientOptions{BaseURL: srv.URL, APIKey: "gw_test_key"})
	ctx := context.Background()

	if _, err := client.GetUsage(ctx); err != nil {
		t.Fatalf("GetUsage: %v", err)
	}
	if _, err := client.GetUsageLimits(ctx); err != nil {
		t.Fatalf("GetUsageLimits: %v", err)
	}
	if _, err := client.PutUsageLimits(ctx, PutUsageLimitsRequest{
		Limits: []UsageLimit{{Metric: "runs", Period: "monthly", Limit: 1000}},
	}, "idem-usage-1"); err != nil {
		t.Fatalf("PutUsageLimits: %v", err)
	}

	if calls[0].method != http.MethodGet || calls[0].path != "/v1/usage" {
		t.Fatalf("call0 = %v", calls[0])
	}
	if calls[1].method != http.MethodGet || calls[1].path != "/v1/usage/limits" {
		t.Fatalf("call1 = %v", calls[1])
	}
	if calls[2].method != http.MethodPut || calls[2].path != "/v1/usage/limits" {
		t.Fatalf("call2 = %v", calls[2])
	}
	if calls[2].key != "idem-usage-1" {
		t.Fatalf("idempotency key = %q", calls[2].key)
	}
	limits, ok := calls[2].body["limits"].([]any)
	if !ok || len(limits) != 1 {
		t.Fatalf("body limits = %v", calls[2].body)
	}
}
