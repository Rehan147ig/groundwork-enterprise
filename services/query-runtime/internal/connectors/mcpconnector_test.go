package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundwork/query-runtime/internal/runtime"
)

func mcpTestConfig(ts *httptest.Server) runtime.ConnectorConfig {
	return runtime.ConnectorConfig{
		BaseURL:             ts.URL,
		TimeoutMS:           5000,
		MaxResponseBytes:    1 << 20,
		TLSVerify:           true,
		AllowedContentTypes: []string{"application/json"},
		RedactionFields:     DefaultRedactionFields(),
	}
}

// fakeMCPServer is a minimal JSON-RPC 2.0 MCP server for tests.
type fakeMCPServer struct {
	initCount   int
	callCount   int
	lastCall    map[string]any
	toolResults map[string]any
}

func newFakeMCPServer() *fakeMCPServer {
	return &fakeMCPServer{toolResults: map[string]any{}}
}

func (f *fakeMCPServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonrpcRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			f.initCount++
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}}`))
		case "ping":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{}}`))
		case "tools/list":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"groundwork_search","description":"s","input_schema":{"type":"object"}}]}}`))
		case "tools/call":
			f.callCount++
			f.lastCall = req.Params
			if res, ok := f.toolResults[req.Method+"-"+callName(req)]; ok {
				b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 4, "result": res})
				_, _ = w.Write(b)
				return
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"hello world"}]}}`))
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":5,"error":{"code":-32601,"message":"method not found"}}`))
		}
	})
}

func callName(req jsonrpcRequest) string {
	name, _ := req.Params["name"].(string)
	return name
}

func TestMCPCallToolHappyPath(t *testing.T) {
	fake := newFakeMCPServer()
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()

	m := NewMCPConnector()
	action := runtime.ConnectorActionManifest{
		Name: "search", TransportMethod: "groundwork_search",
		Risk: runtime.ConnectorRiskMedium, Args: []string{"query"}, MaxRequestBytes: 4096,
	}
	res, err := m.CallTool(context.Background(), mcpTestConfig(ts), action,
		map[string]any{"query": "compensation", "evil": 1}, "Bearer tok", "trace-1")
	if err != nil {
		t.Fatalf("calltool: %v", err)
	}
	if res.Outcome != runtime.InvocationSuccess {
		t.Fatalf("outcome = %+v", res)
	}
	if res.Response != "hello world" {
		t.Fatalf("response = %q", res.Response)
	}
	if fake.initCount != 1 {
		t.Fatalf("init count = %d", fake.initCount)
	}
	if fake.callCount != 1 {
		t.Fatalf("call count = %d", fake.callCount)
	}
	args, _ := fake.lastCall["arguments"].(map[string]any)
	if _, ok := args["evil"]; ok {
		t.Fatal("unallowed argument must be filtered")
	}
	if _, ok := args["query"]; !ok {
		t.Fatal("allowlisted argument must be forwarded")
	}
}

func TestMCPCallToolIsError(t *testing.T) {
	fake := newFakeMCPServer()
	fake.toolResults["tools/call-groundwork_search"] = map[string]any{
		"content": []any{map[string]any{"type": "text", "text": "boom"}},
		"isError": true,
	}
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()

	m := NewMCPConnector()
	action := runtime.ConnectorActionManifest{
		Name: "search", TransportMethod: "groundwork_search",
		Risk: runtime.ConnectorRiskMedium, Args: []string{"query"}, MaxRequestBytes: 4096,
	}
	res, err := m.CallTool(context.Background(), mcpTestConfig(ts), action, map[string]any{"query": "x"}, "", "")
	if err != nil {
		t.Fatalf("calltool: %v", err)
	}
	if res.Outcome != runtime.InvocationFailure || res.ErrorCode != "upstream_tool_error" {
		t.Fatalf("isError must surface as failure, got %+v", res)
	}
}

func TestMCPCallToolSizeBlocked(t *testing.T) {
	fake := newFakeMCPServer()
	fake.toolResults["tools/call-groundwork_search"] = map[string]any{
		"content": []any{map[string]any{"type": "text", "text": strings.Repeat("x", 5000)}},
	}
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()

	cfg := mcpTestConfig(ts)
	cfg.MaxResponseBytes = 1024
	m := NewMCPConnector()
	action := runtime.ConnectorActionManifest{
		Name: "search", TransportMethod: "groundwork_search",
		Risk: runtime.ConnectorRiskMedium, Args: []string{"query"}, MaxRequestBytes: 4096,
	}
	res, err := m.CallTool(context.Background(), cfg, action, map[string]any{"query": "x"}, "", "")
	if err != nil {
		t.Fatalf("calltool: %v", err)
	}
	if res.Outcome != runtime.InvocationResponseBlocked || res.ErrorCode != "response_size_exceeded" {
		t.Fatalf("oversized mcp response must be blocked, got %+v", res)
	}
}

func TestMCPHealth(t *testing.T) {
	fake := newFakeMCPServer()
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()

	m := NewMCPConnector()
	res, err := m.Health(context.Background(), mcpTestConfig(ts), "")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if res.Outcome != runtime.InvocationSuccess {
		t.Fatalf("outcome = %+v", res)
	}
	if fake.initCount != 1 {
		t.Fatalf("health must initialize exactly once, got %d", fake.initCount)
	}
}

func TestMCPListToolsAndDigest(t *testing.T) {
	fake := newFakeMCPServer()
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()

	m := NewMCPConnector()
	tools, err := m.ListTools(context.Background(), mcpTestConfig(ts), "", "")
	if err != nil {
		t.Fatalf("listtools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "groundwork_search" {
		t.Fatalf("tools = %+v", tools)
	}
	d1 := ManifestDigestOfTools(tools)
	rev := []RemoteTool{tools[0], {Name: "other"}}
	d2 := ManifestDigestOfTools(rev)
	if d1 == d2 {
		t.Fatal("digests must differ for different tool sets")
	}
	if !strings.HasPrefix(d1, "sha256:") {
		t.Fatalf("digest = %q", d1)
	}
}

func TestMCPRedactionInCallTool(t *testing.T) {
	fake := newFakeMCPServer()
	fake.toolResults["tools/call-groundwork_search"] = map[string]any{
		"content": []any{map[string]any{"type": "text", "text": "token=abc123xyz"}},
	}
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()

	m := NewMCPConnector()
	action := runtime.ConnectorActionManifest{
		Name: "search", TransportMethod: "groundwork_search",
		Risk: runtime.ConnectorRiskMedium, Args: []string{"query"}, MaxRequestBytes: 4096,
	}
	res, err := m.CallTool(context.Background(), mcpTestConfig(ts), action, map[string]any{"query": "x"}, "", "")
	if err != nil {
		t.Fatalf("calltool: %v", err)
	}
	if strings.Contains(res.Response.(string), "abc123") {
		t.Fatalf("secret must be redacted, got %q", res.Response)
	}
}
