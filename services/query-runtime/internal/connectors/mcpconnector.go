package connectors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// MCPConnector is the production MCP gateway for EXTERNAL MCP servers.
// It speaks JSON-RPC 2.0 over HTTPS (streamable-HTTP style) to the
// remote server and enforces the same pipeline as REST: authorization
// happens BEFORE tools/call; the remote server URL is operator-supplied
// (never from the agent); responses are size-limited and redacted.
type MCPConnector struct {
	client *http.Client
	redact Redaction
}

// NewMCPConnector builds the gateway transport.
func NewMCPConnector() *MCPConnector {
	return &MCPConnector{client: &http.Client{Timeout: 30 * time.Second}}
}

// RemoteTool is one tool discovered from the remote server's tools/list.
type RemoteTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

// ManifestDigestOfTools hashes the sorted remote tool set — the
// discovered manifest digest the console shows and operators pin.
func ManifestDigestOfTools(tools []RemoteTool) string {
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	b, _ := json.Marshal(tools)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ListTools performs an authorized discovery probe (read-only).
func (m *MCPConnector) ListTools(ctx context.Context, cfg runtime.ConnectorConfig, authHeader, traceID string) ([]RemoteTool, error) {
	var result jsonrpcResult
	if err := m.call(ctx, cfg, authHeader, traceID, "tools/list", map[string]any{}, &result); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Tools []RemoteTool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("%w: malformed tools/list result", runtime.ErrConnectorInvalidConfig)
	}
	if len(parsed.Tools) == 0 {
		return nil, fmt.Errorf("%w: remote server advertised no tools", runtime.ErrConnectorNoManifest)
	}
	return parsed.Tools, nil
}

// Health performs initialize + ping against the remote server.
func (m *MCPConnector) Health(ctx context.Context, cfg runtime.ConnectorConfig, authHeader string) (runtime.ConnectorDispatchResult, error) {
	start := time.Now()
	if err := m.initialize(ctx, cfg, authHeader); err != nil {
		return runtime.ConnectorDispatchResult{
			Outcome: runtime.InvocationFailure, ErrorCode: "mcp_initialize_failed",
			DurationMS: time.Since(start).Milliseconds(),
		}, nil
	}
	var result jsonrpcResult
	if err := m.call(ctx, cfg, authHeader, "", "ping", map[string]any{}, &result); err != nil {
		return runtime.ConnectorDispatchResult{
			Outcome: runtime.InvocationFailure, ErrorCode: "mcp_ping_failed",
			DurationMS: time.Since(start).Milliseconds(),
		}, nil
	}
	return runtime.ConnectorDispatchResult{
		Outcome: runtime.InvocationSuccess, DurationMS: time.Since(start).Milliseconds(),
	}, nil
}

// CallTool invokes tools/call on the remote server. Authorization is
// the gateway's job (checked before this method is reachable); this
// layer enforces response size limits and redaction.
func (m *MCPConnector) CallTool(ctx context.Context, cfg runtime.ConnectorConfig, action runtime.ConnectorActionManifest, args map[string]any, authHeader, traceID string) (runtime.ConnectorDispatchResult, error) {
	start := time.Now()
	if err := m.initialize(ctx, cfg, authHeader); err != nil {
		return m.fail(start, "mcp_initialize_failed"), err
	}
	payload := FilterArguments(args, action.Args)
	b, err := json.Marshal(payload)
	if err != nil {
		return m.fail(start, "invalid_arguments"), err
	}
	if len(b) > action.MaxRequestBytes {
		return m.fail(start, "request_size_exceeded"), fmt.Errorf("%w: request size exceeds manifest limit", runtime.ErrConnectorInvalidConfig)
	}
	var result jsonrpcResult
	if err := m.call(ctx, cfg, authHeader, traceID, "tools/call", map[string]any{
		"name":      action.TransportMethod,
		"arguments": payload,
	}, &result); err != nil {
		return m.fail(start, "tools_call_failed"), redactError(err, m.redact)
	}
	raw, _ := json.Marshal(result)
	maxBytes := int64(cfg.MaxResponseBytes)
	if action.MaxResponseBytes > 0 && int64(action.MaxResponseBytes) < maxBytes {
		maxBytes = int64(action.MaxResponseBytes)
	}
	if int64(len(raw)) > maxBytes {
		return runtime.ConnectorDispatchResult{
			Outcome: runtime.InvocationResponseBlocked, ErrorCode: "response_size_exceeded",
			DurationMS: time.Since(start).Milliseconds(), ResponseBytes: int64(len(raw)),
		}, nil
	}
	var call struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &call); err != nil {
		return m.fail(start, "malformed_tools_call_result"), err
	}
	if call.IsError {
		return runtime.ConnectorDispatchResult{
			Outcome: runtime.InvocationFailure, ErrorCode: "upstream_tool_error",
			DurationMS: time.Since(start).Milliseconds(), ResponseBytes: int64(len(raw)),
		}, nil
	}
	texts := make([]string, 0, len(call.Content))
	for _, c := range call.Content {
		texts = append(texts, c.Text)
	}
	joined := strings.Join(texts, "\n")
	return runtime.ConnectorDispatchResult{
		Outcome:       runtime.InvocationSuccess,
		DurationMS:    time.Since(start).Milliseconds(),
		ResponseBytes: int64(len(raw)),
		Response:      Redaction{Fields: cfg.RedactionFields}.RedactText(joined),
	}, nil
}

// --- JSON-RPC plumbing ---

type jsonrpcRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      int            `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type jsonrpcResult map[string]any

var rpcSeq int

func (m *MCPConnector) initialize(ctx context.Context, cfg runtime.ConnectorConfig, authHeader string) error {
	rpcSeq++
	var result jsonrpcResult
	err := m.call(ctx, cfg, authHeader, "", "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "groundwork-gateway", "version": "5"},
	}, &result)
	if err != nil {
		return err
	}
	// Fire-and-forget initialized notification; a compliant server
	// tolerates its absence on call, but we follow the protocol.
	_ = m.notify(ctx, cfg, authHeader, "notifications/initialized", map[string]any{})
	return nil
}

func (m *MCPConnector) call(ctx context.Context, cfg runtime.ConnectorConfig, authHeader, traceID, method string, params map[string]any, out *jsonrpcResult) error {
	timeout := time.Duration(cfg.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := m.client
	if client.Timeout != timeout {
		client = &http.Client{Timeout: timeout}
	}
	body, _ := json.Marshal(jsonrpcRequest{JSONRPC: "2.0", ID: rpcSeq, Method: method, Params: params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BaseURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if traceID != "" {
		req.Header.Set("X-Groundwork-Trace", traceID)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("mcp upstream status %d", resp.StatusCode)
	}
	var rpc jsonrpcResponse
	if err := json.Unmarshal(raw, &rpc); err != nil {
		return err
	}
	if rpc.Error != nil {
		return fmt.Errorf("mcp %s error %d: %s", method, rpc.Error.Code, rpc.Error.Message)
	}
	if len(rpc.Result) == 0 {
		return fmt.Errorf("mcp %s: empty result", method)
	}
	if out != nil {
		if err := json.Unmarshal(rpc.Result, out); err != nil {
			return err
		}
	}
	return nil
}

func (m *MCPConnector) notify(ctx context.Context, cfg runtime.ConnectorConfig, authHeader, method string, params map[string]any) error {
	timeout := time.Duration(cfg.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	body, _ := json.Marshal(jsonrpcRequest{JSONRPC: "2.0", ID: rpcSeq + 1000, Method: method, Params: params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BaseURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func (m *MCPConnector) fail(start time.Time, code string) runtime.ConnectorDispatchResult {
	return runtime.ConnectorDispatchResult{
		Outcome: runtime.InvocationFailure, ErrorCode: code,
		DurationMS: time.Since(start).Milliseconds(),
	}
}
