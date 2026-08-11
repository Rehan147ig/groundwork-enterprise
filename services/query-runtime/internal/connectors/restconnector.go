package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// RESTConnector is the controlled generic REST transport. It is
// configured entirely by the connector registry (base URL, method from
// the manifest, path template, size limits, retry, TLS/mTLS, secrets);
// an agent request can never supply a URL, host, port, or method.
type RESTConnector struct {
	resolver SecretResolver
	client   *http.Client
	timeout  time.Duration
	redact   Redaction
}

// NewRESTConnector builds a transport whose client never follows
// redirects to unapproved hosts (CheckRedirect) and enforces the
// operator-declared timeout.
func NewRESTConnector(resolver SecretResolver) *RESTConnector {
	c := &RESTConnector{resolver: resolver}
	c.client = &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("%w: redirect to %s rejected (single-hop only)", runtime.ErrConnectorInvalidConfig, req.URL.Host)
		},
	}
	return c
}

// Dispatch performs one authorized call. baseURL is the operator
// allow-listed base; method/path/args come from the validated manifest
// and the gateway's argument allowlist. Returns the redacted, size-
// limited response and the raw outcome fields for evidence.
//
// idempotencyKey is the semantic key of the logical mutation (Phase
// 8.2). When non-empty it is forwarded as the Idempotency-Key header so
// the upstream can dedupe the crash window between an executed call and
// its recorded evidence.
func (c *RESTConnector) Dispatch(ctx context.Context, cfg runtime.ConnectorConfig, action runtime.ConnectorActionManifest, args map[string]any, authHeader string, traceID string, idempotencyKey string) (runtime.ConnectorDispatchResult, error) {
	start := time.Now()
	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return c.fail(start, "invalid_base_url", err), err
	}
	path, err := ExpandPathTemplate(action.PathTemplate, args, action.Args)
	if err != nil {
		return c.fail(start, "invalid_arguments", err), err
	}
	target := *base
	target.Path = strings.TrimSuffix(base.Path, "/") + path
	body, err := c.requestBody(action, args)
	if err != nil {
		return c.fail(start, "invalid_arguments", err), err
	}

	timeout := time.Duration(cfg.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := c.client
	if timeout != c.client.Timeout {
		client = &http.Client{
			Timeout:       timeout,
			CheckRedirect: c.client.CheckRedirect,
		}
	}
	tlsCfg, err := TLSConfigFor(cfg.TLSVerify, cfg.ClientCertRef, c.resolver, ctx)
	if err != nil {
		return c.fail(start, "tls_config_failed", err), err
	}
	// TLS is applied by default; a pre-injected transport (tests, custom
	// deployments) keeps its own configuration.
	if client.Transport == nil {
		transport := &http.Transport{TLSClientConfig: tlsCfg}
		defer transport.CloseIdleConnections()
		client.Transport = transport
	}

	req, err := http.NewRequestWithContext(ctx, action.TransportMethod, target.String(), body)
	if err != nil {
		return c.fail(start, "request_build_failed", err), err
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	req.Header.Set("Accept", strings.Join(cfg.AllowedContentTypes, ", "))
	req.Header.Set("X-Groundwork-Trace", traceID)
	req.Header.Set("Traceparent", traceparentOf(traceID))
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}

	maxBytes := c.effectiveMaxResponse(cfg, action)
	attempts := c.retryPolicy(cfg, action)
	var resp *http.Response
	var doErr error
	for attempt := 0; ; attempt++ {
		resp, doErr = client.Do(req)
		if doErr != nil {
			if attempt < attempts && isRetryable(doErr) {
				time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
				continue
			}
			return c.fail(start, "transport_error", doErr), redactError(doErr, c.redact)
		}
		break
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return c.fail(start, "read_error", err), redactError(err, c.redact)
	}
	truncated := int64(len(bodyBytes)) > maxBytes
	if truncated {
		return c.block(start, resp.StatusCode, "response_size_exceeded", maxBytes), nil
	}
	if !c.contentTypeAllowed(resp.Header.Get("Content-Type"), cfg.AllowedContentTypes) {
		return c.block(start, resp.StatusCode, "content_type_blocked", int64(len(bodyBytes))), nil
	}
	if resp.StatusCode >= 300 {
		return runtime.ConnectorDispatchResult{
			Outcome:       runtime.InvocationFailure,
			StatusCode:    resp.StatusCode,
			ErrorCode:     "upstream_status_" + httpStatusName(resp.StatusCode),
			DurationMS:    time.Since(start).Milliseconds(),
			ResponseBytes: int64(len(bodyBytes)),
		}, nil
	}

	// Decode + redact before returning: the caller only ever sees the
	// policy-compliant view. Logging never includes raw headers/body.
	redact := Redaction{Fields: cfg.RedactionFields}
	var decoded any
	if err := json.Unmarshal(bodyBytes, &decoded); err == nil {
		decoded = redact.RedactJSON(decoded)
	} else {
		decoded = redact.RedactText(string(bodyBytes))
	}
	return runtime.ConnectorDispatchResult{
		Outcome:       runtime.InvocationSuccess,
		StatusCode:    resp.StatusCode,
		DurationMS:    time.Since(start).Milliseconds(),
		ResponseBytes: int64(len(bodyBytes)),
		Response:      decoded,
	}, nil
}

// Health executes the safe read-only health probe: GET on the base URL
// with a short timeout. It never sends credentials and never mutates.
func (c *RESTConnector) Health(ctx context.Context, cfg runtime.ConnectorConfig) (runtime.ConnectorDispatchResult, error) {
	start := time.Now()
	timeout := time.Duration(cfg.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tlsCfg, err := TLSConfigFor(cfg.TLSVerify, cfg.ClientCertRef, c.resolver, ctx)
	if err != nil {
		return c.fail(start, "tls_config_failed", err), err
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("%w: redirect rejected during health probe", runtime.ErrConnectorInvalidConfig)
		},
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.BaseURL, nil)
	if err != nil {
		return c.fail(start, "request_build_failed", err), err
	}
	resp, err := client.Do(req)
	if err != nil {
		return c.fail(start, "transport_error", err), err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 500 {
		return runtime.ConnectorDispatchResult{
			Outcome: runtime.InvocationFailure, StatusCode: resp.StatusCode,
			ErrorCode: "upstream_unhealthy", DurationMS: time.Since(start).Milliseconds(),
		}, nil
	}
	return runtime.ConnectorDispatchResult{
		Outcome: runtime.InvocationSuccess, StatusCode: resp.StatusCode,
		DurationMS: time.Since(start).Milliseconds(),
	}, nil
}

func (c *RESTConnector) requestBody(action runtime.ConnectorActionManifest, args map[string]any) (io.Reader, error) {
	if action.TransportMethod == http.MethodGet || action.TransportMethod == http.MethodHead {
		return nil, nil
	}
	payload := FilterArguments(args, action.Args)
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if len(b) > action.MaxRequestBytes {
		return nil, fmt.Errorf("%w: request size exceeds manifest limit", runtime.ErrConnectorInvalidConfig)
	}
	return bytes.NewReader(b), nil
}

func (c *RESTConnector) effectiveMaxResponse(cfg runtime.ConnectorConfig, action runtime.ConnectorActionManifest) int64 {
	max := cfg.MaxResponseBytes
	if action.MaxResponseBytes > 0 && action.MaxResponseBytes < max {
		max = action.MaxResponseBytes
	}
	if max <= 0 {
		max = 262144
	}
	return int64(max)
}

func (c *RESTConnector) retryPolicy(cfg runtime.ConnectorConfig, action runtime.ConnectorActionManifest) int {
	// Retry only for safe, idempotent operations: read-only GET/HEAD.
	// Destructive actions (writes, high/critical risk) never retry.
	if cfg.RetryMax <= 0 || !cfg.RetryIdempotentOnly {
		return 0
	}
	if !action.ReadOnly || (action.TransportMethod != http.MethodGet && action.TransportMethod != http.MethodHead) {
		return 0
	}
	return cfg.RetryMax
}

func isRetryable(err error) bool {
	// Network-level errors only; HTTP status handling never retries.
	var netErr interface{ Timeout() bool }
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "reset by peer") ||
		strings.Contains(msg, "unexpected eof") ||
		strings.Contains(msg, "connection closed")
}

func (c *RESTConnector) contentTypeAllowed(ct string, allowed []string) bool {
	ct = strings.TrimSpace(strings.Split(ct, ";")[0])
	if ct == "" {
		return false
	}
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), ct) {
			return true
		}
	}
	return false
}

func (c *RESTConnector) fail(start time.Time, code string, err error) runtime.ConnectorDispatchResult {
	return runtime.ConnectorDispatchResult{
		Outcome: runtime.InvocationFailure, ErrorCode: code,
		DurationMS: time.Since(start).Milliseconds(),
	}
}

func (c *RESTConnector) block(start time.Time, status int, code string, bytes int64) runtime.ConnectorDispatchResult {
	return runtime.ConnectorDispatchResult{
		Outcome: runtime.InvocationResponseBlocked, StatusCode: status,
		ErrorCode: code, DurationMS: time.Since(start).Milliseconds(), ResponseBytes: bytes,
	}
}

func traceparentOf(traceID string) string {
	if traceID == "" {
		return ""
	}
	return "00-" + traceID + "-0000000000000000-01"
}

func httpStatusName(code int) string {
	if name := http.StatusText(code); name != "" {
		return strings.ToLower(strings.ReplaceAll(name, " ", "_"))
	}
	return fmt.Sprintf("%d", code)
}
