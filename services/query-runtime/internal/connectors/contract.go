// Package connectors implements the Phase 5 Production Connector
// Gateway: registration, versioned manifests, lifecycle, REST and MCP
// transports, and the fail-closed invocation pipeline. It is a leaf
// package: it depends only on internal/runtime (DTOs/interfaces),
// internal/deployment (region model), and internal/keyring (secret
// refs). The runtime owns the ConnectorService/ConnectorDispatcher
// contracts; this package implements them.
package connectors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// ManifestDigest computes the immutable manifest digest over the
// canonical JSON of the action set (sorted by name) plus the
// transport-level configuration. Any change — config or actions —
// yields a new version and a new digest.
func ManifestDigest(cfg runtime.ConnectorConfig, actions []runtime.ConnectorActionManifest) (string, error) {
	canon := map[string]any{
		"config":  cfg,
		"actions": SortedActions(actions),
	}
	b, err := json.Marshal(canon)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ValidateConfig checks the transport-level configuration. Never
// trusts agent input; base_url is operator-supplied.
func ValidateConfig(cfg runtime.ConnectorConfig) error {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return fmt.Errorf("%w: base_url is required", runtime.ErrConnectorInvalidConfig)
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("%w: base_url must be an absolute http(s) URL", runtime.ErrConnectorInvalidConfig)
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("%w: base_url must not carry a path (use path_template on actions)", runtime.ErrConnectorInvalidConfig)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: base_url must have a host", runtime.ErrConnectorInvalidConfig)
	}
	if u.Scheme == "http" && !isPrivateHost(host) {
		return fmt.Errorf("%w: http is allowed only for private-network hosts (RFC1918/localhost)", runtime.ErrConnectorInvalidConfig)
	}
	if u.User != nil {
		return fmt.Errorf("%w: credentials in base_url are not allowed", runtime.ErrConnectorInvalidConfig)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: base_url must not carry query or fragment", runtime.ErrConnectorInvalidConfig)
	}
	if cfg.TimeoutMS < 100 || cfg.TimeoutMS > 120000 {
		return fmt.Errorf("%w: timeout_ms must be between 100 and 120000", runtime.ErrConnectorInvalidConfig)
	}
	if cfg.RetryMax < 0 || cfg.RetryMax > 5 {
		return fmt.Errorf("%w: retry_max must be between 0 and 5", runtime.ErrConnectorInvalidConfig)
	}
	if cfg.MaxResponseBytes < 1024 || cfg.MaxResponseBytes > 64<<20 {
		return fmt.Errorf("%w: max_response_bytes out of range", runtime.ErrConnectorInvalidConfig)
	}
	if strings.Contains(strings.ToLower(cfg.SecretRef), "password=") ||
		strings.Contains(strings.ToLower(cfg.SecretRef), "key=") ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(cfg.SecretRef)), "bearer ") ||
		strings.Contains(strings.ToLower(cfg.SecretRef), "token=") {
		return fmt.Errorf("%w: secret_ref must be a reference (keyring://... or env var name), never raw material", runtime.ErrConnectorInvalidConfig)
	}
	if cfg.AllowedContentTypes == nil {
		return fmt.Errorf("%w: allowed_content_types must list at least one content type", runtime.ErrConnectorInvalidConfig)
	}
	return nil
}

// DefaultMaxRequestBytes and DefaultMaxResponseBytes mirror the
// connector_actions column defaults (migration 018). An operator who
// omits a size limit on an action gets the schema default; without
// normalization the transports would read 0 as "empty request/response"
// and fail every dispatch.
const (
	DefaultMaxRequestBytes  = 65536
	DefaultMaxResponseBytes = 262144
)

// defaultManifestLimits applies the schema defaults to action size
// limits left at zero. It must run before ManifestDigest so the digest
// and the persisted manifest always agree.
func defaultManifestLimits(a runtime.ConnectorActionManifest) runtime.ConnectorActionManifest {
	if a.MaxRequestBytes <= 0 {
		a.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if a.MaxResponseBytes <= 0 {
		a.MaxResponseBytes = DefaultMaxResponseBytes
	}
	return a
}

// ValidateManifest checks one action. transport_method is declared by
// the operator (HTTP method or MCP tool name); the agent can never
// supply it.
func ValidateManifest(connType string, a runtime.ConnectorActionManifest) error {
	if strings.TrimSpace(a.Name) == "" {
		return fmt.Errorf("%w: action name is required", runtime.ErrConnectorInvalidConfig)
	}
	if connType == runtime.ConnectorTypeREST {
		switch a.TransportMethod {
		case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD":
		default:
			return fmt.Errorf("%w: rest transport_method must be an HTTP method", runtime.ErrConnectorInvalidConfig)
		}
		if a.TransportMethod != "GET" && a.TransportMethod != "HEAD" && a.ReadOnly {
			return fmt.Errorf("%w: read_only actions must use GET or HEAD", runtime.ErrConnectorInvalidConfig)
		}
		if a.TransportMethod != "GET" && a.TransportMethod != "HEAD" &&
			a.Risk != runtime.ConnectorRiskHigh && a.Risk != runtime.ConnectorRiskCritical {
			return fmt.Errorf("%w: non-read-only actions must declare high or critical risk", runtime.ErrConnectorInvalidConfig)
		}
		if strings.TrimSpace(a.PathTemplate) == "" {
			return fmt.Errorf("%w: rest actions require a path_template", runtime.ErrConnectorInvalidConfig)
		}
		if err := validatePathTemplate(a.PathTemplate); err != nil {
			return err
		}
	} else {
		if strings.TrimSpace(a.TransportMethod) == "" {
			return fmt.Errorf("%w: mcp transport_method must name the remote tool", runtime.ErrConnectorInvalidConfig)
		}
	}
	switch a.Risk {
	case runtime.ConnectorRiskLow, runtime.ConnectorRiskMedium, runtime.ConnectorRiskHigh, runtime.ConnectorRiskCritical:
	default:
		return fmt.Errorf("%w: unknown risk level %q", runtime.ErrConnectorInvalidConfig, a.Risk)
	}
	if a.MaxRequestBytes < 0 || a.MaxResponseBytes < 0 {
		return fmt.Errorf("%w: size limits cannot be negative", runtime.ErrConnectorInvalidConfig)
	}
	seen := map[string]bool{}
	for _, arg := range a.Args {
		if strings.TrimSpace(arg) == "" {
			return fmt.Errorf("%w: empty argument name in allowlist", runtime.ErrConnectorInvalidConfig)
		}
		if seen[arg] {
			return fmt.Errorf("%w: duplicate argument %q", runtime.ErrConnectorInvalidConfig, arg)
		}
		seen[arg] = true
	}
	return nil
}

// validatePathTemplate ensures the template is a simple /segments path
// with {arg} placeholders only — no host, scheme, port, query, or
// traversal.
func validatePathTemplate(tpl string) error {
	if !strings.HasPrefix(tpl, "/") {
		return fmt.Errorf("%w: path_template must start with /", runtime.ErrConnectorInvalidConfig)
	}
	u, err := url.Parse(tpl)
	if err != nil || u.Host != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: path_template must be a path without host/query/fragment", runtime.ErrConnectorInvalidConfig)
	}
	if strings.Contains(tpl, "..") {
		return fmt.Errorf("%w: path_template must not contain ..", runtime.ErrConnectorInvalidConfig)
	}
	for _, seg := range strings.Split(strings.Trim(tpl, "/"), "/") {
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, "{") {
			if !strings.HasSuffix(seg, "}") || len(seg) < 3 {
				return fmt.Errorf("%w: malformed path placeholder %q", runtime.ErrConnectorInvalidConfig, seg)
			}
		}
	}
	return nil
}

// ExpandPathTemplate substitutes allowlisted argument values into a
// validated path template. Values are URL-path-escaped; placeholder
// values are rejected if they contain slash, query, dot-dot, or
// control characters. Unknown placeholders fail closed (the manifest
// must declare every placeholder in its Args allowlist).
func ExpandPathTemplate(tpl string, args map[string]any, allowed []string) (string, error) {
	if strings.Contains(tpl, "..") {
		return "", fmt.Errorf("%w: path template must not contain ..", runtime.ErrConnectorInvalidConfig)
	}
	allowedSet := map[string]bool{}
	for _, a := range allowed {
		allowedSet[a] = true
	}
	out := tpl
	for {
		start := strings.Index(out, "{")
		if start < 0 {
			break
		}
		end := strings.Index(out[start:], "}")
		if end < 0 {
			return "", fmt.Errorf("%w: unbalanced path template", runtime.ErrConnectorInvalidConfig)
		}
		name := out[start+1 : start+end]
		if !allowedSet[name] {
			return "", fmt.Errorf("%w: path placeholder %q not in argument allowlist", runtime.ErrConnectorInvalidConfig, name)
		}
		raw, ok := args[name]
		if !ok {
			return "", fmt.Errorf("%w: missing argument %q", runtime.ErrConnectorInvalidConfig, name)
		}
		s := fmt.Sprintf("%v", raw)
		if s == "" || strings.ContainsAny(s, "/?&#%\\") || strings.Contains(s, "..") {
			return "", fmt.Errorf("%w: invalid value for path argument %q", runtime.ErrConnectorInvalidConfig, name)
		}
		out = out[:start] + url.PathEscape(s) + out[start+end+1:]
	}
	if strings.ContainsAny(out, "{}") {
		return "", fmt.Errorf("%w: undeclared path placeholder", runtime.ErrConnectorInvalidConfig)
	}
	return out, nil
}

// FilterArguments enforces the manifest argument allowlist: unknown
// arguments are dropped (fail closed — never forwarded).
func FilterArguments(args map[string]any, allowed []string) map[string]any {
	if len(allowed) == 0 {
		return nil
	}
	allowedSet := map[string]bool{}
	for _, a := range allowed {
		allowedSet[a] = true
	}
	out := map[string]any{}
	for k, v := range args {
		if allowedSet[k] {
			out[k] = v
		}
	}
	return out
}

// isPrivateHost reports whether host is loopback or RFC1918/ULA
// (private-network support; public hosts require TLS).
func isPrivateHost(host string) bool {
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// Transition is a lifecycle transition rule set.
func isValidTransition(from, to string) bool {
	if from == runtime.ConnectorLifecycleRevoked || from == runtime.ConnectorLifecycleRetired {
		return false // revoked/retired connectors cannot be reactivated
	}
	switch from {
	case runtime.ConnectorLifecycleDraft:
		return to == runtime.ConnectorLifecycleActive || to == runtime.ConnectorLifecycleRevoked ||
			to == runtime.ConnectorLifecycleRetired
	case runtime.ConnectorLifecycleActive:
		return to == runtime.ConnectorLifecycleSuspended || to == runtime.ConnectorLifecycleRevoked ||
			to == runtime.ConnectorLifecycleRetired
	case runtime.ConnectorLifecycleSuspended:
		return to == runtime.ConnectorLifecycleActive || to == runtime.ConnectorLifecycleRevoked ||
			to == runtime.ConnectorLifecycleRetired
	}
	return false
}

// SortedActions returns the action set sorted by name (canonical order
// for digests and stable listing).
func SortedActions(actions []runtime.ConnectorActionManifest) []runtime.ConnectorActionManifest {
	out := make([]runtime.ConnectorActionManifest, len(actions))
	copy(out, actions)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ConnectorLifecycleDigest hashes a lifecycle event's security-relevant
// fields plus the previous event's digest (hash-chained evidence).
func ConnectorLifecycleDigest(tenantID, connectorID, actionType, from, to, actor, reason, previousDigest string) string {
	sum := sha256.Sum256([]byte(tenantID + "\x1f" + connectorID + "\x1f" + actionType + "\x1f" +
		from + "\x1f" + to + "\x1f" + actor + "\x1f" + reason + "\x1f" + previousDigest))
	return hex.EncodeToString(sum[:])
}

// ConnectorInvocationDigest hashes a single invocation outcome's
// security-relevant fields (write-once evidence; the row is protected
// by no_update/no_delete rules and its digest never changes).
func ConnectorInvocationDigest(inv runtime.ConnectorInvocation) string {
	sum := sha256.Sum256([]byte(inv.TenantID + "\x1f" + inv.ConnectorID + "\x1f" + inv.DecisionID + "\x1f" +
		inv.Kind + "\x1f" + inv.Outcome + "\x1f" + fmt.Sprintf("%d", inv.StatusCode) + "\x1f" +
		inv.ErrorCode + "\x1f" + fmt.Sprintf("%d", inv.DurationMS) + "\x1f" +
		fmt.Sprintf("%d", inv.ResponseBytes) + "\x1f" + inv.Region + "\x1f" + inv.TraceID + "\x1f" +
		inv.OccurredAt.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(sum[:])
}
