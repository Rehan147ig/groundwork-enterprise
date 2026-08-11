package connectors

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Redaction is the defense against leaking secrets in logs and in
// responses. Never log Authorization headers, API keys, cookies, raw
// tokens, or sensitive request bodies.
type Redaction struct {
	Fields []string // sensitive JSON field names (case-insensitive)
}

// DefaultRedactionFields match the schema default.
func DefaultRedactionFields() []string {
	return []string{"token", "secret", "authorization", "password", "api_key", "cookie", "credential"}
}

var (
	// bearerRe matches Authorization-style values.
	bearerRe = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/\-=]{8,}`)
	// apiKeyRe matches common key/value secret patterns (quoted or
	// unquoted values; bare short values are left alone to avoid
	// mangling prose).
	apiKeyRe = regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token|cookie|authorization)\s*[=:]\s*("[^"]*"|[^\s,;"]{8,})`)
	// jwsRe matches raw JWT material.
	jwsRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`)
)

// RedactText replaces secret-bearing substrings in arbitrary text.
func (r Redaction) RedactText(s string) string {
	out := s
	out = bearerRe.ReplaceAllString(out, "$1[REDACTED]")
	out = jwsRe.ReplaceAllString(out, "[REDACTED-JWT]")
	if len(r.Fields) > 0 {
		out = apiKeyRe.ReplaceAllStringFunc(out, func(m string) string {
			lower := strings.ToLower(m)
			for _, field := range r.Fields {
				if strings.Contains(lower, strings.ToLower(field)) {
					return "[REDACTED]"
				}
			}
			return m
		})
	}
	return out
}

// RedactJSON walks a decoded JSON value and masks any key matching a
// redaction field (recursive). Used before returning responses to
// callers and before logging request/response bodies.
func (r Redaction) RedactJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if r.isSensitive(k) {
				out[k] = "[REDACTED]"
				continue
			}
			out[k] = r.RedactJSON(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = r.RedactJSON(val)
		}
		return out
	default:
		return v
	}
}

func (r Redaction) isSensitive(key string) bool {
	lower := strings.ToLower(key)
	for _, f := range r.Fields {
		if strings.Contains(lower, strings.ToLower(f)) {
			return true
		}
	}
	return false
}

// RedactHeader returns a safe representation of one HTTP header value.
func (r Redaction) RedactHeader(name, value string) string {
	if r.isSensitive(name) {
		return "[REDACTED]"
	}
	return value
}

// SanitizedRequest is the safe logging surface for an outbound request.
type SanitizedRequest struct {
	Method  string   `json:"method"`
	Host    string   `json:"host"`
	Path    string   `json:"path"`
	Bytes   int      `json:"bytes"`
	Headers []string `json:"header_names"`
}

// SanitizedResponse is the safe logging surface for a response.
type SanitizedResponse struct {
	StatusCode  int    `json:"status_code"`
	Bytes       int    `json:"bytes"`
	ContentType string `json:"content_type"`
}

// RedactBodyBytes decodes JSON bytes and redacts them; non-JSON bytes
// are redacted as text.
func (r Redaction) RedactBodyBytes(b []byte) string {
	var v any
	if err := json.Unmarshal(b, &v); err == nil {
		red := r.RedactJSON(v)
		out, err := json.Marshal(red)
		if err == nil {
			return string(out)
		}
	}
	return r.RedactText(string(b))
}

// redactError ensures connector errors never embed raw bodies/secrets.
func redactError(err error, r Redaction) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", r.RedactText(err.Error()))
}
