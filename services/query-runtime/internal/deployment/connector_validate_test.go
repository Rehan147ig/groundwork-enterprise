package deployment

import (
	"strings"
	"testing"
)

// TestConnectorEgressValidation exercises the Phase 5 connector bypass
// protections: registered egress only, TLS mandatory for public hosts,
// TLS verification cannot be disabled, plaintext only for private hosts.
func TestConnectorEgressValidation(t *testing.T) {
	base := func() ValidateOptions {
		return ValidateOptions{
			Production:         true,
			ApprovedEgressOnly: true,
			LookupEnv:          func(string) string { return "" },
			Environ:            func() []string { return nil },
		}
	}
	env := func(opts ValidateOptions, kvs ...string) ValidateOptions {
		opts.Environ = func() []string {
			var out []string
			for _, kv := range kvs {
				out = append(out, kv)
			}
			return out
		}
		opts.LookupEnv = func(key string) string {
			prefix := key + "="
			for _, kv := range kvs {
				if strings.HasPrefix(kv, prefix) {
					return strings.TrimPrefix(kv, prefix)
				}
			}
			return ""
		}
		return opts
	}
	cfg := DeploymentConfig{
		DeploymentRegion:       "EU",
		Jurisdiction:           "eu",
		AuditStorageConfigured: true,
		Services: []ServiceEndpoint{
			{Name: "gateway", Port: 443, Public: true},
		},
	}

	has := func(problems Problems, code string) bool {
		for _, p := range problems {
			if p.Code == code {
				return true
			}
		}
		return false
	}

	// Registered egress: connector host on the allowlist is fine.
	opts := env(base(),
		"GROUNDWORK_CONNECTOR_EGRESS_ALLOWLIST=api.stripe.com",
		"GROUNDWORK_CONNECTOR_PAYMENTS_BASE_URL=https://api.stripe.com")
	if problems := Validate(cfg, opts); len(problems) != 0 {
		t.Fatalf("expected clean validation, got %v", problems)
	}

	// Unregistered host fails closed.
	opts = env(base(),
		"GROUNDWORK_CONNECTOR_EGRESS_ALLOWLIST=api.stripe.com",
		"GROUNDWORK_CONNECTOR_PAYMENTS_BASE_URL=https://api.example.org")
	if problems := Validate(cfg, opts); !has(problems, "connector_egress_unregistered") {
		t.Fatalf("expected connector_egress_unregistered, got %v", problems)
	}

	// No allowlist at all with connectors configured fails closed.
	opts = env(base(),
		"GROUNDWORK_CONNECTOR_PAYMENTS_BASE_URL=https://api.stripe.com")
	if problems := Validate(cfg, opts); !has(problems, "connector_egress_unregistered") {
		t.Fatalf("expected connector_egress_unregistered (no allowlist), got %v", problems)
	}

	// Plaintext public host rejected.
	opts = env(base(),
		"GROUNDWORK_CONNECTOR_EGRESS_ALLOWLIST=api.stripe.com",
		"GROUNDWORK_CONNECTOR_PAYMENTS_BASE_URL=http://api.stripe.com")
	if problems := Validate(cfg, opts); !has(problems, "connector_plaintext_endpoint") {
		t.Fatalf("expected connector_plaintext_endpoint, got %v", problems)
	}

	// Plaintext private host is allowed (RFC1918 / localhost).
	opts = env(base(),
		"GROUNDWORK_CONNECTOR_EGRESS_ALLOWLIST=10.0.0.5",
		"GROUNDWORK_CONNECTOR_PAYMENTS_BASE_URL=http://10.0.0.5")
	if problems := Validate(cfg, opts); len(problems) != 0 {
		t.Fatalf("private plaintext host should pass, got %v", problems)
	}

	// TLS verify disabled fails closed (per connector and global).
	opts = env(base(),
		"GROUNDWORK_CONNECTOR_EGRESS_ALLOWLIST=api.stripe.com",
		"GROUNDWORK_CONNECTOR_PAYMENTS_BASE_URL=https://api.stripe.com",
		"GROUNDWORK_CONNECTOR_PAYMENTS_TLS_VERIFY=false")
	if problems := Validate(cfg, opts); !has(problems, "connector_tls_verify_disabled") {
		t.Fatalf("expected connector_tls_verify_disabled, got %v", problems)
	}
	opts = env(base(),
		"GROUNDWORK_CONNECTOR_EGRESS_ALLOWLIST=api.stripe.com",
		"GROUNDWORK_CONNECTOR_PAYMENTS_BASE_URL=https://api.stripe.com",
		"GROUNDWORK_CONNECTOR_TLS_VERIFY=false")
	if problems := Validate(cfg, opts); !has(problems, "connector_tls_verify_disabled") {
		t.Fatalf("expected connector_tls_verify_disabled (global), got %v", problems)
	}

	// Malformed base URL rejected.
	opts = env(base(),
		"GROUNDWORK_CONNECTOR_PAYMENTS_BASE_URL=api.stripe.com")
	if problems := Validate(cfg, opts); !has(problems, "connector_endpoint_invalid") {
		t.Fatalf("expected connector_endpoint_invalid, got %v", problems)
	}
}

func TestConnectorHost(t *testing.T) {
	cases := map[string]string{
		"https://api.stripe.com":     "api.stripe.com",
		"https://api.stripe.com/v1":  "api.stripe.com",
		"http://10.0.0.5:8080/path":  "10.0.0.5",
		"HTTPS://UPPER.example.com":  "upper.example.com",
		"api.stripe.com":             "",
		"https://":                   "",
		"https://api.stripe.com?x=1": "api.stripe.com",
	}
	for in, want := range cases {
		if got := connectorHost(in); got != want {
			t.Errorf("connectorHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsPrivateHost(t *testing.T) {
	priv := []string{"localhost", "10.0.0.5", "192.168.1.10", "172.16.0.1", "127.0.0.1", "redis.local", "db.internal"}
	for _, h := range priv {
		if !isPrivateHost(h) {
			t.Errorf("%q should be private", h)
		}
	}
	pub := []string{"api.stripe.com", "8.8.8.8", "2606:4700::1111"}
	for _, h := range pub {
		if isPrivateHost(h) {
			t.Errorf("%q should be public", h)
		}
	}
}
