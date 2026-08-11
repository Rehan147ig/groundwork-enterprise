package connectors

import (
	"strings"
	"testing"

	"groundwork/query-runtime/internal/runtime"
)

func validRESTConfig(t *testing.T) runtime.ConnectorConfig {
	t.Helper()
	return runtime.ConnectorConfig{
		BaseURL:             "https://api.example.com",
		Region:              "eu",
		TimeoutMS:           5000,
		RetryMax:            2,
		RetryIdempotentOnly: true,
		MaxResponseBytes:    262144,
		TLSVerify:           true,
		AllowedContentTypes: []string{"application/json"},
		RedactionFields:     []string{"token", "secret"},
	}
}

func TestValidateConfig(t *testing.T) {
	if err := ValidateConfig(validRESTConfig(t)); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cfg := validRESTConfig(t)
	cfg.BaseURL = ""
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("empty base_url must fail")
	}
	cfg = validRESTConfig(t)
	cfg.BaseURL = "https://api.example.com/v1"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("base_url with path must fail")
	}
	cfg = validRESTConfig(t)
	cfg.BaseURL = "https://api.example.com/path?q=1"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("base_url with query must fail")
	}
	// Plaintext only for private hosts.
	cfg = validRESTConfig(t)
	cfg.BaseURL = "http://api.example.com"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("plaintext public host must fail")
	}
	cfg = validRESTConfig(t)
	cfg.BaseURL = "http://10.0.0.5"
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("plaintext private host rejected: %v", err)
	}
	// Credentials in URL never allowed.
	cfg = validRESTConfig(t)
	cfg.BaseURL = "https://user:pass@api.example.com"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("credentials in base_url must fail")
	}
	// Raw secret material rejected.
	cfg = validRESTConfig(t)
	cfg.SecretRef = "password=supersecret"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("raw secret in secret_ref must fail")
	}
	// Timeouts out of range.
	cfg = validRESTConfig(t)
	cfg.TimeoutMS = 10
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("tiny timeout must fail")
	}
}

func TestValidateManifestREST(t *testing.T) {
	good := runtime.ConnectorActionManifest{
		Name: "get_balance", TransportMethod: "GET", PathTemplate: "/accounts/{account_id}",
		Risk: runtime.ConnectorRiskLow, ReadOnly: true, Args: []string{"account_id"},
	}
	if err := ValidateManifest(runtime.ConnectorTypeREST, good); err != nil {
		t.Fatalf("valid action rejected: %v", err)
	}
	// Write action must declare high/critical risk.
	bad := good
	bad.TransportMethod = "POST"
	bad.Risk = runtime.ConnectorRiskLow
	if err := ValidateManifest(runtime.ConnectorTypeREST, bad); err == nil {
		t.Fatal("low-risk write must fail")
	}
	// ReadOnly with a write method is inconsistent.
	bad = good
	bad.TransportMethod = "POST"
	bad.Risk = runtime.ConnectorRiskCritical
	bad.ReadOnly = true
	if err := ValidateManifest(runtime.ConnectorTypeREST, bad); err == nil {
		t.Fatal("read_only write action must fail")
	}
	// Missing path template.
	bad = good
	bad.PathTemplate = ""
	if err := ValidateManifest(runtime.ConnectorTypeREST, bad); err == nil {
		t.Fatal("action without path_template must fail")
	}
	// Traversal in path template.
	bad = good
	bad.PathTemplate = "/../etc/passwd"
	if err := ValidateManifest(runtime.ConnectorTypeREST, bad); err == nil {
		t.Fatal("path traversal must fail")
	}
	// Query in path template.
	bad = good
	bad.PathTemplate = "/accounts?all=true"
	if err := ValidateManifest(runtime.ConnectorTypeREST, bad); err == nil {
		t.Fatal("query in path_template must fail")
	}
	// Duplicate args.
	bad = good
	bad.Args = []string{"x", "x"}
	if err := ValidateManifest(runtime.ConnectorTypeREST, bad); err == nil {
		t.Fatal("duplicate args must fail")
	}
}

func TestValidateManifestMCP(t *testing.T) {
	good := runtime.ConnectorActionManifest{
		Name: "search", TransportMethod: "groundwork_search",
		Risk: runtime.ConnectorRiskMedium, Args: []string{"query"},
	}
	if err := ValidateManifest(runtime.ConnectorTypeMCP, good); err != nil {
		t.Fatalf("valid mcp action rejected: %v", err)
	}
	bad := good
	bad.TransportMethod = ""
	if err := ValidateManifest(runtime.ConnectorTypeMCP, bad); err == nil {
		t.Fatal("mcp action without tool name must fail")
	}
}

func TestExpandPathTemplate(t *testing.T) {
	out, err := ExpandPathTemplate("/accounts/{id}", map[string]any{"id": "a b"}, []string{"id"})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if strings.Contains(out, " ") {
		t.Fatalf("value must be path-escaped, got %q", out)
	}
	// Slash-bearing values are rejected outright (single-segment).
	if _, err := ExpandPathTemplate("/accounts/{id}", map[string]any{"id": "a/b"}, []string{"id"}); err == nil {
		t.Fatal("slash value must fail")
	}
	if _, err := ExpandPathTemplate("/accounts/{id}", map[string]any{"id": "abc"}, []string{"other"}); err == nil {
		t.Fatal("placeholder not in allowlist must fail")
	}
	if _, err := ExpandPathTemplate("/accounts/{id}", map[string]any{}, []string{"id"}); err == nil {
		t.Fatal("missing argument must fail")
	}
	if _, err := ExpandPathTemplate("/accounts/{id}/../x", map[string]any{"id": "1"}, []string{"id"}); err == nil {
		t.Fatal("dot-dot value must fail")
	}
	if _, err := ExpandPathTemplate("/accounts/{id}", map[string]any{"id": "a?b=c"}, []string{"id"}); err == nil {
		t.Fatal("query chars in value must fail")
	}
}

func TestFilterArguments(t *testing.T) {
	out := FilterArguments(map[string]any{"allow": 1, "drop": 2, "evil": 3}, []string{"allow"})
	if len(out) != 1 || out["allow"] != 1 {
		t.Fatalf("filter = %v", out)
	}
	if out := FilterArguments(map[string]any{"x": 1}, nil); out != nil {
		t.Fatal("no allowlist must drop everything")
	}
}

func TestManifestDigestStableAndSensitive(t *testing.T) {
	cfg := validRESTConfig(t)
	a1 := runtime.ConnectorActionManifest{
		Name: "get", TransportMethod: "GET", PathTemplate: "/x", Risk: runtime.ConnectorRiskLow, ReadOnly: true,
	}
	a2 := runtime.ConnectorActionManifest{
		Name: "post", TransportMethod: "POST", PathTemplate: "/x", Risk: runtime.ConnectorRiskCritical,
	}
	d1, err := ManifestDigest(cfg, []runtime.ConnectorActionManifest{a1, a2})
	if err != nil {
		t.Fatal(err)
	}
	d2, err := ManifestDigest(cfg, []runtime.ConnectorActionManifest{a2, a1}) // order-insensitive
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("digest must be order-insensitive: %s != %s", d1, d2)
	}
	cfg2 := cfg
	cfg2.TimeoutMS = 6000
	d3, err := ManifestDigest(cfg2, []runtime.ConnectorActionManifest{a1, a2})
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d3 {
		t.Fatal("config change must change the digest")
	}
}

func TestIsValidTransition(t *testing.T) {
	cases := map[[2]string]bool{
		{runtime.ConnectorLifecycleDraft, runtime.ConnectorLifecycleActive}:      true,
		{runtime.ConnectorLifecycleDraft, runtime.ConnectorLifecycleRevoked}:     true,
		{runtime.ConnectorLifecycleActive, runtime.ConnectorLifecycleSuspended}:  true,
		{runtime.ConnectorLifecycleSuspended, runtime.ConnectorLifecycleActive}:  true,
		{runtime.ConnectorLifecycleActive, runtime.ConnectorLifecycleRevoked}:    true,
		{runtime.ConnectorLifecycleRevoked, runtime.ConnectorLifecycleActive}:    false,
		{runtime.ConnectorLifecycleRevoked, runtime.ConnectorLifecycleSuspended}: false,
		{runtime.ConnectorLifecycleRetired, runtime.ConnectorLifecycleActive}:    false,
		{runtime.ConnectorLifecycleDraft, runtime.ConnectorLifecycleDraft}:       false,
	}
	for pair, want := range cases {
		if got := isValidTransition(pair[0], pair[1]); got != want {
			t.Errorf("isValidTransition(%s -> %s) = %v, want %v", pair[0], pair[1], got, want)
		}
	}
}

func TestConnectorLifecycleDigestChains(t *testing.T) {
	e1 := ConnectorLifecycleDigest("t", "c", "activate", "draft", "active", "a", "reason", "")
	e2 := ConnectorLifecycleDigest("t", "c", "suspend", "active", "suspended", "a", "reason", e1)
	if e1 == e2 {
		t.Fatal("digests must differ across the chain")
	}
	e3 := ConnectorLifecycleDigest("t", "c", "suspend", "active", "suspended", "a", "reason", e1)
	if e2 != e3 {
		t.Fatal("same event must produce the same digest")
	}
}
