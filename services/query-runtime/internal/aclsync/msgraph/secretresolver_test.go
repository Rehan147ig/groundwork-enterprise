package msgraph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubResolver resolves every keyring:// reference to "resolved-secret".
type stubResolver struct{}

func (stubResolver) Resolve(_ context.Context, ref string) (string, error) {
	if !strings.HasPrefix(ref, "keyring://") {
		return "", ErrAuthFailed
	}
	return "resolved-secret", nil
}

// tokenEndpoint returns an httptest server that captures the posted
// client_secret and answers a client-credentials token response.
func tokenEndpoint(t *testing.T, capture *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		*capture = r.Form.Get("client_secret")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
}

func TestTokenSourceFailsClosedWithoutResolver(t *testing.T) {
	var captured string
	srv := tokenEndpoint(t, &captured)
	defer srv.Close()

	cfg := Config{
		TenantID:        "tenant",
		ClientID:        "client",
		ClientSecretRef: "keyring://connector/msgraph",
		AuthorityHost:   srv.URL,
	}.withDefaults()
	src := &tokenSource{cfg: cfg, http: &http.Client{}}

	// No resolver injected: the ref must fail closed on first use —
	// there is NO silent environment fallback.
	if _, err := src.get(context.Background()); err == nil {
		t.Fatal("token fetch with a ref but no injected resolver must fail closed")
	}
	if captured != "" {
		t.Fatalf("token endpoint was reached with a secret despite the missing resolver: %q", captured)
	}

	// Injecting a resolver makes the same ref work.
	src.secrets = stubResolver{}
	tok, err := src.get(context.Background())
	if err != nil {
		t.Fatalf("token fetch with resolver: %v", err)
	}
	if tok != "tok" {
		t.Fatalf("token = %q", tok)
	}
	if captured != "resolved-secret" {
		t.Fatalf("client_secret sent = %q, want the resolved secret", captured)
	}
}

func TestTokenSourceEnvResolverDevOnly(t *testing.T) {
	var captured string
	srv := tokenEndpoint(t, &captured)
	defer srv.Close()

	t.Setenv("MS_GRAPH_CLIENT_SECRET", "env-secret")
	cfg := Config{
		TenantID:        "tenant",
		ClientID:        "client",
		ClientSecretRef: "env://MS_GRAPH_CLIENT_SECRET",
		AuthorityHost:   srv.URL,
	}.withDefaults()
	src := &tokenSource{cfg: cfg, http: &http.Client{}, secrets: NewEnvSecretResolver()}

	tok, err := src.get(context.Background())
	if err != nil {
		t.Fatalf("token fetch via env ref: %v", err)
	}
	if tok != "tok" || captured != "env-secret" {
		t.Fatalf("token=%q secret=%q", tok, captured)
	}
}

func TestEnvSecretResolverRejectsKeyringRef(t *testing.T) {
	r := NewEnvSecretResolver()
	_, err := r.Resolve(context.Background(), "keyring://connector/msgraph")
	if err == nil || !strings.Contains(err.Error(), "env://") {
		t.Fatalf("env resolver must reject keyring refs (no silent mapping), got %v", err)
	}
	_, err = r.Resolve(context.Background(), "env://UNSET_VAR_XYZ")
	if err == nil {
		t.Fatal("unset env var must fail closed")
	}
	_, err = r.Resolve(context.Background(), "garbage")
	if err == nil {
		t.Fatal("malformed ref must fail closed")
	}
}

func TestSetSecretResolverWiresTokens(t *testing.T) {
	cfg := Config{AuthorityHost: "https://x"}.withDefaults()
	client := NewHTTPGraphClient(cfg)
	client.SetSecretResolver(stubResolver{})
	if client.tokens.secrets == nil {
		t.Fatal("SetSecretResolver must wire the token source")
	}
}
