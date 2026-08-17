package runtime

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// oidcTestIssuer is a fake OIDC provider: discovery + JWKS + signing.
type oidcTestIssuer struct {
	issuer  string
	jwksURL string
	key     *rsa.PrivateKey
	kid     string
	srv     *httptest.Server
}

func newOIDCTestIssuer(t *testing.T) *oidcTestIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	iss := &oidcTestIssuer{key: key, kid: "test-key-1"}
	n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
	jwks := jwksDocument{Keys: []jsonWebKey{{Kty: "RSA", Kid: iss.kid, Alg: "RS256", Use: "sig", N: n, E: e}}}
	jwksBody, _ := json.Marshal(jwks)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   iss.issuer,
			"jwks_uri": iss.jwksURL,
		})
	})
	iss.srv = httptest.NewServer(mux)
	iss.issuer = iss.srv.URL
	iss.jwksURL = iss.srv.URL + "/jwks"
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBody)
	})
	t.Cleanup(iss.srv.Close)
	return iss
}

func (i *oidcTestIssuer) token(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	now := time.Now()
	payload := map[string]any{
		"sub":   "sub-alice",
		"iss":   i.issuer,
		"aud":   "groundwork-console",
		"exp":   now.Add(time.Hour).Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"iat":   now.Add(-time.Minute).Unix(),
		"tid":   "acme",
		"roles": []string{"analyst", "security-admin"},
	}
	for k, v := range claims {
		payload[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(payload))
	token.Header["kid"] = i.kid
	signed, err := token.SignedString(i.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func oidcVerifier(t *testing.T, iss *oidcTestIssuer, mutate func(*OIDCConfig)) *OIDCVerifier {
	t.Helper()
	cfg := OIDCConfig{
		Issuer:     iss.issuer,
		ClientID:   "groundwork-console",
		Algorithms: []string{"RS256"},
		AdminRoles: []string{"security-admin"},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	v, err := NewOIDCVerifier(cfg)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return v
}

func TestOIDCVerifyHappyPath(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, nil)
	id, err := v.Verify(context.Background(), iss.token(t, nil))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !id.Verified || id.UserID != "sub-alice" || id.Subject != "sub-alice" {
		t.Errorf("unexpected identity: %+v", id)
	}
	if id.TenantID != "acme" {
		t.Errorf("tenant mapping = %q, want acme", id.TenantID)
	}
	if !id.Admin {
		t.Error("configured admin role must map to Admin=true")
	}
	if id.Issuer != iss.issuer {
		t.Errorf("issuer = %q", id.Issuer)
	}
}

func TestOIDCVerifyCanonicalClaim(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, func(c *OIDCConfig) { c.CanonicalClaim = "preferred_username" })
	id, err := v.Verify(context.Background(), iss.token(t, map[string]any{"preferred_username": "alice@example.com"}))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.UserID != "alice@example.com" {
		t.Errorf("canonical user id = %q", id.UserID)
	}
}

func TestOIDCVerifyTenantAllowlistRejectsUnknown(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, func(c *OIDCConfig) { c.TenantAllowlist = []string{"contoso"} })
	if _, err := v.Verify(context.Background(), iss.token(t, nil)); err == nil {
		t.Fatal("token with tenant outside allow-list must fail closed")
	}
	v2 := oidcVerifier(t, iss, func(c *OIDCConfig) { c.TenantAllowlist = []string{"acme", "contoso"} })
	if _, err := v2.Verify(context.Background(), iss.token(t, nil)); err != nil {
		t.Fatalf("allow-listed tenant must verify: %v", err)
	}
}

func TestOIDCVerifyRejectsTampering(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, nil)
	good := iss.token(t, nil)
	bad := good[:len(good)-3] + "abc"
	if _, err := v.Verify(context.Background(), bad); err == nil {
		t.Fatal("tampered token must fail closed")
	}
}

func TestOIDCVerifyRejectsWrongIssuer(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, nil)
	if _, err := v.Verify(context.Background(), iss.token(t, map[string]any{"iss": "https://evil.example"})); err == nil {
		t.Fatal("wrong issuer must fail closed")
	}
}

func TestOIDCVerifyRejectsWrongAudience(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, nil)
	if _, err := v.Verify(context.Background(), iss.token(t, map[string]any{"aud": "other-app"})); err == nil {
		t.Fatal("wrong audience must fail closed")
	}
}

func TestOIDCVerifyRejectsExpired(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, nil)
	now := time.Now()
	if _, err := v.Verify(context.Background(), iss.token(t, map[string]any{"exp": now.Add(-time.Hour).Unix()})); err == nil {
		t.Fatal("expired token must fail closed")
	}
}

func TestOIDCVerifyRejectsFutureNBF(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, nil)
	now := time.Now()
	if _, err := v.Verify(context.Background(), iss.token(t, map[string]any{"nbf": now.Add(time.Hour).Unix()})); err == nil {
		t.Fatal("not-yet-valid token must fail closed")
	}
}

func TestOIDCVerifyRejectsNoKid(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, nil)
	tok := iss.token(t, nil)
	parts := strings.Split(tok, ".")
	headerRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]any
	_ = json.Unmarshal(headerRaw, &header)
	delete(header, "kid")
	reEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(t, header))
	fake := reEncoded + "." + parts[1] + "." + parts[2]
	if _, err := v.Verify(context.Background(), fake); err == nil {
		t.Fatal("token without kid must fail closed")
	}
}

func TestOIDCVerifyRejectsUnknownKid(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, nil)
	tok := iss.token(t, nil)
	parts := strings.Split(tok, ".")
	headerRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]any
	_ = json.Unmarshal(headerRaw, &header)
	header["kid"] = "unknown-key"
	reEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(t, header))
	fake := reEncoded + "." + parts[1] + "." + parts[2]
	if _, err := v.Verify(context.Background(), fake); err == nil {
		t.Fatal("unknown kid must fail closed")
	}
}

func TestOIDCVerifyRejectsAlgorithmNotAllowed(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, nil)
	tok := iss.token(t, nil)
	parts := strings.Split(tok, ".")
	headerRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]any
	_ = json.Unmarshal(headerRaw, &header)
	header["alg"] = "HS256"
	reEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(t, header))
	fake := reEncoded + "." + parts[1] + "." + parts[2]
	if _, err := v.Verify(context.Background(), fake); err == nil {
		t.Fatal("algorithm outside the allow-list must fail closed")
	}
}

func TestOIDCConstructionFailsOnUnreachableIssuer(t *testing.T) {
	ln := httptest.NewServer(http.NotFoundHandler())
	dead := strings.TrimPrefix(ln.URL, "http://")
	ln.Close()
	_, err := NewOIDCVerifier(OIDCConfig{Issuer: "http://" + dead, ClientID: "x"})
	if err == nil {
		t.Fatal("unreachable issuer must fail at construction (startup), not at first request")
	}
}

func TestOIDCConstructionRejectsMismatchedDiscoveryIssuer(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	_, err := NewOIDCVerifier(OIDCConfig{Issuer: "https://not-the-issuer.example", ClientID: "x", HTTPClient: iss.srv.Client()})
	if err == nil {
		t.Fatal("discovered issuer mismatch must fail construction")
	}
}

func TestOIDCNoAdminWithoutConfiguredRoles(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, func(c *OIDCConfig) { c.AdminRoles = nil })
	id, err := v.Verify(context.Background(), iss.token(t, map[string]any{"roles": []string{"security-admin"}}))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Admin {
		t.Fatal("no configured admin roles => a role claim must never grant Admin")
	}
}

func TestOIDCMissingRolesClaimIsNotAdmin(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, nil) // AdminRoles = [security-admin]
	id, err := v.Verify(context.Background(), iss.token(t, map[string]any{"roles": []string{}}))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Admin {
		t.Fatal("token with no roles claim must not map to Admin")
	}
	if len(id.Roles) != 0 {
		t.Fatalf("roles = %v, want empty", id.Roles)
	}
}

func TestOIDCMissingTenantClaimFailsClosed(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, nil)
	if _, err := v.Verify(context.Background(), iss.token(t, map[string]any{"tid": ""})); err == nil {
		t.Fatal("missing tenant claim must fail closed")
	}
}

func TestOIDCMissingCanonicalClaimFailsClosed(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	v := oidcVerifier(t, iss, nil)
	if _, err := v.Verify(context.Background(), iss.token(t, map[string]any{"sub": ""})); err == nil {
		t.Fatal("missing canonical (sub) claim must fail closed")
	}
}

// TestOIDCTenantClaimSubFailsClosed: "sub" is the per-user subject
// identifier, not a tenant identifier — two Okta orgs can issue the
// same sub for different users. Using sub as the tenant claim must fail
// closed at startup (no verifier is ever constructed), even when an
// org allowlist would otherwise gate tenant values.
func TestOIDCTenantClaimSubFailsClosed(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	if _, err := NewOIDCVerifier(OIDCConfig{
		Issuer:          iss.issuer,
		ClientID:        "groundwork-console",
		Algorithms:      []string{"RS256"},
		TenantClaim:     "sub",
		TenantAllowlist: []string{"acme"},
		HTTPClient:      iss.srv.Client(),
	}); err == nil || !strings.Contains(err.Error(), "must not be") {
		t.Fatalf("TENANT_CLAIM=sub with an org allowlist must fail closed at construction, got %v", err)
	}
	// Same gate through the deployment env path (validation fires
	// before discovery, so a dummy https issuer suffices).
	t.Setenv("GROUNDWORK_OIDC_ISSUER", "https://example.okta.com/oauth2/default")
	t.Setenv("GROUNDWORK_OIDC_CLIENT_ID", "groundwork-console")
	t.Setenv("GROUNDWORK_OIDC_ALGORITHMS", "RS256")
	t.Setenv("GROUNDWORK_OIDC_TENANT_CLAIM", "sub")
	t.Setenv("GROUNDWORK_OIDC_TENANT_ALLOWLIST", "acme")
	if _, err := BuildOIDCVerifierFromEnv(); err == nil || !strings.Contains(err.Error(), "must not be") {
		t.Fatalf("GROUNDWORK_OIDC_TENANT_CLAIM=sub must fail validation, got %v", err)
	}
}

func TestOIDCEnvConfigValidation(t *testing.T) {
	// Issuer set with no client id / audience must fail.
	t.Setenv("GROUNDWORK_OIDC_ISSUER", "https://login.microsoftonline.com/example/v2.0")
	t.Setenv("GROUNDWORK_OIDC_CLIENT_ID", "")
	t.Setenv("GROUNDWORK_OIDC_AUDIENCE", "")
	if _, err := BuildOIDCVerifierFromEnv(); err == nil {
		t.Fatal("issuer without client id or audience must fail validation")
	}
	// Non-https issuer must fail.
	t.Setenv("GROUNDWORK_OIDC_CLIENT_ID", "app-id")
	t.Setenv("GROUNDWORK_OIDC_ISSUER", "http://insecure.example")
	if _, err := BuildOIDCVerifierFromEnv(); err == nil {
		t.Fatal("http issuer must fail validation")
	}
	// Tenant allow-list without explicit tenant claim must fail.
	t.Setenv("GROUNDWORK_OIDC_ISSUER", "https://login.microsoftonline.com/example/v2.0")
	t.Setenv("GROUNDWORK_OIDC_TENANT_ALLOWLIST", "acme")
	if _, err := BuildOIDCVerifierFromEnv(); err == nil {
		t.Fatal("tenant allow-list without explicit tenant claim must fail validation")
	}
	t.Setenv("GROUNDWORK_OIDC_TENANT_CLAIM", "tid")
	// Admin roles without explicit roles claim must fail.
	t.Setenv("GROUNDWORK_OIDC_ADMIN_ROLES", "security-admin")
	if _, err := BuildOIDCVerifierFromEnv(); err == nil {
		t.Fatal("admin roles without explicit roles claim must fail validation")
	}
	t.Setenv("GROUNDWORK_OIDC_ADMIN_ROLES_CLAIM", "roles")
	// With all explicit config, the verifier must construct (against the
	// unreachable issuer it fails at discovery, which is the correct
	// fail-at-startup behavior).
	if _, err := BuildOIDCVerifierFromEnv(); err == nil {
		t.Fatal("verifier must fail construction on an unreachable issuer")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
