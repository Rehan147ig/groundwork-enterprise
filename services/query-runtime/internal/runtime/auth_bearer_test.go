package runtime

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Enterprise OIDC (Phase 4) wire-level tests: the console forwards the
// IdP-verified user JWT as "Authorization: Bearer <id_token>" while the
// tenant API key travels in X-Groundwork-API-Key. The runtime must treat
// JWT-shaped Bearer values as user assertions — never as API keys — so
// both channels coexist without ambiguity. API keys are dot-free
// (gw_live_<hex>_<hex>; bootstrap keys like gw_test_key), so a three-
// segment JWT can never collide.

func TestExtractAPIKeyIgnoresBearerJWT(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/query", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig")
	req.Header.Set("X-Groundwork-API-Key", "gw_test_key")
	if got := extractAPIKey(req); got != "gw_test_key" {
		t.Fatalf("JWT in Authorization must not shadow X-Groundwork-API-Key, got %q", got)
	}
}

func TestExtractAPIKeyRejectsJWTSoleCredential(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/query", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig")
	if got := extractAPIKey(req); got != "" {
		t.Fatalf("a bare Bearer JWT is an identity, not an API key; got %q", got)
	}
}

func TestExtractAPIKeyBearerKeyStillResolves(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/query", nil)
	req.Header.Set("Authorization", "Bearer gw_test_key")
	if got := extractAPIKey(req); got != "gw_test_key" {
		t.Fatalf("dot-free Bearer API key must still resolve, got %q", got)
	}
	req.Header.Del("Authorization")
	req.Header.Set("X-Groundwork-API-Key", "gw_test_key")
	if got := extractAPIKey(req); got != "gw_test_key" {
		t.Fatalf("X-Groundwork-API-Key must resolve, got %q", got)
	}
}

func TestExtractUserAssertionPrecedence(t *testing.T) {
	const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig"

	req := httptest.NewRequest(http.MethodPost, "/v1/query", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	if got := extractUserAssertion(req); got != jwt {
		t.Fatalf("Bearer JWT must be read as the user assertion, got %q", got)
	}

	req.Header.Set("X-Groundwork-User-Assertion", "header-jwt")
	if got := extractUserAssertion(req); got != "header-jwt" {
		t.Fatalf("X-Groundwork-User-Assertion must win over Bearer, got %q", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/query", nil)
	req.Header.Set("Authorization", "Bearer gw_test_key")
	if got := extractUserAssertion(req); got != "" {
		t.Fatalf("a dot-free Bearer API key must NOT be read as an assertion, got %q", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/query", nil)
	if got := extractUserAssertion(req); got != "" {
		t.Fatalf("no assertion headers -> empty, got %q", got)
	}
}

// TestQueryAcceptsIdentityViaBearerJWT is the enterprise end-to-end wire
// test: tenant key in X-Groundwork-API-Key, IdP-verified user JWT in
// Authorization: Bearer, OIDC identity verifier wired, demo identity OFF.
// The verified subject must become req.UserID and the body-supplied
// user_id must be ignored.
func TestQueryAcceptsIdentityViaBearerJWT(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	server := newTestServer(Config{})
	server.SetIdentity(oidcVerifier(t, iss, nil), false)

	body := `{"user_id":"attacker","question":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/query", bytes.NewBufferString(body))
	req.Header.Set("X-Groundwork-API-Key", "gw_test_key")
	req.Header.Set("Authorization", "Bearer "+iss.token(t, nil))
	rec := httptest.NewRecorder()

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"user_id":"sub-alice"`) {
		t.Fatalf("identity must come from the verified Bearer JWT, got %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "attacker") {
		t.Fatalf("body user_id was trusted over the verified identity: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"tenant_id":"tenant_demo"`) {
		t.Fatalf("tenant must still come from the API key: %s", rec.Body.String())
	}
}

// TestQueryRejectsTamperedBearerJWT proves a JWT-shaped Bearer value is
// actually verified — tampering fails closed with 401, never falls back.
func TestQueryRejectsTamperedBearerJWT(t *testing.T) {
	iss := newOIDCTestIssuer(t)
	server := newTestServer(Config{})
	server.SetIdentity(oidcVerifier(t, iss, nil), false)

	good := iss.token(t, nil)
	bad := good[:len(good)-3] + "abc"

	body := `{"user_id":"alice","question":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/query", bytes.NewBufferString(body))
	req.Header.Set("X-Groundwork-API-Key", "gw_test_key")
	req.Header.Set("Authorization", "Bearer "+bad)
	rec := httptest.NewRecorder()

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("tampered Bearer JWT must fail closed with 401, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"error":"invalid_identity_assertion"`) {
		t.Fatalf("expected invalid_identity_assertion, got %s", rec.Body.String())
	}
}

// TestBearerAPIKeyOnlyKeepsDemoIdentity proves backward compatibility:
// a dot-free API key in Authorization still authenticates and, on a
// demo-enabled server, still reaches the demo identity path.
func TestBearerAPIKeyOnlyKeepsDemoIdentity(t *testing.T) {
	server := newTestServer(Config{}) // allowDemoIdentity = true

	body := `{"user_id":"demo_user","question":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/query", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer gw_test_key")
	rec := httptest.NewRecorder()

	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"user_id":"demo_user"`) {
		t.Fatalf("demo identity path must be unchanged, got %s", rec.Body.String())
	}
}
