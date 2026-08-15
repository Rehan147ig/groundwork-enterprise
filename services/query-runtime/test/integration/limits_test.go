//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundwork/query-runtime/internal/runtime"

	"github.com/golang-jwt/jwt/v5"
)

// integrationVerifier mirrors the production JWT verifier (HS256, expiry
// required, "none" rejected) so the HTTP stack runs in verified-identity
// mode exactly like production.
type integrationVerifier struct{ secret string }

func (v integrationVerifier) Verify(_ context.Context, token string) (runtime.Identity, error) {
	tok, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(v.secret), nil
	}, jwt.WithExpirationRequired())
	if err != nil || !tok.Valid {
		return runtime.Identity{}, errors.New("invalid token")
	}
	sub, _ := tok.Claims.(jwt.MapClaims)["sub"].(string)
	return runtime.Identity{UserID: sub, Subject: sub, Verified: true}, nil
}

func identityToken(t *testing.T, subject string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": subject,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := tok.SignedString([]byte("integration-secret"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// TestTenantRateLimitEnforcedOnQuery proves the per-tenant rate limiter
// end-to-end against the REAL stack (Qdrant + SpiceDB + Postgres): the
// first query executes and returns the authorized document, the second
// (same tenant, same fixed window) is rejected with 429
// rate_limit_exceeded + Retry-After before it ever reaches the engine,
// and the health endpoint stays exempt.
func TestTenantRateLimitEnforcedOnQuery(t *testing.T) {
	requireFullStack(t)
	db := openDB(t)

	tenant := "tenant_rate_" + unique()
	collection := "gw_int_rate_" + unique()
	seedQdrantChunk(t, collection, tenant, testDoc, "Finance policy chunk for the tenant rate-limit scenario.")

	client := newSpiceDBChecker(t)
	checker := runtime.NewACLAdapter(client)
	writeSpiceDBRelationship(t, client, tenant, "user:user_alice", "viewer", "document:"+testDoc)

	eng := newEngine(qdrantSearcher(collection, startStubEmbedder(t)), checker, postgresAuditor(db))
	apiKeys := runtime.NewMemoryAPIKeyResolver("gw_int_rate_key", runtime.TenantContext{
		TenantID: tenant, Region: testRegion, KeyName: "rate-int-test",
	})
	server := runtime.NewServerWithExecutor(runtime.Config{}, runtime.NewMemoryBackend(), apiKeys, eng)
	server.SetIdentity(integrationVerifier{secret: "integration-secret"}, false)
	server.SetTenantRateLimiter(runtime.NewTenantRateLimiterWindow(1, time.Minute))

	doQuery := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/query", bytes.NewBufferString(
			`{"user_id":"user_alice","question":"finance policy"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Groundwork-API-Key", "gw_int_rate_key")
		req.Header.Set("X-Groundwork-User-Assertion", identityToken(t, "user_alice"))
		rec := httptest.NewRecorder()
		server.Routes().ServeHTTP(rec, req)
		return rec
	}

	first := doQuery()
	if first.Code != http.StatusOK {
		t.Fatalf("first query expected 200, got %d: %s", first.Code, first.Body.String())
	}
	if !strings.Contains(first.Body.String(), testDoc) {
		t.Fatalf("first query must return the authorized document %q; body: %s", testDoc, first.Body.String())
	}

	second := doQuery()
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second query expected 429, got %d: %s", second.Code, second.Body.String())
	}
	if !strings.Contains(second.Body.String(), "rate_limit_exceeded") {
		t.Fatalf("expected rate_limit_exceeded error body, got %s", second.Body.String())
	}
	if ra := second.Header().Get("Retry-After"); ra == "" {
		t.Fatal("expected Retry-After header on the 429")
	}

	health := httptest.NewRecorder()
	server.Routes().ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("healthz must stay exempt from tenant rate limits, got %d: %s", health.Code, health.Body.String())
	}
}
