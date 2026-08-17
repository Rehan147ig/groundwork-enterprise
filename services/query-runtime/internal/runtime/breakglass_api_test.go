// Phase 8.4 break-glass operator access HTTP surface tests: the
// 503-when-unwired nil-safe behavior, admin-scope gating, verified
// operator identity, mandatory reasons, duration caps, the full
// open → use → revoke lifecycle (minted key works, then fails closed),
// and the auth-layer fail-closed guarantee for expired keys.

package runtime_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundwork/query-runtime/internal/breakglass"
	"groundwork/query-runtime/internal/runtime"
)

// stubNotifier is a NotificationService that always delivers
// successfully unless failSend is set — used to keep the break-glass
// lifecycle tests focused on evidence, and to drive notification-failure
// evidence tests.
type stubNotifier struct {
	failSend bool
}

func (n *stubNotifier) SendBreakGlassRequest(context.Context, string, string, string, string, string, string) error {
	if n.failSend {
		return errors.New("stub delivery failure")
	}
	return nil
}

func (n *stubNotifier) SendBreakGlassActivated(context.Context, string, string, string) error {
	if n.failSend {
		return errors.New("stub delivery failure")
	}
	return nil
}

func (n *stubNotifier) SendBreakGlassDenied(context.Context, string, string, string, string, string) error {
	if n.failSend {
		return errors.New("stub delivery failure")
	}
	return nil
}

func (n *stubNotifier) SendBreakGlassTeams(context.Context, string, string, string, string) error {
	if n.failSend {
		return errors.New("stub delivery failure")
	}
	return nil
}

func (n *stubNotifier) AuthorizedAdmin(string, string) bool { return true }

func (n *stubNotifier) VerifySignature(string, string, string) error { return nil }

func newBreakGlassServer(t *testing.T, apiKeys *runtime.MemoryAPIKeyResolver, svc runtime.BreakGlassService) *runtime.Server {
	t.Helper()
	backend := runtime.NewMemoryBackend()
	s := runtime.NewServerWithExecutor(runtime.Config{}, backend, apiKeys, nil)
	s.SetIdentity(testVerifier{secret: "server-secret"}, false)
	if svc != nil {
		s.SetBreakGlassService(svc)
	}
	s.SetNotifier(&stubNotifier{})
	return s
}

// newBreakGlassHarness shares one memory API-key resolver between the
// server and the break-glass service, exactly like cmd/query-runtime
// passes the same resolver as the KeyMinter.
func newBreakGlassHarness(t *testing.T, maxMinutes int, tenant runtime.TenantContext) (*runtime.Server, *runtime.MemoryAPIKeyResolver, *breakglass.Service) {
	t.Helper()
	apiKeys := runtime.NewMemoryAPIKeyResolver(govAdminKey, tenant)
	svc := breakglass.NewService(breakglass.NewMemoryStore(), apiKeys, time.Duration(maxMinutes)*time.Minute)
	return newBreakGlassServer(t, apiKeys, svc), apiKeys, svc
}

func breakGlassRequest(method, path, key, assertion, body string) *http.Request {
	return govRequest(method, path, key, assertion, "", body)
}

func doBreakGlass(t *testing.T, s *runtime.Server, method, path, key, assertion, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := breakGlassRequest(method, path, key, assertion, body)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	return rec
}

type breakGlassOpenResponse struct {
	Grant runtime.BreakGlassGrant `json:"grant"`
	Key   string                  `json:"key"`
}

type breakGlassListResponse struct {
	Grants []runtime.BreakGlassGrant `json:"grants"`
}

type breakGlassGetResponse struct {
	Grant  runtime.BreakGlassGrant   `json:"grant"`
	Events []runtime.BreakGlassEvent `json:"events"`
}

// adminTenant is a break-glass operator with an admin+query key.
func adminTenant() runtime.TenantContext {
	return runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "break-glass-test", Scopes: []string{"admin", "query"},
	}
}

func TestBreakGlassUnavailableWhenNotWired(t *testing.T) {
	apiKeys := runtime.NewMemoryAPIKeyResolver(govAdminKey, adminTenant())
	s := newBreakGlassServer(t, apiKeys, nil)
	rec := doBreakGlass(t, s, http.MethodGet, "/v1/security/break-glass/grants", govAdminKey, "", "")
	if rec.Code != http.StatusServiceUnavailable || govErrorOf(t, rec) != "break_glass_unavailable" {
		t.Fatalf("list: got %d %q, want 503 break_glass_unavailable", rec.Code, rec.Body.String())
	}
	rec = doBreakGlass(t, s, http.MethodGet, "/v1/security/break-glass/grants/grant-1", govAdminKey, "", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("get: got %d, want 503", rec.Code)
	}
	rec = doBreakGlass(t, s, http.MethodPost, "/v1/security/break-glass/grants", govAdminKey, adminTokenFor(t, govOwner), `{"reason":"incident","duration_minutes":15}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("open: got %d, want 503", rec.Code)
	}
	rec = doBreakGlass(t, s, http.MethodPost, "/v1/security/break-glass/grants/grant-1/revoke", govAdminKey, adminTokenFor(t, govOwner), `{"reason":"no longer needed"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("revoke: got %d, want 503", rec.Code)
	}
}

func TestBreakGlassRequiresAdminScope(t *testing.T) {
	tenant := runtime.TenantContext{
		TenantID: govTenant, Region: govRegion, KeyName: "query-only", Scopes: []string{"query"},
	}
	apiKeys := runtime.NewMemoryAPIKeyResolver(govAdminKey, tenant)
	svc := breakglass.NewService(breakglass.NewMemoryStore(), apiKeys, time.Hour)
	s := newBreakGlassServer(t, apiKeys, svc)
	rec := doBreakGlass(t, s, http.MethodGet, "/v1/security/break-glass/grants", govAdminKey, "", "")
	if rec.Code != http.StatusForbidden || govErrorOf(t, rec) != "insufficient_scope" {
		t.Fatalf("got %d %q, want 403 insufficient_scope", rec.Code, rec.Body.String())
	}
}

func TestBreakGlassOpenRequiresVerifiedIdentity(t *testing.T) {
	_, apiKeys, svc := newBreakGlassHarness(t, 60, adminTenant())
	s := newBreakGlassServer(t, apiKeys, svc)
	rec := doBreakGlass(t, s, http.MethodPost, "/v1/security/break-glass/grants", govAdminKey, "", `{"reason":"incident","duration_minutes":15}`)
	if rec.Code != http.StatusUnauthorized || govErrorOf(t, rec) != "verified_identity_required" {
		t.Fatalf("got %d %q, want 401 verified_identity_required", rec.Code, rec.Body.String())
	}
}

func TestBreakGlassOpenValidation(t *testing.T) {
	_, apiKeys, svc := newBreakGlassHarness(t, 60, adminTenant())
	s := newBreakGlassServer(t, apiKeys, svc)

	rec := doBreakGlass(t, s, http.MethodPost, "/v1/security/break-glass/grants", govAdminKey, adminTokenFor(t, govOwner), `{"duration_minutes":15}`)
	if rec.Code != http.StatusBadRequest || govErrorOf(t, rec) != "reason_required" {
		t.Fatalf("empty reason: got %d %q, want 400 reason_required", rec.Code, rec.Body.String())
	}

	rec = doBreakGlass(t, s, http.MethodPost, "/v1/security/break-glass/grants", govAdminKey, adminTokenFor(t, govOwner), `{"reason":"incident"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing duration: got %d, want 400", rec.Code)
	}

	rec = doBreakGlass(t, s, http.MethodPost, "/v1/security/break-glass/grants", govAdminKey, adminTokenFor(t, govOwner), `{"reason":"incident","duration_minutes":61}`)
	if rec.Code != http.StatusBadRequest || govErrorOf(t, rec) != "break_glass_open_failed" {
		t.Fatalf("over cap: got %d %q, want 400 break_glass_open_failed", rec.Code, rec.Body.String())
	}
}

func TestBreakGlassLifecycleAndRevokeFailsClosed(t *testing.T) {
	_, apiKeys, _ := newBreakGlassHarness(t, 60, adminTenant())
	tenant := adminTenant()
	svc := breakglass.NewService(breakglass.NewMemoryStore(), apiKeys, time.Hour)
	s := newBreakGlassServer(t, apiKeys, svc)
	_ = tenant

	rec := doBreakGlass(t, s, http.MethodPost, "/v1/security/break-glass/grants", govAdminKey, adminTokenFor(t, govOwner), `{"reason":"prod incident on-e-call","duration_minutes":30}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("open: got %d %s, want 201", rec.Code, rec.Body.String())
	}
	var opened breakGlassOpenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &opened); err != nil {
		t.Fatalf("decode open response: %v", err)
	}
	if opened.Grant.Status != runtime.BreakGlassStatusActive {
		t.Fatalf("grant status %q, want active", opened.Grant.Status)
	}
	if opened.Key == "" || !strings.HasPrefix(opened.Key, "gw_live_") {
		t.Fatalf("minted key %q, want gw_live_ prefix", opened.Key)
	}
	if opened.Grant.KeyPrefix == "" || opened.Grant.DurationMinutes != 30 || opened.Grant.OperatorPrincipalID != govOwner {
		t.Fatalf("grant missing bindings: %+v", opened.Grant)
	}

	// The minted key is a working admin-scoped key: it can list grants.
	rec = doBreakGlass(t, s, http.MethodGet, "/v1/security/break-glass/grants", opened.Key, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("minted key list: got %d %s, want 200", rec.Code, rec.Body.String())
	}

	// The grant's event chain holds the 'opened' evidence.
	rec = doBreakGlass(t, s, http.MethodGet, "/v1/security/break-glass/grants/"+opened.Grant.ID, govAdminKey, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get grant: got %d %s, want 200", rec.Code, rec.Body.String())
	}
	var detail breakGlassGetResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if len(detail.Events) != 1 || detail.Events[0].EventType != runtime.BreakGlassEventOpened {
		t.Fatalf("events %+v, want one 'opened'", detail.Events)
	}

	// Revoke with a mandatory reason; the minted key fails closed on
	// its next use.
	rec = doBreakGlass(t, s, http.MethodPost, "/v1/security/break-glass/grants/"+opened.Grant.ID+"/revoke", govAdminKey, adminTokenFor(t, govOwner), `{"reason":"incident resolved"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: got %d %s, want 200", rec.Code, rec.Body.String())
	}
	var revoked runtime.BreakGlassGrant
	if err := json.Unmarshal(rec.Body.Bytes(), &revoked); err != nil {
		t.Fatalf("decode revoke response: %v", err)
	}
	if revoked.Status != runtime.BreakGlassStatusRevoked || revoked.RevokedBy != govOwner {
		t.Fatalf("revoked grant %+v", revoked)
	}
	rec = doBreakGlass(t, s, http.MethodGet, "/v1/security/break-glass/grants", opened.Key, "", "")
	if rec.Code != http.StatusUnauthorized || govErrorOf(t, rec) != "invalid_api_key" {
		t.Fatalf("minted key after revoke: got %d %q, want 401 invalid_api_key", rec.Code, rec.Body.String())
	}

	// Revoking again fails: the grant is no longer active.
	rec = doBreakGlass(t, s, http.MethodPost, "/v1/security/break-glass/grants/"+opened.Grant.ID+"/revoke", govAdminKey, adminTokenFor(t, govOwner), `{"reason":"again"}`)
	if rec.Code != http.StatusConflict || govErrorOf(t, rec) != "break_glass_grant_not_active" {
		t.Fatalf("double revoke: got %d %q, want 409 break_glass_grant_not_active", rec.Code, rec.Body.String())
	}
}

func TestBreakGlassRevokeRequiresReason(t *testing.T) {
	_, apiKeys, svc := newBreakGlassHarness(t, 60, adminTenant())
	s := newBreakGlassServer(t, apiKeys, svc)
	rec := doBreakGlass(t, s, http.MethodPost, "/v1/security/break-glass/grants/grant-1/revoke", govAdminKey, adminTokenFor(t, govOwner), `{}`)
	if rec.Code != http.StatusBadRequest || govErrorOf(t, rec) != "reason_required" {
		t.Fatalf("got %d %q, want 400 reason_required", rec.Code, rec.Body.String())
	}
}

// TestBreakGlassExpiredKeyFailsClosed proves the auth-layer guarantee
// break-glass relies on: a key past its expiry is rejected with 401
// api_key_expired on the very next request, before any handler runs.
func TestBreakGlassExpiredKeyFailsClosed(t *testing.T) {
	tenant := adminTenant()
	apiKeys := runtime.NewMemoryAPIKeyResolver(govAdminKey, tenant)
	svc := breakglass.NewService(breakglass.NewMemoryStore(), apiKeys, time.Hour)
	s := newBreakGlassServer(t, apiKeys, svc)

	// Mint a key whose expiry is already in the past (simulates a
	// break-glass grant whose window elapsed between open and use).
	expired, err := apiKeys.Create(context.Background(), runtime.TenantContext{TenantID: govTenant, Region: govRegion}, runtime.CreateAPIKeyRequest{
		Name:      "break-glass",
		Scopes:    []string{"admin"},
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("create expired key: %v", err)
	}
	rec := doBreakGlass(t, s, http.MethodGet, "/v1/security/break-glass/grants", expired.Key, "", "")
	if rec.Code != http.StatusUnauthorized || govErrorOf(t, rec) != "api_key_expired" {
		t.Fatalf("expired key: got %d %q, want 401 api_key_expired", rec.Code, rec.Body.String())
	}
}
