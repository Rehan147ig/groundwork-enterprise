// Milestone 5 notification delivery tests: Slack signature verification
// + replay protection, endpoint allowlisting (fail closed), bounded
// retry on transient failures, interactive action parsing with
// cross-tenant confusion protection, and server-side role checks.

package notifications

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"groundwork/query-runtime/internal/httpclient"
)

const testSecret = "0123456789abcdef"

// sign computes the v0 Slack signature over the raw body.
func sign(secret, timestamp, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "v0:%s:%s", timestamp, body)
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySlackSignature(t *testing.T) {
	body := `{"type":"block_actions","actions":[]}`
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := sign(testSecret, ts, body)

	if err := VerifySlackSignature(testSecret, ts, body, sig, time.Now()); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := VerifySlackSignature("wrong-secret", ts, body, sig, time.Now()); err != ErrInvalidSignature {
		t.Fatalf("wrong secret: err = %v, want ErrInvalidSignature", err)
	}
	if err := VerifySlackSignature(testSecret, ts, body+"x", sig, time.Now()); err != ErrInvalidSignature {
		t.Fatalf("tampered body: err = %v, want ErrInvalidSignature", err)
	}
	if err := VerifySlackSignature(testSecret, ts, body, sign(testSecret, ts, body)+"0", time.Now()); err != ErrInvalidSignature {
		t.Fatalf("tampered signature: err = %v, want ErrInvalidSignature", err)
	}
	if err := VerifySlackSignature("", ts, body, sig, time.Now()); err != ErrInvalidSignature {
		t.Fatalf("empty secret: err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifySlackSignatureReplayWindow(t *testing.T) {
	body := `{"type":"block_actions"}`
	now := time.Now()
	// A captured request replayed 10 minutes later must be rejected.
	oldTS := strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10)
	sig := sign(testSecret, oldTS, body)
	if err := VerifySlackSignature(testSecret, oldTS, body, sig, now); err != ErrReplayWindow {
		t.Fatalf("old timestamp: err = %v, want ErrReplayWindow", err)
	}
	// Future timestamps are equally rejected.
	futureTS := strconv.FormatInt(now.Add(10*time.Minute).Unix(), 10)
	if err := VerifySlackSignature(testSecret, futureTS, body, sign(testSecret, futureTS, body), now); err != ErrReplayWindow {
		t.Fatalf("future timestamp: err = %v, want ErrReplayWindow", err)
	}
}

func TestValidateWebhookURLAllowlist(t *testing.T) {
	for _, ok := range []string{
		"https://hooks.slack.com/services/T/B/X",
		"https://acme.webhook.office.com/webhookb2/abc",
	} {
		if err := validateWebhookURL(ok); err != nil {
			t.Fatalf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://hooks.slack.com/services/T/B/X", // not https
		"https://evil.example.com/hooks",
		"https://hooks.slack.com.evil.example.com/x", // suffix spoof
		"file:///etc/passwd",
		"",
		"not a url",
	} {
		if err := validateWebhookURL(bad); !errors.Is(err, ErrEndpointNotAllowlisted) {
			t.Fatalf("%q: err = %v, want ErrEndpointNotAllowlisted", bad, err)
		}
	}
}

// deliveryHarness swaps the allowlist and retry delay so tests can run
// against a local TLS server (the https-only allowlist invariant is
// kept: plain http endpoints are still rejected).
func deliveryHarness(t *testing.T, handler http.Handler) (*Notifier, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	oldHosts := allowedWebhookHosts
	oldBackoff := retryBase
	allowedWebhookHosts = []string{"127.0.0.1"}
	retryBase = time.Millisecond
	t.Cleanup(func() {
		allowedWebhookHosts = oldHosts
		retryBase = oldBackoff
		srv.Close()
	})
	client := httpclient.DefaultPool().Client(DefaultTimeout)
	pool, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport from pool")
	}
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	pool.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	n := New(client, func(context.Context, string) (string, error) { return srv.URL, nil }, nil, nil, testSecret)
	return n, srv
}

func TestSendSuccess(t *testing.T) {
	var got atomic.Value
	n, _ := deliveryHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got.Store(body)
		w.WriteHeader(http.StatusOK)
	}))
	if err := n.SendBreakGlassRequest(context.Background(), "tenant-acme", "grant-1", "alice", "incident", "30 min", ""); err != nil {
		t.Fatalf("send: %v", err)
	}
	body, _ := got.Load().(map[string]any)
	if body == nil || body["text"] == nil {
		t.Fatal("no message received")
	}
	if _, hasActions := body["attachments"]; hasActions {
		t.Fatal("legacy flow must not carry action buttons")
	}
}

func TestSendRetriesTransientThenSucceeds(t *testing.T) {
	var attempts atomic.Int32
	n, _ := deliveryHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	if err := n.SendBreakGlassRequest(context.Background(), "tenant-acme", "grant-1", "alice", "incident", "30 min", ""); err != nil {
		t.Fatalf("send after retries: %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("attempts = %d, want 3 (initial + 2 retries)", attempts.Load())
	}
}

func TestSendDoesNotRetryPermanent(t *testing.T) {
	var attempts atomic.Int32
	n, _ := deliveryHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	if err := n.SendBreakGlassRequest(context.Background(), "tenant-acme", "grant-1", "alice", "incident", "30 min", ""); err == nil {
		t.Fatal("4xx must fail")
	}
	if attempts.Load() != 1 {
		t.Fatalf("attempts = %d, want 1 (4xx never retried)", attempts.Load())
	}
}

func TestSendRejectsNonAllowlistedEndpoint(t *testing.T) {
	client := httpclient.DefaultPool().Client(DefaultTimeout)
	n := New(client, func(context.Context, string) (string, error) {
		return "https://evil.example.com/hook", nil
	}, nil, nil, testSecret)
	if err := n.SendBreakGlassRequest(context.Background(), "tenant-acme", "grant-1", "alice", "incident", "30 min", ""); !errors.Is(err, ErrEndpointNotAllowlisted) {
		t.Fatalf("err = %v, want ErrEndpointNotAllowlisted", err)
	}
}

func TestSendFourEyesCarriesButtons(t *testing.T) {
	var got atomic.Value
	n, _ := deliveryHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got.Store(body)
		w.WriteHeader(http.StatusOK)
	}))
	if err := n.SendBreakGlassRequest(context.Background(), "tenant-acme", "grant-1", "alice", "incident", "30 min", "slack:UADMIN2"); err != nil {
		t.Fatalf("send: %v", err)
	}
	body, _ := got.Load().(map[string]any)
	atts, _ := body["attachments"].([]any)
	if len(atts) != 1 {
		t.Fatalf("attachments = %v, want one with approve/reject", body["attachments"])
	}
	att := atts[0].(map[string]any)
	if att["callback_id"] != "breakglass:tenant-acme:grant-1" {
		t.Fatalf("callback_id = %v", att["callback_id"])
	}
	actions := att["actions"].([]any)
	if len(actions) != 2 {
		t.Fatalf("actions = %v, want approve+reject", actions)
	}
}

func TestParseSlackActionContext(t *testing.T) {
	payload := `{"type":"block_actions","user":{"id":"UADMIN2","name":"ana"},
		"channel":{"id":"C1","name":"ops"},
		"callback_id":"breakglass:tenant-acme:grant-9",
		"actions":[{"action_id":"breakglass.approve","value":"tenant-acme|grant-9"}]}`
	a, err := ParseSlackAction([]byte(payload))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	actx, err := a.Context()
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	if actx.Action != ActionApprove || actx.TenantID != "tenant-acme" || actx.GrantID != "grant-9" || actx.UserID != "UADMIN2" {
		t.Fatalf("context = %+v", actx)
	}

	// Cross-tenant confusion: callback and value disagree.
	mismatch := `{"type":"block_actions","user":{"id":"U"},
		"callback_id":"breakglass:tenant-other:grant-9",
		"actions":[{"action_id":"breakglass.approve","value":"tenant-acme|grant-9"}]}`
	a, err = ParseSlackAction([]byte(mismatch))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := a.Context(); err != ErrBadActionContext {
		t.Fatalf("mismatched context: err = %v, want ErrBadActionContext", err)
	}

	// Non break-glass action.
	other := `{"type":"block_actions","user":{"id":"U"},
		"callback_id":"other:stuff",
		"actions":[{"action_id":"other.thing","value":"x|y"}]}`
	a, err = ParseSlackAction([]byte(other))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := a.Context(); err != ErrNotBreakGlassAction {
		t.Fatalf("other action: err = %v, want ErrNotBreakGlassAction", err)
	}
}

func TestAuthorizedAdmin(t *testing.T) {
	client := httpclient.DefaultPool().Client(DefaultTimeout)
	n := New(client, nil, nil, map[string][]string{
		"":            {"UGLOBAL"},
		"TENANT_ACME": {"UACME"},
	}, testSecret)
	if !n.AuthorizedAdmin("tenant-acme", "UACME") {
		t.Fatal("tenant-scoped admin must be authorized")
	}
	if !n.AuthorizedAdmin("tenant-any", "UGLOBAL") {
		t.Fatal("global admin must be authorized")
	}
	if n.AuthorizedAdmin("tenant-acme", "UGLOBAL") {
		t.Fatal("tenant-scoped allowlist must override the global one")
	}
	if n.AuthorizedAdmin("tenant-acme", "UINTRUDER") {
		t.Fatal("non-admin must be denied")
	}
	if n.AuthorizedAdmin("", "UINTRUDER") {
		t.Fatal("unknown user denied")
	}

	closed := New(client, nil, nil, nil, testSecret)
	if closed.AuthorizedAdmin("tenant-acme", "UGLOBAL") {
		t.Fatal("no allowlist configured must fail closed")
	}
}

func TestNotifierVerifySignature(t *testing.T) {
	client := httpclient.DefaultPool().Client(DefaultTimeout)
	n := New(client, nil, nil, nil, testSecret)
	body := `{"type":"block_actions"}`
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	if err := n.VerifySignature(ts, body, sign(testSecret, ts, body)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	noSecret := New(client, nil, nil, nil, "")
	if err := noSecret.VerifySignature(ts, body, sign(testSecret, ts, body)); err != ErrInvalidSignature {
		t.Fatalf("no secret: err = %v, want ErrInvalidSignature", err)
	}
}
