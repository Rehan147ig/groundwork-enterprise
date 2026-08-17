// Milestone 5 Slack interactive actions endpoint tests:
// /v1/security/slack/actions must reject unsigned/replayed requests,
// deny non-allowlisted admins, and drive the four-eyes break-glass
// flow (approve / reject / revoke) with the actor recorded as
// "slack:<user-id>".

package runtime_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"groundwork/query-runtime/internal/breakglass"
	"groundwork/query-runtime/internal/httpclient"
	"groundwork/query-runtime/internal/notifications"
	"groundwork/query-runtime/internal/runtime"
)

const slackTestSecret = "slack-test-secret-0123456789"

func slackSign(secret, timestamp, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "v0:%s:%s", timestamp, body)
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

func slackActionBody(actionID, callback, value, userID string) string {
	payload, _ := json.Marshal(map[string]any{
		"type":        "block_actions",
		"user":        map[string]any{"id": userID, "name": "ana"},
		"channel":     map[string]any{"id": "C1", "name": "ops"},
		"callback_id": callback,
		"actions":     []map[string]any{{"action_id": actionID, "value": value}},
	})
	return url.Values{"payload": {string(payload)}}.Encode()
}

func slackActionRequest(t *testing.T, secret, body string, ts int64) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/security/slack/actions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Slack-Signature", slackSign(secret, strconv.FormatInt(ts, 10), body))
	return req
}

func doSlackAction(t *testing.T, s *runtime.Server, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	return rec
}

// newSlackActionServer wires a real notifier (real signature checks +
// server-side admin allowlist) with a webhook resolver that always
// fails, so confirmation notifications fail fast into evidence without
// touching the network.
func newSlackActionServer(t *testing.T) (*runtime.Server, *runtime.MemoryAPIKeyResolver, *breakglass.Service) {
	t.Helper()
	tenant := adminTenant()
	apiKeys := runtime.NewMemoryAPIKeyResolver(govAdminKey, tenant)
	svc := breakglass.NewService(breakglass.NewMemoryStore(), apiKeys, time.Hour)
	backend := runtime.NewMemoryBackend()
	s := runtime.NewServerWithExecutor(runtime.Config{}, backend, apiKeys, nil)
	s.SetIdentity(testVerifier{secret: "server-secret"}, false)
	s.SetBreakGlassService(svc)
	noWebhook := func(context.Context, string) (string, error) {
		return "", errors.New("webhook not configured")
	}
	notifier := notifications.New(
		httpclient.DefaultPool().Client(notifications.DefaultTimeout),
		noWebhook, noWebhook,
		map[string][]string{"TENANT_ACME": {"UADMIN2"}},
		slackTestSecret,
	)
	s.SetNotifier(notifier)
	return s, apiKeys, svc
}

func openFourEyesGrant(t *testing.T, s *runtime.Server) string {
	t.Helper()
	rec := doBreakGlass(t, s, http.MethodPost, "/v1/security/break-glass/grants", govAdminKey, adminTokenFor(t, govOwner),
		`{"reason":"prod incident","duration_minutes":30,"admin2_id":"slack:UADMIN2"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("open four-eyes: %d %s", rec.Code, rec.Body.String())
	}
	var opened breakGlassOpenResponse
	decodeGov(t, rec, &opened)
	if opened.Grant.Status != runtime.BreakGlassStatusPendingApproval {
		t.Fatalf("status = %q, want pending_approval", opened.Grant.Status)
	}
	return opened.Grant.ID
}

func TestSlackActionRejectsBadSignature(t *testing.T) {
	s, _, _ := newSlackActionServer(t)
	body := slackActionBody(notifications.ActionApprove, "breakglass:tenant-acme:grant-9", "tenant-acme|grant-9", "UADMIN2")

	rec := doSlackAction(t, s, slackActionRequest(t, "wrong-secret", body, time.Now().Unix()))
	if rec.Code != http.StatusUnauthorized || govErrorOf(t, rec) != "invalid_signature" {
		t.Fatalf("bad secret: %d %s", rec.Code, rec.Body.String())
	}

	noSig := httptest.NewRequest(http.MethodPost, "/v1/security/slack/actions", strings.NewReader(body))
	rec = doSlackAction(t, s, noSig)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing signature: %d", rec.Code)
	}
}

func TestSlackActionRejectsReplay(t *testing.T) {
	s, _, _ := newSlackActionServer(t)
	body := slackActionBody(notifications.ActionApprove, "breakglass:tenant-acme:grant-9", "tenant-acme|grant-9", "UADMIN2")
	// A captured request replayed 10 minutes later.
	old := time.Now().Add(-10 * time.Minute).Unix()
	rec := doSlackAction(t, s, slackActionRequest(t, slackTestSecret, body, old))
	if rec.Code != http.StatusUnauthorized || govErrorOf(t, rec) != "replay_window" {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSlackActionDeniesUnauthorizedAdmin(t *testing.T) {
	s, _, _ := newSlackActionServer(t)
	grantID := openFourEyesGrant(t, s)
	body := slackActionBody(notifications.ActionApprove, "breakglass:tenant-acme:"+grantID, "tenant-acme|"+grantID, "UINTRUDER")
	rec := doSlackAction(t, s, slackActionRequest(t, slackTestSecret, body, time.Now().Unix()))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("intruder approve: %d %s, want 403", rec.Code, rec.Body.String())
	}
	// The grant must still be pending.
	rec = doBreakGlass(t, s, http.MethodGet, "/v1/security/break-glass/grants/"+grantID, govAdminKey, "", "")
	var detail breakGlassGetResponse
	decodeGov(t, rec, &detail)
	if detail.Grant.Status != runtime.BreakGlassStatusPendingApproval {
		t.Fatalf("grant state changed after forbidden action: %q", detail.Grant.Status)
	}
}

func TestSlackActionApproveActivatesGrant(t *testing.T) {
	s, _, _ := newSlackActionServer(t)
	grantID := openFourEyesGrant(t, s)
	body := slackActionBody(notifications.ActionApprove, "breakglass:tenant-acme:"+grantID, "tenant-acme|"+grantID, "UADMIN2")
	rec := doSlackAction(t, s, slackActionRequest(t, slackTestSecret, body, time.Now().Unix()))
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	rec = doBreakGlass(t, s, http.MethodGet, "/v1/security/break-glass/grants/"+grantID, govAdminKey, "", "")
	var detail breakGlassGetResponse
	decodeGov(t, rec, &detail)
	if detail.Grant.Status != runtime.BreakGlassStatusActive || detail.Grant.KeyID == 0 {
		t.Fatalf("grant not activated: %+v", detail.Grant)
	}
	if detail.Grant.Approver2 != "slack:UADMIN2" {
		t.Fatalf("approver2 = %q, want slack:UADMIN2", detail.Grant.Approver2)
	}
	var sawApproved, sawOpened bool
	for _, ev := range detail.Events {
		if ev.EventType == runtime.BreakGlassEventApprovedByAdmin2 && ev.ActorPrincipalID == "slack:UADMIN2" {
			sawApproved = true
		}
		if ev.EventType == runtime.BreakGlassEventOpened {
			sawOpened = true
		}
	}
	if !sawOpened || !sawApproved {
		t.Fatalf("events missing opened/approved: %+v", detail.Events)
	}
	// The notification confirmation delivery failed (no webhook) and
	// must be recorded as evidence — the activation is never silent.
	var sawFailed bool
	for _, ev := range detail.Events {
		if ev.EventType == runtime.BreakGlassEventNotificationFailed {
			sawFailed = true
		}
	}
	if !sawFailed {
		t.Fatalf("expected notification_failed evidence, events: %+v", detail.Events)
	}
}

func TestSlackActionRejectDeniesGrant(t *testing.T) {
	s, _, _ := newSlackActionServer(t)
	grantID := openFourEyesGrant(t, s)
	body := slackActionBody(notifications.ActionReject, "breakglass:tenant-acme:"+grantID, "tenant-acme|"+grantID, "UADMIN2")
	rec := doSlackAction(t, s, slackActionRequest(t, slackTestSecret, body, time.Now().Unix()))
	if rec.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body.String())
	}
	rec = doBreakGlass(t, s, http.MethodGet, "/v1/security/break-glass/grants/"+grantID, govAdminKey, "", "")
	var detail breakGlassGetResponse
	decodeGov(t, rec, &detail)
	if detail.Grant.Status != runtime.BreakGlassStatusRejected {
		t.Fatalf("status = %q, want rejected", detail.Grant.Status)
	}
}

func TestSlackActionRevokeTerminatesGrant(t *testing.T) {
	s, _, _ := newSlackActionServer(t)
	rec := doBreakGlass(t, s, http.MethodPost, "/v1/security/break-glass/grants", govAdminKey, adminTokenFor(t, govOwner),
		`{"reason":"on-call fix","duration_minutes":30}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("open: %d %s", rec.Code, rec.Body.String())
	}
	var opened breakGlassOpenResponse
	decodeGov(t, rec, &opened)
	body := slackActionBody(notifications.ActionRevoke, "breakglass:tenant-acme:"+opened.Grant.ID, "tenant-acme|"+opened.Grant.ID, "UADMIN2")
	rec = doSlackAction(t, s, slackActionRequest(t, slackTestSecret, body, time.Now().Unix()))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	rec = doBreakGlass(t, s, http.MethodGet, "/v1/security/break-glass/grants/"+opened.Grant.ID, govAdminKey, "", "")
	var detail breakGlassGetResponse
	decodeGov(t, rec, &detail)
	if detail.Grant.Status != runtime.BreakGlassStatusRevoked {
		t.Fatalf("status = %q, want revoked", detail.Grant.Status)
	}
}

func TestSlackActionNonBreakGlassAcknowledged(t *testing.T) {
	s, _, _ := newSlackActionServer(t)
	body := slackActionBody("other.thing", "other:callback", "x|y", "UADMIN2")
	rec := doSlackAction(t, s, slackActionRequest(t, slackTestSecret, body, time.Now().Unix()))
	if rec.Code != http.StatusOK {
		t.Fatalf("non break-glass action: %d, want 200 ack", rec.Code)
	}
}
