package runtime

import (
	"io"
	"net/http"
	"strings"
	"time"

	aclsyncwebhook "groundwork/query-runtime/internal/aclsyncwebhook"
	gwmetrics "groundwork/query-runtime/internal/metrics"
)

// ACLSyncWebhookHandler serves the real-time IAM sync webhook
// endpoints:
//
//	POST /v1/security/acl-sync/entra/{tenant_id}  Entra ID lifecycle notifications
//	POST /v1/security/acl-sync/okta/{tenant_id}   Okta system-log events
//
// Authentication is the provider signature (X-Ms-Connector-Sig hex
// HMAC / X-Okta-Signature base64 HMAC over the raw body with the
// configured shared secret) — the providers cannot hold Groundwork API
// keys. A missing or invalid signature is rejected with 401 before any
// parsing (fail closed). Tenant id comes from the URL path, never from
// the body, so a signed event can only mutate its own tenant's
// permissions.
type ACLSyncWebhookHandler struct {
	entra  *aclsyncwebhook.Receiver
	okta   *aclsyncwebhook.Receiver
	secret string
}

// NewACLSyncWebhookHandler wires both receivers behind one shared
// secret. Receivers may be nil (that provider's endpoint returns 503).
func NewACLSyncWebhookHandler(entra, okta *aclsyncwebhook.Receiver, secret string) *ACLSyncWebhookHandler {
	return &ACLSyncWebhookHandler{entra: entra, okta: okta, secret: secret}
}

// SetACLSyncWebhooks wires the real-time IAM sync surface. Nil-safe:
// when unset, /v1/security/acl-sync/* returns 503.
func (s *Server) SetACLSyncWebhooks(h *ACLSyncWebhookHandler) { s.aclSyncWebhooks = h }

func (s *Server) handleEntraWebhook(w http.ResponseWriter, r *http.Request) {
	s.handleProviderWebhook(w, r, "entra", aclsyncwebhook.EntraSignatureHeader,
		aclsyncwebhook.VerifyEntraSignature, func(body []byte) ([]aclsyncwebhook.Event, error) {
			return aclsyncwebhook.ParseEntraEvents(body)
		})
}

func (s *Server) handleOktaWebhook(w http.ResponseWriter, r *http.Request) {
	s.handleProviderWebhook(w, r, "okta", aclsyncwebhook.OktaSignatureHeader,
		aclsyncwebhook.VerifyOktaSignature, func(body []byte) ([]aclsyncwebhook.Event, error) {
			return aclsyncwebhook.ParseOktaEvents(body)
		})
}

type webhookParser func(body []byte) ([]aclsyncwebhook.Event, error)

func (s *Server) handleProviderWebhook(w http.ResponseWriter, r *http.Request, provider, signatureHeader string, verify func(string, []byte, string) bool, parse webhookParser) {
	if s.aclSyncWebhooks == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "acl_sync_webhook_unavailable"})
		return
	}
	tenantID := r.PathValue("tenant_id")
	if strings.TrimSpace(tenantID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant_id_required"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	if !verify(s.aclSyncWebhooks.secret, body, r.Header.Get(signatureHeader)) {
		gwmetrics.RecordWebhookSignatureFailure(provider)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_signature"})
		return
	}
	events, err := parse(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed_payload"})
		return
	}

	var receiver *aclsyncwebhook.Receiver
	switch provider {
	case "entra":
		receiver = s.aclSyncWebhooks.entra
	case "okta":
		receiver = s.aclSyncWebhooks.okta
	}
	if receiver == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "acl_sync_webhook_unavailable"})
		return
	}

	started := time.Now()
	if err := receiver.Apply(r.Context(), tenantID, events); err != nil {
		gwmetrics.RecordACLSyncError(tenantID)
		gwmetrics.RecordWebhookLatency(tenantID, provider, time.Since(started))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "webhook_apply_failed"})
		return
	}
	gwmetrics.RecordACLSyncRun(tenantID)
	gwmetrics.RecordWebhookLatency(tenantID, provider, time.Since(started))
	writeJSON(w, http.StatusOK, map[string]any{"applied": len(events), "tenant_id": tenantID})
}
