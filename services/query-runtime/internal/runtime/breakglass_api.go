package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/notifications"
)

// Break-Glass Operator Access (Phase 8.4) + Milestone 5 notification
// delivery.
//
// Endpoints (all require the "break_glass" scope — the legacy "admin"
// scope inherits via hasScope; Open/Approve/Reject/Revoke additionally
// require a verified operator identity):
//
//	POST /v1/security/break-glass/grants      open a time-bounded grant
//	   (reason mandatory, duration capped by service config)
//	   When admin2_id is set, the grant opens in PENDING_APPROVAL:
//	   Admin 1's opening is the first approval, and the grant becomes
//	   active only after the named second admin approves. Without
//	   admin2_id the grant opens ACTIVE (legacy single-admin flow).
//	GET  /v1/security/break-glass/grants      list the tenant's grants
//	GET  /v1/security/break-glass/grants/{id} one grant + its
//	   hash-chained event log
//	POST /v1/security/break-glass/grants/{id}/approve
//	   second-admin approval of a pending grant (returns the minted
//	   admin key once, to the approving admin)
//	POST /v1/security/break-glass/grants/{id}/reject
//	   reject a pending grant (reason mandatory)
//	POST /v1/security/break-glass/grants/{id}/revoke
//	   early revocation with mandatory reason
//
//	POST /v1/security/slack/actions           Slack interactive actions
//	   (approve/reject/revoke). Signature-authenticated (X-Slack-
//	   Signature / X-Slack-Request-Timestamp), replay-protected, and
//	   gated by a server-side role check (SLACK_ADMIN_USER_IDS[_<TENANT>]);
//	   the actor is recorded as "slack:<user-id>" and must be exactly
//	   the admin a pending grant is waiting on.
//
// Every lifecycle transition appends write-once, hash-chained evidence;
// expired/revoked grants fail closed at the API-key auth layer on the
// next request. The service is Nil-safe: when unset (no durable store
// wired in cmd/query-runtime), every endpoint returns 503
// break_glass_unavailable.
//
// Notification delivery (Milestone 5): webhook URLs are tenant-scoped
// secret references (SLACK_WEBHOOK_URL[_<TENANT>],
// TEAMS_WORKFLOW_URL[_<TENANT>]) resolved per tenant — never compiled
// into code. A delivery failure is recorded as notification_failed
// evidence on the grant's chain and counted in
// groundwork_notification_failures_total: an authorized emergency
// action never silently succeeds without a visible delivery attempt.
const breakGlassScope = "break_glass"

// SetBreakGlassService wires the Phase 8.4 break-glass service. When
// set, /v1/security/break-glass* endpoints are served. When nil (the
// default for existing tests), those endpoints return 503
// break_glass_unavailable.
func (s *Server) SetBreakGlassService(svc BreakGlassService) { s.breakGlass = svc }

// SetNotifier wires the Milestone 5 notification service. When nil,
// deliveries are recorded as failed (evidence + metric) instead of
// being attempted.
func (s *Server) SetNotifier(n NotificationService) { s.notifier = n }

// openBreakGlassGrant is the handler for POST /v1/security/break-glass/grants.
// It validates the request, invokes the service, and returns the minted grant.
func (s *Server) openBreakGlassGrant(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	decision, ok := identityFromContext(r.Context())
	if !ok || !decision.identity.Verified || decision.identity.UserID == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "verified_identity_required"})
		return
	}
	if s.breakGlass == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
		return
	}
	var req OpenBreakGlassRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.Reason == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reason_required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grant, mintedKey, err := s.breakGlass.Open(ctx, tenant, decision.identity.UserID, req)
	if err != nil {
		if errors.Is(err, ErrBreakGlassUnavailable) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "break_glass_open_failed"})
		return
	}
	// Notify the tenant's channel (Slack and Teams). A delivery failure
	// is evidence + an alerting metric — never a silent success.
	secondAdmin := ""
	if grant.Status == BreakGlassStatusPendingApproval {
		secondAdmin = grant.PendingApprovalBy
	}
	s.notifyBreakGlass(r.Context(), tenant.TenantID, grant.ID, func(ctx context.Context) error {
		if s.notifier == nil {
			return ErrNotificationUnavailable
		}
		return s.notifier.SendBreakGlassRequest(ctx, tenant.TenantID, grant.ID, grant.OperatorPrincipalID, req.Reason, fmt.Sprintf("%d min", req.DurationMinutes), secondAdmin)
	})
	// The minted admin key is returned exactly once, in the Open
	// response. It is never persisted, so losing it means opening a
	// new grant.
	writeJSON(w, http.StatusCreated, map[string]any{"grant": grant, "key": mintedKey})
}

// notifyBreakGlass attempts one notification delivery and, on failure,
// records immutable notification_failed evidence on the grant's chain
// plus an alerting metric. Best-effort, never blocks the API response.
func (s *Server) notifyBreakGlass(ctx context.Context, tenantID, grantID string, send func(context.Context) error) {
	if err := send(ctx); err != nil {
		slog.Error("break_glass_notification_failed", "tenant", tenantID, "grant", grantID, "error", err.Error())
		metrics.RecordNotificationFailure(tenantID, "slack")
		if s.breakGlass != nil {
			if recErr := s.breakGlass.RecordNotificationFailure(ctx, tenantID, grantID, "slack", err.Error()); recErr != nil {
				slog.Error("break_glass_notification_evidence_failed", "tenant", tenantID, "grant", grantID, "error", recErr.Error())
			}
		}
	}
}

// approveBreakGlassGrant is the second admin's four-eyes approval:
// POST /v1/security/break-glass/grants/{id}/approve.
func (s *Server) approveBreakGlassGrant(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	decision, ok := identityFromContext(r.Context())
	if !ok || !decision.identity.Verified || decision.identity.UserID == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "verified_identity_required"})
		return
	}
	grantID := r.PathValue("id")
	if grantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "grant_id_required"})
		return
	}
	if s.breakGlass == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grant, mintedKey, err := s.breakGlass.Approve(ctx, tenant, grantID, decision.identity.UserID)
	if err != nil {
		switch {
		case errors.Is(err, ErrBreakGlassUnavailable):
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
		case errors.Is(err, ErrBreakGlassNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "break_glass_grant_not_found"})
		case errors.Is(err, ErrBreakGlassNotPendingApproval):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "break_glass_grant_not_pending"})
		case errors.Is(err, ErrBreakGlassForbidden):
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "break_glass_action_forbidden"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "break_glass_approve_failed"})
		}
		return
	}
	s.notifyBreakGlass(r.Context(), tenant.TenantID, grantID, func(ctx context.Context) error {
		if s.notifier == nil {
			return ErrNotificationUnavailable
		}
		return s.notifier.SendBreakGlassActivated(ctx, tenant.TenantID, grantID, decision.identity.UserID)
	})
	writeJSON(w, http.StatusOK, map[string]any{"grant": grant, "key": mintedKey})
}

// rejectBreakGlassGrant rejects a pending grant:
// POST /v1/security/break-glass/grants/{id}/reject.
func (s *Server) rejectBreakGlassGrant(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	decision, ok := identityFromContext(r.Context())
	if !ok || !decision.identity.Verified || decision.identity.UserID == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "verified_identity_required"})
		return
	}
	grantID := r.PathValue("id")
	if grantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "grant_id_required"})
		return
	}
	if s.breakGlass == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
		return
	}
	var req RevokeBreakGlassRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.Reason == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reason_required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grant, err := s.breakGlass.Reject(ctx, tenant, grantID, decision.identity.UserID, req)
	if err != nil {
		switch {
		case errors.Is(err, ErrBreakGlassUnavailable):
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
		case errors.Is(err, ErrBreakGlassNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "break_glass_grant_not_found"})
		case errors.Is(err, ErrBreakGlassNotPendingApproval):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "break_glass_grant_not_pending"})
		case errors.Is(err, ErrBreakGlassForbidden):
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "break_glass_action_forbidden"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "break_glass_reject_failed"})
		}
		return
	}
	s.notifyBreakGlass(r.Context(), tenant.TenantID, grantID, func(ctx context.Context) error {
		if s.notifier == nil {
			return ErrNotificationUnavailable
		}
		return s.notifier.SendBreakGlassDenied(ctx, tenant.TenantID, grantID, decision.identity.UserID, notifications.ActionReject, req.Reason)
	})
	writeJSON(w, http.StatusOK, grant)
}

// listBreakGlassGrants lists the tenant's grants.
func (s *Server) listBreakGlassGrants(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	if s.breakGlass == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grants, err := s.breakGlass.List(ctx, tenant.TenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "break_glass_list_failed"})
		return
	}
	if grants == nil {
		grants = []BreakGlassGrant{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": grants})
}

// getBreakGlassGrant returns one grant with its event chain.
func (s *Server) getBreakGlassGrant(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	grantID := r.PathValue("id")
	if grantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "grant_id_required"})
		return
	}
	if s.breakGlass == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grant, events, err := s.breakGlass.Get(ctx, tenant.TenantID, grantID)
	if err != nil {
		if errors.Is(err, ErrBreakGlassNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "break_glass_grant_not_found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "break_glass_get_failed"})
		return
	}
	if events == nil {
		events = []BreakGlassEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"grant": grant, "events": events})
}

// revokeBreakGlassGrant terminates a grant early.
func (s *Server) revokeBreakGlassGrant(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_tenant_context"})
		return
	}
	decision, ok := identityFromContext(r.Context())
	if !ok || !decision.identity.Verified || decision.identity.UserID == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "verified_identity_required"})
		return
	}
	grantID := r.PathValue("id")
	if grantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "grant_id_required"})
		return
	}
	if s.breakGlass == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
		return
	}
	var req RevokeBreakGlassRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.Reason == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reason_required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grant, err := s.breakGlass.Revoke(ctx, tenant, grantID, decision.identity.UserID, req)
	if err != nil {
		if errors.Is(err, ErrBreakGlassUnavailable) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
			return
		}
		if errors.Is(err, ErrBreakGlassNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "break_glass_grant_not_found"})
			return
		}
		if errors.Is(err, ErrBreakGlassNotActive) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "break_glass_grant_not_active"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "break_glass_revoke_failed"})
		return
	}
	s.notifyBreakGlass(r.Context(), tenant.TenantID, grantID, func(ctx context.Context) error {
		if s.notifier == nil {
			return ErrNotificationUnavailable
		}
		return s.notifier.SendBreakGlassDenied(ctx, tenant.TenantID, grantID, decision.identity.UserID, notifications.ActionRevoke, req.Reason)
	})
	writeJSON(w, http.StatusOK, grant)
}

// handleSlackAction processes a signed Slack interactive action:
// POST /v1/security/slack/actions. This endpoint is NOT API-key
// authenticated — authenticity comes from the Slack signature
// (X-Slack-Signature over the raw body) plus the request-timestamp
// replay window, and authorization from the server-side admin
// allowlist. The acting user is recorded as "slack:<user-id>".
func (s *Server) handleSlackAction(w http.ResponseWriter, r *http.Request) {
	if s.notifier == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "notification_unavailable"})
		return
	}
	body, err := readBody(r, 1<<20)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	if err := s.notifier.VerifySignature(r.Header.Get("X-Slack-Request-Timestamp"), string(body), r.Header.Get("X-Slack-Signature")); err != nil {
		reason := "invalid_signature"
		if errors.Is(err, notifications.ErrReplayWindow) {
			reason = "replay_window"
		}
		metrics.RecordNotificationSignatureRejected(reason)
		slog.Warn("slack_action_rejected", "reason", reason)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": reason})
		return
	}

	form, err := parseFormPayload(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_form"})
		return
	}
	action, err := notifications.ParseSlackAction(form)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_payload"})
		return
	}
	actx, err := action.Context()
	if err != nil {
		// Not a break-glass action: acknowledge harmlessly so Slack
		// does not keep the interaction in a loading state.
		if errors.Is(err, notifications.ErrNotBreakGlassAction) {
			writeJSON(w, http.StatusOK, respondEphemeral("This action is not a Groundwork break-glass action."))
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed_action"})
		return
	}
	if !s.notifier.AuthorizedAdmin(actx.TenantID, actx.UserID) {
		slog.Warn("slack_action_forbidden", "tenant", actx.TenantID, "user", actx.UserID, "action", actx.Action)
		writeJSON(w, http.StatusForbidden, respondEphemeral("You are not an authorized admin for this tenant."))
		return
	}
	if s.breakGlass == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "break_glass_unavailable"})
		return
	}

	tenant := TenantContext{TenantID: actx.TenantID, Region: s.tenantRegion(r.Context(), actx.TenantID)}
	actor := "slack:" + actx.UserID
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	switch actx.Action {
	case notifications.ActionApprove:
		_, mintedKey, err := s.breakGlass.Approve(ctx, tenant, actx.GrantID, actor)
		if err != nil {
			writeJSON(w, http.StatusOK, respondEphemeral("%s", breakGlassActionError(err)))
			return
		}
		s.notifyBreakGlass(ctx, actx.TenantID, actx.GrantID, func(c context.Context) error {
			return s.notifier.SendBreakGlassActivated(c, actx.TenantID, actx.GrantID, actor)
		})
		slog.Info("break_glass_approved_via_slack", "tenant", actx.TenantID, "grant", actx.GrantID, "actor", actor)
		writeJSON(w, http.StatusOK, respondEphemeral("Grant approved and activated. The minted admin key was returned to the approving admin in the API response: %s", mintedKey))
	case notifications.ActionReject:
		_, err := s.breakGlass.Reject(ctx, tenant, actx.GrantID, actor, RevokeBreakGlassRequest{Reason: "rejected via Slack interactive action by " + actx.UserID})
		if err != nil {
			writeJSON(w, http.StatusOK, respondEphemeral("%s", breakGlassActionError(err)))
			return
		}
		s.notifyBreakGlass(ctx, actx.TenantID, actx.GrantID, func(c context.Context) error {
			return s.notifier.SendBreakGlassDenied(c, actx.TenantID, actx.GrantID, actor, notifications.ActionReject, "rejected via Slack interactive action")
		})
		slog.Info("break_glass_rejected_via_slack", "tenant", actx.TenantID, "grant", actx.GrantID, "actor", actor)
		writeJSON(w, http.StatusOK, respondEphemeral("Grant rejected."))
	case notifications.ActionRevoke:
		_, err := s.breakGlass.Revoke(ctx, tenant, actx.GrantID, actor, RevokeBreakGlassRequest{Reason: "revoked via Slack interactive action by " + actx.UserID})
		if err != nil {
			writeJSON(w, http.StatusOK, respondEphemeral("%s", breakGlassActionError(err)))
			return
		}
		s.notifyBreakGlass(ctx, actx.TenantID, actx.GrantID, func(c context.Context) error {
			return s.notifier.SendBreakGlassDenied(c, actx.TenantID, actx.GrantID, actor, notifications.ActionRevoke, "revoked via Slack interactive action")
		})
		slog.Info("break_glass_revoked_via_slack", "tenant", actx.TenantID, "grant", actx.GrantID, "actor", actor)
		writeJSON(w, http.StatusOK, respondEphemeral("Grant revoked; the bound admin key is dead."))
	default:
		writeJSON(w, http.StatusOK, respondEphemeral("Unknown break-glass action."))
	}
}

func breakGlassActionError(err error) string {
	switch {
	case errors.Is(err, ErrBreakGlassForbidden):
		return "You are not the admin this grant is waiting on."
	case errors.Is(err, ErrBreakGlassNotPendingApproval):
		return "This grant is not pending approval anymore."
	case errors.Is(err, ErrBreakGlassNotActive):
		return "This grant is no longer active."
	case errors.Is(err, ErrBreakGlassNotFound):
		return "This grant does not exist."
	default:
		return "The action failed server-side; check the runtime logs."
	}
}

func respondEphemeral(format string, args ...any) map[string]any {
	return map[string]any{"response_type": "ephemeral", "text": fmt.Sprintf(format, args...)}
}

// readBody reads the raw request body with a hard size cap.
func readBody(r *http.Request, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("body too large")
	}
	return data, nil
}

// parseFormPayload extracts the Slack "payload" form field (Slack posts
// interactive payloads as application/x-www-form-urlencoded).
func parseFormPayload(body []byte) ([]byte, error) {
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	p := form.Get("payload")
	if p == "" {
		return nil, errors.New("missing payload field")
	}
	return []byte(p), nil
}

// tenantRegion resolves the tenant's directory region for the Slack
// action path (the interactive payload carries no region). Falls back
// to the default "US" region when no directory is wired, matching the
// bootstrap-key convention in auth.go.
func (s *Server) tenantRegion(ctx context.Context, tenantID string) string {
	if directory, ok := s.tenantSvc.(TenantDirectory); ok && directory != nil {
		if region, _, _, found := directory.Lookup(ctx, tenantID); found && region != "" {
			return region
		}
	}
	return "US"
}
