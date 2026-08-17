package runtime

import (
	"context"
	"errors"
)

// ErrNotificationUnavailable means no notifier is wired: deliveries
// cannot be attempted and the event is recorded as evidence instead.
var ErrNotificationUnavailable = errors.New("notification service is not wired")

// NotificationService delivers security notifications (Slack/Teams)
// for break-glass lifecycle events (Milestone 5 notification delivery).
// It is the runtime's surface for the notifications package; the server
// is Nil-safe, and every delivery failure is recorded as
// notification_failed evidence plus an alerting metric — an emergency
// action never silently succeeds without a visible delivery attempt.
type NotificationService interface {
	// SendBreakGlassRequest notifies the tenant's channel that a grant
	// was opened. secondAdmin non-empty means the four-eyes flow is
	// active and the message carries Approve/Reject buttons.
	SendBreakGlassRequest(ctx context.Context, tenantID, grantID, operator, reason, duration, secondAdmin string) error
	// SendBreakGlassActivated notifies that a pending grant was
	// activated by the second admin (message carries a Revoke button).
	SendBreakGlassActivated(ctx context.Context, tenantID, grantID, approver string) error
	// SendBreakGlassDenied notifies that a grant was rejected or
	// revoked (action is notifications.ActionReject or
	// notifications.ActionRevoke).
	SendBreakGlassDenied(ctx context.Context, tenantID, grantID, actor, action, reason string) error
	// SendBreakGlassTeams posts a Teams AdaptiveCard lifecycle update.
	SendBreakGlassTeams(ctx context.Context, tenantID, grantID, title, detail string) error
	// AuthorizedAdmin is the server-side role check for interactive
	// actions: is this Slack user an allowed admin for the tenant?
	AuthorizedAdmin(tenantID, userID string) bool
	// VerifySignature verifies a Slack interactive request (HMAC
	// signature + replay window). Returns a non-nil error when the
	// request is not authentic or fresh.
	VerifySignature(timestamp, body, signature string) error
}
