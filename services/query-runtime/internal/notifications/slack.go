package notifications

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Slack delivery for security notifications. Webhook URLs are resolved
// per tenant (see config.go); every delivery goes through the hardened
// client with the endpoint allowlist (see client.go).
//
// Break-glass request messages carry interactive Approve/Reject buttons
// (four-eyes flow); activated grants carry a Revoke button. Clicks are
// verified by the runtime's /v1/security/slack/actions endpoint.

// SendBreakGlassRequest notifies the tenant's channel that a
// break-glass grant was opened. When secondAdmin is non-empty (four-eyes
// flow) the message carries Approve/Reject buttons; grantID is required
// for the action context.
func (n *Notifier) SendBreakGlassRequest(ctx context.Context, tenantID, grantID, operator, reason, duration, secondAdmin string) error {
	msg := map[string]any{
		"text": fmt.Sprintf(":rotating_light: *Break-Glass Emergency Access Request*\n*Tenant*: %s\n*Requested by*: %s\n*Reason*: %s\n*Duration*: %s",
			tenantID, operator, reason, duration),
	}
	if secondAdmin != "" {
		msg["attachments"] = []map[string]any{{
			"text":        fmt.Sprintf("Awaiting second-admin approval (waiting on %s).", secondAdmin),
			"callback_id": actionCallback(tenantID, grantID),
			"actions": []map[string]any{
				{"name": "approve", "text": "Approve", "type": "button", "value": actionValue(tenantID, grantID)},
				{"name": "reject", "text": "Reject", "type": "button", "style": "danger", "value": actionValue(tenantID, grantID)},
			},
		}}
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal slack notification: %w", err)
	}
	webhook, err := n.SlackWebhookURL(ctx, tenantID)
	if err != nil {
		return err
	}
	return n.send(ctx, webhook, payload)
}

// SendBreakGlassActivated notifies the tenant's channel that a pending
// grant was approved by the second admin and is now active. The message
// carries a Revoke button so an authorized admin can terminate it
// immediately from Slack.
func (n *Notifier) SendBreakGlassActivated(ctx context.Context, tenantID, grantID, approver string) error {
	payload, err := json.Marshal(map[string]any{
		"text": fmt.Sprintf(":white_check_mark: *Break-Glass Grant Active*\n*Tenant*: %s\n*Approved by*: %s\n*Grant*: %s",
			tenantID, approver, grantID),
		"attachments": []map[string]any{{
			"text":        "Terminate the grant immediately if it is no longer needed.",
			"callback_id": actionCallback(tenantID, grantID),
			"actions": []map[string]any{
				{"name": "revoke", "text": "Revoke", "type": "button", "style": "danger", "value": actionValue(tenantID, grantID)},
			},
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal slack notification: %w", err)
	}
	webhook, err := n.SlackWebhookURL(ctx, tenantID)
	if err != nil {
		return err
	}
	return n.send(ctx, webhook, payload)
}

// SendBreakGlassDenied notifies the tenant's channel that a pending
// grant was rejected or a grant was revoked, with the accountable
// reason.
func (n *Notifier) SendBreakGlassDenied(ctx context.Context, tenantID, grantID, actor, action, reason string) error {
	verb := "rejected"
	if action == ActionRevoke {
		verb = "revoked"
	}
	payload, err := json.Marshal(map[string]any{
		"text": fmt.Sprintf(":no_entry_sign: *Break-Glass Grant %s*\n*Tenant*: %s\n*%s by*: %s\n*Reason*: %s",
			verb, tenantID, strings.Title(verb), actor, reason),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal slack notification: %w", err)
	}
	webhook, err := n.SlackWebhookURL(ctx, tenantID)
	if err != nil {
		return err
	}
	return n.send(ctx, webhook, payload)
}

func actionCallback(tenantID, grantID string) string {
	return actionPrefix + ":" + tenantID + ":" + grantID
}

func actionValue(tenantID, grantID string) string {
	return tenantID + "|" + grantID
}
