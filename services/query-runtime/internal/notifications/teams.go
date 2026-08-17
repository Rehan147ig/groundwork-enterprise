package notifications

import (
	"context"
	"encoding/json"
	"fmt"
)

// Microsoft Teams delivery via workflow webhooks (Power Automate /
// connector "Post to a channel when a webhook request is received").
// The workflow webhook URL is tenant-scoped (TEAMS_WORKFLOW_URL[_<TENANT>])
// and enforced by the same allowlist as Slack (host *.webhook.office.com).
// Teams workflow webhooks accept an AdaptiveCard attachment.

// SendBreakGlassTeams posts a break-glass lifecycle update as an
// AdaptiveCard to the tenant's Teams workflow webhook. Notifications
// that cannot be delivered fail loudly: the caller records evidence and
// alerts — a silent success is never acceptable for an emergency
// access event.
func (n *Notifier) SendBreakGlassTeams(ctx context.Context, tenantID, grantID, title, detail string) error {
	card := map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard",
				"version": "1.4",
				"body": []map[string]any{
					{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium"},
					{"type": "TextBlock", "text": detail, "wrap": true},
				},
			},
		}},
	}
	payload, err := json.Marshal(card)
	if err != nil {
		return fmt.Errorf("failed to marshal teams card: %w", err)
	}
	webhook, err := n.TeamsWebhookURL(ctx, tenantID)
	if err != nil {
		return err
	}
	return n.send(ctx, webhook, payload)
}
