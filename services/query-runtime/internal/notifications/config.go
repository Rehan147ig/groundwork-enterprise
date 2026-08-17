package notifications

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"groundwork/query-runtime/internal/httpclient"
)

// Notifier delivers security-critical notifications (break-glass
// requests, approvals, rejections, revocations) to Slack and Microsoft
// Teams. Webhook URLs are tenant-scoped secret references resolved per
// tenant at delivery time — the URLs are never compiled into code, and
// one tenant's channel can never be confused with another's.
//
// Resolution order per tenant:
//
//	env://SLACK_WEBHOOK_URL_<TENANT>  (tenant-scoped override)
//	env://SLACK_WEBHOOK_URL           (default channel)
//
// Teams follows the same shape with TEAMS_WORKFLOW_URL[_<TENANT>].
// Tenant IDs are normalized (uppercased, non-alphanumerics become '_').
//
// Server-side role checks for interactive actions use
// SLACK_ADMIN_USER_IDS[_<TENANT>] (comma-separated Slack user IDs).
// When no admin IDs are configured for a tenant, actions are denied
// (fail closed).
type Notifier struct {
	client        *http.Client
	slackWebhook  func(ctx context.Context, tenantID string) (string, error)
	teamsWebhook  func(ctx context.Context, tenantID string) (string, error)
	adminUserIDs  map[string]map[string]struct{} // tenant -> allowed Slack user IDs
	signingSecret string
	now           func() time.Time
}

// WebhookResolver resolves a tenant-scoped webhook URL. It returns an
// error when no URL is configured for the tenant (the caller decides
// whether a missing webhook is fatal).
type WebhookResolver func(ctx context.Context, tenantID string) (string, error)

// New builds a Notifier with explicit resolvers, admin allowlists, and
// the Slack signing secret. The client must already carry an explicit
// timeout (see httpclient.PoolConfig.Client); Notifier never touches
// http.DefaultClient.
func New(client *http.Client, slack, teams WebhookResolver, admins map[string][]string, signingSecret string) *Notifier {
	adminSets := make(map[string]map[string]struct{}, len(admins))
	for tenant, ids := range admins {
		set := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			if id = strings.TrimSpace(id); id != "" {
				set[id] = struct{}{}
			}
		}
		adminSets[tenant] = set
	}
	return &Notifier{
		client:        client,
		slackWebhook:  slack,
		teamsWebhook:  teams,
		adminUserIDs:  adminSets,
		signingSecret: signingSecret,
		now:           time.Now,
	}
}

// NewFromEnv builds the production Notifier from environment
// configuration. The client is the shared hardened pool with an
// explicit delivery timeout (NOTIFY_TIMEOUT_MS, default 10s). Missing
// signing/admin configuration disables interactive actions but not
// one-way notification delivery.
func NewFromEnv() *Notifier {
	timeout := DefaultTimeout
	if v := os.Getenv("NOTIFY_TIMEOUT_MS"); v != "" {
		if ms, err := parseMillis(v); err == nil && ms > 0 {
			timeout = time.Duration(ms) * time.Millisecond
		}
	}
	pool := httpclient.PoolFromEnv("GROUNDWORK_NOTIFY_HTTP_POOL", httpclient.DefaultPool())
	client := pool.Client(timeout)

	slack := envWebhookResolver("SLACK_WEBHOOK_URL")
	teams := envWebhookResolver("TEAMS_WORKFLOW_URL")

	admins := map[string][]string{}
	if ids := splitCSV(os.Getenv("SLACK_ADMIN_USER_IDS")); len(ids) > 0 {
		admins[""] = ids
	}
	for _, env := range os.Environ() {
		name, value, ok := strings.Cut(env, "=")
		if !ok || !strings.HasPrefix(name, "SLACK_ADMIN_USER_IDS_") {
			continue
		}
		if ids := splitCSV(value); len(ids) > 0 {
			admins[tenantKey(name[len("SLACK_ADMIN_USER_IDS_"):])] = ids
		}
	}
	return New(client, slack, teams, admins, os.Getenv("SLACK_SIGNING_SECRET"))
}

func envWebhookResolver(base string) WebhookResolver {
	return func(ctx context.Context, tenantID string) (string, error) {
		if tenantID != "" {
			if v := os.Getenv(base + "_" + tenantKey(tenantID)); v != "" {
				return v, nil
			}
		}
		if v := os.Getenv(base); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("no %s configured (tenant %q)", base, tenantID)
	}
}

// tenantKey normalizes a tenant ID into an env-var name segment
// (uppercase, non-alphanumerics become '_'): "gov-us-east-1" ->
// "GOV_US_EAST_1".
func tenantKey(tenantID string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(tenantID) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := parts[:0:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseMillis(v string) (int64, error) {
	var n int64
	_, err := fmt.Sscanf(v, "%d", &n)
	return n, err
}

// SlackWebhookURL resolves the tenant-scoped Slack webhook URL.
func (n *Notifier) SlackWebhookURL(ctx context.Context, tenantID string) (string, error) {
	if n.slackWebhook == nil {
		return "", fmt.Errorf("slack delivery is not configured")
	}
	return n.slackWebhook(ctx, tenantID)
}

// TeamsWebhookURL resolves the tenant-scoped Teams workflow webhook URL.
func (n *Notifier) TeamsWebhookURL(ctx context.Context, tenantID string) (string, error) {
	if n.teamsWebhook == nil {
		return "", fmt.Errorf("teams delivery is not configured")
	}
	return n.teamsWebhook(ctx, tenantID)
}

// AuthorizedAdmin is the server-side role check for interactive
// actions: the acting Slack user ID must be allowlisted for the tenant
// (or globally). With no allowlist configured the check fails closed.
func (n *Notifier) AuthorizedAdmin(tenantID, userID string) bool {
	if userID == "" {
		return false
	}
	if set, ok := n.adminUserIDs[tenantKey(tenantID)]; ok {
		_, ok := set[userID]
		return ok
	}
	if set, ok := n.adminUserIDs[""]; ok {
		_, ok := set[userID]
		return ok
	}
	return false
}
