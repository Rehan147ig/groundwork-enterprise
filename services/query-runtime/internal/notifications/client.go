package notifications

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Delivery policy for security notifications: explicit deadline, a
// bounded retry policy, and a strict endpoint allowlist. Notification
// delivery never uses http.DefaultClient — every request goes through
// the shared pooled client so connection use stays bounded and
// timeouts are explicit (Milestone 5 notification delivery).
const (
	// DefaultTimeout bounds one notification delivery attempt.
	DefaultTimeout = 10 * time.Second
	// MaxRetries is the retry budget for transient webhook failures
	// (429 / 5xx). Retries are short and bounded so a dead webhook
	// never turns into a long tail of duplicate deliveries.
	MaxRetries = 2
)

// retryBase is the backoff before the first retry. A var so tests can
// shrink the wait; production uses the default.
var retryBase = 250 * time.Millisecond

// allowedWebhookHosts is the allowlist of notification endpoints. A
// webhook URL is the credential to a channel, so anything outside the
// allowlist is rejected before a byte is sent (fail closed).
var allowedWebhookHosts = []string{
	"hooks.slack.com",    // Slack incoming webhooks
	"webhook.office.com", // Microsoft Teams workflow webhooks
}

// ErrEndpointNotAllowlisted means a notification endpoint is not on the
// allowlist; delivery is refused.
var ErrEndpointNotAllowlisted = errors.New("notification endpoint is not allowlisted")

// ErrDeliveryFailed means the webhook did not acknowledge delivery
// after the retry budget was consumed.
var ErrDeliveryFailed = errors.New("notification delivery failed")

// validateWebhookURL enforces the https-only allowlist before any
// request is made. A misconfigured URL fails closed: no request, no
// partial delivery.
func validateWebhookURL(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("%w: unparseable url: %v", ErrEndpointNotAllowlisted, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q is not https", ErrEndpointNotAllowlisted, u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	for _, allowed := range allowedWebhookHosts {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return nil
		}
	}
	return fmt.Errorf("%w: host %q", ErrEndpointNotAllowlisted, host)
}

// send posts a JSON payload to an allowlisted webhook with an explicit
// deadline and a bounded retry policy. Transient failures (429, 5xx,
// network errors) are retried with short backoff; permanent failures
// (4xx) and allowlist violations are never retried.
func (n *Notifier) send(ctx context.Context, endpoint string, payload []byte) error {
	if err := validateWebhookURL(endpoint); err != nil {
		return err
	}
	body := bytes.NewReader(payload)
	var lastErr error
	for attempt := 0; attempt <= MaxRetries; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, retryBase*time.Duration(attempt)); err != nil {
				return err
			}
			body.Seek(0, 0)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
		if err != nil {
			return fmt.Errorf("failed to create notification request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := n.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("%w: %v", ErrDeliveryFailed, err)
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
			return nil
		}
		lastErr = fmt.Errorf("%w: webhook returned status %d", ErrDeliveryFailed, resp.StatusCode)
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			continue // transient: retry
		}
		return lastErr // permanent: no retry
	}
	return fmt.Errorf("%w after %d attempts: %v", ErrDeliveryFailed, MaxRetries+1, lastErr)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
