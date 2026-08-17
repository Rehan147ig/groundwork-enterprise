package notifications

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Slack signs every interactive request with X-Slack-Signature
// (HMAC-SHA256 over "v0:<timestamp>:<raw body>") and X-Slack-Request-
// Timestamp. Verification is mandatory before any action is executed;
// the timestamp window doubles as replay protection — a captured
// request cannot be replayed outside the skew window, and any replay
// inside the window still has to survive the server-side role check
// and grant-state checks.
const (
	// signatureVersion is the only supported Slack signature version.
	signatureVersion = "v0"
	// ReplayWindow bounds how far a request timestamp may deviate from
	// the server clock. Slack recommends 5 minutes.
	ReplayWindow = 5 * time.Minute
)

var (
	// ErrInvalidSignature means the signature is missing, malformed, or
	// does not match the computed HMAC (constant-time comparison).
	ErrInvalidSignature = errors.New("invalid slack signature")
	// ErrReplayWindow means the request timestamp is outside the
	// accepted window — the request is treated as a replay.
	ErrReplayWindow = errors.New("slack request timestamp outside replay window")
)

// VerifySignature verifies a Slack interactive request against the
// notifier's signing secret (SLACK_SIGNING_SECRET), including the
// replay window.
func (n *Notifier) VerifySignature(timestamp, body, signature string) error {
	if n.signingSecret == "" {
		return ErrInvalidSignature
	}
	return VerifySlackSignature(n.signingSecret, timestamp, body, signature, n.now())
}

// VerifySlackSignature checks the Slack request signature and timestamp
// window. body must be the exact raw request body. now is the server
// clock. Returns nil when the request is authentic and fresh.
func VerifySlackSignature(secret, timestamp, body, signature string, now time.Time) error {
	if secret == "" {
		return ErrInvalidSignature
	}
	if signature == "" || !strings.HasPrefix(signature, signatureVersion+"=") {
		return ErrInvalidSignature
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ErrInvalidSignature
	}
	skew := now.Unix() - ts
	if skew > int64(ReplayWindow.Seconds()) || skew < -int64(ReplayWindow.Seconds()) {
		return ErrReplayWindow
	}
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%s:%s:%s", signatureVersion, timestamp, body)
	expected := hex.EncodeToString(mac.Sum(nil))
	provided := strings.TrimPrefix(signature, signatureVersion+"=")
	if !hmac.Equal([]byte(expected), []byte(provided)) {
		return ErrInvalidSignature
	}
	return nil
}
