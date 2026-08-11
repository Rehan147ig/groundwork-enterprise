package sdk

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// MintUserAssertion mints an HS256 JWT signed with the runtime's
// GROUNDWORK_JWT_HS_SECRET. Only for local development and first-party
// console flows; production integrations receive end-user assertions
// from the enterprise OIDC provider instead. Mirrors the TypeScript
// mintUserAssertion helper claim-for-claim.
func MintUserAssertion(hsSecret, subject, tenantID string, roles []string, ttlSeconds int) (string, error) {
	if roles == nil {
		roles = []string{"console-admin"}
	}
	if ttlSeconds <= 0 {
		ttlSeconds = 300
	}
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	now := time.Now().Unix()
	payload := map[string]any{
		"sub":       subject,
		"iss":       "groundwork-console",
		"aud":       "groundwork-query-runtime",
		"tenant_id": tenantID,
		"roles":     roles,
		"iat":       now,
		"exp":       now + int64(ttlSeconds),
	}
	b64url := func(v any) (string, error) {
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	headerPart, err := b64url(header)
	if err != nil {
		return "", err
	}
	payloadPart, err := b64url(payload)
	if err != nil {
		return "", err
	}
	signingInput := headerPart + "." + payloadPart
	mac := hmac.New(sha256.New, []byte(hsSecret))
	if _, err := mac.Write([]byte(signingInput)); err != nil {
		return "", err
	}
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s.%s", signingInput, signature), nil
}

// splitAssertionParts is a small helper kept for parity with the
// TypeScript verifiable-JWT test.
func splitAssertionParts(token string) (string, string, string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}
