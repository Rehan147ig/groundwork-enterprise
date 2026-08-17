package contract

import (
	"errors"
	"net"
	"strings"
)

// Error taxonomy (contract requirement: health, sync lag, credential
// expiry, and error taxonomy). Every connector error is classified into
// a Kind. Classification lives here — never duplicated inside provider
// packages. The service uses the kind to decide retry behavior and
// fail-closed behavior.
//
// Fail-closed kinds (FailsClosed == true): the connector must surface
// the error, never a partial/empty snapshot; the service treats the
// source as untrusted.
//
// Retryable kinds (IsRetryable == true): the service retries with
// backoff; a persistent failure still marks the installation degraded.

// Kind is the taxonomy of connector errors.
type Kind string

const (
	// KindAuth: authentication/authorization failed (bad credential,
	// revoked grant, insufficient scope). Fail-closed, non-retryable
	// with the same credential.
	KindAuth Kind = "auth"
	// KindRateLimited: provider returned 429 / rate limit. Retryable.
	KindRateLimited Kind = "rate_limited"
	// KindTimeout: the call exceeded its deadline. Retryable.
	KindTimeout Kind = "timeout"
	// KindQuota: provider quota exhausted (non-transient until renewed).
	// Retryable with backoff.
	KindQuota Kind = "quota"
	// KindNotFound: the resource does not exist (deleted elsewhere).
	// Not an error for delta/tombstone semantics; fail-closed for
	// reads that must exist.
	KindNotFound Kind = "not_found"
	// KindInvalidData: the provider returned data the connector cannot
	// model safely (unexpected shape, unsupported feature). Fail-closed:
	// a connector must refuse to guess rather than emit wrong tuples.
	KindInvalidData Kind = "invalid_data"
	// KindUnsupported: the source feature is outside the connector's
	// documented supported subset. Fail-closed: unmodeled features
	// deny.
	KindUnsupported Kind = "unsupported"
	// KindPagination: the provider's paging contract is inconsistent
	// (infinite loop, skipped pages). Fail-closed: an incomplete
	// inventory must not be treated as complete.
	KindPagination Kind = "pagination"
	// KindTransient: transient transport failure (connection reset,
	// 5xx). Retryable.
	KindTransient Kind = "transient"
	// KindPermanent: anything else the connector cannot classify.
	KindPermanent Kind = "permanent"
)

// failClosedKinds are kinds where the caller must treat the operation as
// failed and must not proceed with partial data.
var failClosedKinds = map[Kind]bool{
	KindAuth:        true,
	KindInvalidData: true,
	KindUnsupported: true,
	KindPagination:  true,
}

// retryableKinds are kinds worth retrying with backoff.
var retryableKinds = map[Kind]bool{
	KindRateLimited: true,
	KindTimeout:     true,
	KindQuota:       true,
	KindTransient:   true,
}

// ConnectorError is the classified connector error. Wrap provider errors
// with NewConnectorError/Wrap; callers use KindOf, IsRetryable,
// FailsClosed instead of string-matching provider messages.
type ConnectorError struct {
	Kind Kind
	// Message never contains secrets or credential material.
	Message string
	// Err is the wrapped underlying error (may be nil).
	Err error
}

func (e *ConnectorError) Error() string {
	if e.Message == "" && e.Err != nil {
		return "connector " + string(e.Kind) + ": " + e.Err.Error()
	}
	if e.Err != nil {
		return "connector " + string(e.Kind) + ": " + e.Message + ": " + e.Err.Error()
	}
	return "connector " + string(e.Kind) + ": " + e.Message
}

func (e *ConnectorError) Unwrap() error { return e.Err }

// NewConnectorError builds a classified error. Messages must not contain
// secrets (the connector must never log or surface credential material).
func NewConnectorError(kind Kind, message string) *ConnectorError {
	return &ConnectorError{Kind: kind, Message: message}
}

// Wrap classifies an underlying provider error, preserving a more
// specific kind when err is already classified.
func Wrap(kind Kind, err error) error {
	if err == nil {
		return nil
	}
	if k := KindOf(err); k != KindPermanent && k != "" {
		return err
	}
	return &ConnectorError{Kind: kind, Err: err}
}

// KindOf returns the error's taxonomy kind. Unclassified errors are
// heuristically classified (timeout/network/HTTP-status strings);
// anything unrecognized becomes KindPermanent.
func KindOf(err error) Kind {
	if err == nil {
		return ""
	}
	var ce *ConnectorError
	if errors.As(err, &ce) {
		return ce.Kind
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return KindTimeout
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "429") || strings.Contains(strings.ToLower(msg), "rate limit") || strings.Contains(strings.ToLower(msg), "too many requests"):
		return KindRateLimited
	case strings.Contains(strings.ToLower(msg), "timeout") || strings.Contains(strings.ToLower(msg), "deadline exceeded"):
		return KindTimeout
	case strings.Contains(msg, "401") || strings.Contains(msg, "403") || strings.Contains(strings.ToLower(msg), "unauthorized") || strings.Contains(strings.ToLower(msg), "forbidden") || strings.Contains(strings.ToLower(msg), "access token"):
		return KindAuth
	case strings.Contains(msg, "404") || strings.Contains(strings.ToLower(msg), "not found"):
		return KindNotFound
	case strings.Contains(strings.ToLower(msg), "connection reset") || strings.Contains(strings.ToLower(msg), "connection refused") ||
		strings.Contains(msg, "502") || strings.Contains(msg, "503") || strings.Contains(msg, "504"):
		return KindTransient
	default:
		return KindPermanent
	}
}

// IsRetryable reports whether an error is worth retrying with backoff.
func IsRetryable(err error) bool {
	return retryableKinds[KindOf(err)]
}

// FailsClosed reports whether an error requires fail-closed handling
// (no partial snapshot, no continuation on partial data).
func FailsClosed(err error) bool {
	return failClosedKinds[KindOf(err)]
}

// Sentinel errors providers use to signal their own fail-closed
// decisions without importing the taxonomy into provider internals.
var (
	// ErrUnsupportedFeature: the source feature is outside the
	// connector's documented subset. The connector must return this
	// instead of guessing (fail closed).
	ErrUnsupportedFeature = NewConnectorError(KindUnsupported, "source feature is outside the connector's documented supported subset")
	// ErrInvalidProviderData: provider data cannot be modeled safely.
	ErrInvalidProviderData = NewConnectorError(KindInvalidData, "provider data cannot be modeled safely")
)
