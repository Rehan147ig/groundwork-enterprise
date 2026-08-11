package relationship

import (
	"context"
	"hash/fnv"
	"math"
	"time"
)

// ShadowOptions configures ShadowAuthorizer.
type ShadowOptions struct {
	// SampleRate selects the fraction of checks mirrored to the shadow
	// backend. 0 disables shadowing entirely; 1 mirrors everything;
	// intermediate values sample deterministically per request (the
	// same request always lands in the same bucket), so behavior is
	// stable under retries and across replicas.
	SampleRate float64

	// Fallback enables serving the shadow backend's answer when the
	// primary fails. Default false: the shadow is strictly observe-only
	// and the primary error propagates (checks stay fail-closed).
	Fallback bool

	// OnFallback, when set, is invoked with the tenant ID whenever a
	// check is answered by the shadow backend after a primary failure.
	OnFallback func(tenantID string)

	// OnShadowError, when set, is invoked with the tenant ID when the
	// shadow backend itself fails. Shadow failures never change the
	// decision.
	OnShadowError func(tenantID string)

	// OnMismatch, when set, is invoked with the tenant ID and a
	// category whenever the shadow answer disagrees with the primary.
	// Categories:
	//
	//	ShadowMismatchAllowDeny — both backends answered without error
	//	but reached different decisions.
	//	ShadowMismatchError — one backend errored while the other
	//	answered (primary error or shadow error).
	//
	// Mismatches are observe-only: the primary decision is never
	// altered. The parity threshold for cutover is zero unresolved
	// mismatches.
	OnMismatch func(tenantID, category string)
}

// Shadow mismatch categories (see ShadowOptions.OnMismatch).
const (
	ShadowMismatchAllowDeny = "allow_deny_mismatch"
	ShadowMismatchError     = "error_mismatch"
)

// ShadowAuthorizer mirrors checks to a second authorization backend
// (the SpiceDB migration target during Phase C) without changing the
// primary decision path. It implements Authorizer, so it can be wrapped
// around ANY backend pairing — the business layer keeps consuming the
// neutral interface.
//
// Semantics:
//
//   - The primary answer is always the decision. Shadow latency never
//     adds to the hot path: the shadow check runs concurrently and
//     detached from the request deadline (bounded by its own 2s cap).
//   - Fallback is best-effort by design: it only serves the shadow's
//     answer when the shadow already answered (or answers within a
//     50ms grace window) AND the primary failed. It never waits for
//     the shadow — a slow shadow degrades nothing.
//   - Shadow errors are observed (OnShadowError) but never change the
//     result.
type ShadowAuthorizer struct {
	primary Authorizer
	shadow  Authorizer
	opts    ShadowOptions
}

// NewShadowAuthorizer wraps primary with a shadow that mirrors checks.
// A nil shadow disables shadowing entirely (pure passthrough).
func NewShadowAuthorizer(primary, shadow Authorizer, opts ShadowOptions) *ShadowAuthorizer {
	return &ShadowAuthorizer{primary: primary, shadow: shadow, opts: opts}
}

// shadowCheckResult carries one shadow backend answer.
type shadowCheckResult struct {
	allow bool
	err   error
}

// Check mirrors the request to the shadow backend (when sampled) and
// returns the primary's decision. See the type comment for the
// fallback semantics.
func (s *ShadowAuthorizer) Check(ctx context.Context, req CheckRequest) (bool, error) {
	if s.shadow == nil || !s.wantShadow(req) {
		return s.primary.Check(ctx, req)
	}

	// Fire the shadow concurrently. WithoutCancel + a fixed cap keeps a
	// hanging shadow from cancelling or blocking the primary path.
	shadowCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	done := make(chan shadowCheckResult, 1)
	go func() {
		allow, err := s.shadow.Check(shadowCtx, req)
		done <- shadowCheckResult{allow: allow, err: err}
	}()

	allow, err := s.primary.Check(ctx, req)
	if err != nil && s.opts.Fallback {
		select {
		case r := <-done:
			// The shadow answered (with a decision or an error). If it
			// succeeded, serve it; if it also errored, fall through to
			// the normal observe path without re-reading the channel.
			if r.err == nil {
				if s.opts.OnFallback != nil {
					s.opts.OnFallback(req.TenantID)
				}
				s.reportMismatch(req.TenantID, allow, err, r.allow, r.err)
				return r.allow, nil
			}
			s.observeResult(r, req.TenantID, func(r shadowCheckResult) {
				s.reportMismatch(req.TenantID, allow, err, r.allow, r.err)
			})
			return allow, err
		case <-time.After(50 * time.Millisecond):
		}
	}
	s.observeShadow(done, req.TenantID, func(r shadowCheckResult) {
		s.reportMismatch(req.TenantID, allow, err, r.allow, r.err)
	})
	return allow, err
}

// reportMismatch fires OnMismatch when the two backends disagree:
// both answered but differently (allow/deny), or exactly one errored.
func (s *ShadowAuthorizer) reportMismatch(tenantID string, pAllow bool, pErr error, sAllow bool, sErr error) {
	if s.opts.OnMismatch == nil {
		return
	}
	switch {
	case pErr == nil && sErr == nil && pAllow != sAllow:
		s.opts.OnMismatch(tenantID, ShadowMismatchAllowDeny)
	case pErr != nil && sErr == nil, pErr == nil && sErr != nil:
		s.opts.OnMismatch(tenantID, ShadowMismatchError)
	}
}

// Ready reports on the primary only — the shadow must never gate the
// primary's readiness.
func (s *ShadowAuthorizer) Ready(ctx context.Context) error {
	return s.primary.Ready(ctx)
}

// observeShadow drains the shadow result so its error surfaces in
// OnShadowError without ever blocking the caller meaningfully.
func (s *ShadowAuthorizer) observeShadow(done chan shadowCheckResult, tenantID string, observed func(r shadowCheckResult)) {
	select {
	case r := <-done:
		s.observeResult(r, tenantID, observed)
	default:
		go func() {
			r := <-done
			s.observeResult(r, tenantID, observed)
		}()
	}
}

// observeResult runs the error and mismatch observers for one shadow
// result.
func (s *ShadowAuthorizer) observeResult(r shadowCheckResult, tenantID string, observed func(r shadowCheckResult)) {
	if r.err != nil && s.opts.OnShadowError != nil {
		s.opts.OnShadowError(tenantID)
	}
	if observed != nil {
		observed(r)
	}
}

// wantShadow applies the deterministic sample bucket for a request.
func (s *ShadowAuthorizer) wantShadow(req CheckRequest) bool {
	if s.opts.SampleRate <= 0 {
		return false
	}
	if s.opts.SampleRate >= 1 {
		return true
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(req.TenantID + "/" +
		req.Subject.Type + ":" + req.Subject.ID + "/" +
		req.Resource.Type + ":" + req.Resource.ID + "/" +
		req.Permission))
	return float64(h.Sum32())/float64(math.MaxUint32) < s.opts.SampleRate
}
