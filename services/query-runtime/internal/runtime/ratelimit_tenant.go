package runtime

import (
	"sync"
	"time"
)

// TenantRateLimiter is a per-tenant fixed-window limiter (requests per
// minute), complementing the per-API-key limiter in ratelimit.go: a tenant
// with many keys cannot exhaust the instance through any single key's
// budget, so the tenant as a whole gets a shared ceiling. It is in-memory
// and per-process; a multi-replica deployment should back it with a shared
// store (see ratelimit.go for the same caveat).
//
// A non-positive rpm means "unlimited" (the limiter is a no-op), so
// deployments that do not configure tenant limits are never throttled.
type TenantRateLimiter struct {
	mu      sync.Mutex
	rpm     int
	window  time.Duration
	windows map[string]*rlWindow
}

// NewTenantRateLimiter returns a per-tenant limiter with a one-minute
// fixed window. rpm <= 0 makes it a no-op.
func NewTenantRateLimiter(rpm int) *TenantRateLimiter {
	return NewTenantRateLimiterWindow(rpm, time.Minute)
}

// NewTenantRateLimiterWindow is NewTenantRateLimiter with a custom window
// (used by tests; production should use the one-minute window).
func NewTenantRateLimiterWindow(rpm int, window time.Duration) *TenantRateLimiter {
	return &TenantRateLimiter{
		rpm:     rpm,
		window:  window,
		windows: map[string]*rlWindow{},
	}
}

// Allow reports whether the tenant is within its per-window budget. When
// the budget is exhausted it returns false plus the duration until the
// window resets (suitable for a Retry-After header). A nil receiver or
// rpm <= 0 always allows.
func (r *TenantRateLimiter) Allow(tenantID string) (bool, time.Duration) {
	if r == nil || r.rpm <= 0 {
		return true, 0
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	w, ok := r.windows[tenantID]
	if !ok || now.After(w.resetAt) {
		r.windows[tenantID] = &rlWindow{count: 1, resetAt: now.Add(r.window)}
		return true, 0
	}
	if w.count >= r.rpm {
		return false, time.Until(w.resetAt)
	}
	w.count++
	return true, 0
}

// TenantConcurrencyLimiter caps the number of in-flight requests a tenant
// may have in the instance. Requests beyond the cap are rejected
// immediately (fail-closed, HTTP 503) rather than queued, so one noisy
// tenant cannot pile up work for the others. In-memory and per-process,
// like the rate limiters.
//
// The cap is per-call (AcquireWithLimit), so the auth layer can derive
// it from the tenant's capacity tier (Phase 8.2 capacity model). A
// non-positive limit means "unlimited" (the limiter is a no-op).
type TenantConcurrencyLimiter struct {
	mu    sync.Mutex
	limit int
	slots map[string]chan struct{}
}

// NewTenantConcurrencyLimiter returns a per-tenant concurrency limiter
// with the given default limit. limit <= 0 makes it a no-op; callers
// can override per acquire via AcquireWithLimit.
func NewTenantConcurrencyLimiter(limit int) *TenantConcurrencyLimiter {
	return &TenantConcurrencyLimiter{
		limit: limit,
		slots: map[string]chan struct{}{},
	}
}

// Acquire reserves one of the tenant's in-flight slots using the
// limiter's default limit. See AcquireWithLimit.
func (l *TenantConcurrencyLimiter) Acquire(tenantID string) (release func(), ok bool) {
	if l == nil {
		return func() {}, true
	}
	return l.AcquireWithLimit(tenantID, l.limit)
}

// AcquireWithLimit reserves one of the tenant's in-flight slots against
// the given cap (limit <= 0 always succeeds — unlimited). ok == false
// means the tenant is at its concurrency cap and the caller must reject
// the request. The returned release function must be called exactly
// once for a successful acquire. A nil receiver always succeeds with a
// no-op release.
func (l *TenantConcurrencyLimiter) AcquireWithLimit(tenantID string, limit int) (release func(), ok bool) {
	if l == nil || limit <= 0 {
		return func() {}, true
	}
	l.mu.Lock()
	ch, exists := l.slots[tenantID]
	if !exists {
		ch = make(chan struct{}, limit)
		l.slots[tenantID] = ch
	}
	select {
	case ch <- struct{}{}:
		l.mu.Unlock()
		return func() {
			l.mu.Lock()
			<-ch
			if len(ch) == 0 {
				delete(l.slots, tenantID)
			}
			l.mu.Unlock()
		}, true
	default:
		l.mu.Unlock()
		return nil, false
	}
}
