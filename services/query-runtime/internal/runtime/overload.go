package runtime

import "sync"

// OverloadLimiter is the instance-wide in-flight request cap (Phase
// 8.2 overload protection). It complements the per-tenant concurrency
// limiter: per-tenant caps keep one noisy tenant from hogging the
// instance, while this global cap refuses NEW work when the whole
// process is saturated — under an exhausted pool, rejecting a request
// is strictly better than parking a goroutine on a queue.
//
// Rejection is immediate (fail-closed, HTTP 503 overload_exceeded) and
// never queued: no unbounded buffers, no piled-up goroutines. In-memory
// and per-process; a multi-replica deployment should load-balance so
// each replica enforces its own cap. A non-positive limit means
// "unlimited" (the limiter is a no-op).
type OverloadLimiter struct {
	mu    sync.Mutex
	limit int
	slots chan struct{}
}

// NewOverloadLimiter returns an instance-wide concurrency limiter.
// limit <= 0 makes it a no-op.
func NewOverloadLimiter(limit int) *OverloadLimiter {
	return &OverloadLimiter{limit: limit}
}

// Acquire reserves one of the instance's in-flight slots. ok == false
// means the instance is saturated and the caller must reject the
// request immediately. The returned release function must be called
// exactly once for a successful acquire. A nil receiver or limit <= 0
// always succeeds with a no-op release.
func (l *OverloadLimiter) Acquire() (release func(), ok bool) {
	if l == nil || l.limit <= 0 {
		return func() {}, true
	}
	l.mu.Lock()
	if l.slots == nil {
		l.slots = make(chan struct{}, l.limit)
	}
	select {
	case l.slots <- struct{}{}:
		l.mu.Unlock()
		return func() {
			l.mu.Lock()
			<-l.slots
			l.mu.Unlock()
		}, true
	default:
		l.mu.Unlock()
		return nil, false
	}
}
