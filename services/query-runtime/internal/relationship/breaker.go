package relationship

import (
	"errors"
	"sync"
	"time"
)

// CircuitState is the state of a CircuitBreaker.
type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half_open"
)

// CircuitBreakerSettings configures a CircuitBreaker. Zero values get
// defaults via NewCircuitBreaker.
type CircuitBreakerSettings struct {
	Name          string
	FailureLimit  int
	OpenTimeout   time.Duration
	HalfOpenLimit int
}

// CircuitBreaker is a classic failure-counting breaker. It lives here —
// not in the runtime package — because the SpiceDB adapter (and shadow
// wiring) needs the same semantics: when a backend fails repeatedly, the
// adapter short-circuits with ErrCircuitOpen instead of hammering a
// broken dependency. The runtime package re-exports the same types as
// aliases, so business code that already uses runtime.CircuitBreaker
// keeps compiling unchanged.
type CircuitBreaker struct {
	mu               sync.Mutex
	settings         CircuitBreakerSettings
	state            CircuitState
	consecutiveFails int
	openedAt         time.Time
	halfOpenInFlight int
}

// ErrCircuitOpen is returned by Allow when the breaker is open (or
// half-open at capacity). Adapters wrap backend failures with it so
// callers can distinguish "dependency is down" from "we stopped trying".
var ErrCircuitOpen = errors.New("relationship: authorization circuit open")

// NewCircuitBreaker builds a breaker, applying defaults for zero-valued
// settings: FailureLimit 3, OpenTimeout 10s, HalfOpenLimit 1.
func NewCircuitBreaker(settings CircuitBreakerSettings) *CircuitBreaker {
	if settings.FailureLimit <= 0 {
		settings.FailureLimit = 3
	}
	if settings.OpenTimeout <= 0 {
		settings.OpenTimeout = 10 * time.Second
	}
	if settings.HalfOpenLimit <= 0 {
		settings.HalfOpenLimit = 1
	}
	return &CircuitBreaker{settings: settings, state: CircuitClosed}
}

// Allow reports whether a call may proceed. When the breaker is open
// past OpenTimeout it transitions to half-open and admits up to
// HalfOpenLimit probes.
func (c *CircuitBreaker) Allow() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == CircuitOpen && time.Since(c.openedAt) >= c.settings.OpenTimeout {
		c.state = CircuitHalfOpen
		c.halfOpenInFlight = 0
	}

	switch c.state {
	case CircuitOpen:
		return ErrCircuitOpen
	case CircuitHalfOpen:
		if c.halfOpenInFlight >= c.settings.HalfOpenLimit {
			return ErrCircuitOpen
		}
		c.halfOpenInFlight++
	}
	return nil
}

// ReportSuccess closes the breaker and resets the failure counter.
func (c *CircuitBreaker) ReportSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = CircuitClosed
	c.consecutiveFails = 0
	c.halfOpenInFlight = 0
}

// ReportFailure increments the failure counter; at FailureLimit (or on
// any half-open failure) the breaker opens. It reports whether the
// failure caused a transition to open (callers use this to fire
// trip-level metrics exactly once per trip).
func (c *CircuitBreaker) ReportFailure() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == CircuitHalfOpen {
		c.open()
		return true
	}
	c.consecutiveFails++
	if c.consecutiveFails >= c.settings.FailureLimit {
		c.open()
		return true
	}
	return false
}

// State returns the current state.
func (c *CircuitBreaker) State() CircuitState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *CircuitBreaker) open() {
	c.state = CircuitOpen
	c.openedAt = time.Now()
	c.halfOpenInFlight = 0
}

// CircuitStateValue maps a circuit state to a number for gauges:
// closed=0, half_open=1, open=2. Metrics consumers must not import this
// package's state type, so callers convert before recording.
func CircuitStateValue(state CircuitState) float64 {
	switch state {
	case CircuitHalfOpen:
		return 1
	case CircuitOpen:
		return 2
	default:
		return 0
	}
}

// BreakerRegistry maps stable keys (tenant, tenant|connector) to
// breakers sharing one settings template. Breakers are created on first
// use and never evicted — keys are bounded by the registry's use case
// (active tenants, registered connectors), so growth is safe. It is
// safe for concurrent use.
type BreakerRegistry struct {
	mu       sync.Mutex
	settings CircuitBreakerSettings
	breakers map[string]*CircuitBreaker
}

// NewBreakerRegistry builds an empty registry. Settings get defaults
// via NewCircuitBreaker on first use.
func NewBreakerRegistry(settings CircuitBreakerSettings) *BreakerRegistry {
	return &BreakerRegistry{
		settings: settings,
		breakers: make(map[string]*CircuitBreaker),
	}
}

// For returns the breaker for key, creating it on first use.
func (r *BreakerRegistry) For(key string) *CircuitBreaker {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.breakers[key]
	if !ok {
		b = NewCircuitBreaker(r.settings)
		r.breakers[key] = b
	}
	return b
}
