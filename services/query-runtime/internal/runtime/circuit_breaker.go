// Package runtime — circuit breaker re-exports.
//
// The circuit breaker implementation moved to
// internal/relationship/breaker.go so the SpiceDB adapter (and shadow
// wiring) can share it without importing the runtime package. These
// aliases keep every existing runtime.CircuitBreaker consumer compiling
// and behaving identically. New consumers may import either name; the
// types are the same.
package runtime

import "groundwork/query-runtime/internal/relationship"

type CircuitState = relationship.CircuitState

const (
	CircuitClosed   = relationship.CircuitClosed
	CircuitOpen     = relationship.CircuitOpen
	CircuitHalfOpen = relationship.CircuitHalfOpen
)

type CircuitBreakerSettings = relationship.CircuitBreakerSettings
type CircuitBreaker = relationship.CircuitBreaker
type BreakerRegistry = relationship.BreakerRegistry

func NewCircuitBreaker(settings CircuitBreakerSettings) *CircuitBreaker {
	return relationship.NewCircuitBreaker(settings)
}

func NewBreakerRegistry(settings CircuitBreakerSettings) *BreakerRegistry {
	return relationship.NewBreakerRegistry(settings)
}

func CircuitStateValue(state CircuitState) float64 {
	return relationship.CircuitStateValue(state)
}
