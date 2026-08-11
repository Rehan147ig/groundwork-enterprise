package runtime

import (
	"testing"
	"time"
)

func TestBreakerRegistryCreatesPerKey(t *testing.T) {
	r := NewBreakerRegistry(CircuitBreakerSettings{Name: "test", FailureLimit: 2, OpenTimeout: time.Minute})
	a1 := r.For("a")
	a2 := r.For("a")
	b := r.For("b")
	if a1 != a2 {
		t.Fatal("same key must return the same breaker")
	}
	if a1 == b {
		t.Fatal("different keys must return different breakers")
	}
}

func TestBreakerRegistryAppliesSettings(t *testing.T) {
	r := NewBreakerRegistry(CircuitBreakerSettings{Name: "test", FailureLimit: 2, OpenTimeout: 5 * time.Second})
	b := r.For("k")
	for i := 0; i < 2; i++ {
		b.ReportFailure()
	}
	s := b.State()
	if s != CircuitOpen {
		t.Fatalf("state = %v, want open after 2 failures", s)
	}
	if v := CircuitStateValue(s); v != 2 {
		t.Fatalf("open = %v, want 2", v)
	}
}

func TestCircuitStateValue(t *testing.T) {
	if v := CircuitStateValue(CircuitClosed); v != 0 {
		t.Fatalf("closed = %v, want 0", v)
	}
	if v := CircuitStateValue(CircuitHalfOpen); v != 1 {
		t.Fatalf("half_open = %v, want 1", v)
	}
	if v := CircuitStateValue(CircuitOpen); v != 2 {
		t.Fatalf("open = %v, want 2", v)
	}
}
