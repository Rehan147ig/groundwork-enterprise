// Phase 8.2 outbox backpressure gate: the evidence pipeline is the
// bounded buffer between decisions and delivery. At/above the
// high-water mark the gate refuses new work fail-closed with
// ErrBackpressureExceeded instead of deepening the backlog; a nil
// store or non-positive mark disables the gate entirely.

package outbox

import (
	"context"
	"errors"
	"testing"
)

type fakeBackpressureStore struct {
	pending map[string]int
	err     error
}

func (f *fakeBackpressureStore) CountPendingOutbox(_ context.Context, tenantID string) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.pending[tenantID], nil
}

func TestBackpressureAllowsBelowMark(t *testing.T) {
	store := &fakeBackpressureStore{pending: map[string]int{"t1": 9}}
	gate := NewBackpressure(store, 10)
	if err := gate.Allow(context.Background(), "t1"); err != nil {
		t.Fatalf("below the mark must pass, got %v", err)
	}
}

func TestBackpressureRefusesAtMark(t *testing.T) {
	store := &fakeBackpressureStore{pending: map[string]int{"t1": 10}}
	gate := NewBackpressure(store, 10)
	err := gate.Allow(context.Background(), "t1")
	if !errors.Is(err, ErrBackpressureExceeded) {
		t.Fatalf("at the mark must refuse fail-closed with ErrBackpressureExceeded, got %v", err)
	}
	if gate.ErrExceeded() != ErrBackpressureExceeded {
		t.Fatal("ErrExceeded must return the sentinel")
	}
}

func TestBackpressureRefusesAboveMark(t *testing.T) {
	store := &fakeBackpressureStore{pending: map[string]int{"t1": 42}}
	gate := NewBackpressure(store, 10)
	if err := gate.Allow(context.Background(), "t1"); !errors.Is(err, ErrBackpressureExceeded) {
		t.Fatalf("above the mark must refuse, got %v", err)
	}
}

func TestBackpressurePerTenant(t *testing.T) {
	store := &fakeBackpressureStore{pending: map[string]int{"noisy": 10, "quiet": 1}}
	gate := NewBackpressure(store, 10)
	if err := gate.Allow(context.Background(), "noisy"); !errors.Is(err, ErrBackpressureExceeded) {
		t.Fatalf("noisy tenant must be refused, got %v", err)
	}
	if err := gate.Allow(context.Background(), "quiet"); err != nil {
		t.Fatalf("quiet tenant must not inherit the noisy tenant's backlog, got %v", err)
	}
}

func TestBackpressurePropagatesStoreErrors(t *testing.T) {
	boom := errors.New("pg connection refused")
	gate := NewBackpressure(&fakeBackpressureStore{err: boom}, 10)
	if err := gate.Allow(context.Background(), "t1"); !errors.Is(err, boom) {
		t.Fatalf("store errors must propagate (fail-closed), got %v", err)
	}
}

func TestBackpressureDisabledWhenNoop(t *testing.T) {
	if err := NewBackpressure(nil, 10).Allow(context.Background(), "t1"); err != nil {
		t.Fatalf("nil store must disable the gate, got %v", err)
	}
	if err := NewBackpressure(&fakeBackpressureStore{pending: map[string]int{"t1": 999}}, 0).Allow(context.Background(), "t1"); err != nil {
		t.Fatalf("non-positive mark must disable the gate, got %v", err)
	}
	if err := NewBackpressure(&fakeBackpressureStore{pending: map[string]int{"t1": 999}}, -5).Allow(context.Background(), "t1"); err != nil {
		t.Fatalf("negative mark must disable the gate, got %v", err)
	}
	if NewBackpressure(nil, 0).ErrExceeded() != ErrBackpressureExceeded {
		t.Fatal("ErrExceeded must be callable on a disabled gate")
	}
}
