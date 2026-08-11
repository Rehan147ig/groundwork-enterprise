package outbox

import (
	"context"
	"errors"
	"fmt"

	gwmetrics "groundwork/query-runtime/internal/metrics"
)

// ErrBackpressureExceeded is returned by Backpressure.Allow when the
// tenant's pending outbox events are at or above the high-water mark.
// Callers must treat it as a fail-closed denial (HTTP 503
// outbox_backpressure): the evidence pipeline is backed up, so accepting
// more work would only deepen the backlog.
var ErrBackpressureExceeded = errors.New("outbox_backpressure: pending events above high-water mark")

// BackpressureStore is the optional store capability Backpressure uses
// to read a tenant's pending-event depth. It matches the governance
// store surface (memory + Postgres both implement it).
type BackpressureStore interface {
	CountPendingOutbox(ctx context.Context, tenantID string) (int, error)
}

// Backpressure is the Phase 8.2 gate that refuses new evidence-producing
// work when the outbox delivery pipeline is constrained. The outbox
// table is the bounded buffer between decisions and delivery: when the
// webhook is slow or down, pending events accumulate without limit. The
// high-water mark turns that unbounded backlog into an explicit,
// fail-closed rejection at the entry point instead of a silent
// degradation hours later.
type Backpressure struct {
	store BackpressureStore
	// MaxPending is the per-tenant high-water mark. <= 0 disables the
	// gate (the default — opt-in via OUTBOX_BACKPRESSURE_MAX_PENDING).
	MaxPending int
}

// NewBackpressure builds the gate. A nil store or a non-positive
// MaxPending makes Allow a no-op, so an unconfigured or partially wired
// deployment never throttles itself.
func NewBackpressure(store BackpressureStore, maxPending int) *Backpressure {
	return &Backpressure{store: store, MaxPending: maxPending}
}

// ErrExceeded returns the sentinel error Allow returns at the
// high-water mark. It exists so callers can classify refusals through
// the engine's BackpressureGate interface without importing this
// package.
func (b *Backpressure) ErrExceeded() error { return ErrBackpressureExceeded }

// Allow reports whether the tenant may enqueue more evidence work. It
// returns ErrBackpressureExceeded at or above the high-water mark. A
// store read failure also returns an error — the dependency is
// unreadable, which is itself a constraint the caller must fail closed
// on (never "assume the backlog is fine").
func (b *Backpressure) Allow(ctx context.Context, tenantID string) error {
	if b == nil || b.store == nil || b.MaxPending <= 0 {
		return nil
	}
	n, err := b.store.CountPendingOutbox(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("count pending outbox: %w", err)
	}
	if n >= b.MaxPending {
		gwmetrics.RecordOutboxBackpressureRejection(tenantID)
		return ErrBackpressureExceeded
	}
	return nil
}
