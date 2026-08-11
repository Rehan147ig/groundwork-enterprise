package aclsync

import (
	"context"
)

// DualSink fans every write out to a secondary sink (e.g. a second
// relationship backend kept warm during a migration or rollback window).
// The primary sink is authoritative: its write result is the operation
// result. The secondary is kept in sync best-effort — a secondary failure
// is reported via OnConflict (and counted in metrics) but never fails the
// operation, because the authoritative copy already succeeded. Reads
// always come from the primary.
//
// Typical wiring during dual-write:
//
//	primary   = the authoritative backend (e.g. SpiceDB)
//	secondary = the mirror backend
//
// The semantic rule is the same either way — the first sink decides, the
// second is mirrored.
type DualSink struct {
	primary   TupleSink
	secondary TupleSink
	// secondaryName identifies the secondary in conflict reports
	// (e.g. "secondary").
	secondaryName string
	// OnConflict, when set, is invoked with the tenant ID and the
	// secondary error whenever the secondary rejects a write/delete
	// the primary accepted.
	OnConflict func(tenantID string, err error)
}

// NewDualSink builds a dual sink with a default secondary name.
func NewDualSink(primary, secondary TupleSink) *DualSink {
	return NewDualSinkNamed(primary, secondary, "secondary")
}

// NewDualSinkNamed builds a dual sink with an explicit secondary name.
func NewDualSinkNamed(primary, secondary TupleSink, secondaryName string) *DualSink {
	return &DualSink{primary: primary, secondary: secondary, secondaryName: secondaryName}
}

// WriteTuples writes to both sinks. The primary's error, if any, is
// returned; a secondary error is only reported.
func (d *DualSink) WriteTuples(ctx context.Context, tenantID string, tuples []Tuple) error {
	if err := d.primary.WriteTuples(ctx, tenantID, tuples); err != nil {
		return err
	}
	if d.secondary != nil {
		if err := d.secondary.WriteTuples(ctx, tenantID, tuples); err != nil {
			d.reportConflict(tenantID, err)
		}
	}
	return nil
}

// DeleteTuples deletes from both sinks. Same semantics as WriteTuples.
func (d *DualSink) DeleteTuples(ctx context.Context, tenantID string, tuples []Tuple) error {
	if err := d.primary.DeleteTuples(ctx, tenantID, tuples); err != nil {
		return err
	}
	if d.secondary != nil {
		if err := d.secondary.DeleteTuples(ctx, tenantID, tuples); err != nil {
			d.reportConflict(tenantID, err)
		}
	}
	return nil
}

// ListTuples reads from the primary only — the authoritative copy.
func (d *DualSink) ListTuples(ctx context.Context, tenantID string) ([]Tuple, error) {
	return d.primary.ListTuples(ctx, tenantID)
}

func (d *DualSink) reportConflict(tenantID string, err error) {
	if d.OnConflict != nil {
		d.OnConflict(tenantID, err)
	}
}

var _ TupleSink = (*DualSink)(nil)
