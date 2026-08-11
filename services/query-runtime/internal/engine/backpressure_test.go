// Phase 8.2 engine backpressure: when the outbox gate refuses, the
// query fails closed with its own error code (outbox_backpressure) so
// operators can distinguish "evidence pipeline backed up" from "audit
// store broken". Unset gate = unconstrained.

package engine

import (
	"context"
	"errors"
	"testing"

	"groundwork/query-runtime/internal/outbox"
	"groundwork/query-runtime/internal/runtime"
)

type fakeGate struct {
	allowErr error
	refused  bool
}

func (f *fakeGate) Allow(_ context.Context, _ string) error {
	if f.refused {
		return outbox.ErrBackpressureExceeded
	}
	return f.allowErr
}

func (f *fakeGate) ErrExceeded() error { return outbox.ErrBackpressureExceeded }

func TestExecuteBackpressureFailsClosedWithDistinctCode(t *testing.T) {
	e := testEngineWithACL(true)
	e.Backpressure = &fakeGate{refused: true}

	resp := e.Execute(context.Background(), runtime.QueryRequest{TenantID: "acme", Region: "US", UserID: "finance_user", Question: "policy"})

	if resp.Trace.FailureStage != "audit" || resp.Trace.ErrorCode != "outbox_backpressure" {
		t.Fatalf("expected outbox_backpressure fail-closed, got %+v", resp.Trace)
	}
	if len(resp.Citations) != 0 {
		t.Fatalf("backpressure refusal must return zero chunks, got %+v", resp.Citations)
	}
}

func TestExecuteBackpressureGuardsDeniedQueries(t *testing.T) {
	// Denied queries still write evidence (TestAuditDeniedQueryWritesEntry
	// pins this), so the gate guards them too — the pipeline must be
	// able to absorb the record.
	e := testEngineWithACL(false)
	e.Backpressure = &fakeGate{refused: true}

	resp := e.Execute(context.Background(), runtime.QueryRequest{TenantID: "acme", Region: "US", UserID: "general_user", Question: "policy"})

	if resp.Trace.FailureStage != "audit" || resp.Trace.ErrorCode != "outbox_backpressure" {
		t.Fatalf("denied queries still write evidence; backpressure must fail them closed, got %+v", resp.Trace)
	}
}

func TestExecuteBackpressurePropagatesStoreErrors(t *testing.T) {
	boom := errors.New("pg down")
	e := testEngineWithACL(true)
	e.Backpressure = &fakeGate{allowErr: boom}

	resp := e.Execute(context.Background(), runtime.QueryRequest{TenantID: "acme", Region: "US", UserID: "finance_user", Question: "policy"})

	if resp.Trace.ErrorCode != "audit_write_failed" {
		t.Fatalf("store errors must classify as audit_write_failed, got %+v", resp.Trace)
	}
}

func TestExecuteBackpressureUnsetIsUnconstrained(t *testing.T) {
	e := testEngineWithACL(true)
	// No gate wired: the query must complete normally.
	resp := e.Execute(context.Background(), runtime.QueryRequest{TenantID: "acme", Region: "US", UserID: "finance_user", Question: "policy"})
	if resp.Trace.FailureStage != "" || len(resp.Citations) != 1 {
		t.Fatalf("unset gate must not throttle, got %+v", resp.Trace)
	}
}
