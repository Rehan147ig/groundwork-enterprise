package telemetry

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTraceParentRoundTrip(t *testing.T) {
	tc := NewTraceContext()
	parsed, ok := ParseTraceParent(tc.String())
	if !ok {
		t.Fatalf("valid traceparent %q must parse", tc.String())
	}
	if parsed.TraceID != tc.TraceID || parsed.SpanID != tc.SpanID || !parsed.Sampled {
		t.Fatalf("round trip mismatch: got %+v want %+v", parsed, tc)
	}
}

func TestParseTraceParentRejectsGarbage(t *testing.T) {
	bad := []string{
		"",
		"00-abc", "01-deadbeef-00", "ff-00000000000000000000000000000000-0000000000000000-01",
		"00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-0000000000000000-01",
		"00-00000000000000000000000000000000-zzzzzzzzzzzzzzzz-01",
		"00-00000000000000000000000000000000-0000000000000000",
	}
	for _, h := range bad {
		if _, ok := ParseTraceParent(h); ok {
			t.Fatalf("header %q must be rejected", h)
		}
	}
}

func TestUnsampledTraceFlag(t *testing.T) {
	tc := NewTraceContext()
	parts := strings.Split(tc.String(), "-")
	header := parts[0] + "-" + parts[1] + "-" + parts[2] + "-00"
	if header == tc.String() {
		t.Fatal("fixture must differ from sampled context")
	}
	parsed, ok := ParseTraceParent(header)
	if !ok || parsed.Sampled {
		t.Fatalf("00 flags must parse as unsampled, got %+v ok=%v", parsed, ok)
	}
}

func TestContextPropagationAndChildSpans(t *testing.T) {
	parent := NewTraceContext()
	ctx := WithTraceContext(context.Background(), parent)
	if got := TraceContextFromContext(ctx); got != parent {
		t.Fatalf("context round trip mismatch: got %+v want %+v", got, parent)
	}
	if got := TraceContextFromContext(context.Background()); !got.IsZero() {
		t.Fatal("background context must carry zero trace context")
	}

	child := Child(parent)
	if child.TraceID != parent.TraceID {
		t.Fatal("child must keep the parent trace id")
	}
	if child.SpanID == parent.SpanID {
		t.Fatal("child must derive a fresh span id")
	}
	if child.IsZero() {
		t.Fatal("child must not be zero")
	}
	if got := Child(TraceContext{}); got.IsZero() {
		t.Fatal("orphan child must start a new trace")
	}

	ctx2, span := StartSpan(ctx, "test.op")
	span.Observe = func(name string, tc TraceContext, d time.Duration) {
		if name != "test.op" {
			t.Fatalf("span name must be preserved, got %q", name)
		}
		if tc.TraceID != parent.TraceID {
			t.Fatal("span must inherit the trace id")
		}
		if d < 0 {
			t.Fatalf("duration must be non-negative, got %v", d)
		}
	}
	if TraceContextFromContext(ctx2).SpanID == parent.SpanID {
		t.Fatal("child context must carry the child span id")
	}
	span.End()

	if !strings.HasPrefix(span.Context().String(), "00-") {
		t.Fatalf("span context must render a traceparent, got %q", span.Context().String())
	}
}
