// Package telemetry provides dependency-free distributed tracing: W3C
// trace-context (traceparent) parsing/generation and span timing. It
// intentionally does not pull in an OTel SDK; spans are propagated as
// context values and can be exported to any sink by the caller.
package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// TraceContext is a W3C traceparent (version 00) segment.
type TraceContext struct {
	TraceID [16]byte
	SpanID  [8]byte
	Sampled bool
}

// NewTraceContext starts a fresh trace.
func NewTraceContext() TraceContext {
	var tc TraceContext
	_, _ = rand.Read(tc.TraceID[:])
	_, _ = rand.Read(tc.SpanID[:])
	tc.Sampled = true
	return tc
}

// ParseTraceParent parses a traceparent header. Invalid headers return
// ok=false; callers should start a new trace.
func ParseTraceParent(header string) (TraceContext, bool) {
	parts := strings.Split(strings.TrimSpace(header), "-")
	if len(parts) != 4 || parts[0] != "00" {
		return TraceContext{}, false
	}
	if len(parts[1]) != 32 || len(parts[2]) != 16 {
		return TraceContext{}, false
	}
	traceID, err := hex.DecodeString(parts[1])
	if err != nil {
		return TraceContext{}, false
	}
	spanID, err := hex.DecodeString(parts[2])
	if err != nil {
		return TraceContext{}, false
	}
	tc := TraceContext{Sampled: parts[3] == "01"}
	copy(tc.TraceID[:], traceID)
	copy(tc.SpanID[:], spanID)
	return tc, true
}

// String renders the traceparent header value.
func (tc TraceContext) String() string {
	flags := "00"
	if tc.Sampled {
		flags = "01"
	}
	return fmt.Sprintf("00-%s-%s-%s",
		hex.EncodeToString(tc.TraceID[:]),
		hex.EncodeToString(tc.SpanID[:]),
		flags,
	)
}

// IsZero reports whether the context carries no trace.
func (tc TraceContext) IsZero() bool {
	return tc.TraceID == [16]byte{} && tc.SpanID == [8]byte{}
}

type traceContextKey struct{}

// WithTraceContext stores tc in ctx.
func WithTraceContext(ctx context.Context, tc TraceContext) context.Context {
	return context.WithValue(ctx, traceContextKey{}, tc)
}

// TraceContextFromContext returns the stored context, or a zero value.
func TraceContextFromContext(ctx context.Context) TraceContext {
	if tc, ok := ctx.Value(traceContextKey{}).(TraceContext); ok {
		return tc
	}
	return TraceContext{}
}

// Child derives a child span id from the parent context. A zero parent
// starts a new trace.
func Child(parent TraceContext) TraceContext {
	tc := parent
	if tc.IsZero() {
		return NewTraceContext()
	}
	_, _ = rand.Read(tc.SpanID[:])
	tc.Sampled = true
	return tc
}

// Span is a timed child span; End records the duration (and may be
// exported by the caller-provided observer).
type Span struct {
	ctx     TraceContext
	name    string
	started time.Time
	Observe func(name string, tc TraceContext, duration time.Duration)
}

// StartSpan begins a child span of the trace in ctx.
func StartSpan(ctx context.Context, name string) (context.Context, *Span) {
	parent := TraceContextFromContext(ctx)
	child := Child(parent)
	return WithTraceContext(ctx, child), &Span{
		ctx: child, name: name, started: time.Now(),
		Observe: func(string, TraceContext, time.Duration) {},
	}
}

// End stops the span and reports its duration to Observe (if set).
func (s *Span) End() {
	if s == nil {
		return
	}
	if s.Observe != nil {
		s.Observe(s.name, s.ctx, time.Since(s.started))
	}
}

// Context returns the span's trace context (for outbound headers).
func (s *Span) Context() TraceContext {
	return s.ctx
}
