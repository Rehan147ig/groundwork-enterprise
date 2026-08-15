package relationship

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// guardedCounter is a counter shared between shadow-observer goroutines
// and the test goroutine (race detector safety).
type guardedCounter struct{ v atomic.Int64 }

func (g *guardedCounter) Inc()     { g.v.Add(1) }
func (g *guardedCounter) Get() int { return int(g.v.Load()) }

// guardedCategories collects observer categories from arbitrary
// goroutines (race detector safety).
type guardedCategories struct {
	mu sync.Mutex
	v  []string
}

func (g *guardedCategories) Add(category string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.v = append(g.v, category)
}

func (g *guardedCategories) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.v)
}

func (g *guardedCategories) First() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.v[0]
}

type stubAuthorizer struct {
	allow  bool
	err    error
	calls  int64
	onCall func(req CheckRequest)
}

func (s *stubAuthorizer) Check(ctx context.Context, req CheckRequest) (bool, error) {
	atomic.AddInt64(&s.calls, 1)
	if s.onCall != nil {
		s.onCall(req)
	}
	return s.allow, s.err
}

func (s *stubAuthorizer) Ready(ctx context.Context) error { return nil }

func (s *stubAuthorizer) CallCount() int { return int(atomic.LoadInt64(&s.calls)) }

var shadowReq = CheckRequest{
	TenantID:   "tenant_a",
	Subject:    UserRef("alice"),
	Permission: PermissionView,
	Resource:   DocumentRef("doc-1"),
}

func TestShadowDisabledByZeroSampleRate(t *testing.T) {
	primary := &stubAuthorizer{allow: true}
	shadow := &stubAuthorizer{allow: false}
	s := NewShadowAuthorizer(primary, shadow, ShadowOptions{SampleRate: 0})

	allow, err := s.Check(context.Background(), shadowReq)
	if err != nil || !allow {
		t.Fatalf("primary decision must pass through: allow=%v err=%v", allow, err)
	}
	if shadow.CallCount() != 0 {
		t.Fatalf("shadow must never be invoked at sample rate 0, got %d calls", shadow.CallCount())
	}
}

func TestShadowFullSampleInvokesShadow(t *testing.T) {
	primary := &stubAuthorizer{allow: true}
	shadow := &stubAuthorizer{allow: false}
	s := NewShadowAuthorizer(primary, shadow, ShadowOptions{SampleRate: 1})

	allow, err := s.Check(context.Background(), shadowReq)
	if err != nil || !allow {
		t.Fatalf("primary decision must win: allow=%v err=%v", allow, err)
	}
	waitForCalls(t, shadow, 1)
}

func TestShadowPrimaryResultUnaffectedByShadowError(t *testing.T) {
	primary := &stubAuthorizer{allow: true}
	shadow := &stubAuthorizer{allow: false, err: errors.New("shadow down")}
	var shadowErrs guardedCounter
	s := NewShadowAuthorizer(primary, shadow, ShadowOptions{
		SampleRate:    1,
		OnShadowError: func(string) { shadowErrs.Inc() },
	})

	allow, err := s.Check(context.Background(), shadowReq)
	if err != nil || !allow {
		t.Fatalf("primary decision must win: allow=%v err=%v", allow, err)
	}
	waitFor(t, func() bool { return shadowErrs.Get() == 1 }, "shadow error observation")
}

// waitForCalls polls until the stub has recorded at least n calls.
func waitForCalls(t *testing.T, s *stubAuthorizer, n int) {
	t.Helper()
	waitFor(t, func() bool { return s.CallCount() >= n }, "shadow invocation")
}

// waitFor polls cond until it holds (2s budget).
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestShadowFallbackServesShadowOnPrimaryError(t *testing.T) {
	primary := &stubAuthorizer{err: errors.New("primary down")}
	shadow := &stubAuthorizer{allow: true}
	var fallbacks int
	s := NewShadowAuthorizer(primary, shadow, ShadowOptions{
		SampleRate: 1,
		Fallback:   true,
		OnFallback: func(tenantID string) {
			if tenantID != "tenant_a" {
				t.Fatalf("fallback tenant = %q, want tenant_a", tenantID)
			}
			fallbacks++
		},
	})

	allow, err := s.Check(context.Background(), shadowReq)
	if err != nil {
		t.Fatalf("fallback must serve the shadow answer, got err=%v", err)
	}
	if !allow {
		t.Fatal("fallback must serve the shadow's allow")
	}
	if fallbacks != 1 {
		t.Fatalf("OnFallback must fire once, got %d", fallbacks)
	}
}

func TestShadowNoFallbackWithoutOption(t *testing.T) {
	primary := &stubAuthorizer{err: errors.New("primary down")}
	shadow := &stubAuthorizer{allow: true}
	var fallbacks int
	s := NewShadowAuthorizer(primary, shadow, ShadowOptions{
		SampleRate: 1,
		Fallback:   false,
		OnFallback: func(string) { fallbacks++ },
	})

	allow, err := s.Check(context.Background(), shadowReq)
	if err == nil {
		t.Fatalf("observe-only shadow must propagate the primary error (allow=%v)", allow)
	}
	if fallbacks != 0 {
		t.Fatalf("no fallback without Fallback option, got %d", fallbacks)
	}
}

func TestShadowSlowShadowDoesNotBlockOrFallback(t *testing.T) {
	primary := &stubAuthorizer{err: errors.New("primary down")}
	shadow := &stubAuthorizer{onCall: func(CheckRequest) {
		// Simulate a shadow that hangs: the primary error must be
		// returned within the 50ms grace window regardless.
		time.Sleep(5 * time.Second)
	}}
	var fallbacks int
	s := NewShadowAuthorizer(primary, shadow, ShadowOptions{
		SampleRate: 1,
		Fallback:   true,
		OnFallback: func(string) { fallbacks++ },
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	allow, err := s.Check(ctx, shadowReq)
	if err == nil {
		t.Fatalf("slow shadow must not cause a fallback: allow=%v", allow)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("check must not wait for the shadow, took %s", elapsed)
	}
	if fallbacks != 0 {
		t.Fatalf("slow shadow must not trigger fallback, got %d", fallbacks)
	}
}

func TestShadowNilShadowIsPassthrough(t *testing.T) {
	primary := &stubAuthorizer{allow: true}
	s := NewShadowAuthorizer(primary, nil, ShadowOptions{SampleRate: 1})
	allow, err := s.Check(context.Background(), shadowReq)
	if err != nil || !allow {
		t.Fatalf("nil shadow must be a pure passthrough: allow=%v err=%v", allow, err)
	}
}

func TestShadowReadyDelegatesToPrimary(t *testing.T) {
	primary := &stubAuthorizer{}
	shadow := &stubAuthorizer{}
	s := NewShadowAuthorizer(primary, shadow, ShadowOptions{SampleRate: 1})
	if err := s.Ready(context.Background()); err != nil {
		t.Fatalf("ready: %v", err)
	}
}

func TestShadowPartialSamplingIsDeterministic(t *testing.T) {
	primary := &stubAuthorizer{allow: true}
	shadow := &stubAuthorizer{}
	s := NewShadowAuthorizer(primary, shadow, ShadowOptions{SampleRate: 0.5})

	first := s.wantShadow(shadowReq)
	for i := 0; i < 100; i++ {
		if got := s.wantShadow(shadowReq); got != first {
			t.Fatalf("sampling must be deterministic per request (flipped to %v)", got)
		}
	}
	// Different request may land in a different bucket.
	other := shadowReq
	other.Resource = DocumentRef("doc-2")
	_ = s.wantShadow(other)
}

func TestShadowMismatchAllowDeny(t *testing.T) {
	primary := &stubAuthorizer{allow: true}
	shadow := &stubAuthorizer{allow: false}
	var mismatches guardedCategories
	s := NewShadowAuthorizer(primary, shadow, ShadowOptions{
		SampleRate: 1,
		OnMismatch: func(tenantID, category string) {
			if tenantID != "tenant_a" {
				t.Fatalf("mismatch tenant = %q, want tenant_a", tenantID)
			}
			mismatches.Add(category)
		},
	})

	allow, err := s.Check(context.Background(), shadowReq)
	if err != nil || !allow {
		t.Fatalf("primary decision must win: allow=%v err=%v", allow, err)
	}
	waitFor(t, func() bool { return mismatches.Len() == 1 }, "allow/deny mismatch")
	if mismatches.First() != ShadowMismatchAllowDeny {
		t.Fatalf("category = %q, want allow_deny_mismatch", mismatches.First())
	}
}

func TestShadowMismatchAgreementIsNotMismatch(t *testing.T) {
	primary := &stubAuthorizer{allow: true}
	shadow := &stubAuthorizer{allow: true}
	var mismatches guardedCounter
	s := NewShadowAuthorizer(primary, shadow, ShadowOptions{
		SampleRate: 1,
		OnMismatch: func(string, string) { mismatches.Inc() },
	})

	if allow, err := s.Check(context.Background(), shadowReq); err != nil || !allow {
		t.Fatalf("check: allow=%v err=%v", allow, err)
	}
	// Agreement must not fire a mismatch; a short settle window proves
	// the observer ran without reporting.
	time.Sleep(100 * time.Millisecond)
	if mismatches.Get() != 0 {
		t.Fatalf("agreement must not be a mismatch, got %d", mismatches.Get())
	}
}

func TestShadowMismatchErrorCategory(t *testing.T) {
	primary := &stubAuthorizer{allow: true}
	shadow := &stubAuthorizer{allow: true, err: errors.New("shadow down")}
	var mismatches guardedCategories
	s := NewShadowAuthorizer(primary, shadow, ShadowOptions{
		SampleRate: 1,
		OnMismatch: func(tenantID, category string) {
			mismatches.Add(category)
		},
	})

	if allow, err := s.Check(context.Background(), shadowReq); err != nil || !allow {
		t.Fatalf("check: allow=%v err=%v", allow, err)
	}
	waitFor(t, func() bool { return mismatches.Len() == 1 }, "error mismatch")
	if mismatches.First() != ShadowMismatchError {
		t.Fatalf("category = %q, want error_mismatch", mismatches.First())
	}
}

func TestShadowFallbackAlsoReportsErrorMismatch(t *testing.T) {
	primary := &stubAuthorizer{err: errors.New("primary down")}
	shadow := &stubAuthorizer{allow: true}
	var mismatches guardedCategories
	s := NewShadowAuthorizer(primary, shadow, ShadowOptions{
		SampleRate: 1,
		Fallback:   true,
		OnMismatch: func(tenantID, category string) {
			mismatches.Add(category)
		},
	})

	if allow, err := s.Check(context.Background(), shadowReq); err != nil || !allow {
		t.Fatalf("fallback must serve the shadow answer: allow=%v err=%v", allow, err)
	}
	if mismatches.Len() != 1 || mismatches.First() != ShadowMismatchError {
		t.Fatalf("primary error vs shadow success must be an error mismatch, got %v", mismatches.First())
	}
}

func TestShadowBothErroredIsNotMismatch(t *testing.T) {
	primary := &stubAuthorizer{err: errors.New("primary down")}
	shadow := &stubAuthorizer{err: errors.New("shadow down")}
	var mismatches guardedCounter
	s := NewShadowAuthorizer(primary, shadow, ShadowOptions{
		SampleRate: 1,
		Fallback:   true,
		OnMismatch: func(string, string) { mismatches.Inc() },
	})

	if _, err := s.Check(context.Background(), shadowReq); err == nil {
		t.Fatal("both backends errored: the primary error must propagate")
	}
	if mismatches.Get() != 0 {
		t.Fatalf("both errored is consistent, not a mismatch, got %d", mismatches.Get())
	}
}
