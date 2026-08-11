// Package outbox runs the transactional-outbox delivery worker. It
// drains events enqueued atomically with business transactions (governance,
// agent registry) and delivers them to the configured webhook endpoint,
// HMAC-signed so receivers can verify the payloads came from this
// service.
//
// Delivery guarantees:
//   - at-least-once: events stay pending until a 2xx; receivers must
//     dedupe by event id;
//   - exponential backoff: failures reschedule with 2^n growth up to a
//     cap, then the event is dead-lettered for manual inspection;
//   - crash safety: a claimed event carries a lease; if the worker dies
//     mid-delivery the lease reaper returns the event to pending.
package outbox

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	gwhttpclient "groundwork/query-runtime/internal/httpclient"
	gwmetrics "groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/runtime"
)

// DeliveryStore is the delivery surface the worker drives. It matches
// governance.OutboxDeliveryStore so a governance store can be passed
// directly.
type DeliveryStore interface {
	ListPendingOutbox(ctx context.Context, limit int) ([]runtime.OutboxEvent, error)
	ClaimOutboxEvent(ctx context.Context, eventID string) error
	MarkOutboxDelivered(ctx context.Context, eventID string) error
	MarkOutboxDeadLetter(ctx context.Context, eventID, lastError string) error
	RescheduleOutboxEvent(ctx context.Context, eventID string, nextAttemptAt time.Time) error
}

// StatsSource is an optional capability stores may implement: it reports
// per-tenant outbox health (oldest pending age, dead-letter count) that
// the worker publishes to the pending-age and dead-letter gauges each
// cycle (Phase 8.5). It matches runtime.OutboxStatsSource.
type StatsSource interface {
	OutboxPendingStats(ctx context.Context) ([]runtime.OutboxTenantStats, error)
}

type Config struct {
	// Endpoint is the webhook URL events are POSTed to.
	Endpoint string
	// Secret signs every request (X-Groundwork-Signature). Empty
	// disables signing.
	Secret []byte
	// PollInterval is the gap between delivery cycles. Default 5s.
	PollInterval time.Duration
	// BatchSize caps events drained per cycle. Default 50.
	BatchSize int
	// MaxAttempts before an event is dead-lettered. Default 8.
	MaxAttempts int
	// BackoffBase is the first retry delay. Default 1s.
	BackoffBase time.Duration
	// BackoffCap caps the retry delay. Default 5m.
	BackoffCap time.Duration
	// Lease is how long a claimed event may stay in-flight before the
	// reaper returns it to pending. Default 60s.
	Lease time.Duration
	// HTTPClient overrides the delivery client (default: 10s timeout).
	HTTPClient *http.Client
	// Logger defaults to log.Default().
	Logger *log.Logger
	// PreDeliver is invoked before each delivery attempt with the
	// event's tenant id. Returning an error SKIPS the delivery: the
	// event is left pending (no claim, no attempt bump, no webhook
	// POST) and is retried on the next cycle (Phase 8.1 enforces the
	// outbox_deliveries quota this way — over-quota events stay queued
	// until the tenant's quota is raised or the month rolls over).
	// Nil-safe.
	PreDeliver func(tenantID string) error
	// BreakerFailureLimit is the number of consecutive delivery failures
	// that open the per-tenant delivery circuit. Default 3.
	BreakerFailureLimit int
	// BreakerOpenTimeout is how long an open delivery circuit stays open
	// before allowing a probe. Default 30s.
	BreakerOpenTimeout time.Duration
}

// Worker delivers outbox events until the context is cancelled.
type Worker struct {
	store       DeliveryStore
	endpoint    string
	secret      []byte
	interval    time.Duration
	batchSize   int
	maxAttempts int
	backoffBase time.Duration
	backoffCap  time.Duration
	client      *http.Client
	logger      *log.Logger
	preDeliver  func(tenantID string) error
	// breakers is the per-tenant delivery circuit (Phase 8.2): when a
	// webhook is down, consecutive failures open the tenant's circuit
	// and the worker stops POSTing (events stay pending) until a probe
	// succeeds. A dead endpoint is thereby priced in failed attempts
	// once, not every poll cycle.
	breakers *runtime.BreakerRegistry
}

// NewWorker builds a worker from cfg (zero fields get safe defaults).
func NewWorker(store DeliveryStore, cfg Config) *Worker {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 8
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = time.Second
	}
	if cfg.BackoffCap <= 0 {
		cfg.BackoffCap = 5 * time.Minute
	}
	if cfg.HTTPClient == nil {
		// Pooled delivery client (Phase 8.2 connection pool
		// configuration): bounded, env-tunable idle connections with a
		// 10s request budget.
		cfg.HTTPClient = gwhttpclient.PoolFromEnv("GROUNDWORK_HTTP_POOL", gwhttpclient.DefaultPool()).Client(10 * time.Second)
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.BreakerFailureLimit <= 0 {
		cfg.BreakerFailureLimit = 3
	}
	if cfg.BreakerOpenTimeout <= 0 {
		cfg.BreakerOpenTimeout = 30 * time.Second
	}
	return &Worker{
		store: store, endpoint: cfg.Endpoint, secret: cfg.Secret,
		interval: cfg.PollInterval, batchSize: cfg.BatchSize,
		maxAttempts: cfg.MaxAttempts, backoffBase: cfg.BackoffBase,
		backoffCap: cfg.BackoffCap, client: cfg.HTTPClient, logger: cfg.Logger,
		preDeliver: cfg.PreDeliver,
		breakers: runtime.NewBreakerRegistry(runtime.CircuitBreakerSettings{
			Name: "outbox_delivery", FailureLimit: cfg.BreakerFailureLimit,
			OpenTimeout: cfg.BreakerOpenTimeout, HalfOpenLimit: 1,
		}),
	}
}

// Run polls the store until ctx is cancelled, then returns nil. Store
// errors are logged and skipped so a transient DB outage does not kill
// the worker.
func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	if err := w.tick(ctx); err != nil {
		w.logger.Printf("outbox: initial cycle: %v", err)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := w.tick(ctx); err != nil {
				w.logger.Printf("outbox: cycle: %v", err)
			}
		}
	}
}

// tick runs one delivery cycle: reap stale leases, drain pending events,
// then refresh the outbox health gauges.
func (w *Worker) tick(ctx context.Context) error {
	if err := w.reap(ctx); err != nil {
		return fmt.Errorf("reap leases: %w", err)
	}
	pending, err := w.store.ListPendingOutbox(ctx, w.batchSize)
	if err != nil {
		return fmt.Errorf("list pending: %w", err)
	}
	for _, e := range pending {
		if err := w.deliver(ctx, e); err != nil {
			w.logger.Printf("outbox: event %s: %v", e.EventID, err)
		}
	}
	if err := w.collectStats(ctx); err != nil {
		return fmt.Errorf("outbox stats: %w", err)
	}
	return nil
}

// collectStats publishes the per-tenant pending-age and dead-letter
// gauges when the store supports stats; absent that capability it is a
// no-op. Stats refresh failures never fail the delivery cycle.
func (w *Worker) collectStats(ctx context.Context) error {
	stats, ok := w.store.(StatsSource)
	if !ok {
		return nil
	}
	tenants, err := stats.OutboxPendingStats(ctx)
	if err != nil {
		return err
	}
	for _, t := range tenants {
		gwmetrics.SetOutboxPending(t.TenantID, t.PendingCount)
		if t.OldestPendingAt.IsZero() {
			gwmetrics.SetOutboxPendingAge(t.TenantID, 0)
		} else {
			gwmetrics.SetOutboxPendingAge(t.TenantID, time.Since(t.OldestPendingAt))
		}
		gwmetrics.SetOutboxDeadLetterPending(t.TenantID, t.DeadLetterCount)
	}
	return nil
}

func (w *Worker) reap(ctx context.Context) error {
	r, ok := w.store.(interface {
		ReapExpiredLeases(ctx context.Context) error
	})
	if !ok {
		return nil
	}
	return r.ReapExpiredLeases(ctx)
}

// deliver claims the event and attempts one webhook POST, then marks
// delivered, reschedules with exponential backoff, or dead-letters.
// The PreDeliver gate runs BEFORE the claim: a denied (e.g. over-quota)
// event is left untouched and pending, so no attempt is consumed and
// the next cycle retries it.
func (w *Worker) deliver(ctx context.Context, e runtime.OutboxEvent) error {
	if w.preDeliver != nil {
		if err := w.preDeliver(e.TenantID); err != nil {
			return fmt.Errorf("delivery skipped by policy: %w", err)
		}
	}
	// Phase 8.2 delivery circuit: while the tenant's breaker is open,
	// events are left pending (no claim, no attempt consumed, no webhook
	// POST) until a probe succeeds. The failure that opened the circuit
	// is thereby paid once instead of once per poll cycle, and the
	// pending backlog (which outbox backpressure then refuses to grow)
	// stays capped.
	breaker := w.breakers.For(e.TenantID)
	if err := breaker.Allow(); err != nil {
		gwmetrics.SetOutboxDeliveryBreakerState(e.TenantID, runtime.CircuitStateValue(breaker.State()))
		gwmetrics.RecordOutboxDeliveryBreakerSkip(e.TenantID)
		return nil
	}
	if err := w.store.ClaimOutboxEvent(ctx, e.ID); err != nil {
		return fmt.Errorf("claim: %w", err)
	}
	resp, attempt, err := w.post(ctx, e)
	if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		breaker.ReportSuccess()
		gwmetrics.SetOutboxDeliveryBreakerState(e.TenantID, runtime.CircuitStateValue(breaker.State()))
		if err := w.store.MarkOutboxDelivered(ctx, e.ID); err != nil {
			return fmt.Errorf("mark delivered: %w", err)
		}
		gwmetrics.RecordOutboxDelivered(e.EventType)
		return nil
	}
	if err == nil {
		err = fmt.Errorf("webhook returned %s", resp.Status)
	}
	breaker.ReportFailure()
	gwmetrics.SetOutboxDeliveryBreakerState(e.TenantID, runtime.CircuitStateValue(breaker.State()))
	if breaker.State() == runtime.CircuitOpen {
		gwmetrics.RecordOutboxDeliveryBreakerTrip(e.TenantID)
	}
	if attempt >= w.maxAttempts {
		if merr := w.store.MarkOutboxDeadLetter(ctx, e.ID, err.Error()); merr != nil {
			return fmt.Errorf("dead-letter: %v (original: %v)", merr, err)
		}
		gwmetrics.RecordOutboxDeadLetter(e.EventType)
		return nil
	}
	delay := w.backoffBase << (attempt - 1)
	if delay > w.backoffCap {
		delay = w.backoffCap
	}
	next := time.Now().UTC().Add(delay)
	if rerr := w.store.RescheduleOutboxEvent(ctx, e.ID, next); rerr != nil {
		return fmt.Errorf("reschedule: %v (original: %v)", rerr, err)
	}
	return err
}

// post sends one signed delivery request and returns the response, the
// attempt number the store recorded, and any error.
func (w *Worker) post(ctx context.Context, e runtime.OutboxEvent) (*http.Response, int, error) {
	body := e.Payload
	if len(body) == 0 {
		body = []byte("{}")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Groundwork-Event-ID", e.EventID)
	req.Header.Set("X-Groundwork-Event-Type", e.EventType)
	req.Header.Set("X-Groundwork-Tenant-ID", e.TenantID)
	if len(w.secret) > 0 {
		ts := time.Now().Unix()
		req.Header.Set("X-Groundwork-Timestamp", fmt.Sprintf("%d", ts))
		req.Header.Set("X-Groundwork-Signature", "v1="+signature(w.secret, ts, e.EventID, body))
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, e.Attempts + 1, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	return resp, e.Attempts + 1, nil
}

// signature HMAC-SHA256 signs the canonical delivery string
// "v1:<ts>:<event_id>:<body>".
func signature(secret []byte, ts int64, eventID string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = fmt.Fprintf(mac, "v1:%d:%s:", ts, eventID)
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks a signed request header against the body. It is
// exported for webhook receivers (and tests) to validate deliveries.
func VerifySignature(secret []byte, ts int64, eventID string, body []byte, want string) bool {
	if want == "" || len(secret) == 0 {
		return false
	}
	wantHex, err := hex.DecodeString(want)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = fmt.Fprintf(mac, "v1:%d:%s:", ts, eventID)
	_, _ = mac.Write(body)
	return hmac.Equal(wantHex, mac.Sum(nil))
}
