package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Phase 8.5 observability metrics: decision-latency decomposition,
// outbox health (age), connector health, and key expiry monitoring.
// Labels are bounded (no run/event/key ids) to keep cardinality safe.
var (
	DecisionGateDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "groundwork_decision_gate_duration_seconds",
			Help:    "Duration of one governed decision gate (controls, grant_binding, agent, permitted, tool, grant, budget, relationship, approval)",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5},
		},
		[]string{"tenant_id", "gate"},
	)
	OutboxPendingAgeSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "groundwork_outbox_pending_age_seconds", Help: "Age of the oldest pending outbox event per tenant"},
		[]string{"tenant_id"},
	)
	OutboxDeadLetterPending = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "groundwork_outbox_dead_letter_pending", Help: "Dead-lettered outbox events awaiting manual inspection"},
		[]string{"tenant_id"},
	)
	ConnectorHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "groundwork_connector_health", Help: "Last health probe result per connector (1 healthy, 0 unhealthy, -1 unknown)"},
		[]string{"tenant_id", "connector_id"},
	)
	KeyExpiryTimestampSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "groundwork_key_expiry_timestamp_seconds", Help: "Key expiry as a Unix timestamp per purpose (0 = no expiry)"},
		[]string{"purpose"},
	)
	KeyDaysUntilExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "groundwork_key_days_until_expiry", Help: "Days until key expiry per purpose (negative = expired, 0 = no expiry configured)"},
		[]string{"purpose"},
	)
	// Connector credential expiry (Phase 8.5): days-until-expiry per
	// connector secret reference (keyring://<purpose> — the reference,
	// never material). 0 = no expiry metadata (env-provided or
	// never-expiring); negative = expired. Labeled with the secret
	// reference so rotation owners can tell which purpose is due.
	ConnectorCredentialExpiryTimestampSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "groundwork_connector_credential_expiry_timestamp_seconds", Help: "Connector credential expiry as a Unix timestamp per connector secret ref (0 = no expiry metadata)"},
		[]string{"tenant_id", "connector_id", "secret_ref"},
	)
	ConnectorCredentialDaysUntilExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "groundwork_connector_credential_days_until_expiry", Help: "Days until connector credential expiry (negative = expired, 0 = no expiry metadata)"},
		[]string{"tenant_id", "connector_id", "secret_ref"},
	)
	// SLO counters (Phase 8.5 acceptance: decision rate, denial rate,
	// fail-closed rate, error rate). Labels are bounded (outcome, method,
	// status class, error code) to keep cardinality safe.
	SLODecisionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_slo_decisions_total", Help: "Governed decision outcomes (allowed, denied, fail_closed, approval_required)"},
		[]string{"tenant_id", "outcome"},
	)
	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_http_requests_total", Help: "API requests by tenant, method, and status class (2xx/3xx/4xx/5xx)"},
		[]string{"tenant_id", "method", "code_class"},
	)
	ConnectorErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_connector_errors_total", Help: "Failed connector dispatches by error code"},
		[]string{"tenant_id", "connector_id", "error_code"},
	)
	// Overload + backpressure rejections (Phase 8.2): requests refused
	// because the instance or the evidence pipeline is saturated.
	OverloadRejectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_overload_rejections_total", Help: "Requests rejected because the instance-wide concurrency cap was reached (503 overload_exceeded)"},
		[]string{"tenant_id"},
	)
	OutboxBackpressureRejectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_outbox_backpressure_rejections_total", Help: "Protected actions denied because the tenant's pending outbox exceeded the high-water mark (fail-closed)"},
		[]string{"tenant_id"},
	)
	// Per-tenant capacity (Phase 8.2 capacity model): requests refused
	// because the tenant reached its tier's in-flight concurrency cap.
	TenantCapacityRejectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_tenant_capacity_rejections_total", Help: "Requests rejected because the tenant reached its capacity-tier in-flight concurrency cap (503 concurrency_limit_exceeded)"},
		[]string{"tenant_id"},
	)
	// Dispatch circuit breakers (Phase 8.2): a dead connector or a dead
	// delivery endpoint fails fast instead of burning timeout + retry
	// budget on every call. State gauges: 0 closed, 1 half_open, 2 open.
	ConnectorBreakerState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "groundwork_connector_breaker_state", Help: "Dispatch circuit state per connector (0 closed, 1 half_open, 2 open)"},
		[]string{"tenant_id", "connector_id"},
	)
	ConnectorBreakerTripsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_connector_breaker_trips_total", Help: "Times the dispatch breaker transitioned to open per connector"},
		[]string{"tenant_id", "connector_id"},
	)
	OutboxDeliveryBreakerState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "groundwork_outbox_delivery_breaker_state", Help: "Delivery circuit state per tenant (0 closed, 1 half_open, 2 open)"},
		[]string{"tenant_id"},
	)
	OutboxDeliveryBreakerTripsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_outbox_delivery_breaker_trips_total", Help: "Times the delivery breaker transitioned to open per tenant"},
		[]string{"tenant_id"},
	)
	OutboxDeliveryBreakerSkipsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_outbox_delivery_breaker_skips_total", Help: "Delivery attempts skipped while the breaker was open (events stay pending, no attempt consumed)"},
		[]string{"tenant_id"},
	)
	// Dispatch idempotency (Phase 8.2): client retries of an already
	// executed logical mutation are replayed from evidence instead of
	// calling the upstream a second time.
	ConnectorDispatchReplaysTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_connector_dispatch_replays_total", Help: "Dispatches replayed from recorded evidence instead of re-calling the connector (same idempotency key already succeeded)"},
		[]string{"tenant_id"},
	)

	registerPhase8Once sync.Once
)

// RecordDecisionGate is called once per gate evaluated in a governed
// decision (governance evaluateInTx). Gate names are a closed set.
func RecordDecisionGate(tenantID, gate string, duration time.Duration) {
	DecisionGateDuration.WithLabelValues(tenantID, gate).Observe(duration.Seconds())
}

// SetOutboxPendingAge reports the age of the tenant's oldest pending
// outbox event (gauge, updated by the worker on a cadence).
func SetOutboxPendingAge(tenantID string, age time.Duration) {
	OutboxPendingAgeSeconds.WithLabelValues(tenantID).Set(age.Seconds())
}

// SetOutboxDeadLetterPending reports the tenant's dead-lettered outbox
// count awaiting manual inspection.
func SetOutboxDeadLetterPending(tenantID string, count int) {
	OutboxDeadLetterPending.WithLabelValues(tenantID).Set(float64(count))
}

// SetConnectorHealth records the outcome of one connector health probe
// (1 healthy, 0 unhealthy).
func SetConnectorHealth(tenantID, connectorID string, healthy bool) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	ConnectorHealth.WithLabelValues(tenantID, connectorID).Set(value)
}

// SetKeyExpiryMetrics reports a purpose key's expiry. A zero expiry
// (no expiry configured) sets the timestamp gauge to 0 and the
// days-until gauge to 0; an expired key yields a negative
// days-until value so expiry monitoring alerts on it.
func SetKeyExpiryMetrics(purpose string, expiry time.Time) {
	if expiry.IsZero() {
		KeyExpiryTimestampSeconds.WithLabelValues(purpose).Set(0)
		KeyDaysUntilExpiry.WithLabelValues(purpose).Set(0)
		return
	}
	KeyExpiryTimestampSeconds.WithLabelValues(purpose).Set(float64(expiry.Unix()))
	KeyDaysUntilExpiry.WithLabelValues(purpose).Set(time.Until(expiry).Hours() / 24)
}

// SetConnectorCredentialExpiryMetrics reports one connector's secret
// expiry (Phase 8.5). Zero expiry (no metadata) sets both gauges to 0;
// an expired credential yields a negative days-until value so the
// monitoring alert fires.
func SetConnectorCredentialExpiryMetrics(tenantID, connectorID, secretRef string, expiry time.Time) {
	if expiry.IsZero() {
		ConnectorCredentialExpiryTimestampSeconds.WithLabelValues(tenantID, connectorID, secretRef).Set(0)
		ConnectorCredentialDaysUntilExpiry.WithLabelValues(tenantID, connectorID, secretRef).Set(0)
		return
	}
	ConnectorCredentialExpiryTimestampSeconds.WithLabelValues(tenantID, connectorID, secretRef).Set(float64(expiry.Unix()))
	ConnectorCredentialDaysUntilExpiry.WithLabelValues(tenantID, connectorID, secretRef).Set(time.Until(expiry).Hours() / 24)
}

// RecordSLODecision counts one governed decision outcome. Outcomes come
// from the closed runtime.Decision* set (allowed | denied |
// fail_closed | approval_required).
func RecordSLODecision(tenantID, outcome string) {
	SLODecisionsTotal.WithLabelValues(tenantID, outcome).Inc()
}

// RecordHTTPRequest counts one API request by status class once its
// handler has responded. codeClass must be one of 2xx/3xx/4xx/5xx (see
// StatusClass).
func RecordHTTPRequest(tenantID, method, codeClass string) {
	HTTPRequestsTotal.WithLabelValues(tenantID, method, codeClass).Inc()
}

// RecordConnectorError counts one failed connector dispatch. errorCode
// comes from the closed ConnectorDispatchResult.ErrorCode set.
func RecordConnectorError(tenantID, connectorID, errorCode string) {
	ConnectorErrorsTotal.WithLabelValues(tenantID, connectorID, errorCode).Inc()
}

// RecordOverloadRejection counts one request refused by the
// instance-wide overload limiter (503 overload_exceeded).
func RecordOverloadRejection(tenantID string) {
	OverloadRejectionsTotal.WithLabelValues(tenantID).Inc()
}

// RecordTenantCapacityRejection counts one request refused because the
// tenant reached its capacity-tier in-flight cap (503
// concurrency_limit_exceeded).
func RecordTenantCapacityRejection(tenantID string) {
	TenantCapacityRejectionsTotal.WithLabelValues(tenantID).Inc()
}

// RecordOutboxBackpressureRejection counts one protected action denied
// because the tenant's pending outbox exceeded the high-water mark
// (fail-closed, 503 outbox_backpressure).
func RecordOutboxBackpressureRejection(tenantID string) {
	OutboxBackpressureRejectionsTotal.WithLabelValues(tenantID).Inc()
}

// SetConnectorBreakerState publishes the dispatch circuit state for a
// connector. state is 0 closed, 1 half_open, 2 open (see
// runtime.CircuitStateValue).
func SetConnectorBreakerState(tenantID, connectorID string, state float64) {
	ConnectorBreakerState.WithLabelValues(tenantID, connectorID).Set(state)
}

// RecordConnectorBreakerTrip counts one dispatch breaker transition to
// open for a connector.
func RecordConnectorBreakerTrip(tenantID, connectorID string) {
	ConnectorBreakerTripsTotal.WithLabelValues(tenantID, connectorID).Inc()
}

// SetOutboxDeliveryBreakerState publishes the delivery circuit state for
// a tenant. state is 0 closed, 1 half_open, 2 open.
func SetOutboxDeliveryBreakerState(tenantID string, state float64) {
	OutboxDeliveryBreakerState.WithLabelValues(tenantID).Set(state)
}

// RecordOutboxDeliveryBreakerTrip counts one delivery breaker transition
// to open for a tenant.
func RecordOutboxDeliveryBreakerTrip(tenantID string) {
	OutboxDeliveryBreakerTripsTotal.WithLabelValues(tenantID).Inc()
}

// RecordOutboxDeliveryBreakerSkip counts one delivery attempt skipped
// while the tenant's breaker was open (event stays pending, no attempt
// consumed, no webhook POST).
func RecordOutboxDeliveryBreakerSkip(tenantID string) {
	OutboxDeliveryBreakerSkipsTotal.WithLabelValues(tenantID).Inc()
}

// RecordConnectorDispatchReplay counts one dispatch answered from
// recorded evidence because the same idempotency key already succeeded
// (no quota consumed, no connector call, no new evidence row).
func RecordConnectorDispatchReplay(tenantID string) {
	ConnectorDispatchReplaysTotal.WithLabelValues(tenantID).Inc()
}

// RegisterPhase8 registers the Phase 8.5 metrics (idempotent).
func RegisterPhase8() {
	registerPhase8Once.Do(func() {
		prometheus.MustRegister(
			DecisionGateDuration,
			OutboxPendingAgeSeconds,
			OutboxDeadLetterPending,
			ConnectorHealth,
			KeyExpiryTimestampSeconds,
			KeyDaysUntilExpiry,
			ConnectorCredentialExpiryTimestampSeconds,
			ConnectorCredentialDaysUntilExpiry,
			SLODecisionsTotal,
			HTTPRequestsTotal,
			ConnectorErrorsTotal,
			OverloadRejectionsTotal,
			OutboxBackpressureRejectionsTotal,
			TenantCapacityRejectionsTotal,
			ConnectorBreakerState,
			ConnectorBreakerTripsTotal,
			OutboxDeliveryBreakerState,
			OutboxDeliveryBreakerTripsTotal,
			OutboxDeliveryBreakerSkipsTotal,
			ConnectorDispatchReplaysTotal,
		)
	})
}
