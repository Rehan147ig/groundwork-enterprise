package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	QueryTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_queries_total", Help: "Total queries processed"},
		[]string{"tenant_id", "outcome"},
	)
	ACLCheckDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "groundwork_acl_check_duration_seconds",
			Help:    "Duration of ACL checks",
			Buckets: []float64{.005, .01, .025, .05, .1},
		},
		[]string{"tenant_id", "result"},
	)
	ChunksBlockedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_chunks_blocked_total", Help: "Total chunks blocked"},
		[]string{"tenant_id", "reason"},
	)
	CircuitBreakerState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "groundwork_circuit_breaker_state", Help: "Circuit breaker state"},
		[]string{"service"},
	)
	RelationshipBackendUnreachable = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_relationship_backend_unreachable_total", Help: "Relationship authorization backend unreachable count (fail-closed denials)"},
		[]string{"tenant_id"},
	)
	TenantQueryLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "groundwork_query_latency_seconds",
			Help:    "End-to-end query latency",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"tenant_id"},
	)

	ACLSyncRunsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_acl_sync_runs_total", Help: "Total ACL sync runs"},
		[]string{"tenant_id"},
	)
	ACLSyncErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_acl_sync_errors_total", Help: "Total ACL sync errors"},
		[]string{"tenant_id"},
	)
	ACLSyncDriftItems = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "groundwork_acl_sync_drift_items", Help: "Drift item count from the last drift check"},
		[]string{"tenant_id"},
	)
	ACLSyncDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "groundwork_acl_sync_duration_seconds",
			Help:    "ACL sync run duration",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"tenant_id"},
	)

	// Shadow-authorizer observability (SpiceDB migration, Phase C):
	// a check was answered by the shadow backend because the primary
	// failed (fallback) or the shadow itself failed (error). Both are
	// zero in normal operation.
	RelationshipShadowFallbacks = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_relationship_shadow_fallbacks_total", Help: "Checks answered by the shadow authorizer after a primary failure"},
		[]string{"tenant_id"},
	)
	RelationshipShadowErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_relationship_shadow_errors_total", Help: "Shadow authorizer failures (shadow backend unreachable or errored)"},
		[]string{"tenant_id"},
	)
	// Decision-parity mismatches between primary and shadow backend
	// (allow/deny disagreement, or exactly one side errored). Observe-only:
	// the primary decision is authoritative. The cutover threshold is
	// zero unresolved mismatches.
	RelationshipShadowMismatches = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_relationship_shadow_mismatches_total", Help: "Shadow vs primary decision mismatches"},
		[]string{"tenant_id", "category"},
	)

	// SpiceDB circuit breaker trips: how often the adapter opened the
	// breaker and started short-circuiting instead of hammering a sick
	// backend.
	SpiceDBCircuitTrips = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "groundwork_spicedb_circuit_trips_total", Help: "SpiceDB adapter circuit breaker open transitions"},
	)

	// Dual-sink conflicts: a secondary sink rejected a write/delete that
	// the primary (SpiceDB) accepted. The primary is authoritative, so
	// this is a sync-health signal, not an authorization failure.
	ACLSyncConflictsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_acl_sync_conflicts_total", Help: "Secondary ACL sink write/delete failures during dual-write"},
		[]string{"tenant_id", "sink"},
	)

	registerOnce sync.Once
)

func RegisterAll() {
	registerOnce.Do(func() {
		prometheus.MustRegister(
			QueryTotal,
			ACLCheckDuration,
			ChunksBlockedTotal,
			CircuitBreakerState,
			RelationshipBackendUnreachable,
			TenantQueryLatency,
			ACLSyncRunsTotal,
			ACLSyncErrorsTotal,
			ACLSyncDriftItems,
			ACLSyncDuration,
			RelationshipShadowFallbacks,
			RelationshipShadowErrors,
			RelationshipShadowMismatches,
			SpiceDBCircuitTrips,
			ACLSyncConflictsTotal,
			PolicyCacheHits,
			PolicyCacheMisses,
			PolicyL1RuleDecisions,
			PolicyL2Fallbacks,
			PolicyCacheInvalidations,
			PolicyCacheSize,
			FirewallRedactionsTotal,
			FirewallInjectionsTotal,
			FirewallInjectionsBlocked,
			FirewallChunksWatermarked,
			HybridFusionTotal,
			HybridLexicalDocs,
			EnvelopeSealsTotal,
			EnvelopeOpensTotal,
			EnvelopeFailuresTotal,
			WebhookEventsApplied,
			WebhookSignatureFailures,
			WebhookLatency,
		)
	})
}

func RecordQuery(tenantID, outcome string) {
	QueryTotal.WithLabelValues(tenantID, outcome).Inc()
}

func RecordACLCheck(tenantID, result string, duration time.Duration) {
	ACLCheckDuration.WithLabelValues(tenantID, result).Observe(duration.Seconds())
}

func RecordBlockedChunks(tenantID, reason string, count int) {
	if count <= 0 {
		return
	}
	ChunksBlockedTotal.WithLabelValues(tenantID, reason).Add(float64(count))
}

func SetCircuitBreakerState(service string, state float64) {
	CircuitBreakerState.WithLabelValues(service).Set(state)
}

func RecordRelationshipBackendUnreachable(tenantID string) {
	RelationshipBackendUnreachable.WithLabelValues(tenantID).Inc()
}

func RecordQueryLatency(tenantID string, duration time.Duration) {
	TenantQueryLatency.WithLabelValues(tenantID).Observe(duration.Seconds())
}

func RecordACLSyncRun(tenantID string) {
	ACLSyncRunsTotal.WithLabelValues(tenantID).Inc()
}

func RecordACLSyncError(tenantID string) {
	ACLSyncErrorsTotal.WithLabelValues(tenantID).Inc()
}

func SetACLSyncDriftItems(tenantID string, count int) {
	ACLSyncDriftItems.WithLabelValues(tenantID).Set(float64(count))
}

func RecordACLSyncDuration(tenantID string, duration time.Duration) {
	ACLSyncDuration.WithLabelValues(tenantID).Observe(duration.Seconds())
}

// RecordShadowFallback counts a check answered by the shadow authorizer
// because the primary backend failed (fail-open only for the shadow
// path; the primary contract stays fail-closed).
func RecordShadowFallback(tenantID string) {
	RelationshipShadowFallbacks.WithLabelValues(tenantID).Inc()
}

// RecordShadowError counts a shadow authorizer failure. The primary
// result is unaffected — shadow failures never change a decision.
func RecordShadowError(tenantID string) {
	RelationshipShadowErrors.WithLabelValues(tenantID).Inc()
}

// RecordShadowMismatch counts a primary/shadow decision-parity
// mismatch. category is relationship.ShadowMismatchAllowDeny or
// relationship.ShadowMismatchError. Observe-only — the primary decision
// is authoritative; the cutover threshold is zero mismatches.
func RecordShadowMismatch(tenantID, category string) {
	RelationshipShadowMismatches.WithLabelValues(tenantID, category).Inc()
}

// RecordSpiceDBCircuitTrip counts one open transition of the SpiceDB
// adapter circuit breaker.
func RecordSpiceDBCircuitTrip() {
	SpiceDBCircuitTrips.Inc()
}

// RecordACLSyncConflict counts a secondary-sink write/delete failure
// during dual-write. sink identifies the secondary.
func RecordACLSyncConflict(tenantID, sink string) {
	ACLSyncConflictsTotal.WithLabelValues(tenantID, sink).Inc()
}
