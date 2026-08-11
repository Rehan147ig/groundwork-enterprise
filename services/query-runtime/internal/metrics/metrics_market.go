package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Market-leader layer metrics: the L1 policy cache, the zero-trust
// context firewall, and the hybrid retrieval pipeline. Registered
// alongside the core collectors in RegisterAll.
var (
	// L1 policy cache / tiered authorization.
	PolicyCacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_policy_l1_hits_total", Help: "L1 policy cache hits"},
		[]string{"tenant_id"},
	)
	PolicyCacheMisses = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_policy_l1_misses_total", Help: "L1 policy cache misses"},
		[]string{"tenant_id"},
	)
	PolicyL1RuleDecisions = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_policy_l1_rule_decisions_total", Help: "Decisions made by in-process L1 rules"},
		[]string{"tenant_id", "effect"},
	)
	PolicyL2Fallbacks = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_policy_l2_fallbacks_total", Help: "Decisions resolved by the L2 backend"},
		[]string{"tenant_id", "outcome"},
	)
	PolicyCacheInvalidations = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_policy_l1_invalidations_total", Help: "L1 cache invalidations from privilege-revocation events"},
		[]string{"tenant_id"},
	)
	PolicyCacheSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "groundwork_policy_l1_cache_entries", Help: "Current L1 policy cache entry count"},
		[]string{"tenant_id"},
	)

	// Zero-trust context firewall.
	FirewallRedactionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_firewall_redactions_total", Help: "PII spans redacted by the context firewall"},
		[]string{"tenant_id", "kind"},
	)
	FirewallInjectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_firewall_injections_total", Help: "Indirect prompt injections detected"},
		[]string{"tenant_id", "severity"},
	)
	FirewallInjectionsBlocked = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_firewall_injections_blocked_total", Help: "Chunks excluded from context by the firewall (block mode)"},
		[]string{"tenant_id"},
	)
	FirewallChunksWatermarked = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_firewall_watermarked_chunks_total", Help: "Chunks signed with a provenance watermark"},
		[]string{"tenant_id"},
	)

	// Hybrid retrieval.
	HybridFusionTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_hybrid_fusions_total", Help: "Hybrid retrievals fused (dense + lexical)"},
		[]string{"tenant_id"},
	)
	HybridLexicalDocs = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "groundwork_hybrid_lexical_documents", Help: "Chunks in the in-process BM25 lexical index"},
		[]string{"tenant_id"},
	)

	// Envelope encryption.
	EnvelopeSealsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_envelope_seals_total", Help: "Payloads sealed with envelope encryption"},
		[]string{"kind"},
	)
	EnvelopeOpensTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_envelope_opens_total", Help: "Payloads opened with envelope encryption"},
		[]string{"kind"},
	)
	EnvelopeFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_envelope_failures_total", Help: "Envelope encryption failures (fail closed)"},
		[]string{"kind"},
	)

	// Real-time webhook ingestion.
	WebhookEventsApplied = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_aclsync_webhook_events_total", Help: "Webhook permission-change events applied"},
		[]string{"tenant_id", "provider", "type"},
	)
	WebhookSignatureFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_aclsync_webhook_signature_failures_total", Help: "Webhook requests rejected on signature verification"},
		[]string{"provider"},
	)
	WebhookLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "groundwork_aclsync_webhook_duration_seconds",
			Help:    "Webhook apply duration",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"tenant_id", "provider"},
	)
)

// RegisterMarketLeaderMetrics registers the layer metrics with the
// default registry. All layer metrics are registered via RegisterAll
// (single registration point, single sync.Once).
func RegisterMarketLeaderMetrics() {
	RegisterAll()
}

func RecordPolicyL1Hit(tenantID string)  { PolicyCacheHits.WithLabelValues(tenantID).Inc() }
func RecordPolicyL1Miss(tenantID string) { PolicyCacheMisses.WithLabelValues(tenantID).Inc() }
func RecordPolicyRuleDecision(tenantID, effect string) {
	PolicyL1RuleDecisions.WithLabelValues(tenantID, effect).Inc()
}
func RecordPolicyL2Fallback(tenantID, outcome string) {
	PolicyL2Fallbacks.WithLabelValues(tenantID, outcome).Inc()
}
func RecordPolicyCacheInvalidation(tenantID string) {
	PolicyCacheInvalidations.WithLabelValues(tenantID).Inc()
}
func SetPolicyCacheSize(tenantID string, entries int) {
	PolicyCacheSize.WithLabelValues(tenantID).Set(float64(entries))
}

func RecordFirewallRedaction(tenantID, kind string) {
	FirewallRedactionsTotal.WithLabelValues(tenantID, kind).Inc()
}
func RecordFirewallInjection(tenantID, severity string) {
	FirewallInjectionsTotal.WithLabelValues(tenantID, severity).Inc()
}
func RecordFirewallInjectionBlocked(tenantID string) {
	FirewallInjectionsBlocked.WithLabelValues(tenantID).Inc()
}
func RecordFirewallWatermark(tenantID string) {
	FirewallChunksWatermarked.WithLabelValues(tenantID).Inc()
}

func RecordHybridFusion(tenantID string) { HybridFusionTotal.WithLabelValues(tenantID).Inc() }
func SetHybridLexicalDocs(tenantID string, count int) {
	HybridLexicalDocs.WithLabelValues(tenantID).Set(float64(count))
}

func RecordEnvelopeSeal(kind string)    { EnvelopeSealsTotal.WithLabelValues(kind).Inc() }
func RecordEnvelopeOpen(kind string)    { EnvelopeOpensTotal.WithLabelValues(kind).Inc() }
func RecordEnvelopeFailure(kind string) { EnvelopeFailuresTotal.WithLabelValues(kind).Inc() }

func RecordWebhookEvent(tenantID, provider, eventType string) {
	WebhookEventsApplied.WithLabelValues(tenantID, provider, eventType).Inc()
}
func RecordWebhookSignatureFailure(provider string) {
	WebhookSignatureFailures.WithLabelValues(provider).Inc()
}
func RecordWebhookLatency(tenantID, provider string, duration time.Duration) {
	WebhookLatency.WithLabelValues(tenantID, provider).Observe(duration.Seconds())
}
