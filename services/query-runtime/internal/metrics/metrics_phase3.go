package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Phase 3 metrics: emergency controls, budgets, evidence verification,
// and outbox delivery. Labels are bounded (no run/user/event ids) to
// keep cardinality safe.
var (
	ControlEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_control_events_total", Help: "Emergency control mutations applied"},
		[]string{"tenant_id", "entity", "action"},
	)
	BudgetExhaustionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_budget_exhaustions_total", Help: "Run budget denials"},
		[]string{"tenant_id", "reason"},
	)
	AuditVerifyTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_audit_verify_total", Help: "Audit chain verification runs"},
		[]string{"tenant_id", "outcome"},
	)
	EvidenceEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_evidence_events_total", Help: "Evidence events recorded"},
		[]string{"tenant_id", "kind"},
	)
	OutboxDeliveredTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_outbox_delivered_total", Help: "Outbox events delivered to webhook"},
		[]string{"event_type"},
	)
	OutboxDeadLetterTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "groundwork_outbox_dead_letter_total", Help: "Outbox events dead-lettered"},
		[]string{"event_type"},
	)
	OutboxPending = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{Name: "groundwork_outbox_pending", Help: "Outbox events awaiting delivery"},
		[]string{"tenant_id"},
	)
)

// RecordControlEvent is called once per applied emergency control
// mutation (kill-switch, resume, revoke, terminate).
func RecordControlEvent(tenantID, entity, action string) {
	ControlEventsTotal.WithLabelValues(tenantID, entity, action).Inc()
}

// RecordBudgetExhaustion is called once per budget denial decision.
func RecordBudgetExhaustion(tenantID, reason string) {
	BudgetExhaustionsTotal.WithLabelValues(tenantID, reason).Inc()
}

// RecordAuditVerify records one verification run outcome (verified |
// failed).
func RecordAuditVerify(tenantID, outcome string) {
	AuditVerifyTotal.WithLabelValues(tenantID, outcome).Inc()
}

// RecordEvidenceEvent is called once per recorded evidence event.
func RecordEvidenceEvent(tenantID, kind string) {
	EvidenceEventsTotal.WithLabelValues(tenantID, kind).Inc()
}

// RecordOutboxDelivered is called by the outbox worker per delivery.
func RecordOutboxDelivered(eventType string) {
	OutboxDeliveredTotal.WithLabelValues(eventType).Inc()
}

// RecordOutboxDeadLetter is called by the outbox worker per
// dead-lettered event.
func RecordOutboxDeadLetter(eventType string) {
	OutboxDeadLetterTotal.WithLabelValues(eventType).Inc()
}

// SetOutboxPending reports the pending count for a tenant (gauge,
// updated on a cadence).
func SetOutboxPending(tenantID string, count int) {
	OutboxPending.WithLabelValues(tenantID).Set(float64(count))
}

// registerPhase3Once is separate from registerOnce in metrics.go so the
// Phase 3 set registers even when RegisterAll ran first.
var registerPhase3Once sync.Once

// RegisterPhase3 registers the Phase 3 metrics (idempotent with the
// existing registry).
func RegisterPhase3() {
	registerPhase3Once.Do(func() {
		prometheus.MustRegister(
			ControlEventsTotal,
			BudgetExhaustionsTotal,
			AuditVerifyTotal,
			EvidenceEventsTotal,
			OutboxDeliveredTotal,
			OutboxDeadLetterTotal,
			OutboxPending,
		)
	})
}
