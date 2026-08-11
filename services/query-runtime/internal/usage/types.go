package usage

import (
	"time"
)

// Usage Metering & Tenant Limits (Phase 8.1).
//
// Every tenant-scoped unit of work that matters for capacity and
// billing is metered into per-month counters, and operators can attach
// quota limits per metric. Enforcement is fail-closed: when a limited
// metric would exceed its quota the operation is denied with a
// quota_exceeded:<metric> error and the counter is NOT incremented
// (atomic check-and-increment in the store). Absent a limit row,
// metrics are unlimited and recording is a no-op for enforcement.
//
// Metrics are recorded at the runtime HTTP layer (and the outbox
// delivery worker), never inside the SDKs or the console.

// Metric names. These are stable identifiers: they appear in counters,
// quota rows, API responses, and OpenAPI — renaming is breaking.
const (
	MetricAgents           = "agents"            // registered agents (create)
	MetricRuns             = "runs"              // governed runs + query executions
	MetricDecisions        = "decisions"         // governed action decisions
	MetricConnectorCalls   = "connector_calls"   // external connector invocations
	MetricExports          = "exports"           // governance framework exports
	MetricOutboxDeliveries = "outbox_deliveries" // outbox events delivered
	MetricStorageBytes     = "storage_bytes"     // export payload volume (bytes)
)

// Periods for quota limits. Counters are always stored per calendar
// month (UTC); a "lifetime" limit applies to the sum across all months.
const (
	PeriodMonthly  = "monthly"
	PeriodLifetime = "lifetime"
)

// AllMetrics enumerates the metered metrics in stable order.
func AllMetrics() []string {
	return []string{
		MetricAgents,
		MetricRuns,
		MetricDecisions,
		MetricConnectorCalls,
		MetricExports,
		MetricOutboxDeliveries,
		MetricStorageBytes,
	}
}

// MonthKey is the counter window key for the current UTC calendar month.
func MonthKey(now time.Time) string {
	return now.UTC().Format("2006-01")
}

// Limit is one quota policy row: how many units of Metric the tenant
// may consume in Period. A Limit <= 0 removes the limit (unlimited).
type Limit struct {
	Metric string `json:"metric"`
	Period string `json:"period"`
	Limit  int64  `json:"limit"`
}

// MetricUsage is one metered snapshot: current count against the
// applicable limit. Remaining is -1 when unlimited.
type MetricUsage struct {
	Metric    string `json:"metric"`
	Period    string `json:"period"`
	Count     int64  `json:"count"`
	Limit     int64  `json:"limit"`
	Remaining int64  `json:"remaining"`
}

// UsageSnapshot is the GET /v1/usage response shape.
type UsageSnapshot struct {
	TenantID string        `json:"tenant_id"`
	Period   string        `json:"period"`
	Usage    []MetricUsage `json:"usage"`
}

// LimitsSnapshot is the GET/PUT /v1/usage/limits response shape.
type LimitsSnapshot struct {
	TenantID string  `json:"tenant_id"`
	Limits   []Limit `json:"limits"`
}

// QuotaError is the fail-closed denial returned by Record when a
// limited metric would exceed its quota. Metric identifies the
// exhausted metric (stable identifier, safe for error codes).
type QuotaError struct {
	Metric string
}

func (e *QuotaError) Error() string {
	return "usage quota exceeded: " + e.Metric
}
