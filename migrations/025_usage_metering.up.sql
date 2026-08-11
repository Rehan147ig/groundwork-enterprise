-- Usage metering & tenant limits (Phase 8.1).
--
-- Three tables:
--   usage_counters — per (tenant, metric, calendar month) counters.
--     The PRIMARY KEY is the composite counter key; Record upserts it
--     atomically inside one transaction so concurrent requests can
--     never overrun a limit.
--   usage_limits   — per-tenant quota rows (metric x period). A
--     limit_value <= 0 (deleted row) means "unlimited"; "monthly"
--     applies to the current-month counter, "lifetime" to the sum
--     across all months.
--
-- Metrics are stable identifiers from internal/usage (agents, runs,
-- decisions, connector_calls, exports, outbox_deliveries,
-- storage_bytes). Periods are 'monthly' | 'lifetime'.

CREATE TABLE IF NOT EXISTS usage_counters (
    tenant_id   TEXT        NOT NULL,
    metric      TEXT        NOT NULL,
    period      TEXT        NOT NULL,
    count       BIGINT      NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, metric, period)
);

CREATE TABLE IF NOT EXISTS usage_limits (
    tenant_id   TEXT        NOT NULL,
    metric      TEXT        NOT NULL,
    period      TEXT        NOT NULL,
    limit_value BIGINT      NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, metric, period)
);
