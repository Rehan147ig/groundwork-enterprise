-- Scheduled leak-report snapshots (background drift detection).
--
-- Every LEAK_REPORT_CRON cycle, the query-runtime scheduler runs the
-- exposure analysis and persists the full Report here as an immutable
-- snapshot. The drift surface (GET /v1/leak-report/diff) compares
-- consecutive snapshots to surface newly introduced and remediated
-- exposure. The store defensively bootstraps this table itself
-- (CREATE TABLE IF NOT EXISTS), so a lagging migration run degrades
-- neither the scheduler nor the history API.
--
-- Security invariants:
--   - rows are tenant-scoped; tenant_id comes only from the verified
--     API-key context on reads, never from the URL or body;
--   - findings_json holds the serialized Finding list of one run;
--   - snapshots are append-only (no UPDATE/DELETE of recorded runs).

CREATE TABLE leak_report_history (
    id             BIGSERIAL PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    ran_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    document_count INTEGER NOT NULL DEFAULT 0,
    group_count    INTEGER NOT NULL DEFAULT 0,
    findings_json  TEXT NOT NULL DEFAULT '[]',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_leak_report_history_tenant_time
    ON leak_report_history (tenant_id, ran_at DESC);