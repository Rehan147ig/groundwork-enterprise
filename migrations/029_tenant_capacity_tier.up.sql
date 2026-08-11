-- Per-tenant capacity model (Phase 8.2 Availability and performance).
--
-- Adds the deployment tier to the tenant directory: the runtime enforces
-- a per-tenant concurrency cap derived from the tier (capacity model in
-- cmd/query-runtime), so an enterprise tenant can be granted more
-- in-flight capacity than a standard tenant while no tenant can exhaust
-- the shared instance. The tier is operator-set at provisioning time and
-- immutable for the directory entry (re-provisioning a deprovisioned
-- tenant may change it).
--
-- Invariants:
--   - capacity_tier is one of standard / plus / enterprise;
--   - existing tenants default to 'standard' (the most restrictive tier),
--     so a schema upgrade never silently expands capacity;
--   - tier changes are additive (ALTER) and reversible (DROP).

ALTER TABLE tenants ADD COLUMN capacity_tier TEXT NOT NULL DEFAULT 'standard'
    CHECK (capacity_tier IN ('standard','plus','enterprise'));
