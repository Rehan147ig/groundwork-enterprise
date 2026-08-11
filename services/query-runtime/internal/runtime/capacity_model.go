package runtime

// CapacityModel is the Phase 8.2 per-tenant capacity model: the map
// from deployment tier (standard|plus|enterprise, see tenancy.go) to
// per-tenant in-flight concurrency caps. It is the operator's sizing
// decision — a tenant's requests beyond its tier cap are rejected
// fail-closed (503 concurrency_limit_exceeded) so one noisy tenant can
// never hog the instance, while higher tiers get more headroom.
//
// Enforced in-process per replica (like the rate limiters); a
// multi-replica deployment sizes the model per replica. A zero/absent
// limit means "unlimited" for that tier.
type CapacityModel struct {
	// Concurrency maps tier -> max in-flight requests per tenant.
	Concurrency map[string]int
	// DefaultLimit applies to tiers absent from the map (and to
	// tenants outside the directory). 0 = unlimited.
	DefaultLimit int
}

// ConcurrencyFor returns the in-flight cap for a tenant of the given
// tier. Unknown/empty tiers fall back to the model default.
func (m *CapacityModel) ConcurrencyFor(tier string) int {
	if m == nil {
		return 0
	}
	if limit, ok := m.Concurrency[tier]; ok {
		return limit
	}
	return m.DefaultLimit
}
