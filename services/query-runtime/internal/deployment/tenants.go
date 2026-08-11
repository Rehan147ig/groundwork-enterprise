package deployment

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"groundwork/query-runtime/internal/runtime"
)

// TenantRegionResolver maps tenants to their trusted region and
// jurisdiction. The source of truth is deployment configuration
// (GROUNDWORK_TENANT_REGIONS=tenant1:EU,tenant2:UK) — never request
// bodies. A tenant absent from the configuration fails closed
// (region_unprovisioned) when the resolver is wired.
type TenantRegionResolver struct {
	// tenants: tenantID -> trusted region identifier.
	tenants map[string]string
}

// Compile-time assertion: implements runtime.TenantRegionResolver.
var _ runtime.TenantRegionResolver = (*TenantRegionResolver)(nil)

// BuildTenantRegionResolver constructs the resolver from trusted
// configuration. Spec format (comma-separated):
//
//	GROUNDWORK_TENANT_REGIONS=acme:EU,contoso:UK,dataworks:eu-central-1
//
// Every tenant/region pair is validated at build time; an invalid pair
// is an error (fail at startup, not at first request).
func BuildTenantRegionResolver(spec string) (*TenantRegionResolver, error) {
	tenants := map[string]string{}
	for _, pair := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == '\n' || r == ';' }) {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid GROUNDWORK_TENANT_REGIONS entry %q: expected tenant:REGION", pair)
		}
		tenantID := strings.TrimSpace(parts[0])
		region, err := ParseRegion(parts[1])
		if err != nil {
			return nil, fmt.Errorf("GROUNDWORK_TENANT_REGIONS entry %q: %w", pair, err)
		}
		if tenantID == "" {
			return nil, fmt.Errorf("invalid GROUNDWORK_TENANT_REGIONS entry %q: empty tenant id", pair)
		}
		tenants[tenantID] = string(region)
	}
	if len(tenants) == 0 {
		return nil, nil
	}
	return &TenantRegionResolver{tenants: tenants}, nil
}

// Resolve implements runtime.TenantRegionResolver. ok=false for tenants
// absent from the trusted configuration (callers fail closed).
func (r *TenantRegionResolver) Resolve(tenantID string) (region, jurisdiction string, ok bool) {
	if r == nil {
		return "", "", false
	}
	region, ok = r.tenants[tenantID]
	if !ok {
		return "", "", false
	}
	return region, Region(region).Jurisdiction(), true
}

// Tenants returns the configured tenant ids (sorted; stable for tests).
func (r *TenantRegionResolver) Tenants() []string {
	ids := make([]string, 0, len(r.tenants))
	for id := range r.tenants {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// FromEnvironment builds the resolver from GROUNDWORK_TENANT_REGIONS.
func FromEnvironment() (*TenantRegionResolver, error) {
	spec := strings.TrimSpace(os.Getenv("GROUNDWORK_TENANT_REGIONS"))
	if spec == "" {
		return nil, nil
	}
	return BuildTenantRegionResolver(spec)
}
