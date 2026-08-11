// Package deployment models Groundwork's sovereign multi-region
// deployment topology (Phase 4): the jurisdiction of every component,
// the transfer policies that permit (rare, auditable) cross-region
// flows, and the fail-closed validation every production deployment
// must pass before it can be considered compliant.
//
// The core product rule enforced here:
//
//	tenant jurisdiction -> regional runtime -> regional databases and
//	vector stores -> regional audit records -> regional telemetry ->
//	regional encryption keys
//
// A tenant must never cross regions unless an explicit, configured,
// auditable transfer policy permits it.
package deployment

import (
	"fmt"
	"regexp"
	"strings"
)

// Region is a deployment region identifier. Known jurisdictions map to
// EU / UK / US; any other non-empty identifier is a customer-defined
// region with a customer-defined jurisdiction.
type Region string

// Well-known regions. A deployment profile selects exactly one.
const (
	RegionEU = Region("EU")
	RegionUK = Region("UK")
	RegionUS = Region("US")
)

// jurisdictionOf maps well-known regions to their jurisdictions. A
// customer-defined region identifier carries a customer-defined
// jurisdiction (see Region.Jurisdiction).
var jurisdictionOf = map[Region]string{
	RegionEU: "eu",
	RegionUK: "uk",
	RegionUS: "us",
}

// Compliance frameworks applicable per jurisdiction. Exports map to
// these profiles; see internal/exports.
var frameworksByJurisdiction = map[string][]string{
	"eu": {"eu_ai_act", "dora", "gdpr", "iso_42001", "nist_ai_rmf"},
	"uk": {"uk_customer_policy", "iso_42001", "nist_ai_rmf"},
	"us": {"us_customer_policy", "nist_ai_rmf", "iso_42001"},
}

var regionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Valid reports whether id is a syntactically valid region identifier.
func (r Region) Valid() bool {
	return regionPattern.MatchString(string(r))
}

// Jurisdiction returns the jurisdiction governing the region. Known
// regions map to eu/uk/us; a customer-defined region is its own
// jurisdiction (its identifier, lower-cased).
func (r Region) Jurisdiction() string {
	if j, ok := jurisdictionOf[r]; ok {
		return j
	}
	return strings.ToLower(string(r))
}

// ComplianceFrameworks lists the evidence-export profiles applicable to
// the region's jurisdiction.
func (r Region) ComplianceFrameworks() []string {
	return frameworksByJurisdiction[r.Jurisdiction()]
}

// String implements fmt.Stringer.
func (r Region) String() string { return string(r) }

// ParseRegion validates and returns a region identifier from trusted
// configuration. Request-body region fields are NEVER routed here —
// this is the only accepted input path, and it is configuration.
func ParseRegion(id string) (Region, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", fmt.Errorf("region configuration missing: a deployment region must be set")
	}
	r := Region(id)
	if !r.Valid() {
		return "", fmt.Errorf("invalid region %q: expected 1-64 chars of [A-Za-z0-9._-]", id)
	}
	return r, nil
}

// TransferPolicyKinds classify what may cross a regional boundary. Only
// these flows exist; everything else fails closed by default.
type TransferPolicyKinds = string

const (
	TransferKindTelemetry TransferPolicyKinds = "telemetry"
	TransferKindBackup    TransferPolicyKinds = "backup"
	TransferKindModel     TransferPolicyKinds = "model"
	TransferKindAudit     TransferPolicyKinds = "audit"
)

// KnownTransferKinds is the closed set of cross-region flow kinds.
var KnownTransferKinds = map[string]bool{
	TransferKindTelemetry: true,
	TransferKindBackup:    true,
	TransferKindModel:     true,
	TransferKindAudit:     true,
}

// TransferPolicy is an explicit, configured, auditable permission for
// one data class to move from one region to another. It is the ONLY
// mechanism that allows cross-region flow — anything not covered by a
// policy fails closed.
type TransferPolicy struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`       // one of KnownTransferKinds
	From      string `json:"from"`       // region identifier
	To        string `json:"to"`         // region identifier
	DataClass string `json:"data_class"` // e.g. "encrypted_backup", "anonymized_telemetry"
	Allowed   bool   `json:"allowed"`    // explicit consent flag; false == denied
	Notes     string `json:"notes,omitempty"`
}

// Allows reports whether a policy explicitly permits flow of the given
// kind between from and to.
func (p TransferPolicy) Allows(kind, from, to string) bool {
	return p.Allowed && p.Kind == kind && p.From == from && p.To == to
}

// DeploymentConfig is the trusted, validated topology of one regional
// deployment. Every field is region-resolved; validation rejects any
// component whose region differs from the deployment region without a
// matching transfer policy.
type DeploymentConfig struct {
	// DeploymentRegion is THIS deployment's region (the runtime region).
	DeploymentRegion string `json:"deployment_region"`
	// Jurisdiction is the tenant jurisdiction served here. It is
	// derived from DeploymentRegion when empty.
	Jurisdiction string `json:"jurisdiction,omitempty"`

	// Component regions. Empty means "co-located in DeploymentRegion";
	// a non-empty value must match DeploymentRegion or be covered by a
	// transfer policy of the right kind.
	PostgresRegion      string `json:"postgres_region,omitempty"`
	SpiceDBRegion       string `json:"spicedb_region,omitempty"`
	QdrantRegion        string `json:"qdrant_region,omitempty"`
	ElasticsearchRegion string `json:"elasticsearch_region,omitempty"`
	BackupRegion        string `json:"backup_region,omitempty"`
	TelemetryRegion     string `json:"telemetry_region,omitempty"`
	KMSRegion           string `json:"kms_region,omitempty"`
	ModelEndpointRegion string `json:"model_endpoint_region,omitempty"`

	// TransferPolicies is the complete, explicit cross-region policy
	// set. Absence means no cross-region flow is permitted.
	TransferPolicies []TransferPolicy `json:"transfer_policies,omitempty"`

	// Services lists every service and its exposure. Only the gateway
	// may be public; every backend must be private (internal network).
	Services []ServiceEndpoint `json:"services,omitempty"`

	// ModelEndpoints lists approved model/provider endpoints. An
	// endpoint outside the deployment region requires a policy of kind
	// "model"; an endpoint not listed here is unapproved.
	ModelEndpoints []ModelEndpoint `json:"model_endpoints,omitempty"`

	// EgressAllowlist is the customer-controlled outbound allow-list
	// (hostnames only; the network layer enforces default-deny egress).
	EgressAllowlist []string `json:"egress_allowlist,omitempty"`

	// AuditStorageConfigured records whether the immutable audit store
	// (PostgreSQL audit ledger) is provisioned in this deployment.
	AuditStorageConfigured bool `json:"audit_storage_configured"`
	// BackupRegion etc. above; BackupEnabled records whether regional
	// backups are configured.
	BackupEnabled bool `json:"backup_enabled"`

	// Gateway is the only public ingress.
	Gateway GatewayEndpoint `json:"gateway"`
}

// GatewayEndpoint is the sole public ingress.
type GatewayEndpoint struct {
	Enabled bool   `json:"enabled"`
	Ports   []int  `json:"ports"`  // e.g. [80, 443]
	Region  string `json:"region"` // gateway co-located; must equal DeploymentRegion
}

// ServiceEndpoint describes one service's exposure in the deployment.
type ServiceEndpoint struct {
	Name    string `json:"name"`
	Port    int    `json:"port"`
	Public  bool   `json:"public"` // ONLY the gateway may set true
	Region  string `json:"region"`
	Exposed bool   `json:"exposed"` // published on the host interface
}

// ModelEndpoint is one approved model/provider endpoint.
type ModelEndpoint struct {
	Name   string `json:"name"`
	URL    string `json:"url"` // for classification only; never a secret
	Region string `json:"region"`
}

// EffectiveRegion resolves a component region: empty means co-located
// in the deployment region.
func (c DeploymentConfig) EffectiveRegion(component string) string {
	switch component {
	case "postgres":
		return firstNonEmpty(c.PostgresRegion, c.DeploymentRegion)
	case "spicedb":
		return firstNonEmpty(c.SpiceDBRegion, c.DeploymentRegion)
	case "qdrant":
		return firstNonEmpty(c.QdrantRegion, c.DeploymentRegion)
	case "elasticsearch":
		return firstNonEmpty(c.ElasticsearchRegion, c.DeploymentRegion)
	case "backup":
		return firstNonEmpty(c.BackupRegion, c.DeploymentRegion)
	case "telemetry":
		return firstNonEmpty(c.TelemetryRegion, c.DeploymentRegion)
	case "kms":
		return firstNonEmpty(c.KMSRegion, c.DeploymentRegion)
	case "model":
		return firstNonEmpty(c.ModelEndpointRegion, c.DeploymentRegion)
	}
	return c.DeploymentRegion
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// RegionResolver answers jurisdiction questions from trusted
// deployment configuration. It never accepts request-body input.
type RegionResolver struct {
	cfg DeploymentConfig
}

// NewRegionResolver wraps a validated deployment config.
func NewRegionResolver(cfg DeploymentConfig) *RegionResolver {
	return &RegionResolver{cfg: cfg}
}

// DeploymentRegion returns the runtime region of this deployment.
func (r *RegionResolver) DeploymentRegion() string { return r.cfg.DeploymentRegion }

// Jurisdiction returns the jurisdiction of a region under this
// deployment's configuration.
func (r *RegionResolver) Jurisdiction(region string) string {
	return Region(region).Jurisdiction()
}

// Config exposes the validated configuration (read-only use).
func (r *RegionResolver) Config() DeploymentConfig { return r.cfg }

// Allowed reports whether a cross-region flow of the given kind is
// explicitly permitted by a configured transfer policy.
func (r *RegionResolver) Allowed(kind, from, to string) bool {
	for _, p := range r.cfg.TransferPolicies {
		if p.Allows(kind, from, to) {
			return true
		}
	}
	return false
}
