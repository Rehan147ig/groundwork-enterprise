// Package contract defines the versioned connector SDK contract that
// every Groundwork permission connector must implement (Milestone 4).
//
// A connector is a self-describing adapter: it declares a ProviderDescriptor
// (authentication method and secret references, capabilities, supported
// subset, retry/timeout policy), implements the aclsync.Connector read
// surface, and — when it supports deltas — surfaces versioned ChangeEvent
// envelopes with replay-protection IDs. Security behavior (secret
// resolution, error classification, fail-closed rules) lives here and in
// the aclsync service layer, NOT duplicated inside provider packages.
//
// Versioning: the contract is explicit and versioned. Every descriptor
// carries ContractVersion; Validate refuses descriptors whose version is
// not in SupportedVersions. Breaking changes introduce a new version
// rather than silently altering v1 semantics.
package contract

import (
	"strings"
	"time"
)

// Version is the current contract version.
const Version = "v1"

// SupportedVersions lists every contract version Validate accepts.
// New connectors must target the latest version.
func SupportedVersions() []string { return []string{Version} }

// AuthMethod enumerates how a connector authenticates to its provider.
type AuthMethod string

const (
	// AuthOAuth2ClientCredentials: service principal client secret,
	// referenced via a secret reference (never plaintext env in
	// production).
	AuthOAuth2ClientCredentials AuthMethod = "oauth2_client_credentials"
	// AuthAPIKey: static API key resolved via a secret reference.
	AuthAPIKey AuthMethod = "api_key"
	// AuthNone: provider is unauthenticated or the connector is a
	// synthetic/test source. Secret reference requirements do not apply.
	AuthNone AuthMethod = "none"
)

// SecretRefScheme is an allowed credential reference scheme. A connector
// lists every scheme its deployment may use; production deployments must
// choose one of these (the aclsync registry enforces keyring-or-approved-
// secret-manager refs).
type SecretRefScheme string

const (
	// SchemeKeyring references a key sealed under the connector purpose
	// key (keyring.PurposeConnector), e.g. "keyring://connector/msgraph".
	SchemeKeyring SecretRefScheme = "keyring://"
	// SchemeSecretsManager references an external secrets manager
	// ("secretsmanager://", "aws:secretsmanager:", "gcp:secretmanager:",
	// "vault://").
	SchemeSecretsManager SecretRefScheme = "secrets_manager"
	// SchemeEnv is the dev/local-only fallback. Connectors must NOT list
	// it in production auth specs; the doctor check fails when a
	// production deployment resolves a secret to plaintext env.
	SchemeEnv SecretRefScheme = "env"
)

// AuthSpec declares how the connector authenticates and how its
// credentials are referenced. Credential material never appears here —
// only schemes.
type AuthSpec struct {
	Method AuthMethod
	// SecretRefSchemes lists the schemes this connector supports for its
	// credential reference. Empty for AuthNone.
	SecretRefSchemes []SecretRefScheme
	// Scopes is the least-privilege scope set the connector requests.
	Scopes []string
	// CredentialExpiry indicates whether the provider credential has a
	// known expiry that must be surfaced via the installation registry's
	// credential_expires_at (drives the credential-expiry metric).
	CredentialExpiry bool
}

// HasScheme reports whether scheme is an allowed credential scheme.
func (a AuthSpec) HasScheme(scheme SecretRefScheme) bool {
	for _, s := range a.SecretRefSchemes {
		if s == scheme {
			return true
		}
	}
	return false
}

// RequiresSecret reports whether the auth method needs a secret reference.
func (a AuthSpec) RequiresSecret() bool {
	return a.Method == AuthOAuth2ClientCredentials || a.Method == AuthAPIKey
}

// ConnectorStatus is the connector's production-readiness
// classification. It is a claim enforced by the CI production-claims
// check (scripts/check-connector-production-claims.sh): a connector may
// declare production only when it is on the verified allowlist, so an
// unreviewed connector can never quietly claim production readiness.
type ConnectorStatus string

const (
	// ConnectorStatusProduction: verified in production deployments.
	// Declared literally ("production") so the CI gate can audit it.
	ConnectorStatusProduction ConnectorStatus = "production"
	// ConnectorStatusExperimental: safe in dev/staging only; not on the
	// production allowlist.
	ConnectorStatusExperimental ConnectorStatus = "experimental"
)

// Capability is a declared connector capability. Capabilities are
// claims: the contract test suite verifies the ones a connector
// declares, and the Service refuses to rely on a capability the
// connector did not declare.
type Capability string

const (
	// CapabilityDelta: the connector detects incremental source changes
	// and surfaces them as ChangeEvent envelopes (WatchEvents). Without
	// it, correctness rests on periodic full reconcile alone.
	CapabilityDelta Capability = "delta"
	// CapabilityTombstones: deleted source content is surfaced as a
	// tombstone event (ChangeEvent.Tombstone), letting the service
	// revoke every grantee of the deleted resource.
	CapabilityTombstones Capability = "tombstones"
	// CapabilityGroups: the source exposes groups with (possibly nested)
	// memberships.
	CapabilityGroups Capability = "groups"
	// CapabilityFolders: the source exposes folders with inherited
	// viewer grants.
	CapabilityFolders Capability = "folders"
	// CapabilityInheritance: source permissions inherit along a
	// parent/child chain (folder → document) and the connector models it.
	CapabilityInheritance Capability = "inheritance"
	// CapabilityEffectivePermissions: the connector can prove each end
	// user's effective permission from source data. Connectors that
	// cannot (e.g. integration-scoped providers) must NOT claim it — the
	// service must never claim per-user authorization on their behalf.
	CapabilityEffectivePermissions Capability = "effective_permissions"
	// CapabilityRegionMetadata: snapshots/events carry region/residency
	// metadata the service can use for jurisdiction decisions.
	CapabilityRegionMetadata Capability = "region_metadata"
)

// RegionMetadata carries the region/residency of the source tenant or of
// an individual resource. Jurisdiction is a Groundwork deployment value
// (eu/uk/us/customer-defined) mapped from trusted configuration, never
// from the provider.
type RegionMetadata struct {
	// Region is the provider-reported region (e.g. "eu-west-2").
	Region string
	// DataResidency describes where source data resides if the provider
	// exposes it (e.g. "eu").
	DataResidency string
}

// RetryPolicy is the connector's declared retry/backoff policy. The
// service applies it around connector I/O; a connector may tighten it
// per-call but must not exceed these bounds.
type RetryPolicy struct {
	Base           time.Duration // backoff base (>= 250ms recommended)
	Max            time.Duration // backoff cap
	MaxAttempts    int           // 0 = unbounded (bounded by context)
	DefaultTimeout time.Duration // per-call timeout applied to provider requests
}

// Validate checks the policy is sane (nonzero, ordered).
func (r RetryPolicy) Validate() error {
	var problems []string
	if r.Base <= 0 {
		problems = append(problems, "retry base must be > 0")
	}
	if r.Max < r.Base {
		problems = append(problems, "retry max must be >= base")
	}
	if r.DefaultTimeout <= 0 {
		problems = append(problems, "default timeout must be > 0")
	}
	if len(problems) > 0 {
		return &DescriptorError{Problems: problems}
	}
	return nil
}

// ProviderDescriptor is the versioned self-description every connector
// must return from Descriptor(). It is the contract between a provider
// package and the aclsync service: the service uses it to decide which
// guarantees it may rely on (capabilities), how to resolve credentials
// (AuthSpec), and how aggressively to retry (RetryPolicy).
type ProviderDescriptor struct {
	// Provider is the stable provider name (e.g. "msgraph", "s3",
	// "notion"). Must match the installation registry's provider column.
	Provider string
	// Status is the production-readiness classification
	// (ConnectorStatusProduction|ConnectorStatusExperimental). The CI
	// production-claims check audits this literal: production status
	// requires a verified production review.
	Status ConnectorStatus
	// ContractVersion must be in SupportedVersions.
	ContractVersion string
	// Auth describes the authentication method and secret-reference
	// requirements.
	Auth AuthSpec
	// Capabilities lists every Capability this connector provides. It
	// must be complete: the service treats undeclared capabilities as
	// absent.
	Capabilities []Capability
	// SupportedSubset documents the strict subset of provider features
	// the connector models (e.g. "object ACLs only; bucket policies,
	// IAM roles, access points, and inherited grants are NOT modeled").
	// Required: a connector must fail closed outside its documented
	// subset.
	SupportedSubset string
	// FailClosedOutsideSubset must be true: connectors that cannot prove
	// effective permissions outside their subset must say so, and the
	// service treats any unmodeled source feature as a deny.
	FailClosedOutsideSubset bool
	// Retry is the connector's declared retry/timeout policy.
	Retry RetryPolicy
}

// HasCapability reports whether the descriptor declares cap.
func (d ProviderDescriptor) HasCapability(cap Capability) bool {
	for _, c := range d.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// Validate checks the descriptor is well-formed for the current contract
// version. It does not I/O; connector-level checks (auth actually works,
// capabilities actually hold) are the contract test suite's job.
func (d ProviderDescriptor) Validate() error {
	var problems []string
	if strings.TrimSpace(d.Provider) == "" {
		problems = append(problems, "provider name required")
	}
	if d.Status != ConnectorStatusProduction && d.Status != ConnectorStatusExperimental {
		problems = append(problems, "status must be declared (production or experimental)")
	}
	if d.ContractVersion != Version {
		problems = append(problems, "unsupported contract version "+quote(d.ContractVersion))
	}
	if d.Auth.RequiresSecret() && len(d.Auth.SecretRefSchemes) == 0 {
		problems = append(problems, "auth requires at least one secret-reference scheme")
	}
	if d.Auth.Method == AuthNone && len(d.Auth.SecretRefSchemes) > 0 {
		problems = append(problems, "AuthNone must not declare secret-reference schemes")
	}
	if strings.TrimSpace(d.SupportedSubset) == "" {
		problems = append(problems, "supported subset must be documented")
	}
	if !d.FailClosedOutsideSubset {
		problems = append(problems, "FailClosedOutsideSubset must be true (unmodeled provider features must deny)")
	}
	if err := d.Retry.Validate(); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		return &DescriptorError{Problems: problems}
	}
	return nil
}

// DescriptorError reports descriptor validation problems.
type DescriptorError struct {
	Problems []string
}

func (e *DescriptorError) Error() string {
	return "connector contract descriptor invalid: " + strings.Join(e.Problems, "; ")
}

func quote(s string) string {
	if s == "" {
		return `""`
	}
	return `"` + s + `"`
}
