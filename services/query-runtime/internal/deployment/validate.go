package deployment

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// Problem is one validation failure. Production deployments must have
// zero problems; any problem fails startup or deploy-validate.
type Problem struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (p Problem) Error() string { return fmt.Sprintf("%s: %s", p.Code, p.Detail) }

// Problems is a collectable set of validation failures.
type Problems []Problem

func (ps Problems) Error() string {
	if len(ps) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		parts = append(parts, p.Error())
	}
	return strings.Join(parts, "; ")
}

// RequiredKeyEnv is the set of environment variables that must carry a
// value in a production deployment (signing keys and secrets). The
// runtime refuses to start (or deploy-validate fails) when any is
// missing. Raw values are never logged or exported — only presence.
var RequiredKeyEnv = []string{
	"GROUNDWORK_JWT_HS_SECRET",
	"GROUNDWORK_DELEGATION_HS_SECRET",
	"GROUNDWORK_DELEGATION_RS_PRIVATE_KEY",
	"GROUNDWORK_DELEGATION_RS_PRIVATE_KEY_FILE",
	"GROUNDWORK_OUTBOX_WEBHOOK_SECRET",
}

// ProductionKeyEnv maps key purposes to the environment variables that
// carry their material (see internal/keyring for the provider model).
// The "identity" purpose is satisfied by either an OIDC issuer (Phase 4
// enterprise identity) or the JWT HMAC secret.
var ProductionKeyEnv = map[string][]string{
	"identity":     {"GROUNDWORK_OIDC_ISSUER", "GROUNDWORK_JWT_HS_SECRET"},
	"delegation":   {"GROUNDWORK_DELEGATION_HS_SECRET", "GROUNDWORK_DELEGATION_RS_PRIVATE_KEY", "GROUNDWORK_DELEGATION_RS_PRIVATE_KEY_FILE"},
	"webhook":      {"GROUNDWORK_OUTBOX_WEBHOOK_SECRET"},
	"audit_digest": {"GROUNDWORK_AUDIT_DIGEST_KEY"},
	"database":     {"GROUNDWORK_DATABASE_KEY_ID"},
	"backup":       {"GROUNDWORK_BACKUP_KEY_ID"},
}

// ValidateOptions carries the environment lookup used by Validate.
// Production deployments must fail when a required key is missing.
type ValidateOptions struct {
	// LookupEnv returns the value of an environment variable. Defaults
	// to os.Getenv when nil. Presence is checked for key envs; values
	// are never exposed.
	LookupEnv func(string) string
	// Environ enumerates the process environment (default os.Environ).
	// Used by prefix-scanned connector registry checks.
	Environ func() []string
	// Production forces the strict checks (keys, audit storage,
	// demo identity). Local/dev mode validates topology only.
	Production bool
	// StrictKeys requires every purpose key to be provisioned when
	// Production is true.
	StrictKeys bool
	// ModelEndpointRegion of an unapproved endpoint triggers
	// "unapproved_external_endpoint" problems.
	ApprovedEgressOnly bool
}

func (o ValidateOptions) lookup(key string) string {
	if o.LookupEnv == nil {
		return strings.TrimSpace(os.Getenv(key))
	}
	return strings.TrimSpace(o.LookupEnv(key))
}

func (o ValidateOptions) envSet(key string) bool { return o.lookup(key) != "" }

func (o ValidateOptions) environ() []string {
	if o.Environ == nil {
		return os.Environ()
	}
	return o.Environ()
}

// Validate checks a DeploymentConfig against the sovereign deployment
// rules. It returns every problem found (never a partial picture):
//
//   - region configuration missing / invalid
//   - a component's region differs from the deployment region without a
//     matching transfer policy (region mismatch fails closed)
//   - a backend port is public (only the gateway may be public)
//   - an unapproved external endpoint exists (public service that is
//     not the gateway, or a model endpoint outside the deployment
//     region without a model transfer policy)
//   - production signing keys missing
//   - audit storage not configured
//   - telemetry leaves the configured jurisdiction without an explicit
//     policy
//   - demo identity enabled in production
func Validate(cfg DeploymentConfig, opts ValidateOptions) Problems {
	var problems Problems

	// 1. Region configuration missing or invalid.
	region, err := ParseRegion(cfg.DeploymentRegion)
	if err != nil {
		problems = append(problems, Problem{Code: "region_missing", Detail: err.Error()})
		region = ""
	}
	if region != "" {
		if j := region.Jurisdiction(); j != "" && cfg.Jurisdiction != "" &&
			!strings.EqualFold(j, cfg.Jurisdiction) {
			problems = append(problems, Problem{
				Code:   "jurisdiction_mismatch",
				Detail: fmt.Sprintf("jurisdiction %q does not match region %q (%s)", cfg.Jurisdiction, region, j),
			})
		}
	}

	// 2. Component regions: every component must be co-located unless a
	// transfer policy of the right kind explicitly permits the flow.
	components := []struct {
		kind   string
		name   string
		region string
	}{
		{"", "postgres", cfg.EffectiveRegion("postgres")},
		{"", "spicedb", cfg.EffectiveRegion("spicedb")},
		{"", "qdrant", cfg.EffectiveRegion("qdrant")},
		{"", "elasticsearch", cfg.EffectiveRegion("elasticsearch")},
		{"telemetry", "telemetry", cfg.EffectiveRegion("telemetry")},
		{"", "kms", cfg.EffectiveRegion("kms")},
		{"backup", "backup", cfg.EffectiveRegion("backup")},
		{"model", "model_endpoints", cfg.EffectiveRegion("model")},
	}
	for _, c := range components {
		if region == "" {
			continue
		}
		if c.region != "" && c.region != string(region) {
			// Cross-region flow needs an explicit transfer policy.
			allowed := c.kind != "" && transferAllowed(cfg.TransferPolicies, c.kind, string(region), c.region)
			if !allowed {
				problems = append(problems, Problem{
					Code:   "region_mismatch",
					Detail: fmt.Sprintf("%s is in region %q but this deployment is %q — cross-region flow requires an explicit transfer policy (fails closed)", c.name, c.region, region),
				})
			}
		}
	}

	// 3. Backend ports must not be public.
	for _, svc := range cfg.Services {
		if svc.Public && !isGateway(svc.Name) {
			problems = append(problems, Problem{
				Code:   "backend_port_public",
				Detail: fmt.Sprintf("%s (port %d) is marked public — only the gateway may be exposed; backends must be private", svc.Name, svc.Port),
			})
		}
		if svc.Exposed && !isGateway(svc.Name) {
			problems = append(problems, Problem{
				Code:   "backend_port_public",
				Detail: fmt.Sprintf("%s (port %d) is published on the host interface — backends must be reachable only on the internal network", svc.Name, svc.Port),
			})
		}
	}

	// 4. Unapproved external endpoints.
	for _, svc := range cfg.Services {
		if svc.Public && isGateway(svc.Name) {
			continue
		}
		if svc.Public && region != "" && svc.Region != "" && svc.Region != string(region) {
			problems = append(problems, Problem{
				Code:   "unapproved_external_endpoint",
				Detail: fmt.Sprintf("%s is public and outside the deployment region %q", svc.Name, region),
			})
		}
	}
	for _, ep := range cfg.ModelEndpoints {
		if ep.Region == "" {
			continue
		}
		if region != "" && ep.Region != string(region) && !transferAllowed(cfg.TransferPolicies, "model", string(region), ep.Region) {
			problems = append(problems, Problem{
				Code:   "unapproved_external_endpoint",
				Detail: fmt.Sprintf("model endpoint %q is in region %q with no model transfer policy from %q", ep.Name, ep.Region, region),
			})
		}
	}

	// 5. Telemetry must stay in jurisdiction unless a policy permits it.
	// Unconditional — the same fail-closed rule as component regions.
	if region != "" {
		tel := cfg.EffectiveRegion("telemetry")
		if tel == "" {
			tel = string(region)
		}
		if Region(tel).Jurisdiction() != region.Jurisdiction() &&
			!transferAllowed(cfg.TransferPolicies, "telemetry", string(region), tel) {
			problems = append(problems, Problem{
				Code:   "telemetry_jurisdiction",
				Detail: fmt.Sprintf("telemetry in %q leaves jurisdiction %q without an explicit telemetry transfer policy", tel, region.Jurisdiction()),
			})
		}
	}

	if !opts.Production {
		return problems
	}

	// 6. Production signing keys present.
	if opts.StrictKeys {
		for _, purpose := range sortedKeys(ProductionKeyEnv) {
			found := false
			for _, envKey := range ProductionKeyEnv[purpose] {
				if opts.envSet(envKey) {
					found = true
					break
				}
			}
			if !found {
				problems = append(problems, Problem{
					Code:   "production_key_missing",
					Detail: fmt.Sprintf("no key material configured for purpose %q (expected one of %s)", purpose, strings.Join(ProductionKeyEnv[purpose], ", ")),
				})
			}
		}
	}

	// 7. Audit storage configured.
	if !cfg.AuditStorageConfigured {
		problems = append(problems, Problem{
			Code:   "audit_storage_not_configured",
			Detail: "audit storage (PostgreSQL immutable audit ledger) is not configured in this deployment profile",
		})
	}

	// 8. Demo identity disabled in production.
	if strings.EqualFold(opts.lookup("ALLOW_DEMO_IDENTITY"), "true") {
		problems = append(problems, Problem{
			Code:   "demo_identity_in_production",
			Detail: "ALLOW_DEMO_IDENTITY=true is forbidden in production — a raw user_id is never trusted",
		})
	}

	// 9. Production Connector Gateway bypass protections (Phase 5).
	// Connectors are registered at runtime through the governance API,
	// but a deployment profile may pre-register them via environment
	// (GROUNDWORK_CONNECTOR_<NAME>_BASE_URL). These checks make sure
	// the deployment cannot accidentally bypass the gateway:
	//   - every connector base URL host must be on the registered
	//     egress allowlist (connector-specific list, else the global
	//     GROUNDWORK_EGRESS_ALLOWLIST) — outbound domains must be
	//     registered before the runtime starts;
	//   - a connector pointing at a public host over plaintext http is
	//     rejected (TLS is mandatory for public egress);
	//   - TLS verification must never be disabled in production
	//     (GROUNDWORK_CONNECTOR_<NAME>_TLS_VERIFY=false or the global
	//     GROUNDWORK_CONNECTOR_TLS_VERIFY=false);
	//   - raw credentials are never valid connector config: secrets are
	//     env references (env://<NAME> or keyring://<purpose>); a
	//     connector-level secret variable whose name implies inline
	//     material is a misconfiguration and fails closed.
	connectorEgress := splitEnvList(opts.lookup("GROUNDWORK_CONNECTOR_EGRESS_ALLOWLIST"))
	globalEgress := cfg.EgressAllowlist
	egress := connectorEgress
	if len(egress) == 0 {
		egress = globalEgress
	}
	registered := map[string]bool{}
	for _, h := range egress {
		registered[strings.ToLower(strings.TrimSpace(h))] = true
	}
	connectorsFound := false
	for _, kv := range opts.environ() {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		key, value := kv[:eq], strings.TrimSpace(kv[eq+1:])
		if !strings.HasPrefix(key, "GROUNDWORK_CONNECTOR_") || !strings.HasSuffix(key, "_BASE_URL") {
			continue
		}
		connectorsFound = true
		if value == "" {
			continue
		}
		host := connectorHost(value)
		if host == "" {
			problems = append(problems, Problem{
				Code:   "connector_endpoint_invalid",
				Detail: fmt.Sprintf("%s: %q is not a valid connector base URL (scheme+host required)", key, value),
			})
			continue
		}
		if opts.Production && opts.ApprovedEgressOnly {
			if len(egress) == 0 {
				problems = append(problems, Problem{
					Code:   "connector_egress_unregistered",
					Detail: fmt.Sprintf("%s: no egress allowlist configured (GROUNDWORK_CONNECTOR_EGRESS_ALLOWLIST or GROUNDWORK_EGRESS_ALLOWLIST) — outbound connector traffic must be registered", key),
				})
			} else if !registered[host] {
				problems = append(problems, Problem{
					Code:   "connector_egress_unregistered",
					Detail: fmt.Sprintf("%s: host %q is not on the registered egress allowlist", key, host),
				})
			}
		}
		if strings.HasPrefix(strings.ToLower(value), "http://") && !isPrivateHost(host) {
			problems = append(problems, Problem{
				Code:   "connector_plaintext_endpoint",
				Detail: fmt.Sprintf("%s: public host %q must use https — plaintext egress is forbidden", key, host),
			})
		}
		if strings.EqualFold(opts.lookup(strings.TrimSuffix(key, "_BASE_URL")+"_TLS_VERIFY"), "false") {
			problems = append(problems, Problem{
				Code:   "connector_tls_verify_disabled",
				Detail: fmt.Sprintf("%s: TLS certificate verification is disabled in production — fails closed", key),
			})
		}
	}
	if opts.Production && strings.EqualFold(opts.lookup("GROUNDWORK_CONNECTOR_TLS_VERIFY"), "false") {
		problems = append(problems, Problem{
			Code:   "connector_tls_verify_disabled",
			Detail: "GROUNDWORK_CONNECTOR_TLS_VERIFY=false disables TLS verification for every connector in production — fails closed",
		})
	}
	if opts.Production && connectorsFound && len(egress) == 0 && opts.ApprovedEgressOnly {
		problems = append(problems, Problem{
			Code:   "connector_egress_unregistered",
			Detail: "connectors are configured but no egress allowlist is registered — outbound connector traffic must be registered before startup",
		})
	}

	return problems
}

// connectorHost extracts the hostname of a connector base URL.
func connectorHost(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	scheme := ""
	for _, s := range []string{"https://", "http://"} {
		if strings.HasPrefix(lower, s) {
			scheme = s
			break
		}
	}
	if scheme == "" {
		return ""
	}
	rest := lower[len(scheme):]
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// isPrivateHost reports whether host is a loopback, RFC1918, or
// link-local address — the only hosts allowed plaintext egress.
func isPrivateHost(host string) bool {
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	// "localhost" and names ending in .local/.internal are treated as
	// private; everything else (including unresolved names) is public.
	switch strings.ToLower(host) {
	case "localhost":
		return true
	}
	return strings.HasSuffix(strings.ToLower(host), ".local") ||
		strings.HasSuffix(strings.ToLower(host), ".internal")
}

// transferAllowed reports whether any policy in the set explicitly
// allows the kind/from/to flow.
func transferAllowed(policies []TransferPolicy, kind, from, to string) bool {
	for _, p := range policies {
		if p.Allows(kind, from, to) {
			return true
		}
	}
	return false
}

func isGateway(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), "gateway")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
