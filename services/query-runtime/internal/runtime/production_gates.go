package runtime

import (
	"fmt"
	"strings"
)

// ProductionGate is one fail-closed startup requirement for a
// non-local (staging/production/self-hosted) deployment. Each gate is
// enforced at runtime startup and by `groundwork doctor`.
type ProductionGate struct {
	Code   string
	Detail string
}

// PredictableAuditSalts are IMMUTABLE_AUDIT_SALT values that are
// trivially guessable — exactly the ones an attacker with table-write
// privileges would try first when recomputing digests after tampering
// (L-004). Values that appear literally in the repository are included:
// a salt published in the repo provides no tamper-evidence.
var PredictableAuditSalts = map[string]bool{
	"change-me":                          true,
	"change_me":                          true,
	"changeme":                           true,
	"default":                            true,
	"default-salt":                       true,
	"default_salt":                       true,
	"default-salt-change-me":             true,
	"default_salt_change_me":             true,
	"secret":                             true,
	"password":                           true,
	"salt":                               true,
	"groundwork":                         true,
	"groundwork-salt":                    true,
	"groundwork_audit_salt":              true,
	"example-audit-salt-017-aabbccddee":  true,
	"quickstart_demo_salt_37840ed_valid": true,
}

// ValidateAuditSalt enforces the L-004 guard: predictable non-empty
// IMMUTABLE_AUDIT_SALT values are refused at startup. An empty salt
// reproduces the original unsalted digest formula (local/dev and
// pre-salt deployments). Production operators must set a strong random
// value (>= 16 chars) once and never change it.
func ValidateAuditSalt(salt string) error {
	if salt == "" {
		return nil
	}
	if PredictableAuditSalts[strings.ToLower(strings.TrimSpace(salt))] {
		return fmt.Errorf("IMMUTABLE_AUDIT_SALT is set to a predictable value %q — refusing to run with a salt that provides no tamper-evidence protection. Generate a strong random value and set it once; never change it afterwards (changing it invalidates the chain). See docs/threat-model.md L-004.", salt)
	}
	if len(salt) < 16 {
		return fmt.Errorf("IMMUTABLE_AUDIT_SALT must be at least 16 characters (got %d)", len(salt))
	}
	return nil
}

// ProductionConfig holds the environment-derived values the production
// gate suite evaluates. Tests populate it directly; main.go and doctor
// build it from the process environment.
type ProductionConfig struct {
	Env             string
	BootstrapKey    string
	BootstrapTenant string
	AuditSalt       string
	// Identity material: OIDC issuer or a JWT HS/RS secret.
	OIDCIssuer        string
	JWTSecret         string
	JWTPrivateKey     string
	JWTPrivateKeyFile string
	// Store / transport hardening.
	AllowMemoryAPIKeys bool
	SpiceDBPlaintext   bool
	DatabaseURL        string
	// Firewall is either enabled via mode or explicitly opted out.
	FirewallMode           string
	FirewallExplicitOptOut bool
}

// ValidateProductionGates returns every failing gate for the given
// config. A non-local environment fails closed on the first violation;
// local/dev/demo environments pass without checks.
func ValidateProductionGates(cfg ProductionConfig) []ProductionGate {
	if IsLocalEnv(cfg.Env) {
		return nil
	}

	var gates []ProductionGate

	// G1: bootstrap key must be set, non-default, and not a repo literal.
	if err := ValidateBootstrapAPIKey(cfg.BootstrapKey, cfg.Env); err != nil {
		gates = append(gates, ProductionGate{Code: "bootstrap_api_key", Detail: err.Error()})
	}

	// G2: audit salt must be set and unpredictable in production.
	if err := ValidateAuditSalt(cfg.AuditSalt); err != nil {
		gates = append(gates, ProductionGate{Code: "audit_salt", Detail: err.Error()})
	} else if cfg.AuditSalt == "" {
		gates = append(gates, ProductionGate{Code: "audit_salt", Detail: "IMMUTABLE_AUDIT_SALT is required in production (set a fresh random value before the first audit write)"})
	}

	// G3: identity must come from OIDC or a configured signing key.
	if cfg.OIDCIssuer == "" && len(cfg.JWTSecret) < 32 && cfg.JWTPrivateKey == "" && cfg.JWTPrivateKeyFile == "" {
		gates = append(gates, ProductionGate{Code: "identity", Detail: "production requires GROUNDWORK_OIDC_ISSUER or a JWT signing key (GROUNDWORK_JWT_HS_SECRET >= 32 chars / GROUNDWORK_JWT_RS_PRIVATE_KEY[_FILE])"})
	}

	// G4: memory stores must not be enabled.
	if cfg.AllowMemoryAPIKeys {
		gates = append(gates, ProductionGate{Code: "memory_store", Detail: "ALLOW_MEMORY_API_KEYS=true is forbidden in production — API keys must be Postgres-backed"})
	}

	// G5: TLS on the relationship and database transports.
	if cfg.SpiceDBPlaintext {
		gates = append(gates, ProductionGate{Code: "spicedb_tls", Detail: "SPICEDB_INSECURE_PLAINTEXT=true is forbidden in production"})
	}
	if cfg.DatabaseURL != "" && (strings.Contains(cfg.DatabaseURL, "sslmode=disable") || strings.Contains(cfg.DatabaseURL, "sslmode%3Ddisable")) {
		gates = append(gates, ProductionGate{Code: "postgres_tls", Detail: "DATABASE_URL disables TLS (sslmode=disable) — production requires encrypted database transport"})
	}

	// G7: firewall must be enabled or explicitly opted out.
	if cfg.FirewallMode == "" && !cfg.FirewallExplicitOptOut {
		gates = append(gates, ProductionGate{Code: "firewall", Detail: "GW_FIREWALL_MODE is unset — set redact|block, or set GW_FIREWALL_OPT_OUT=true to acknowledge the risk"})
	}

	// G8: no default/demo credentials.
	if strings.HasPrefix(cfg.BootstrapKey, "gw_local_") {
		gates = append(gates, ProductionGate{Code: "default_credentials", Detail: "BOOTSTRAP_API_KEY uses the gw_local_ demo prefix in production"})
	}
	if cfg.BootstrapTenant == "acme" {
		gates = append(gates, ProductionGate{Code: "default_credentials", Detail: "BOOTSTRAP_TENANT_ID=acme (demo tenant) in production"})
	}

	return gates
}
