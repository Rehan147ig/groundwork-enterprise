package runtime

import "testing"

func validProductionConfig() ProductionConfig {
	return ProductionConfig{
		Env:             "production",
		BootstrapKey:    "gw_live_00000000_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		BootstrapTenant: "acme-corp",
		AuditSalt:       "a7f3e9c1d2b84f6e9a0c1d2e3f4a5b6c",
		JWTSecret:       "production-jwt-hs-secret-that-is-at-least-32-chars",
		DatabaseURL:     "postgres://user:pass@db:5432/groundwork?sslmode=require",
		FirewallMode:    "block",
	}
}

func TestValidateProductionGatesPassesValidConfig(t *testing.T) {
	if gates := ValidateProductionGates(validProductionConfig()); len(gates) != 0 {
		t.Fatalf("expected no gates to fail, got %v", gates)
	}
}

func TestValidateProductionGatesLocalSkips(t *testing.T) {
	if gates := ValidateProductionGates(ProductionConfig{}); len(gates) != 0 {
		t.Fatalf("expected local env to skip gates, got %v", gates)
	}
}

func TestValidateProductionGatesFlagsBootstrapKey(t *testing.T) {
	cfg := validProductionConfig()
	cfg.BootstrapKey = DefaultBootstrapAPIKey
	assertGateCode(t, ValidateProductionGates(cfg), "bootstrap_api_key")
}

func TestValidateProductionGatesFlagsMissingAuditSalt(t *testing.T) {
	cfg := validProductionConfig()
	cfg.AuditSalt = ""
	assertGateCode(t, ValidateProductionGates(cfg), "audit_salt")
}

func TestValidateProductionGatesFlagsMissingIdentity(t *testing.T) {
	cfg := validProductionConfig()
	cfg.JWTSecret = ""
	cfg.OIDCIssuer = ""
	cfg.JWTPrivateKey = ""
	cfg.JWTPrivateKeyFile = ""
	assertGateCode(t, ValidateProductionGates(cfg), "identity")
}

func TestValidateProductionGatesFlagsMemoryKeys(t *testing.T) {
	cfg := validProductionConfig()
	cfg.AllowMemoryAPIKeys = true
	assertGateCode(t, ValidateProductionGates(cfg), "memory_store")
}

func TestValidateProductionGatesFlagsSpiceDBPlaintext(t *testing.T) {
	cfg := validProductionConfig()
	cfg.SpiceDBPlaintext = true
	assertGateCode(t, ValidateProductionGates(cfg), "spicedb_tls")
}

func TestValidateProductionGatesFlagsPostgresTLS(t *testing.T) {
	cfg := validProductionConfig()
	cfg.DatabaseURL = "postgres://user:pass@db:5432/groundwork?sslmode=disable"
	assertGateCode(t, ValidateProductionGates(cfg), "postgres_tls")
}

func TestValidateProductionGatesFlagsMissingFirewall(t *testing.T) {
	cfg := validProductionConfig()
	cfg.FirewallMode = ""
	cfg.FirewallExplicitOptOut = false
	assertGateCode(t, ValidateProductionGates(cfg), "firewall")
}

func TestValidateProductionGatesAllowsFirewallOptOut(t *testing.T) {
	cfg := validProductionConfig()
	cfg.FirewallMode = ""
	cfg.FirewallExplicitOptOut = true
	for _, g := range ValidateProductionGates(cfg) {
		if g.Code == "firewall" {
			t.Fatalf("expected firewall opt-out to be accepted, got %v", g)
		}
	}
}

func TestValidateProductionGatesFlagsDemoCredentials(t *testing.T) {
	cfg := validProductionConfig()
	cfg.BootstrapKey = "gw_local_custom"
	cfg.BootstrapTenant = "acme"
	// At least the demo credentials and acme tenant gates should fire.
	gates := ValidateProductionGates(cfg)
	assertGateCode(t, gates, "default_credentials")
}

func assertGateCode(t *testing.T, gates []ProductionGate, want string) {
	t.Helper()
	for _, g := range gates {
		if g.Code == want {
			return
		}
	}
	t.Fatalf("expected gate %q in %v", want, gates)
}
