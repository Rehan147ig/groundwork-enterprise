package runtime

import "testing"

func TestValidateBootstrapAPIKeyRejectsDefaultInProduction(t *testing.T) {
	for _, env := range []string{"production", "staging", "PROD", "self-hosted"} {
		if err := ValidateBootstrapAPIKey(DefaultBootstrapAPIKey, env); err == nil {
			t.Fatalf("expected default key to be rejected in %q", env)
		}
	}
}

func TestValidateBootstrapAPIKeyRejectsEmptyInProduction(t *testing.T) {
	if err := ValidateBootstrapAPIKey("", "production"); err == nil {
		t.Fatal("expected empty bootstrap key to be rejected in production")
	}
}

func TestValidateBootstrapAPIKeyAllowsDefaultInLocal(t *testing.T) {
	for _, env := range []string{"", "local", "dev", "development", "test", "demo"} {
		if err := ValidateBootstrapAPIKey(DefaultBootstrapAPIKey, env); err != nil {
			t.Fatalf("expected default key to be allowed in local env %q, got %v", env, err)
		}
	}
}

func TestValidateBootstrapAPIKeyAllowsCustomKeyInProduction(t *testing.T) {
	if err := ValidateBootstrapAPIKey("gw_live_00000000_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "production"); err != nil {
		t.Fatalf("expected custom key to be allowed in production, got %v", err)
	}
}
