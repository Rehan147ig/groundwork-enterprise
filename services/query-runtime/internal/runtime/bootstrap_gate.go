package runtime

import (
	"fmt"
	"strings"
)

// DefaultBootstrapAPIKey is the fallback used when BOOTSTRAP_API_KEY is
// unset. It is intentionally public only for local/demo deployments; the
// production gate refuses to mint it outside a local environment.
const DefaultBootstrapAPIKey = "gw_local_acme_key"

// IsLocalEnv reports whether env is an explicitly local/development/test
// value. An empty value counts as local so the default demo path keeps
// working, mirroring the runtime's startup behavior.
func IsLocalEnv(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "", "local", "dev", "development", "test", "testing", "demo":
		return true
	default:
		return false
	}
}

// ValidateBootstrapAPIKey fails closed when the default, publicly-known
// bootstrap key would be minted outside a local environment. The key is
// published in the open-source repo, so minting it with query+admin
// scope in production is an authentication bypass.
func ValidateBootstrapAPIKey(bootstrapKey, env string) error {
	if IsLocalEnv(env) {
		return nil
	}
	if strings.TrimSpace(bootstrapKey) == "" {
		return fmt.Errorf("BOOTSTRAP_API_KEY is required when GROUNDWORK_ENV=%q", env)
	}
	if bootstrapKey == DefaultBootstrapAPIKey {
		return fmt.Errorf("BOOTSTRAP_API_KEY is the publicly-known default %q; refusing to mint it as an admin key in GROUNDWORK_ENV=%q", DefaultBootstrapAPIKey, env)
	}
	return nil
}
