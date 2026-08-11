package connectors

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"groundwork/query-runtime/internal/keyring"
	"groundwork/query-runtime/internal/runtime"
)

// SecretResolver resolves secret references to credential material.
// References are never raw credentials: keyring://<purpose> resolves
// through the configured keyring; env://<NAME> resolves an environment
// variable. Any other prefix (or empty reference for a connector that
// declares one) fails closed.
type SecretResolver interface {
	// Resolve returns the secret bytes for ref, or an error. The raw
	// material is never logged and never returned to callers.
	Resolve(ctx context.Context, tenantID, ref string) ([]byte, error)
	// Expiry reports when the credential behind ref expires (zero =
	// no expiry metadata, e.g. env-provided material). Used by the
	// Phase 8.5 credential-expiry monitor; never errors — a ref that
	// cannot be dated simply reports zero so the scan continues.
	Expiry(ctx context.Context, tenantID, ref string) time.Time
	// Health returns a description of the resolver source (for the
	// console; never secrets).
	Health() string
}

// KeyringSecretResolver resolves keyring://<purpose> references via the
// configured keyring (Phase 4) and env://<NAME> references from the
// environment (injected through the secret provider at deploy time —
// never in config files).
type KeyringSecretResolver struct {
	ring *keyring.Keyring
}

// NewKeyringSecretResolver wires the Phase 4 keyring as the secret
// provider. A nil ring resolves nothing (fail closed).
func NewKeyringSecretResolver(ring *keyring.Keyring) *KeyringSecretResolver {
	return &KeyringSecretResolver{ring: ring}
}

func (s *KeyringSecretResolver) Resolve(ctx context.Context, tenantID, ref string) ([]byte, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("%w: no secret reference configured", runtime.ErrConnectorInvalidConfig)
	}
	lower := strings.ToLower(ref)
	switch {
	case strings.HasPrefix(lower, "keyring://"):
		purpose := strings.TrimPrefix(lower, "keyring://")
		if !keyring.IsKnownPurpose(purpose) {
			return nil, fmt.Errorf("%w: unknown keyring purpose %q", runtime.ErrConnectorInvalidConfig, purpose)
		}
		if s.ring == nil {
			return nil, runtime.ErrConnectorUnavailable
		}
		key, err := s.ring.Get(ctx, purpose)
		if err != nil {
			return nil, fmt.Errorf("connector secret: %w", err)
		}
		return key.Secret, nil
	case strings.HasPrefix(lower, "env://"):
		name := strings.TrimPrefix(ref, "env://")
		name = strings.TrimPrefix(name, "ENV://")
		if name == "" || strings.ContainsAny(name, " \t\n") {
			return nil, fmt.Errorf("%w: malformed env secret reference", runtime.ErrConnectorInvalidConfig)
		}
		// References name a *prefix*; the actual variable is
		// GROUNDWORK_CONNECTOR_<NAME>_SECRET or <NAME> verbatim.
		for _, candidate := range []string{name, "GROUNDWORK_CONNECTOR_" + name + "_SECRET"} {
			if v := strings.TrimSpace(os.Getenv(candidate)); v != "" {
				return []byte(v), nil
			}
		}
		return nil, fmt.Errorf("%w: env secret %q not provisioned (fail closed)", runtime.ErrConnectorUnavailable, name)
	default:
		return nil, fmt.Errorf("%w: secret_ref must be keyring://<purpose> or env://<NAME>", runtime.ErrConnectorInvalidConfig)
	}
}

func (s *KeyringSecretResolver) Health() string {
	if s.ring == nil {
		return "not configured"
	}
	return "keyring + env"
}

// Expiry dates the credential behind a reference: keyring://<purpose>
// reports the purpose key's expiry (zero when unprovisioned or never
// expiring); env:// material carries no metadata so it reports zero.
// Unknown/malformed references report zero (monitor-only, never
// fail-closed).
func (s *KeyringSecretResolver) Expiry(ctx context.Context, _ string, ref string) time.Time {
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(strings.ToLower(ref), "keyring://") || s.ring == nil {
		return time.Time{}
	}
	purpose := strings.TrimPrefix(strings.ToLower(ref), "keyring://")
	if !keyring.IsKnownPurpose(purpose) {
		return time.Time{}
	}
	return s.ring.Expiries(ctx)[purpose]
}

// TLSConfigFor builds the outbound TLS configuration: verification is
// always on for public hosts; private hosts may disable verification
// ONLY when the connector explicitly sets tls_verify=false (dev). A
// client certificate is loaded from client_cert_ref (PEM bundle).
func TLSConfigFor(verify bool, clientCertRef string, resolver SecretResolver, ctx context.Context) (*tls.Config, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if !verify {
		// InsecureSkipVerify is allowed only when the operator declared
		// it (dev/private-network); the deployment validator rejects
		// tls_verify=false in production.
		tlsCfg.InsecureSkipVerify = true // #nosec G402 — operator-declared for private nets
	}
	if clientCertRef != "" {
		raw, err := resolver.Resolve(ctx, "", clientCertRef)
		if err != nil {
			return nil, fmt.Errorf("connector mTLS client cert: %w", err)
		}
		cert, err := tls.X509KeyPair(raw, raw)
		if err != nil {
			// PEM bundle may hold cert + key blocks; X509KeyPair needs
			// both — resolve refs that embed both cert and key.
			block, _ := pem.Decode(raw)
			if block == nil {
				return nil, fmt.Errorf("connector mTLS: invalid PEM in %q", clientCertRef)
			}
			keyPEM := keyBlock(raw)
			if keyPEM == nil {
				return nil, fmt.Errorf("connector mTLS: no private key block in %q", clientCertRef)
			}
			cert, err = tls.X509KeyPair(pem.EncodeToMemory(block), keyPEM)
			if err != nil {
				return nil, fmt.Errorf("connector mTLS: %w", err)
			}
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

func keyBlock(pemBytes []byte) []byte {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		if block.Type == "PRIVATE KEY" || block.Type == "RSA PRIVATE KEY" || block.Type == "EC PRIVATE KEY" {
			return pem.EncodeToMemory(block)
		}
	}
}
