package keyring

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"groundwork/query-runtime/internal/cryptosvc"
	"groundwork/query-runtime/internal/secretref"
)

// SecretResolver resolves keyring://<purpose>[/<id>] credential
// references through a KeyProvider — the production resolver for
// connector credentials and every other secret that travels as a
// reference. References to unknown purposes, missing material, or
// non-keyring schemes fail closed; resolved material is returned to
// the caller and never logged by this package.
//
// The reference id is informational: resolution returns the CURRENT
// key for the purpose, so rotation moves forward without any reference
// changes and historical material remains reachable through
// GetForVerification.
//
// Tenant-scoped resolution: when a tenant is set via WithTenant, keyring://connector/<id>
// references resolve under the per-tenant namespace
// "tenants/<tenant>/connectors/<id>". Other purposes use the default
// "purpose:<purpose>" namespace.
type SecretResolver struct {
	keyring KeyProvider
	tenant  string
}

// NewSecretResolver builds a resolver over a KeyProvider. A nil
// provider fails closed on every Resolve.
func NewSecretResolver(k KeyProvider) *SecretResolver {
	return &SecretResolver{keyring: k}
}

// WithTenant returns a resolver that scopes connector purposes to the
// given tenant (namespace: tenants/<tenant>/connectors/<id>). The
// original resolver is unchanged.
func (r *SecretResolver) WithTenant(tenant string) *SecretResolver {
	if r == nil {
		return nil
	}
	return &SecretResolver{keyring: r.keyring, tenant: tenant}
}

// GuardConnectorSecret enforces the connector credential policy at
// startup and returns the keyring-backed resolver for the reference.
//
// production (GROUNDWORK_ENV=production):
//   - the reference is REQUIRED — a plaintext client secret (empty ref)
//     is a startup error
//   - env:// references are rejected (secretref.GuardProductionRef)
//   - keyring references must resolve NOW: missing material fails
//     startup (fail fast, fail closed)
//   - secret-manager references are rejected because no external
//     adapter is wired in this build (the connector would fail on its
//     first token fetch otherwise)
//   - in production, a DB-backed KeyProvider is REQUIRED (via
//     DBKeyProviderOptions); EnvProvider is NOT used
//
// local/dev: plaintext secrets and env:// references remain permitted;
// the returned resolver is nil for env:// so the caller can wire the
// env resolver. The expiry is the resolved key's ExpiresAt (zero when
// none configured) and flows into Installation.CredentialTTL.
//
// dbOpts is optional; when nil and production=true, the function fails
// with a clear error directing the caller to wire a DB keyring.
func GuardConnectorSecret(ctx context.Context, production bool, clientSecret, ref string, dbOpts ...*DBKeyProviderOptions) (*SecretResolver, time.Time, error) {
	var opts *DBKeyProviderOptions
	if len(dbOpts) > 0 {
		opts = dbOpts[0]
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		if production {
			return nil, time.Time{}, errors.New("keyring: MS_GRAPH_CLIENT_SECRET_REF is required in production — plaintext MS_GRAPH_CLIENT_SECRET is forbidden")
		}
		return nil, time.Time{}, nil
	}
	parsed, err := secretref.Parse(ref)
	if err != nil {
		return nil, time.Time{}, err
	}
	if production {
		if err := secretref.GuardProductionRef(ref); err != nil {
			return nil, time.Time{}, err
		}
	}
	switch {
	case parsed.IsKeyring():
		var provider KeyProvider
		if production {
			if opts == nil {
				return nil, time.Time{}, errors.New("keyring: production requires DBKeyProviderOptions (db, kekResolver, kekRef) to resolve keyring:// references")
			}
			dbProvider, err := NewDBKeyProvider(ctx, *opts)
			if err != nil {
				return nil, time.Time{}, fmt.Errorf("keyring: failed to initialize DB keyring: %w", err)
			}
			provider = dbProvider
		} else {
			provider = New(NewEnvProvider())
		}
		resolver := NewSecretResolver(provider)
		if _, err := resolver.Resolve(ctx, ref); err != nil {
			return nil, time.Time{}, fmt.Errorf("keyring: connector credential reference failed to resolve at startup (fail closed): %w", err)
		}
		expiry, _ := resolver.Expiry(ctx, ref)
		return resolver, expiry, nil
	case parsed.IsEnv():
		if production {
			return nil, time.Time{}, errors.New("keyring: env:// references are forbidden in production")
		}
		return nil, time.Time{}, nil // caller wires the env resolver (local/dev only)
	case parsed.IsSecretsManager():
		return nil, time.Time{}, errors.New("keyring: secret-manager references require an external adapter that is not wired in this build — use keyring://<purpose>/<id>")
	}
	return nil, time.Time{}, fmt.Errorf("keyring: unsupported credential reference %q", ref)
}

// Resolve implements the connector secret-resolution contract:
// keyring://connector/msgraph -> current key material for the
// "connector" purpose. Empty material is an error, never a result.
// When tenant is set, connector purposes resolve under the
// per-tenant namespace (tenants/<tenant>/connectors/<id>).
func (r *SecretResolver) Resolve(ctx context.Context, ref string) (string, error) {
	if r == nil || r.keyring == nil {
		return "", errors.New("keyring: secret resolver has no keyring (fail closed)")
	}
	parsed, err := secretref.Parse(ref)
	if err != nil {
		return "", err
	}
	if !parsed.IsKeyring() {
		return "", fmt.Errorf("keyring: %q is not a keyring reference", ref)
	}
	if parsed.Purpose == "" {
		return "", fmt.Errorf("keyring: reference %q has no purpose", ref)
	}
	if !IsKnownPurpose(parsed.Purpose) {
		return "", fmt.Errorf("%w: %s (ref %q)", ErrInvalidPurpose, parsed.Purpose, ref)
	}

	// Tenant-scoped connector resolution: when tenant is set and
	// purpose is "connector" with a connector ID, use the
	// per-tenant namespace (tenants/<tenant>/connectors/<id>).
	if r.tenant != "" && parsed.Purpose == PurposeConnector && parsed.ID != "" {
		if dbProvider, ok := r.keyring.(*DBKeyProvider); ok {
			key, err := dbProvider.GetForConnector(ctx, r.tenant, parsed.Purpose, parsed.ID)
			if err != nil {
				return "", fmt.Errorf("%w (ref %q)", err, ref)
			}
			if len(key.Secret) == 0 {
				return "", fmt.Errorf("keyring: empty secret material for purpose %s (ref %q) — fail closed", parsed.Purpose, ref)
			}
			return string(key.Secret), nil
		}
		// If not a DBKeyProvider, fall through to fail closed
		return "", fmt.Errorf("%w: tenant %s connector %s (ref %q)", ErrSecretNotFound, r.tenant, parsed.ID, ref)
	}

	key, err := r.keyring.Get(ctx, parsed.Purpose)
	if err != nil {
		return "", fmt.Errorf("%w (ref %q)", err, ref)
	}
	if len(key.Secret) == 0 {
		return "", fmt.Errorf("keyring: empty secret material for purpose %s (ref %q) — fail closed", parsed.Purpose, ref)
	}
	return string(key.Secret), nil
}

// Expiry resolves the keyring reference's credential expiry (the
// Installation.CredentialTTL source). Zero time means the purpose key
// has no configured expiry. It never errors for an unprovisioned
// purpose — callers treat zero as "no expiry configured".
func (r *SecretResolver) Expiry(ctx context.Context, ref string) (time.Time, error) {
	if r == nil || r.keyring == nil {
		return time.Time{}, errors.New("keyring: secret resolver has no keyring (fail closed)")
	}
	parsed, err := secretref.Parse(ref)
	if err != nil {
		return time.Time{}, err
	}
	if !parsed.IsKeyring() || !IsKnownPurpose(parsed.Purpose) {
		return time.Time{}, nil
	}

	// Tenant-scoped connector expiry: when tenant is set and
	// purpose is "connector" with a connector ID, use the
	// per-tenant namespace.
	if r.tenant != "" && parsed.Purpose == PurposeConnector && parsed.ID != "" {
		if dbProvider, ok := r.keyring.(*DBKeyProvider); ok {
			exp, err := dbProvider.ExpiryForConnector(ctx, r.tenant, parsed.Purpose, parsed.ID)
			if err != nil {
				return time.Time{}, nil
			}
			return exp, nil
		}
		return time.Time{}, nil
	}

	key, err := r.keyring.Get(ctx, parsed.Purpose)
	if err != nil {
		return time.Time{}, nil
	}
	return key.ExpiresAt, nil
}

// BuildDBKeyProviderOptions constructs DBKeyProviderOptions from
// environment variables. Returns nil if not in production or if
// required env vars are missing (caller should fail closed).
func BuildDBKeyProviderOptions() *DBKeyProviderOptions {
	if !strings.EqualFold(os.Getenv("GROUNDWORK_ENV"), "production") {
		return nil
	}
	dbURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dbURL == "" {
		return nil
	}
	kekRef := strings.TrimSpace(os.Getenv("GROUNDWORK_KEK_REF"))
	if kekRef == "" {
		kekBase64 := strings.TrimSpace(os.Getenv("GROUNDWORK_KEK_BASE64"))
		if kekBase64 == "" {
			return nil
		}
		kekRef = "env://GROUNDWORK_KEK_BASE64"
	}
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return nil
	}
	return &DBKeyProviderOptions{
		DB:          db,
		KEKResolver: cryptosvc.ResolverChain{cryptosvc.EnvKEK{}, cryptosvc.FileKEK{}},
		KEKRef:      kekRef,
		Namespace:   "purpose:",
	}
}

// CloseDB closes the database connection if it was opened by
// BuildDBKeyProviderOptions. Safe to call with nil.
func CloseDB(db *sql.DB) {
	if db != nil {
		_ = db.Close()
	}
}
