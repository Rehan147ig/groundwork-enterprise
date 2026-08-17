// Package keyring is the customer-managed key layer (Phase 4d).
//
// Every key purpose in the system (identity, delegation, webhook,
// audit digest, database, backup) resolves through one KeyProvider.
// Local/dev deployments use EnvProvider (key material in environment
// variables). Production deployments should use a KMS-backed provider
// (AWS/GCP) or the ExternalProvider adapter for HYOK / in-house KMS;
// those adapters live outside this package (customer-specific) and
// implement the KeyProvider interface here.
//
// Missing key material for a purpose MUST surface as ErrKeyMissing so
// callers fail closed. Rotation is recorded as metadata by Keyring; a
// provider that cannot rotate (e.g. env) returns ErrRotationUnsupported.
package keyring

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Purposes is the closed set of key purposes.
const (
	PurposeIdentity    = "identity"     // OIDC/JWT end-user assertion verification
	PurposeDelegation  = "delegation"   // governed delegation tokens (RS256/HS256)
	PurposeWebhook     = "webhook"      // outbox webhook HMAC signing (v1=...)
	PurposeAuditDigest = "audit_digest" // audit chain digest key (phase 3)
	PurposeDatabase    = "database"     // database encryption key reference
	PurposeBackup      = "backup"       // backup encryption key reference
	PurposeConnector   = "connector"    // connector credential metadata encryption (Milestone 3)
)

// KnownPurposes is the closed, sorted set of key purposes.
func KnownPurposes() []string {
	return []string{
		PurposeAuditDigest,
		PurposeBackup,
		PurposeConnector,
		PurposeDatabase,
		PurposeDelegation,
		PurposeIdentity,
		PurposeWebhook,
	}
}

// IsKnownPurpose reports whether p is in the closed purpose set.
func IsKnownPurpose(p string) bool {
	for _, known := range KnownPurposes() {
		if p == known {
			return true
		}
	}
	return false
}

// Errors returned by providers. Callers treat ErrKeyMissing as
// fail-closed: never substitute a default or demo key.
var (
	ErrKeyMissing            = errors.New("keyring: no key material for purpose")
	ErrKeyUnknown            = errors.New("keyring: no key with the given id for historical verification")
	ErrRotationUnsupported   = errors.New("keyring: this provider cannot rotate keys")
	ErrInvalidPurpose        = errors.New("keyring: unknown purpose")
	ErrProviderNotConfigured = errors.New("keyring: provider is not configured for this purpose")
	ErrSecretNotFound        = errors.New("keyring: secret not found for tenant/connector")
)

// Key is one provisioned key for a purpose.
type Key struct {
	ID           string    `json:"id"`                   // stable key id (env: derived fingerprint; KMS: key id/version)
	Purpose      string    `json:"purpose"`              // one of KnownPurposes
	Provider     string    `json:"provider"`             // "env", "kms", "external"
	Provisioned  time.Time `json:"provisioned"`          // when this key became current
	ExpiresAt    time.Time `json:"expires_at,omitempty"` // zero = no expiry configured
	Secret       []byte    `json:"-"`                    // key material; never serialized
	MaterialKind string    `json:"material_kind"`        // "hmac", "rsa_private", "key_id_reference"
}

// KeyProvider resolves key material by purpose. Implementations MUST
// return ErrKeyMissing for an unprovisioned purpose and MUST NOT return
// zero/empty material.
type KeyProvider interface {
	// Get returns the current key for the purpose.
	Get(ctx context.Context, purpose string) (Key, error)
	// GetForVerification returns historical key material so signatures
	// created before rotation can still be verified. Unknown key ids
	// return ErrKeyUnknown.
	GetForVerification(ctx context.Context, purpose, keyID string) (Key, error)
	// Rotate provisions new material for the purpose and returns it.
	// Providers that cannot rotate return ErrRotationUnsupported.
	Rotate(ctx context.Context, purpose string) (Key, error)
	// Source identifies the provider (for audit logging).
	Source() string
}

// Rotation records a rotation for the audit trail.
type Rotation struct {
	Purpose       string    `json:"purpose"`
	FromKeyID     string    `json:"from_key_id"`
	ToKeyID       string    `json:"to_key_id"`
	ProvisionedAt time.Time `json:"provisioned_at"`
	Provider      string    `json:"provider"`
}

// Keyring is the aggregate key manager: one provider, rotation ledger,
// and a fail-closed view of provisioned purposes.
type Keyring struct {
	provider  KeyProvider
	rotations []Rotation
}

// New builds a Keyring over the given provider.
func New(provider KeyProvider) *Keyring {
	return &Keyring{provider: provider}
}

// Provider exposes the underlying provider (for audits and external
// adapters).
func (k *Keyring) Provider() KeyProvider { return k.provider }

// Source returns the provider's source identifier.
func (k *Keyring) Source() string { return k.provider.Source() }

// Get returns the current key for the purpose. Missing material
// surfaces ErrKeyMissing (fail closed).
func (k *Keyring) Get(ctx context.Context, purpose string) (Key, error) {
	if !IsKnownPurpose(purpose) {
		return Key{}, ErrInvalidPurpose
	}
	return k.provider.Get(ctx, purpose)
}

// GetForVerification returns historical key material for the given
// key_id. Delegates to the underlying provider.
func (k *Keyring) GetForVerification(ctx context.Context, purpose, keyID string) (Key, error) {
	if !IsKnownPurpose(purpose) {
		return Key{}, ErrInvalidPurpose
	}
	return k.provider.GetForVerification(ctx, purpose, keyID)
}

// Rotate rotates the purpose key and records the rotation. Providers
// without rotation support return ErrRotationUnsupported unchanged.
func (k *Keyring) Rotate(ctx context.Context, purpose string) (Key, error) {
	if !IsKnownPurpose(purpose) {
		return Key{}, ErrInvalidPurpose
	}
	before, err := k.provider.Get(ctx, purpose)
	if err != nil && !errors.Is(err, ErrKeyMissing) {
		return Key{}, err
	}
	next, err := k.provider.Rotate(ctx, purpose)
	if err != nil {
		return Key{}, err
	}
	fromID := ""
	if err == nil && before.ID != "" {
		fromID = before.ID
	}
	k.rotations = append(k.rotations, Rotation{
		Purpose:       purpose,
		FromKeyID:     fromID,
		ToKeyID:       next.ID,
		ProvisionedAt: time.Now().UTC(),
		Provider:      k.provider.Source(),
	})
	return next, nil
}

// Rotations returns a copy of the rotation ledger (newest last).
func (k *Keyring) Rotations() []Rotation {
	out := make([]Rotation, len(k.rotations))
	copy(out, k.rotations)
	return out
}

// MissingPurposes returns the purposes without provisioned material.
// Production startup must fail when this is non-empty.
func (k *Keyring) MissingPurposes(ctx context.Context) []string {
	var missing []string
	for _, purpose := range KnownPurposes() {
		if _, err := k.provider.Get(ctx, purpose); err != nil {
			missing = append(missing, purpose)
		}
	}
	return missing
}

// Expiries returns each known purpose's key expiry as a closed-set map
// (zero time = no expiry configured or unprovisioned). It never errors
// and never surfaces key material — monitoring calls it on a cadence
// (Phase 8.5 key-expiry gauges).
func (k *Keyring) Expiries(ctx context.Context) map[string]time.Time {
	out := make(map[string]time.Time, len(KnownPurposes()))
	for _, purpose := range KnownPurposes() {
		if key, err := k.provider.Get(ctx, purpose); err == nil {
			out[purpose] = key.ExpiresAt
		}
	}
	return out
}

// EnvProvider reads key material from environment variables — the
// local/dev provider and the fallback for KMS-less production runs.
//
//	identity:     GROUNDWORK_OIDC_ISSUER or GROUNDWORK_JWT_HS_SECRET
//	delegation:   GROUNDWORK_DELEGATION_RS_PRIVATE_KEY or GROUNDWORK_DELEGATION_HS_SECRET
//	webhook:      GROUNDWORK_OUTBOX_WEBHOOK_SECRET
//	audit_digest: GROUNDWORK_AUDIT_DIGEST_KEY
//	database:     GROUNDWORK_DATABASE_KEY_ID   (reference, not material)
//	backup:       GROUNDWORK_BACKUP_KEY_ID     (reference, not material)
//
// An optional RFC3339 GROUNDWORK_<PURPOSE>_KEY_EXPIRY (e.g.
// GROUNDWORK_WEBHOOK_KEY_EXPIRY=2027-01-01T00:00:00Z) surfaces an
// expiry for the purpose key (Phase 8.5 key-expiry monitoring); an
// unset or unparseable value means no expiry.
type EnvProvider struct {
	lookup func(string) string
}

// NewEnvProvider builds an EnvProvider over os.Getenv.
func NewEnvProvider() *EnvProvider {
	return &EnvProvider{lookup: os.Getenv}
}

// Source implements KeyProvider.
func (p *EnvProvider) Source() string { return "env" }

var purposeEnv = map[string][]string{
	PurposeIdentity:    {"GROUNDWORK_OIDC_ISSUER", "GROUNDWORK_JWT_HS_SECRET"},
	PurposeDelegation:  {"GROUNDWORK_DELEGATION_RS_PRIVATE_KEY", "GROUNDWORK_DELEGATION_HS_SECRET"},
	PurposeWebhook:     {"GROUNDWORK_OUTBOX_WEBHOOK_SECRET"},
	PurposeAuditDigest: {"GROUNDWORK_AUDIT_DIGEST_KEY"},
	PurposeDatabase:    {"GROUNDWORK_DATABASE_KEY_ID"},
	PurposeBackup:      {"GROUNDWORK_BACKUP_KEY_ID"},
	PurposeConnector:   {"GROUNDWORK_CONNECTOR_CREDENTIAL_KEY"},
}

func keyEnv(purpose string) []string {
	return purposeEnv[purpose]
}

// Get implements KeyProvider.
func (p *EnvProvider) Get(_ context.Context, purpose string) (Key, error) {
	if !IsKnownPurpose(purpose) {
		return Key{}, ErrInvalidPurpose
	}
	for _, env := range keyEnv(purpose) {
		if v := strings.TrimSpace(p.lookup(env)); v != "" {
			digest := sha256.Sum256([]byte(env + ":" + v))
			id := purpose + "-" + hex.EncodeToString(digest[:8])
			return Key{
				ID:           id,
				Purpose:      purpose,
				Provider:     p.Source(),
				Provisioned:  time.Now().UTC(),
				ExpiresAt:    p.expiry(purpose),
				Secret:       []byte(v),
				MaterialKind: materialKind(purpose),
			}, nil
		}
	}
	return Key{}, fmt.Errorf("%w: %s", ErrKeyMissing, purpose)
}

// expiry resolves the optional GROUNDWORK_<PURPOSE>_KEY_EXPIRY override
// (RFC3339); zero time means no expiry configured.
func (p *EnvProvider) expiry(purpose string) time.Time {
	raw := strings.TrimSpace(p.lookup("GROUNDWORK_" + strings.ToUpper(purpose) + "_KEY_EXPIRY"))
	if raw == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// GetForVerification implements KeyProvider. Env cannot store history:
// the current key verifies; anything else is unknown (fail closed).
func (p *EnvProvider) GetForVerification(ctx context.Context, purpose, keyID string) (Key, error) {
	cur, err := p.Get(ctx, purpose)
	if err != nil {
		return Key{}, err
	}
	if cur.ID != keyID {
		return Key{}, fmt.Errorf("%w: %s/%s", ErrKeyUnknown, purpose, keyID)
	}
	return cur, nil
}

// Rotate implements KeyProvider — env files cannot rotate keys; use a
// KMS-backed or external provider for rotation.
func (p *EnvProvider) Rotate(_ context.Context, purpose string) (Key, error) {
	return Key{}, fmt.Errorf("%w: %s (env key material is immutable; rotate in your secrets store)", ErrRotationUnsupported, purpose)
}

func materialKind(purpose string) string {
	switch purpose {
	case PurposeDelegation:
		return "rsa_private_or_hmac"
	case PurposeDatabase, PurposeBackup:
		return "key_id_reference"
	default:
		return "hmac_or_shared_secret"
	}
}

// ExternalProvider is the adapter boundary for customer KMS / HYOK
// providers (AWS KMS, GCP KMS, Thales, in-house HSM). Implementations
// MUST:
//   - resolve key material per region (a key created in one region is
//     never usable in another)
//   - keep rotation history for GetForVerification (signatures from
//     previous key versions must verify)
//   - return ErrKeyMissing, never zero material
//
// A canonical implementation for a specific cloud lives in the
// customer's integration package.
type ExternalProvider struct {
	SourceName string
	GetFn      func(ctx context.Context, purpose string) (Key, error)
	HistoryFn  func(ctx context.Context, purpose, keyID string) (Key, error)
	RotateFn   func(ctx context.Context, purpose string) (Key, error)
}

// Get implements KeyProvider.
func (p *ExternalProvider) Get(ctx context.Context, purpose string) (Key, error) {
	if p.GetFn == nil {
		return Key{}, ErrProviderNotConfigured
	}
	return p.GetFn(ctx, purpose)
}

// GetForVerification implements KeyProvider.
func (p *ExternalProvider) GetForVerification(ctx context.Context, purpose, keyID string) (Key, error) {
	if p.HistoryFn == nil {
		return Key{}, ErrKeyUnknown
	}
	return p.HistoryFn(ctx, purpose, keyID)
}

// Rotate implements KeyProvider.
func (p *ExternalProvider) Rotate(ctx context.Context, purpose string) (Key, error) {
	if p.RotateFn == nil {
		return Key{}, ErrRotationUnsupported
	}
	return p.RotateFn(ctx, purpose)
}

// Source implements KeyProvider.
func (p *ExternalProvider) Source() string {
	if p.SourceName == "" {
		return "external"
	}
	return p.SourceName
}
