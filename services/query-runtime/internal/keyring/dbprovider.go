package keyring

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"groundwork/query-runtime/internal/cryptosvc"
)

// DBKeyProvider is a KeyProvider backed by a PostgreSQL table
// (keyring_keys). Each row stores an envelope-encrypted secret for a
// specific namespace (e.g. "purpose:connector" or
// "tenants/<tenant_id>/connectors/<connector_id>"). The envelope uses
// AES-GCM via cryptosvc with a KEK from the provided resolver chain.
type DBKeyProvider struct {
	db        *sql.DB
	envelope  *cryptosvc.Envelope
	namespace string // default namespace prefix (e.g. "purpose:")
	tenantID  string // optional tenant for tenant-scoped namespaces
}

// DBKeyProviderOptions configures the DBKeyProvider.
type DBKeyProviderOptions struct {
	DB          *sql.DB
	KEKResolver cryptosvc.KEKResolver
	KEKRef      string
	Namespace   string // default: "purpose:"
	TenantID    string // optional: tenant ID for per-tenant namespaces
}

// NewDBKeyProvider builds a DBKeyProvider. It ensures the
// keyring_keys table exists (idempotent CREATE TABLE IF NOT EXISTS).
func NewDBKeyProvider(ctx context.Context, opts DBKeyProviderOptions) (*DBKeyProvider, error) {
	if opts.DB == nil {
		return nil, errors.New("dbprovider: nil DB")
	}
	if opts.KEKResolver == nil {
		return nil, errors.New("dbprovider: nil KEKResolver")
	}
	if strings.TrimSpace(opts.KEKRef) == "" {
		return nil, errors.New("dbprovider: empty KEKRef")
	}
	ns := opts.Namespace
	if ns == "" {
		ns = "purpose:"
	}
	if !strings.HasSuffix(ns, ":") {
		ns += ":"
	}

	envelope := cryptosvc.NewEnvelope(opts.KEKResolver, opts.KEKRef)

	p := &DBKeyProvider{
		db:        opts.DB,
		envelope:  envelope,
		namespace: ns,
		tenantID:  opts.TenantID,
	}

	// Ensure table exists (idempotent; avoids migration churn in
	// environments that cannot run the migration). The proper
	// migration (034_create_keyring_keys.sql) should be applied in
	// managed deployments; this is a safety net.
	if err := p.ensureTable(ctx); err != nil {
		return nil, fmt.Errorf("dbprovider: ensure table: %w", err)
	}
	return p, nil
}

func (p *DBKeyProvider) ensureTable(ctx context.Context) error {
	_, err := p.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS keyring_keys (
			namespace TEXT NOT NULL,
			purpose   TEXT NOT NULL,
			key_id    TEXT NOT NULL,
			ciphertext BYTEA NOT NULL,
			provisioned TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMPTZ,
			PRIMARY KEY (namespace, purpose, key_id)
		);
		CREATE INDEX IF NOT EXISTS idx_keyring_keys_purpose
			ON keyring_keys (purpose);
		CREATE INDEX IF NOT EXISTS idx_keyring_keys_namespace
			ON keyring_keys (namespace);
	`)
	return err
}

// Source implements KeyProvider.
func (p *DBKeyProvider) Source() string { return "database" }

// namespaceFor returns the storage namespace for a purpose.
// If tenantID is set and purpose is "connector", it uses the
// per-tenant, per-connector namespace: tenants/<tenant>/connectors/<connector_id>.
// Otherwise it uses the default "purpose:<purpose>" namespace.
func (p *DBKeyProvider) namespaceFor(purpose, connectorID string) string {
	if p.tenantID != "" && purpose == PurposeConnector && connectorID != "" {
		return "tenants/" + p.tenantID + "/connectors/" + connectorID
	}
	return p.namespace + purpose
}

// Get implements KeyProvider. Returns the current key for the
// purpose. The key_id is the newest (by provisioned) row's key_id.
// Missing material returns ErrKeyMissing (fail closed).
func (p *DBKeyProvider) Get(ctx context.Context, purpose string) (Key, error) {
	if !IsKnownPurpose(purpose) {
		return Key{}, ErrInvalidPurpose
	}

	ns := p.namespaceFor(purpose, "")

	var ciphertext []byte
	var keyID string
	var expiresAt sql.NullTime
	err := p.db.QueryRowContext(ctx, `
		SELECT ciphertext, key_id, expires_at
		FROM keyring_keys
		WHERE namespace = $1 AND purpose = $2
		ORDER BY provisioned DESC
		LIMIT 1
	`, ns, purpose).Scan(&ciphertext, &keyID, &expiresAt)
	if err == sql.ErrNoRows {
		return Key{}, fmt.Errorf("%w: %s (namespace %s)", ErrKeyMissing, purpose, ns)
	}
	if err != nil {
		return Key{}, fmt.Errorf("dbprovider: get %s: %w", purpose, err)
	}

	plaintext, err := p.envelope.Open(ctx, ciphertext)
	if err != nil {
		return Key{}, fmt.Errorf("dbprovider: decrypt %s: %w", purpose, err)
	}

	var exp time.Time
	if expiresAt.Valid {
		exp = expiresAt.Time
	}
	return Key{
		ID:           keyID,
		Purpose:      purpose,
		Provider:     p.Source(),
		Provisioned:  time.Now().UTC(),
		ExpiresAt:    exp,
		Secret:       plaintext,
		MaterialKind: materialKind(purpose),
	}, nil
}

// GetForVerification implements KeyProvider. Returns historical key
// material for the given key_id. Unknown key_id returns ErrKeyUnknown.
func (p *DBKeyProvider) GetForVerification(ctx context.Context, purpose, keyID string) (Key, error) {
	if !IsKnownPurpose(purpose) {
		return Key{}, ErrInvalidPurpose
	}
	ns := p.namespaceFor(purpose, "")

	var ciphertext []byte
	var expiresAt sql.NullTime
	err := p.db.QueryRowContext(ctx, `
		SELECT ciphertext, expires_at
		FROM keyring_keys
		WHERE namespace = $1 AND purpose = $2 AND key_id = $3
	`, ns, purpose, keyID).Scan(&ciphertext, &expiresAt)
	if err == sql.ErrNoRows {
		return Key{}, fmt.Errorf("%w: %s/%s (namespace %s)", ErrKeyUnknown, purpose, keyID, ns)
	}
	if err != nil {
		return Key{}, fmt.Errorf("dbprovider: get for verification %s/%s: %w", purpose, keyID, err)
	}

	plaintext, err := p.envelope.Open(ctx, ciphertext)
	if err != nil {
		return Key{}, fmt.Errorf("dbprovider: decrypt verification %s/%s: %w", purpose, keyID, err)
	}

	var exp time.Time
	if expiresAt.Valid {
		exp = expiresAt.Time
	}
	return Key{
		ID:           keyID,
		Purpose:      purpose,
		Provider:     p.Source(),
		Provisioned:  time.Now().UTC(),
		ExpiresAt:    exp,
		Secret:       plaintext,
		MaterialKind: materialKind(purpose),
	}, nil
}

// Rotate implements KeyProvider. Generates new random key material,
// encrypts it, and stores it as a new row with a new key_id. Returns
// the new key. Providers that cannot rotate (e.g. missing DB) return
// ErrRotationUnsupported.
func (p *DBKeyProvider) Rotate(ctx context.Context, purpose string) (Key, error) {
	if !IsKnownPurpose(purpose) {
		return Key{}, ErrInvalidPurpose
	}
	ns := p.namespaceFor(purpose, "")

	// Generate new key material (32 bytes for HMAC/shared secret)
	newMaterial := make([]byte, 32)
	if _, err := rand.Read(newMaterial); err != nil {
		return Key{}, fmt.Errorf("dbprovider: generate material: %w", err)
	}

	blob, err := p.envelope.Seal(ctx, newMaterial)
	if err != nil {
		return Key{}, fmt.Errorf("dbprovider: seal: %w", err)
	}

	// Derive key_id from purpose + sha256(material) prefix
	sum := sha256.Sum256(newMaterial)
	keyID := purpose + "-" + hex.EncodeToString(sum[:8])

	// Determine expiry from env override (same as EnvProvider)
	exp := time.Time{}
	raw := strings.TrimSpace(os.Getenv("GROUNDWORK_" + strings.ToUpper(purpose) + "_KEY_EXPIRY"))
	if raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			exp = t.UTC()
		}
	}

	_, err = p.db.ExecContext(ctx, `
		INSERT INTO keyring_keys (namespace, purpose, key_id, ciphertext, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (namespace, purpose, key_id) DO UPDATE
			SET ciphertext = EXCLUDED.ciphertext,
				provisioned = NOW(),
				expires_at = EXCLUDED.expires_at
	`, ns, purpose, keyID, blob, nullTime(exp))
	if err != nil {
		return Key{}, fmt.Errorf("dbprovider: insert rotated key: %w", err)
	}

	return Key{
		ID:           keyID,
		Purpose:      purpose,
		Provider:     p.Source(),
		Provisioned:  time.Now().UTC(),
		ExpiresAt:    exp,
		Secret:       newMaterial,
		MaterialKind: materialKind(purpose),
	}, nil
}

func nullTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}

// Provision manually provisions (or updates) a key for a purpose under
// a specific namespace. Used for seeding per-tenant connector keys
// (e.g. tenants/<tid>/connectors/msgraph). Returns the key_id.
func (p *DBKeyProvider) Provision(ctx context.Context, purpose, connectorID string, secret []byte, expiresAt time.Time) (string, error) {
	if !IsKnownPurpose(purpose) {
		return "", ErrInvalidPurpose
	}
	ns := p.namespaceFor(purpose, connectorID)

	sum := sha256.Sum256(secret)
	keyID := purpose + "-" + hex.EncodeToString(sum[:8])

	blob, err := p.envelope.Seal(ctx, secret)
	if err != nil {
		return "", fmt.Errorf("dbprovider: seal provision: %w", err)
	}

	_, err = p.db.ExecContext(ctx, `
		INSERT INTO keyring_keys (namespace, purpose, key_id, ciphertext, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (namespace, purpose, key_id) DO UPDATE
			SET ciphertext = EXCLUDED.ciphertext,
				provisioned = NOW(),
				expires_at = EXCLUDED.expires_at
	`, ns, purpose, keyID, blob, nullTime(expiresAt))
	if err != nil {
		return "", fmt.Errorf("dbprovider: provision: %w", err)
	}
	return keyID, nil
}

// GetAllForPurpose returns all key versions for a purpose in a
// namespace (newest first). Used for rotation history and audits.
func (p *DBKeyProvider) GetAllForPurpose(ctx context.Context, purpose, connectorID string) ([]Key, error) {
	if !IsKnownPurpose(purpose) {
		return nil, ErrInvalidPurpose
	}
	ns := p.namespaceFor(purpose, connectorID)

	rows, err := p.db.QueryContext(ctx, `
		SELECT key_id, ciphertext, provisioned, expires_at
		FROM keyring_keys
		WHERE namespace = $1 AND purpose = $2
		ORDER BY provisioned DESC
	`, ns, purpose)
	if err != nil {
		return nil, fmt.Errorf("dbprovider: get all %s: %w", purpose, err)
	}
	defer rows.Close()

	var keys []Key
	for rows.Next() {
		var keyID string
		var ciphertext []byte
		var provisioned time.Time
		var expiresAt sql.NullTime
		if err := rows.Scan(&keyID, &ciphertext, &provisioned, &expiresAt); err != nil {
			return nil, err
		}
		plaintext, err := p.envelope.Open(ctx, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("dbprovider: decrypt %s/%s: %w", purpose, keyID, err)
		}
		var exp time.Time
		if expiresAt.Valid {
			exp = expiresAt.Time
		}
		keys = append(keys, Key{
			ID:           keyID,
			Purpose:      purpose,
			Provider:     p.Source(),
			Provisioned:  provisioned,
			ExpiresAt:    exp,
			Secret:       plaintext,
			MaterialKind: materialKind(purpose),
		})
	}
	return keys, rows.Err()
}

// MissingPurposes implements the same check as Keyring.MissingPurposes
// but for the DB provider. Returns purposes without provisioned
// material in the default namespace.
func (p *DBKeyProvider) MissingPurposes(ctx context.Context) []string {
	var missing []string
	for _, purpose := range KnownPurposes() {
		ns := p.namespaceFor(purpose, "")
		var count int
		err := p.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM keyring_keys WHERE namespace = $1 AND purpose = $2
		`, ns, purpose).Scan(&count)
		if err != nil || count == 0 {
			missing = append(missing, purpose)
		}
	}
	return missing
}

// Expiries returns each known purpose's key expiry as a closed-set map
// (zero time = no expiry configured or unprovisioned).
func (p *DBKeyProvider) Expiries(ctx context.Context) map[string]time.Time {
	out := make(map[string]time.Time, len(KnownPurposes()))
	for _, purpose := range KnownPurposes() {
		key, err := p.Get(ctx, purpose)
		if err == nil {
			out[purpose] = key.ExpiresAt
		} else {
			out[purpose] = time.Time{}
		}
	}
	return out
}

// GetForConnector returns the current key for a connector purpose
// scoped to a specific tenant and connector ID. The namespace is
// strictly "tenants/<tenantID>/connectors/<connectorID>". Returns
// ErrSecretNotFound if no secret exists for that tenant/connector.
func (p *DBKeyProvider) GetForConnector(ctx context.Context, tenantID, purpose, connectorID string) (Key, error) {
	if !IsKnownPurpose(purpose) {
		return Key{}, ErrInvalidPurpose
	}
	if purpose != PurposeConnector {
		return Key{}, fmt.Errorf("dbprovider: GetForConnector only supports connector purpose, got %s", purpose)
	}
	if tenantID == "" {
		return Key{}, errors.New("dbprovider: tenantID required for connector resolution")
	}
	if connectorID == "" {
		return Key{}, errors.New("dbprovider: connectorID required for connector resolution")
	}

	ns := "tenants/" + tenantID + "/connectors/" + connectorID

	var ciphertext []byte
	var keyID string
	var expiresAt sql.NullTime
	err := p.db.QueryRowContext(ctx, `
		SELECT ciphertext, key_id, expires_at
		FROM keyring_keys
		WHERE namespace = $1 AND purpose = $2
		ORDER BY provisioned DESC
		LIMIT 1
	`, ns, purpose).Scan(&ciphertext, &keyID, &expiresAt)
	if err == sql.ErrNoRows {
		return Key{}, fmt.Errorf("%w: tenant %s connector %s (namespace %s)", ErrSecretNotFound, tenantID, connectorID, ns)
	}
	if err != nil {
		return Key{}, fmt.Errorf("dbprovider: get connector %s/%s: %w", tenantID, connectorID, err)
	}

	plaintext, err := p.envelope.Open(ctx, ciphertext)
	if err != nil {
		return Key{}, fmt.Errorf("dbprovider: decrypt connector %s/%s: %w", tenantID, connectorID, err)
	}

	var exp time.Time
	if expiresAt.Valid {
		exp = expiresAt.Time
	}
	return Key{
		ID:           keyID,
		Purpose:      purpose,
		Provider:     p.Source(),
		Provisioned:  time.Now().UTC(),
		ExpiresAt:    exp,
		Secret:       plaintext,
		MaterialKind: materialKind(purpose),
	}, nil
}

// ExpiryForConnector returns the expiry for a connector key scoped
// to a specific tenant and connector ID. Returns zero time and
// ErrSecretNotFound if no secret exists.
func (p *DBKeyProvider) ExpiryForConnector(ctx context.Context, tenantID, purpose, connectorID string) (time.Time, error) {
	if !IsKnownPurpose(purpose) {
		return time.Time{}, ErrInvalidPurpose
	}
	if purpose != PurposeConnector {
		return time.Time{}, fmt.Errorf("dbprovider: ExpiryForConnector only supports connector purpose, got %s", purpose)
	}
	if tenantID == "" {
		return time.Time{}, errors.New("dbprovider: tenantID required for connector resolution")
	}
	if connectorID == "" {
		return time.Time{}, errors.New("dbprovider: connectorID required for connector resolution")
	}

	ns := "tenants/" + tenantID + "/connectors/" + connectorID

	var expiresAt sql.NullTime
	err := p.db.QueryRowContext(ctx, `
		SELECT expires_at
		FROM keyring_keys
		WHERE namespace = $1 AND purpose = $2
		ORDER BY provisioned DESC
		LIMIT 1
	`, ns, purpose).Scan(&expiresAt)
	if err == sql.ErrNoRows {
		return time.Time{}, fmt.Errorf("%w: tenant %s connector %s (namespace %s)", ErrSecretNotFound, tenantID, connectorID, ns)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("dbprovider: expiry connector %s/%s: %w", tenantID, connectorID, err)
	}

	if expiresAt.Valid {
		return expiresAt.Time, nil
	}
	return time.Time{}, nil
}
