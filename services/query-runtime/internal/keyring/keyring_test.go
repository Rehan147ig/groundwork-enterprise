package keyring

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func withEnv(t *testing.T, pairs map[string]string) {
	t.Helper()
	restore := map[string]string{}
	for k, v := range pairs {
		restore[k] = os.Getenv(k)
		if v == "" {
			_ = os.Unsetenv(k)
		} else {
			_ = os.Setenv(k, v)
		}
	}
	t.Cleanup(func() {
		for k, v := range restore {
			if v == "" {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, v)
			}
		}
	})
}

func TestEnvProviderGet(t *testing.T) {
	withEnv(t, map[string]string{
		"GROUNDWORK_JWT_HS_SECRET":             "jwt-secret",
		"GROUNDWORK_DELEGATION_RS_PRIVATE_KEY": "rsa-pem",
		"GROUNDWORK_OUTBOX_WEBHOOK_SECRET":     "hook-secret",
		"GROUNDWORK_AUDIT_DIGEST_KEY":          "digest-secret",
		"GROUNDWORK_DATABASE_KEY_ID":           "arn:aws:kms:eu-west-1:1:key/xyz",
		"GROUNDWORK_BACKUP_KEY_ID":             "projects/p/keys/123",
	})
	p := NewEnvProvider()
	ctx := context.Background()
	k, err := p.Get(ctx, PurposeWebhook)
	if err != nil {
		t.Fatalf("webhook: %v", err)
	}
	if k.ID == "" || k.Provider != "env" || string(k.Secret) != "hook-secret" {
		t.Errorf("webhook key = %+v", k)
	}
	if kdb, err := p.Get(ctx, PurposeDatabase); err != nil || kdb.MaterialKind != "key_id_reference" {
		t.Errorf("database key: %+v, %v", kdb, err)
	}
}

func TestEnvProviderMissingFailsClosed(t *testing.T) {
	withEnv(t, map[string]string{})
	p := NewEnvProvider()
	for _, purpose := range KnownPurposes() {
		if _, err := p.Get(context.Background(), purpose); !errors.Is(err, ErrKeyMissing) {
			t.Errorf("%s: want ErrKeyMissing, got %v", purpose, err)
		}
	}
}

func TestEnvProviderOIDCOrJWTSatisfiesIdentity(t *testing.T) {
	withEnv(t, map[string]string{"GROUNDWORK_OIDC_ISSUER": "https://issuer.example"})
	p := NewEnvProvider()
	if _, err := p.Get(context.Background(), PurposeIdentity); err != nil {
		t.Errorf("OIDC issuer must satisfy identity purpose: %v", err)
	}
}

func TestEnvProviderUnknownPurpose(t *testing.T) {
	p := NewEnvProvider()
	if _, err := p.Get(context.Background(), "banana"); !errors.Is(err, ErrInvalidPurpose) {
		t.Errorf("want ErrInvalidPurpose, got %v", err)
	}
}

func TestEnvProviderHistoricalOnlyCurrent(t *testing.T) {
	withEnv(t, map[string]string{"GROUNDWORK_OUTBOX_WEBHOOK_SECRET": "hook-secret"})
	p := NewEnvProvider()
	ctx := context.Background()
	cur, err := p.Get(ctx, PurposeWebhook)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	hist, err := p.GetForVerification(ctx, PurposeWebhook, cur.ID)
	if err != nil || string(hist.Secret) != "hook-secret" {
		t.Errorf("current key must verify: %+v, %v", hist, err)
	}
	if _, err := p.GetForVerification(ctx, PurposeWebhook, "unknown-key-id"); !errors.Is(err, ErrKeyUnknown) {
		t.Errorf("unknown historical key must fail closed: %v", err)
	}
}

func TestEnvProviderRotationUnsupported(t *testing.T) {
	withEnv(t, map[string]string{"GROUNDWORK_OUTBOX_WEBHOOK_SECRET": "hook-secret"})
	p := NewEnvProvider()
	if _, err := p.Rotate(context.Background(), PurposeWebhook); !errors.Is(err, ErrRotationUnsupported) {
		t.Errorf("env provider must refuse rotation: %v", err)
	}
}

func TestKeyringMissingPurposes(t *testing.T) {
	withEnv(t, map[string]string{"GROUNDWORK_OUTBOX_WEBHOOK_SECRET": "hook-secret"})
	ring := New(NewEnvProvider())
	missing := ring.MissingPurposes(context.Background())
	if len(missing) != len(KnownPurposes())-1 {
		t.Errorf("want %d missing, got %v", len(KnownPurposes())-1, missing)
	}
	for _, purpose := range missing {
		if purpose == PurposeWebhook {
			t.Errorf("webhook is provisioned; must not be missing")
		}
	}
}

func TestKeyringRotationLedger(t *testing.T) {
	var current = "v1"
	provider := &ExternalProvider{
		SourceName: "test-kms",
		GetFn: func(_ context.Context, _ string) (Key, error) {
			return Key{ID: current, Purpose: PurposeWebhook, Provider: "test-kms"}, nil
		},
		RotateFn: func(_ context.Context, _ string) (Key, error) {
			current = "v2"
			return Key{ID: "v2", Purpose: PurposeWebhook, Provider: "test-kms"}, nil
		},
	}
	ring := New(provider)
	ctx := context.Background()
	if _, err := ring.Rotate(ctx, PurposeWebhook); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	rotations := ring.Rotations()
	if len(rotations) != 1 {
		t.Fatalf("want 1 rotation, got %d", len(rotations))
	}
	if rotations[0].FromKeyID != "v1" || rotations[0].ToKeyID != "v2" || rotations[0].Provider != "test-kms" {
		t.Errorf("rotation = %+v", rotations[0])
	}
}

func TestExternalProviderFailClosedWithoutAdapter(t *testing.T) {
	provider := &ExternalProvider{SourceName: "hyok"}
	if _, err := provider.Get(context.Background(), PurposeWebhook); !errors.Is(err, ErrProviderNotConfigured) {
		t.Errorf("unconfigured external provider must fail closed: %v", err)
	}
	if _, err := provider.GetForVerification(context.Background(), PurposeWebhook, "k1"); !errors.Is(err, ErrKeyUnknown) {
		t.Errorf("unconfigured history must fail closed: %v", err)
	}
	if _, err := provider.Rotate(context.Background(), PurposeWebhook); !errors.Is(err, ErrRotationUnsupported) {
		t.Errorf("unconfigured rotation must fail closed: %v", err)
	}
}

func TestKnownPurposesClosedSet(t *testing.T) {
	purposes := KnownPurposes()
	for i, p := range purposes {
		if !IsKnownPurpose(p) {
			t.Errorf("IsKnownPurpose(%q) must be true", p)
		}
		if i > 0 && strings.Compare(purposes[i-1], p) >= 0 {
			t.Errorf("purposes must be strictly ascending")
		}
	}
	if IsKnownPurpose("anything-else") {
		t.Error("open set: arbitrary purposes must be rejected")
	}
}

func TestEnvProviderKeyExpiry(t *testing.T) {
	withEnv(t, map[string]string{
		"GROUNDWORK_OUTBOX_WEBHOOK_SECRET": "hook-secret",
		"GROUNDWORK_WEBHOOK_KEY_EXPIRY":    "2027-01-01T00:00:00Z",
	})
	p := NewEnvProvider()
	k, err := p.Get(context.Background(), PurposeWebhook)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	want := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if !k.ExpiresAt.Equal(want) {
		t.Fatalf("expiry = %v, want %v", k.ExpiresAt, want)
	}
}

func TestEnvProviderKeyExpiryUnsetMeansNoExpiry(t *testing.T) {
	withEnv(t, map[string]string{"GROUNDWORK_OUTBOX_WEBHOOK_SECRET": "hook-secret"})
	p := NewEnvProvider()
	k, err := p.Get(context.Background(), PurposeWebhook)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !k.ExpiresAt.IsZero() {
		t.Fatalf("no expiry env must leave ExpiresAt zero, got %v", k.ExpiresAt)
	}
}

func TestEnvProviderKeyExpiryGarbageIgnored(t *testing.T) {
	withEnv(t, map[string]string{
		"GROUNDWORK_OUTBOX_WEBHOOK_SECRET": "hook-secret",
		"GROUNDWORK_WEBHOOK_KEY_EXPIRY":    "not-a-date",
	})
	p := NewEnvProvider()
	k, err := p.Get(context.Background(), PurposeWebhook)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !k.ExpiresAt.IsZero() {
		t.Fatalf("unparseable expiry must be ignored, got %v", k.ExpiresAt)
	}
}

func TestKeyringExpiries(t *testing.T) {
	expiry := time.Date(2027, 6, 30, 23, 59, 59, 0, time.UTC)
	provider := &ExternalProvider{
		SourceName: "test-kms",
		GetFn: func(_ context.Context, purpose string) (Key, error) {
			switch purpose {
			case PurposeWebhook:
				return Key{ID: "wh", Purpose: PurposeWebhook, ExpiresAt: expiry}, nil
			case PurposeIdentity:
				return Key{ID: "id", Purpose: PurposeIdentity}, nil
			default:
				return Key{}, fmt.Errorf("unprovisioned")
			}
		},
	}
	ring := New(provider)
	expiries := ring.Expiries(context.Background())
	if len(expiries) != 2 {
		t.Fatalf("want one entry per provisioned purpose, got %d", len(expiries))
	}
	if !expiries[PurposeWebhook].Equal(expiry) {
		t.Errorf("webhook expiry = %v, want %v", expiries[PurposeWebhook], expiry)
	}
	if !expiries[PurposeIdentity].IsZero() {
		t.Errorf("identity (no expiry) must be zero, got %v", expiries[PurposeIdentity])
	}
	if !expiries[PurposeDelegation].IsZero() {
		t.Errorf("unprovisioned purpose must be zero, got %v", expiries[PurposeDelegation])
	}
}
