package cryptosvc

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func otherKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(255 - i)
	}
	return key
}

func TestEnvelopeRoundTrip(t *testing.T) {
	ctx := context.Background()
	env := NewEnvelope(StaticKEK{Key: testKey()}, "static")
	plaintext := []byte("finance security policy — restricted")
	blob, err := env.Seal(ctx, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(blob, plaintext) {
		t.Fatal("ciphertext must not contain plaintext bytes")
	}
	got, err := env.Open(ctx, blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

func TestEnvelopeFieldRoundTrip(t *testing.T) {
	ctx := context.Background()
	env := NewEnvelope(StaticKEK{Key: testKey()}, "static")
	sealed, err := env.EncryptField(ctx, "exec-comp@2026")
	if err != nil {
		t.Fatalf("EncryptField: %v", err)
	}
	if sealed == "exec-comp@2026" {
		t.Fatal("field must not be stored in plaintext")
	}
	got, err := env.DecryptField(ctx, sealed)
	if err != nil {
		t.Fatalf("DecryptField: %v", err)
	}
	if got != "exec-comp@2026" {
		t.Fatalf("field round trip mismatch: got %q", got)
	}
}

func TestEnvelopeWrongKEKFailsClosed(t *testing.T) {
	ctx := context.Background()
	blob, err := NewEnvelope(StaticKEK{Key: testKey()}, "a").Seal(ctx, []byte("classified"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEnvelope(StaticKEK{Key: otherKey()}, "b").Open(ctx, blob); !errors.Is(err, ErrCiphertextInvalid) {
		t.Fatalf("wrong KEK must fail closed with ErrCiphertextInvalid, got %v", err)
	}
}

func TestEnvelopeTamperedFailsClosed(t *testing.T) {
	ctx := context.Background()
	env := NewEnvelope(StaticKEK{Key: testKey()}, "static")
	blob, err := env.Seal(ctx, []byte("classified"))
	if err != nil {
		t.Fatal(err)
	}
	for _, flipAt := range []int{0, 8, len(blob) - 1, len(blob) / 2} {
		tampered := append([]byte(nil), blob...)
		tampered[flipAt] ^= 0xff
		if _, err := env.Open(ctx, tampered); !errors.Is(err, ErrCiphertextInvalid) {
			t.Fatalf("tampered byte %d must fail closed, got %v", flipAt, err)
		}
	}
	// Truncation and garbage magic also fail closed.
	if _, err := env.Open(ctx, blob[:len(blob)-5]); !errors.Is(err, ErrCiphertextInvalid) {
		t.Fatalf("truncated blob must fail closed, got %v", err)
	}
	if _, err := env.Open(ctx, []byte("garbage")); !errors.Is(err, ErrCiphertextInvalid) {
		t.Fatalf("garbage blob must fail closed, got %v", err)
	}
}

func TestEnvelopeNilResolverFailsClosed(t *testing.T) {
	env := NewEnvelope(nil, "whatever")
	if _, err := env.Seal(context.Background(), []byte("x")); !errors.Is(err, ErrKEKUnavailable) {
		t.Fatalf("nil resolver must fail closed with ErrKEKUnavailable, got %v", err)
	}
}

func TestStaticKEKRejectsBadLength(t *testing.T) {
	if _, err := (StaticKEK{Key: []byte("short")}).ResolveKEK(context.Background(), ""); !errors.Is(err, ErrKEKUnavailable) {
		t.Fatalf("short static key must be rejected, got %v", err)
	}
}

func TestEnvKEKResolves(t *testing.T) {
	t.Setenv("GW_TEST_KEK", "0123456789abcdef0123456789abcdef")
	ctx := context.Background()
	key, err := EnvKEK{}.ResolveKEK(ctx, "env://GW_TEST_KEK")
	if err != nil {
		t.Fatalf("ResolveKEK: %v", err)
	}
	if string(key) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("got key %x", key)
	}
	// Shorter passphrases are derived to 32 bytes.
	t.Setenv("GW_TEST_PASSPHRASE", "hunter2")
	key, err = EnvKEK{}.ResolveKEK(ctx, "env://GW_TEST_PASSPHRASE")
	if err != nil || len(key) != 32 {
		t.Fatalf("derived key: len=%d err=%v", len(key), err)
	}
	// Missing variable and unknown scheme fail closed.
	if _, err := (EnvKEK{}).ResolveKEK(ctx, "env://GW_TEST_MISSING_VAR"); !errors.Is(err, ErrKEKUnavailable) {
		t.Fatalf("missing var must fail closed, got %v", err)
	}
	if _, err := (EnvKEK{}).ResolveKEK(ctx, "file://whatever"); !errors.Is(err, ErrKEKUnavailable) {
		t.Fatalf("non-env ref must fail closed, got %v", err)
	}
}

func TestFileKEKResolves(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	exact := filepath.Join(dir, "kek.bin")
	if err := os.WriteFile(exact, testKey(), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := (FileKEK{}).ResolveKEK(ctx, "file://"+exact)
	if err != nil {
		t.Fatalf("ResolveKEK: %v", err)
	}
	if !bytes.Equal(key, testKey()) {
		t.Fatal("file key mismatch")
	}
	missing := filepath.Join(dir, "nope.bin")
	if _, err := (FileKEK{}).ResolveKEK(ctx, "file://"+missing); !errors.Is(err, ErrKEKUnavailable) {
		t.Fatalf("missing file must fail closed, got %v", err)
	}
}

func TestResolverChainFallsThrough(t *testing.T) {
	ctx := context.Background()
	t.Setenv("GW_TEST_CHAIN_KEK", "0123456789abcdef0123456789abcdef")

	// env:// is owned by EnvKEK; FileKEK must not claim it, and the
	// chain must return the env key.
	chain := ResolverChain{FileKEK{}, EnvKEK{}}
	key, err := chain.ResolveKEK(ctx, "env://GW_TEST_CHAIN_KEK")
	if err != nil {
		t.Fatalf("chain should fall through to EnvKEK, got %v", err)
	}
	if string(key) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("got key %x", key)
	}

	// No resolver owns the scheme: fail closed.
	if _, err := (ResolverChain{FileKEK{}}).ResolveKEK(ctx, "vault://secret/x"); !errors.Is(err, ErrKEKUnavailable) {
		t.Fatalf("unowned scheme must fail closed, got %v", err)
	}

	// Empty chain fails closed.
	if _, err := (ResolverChain{}).ResolveKEK(ctx, "env://GW_TEST_CHAIN_KEK"); !errors.Is(err, ErrKEKUnavailable) {
		t.Fatalf("empty chain must fail closed, got %v", err)
	}
}
