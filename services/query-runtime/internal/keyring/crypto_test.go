package keyring

import (
	"bytes"
	"context"
	"testing"
)

// envKeyring builds a Keyring whose connector purpose resolves from the
// given env lookup (used to avoid touching the real environment).
func envKeyring(t *testing.T, secret string) *Keyring {
	t.Helper()
	lookup := func(string) string { return secret }
	p := &EnvProvider{lookup: lookup}
	return New(p)
}

func TestConnectorMetadataEncryptDecryptRoundTrip(t *testing.T) {
	ctx := context.Background()
	k := envKeyring(t, "super-secret-connector-key-material-1")
	aad := "tenant_id=t1:provider=msgraph:field=credential"
	plain := []byte(`{"client_secret":"s3cr3t","tenant_id":"t1"}`)

	sealed, err := EncryptConnectorMetadata(ctx, k, aad, plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("ciphertext must not contain plaintext")
	}
	if len(sealed) != len(plain)+28 { // 12-byte nonce + 16-byte GCM tag
		t.Fatalf("unexpected ciphertext length %d (want %d)", len(sealed), len(plain)+28)
	}

	got, err := DecryptConnectorMetadata(ctx, k, aad, sealed)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestConnectorMetadataFailsClosedOnTamper(t *testing.T) {
	ctx := context.Background()
	k := envKeyring(t, "super-secret-connector-key-material-2")

	sealed, err := EncryptConnectorMetadata(ctx, k, "aad-1", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	// Flip one byte inside the sealed region (not the nonce) -> tag fails.
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := DecryptConnectorMetadata(ctx, k, "aad-1", tampered); err != ErrCiphertextTampered {
		t.Fatalf("tampered ciphertext: got %v, want ErrCiphertextTampered", err)
	}

	// Wrong AAD -> tag fails.
	if _, err := DecryptConnectorMetadata(ctx, k, "aad-2", sealed); err != ErrCiphertextTampered {
		t.Fatalf("wrong aad: got %v, want ErrCiphertextTampered", err)
	}

	// Wrong key -> tag fails.
	other := envKeyring(t, "different-connector-key-material-9")
	if _, err := DecryptConnectorMetadata(ctx, other, "aad-1", sealed); err != ErrCiphertextTampered {
		t.Fatalf("wrong key: got %v, want ErrCiphertextTampered", err)
	}

	// Truncated ciphertext -> ErrCiphertextTooShort.
	if _, err := DecryptConnectorMetadata(ctx, k, "aad-1", []byte("short")); err != ErrCiphertextTooShort {
		t.Fatalf("truncated: got %v, want ErrCiphertextTooShort", err)
	}
}

func TestConnectorMetadataFailsClosedOnMissingKey(t *testing.T) {
	ctx := context.Background()
	k := envKeyring(t, "") // connector purpose key missing
	if _, err := EncryptConnectorMetadata(ctx, k, "aad", []byte("x")); err == nil {
		t.Fatal("encrypt must fail when the connector key is missing")
	}
	if _, err := DecryptConnectorMetadata(ctx, k, "aad", []byte("x")); err == nil {
		t.Fatal("decrypt must fail when the connector key is missing")
	}
}

func TestConnectorPurposeRegistered(t *testing.T) {
	if !IsKnownPurpose(PurposeConnector) {
		t.Fatal("connector purpose must be in the known purpose set")
	}
	found := false
	for _, p := range KnownPurposes() {
		if p == PurposeConnector {
			found = true
		}
	}
	if !found {
		t.Fatal("connector purpose missing from KnownPurposes")
	}
}
