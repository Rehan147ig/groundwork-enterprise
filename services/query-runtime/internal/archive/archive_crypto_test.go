package archive

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"groundwork/query-runtime/internal/cryptosvc"
)

// TestSealedArtifactEncryptsAtRest proves the archive + envelope
// integration: a payload sealed through the Envelope is stored in the
// WORM store in ciphertext (plaintext never hits disk), and the
// restored bytes decrypt back to the original — with the integrity
// chain still validating.
func TestSealedArtifactEncryptsAtRest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	env := cryptosvc.NewEnvelope(cryptosvc.StaticKEK{Key: key}, "static")

	plaintext := []byte("soc2-evidence-export-restricted")
	blob, err := env.Seal(ctx, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	a := seal(t, s, "acme", "audit_export", blob, map[string]string{"encrypted": "gwenc1"})

	// The plaintext must never appear on disk.
	raw, err := s.blobPath("acme", a.ID)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(raw)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if bytes.Contains(content, plaintext) {
		t.Fatal("plaintext must not be stored at rest")
	}

	// Integrity chain still verifies.
	if _, err := s.Verify(ctx, "acme", a.ID); err != nil {
		t.Fatalf("Verify encrypted artifact: %v", err)
	}

	// Restore: open + decrypt yields the original payload.
	stored, row, err := s.Open(ctx, "acme", a.ID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(stored, blob) {
		t.Fatal("stored ciphertext differs from the sealed envelope")
	}
	restored, err := env.Open(ctx, stored)
	if err != nil {
		t.Fatalf("decrypt restored blob: %v", err)
	}
	if !bytes.Equal(restored, plaintext) {
		t.Fatal("restored plaintext differs from the original")
	}
	if row.Kind != "audit_export" {
		t.Fatalf("row kind = %q", row.Kind)
	}

	// Wrong KEK must fail closed at restore time.
	wrongEnv := cryptosvc.NewEnvelope(cryptosvc.StaticKEK{Key: make([]byte, 32)}, "wrong")
	if _, err := wrongEnv.Open(ctx, stored); !errors.Is(err, cryptosvc.ErrCiphertextInvalid) {
		t.Fatalf("wrong KEK must fail closed, got %v", err)
	}
}
