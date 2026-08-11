// Phase 8.3 WORM archive: write-once sealing, content addressing,
// tamper-evident per-tenant manifest chains, and fail-closed
// verification (payload edits, manifest edits, deletions, and
// reordering are all detected). Sealing is idempotent; tenants are
// isolated; there is no delete or update path on the interface.

package archive

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) *FileWORMStore {
	t.Helper()
	return NewFileWORMStore(t.TempDir())
}

func seal(t *testing.T, s *FileWORMStore, tenantID, kind string, payload []byte, meta map[string]string) Artifact {
	t.Helper()
	a, err := s.Seal(context.Background(), tenantID, kind, payload, meta)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return a
}

func TestSealCreatesChainedManifestAndIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a0 := seal(t, s, "acme", "audit_export", []byte("export-v1"), map[string]string{"framework": "soc2"})
	a1 := seal(t, s, "acme", "audit_export", []byte("export-v2"), map[string]string{"framework": "soc2"})

	if a0.ChainIndex != 0 || a1.ChainIndex != 1 {
		t.Fatalf("chain indexes = %d, %d; want 0, 1", a0.ChainIndex, a1.ChainIndex)
	}
	if a0.PrevDigest != "" {
		t.Fatalf("first row prev_digest = %q, want empty", a0.PrevDigest)
	}
	if a1.PrevDigest != a0.ChainDigest {
		t.Fatal("second row must link to the first row's chain digest")
	}
	if a0.ChainDigest == a1.ChainDigest {
		t.Fatal("rows must have distinct chain digests")
	}

	// Idempotent: sealing the same payload + kind + meta returns the
	// original artifact and does not grow the manifest.
	again, err := s.Seal(ctx, "acme", "audit_export", []byte("export-v1"), map[string]string{"framework": "soc2"})
	if err != nil {
		t.Fatalf("re-Seal: %v", err)
	}
	if again.ID != a0.ID || again.ChainIndex != 0 {
		t.Fatalf("re-seal returned %+v, want the original %+v", again, a0)
	}
	rows, err := s.List(ctx, "acme")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("manifest grew: want 2 rows, got %d", len(rows))
	}

	// Different metadata seals a distinct artifact even for the same
	// payload (different retention context is a different object).
	diff := seal(t, s, "acme", "audit_export", []byte("export-v1"), map[string]string{"framework": "iso27001"})
	if diff.ID == a0.ID {
		t.Fatal("different meta must yield a different artifact id")
	}
}

func TestSealContentAddressesDifferentPayloads(t *testing.T) {
	s := newTestStore(t)
	a0 := seal(t, s, "acme", "audit_export", []byte("one"), nil)
	a1 := seal(t, s, "acme", "audit_export", []byte("two"), nil)
	if a0.ID == a1.ID {
		t.Fatal("different payloads must never share an id")
	}
}

func TestVerifyPassesIntactChain(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		seal(t, s, "acme", "evidence_report", []byte("report-"+string(rune('a'+i))), nil)
	}
	rows, err := s.List(ctx, "acme")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := s.Verify(ctx, "acme", rows[2].ID); err != nil {
		t.Fatalf("Verify intact chain: %v", err)
	}
}

func TestTamperedPayloadFailsVerifyAndOpen(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a := seal(t, s, "acme", "audit_export", []byte("original-export"), nil)

	blob, err := s.blobPath("acme", a.ID)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(blob)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	content[0] ^= 0xff
	if err := os.WriteFile(blob, content, 0o600); err != nil {
		t.Fatalf("tamper blob: %v", err)
	}

	if _, err := s.Verify(ctx, "acme", a.ID); err == nil || !strings.Contains(err.Error(), ErrArchiveIntegrity.Error()) {
		t.Fatalf("Verify must fail closed on a tampered payload, got %v", err)
	}
	if _, _, err := s.Open(ctx, "acme", a.ID); err == nil || !strings.Contains(err.Error(), ErrArchiveIntegrity.Error()) {
		t.Fatalf("Open must never return tampered content, got %v", err)
	}
}

func TestTamperedManifestFailsVerify(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a0 := seal(t, s, "acme", "audit_export", []byte("v1"), nil)
	seal(t, s, "acme", "audit_export", []byte("v2"), nil)

	// Edit a manifest row's chain digest, as an attacker editing the
	// ledger would.
	manifest, err := s.manifestPath("acme")
	if err != nil {
		t.Fatal(err)
	}
	lines, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	edited := strings.Replace(string(lines), a0.ChainDigest, strings.Repeat("0", len(a0.ChainDigest)), 1)
	if edited == string(lines) {
		t.Fatal("test setup: manifest edit had no effect")
	}
	if err := os.WriteFile(manifest, []byte(edited), 0o600); err != nil {
		t.Fatalf("tamper manifest: %v", err)
	}

	if _, err := s.Verify(ctx, "acme", a0.ID); err == nil || !strings.Contains(err.Error(), ErrArchiveIntegrity.Error()) {
		t.Fatalf("Verify must detect a manifest edit, got %v", err)
	}
}

func TestManifestRowReorderFailsVerify(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seal(t, s, "acme", "audit_export", []byte("first"), nil)
	a1 := seal(t, s, "acme", "audit_export", []byte("second"), nil)

	manifest, err := s.manifestPath("acme")
	if err != nil {
		t.Fatal(err)
	}
	lines, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	parts := strings.Split(strings.TrimSpace(string(lines)), "\n")
	if len(parts) != 2 {
		t.Fatalf("want 2 manifest rows, got %d", len(parts))
	}
	if err := os.WriteFile(manifest, []byte(parts[1]+"\n"+parts[0]+"\n"), 0o600); err != nil {
		t.Fatalf("reorder manifest: %v", err)
	}

	if _, err := s.Verify(ctx, "acme", a1.ID); err == nil || !strings.Contains(err.Error(), ErrArchiveIntegrity.Error()) {
		t.Fatalf("Verify must detect a reordered manifest, got %v", err)
	}
}

func TestDeletedArtifactFailsVerifyAndOpen(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a := seal(t, s, "acme", "audit_export", []byte("gone-soon"), nil)

	blob, err := s.blobPath("acme", a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(blob); err != nil {
		t.Fatalf("remove blob: %v", err)
	}
	if _, err := s.Verify(ctx, "acme", a.ID); err == nil || !strings.Contains(err.Error(), ErrArchiveIntegrity.Error()) {
		t.Fatalf("Verify must detect a deleted artifact, got %v", err)
	}
	if _, _, err := s.Open(ctx, "acme", a.ID); err == nil || !strings.Contains(err.Error(), ErrArchiveIntegrity.Error()) {
		t.Fatalf("Open must fail closed on a deleted artifact, got %v", err)
	}
}

func TestCrossTenantIsolation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a := seal(t, s, "acme", "audit_export", []byte("secret-export"), nil)

	rows, err := s.List(ctx, "otherco")
	if err != nil {
		t.Fatalf("List other tenant: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("other tenant sees %d artifacts", len(rows))
	}
	if _, _, err := s.Open(ctx, "otherco", a.ID); err == nil || !strings.Contains(err.Error(), ErrArtifactNotFound.Error()) {
		t.Fatalf("other tenant must not open acme artifacts, got %v", err)
	}
	// Same payload under another tenant is a distinct artifact.
	b := seal(t, s, "otherco", "audit_export", []byte("secret-export"), nil)
	if b.ID == a.ID {
		t.Fatal("artifact ids must be tenant-scoped")
	}
	if payload, row, err := s.Open(ctx, "acme", a.ID); err != nil || !bytes.Equal(payload, []byte("secret-export")) || row.ID != a.ID {
		t.Fatalf("acme artifact must remain intact: %v", err)
	}
}

func TestRestoreRoundtrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	payload := []byte("soc2-export-with-evidence-chain-digests")
	a := seal(t, s, "acme", "audit_export", payload, map[string]string{"framework": "soc2", "source_chain_digest": "abc123"})

	got, row, err := s.Open(ctx, "acme", a.ID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("restored payload differs from the sealed payload")
	}
	if row.Kind != "audit_export" || row.Meta["framework"] != "soc2" || row.Meta["source_chain_digest"] != "abc123" {
		t.Fatalf("artifact metadata = %+v", row)
	}
}

func TestInvalidTenantRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, bad := range []string{"", "a/b", "..", "..\\escape", "has space", "a:b"} {
		if _, err := s.Seal(ctx, bad, "audit_export", []byte("x"), nil); err == nil {
			t.Fatalf("Seal with tenant %q must be rejected", bad)
		}
	}
}

func TestVerifyValidatesWholePrefix(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a0 := seal(t, s, "acme", "audit_export", []byte("early"), nil)
	a1 := seal(t, s, "acme", "audit_export", []byte("late"), nil)

	// Corrupt the FIRST artifact's blob: verifying the SECOND must still
	// fail — the prefix chain is validated all the way back.
	blob, err := s.blobPath("acme", a0.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blob, []byte("tampered"), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := s.Verify(ctx, "acme", a1.ID); err == nil || !strings.Contains(err.Error(), ErrArchiveIntegrity.Error()) {
		t.Fatalf("Verify must check the whole prefix, got %v", err)
	}
}

func TestManifestMissingIsEmpty(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	rows, err := s.List(ctx, "acme")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("want empty list, got %d", len(rows))
	}
}

func TestFileLayout(t *testing.T) {
	s := newTestStore(t)
	a := seal(t, s, "acme", "audit_export", []byte("layout"), nil)
	if _, err := os.Stat(filepath.Join(s.root, "acme", "artifacts", a.ID+".blob")); err != nil {
		t.Fatalf("blob not at the documented layout: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.root, "acme", "manifest")); err != nil {
		t.Fatalf("manifest not at the documented layout: %v", err)
	}
}
