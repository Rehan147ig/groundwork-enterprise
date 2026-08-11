package archive

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FileWORMStore is a filesystem-backed WORM store. Layout:
//
//	<root>/<tenant_id>/manifest            append-only JSONL ledger
//	<root>/<tenant_id>/artifacts/<id>.blob sealed payload (write-once)
//
// Sealing creates the blob with O_EXCL (never overwrites) and then
// appends the chained manifest row; both are fsynced before returning.
// The store exposes no delete or update path, so once a row exists the
// only way to change the archive is to violate it — which Verify
// detects. Object-storage equivalents (S3 object-lock, Azure immutable
// blobs) can implement the same interface.
type FileWORMStore struct {
	root string
	mu   sync.Mutex
}

var (
	tenantIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	artifactIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// NewFileWORMStore returns a store rooted at root (created if needed).
// The root is absolutized and cleaned at construction, and every path
// built from it is verified to stay inside it — defense in depth for
// the tenant-dir/blob path construction below.
func NewFileWORMStore(root string) (*FileWORMStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("archive root must not be empty")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("archive root %q: %w", root, err)
	}
	return &FileWORMStore{root: filepath.Clean(abs)}, nil
}

// inRoot joins elem onto the store root and fails closed if the result
// escapes it (e.g. via separators or ..), so a path can never walk out
// of the archive even if an input slips past the format regexes.
func (s *FileWORMStore) inRoot(elem ...string) (string, error) {
	parts := make([]string, 0, len(elem)+1)
	parts = append(parts, s.root)
	parts = append(parts, elem...)
	p := filepath.Clean(filepath.Join(parts...))
	if p != s.root && !strings.HasPrefix(p, s.root+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: path escapes archive root", ErrArchiveIntegrity)
	}
	return p, nil
}

// canonicalMeta renders meta deterministically (sorted k=v, joined by &)
// so chain digests are stable across processes.
func canonicalMeta(meta map[string]string) string {
	if len(meta) == 0 {
		return ""
	}
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+meta[k])
	}
	return strings.Join(parts, "&")
}

// artifactID content-addresses the full seal input.
func artifactID(tenantID, kind, canonical string, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(tenantID))
	h.Write([]byte{0})
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(canonical))
	h.Write([]byte{0})
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// chainDigest binds a row to the previous chain state.
func chainDigest(prev, id, kind, size, digest, sealedAt, canonical string) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte("|"))
	h.Write([]byte(id))
	h.Write([]byte("|"))
	h.Write([]byte(kind))
	h.Write([]byte("|"))
	h.Write([]byte(size))
	h.Write([]byte("|"))
	h.Write([]byte(digest))
	h.Write([]byte("|"))
	h.Write([]byte(sealedAt))
	h.Write([]byte("|"))
	h.Write([]byte(canonical))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *FileWORMStore) tenantDir(tenantID string) (string, error) {
	if !tenantIDPattern.MatchString(tenantID) {
		return "", fmt.Errorf("%w: invalid tenant id %q", ErrArchiveIntegrity, tenantID)
	}
	return s.inRoot(tenantID)
}

func (s *FileWORMStore) manifestPath(tenantID string) (string, error) {
	dir, err := s.tenantDir(tenantID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "manifest"), nil
}

// blobPath builds the sealed-payload path. The artifact ID must be
// exactly 64 hex chars (a content-addressed SHA-256), so it can never
// carry separators or traversal segments even if a caller passes an
// unvalidated value.
func (s *FileWORMStore) blobPath(tenantID, artifactID string) (string, error) {
	if !artifactIDPattern.MatchString(artifactID) {
		return "", fmt.Errorf("%w: invalid artifact id %q", ErrArchiveIntegrity, artifactID)
	}
	dir, err := s.tenantDir(tenantID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "artifacts", artifactID+".blob"), nil
}

// readManifest loads the tenant's manifest rows, oldest first. A missing
// manifest is an empty list.
func (s *FileWORMStore) readManifest(tenantID string) ([]Artifact, error) {
	path, err := s.manifestPath(tenantID)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var rows []Artifact
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var a Artifact
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			return nil, fmt.Errorf("%w: corrupt manifest row: %v", ErrArchiveIntegrity, err)
		}
		rows = append(rows, a)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *FileWORMStore) findRow(rows []Artifact, artifactID string) (Artifact, bool) {
	for _, a := range rows {
		if a.ID == artifactID {
			return a, true
		}
	}
	return Artifact{}, false
}

// verifyRows recomputes the chain from row 0 to row limit (inclusive) and
// cross-checks each row against its sealed blob. The first broken row is
// reported; verification fails closed.
func (s *FileWORMStore) verifyRows(tenantID string, rows []Artifact, limit int) (Artifact, error) {
	var prev string
	for i := 0; i <= limit && i < len(rows); i++ {
		row := rows[i]
		if i == 0 && row.ChainIndex != 0 {
			return Artifact{}, fmt.Errorf("%w: first manifest row has chain_index %d", ErrArchiveIntegrity, row.ChainIndex)
		}
		if row.PrevDigest != prev {
			return Artifact{}, fmt.Errorf("%w: row %d breaks prev linkage (chain_index %d)", ErrArchiveIntegrity, i, row.ChainIndex)
		}
		got := chainDigest(prev, row.ID, row.Kind, strconv.FormatInt(row.Size, 10), row.Digest, row.SealedAt, canonicalMeta(row.Meta))
		if got != row.ChainDigest {
			return Artifact{}, fmt.Errorf("%w: row %d chain digest mismatch (chain_index %d)", ErrArchiveIntegrity, i, row.ChainIndex)
		}
		payload, err := s.readBlob(row)
		if err != nil {
			return Artifact{}, err
		}
		if h := hex.EncodeToString(sha256Sum(payload)); h != row.Digest {
			return Artifact{}, fmt.Errorf("%w: artifact %s payload digest mismatch", ErrArchiveIntegrity, row.ID)
		}
		prev = row.ChainDigest
	}
	return rows[limit], nil
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func (s *FileWORMStore) readBlob(row Artifact) ([]byte, error) {
	path, err := s.blobPath(row.TenantID, row.ID)
	if err != nil {
		return nil, err
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: artifact %s is missing from the archive", ErrArchiveIntegrity, row.ID)
		}
		return nil, err
	}
	return payload, nil
}

// Seal implements WORMStore.Seal.
func (s *FileWORMStore) Seal(_ context.Context, tenantID, kind string, payload []byte, meta map[string]string) (Artifact, error) {
	canonical := canonicalMeta(meta)
	id := artifactID(tenantID, kind, canonical, payload)

	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.readManifest(tenantID)
	if err != nil {
		return Artifact{}, err
	}
	if existing, ok := s.findRow(rows, id); ok {
		return existing, nil
	}

	dir, err := s.tenantDir(tenantID)
	if err != nil {
		return Artifact{}, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "artifacts"), 0o700); err != nil {
		return Artifact{}, err
	}

	digest := hex.EncodeToString(sha256Sum(payload))
	sealedAt := time.Now().UTC().Format(time.RFC3339)
	prev := ""
	if len(rows) > 0 {
		prev = rows[len(rows)-1].ChainDigest
	}
	row := Artifact{
		ID:          id,
		TenantID:    tenantID,
		Kind:        kind,
		Size:        int64(len(payload)),
		Digest:      digest,
		Meta:        meta,
		SealedAt:    sealedAt,
		ChainIndex:  len(rows),
		PrevDigest:  prev,
		ChainDigest: chainDigest(prev, id, kind, strconv.Itoa(len(payload)), digest, sealedAt, canonical),
	}

	// Write the blob first with O_EXCL: a sealed artifact can never be
	// overwritten. If the blob already exists (a crashed prior seal),
	// we still only append the manifest row — the payload is already
	// immutable and digest-matched by verify.
	blob, err := s.blobPath(tenantID, id)
	if err != nil {
		return Artifact{}, err
	}
	f, err := os.OpenFile(blob, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if _, werr := f.Write(payload); werr != nil {
			f.Close()
			return Artifact{}, werr
		}
		if werr := f.Sync(); werr != nil {
			f.Close()
			return Artifact{}, werr
		}
		if werr := f.Close(); werr != nil {
			return Artifact{}, werr
		}
	} else if !os.IsExist(err) {
		return Artifact{}, err
	}

	path, err := s.manifestPath(tenantID)
	if err != nil {
		return Artifact{}, err
	}
	mf, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		// The row was never written, so the blob is not a sealed
		// artifact yet; removing our own partial creation is allowed.
		os.Remove(blob)
		return Artifact{}, err
	}
	if err := json.NewEncoder(mf).Encode(row); err != nil {
		mf.Close()
		os.Remove(blob)
		return Artifact{}, err
	}
	if err := mf.Sync(); err != nil {
		mf.Close()
		os.Remove(blob)
		return Artifact{}, err
	}
	if err := mf.Close(); err != nil {
		os.Remove(blob)
		return Artifact{}, err
	}
	return row, nil
}

// Open implements WORMStore.Open.
func (s *FileWORMStore) Open(_ context.Context, tenantID, artifactID string) ([]byte, Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.readManifest(tenantID)
	if err != nil {
		return nil, Artifact{}, err
	}
	row, ok := s.findRow(rows, artifactID)
	if !ok {
		return nil, Artifact{}, fmt.Errorf("%w: artifact %s", ErrArtifactNotFound, artifactID)
	}
	payload, err := s.readBlob(row)
	if err != nil {
		return nil, Artifact{}, err
	}
	if h := hex.EncodeToString(sha256Sum(payload)); h != row.Digest {
		return nil, Artifact{}, fmt.Errorf("%w: artifact %s payload digest mismatch", ErrArchiveIntegrity, row.ID)
	}
	return payload, row, nil
}

// List implements WORMStore.List.
func (s *FileWORMStore) List(_ context.Context, tenantID string) ([]Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.readManifest(tenantID)
	if err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []Artifact{}
	}
	return rows, nil
}

// Verify implements WORMStore.Verify.
func (s *FileWORMStore) Verify(_ context.Context, tenantID, artifactID string) (Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.readManifest(tenantID)
	if err != nil {
		return Artifact{}, err
	}
	idx := -1
	for i, r := range rows {
		if r.ID == artifactID {
			idx = i
			break
		}
	}
	if idx == -1 {
		return Artifact{}, fmt.Errorf("%w: artifact %s", ErrArtifactNotFound, artifactID)
	}
	return s.verifyRows(tenantID, rows, idx)
}
