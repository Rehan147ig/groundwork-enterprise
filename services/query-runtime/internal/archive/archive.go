// Package archive implements the Phase 8.3 immutable/WORM archive
// interface for audit exports and long-term retention.
//
// A WORMStore seals payloads (audit exports, evidence reports) exactly
// once. Artifacts are content-addressed, cannot be overwritten or
// deleted through the interface, and every seal appends a row to the
// tenant's append-only manifest with a chained digest — so later edits,
// deletions, or reorderings are detected by Verify. Sealing the same
// payload with the same metadata is idempotent and returns the original
// artifact.
package archive

import (
	"context"
	"errors"
)

// ErrArchiveIntegrity reports a tamper-evidence failure: a sealed
// payload's content no longer matches its digest, the manifest chain is
// broken (edited, deleted, or reordered row), or a sealed artifact is
// missing. Verification always fails closed.
var ErrArchiveIntegrity = errors.New("archive integrity violation")

// ErrArtifactNotFound reports a request for an artifact id the tenant
// never sealed.
var ErrArtifactNotFound = errors.New("archive artifact not found")

// ErrArchiveUnavailable reports a store that is not wired (nil-safe
// surfaces mirror the rest of the runtime).
var ErrArchiveUnavailable = errors.New("archive unavailable")

// Artifact is one sealed archive object. The manifest chain fields
// (ChainIndex, PrevDigest, ChainDigest) are computed by the store at
// seal time and re-verified at read time.
type Artifact struct {
	// ID is the content address: sha256 over the canonical seal input
	// (tenant, kind, payload, meta). Sealing identical content and
	// metadata yields the same ID (idempotent).
	ID string `json:"id"`
	// TenantID is the owning tenant. Archive objects are never shared
	// across tenants.
	TenantID string `json:"tenant_id"`
	// Kind classifies the payload, e.g. "audit_export", "evidence_report".
	Kind string `json:"kind"`
	// Size is the payload length in bytes.
	Size int64 `json:"size"`
	// Digest is sha256 over the raw payload.
	Digest string `json:"digest"`
	// Meta is operator-supplied, non-secret metadata (e.g.
	// framework=soc2, source_chain_digest=<checkpoint digest>). Meta
	// must never carry secrets or evidence material.
	Meta map[string]string `json:"meta,omitempty"`
	// SealedAt is the UTC seal timestamp (RFC 3339).
	SealedAt string `json:"sealed_at"`
	// ChainIndex is the artifact's row number in the tenant manifest
	// (0-based, append-only).
	ChainIndex int `json:"chain_index"`
	// PrevDigest is the previous manifest row's chain digest ("" for the
	// first row).
	PrevDigest string `json:"prev_digest,omitempty"`
	// ChainDigest binds this row to the previous one and to the payload
	// digest, so a manifest row cannot be edited, reordered, or dropped
	// without breaking the chain.
	ChainDigest string `json:"chain_digest"`
}

// WORMStore is the write-once archive interface. There is deliberately
// no Delete and no Update: sealing is the only mutation, and it never
// overwrites an existing artifact. Implementations must be
// tenant-scoped and verify digests before returning content.
type WORMStore interface {
	// Seal writes the payload to the archive exactly once. Idempotent:
	// sealing the same payload with the same kind and metadata returns
	// the original artifact. Never overwrites or deletes.
	Seal(ctx context.Context, tenantID, kind string, payload []byte, meta map[string]string) (Artifact, error)
	// Open returns the verified payload for a sealed artifact, or an
	// error (ErrArtifactNotFound / ErrArchiveIntegrity) — content is
	// never returned on verification failure.
	Open(ctx context.Context, tenantID, artifactID string) ([]byte, Artifact, error)
	// List returns the tenant's manifest rows, oldest first.
	List(ctx context.Context, tenantID string) ([]Artifact, error)
	// Verify re-checks every manifest row up to and including the
	// artifact (payload digest + chain linkage) and returns the
	// artifact. Fails closed with ErrArchiveIntegrity on any violation.
	Verify(ctx context.Context, tenantID, artifactID string) (Artifact, error)
}
