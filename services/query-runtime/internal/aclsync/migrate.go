package aclsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// MigrateOptions tunes a Migrate run.
type MigrateOptions struct {
	// ChunkSize bounds each WriteTuples batch (default 1000).
	ChunkSize int
	// OnChunk, when set, is invoked after each applied chunk with the
	// cumulative applied count and the total.
	OnChunk func(applied, total int)
}

// MigrateResult reports what one Migrate run did.
type MigrateResult struct {
	// Applied is the number of tuples written to the destination.
	Applied int
	// Total is the deduplicated source count for the tenant.
	Total int
	// Skipped is the number of source tuples ignored because they are
	// invalid (empty user/relation/object) and cannot be represented.
	Skipped int
	// Checksum is the SHA-256 over the sorted, deduplicated source
	// tuple set ("user relation object" per line). Stable across runs,
	// so two tenants or two runs can be compared by checksum.
	Checksum string
}

// ChecksumTuples returns the canonical SHA-256 of a tuple set: the
// tuples sorted and joined as "<user> <relation> <object>\n". Used to
// compare source and destination state independently of list order.
func ChecksumTuples(tuples []Tuple) string {
	tuples = dedupeTuples(tuples)
	sort.Slice(tuples, func(i, j int) bool { return tupleLess(tuples[i], tuples[j]) })
	h := sha256.New()
	for _, t := range tuples {
		_, _ = h.Write([]byte(t.String()))
		_, _ = h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Migrate copies every tuple from src to dst, tenant-scoped by
// tenantID. The source is read once, chunked, and written to the
// destination with TOUCH-style idempotency — rerunning the migration
// is safe and converges (resume = rerun: already-applied tuples are
// re-touched and converge).
//
// Tenant semantics: the full source set is replicated into the
// destination under tenantID, so a shared/unsplit source can be
// materialized per-tenant in a scoped destination by running this
// command once per tenant.
func Migrate(ctx context.Context, src, dst TupleSink, tenantID string, opts MigrateOptions) (*MigrateResult, error) {
	if opts.ChunkSize <= 0 {
		opts.ChunkSize = 1000
	}
	tuples, err := src.ListTuples(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("migrate: read source: %w", err)
	}
	tuples = dedupeTuples(tuples)

	res := &MigrateResult{
		Total:    len(tuples),
		Checksum: ChecksumTuples(tuples),
	}
	valid := make([]Tuple, 0, len(tuples))
	for _, t := range tuples {
		if t.User == "" || t.Relation == "" || t.Object == "" {
			res.Skipped++
			continue
		}
		valid = append(valid, t)
	}
	for start := 0; start < len(valid); start += opts.ChunkSize {
		end := min(start+opts.ChunkSize, len(valid))
		if err := dst.WriteTuples(ctx, tenantID, valid[start:end]); err != nil {
			return res, fmt.Errorf("migrate: write chunk %d: %w", start/opts.ChunkSize, err)
		}
		res.Applied = end
		if opts.OnChunk != nil {
			opts.OnChunk(end, len(valid))
		}
	}
	return res, nil
}

// DriftResult is the set difference between two sinks for one tenant.
type DriftResult struct {
	// OnlySource tuples exist in the source but not in the destination
	// (they would be copied by Migrate).
	OnlySource []Tuple
	// OnlyDestination tuples exist in the destination but not in the
	// source (extraneous state, e.g. leftover from a prior run).
	OnlyDestination []Tuple
}

// Total returns the total number of differing tuples.
func (d *DriftResult) Total() int {
	return len(d.OnlySource) + len(d.OnlyDestination)
}

// Compare lists the per-tenant tuple differences between two sinks.
// Deterministic ordering (sorted) so reports are diffable.
func Compare(ctx context.Context, src, dst TupleSink, tenantID string) (*DriftResult, error) {
	fromSrc, err := src.ListTuples(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("compare: read source: %w", err)
	}
	fromDst, err := dst.ListTuples(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("compare: read destination: %w", err)
	}
	srcSet := tupleKeySet(fromSrc)
	dstSet := tupleKeySet(fromDst)
	res := &DriftResult{}
	for t := range srcSet {
		if !dstSet[t] {
			res.OnlySource = append(res.OnlySource, t)
		}
	}
	for t := range dstSet {
		if !srcSet[t] {
			res.OnlyDestination = append(res.OnlyDestination, t)
		}
	}
	sort.Slice(res.OnlySource, func(i, j int) bool { return tupleLess(res.OnlySource[i], res.OnlySource[j]) })
	sort.Slice(res.OnlyDestination, func(i, j int) bool { return tupleLess(res.OnlyDestination[i], res.OnlyDestination[j]) })
	return res, nil
}

func tupleKeySet(tuples []Tuple) map[Tuple]bool {
	set := make(map[Tuple]bool, len(tuples))
	for _, t := range tuples {
		set[t] = true
	}
	return set
}

func tupleLess(a, b Tuple) bool {
	if a.Object != b.Object {
		return a.Object < b.Object
	}
	if a.Relation != b.Relation {
		return a.Relation < b.Relation
	}
	return a.User < b.User
}
