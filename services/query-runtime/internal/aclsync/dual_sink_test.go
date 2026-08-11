package aclsync

import (
	"context"
	"errors"
	"testing"
)

func TestDualSinkWritesToBoth(t *testing.T) {
	primary := NewMemoryTupleSink()
	secondary := NewMemoryTupleSink()
	sink := NewDualSink(primary, secondary)

	tuples := []Tuple{{User: "user:alice", Relation: "viewer", Object: "document:d1"}}
	if err := sink.WriteTuples(context.Background(), "t1", tuples); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sink.DeleteTuples(context.Background(), "t1", tuples); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got, _ := primary.ListTuples(context.Background(), "t1"); len(got) != 0 {
		t.Fatalf("primary must reflect delete, got %d tuples", len(got))
	}
	if got, _ := secondary.ListTuples(context.Background(), "t1"); len(got) != 0 {
		t.Fatalf("secondary must reflect delete, got %d tuples", len(got))
	}
}

func TestDualSinkPrimaryErrorPropagates(t *testing.T) {
	failing := &failingSink{err: errors.New("primary down")}
	secondary := NewMemoryTupleSink()
	sink := NewDualSink(failing, secondary)

	if err := sink.WriteTuples(context.Background(), "t1", []Tuple{{User: "user:a", Relation: "viewer", Object: "document:d"}}); err == nil {
		t.Fatal("primary error must propagate")
	}
}

func TestDualSinkSecondaryConflictReportedNotFatal(t *testing.T) {
	primary := NewMemoryTupleSink()
	failing := &failingSink{err: errors.New("secondary down")}
	var conflicts int
	var conflictTenant string
	sink := NewDualSinkNamed(primary, failing, "secondary")
	sink.OnConflict = func(tenantID string, err error) {
		conflicts++
		conflictTenant = tenantID
	}

	tuples := []Tuple{{User: "user:alice", Relation: "viewer", Object: "document:d1"}}
	if err := sink.WriteTuples(context.Background(), "t1", tuples); err != nil {
		t.Fatalf("secondary failure must not fail the operation: %v", err)
	}
	if conflicts != 1 || conflictTenant != "t1" {
		t.Fatalf("conflict must be reported once for tenant t1, got %d (%q)", conflicts, conflictTenant)
	}
	// The authoritative copy must exist despite the secondary failure.
	if got, _ := primary.ListTuples(context.Background(), "t1"); len(got) != 1 {
		t.Fatalf("primary must hold the tuple, got %d", len(got))
	}
}

func TestDualSinkListFromPrimaryOnly(t *testing.T) {
	primary := NewMemoryTupleSink()
	secondary := NewMemoryTupleSink()
	sink := NewDualSink(primary, secondary)

	if err := primary.WriteTuples(context.Background(), "t1", []Tuple{{User: "user:alice", Relation: "viewer", Object: "document:d1"}}); err != nil {
		t.Fatal(err)
	}
	if err := secondary.WriteTuples(context.Background(), "t1", []Tuple{{User: "user:bob", Relation: "viewer", Object: "document:d1"}}); err != nil {
		t.Fatal(err)
	}
	got, err := sink.ListTuples(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].User != "user:alice" {
		t.Fatalf("list must read from primary only, got %v", got)
	}
}

func TestMigrateCopiesChunked(t *testing.T) {
	src := NewMemoryTupleSink()
	dst := NewMemoryTupleSink()

	var want []Tuple
	for i := 0; i < 25; i++ {
		t := Tuple{User: "user:u" + string(rune('a'+i)), Relation: "viewer", Object: "document:d" + string(rune('a'+i))}
		want = append(want, t)
	}
	if err := src.WriteTuples(context.Background(), "t1", want); err != nil {
		t.Fatal(err)
	}

	var applied, total int
	opts := MigrateOptions{ChunkSize: 10, OnChunk: func(a, tot int) { applied, total = a, tot }}
	res, err := Migrate(context.Background(), src, dst, "t1", opts)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if applied != 25 || total != 25 {
		t.Fatalf("progress = %d/%d, want 25/25", applied, total)
	}
	if res.Applied != 25 || res.Total != 25 || res.Skipped != 0 {
		t.Fatalf("result = applied %d total %d skipped %d, want 25/25/0", res.Applied, res.Total, res.Skipped)
	}
	if res.Checksum != ChecksumTuples(want) {
		t.Fatalf("checksum %s does not match source set checksum", res.Checksum)
	}
	got, err := dst.ListTuples(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("destination has %d tuples, want %d", len(got), len(want))
	}
}

func TestMigrateIdempotent(t *testing.T) {
	src := NewMemoryTupleSink()
	dst := NewMemoryTupleSink()
	tuples := []Tuple{{User: "user:alice", Relation: "viewer", Object: "document:d1"}}
	if err := src.WriteTuples(context.Background(), "t1", tuples); err != nil {
		t.Fatal(err)
	}
	if _, err := Migrate(context.Background(), src, dst, "t1", MigrateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := Migrate(context.Background(), src, dst, "t1", MigrateOptions{}); err != nil {
		t.Fatalf("rerun must be safe: %v", err)
	}
	if got, _ := dst.ListTuples(context.Background(), "t1"); len(got) != 1 {
		t.Fatalf("rerun must not duplicate tuples, got %d", len(got))
	}
}

func TestCompareReportsBothDirections(t *testing.T) {
	src := NewMemoryTupleSink()
	dst := NewMemoryTupleSink()
	if err := src.WriteTuples(context.Background(), "t1", []Tuple{
		{User: "user:alice", Relation: "viewer", Object: "document:d1"},
		{User: "user:carol", Relation: "viewer", Object: "document:d1"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := dst.WriteTuples(context.Background(), "t1", []Tuple{
		{User: "user:alice", Relation: "viewer", Object: "document:d1"},
		{User: "user:bob", Relation: "viewer", Object: "document:d1"},
	}); err != nil {
		t.Fatal(err)
	}
	res, err := Compare(context.Background(), src, dst, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Total() != 2 {
		t.Fatalf("drift total = %d, want 2", res.Total())
	}
	if len(res.OnlySource) != 1 || res.OnlySource[0].User != "user:carol" {
		t.Fatalf("only-source = %v, want carol", res.OnlySource)
	}
	if len(res.OnlyDestination) != 1 || res.OnlyDestination[0].User != "user:bob" {
		t.Fatalf("only-destination = %v, want bob", res.OnlyDestination)
	}
}

func TestCompareTenantScoped(t *testing.T) {
	src := NewMemoryTupleSink()
	dst := NewMemoryTupleSink()
	if err := src.WriteTuples(context.Background(), "t1", []Tuple{{User: "user:alice", Relation: "viewer", Object: "document:d1"}}); err != nil {
		t.Fatal(err)
	}
	if err := src.WriteTuples(context.Background(), "t2", []Tuple{{User: "user:bob", Relation: "viewer", Object: "document:d1"}}); err != nil {
		t.Fatal(err)
	}
	res, err := Compare(context.Background(), src, dst, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Total() != 1 {
		t.Fatalf("comparison must be tenant-scoped, total = %d", res.Total())
	}
}

func TestChecksumOrderIndependent(t *testing.T) {
	a := []Tuple{
		{User: "user:alice", Relation: "viewer", Object: "document:d1"},
		{User: "group:eng#member", Relation: "member", Object: "group:all"},
		{User: "user:bob", Relation: "use", Object: "tool:t1"},
	}
	b := []Tuple{
		{User: "user:bob", Relation: "use", Object: "tool:t1"},
		{User: "user:alice", Relation: "viewer", Object: "document:d1"},
		{User: "group:eng#member", Relation: "member", Object: "group:all"},
		{User: "user:alice", Relation: "viewer", Object: "document:d1"}, // duplicate
	}
	if ChecksumTuples(a) != ChecksumTuples(b) {
		t.Fatal("checksum must ignore order and duplicates")
	}
	if ChecksumTuples(a) == ChecksumTuples([]Tuple{{User: "user:alice", Relation: "viewer", Object: "document:d1"}}) {
		t.Fatal("checksum must change when the set changes")
	}
}

func TestMigrateSkipsInvalidTuples(t *testing.T) {
	src := NewMemoryTupleSink()
	dst := NewMemoryTupleSink()
	if err := src.WriteTuples(context.Background(), "t1", []Tuple{
		{User: "user:alice", Relation: "viewer", Object: "document:d1"},
		{User: "", Relation: "viewer", Object: "document:d2"},
		{User: "user:bob", Relation: "", Object: "document:d3"},
		{User: "user:carol", Relation: "viewer", Object: ""},
	}); err != nil {
		t.Fatal(err)
	}
	res, err := Migrate(context.Background(), src, dst, "t1", MigrateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 4 || res.Skipped != 3 || res.Applied != 1 {
		t.Fatalf("result = total %d skipped %d applied %d, want 4/3/1", res.Total, res.Skipped, res.Applied)
	}
	got, err := dst.ListTuples(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("destination has %d tuples, want 1", len(got))
	}
}

// failingSink is a TupleSink that errors on every mutation.
type failingSink struct {
	err error
}

func (f *failingSink) ListTuples(context.Context, string) ([]Tuple, error) { return nil, f.err }
func (f *failingSink) WriteTuples(context.Context, string, []Tuple) error  { return f.err }
func (f *failingSink) DeleteTuples(context.Context, string, []Tuple) error { return f.err }

var _ TupleSink = (*failingSink)(nil)
