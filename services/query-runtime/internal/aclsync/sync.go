package aclsync

import (
	"context"
	"log/slog"
	"strings"
	"time"
)

// SyncResult summarizes one sync run.
type SyncResult struct {
	TenantID      string `json:"tenant_id"`
	TuplesWritten int    `json:"tuples_written"`
	TuplesDeleted int    `json:"tuples_deleted"`
	DurationMs    int64  `json:"sync_duration_ms"`
}

// DriftReport describes divergence between the source of truth and the
// relationship backend.
type DriftReport struct {
	TenantID string `json:"tenant_id"`
	// SourceMissingInBackend: the source grants these, but the backend has no matching tuple.
	SourceMissingInBackend []Tuple `json:"source_missing_in_backend"`
	// BackendExtraNotInSource: the backend has these tuples, but the source no longer grants them.
	BackendExtraNotInSource []Tuple `json:"backend_extra_not_in_source"`
	// DocumentsMissingInBackend: documents that exist in the source but have no backend tuples.
	DocumentsMissingInBackend []string `json:"documents_missing_in_backend"`
	// OrphanedBackendDocuments: documents referenced by backend tuples but absent from the source.
	OrphanedBackendDocuments []string `json:"orphaned_backend_documents"`
}

// HasDrift reports whether any divergence was found.
func (r DriftReport) HasDrift() bool {
	return len(r.SourceMissingInBackend) > 0 || len(r.BackendExtraNotInSource) > 0 ||
		len(r.DocumentsMissingInBackend) > 0 || len(r.OrphanedBackendDocuments) > 0
}

// Syncer reconciles a Connector's permissions into a TupleSink (SpiceDB in
// production, MemoryTupleSink in tests). It does not touch the query engine;
// it only feeds the sink.
type Syncer struct {
	Connector Connector
	Sink      TupleSink
	Logger    *slog.Logger
	// AllowEmptyDestructive permits deletes even when the source snapshot is empty.
	// Default false: an empty/unconfirmed snapshot never deletes existing tuples, which
	// guards against wiping all permissions if a connector outage returns nothing.
	AllowEmptyDestructive bool
}

func NewSyncer(c Connector, sink TupleSink, logger *slog.Logger) *Syncer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Syncer{Connector: c, Sink: sink, Logger: logger}
}

// Sync reconciles the relationship backend to match the source of truth:
// it writes tuples the source grants but the backend lacks, and deletes
// tuples the backend has but the source no longer grants (this is how
// revocations propagate). Idempotent.
func (s *Syncer) Sync(ctx context.Context, tenantID string) (SyncResult, error) {
	start := time.Now()
	s.Logger.Info("sync_started", "tenant", tenantID)

	ps, err := s.Connector.Snapshot(ctx, tenantID)
	if err != nil {
		return SyncResult{}, err
	}
	desired := tupleSet(PermissionSetToTuples(ps))

	current, err := s.Sink.ListTuples(ctx, tenantID)
	if err != nil {
		return SyncResult{}, err
	}
	have := tupleSet(current)

	toWrite := difference(desired, have)
	toDelete := difference(have, desired)

	// Safety: never delete on an empty (unconfirmed) snapshot unless explicitly allowed.
	// A revocation arrives as a non-empty snapshot missing the revoked grant, or as an
	// explicit change event — both safe. An all-empty snapshot is treated as suspect
	// (e.g. a connector outage) and must not wipe existing permissions.
	if len(toDelete) > 0 && len(desired) == 0 && !s.AllowEmptyDestructive {
		s.Logger.Warn("acl_sync_skipped_destructive_delete",
			"tenant", tenantID, "would_delete", len(toDelete), "reason", "empty_or_unconfirmed_snapshot")
		toDelete = nil
	}

	if len(toWrite) > 0 {
		if err := s.Sink.WriteTuples(ctx, tenantID, toWrite); err != nil {
			return SyncResult{}, err
		}
	}
	if len(toDelete) > 0 {
		if err := s.Sink.DeleteTuples(ctx, tenantID, toDelete); err != nil {
			return SyncResult{}, err
		}
	}

	res := SyncResult{
		TenantID:      tenantID,
		TuplesWritten: len(toWrite),
		TuplesDeleted: len(toDelete),
		DurationMs:    time.Since(start).Milliseconds(),
	}
	s.Logger.Info("sync_completed",
		"tenant", tenantID,
		"tuples_written", res.TuplesWritten,
		"tuples_deleted", res.TuplesDeleted,
		"sync_duration_ms", res.DurationMs,
	)
	return res, nil
}

// DetectDrift compares the source of truth against the tuples currently in the sink and
// returns a structured report without mutating anything.
func (s *Syncer) DetectDrift(ctx context.Context, tenantID string) (DriftReport, error) {
	ps, err := s.Connector.Snapshot(ctx, tenantID)
	if err != nil {
		return DriftReport{}, err
	}
	desired := tupleSet(PermissionSetToTuples(ps))

	current, err := s.Sink.ListTuples(ctx, tenantID)
	if err != nil {
		return DriftReport{}, err
	}
	have := tupleSet(current)

	report := DriftReport{
		TenantID:            tenantID,
		SourceMissingInBackend:  difference(desired, have),
		BackendExtraNotInSource: difference(have, desired),
	}

	// Document-level drift.
	srcDocs := map[string]bool{}
	for _, d := range ps.Documents {
		srcDocs[documentRef(d.ID)] = true
	}
	fgaDocs := map[string]bool{}
	for t := range have {
		if strings.HasPrefix(t.Object, "document:") {
			fgaDocs[t.Object] = true
		}
	}
	for doc := range srcDocs {
		if !fgaDocs[doc] {
			report.DocumentsMissingInBackend = append(report.DocumentsMissingInBackend, doc)
		}
	}
	for doc := range fgaDocs {
		if !srcDocs[doc] {
			report.OrphanedBackendDocuments = append(report.OrphanedBackendDocuments, doc)
		}
	}

	s.Logger.Info("drift_detected",
		"tenant", tenantID,
		"source_missing_in_backend", len(report.SourceMissingInBackend),
		"backend_extra_not_in_source", len(report.BackendExtraNotInSource),
		"documents_missing_in_backend", len(report.DocumentsMissingInBackend),
		"orphaned_backend_documents", len(report.OrphanedBackendDocuments),
		"has_drift", report.HasDrift(),
	)
	return report, nil
}

func tupleSet(tuples []Tuple) map[Tuple]bool {
	set := make(map[Tuple]bool, len(tuples))
	for _, t := range tuples {
		set[t] = true
	}
	return set
}

// difference returns the tuples present in a but not in b.
func difference(a, b map[Tuple]bool) []Tuple {
	var out []Tuple
	for t := range a {
		if !b[t] {
			out = append(out, t)
		}
	}
	return out
}
