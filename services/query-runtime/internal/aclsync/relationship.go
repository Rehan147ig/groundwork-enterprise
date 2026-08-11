package aclsync

import (
	"context"

	"groundwork/query-runtime/internal/relationship"
)

// This file bridges the tuple format (Tuple) to the neutral
// relationship surface. It exists so the sync pipeline can target
// relationship.Store without business logic knowing the wire format,
// and so any relationship.Store adapter (e.g. the SpiceDB backend) can
// wrap StoreSink losslessly.

// TuplesToRelationships converts tuple-format entries to neutral
// relationships. Lossless: EncodeSubject/EncodeObject
// reproduce the exact user/object strings (composite tool_action ids
// and legacy "principal:" prefixes included).
func TuplesToRelationships(in []Tuple) []relationship.Relationship {
	out := make([]relationship.Relationship, 0, len(in))
	for _, t := range in {
		subject, err := relationship.ParseSubject(t.User)
		if err != nil {
			continue
		}
		resource, err := relationship.ParseObject(t.Object)
		if err != nil {
			continue
		}
		out = append(out, relationship.Relationship{
			Resource: resource,
			Relation: t.Relation,
			Subject:  subject,
		})
	}
	return out
}

// RelationshipsToTuples is the inverse of TuplesToRelationships.
func RelationshipsToTuples(in []relationship.Relationship) []Tuple {
	out := make([]Tuple, 0, len(in))
	for _, rel := range in {
		out = append(out, Tuple{
			User:     relationship.EncodeSubject(rel.Subject),
			Relation: rel.Relation,
			Object:   relationship.EncodeObject(rel.Resource),
		})
	}
	return dedupeTuples(out)
}

// StoreSink adapts a relationship.Store to the TupleSink contract the
// sync pipeline and webhook receiver consume. Production wires StoreSink
// over the relationship/spicedb.Store.
type StoreSink struct {
	Store relationship.Store
}

// NewStoreSink builds a TupleSink over a relationship.Store.
func NewStoreSink(store relationship.Store) *StoreSink {
	return &StoreSink{Store: store}
}

func (s *StoreSink) WriteTuples(ctx context.Context, tenantID string, tuples []Tuple) error {
	return s.Store.Write(ctx, tenantID, TuplesToRelationships(tuples))
}

func (s *StoreSink) DeleteTuples(ctx context.Context, tenantID string, tuples []Tuple) error {
	return s.Store.Delete(ctx, tenantID, TuplesToRelationships(tuples))
}

func (s *StoreSink) ListTuples(ctx context.Context, tenantID string) ([]Tuple, error) {
	rels, err := s.Store.List(ctx, tenantID, relationship.Filter{})
	if err != nil {
		return nil, err
	}
	return RelationshipsToTuples(rels), nil
}

var _ TupleSink = (*StoreSink)(nil)

// relationship.Store conformance for MemoryTupleSink: the dev/test double can
// be wired anywhere relationship.Store is accepted. Its Check (tuple
// resolution) is intentionally NOT exposed as relationship.Authorizer —
// the reference Authorizer is relationship.MemoryBackend.
func (m *MemoryTupleSink) Write(ctx context.Context, tenantID string, rels []relationship.Relationship) error {
	return m.WriteTuples(ctx, tenantID, RelationshipsToTuples(rels))
}

func (m *MemoryTupleSink) Delete(ctx context.Context, tenantID string, rels []relationship.Relationship) error {
	return m.DeleteTuples(ctx, tenantID, RelationshipsToTuples(rels))
}

func (m *MemoryTupleSink) List(ctx context.Context, tenantID string, f relationship.Filter) ([]relationship.Relationship, error) {
	tuples, err := m.ListTuples(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	rels := TuplesToRelationships(tuples)
	out := rels[:0]
	for _, rel := range rels {
		if f.ResourceType != "" && rel.Resource.Type != f.ResourceType {
			continue
		}
		if f.ResourceID != "" && rel.Resource.ID != f.ResourceID {
			continue
		}
		if f.Relation != "" && rel.Relation != f.Relation {
			continue
		}
		if f.SubjectType != "" && rel.Subject.Type != f.SubjectType {
			continue
		}
		if f.SubjectID != "" && rel.Subject.ID != f.SubjectID {
			continue
		}
		out = append(out, rel)
	}
	return out, nil
}

var _ relationship.Store = (*MemoryTupleSink)(nil)
