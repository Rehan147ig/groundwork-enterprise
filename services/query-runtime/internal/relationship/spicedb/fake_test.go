package spicedb

import (
	"context"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"

	"groundwork/query-runtime/internal/relationship"
)

// fakeSpiceDBServer is an in-process gRPC server implementing the subset
// of the authzed v1 API the adapter uses, with the same model semantics
// as the reference MemoryBackend (nested group membership, folder
// inheritance, direct-user-only tool relations, fail-closed checks). The
// adapter composes tenant-scoped IDs before the wire, so the fake stores
// and matches IDs verbatim — the tenant dimension never reaches it.
type fakeSpiceDBServer struct {
	v1.UnimplementedPermissionsServiceServer
	v1.UnimplementedSchemaServiceServer

	store  *relationship.MemoryBackend
	schema string
}

// newFakeSpiceDBServer starts the fake and returns its endpoint.
func newFakeSpiceDBServer(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake spicedb listen: %v", err)
	}
	fake := &fakeSpiceDBServer{store: relationship.NewMemoryBackend()}
	srv := grpc.NewServer()
	v1.RegisterPermissionsServiceServer(srv, fake)
	v1.RegisterSchemaServiceServer(srv, fake)
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	hs.SetServingStatus("authzed.api.v1.PermissionsService", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, hs)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func (f *fakeSpiceDBServer) CheckPermission(ctx context.Context, req *v1.CheckPermissionRequest) (*v1.CheckPermissionResponse, error) {
	allowed, err := f.store.Check(ctx, relationship.CheckRequest{
		Subject:    subjectRef(req.GetSubject()),
		Permission: req.GetPermission(),
		Resource:   resourceRef(req.GetResource()),
	})
	if err != nil {
		return nil, err
	}
	if allowed {
		return &v1.CheckPermissionResponse{Permissionship: v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION}, nil
	}
	return &v1.CheckPermissionResponse{Permissionship: v1.CheckPermissionResponse_PERMISSIONSHIP_NO_PERMISSION}, nil
}

func (f *fakeSpiceDBServer) WriteRelationships(ctx context.Context, req *v1.WriteRelationshipsRequest) (*v1.WriteRelationshipsResponse, error) {
	var rels []relationship.Relationship
	for _, u := range req.GetUpdates() {
		rel, err := relationshipFromWire(u.GetRelationship())
		if err != nil {
			return nil, err
		}
		rels = append(rels, rel)
	}
	if err := f.store.Write(ctx, "", rels); err != nil {
		return nil, err
	}
	return &v1.WriteRelationshipsResponse{}, nil
}

func (f *fakeSpiceDBServer) DeleteRelationships(ctx context.Context, req *v1.DeleteRelationshipsRequest) (*v1.DeleteRelationshipsResponse, error) {
	rel, err := relationshipFromFilter(req.GetRelationshipFilter())
	if err != nil {
		return nil, err
	}
	if err := f.store.Delete(ctx, "", []relationship.Relationship{rel}); err != nil {
		return nil, err
	}
	return &v1.DeleteRelationshipsResponse{}, nil
}

func (f *fakeSpiceDBServer) ReadRelationships(req *v1.ReadRelationshipsRequest, stream grpc.ServerStreamingServer[v1.ReadRelationshipsResponse]) error {
	rel, err := relationshipFromFilter(req.GetRelationshipFilter())
	if err != nil {
		return err
	}
	rels, err := f.store.List(stream.Context(), "", relationship.Filter{
		ResourceType: rel.Resource.Type,
		ResourceID:   rel.Resource.ID,
		Relation:     rel.Relation,
		SubjectType:  rel.Subject.Type,
		SubjectID:    rel.Subject.ID,
	})
	if err != nil {
		return err
	}
	for _, r := range rels {
		if err := stream.Send(&v1.ReadRelationshipsResponse{Relationship: relationshipToWire(r)}); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeSpiceDBServer) WriteSchema(ctx context.Context, req *v1.WriteSchemaRequest) (*v1.WriteSchemaResponse, error) {
	if strings.TrimSpace(req.GetSchema()) == "" {
		return nil, status.Error(codes.InvalidArgument, "empty schema")
	}
	f.schema = req.GetSchema()
	return &v1.WriteSchemaResponse{}, nil
}

func (f *fakeSpiceDBServer) ReadSchema(ctx context.Context, req *v1.ReadSchemaRequest) (*v1.ReadSchemaResponse, error) {
	return &v1.ReadSchemaResponse{SchemaText: f.schema}, nil
}

// subjectRef decodes a wire subject back into a neutral reference. The
// fake stores IDs verbatim (the adapter already composed tenant
// prefixes), so no unscoping happens here.
func subjectRef(s *v1.SubjectReference) relationship.SubjectRef {
	if s == nil || s.GetObject() == nil {
		return relationship.SubjectRef{}
	}
	return relationship.SubjectRef{
		Type:     s.GetObject().GetObjectType(),
		ID:       s.GetObject().GetObjectId(),
		Relation: s.GetOptionalRelation(),
	}
}

func resourceRef(o *v1.ObjectReference) relationship.ResourceRef {
	if o == nil {
		return relationship.ResourceRef{}
	}
	return relationship.ResourceRef{Type: o.GetObjectType(), ID: o.GetObjectId()}
}

func relationshipFromWire(r *v1.Relationship) (relationship.Relationship, error) {
	if r == nil || r.GetResource() == nil || r.GetSubject() == nil || r.GetSubject().GetObject() == nil {
		return relationship.Relationship{}, status.Error(codes.InvalidArgument, "malformed relationship")
	}
	return relationship.Relationship{
		Resource: resourceRef(r.GetResource()),
		Relation: r.GetRelation(),
		Subject:  subjectRef(r.GetSubject()),
	}, nil
}

// relationshipFromFilter turns a fully- or partially-specified filter
// into a Relationship whose empty fields act as wildcards.
func relationshipFromFilter(f *v1.RelationshipFilter) (relationship.Relationship, error) {
	if f == nil || f.GetResourceType() == "" {
		return relationship.Relationship{}, status.Error(codes.InvalidArgument, "relationship filter requires resource_type")
	}
	rel := relationship.Relationship{
		Resource: relationship.ResourceRef{Type: f.GetResourceType(), ID: f.GetOptionalResourceId()},
		Relation: f.GetOptionalRelation(),
	}
	if sf := f.GetOptionalSubjectFilter(); sf != nil {
		rel.Subject.Type = sf.GetSubjectType()
		rel.Subject.ID = sf.GetOptionalSubjectId()
		rel.Subject.Relation = sf.GetOptionalRelation().GetRelation()
	}
	return rel, nil
}

func relationshipToWire(r relationship.Relationship) *v1.Relationship {
	return &v1.Relationship{
		Resource: &v1.ObjectReference{ObjectType: r.Resource.Type, ObjectId: r.Resource.ID},
		Relation: r.Relation,
		Subject: &v1.SubjectReference{
			Object:           &v1.ObjectReference{ObjectType: r.Subject.Type, ObjectId: r.Subject.ID},
			OptionalRelation: r.Subject.Relation,
		},
	}
}

// TestSpiceDBContract runs the shared conformance suite against the
// adapter + fake. TenantIsolation is true: unlike the memory backend's shared
// store, the SpiceDB adapter composes tenant prefixes into IDs, so
// cross-tenant access is physically impossible.
func TestSpiceDBContract(t *testing.T) {
	addr := newFakeSpiceDBServer(t)
	client, err := New(addr, "test-preshared-key", WithInsecurePlaintext())
	if err != nil {
		t.Fatalf("new spicedb client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()
	if err := client.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap schema: %v", err)
	}
	if err := client.Ready(ctx); err != nil {
		t.Fatalf("ready: %v", err)
	}

	relationship.ContractSuite(t, relationship.Backend{
		Name:            "spicedb (authzed-go adapter)",
		Auth:            client,
		Store:           client,
		TenantIsolation: true,
	})
}
