// Package spicedb adapts a SpiceDB server (via authzed-go) to the neutral
// relationship contracts (relationship.Authorizer + relationship.Store).
// It is a thin wire adapter: all typed translation happens here and in
// the shared schema package (internal/relationship/schema); business
// logic only ever sees the neutral types.
//
// Tenant isolation: unlike the memory backend, this adapter physically
// scopes tuples per tenant. Every object and subject ID is composed on
// the wire as EscapeID(tenantID) + "/" + EscapeID(id) and decomposed on
// read, so the same ID in two tenants is two distinct SpiceDB objects.
// Cross-tenant checks, lists, and deletes are then structurally
// impossible, which is what the contract suite's TenantIsolation
// capability verifies.
//
// Fail-closed behavior mirrors the memory backend: malformed or unknown
// permission checks deny without touching the network, conditional
// results deny, and transport failures surface as
// relationship.ErrBackendUnavailable / ErrBackendTimeout.
//
// Options:
//
//   - Consistency: SPICEDB_CONSISTENCY selects the read consistency
//     ("at_least_as_fresh" default, "minimize_latency", "fully_consistent").
//     At-least-as-fresh is implemented by tracking the newest ZedToken
//     observed on any read or write and pinning subsequent reads to it,
//     so a check issued right after a write is never served from a stale
//     snapshot (minimize_latency can deny a grant that landed a
//     millisecond earlier).
//   - Circuit breaker: WithCircuitBreaker wraps every permissions call;
//     when the backend fails repeatedly the adapter short-circuits with
//     relationship.ErrCircuitOpen instead of hammering a sick backend.
//     Failures are counted only for transport-level errors (the
//     relationship.ErrBackend* sentinels), never for validation or
//     schema errors.
//   - Custom CA: WithCA pins the gRPC trust anchor to a supplied PEM
//     bundle (internal PKI), mutually exclusive with the insecure
//     plaintext option.
//   - mTLS client cert: WithClientCert presents a PEM certificate/key
//     pair to the server (SpiceDB --grpc-ca requires client certs).
//     Applied together with WithCA for a dedicated internal PKI.
//   - Deep readiness: Ready is not just the gRPC health check — it also
//     ensures the authorization model is written and matches the
//     embedded groundwork.zed (fail closed with ErrModelMissing on
//     drift), so a pod never enters rotation against a stale schema.
package spicedb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"

	"groundwork/query-runtime/internal/relationship"
	"groundwork/query-runtime/internal/relationship/schema"
)

const (
	defaultTimeout = 5 * time.Second
	writeChunkSize = 1000
)

// Read-consistency modes accepted by WithConsistency.
const (
	ConsistencyMinimizeLatency = "minimize_latency"
	ConsistencyAtLeastAsFresh  = "at_least_as_fresh"
	ConsistencyFullyConsistent = "fully_consistent"
)

// Client adapts a SpiceDB endpoint to relationship.Authorizer and
// relationship.Store. It is safe for concurrent use.
type Client struct {
	conn    *grpc.ClientConn
	perms   v1.PermissionsServiceClient
	schema  v1.SchemaServiceClient
	health  grpc_health_v1.HealthClient
	timeout time.Duration

	// migration options
	consistencyMode string
	breaker         *relationship.CircuitBreaker
	onTrip          func()

	// at_least_as_fresh: newest zed token observed on any read.
	tokenMu  sync.Mutex
	zedToken string

	bootstrapOnce sync.Once
	bootstrapErr  error
}

// Option configures the SpiceDB client.
type Option func(*options)

type options struct {
	timeout         time.Duration
	plain           bool
	caPEM           []byte
	certPEM         []byte
	keyPEM          []byte
	consistencyMode string
	breaker         *relationship.CircuitBreaker
	onTrip          func()
}

// WithTimeout sets the per-request deadline (default 5s).
func WithTimeout(d time.Duration) Option {
	return func(o *options) { o.timeout = d }
}

// WithInsecurePlaintext dials without TLS. Dev/test only — production
// deployments must use TLS (and the SpiceDB preshared key via token).
// Mutually exclusive with WithCA.
func WithInsecurePlaintext() Option {
	return func(o *options) { o.plain = true }
}

// WithCA pins the gRPC trust anchor to the given PEM bundle (an
// internal CA or an mTLS intermediary). Mutually exclusive with
// WithInsecurePlaintext. When unset, the system roots are used.
func WithCA(caPEM []byte) Option {
	return func(o *options) { o.caPEM = caPEM }
}

// WithClientCert presents a PEM certificate/key pair to the server for
// mutual TLS. Use together with WithCA so the server's own cert
// verifies against the same internal CA. Mutually exclusive with
// WithInsecurePlaintext.
func WithClientCert(certPEM, keyPEM []byte) Option {
	return func(o *options) { o.certPEM = certPEM; o.keyPEM = keyPEM }
}

// WithConsistency selects the read-consistency mode for checks and
// lists: ConsistencyAtLeastAsFresh (default; token-tracked so reads
// never lag behind observed writes/reads), ConsistencyMinimizeLatency,
// or ConsistencyFullyConsistent. An unrecognized mode fails at New
// (fail closed at construction) rather than silently degrading reads.
func WithConsistency(mode string) Option {
	return func(o *options) { o.consistencyMode = mode }
}

// WithCircuitBreaker wraps permissions calls with the given breaker.
// See the package comment for the failure-counting semantics.
func WithCircuitBreaker(b *relationship.CircuitBreaker) Option {
	return func(o *options) { o.breaker = b }
}

// WithOnCircuitTrip registers a callback fired (outside the breaker
// lock) whenever the breaker transitions to open — e.g. a Prometheus
// trip counter.
func WithOnCircuitTrip(fn func()) Option {
	return func(o *options) { o.onTrip = fn }
}

// New dials a SpiceDB endpoint. The gRPC connection is established
// lazily; Bootstrap is the only call that touches the schema service.
// TLS is the default transport; dev deployments opt out with
// WithInsecurePlaintext.
func New(endpoint, token string, opts ...Option) (*Client, error) {
	o := options{timeout: defaultTimeout, consistencyMode: ConsistencyAtLeastAsFresh}
	for _, opt := range opts {
		opt(&o)
	}
	if o.plain && (len(o.caPEM) > 0 || len(o.certPEM) > 0 || len(o.keyPEM) > 0) {
		return nil, fmt.Errorf("spicedb: WithInsecurePlaintext is mutually exclusive with TLS options (WithCA / WithClientCert)")
	}
	if (len(o.certPEM) > 0) != (len(o.keyPEM) > 0) {
		return nil, fmt.Errorf("spicedb: WithClientCert requires both the certificate and its key")
	}
	switch o.consistencyMode {
	case "", ConsistencyMinimizeLatency, ConsistencyAtLeastAsFresh, ConsistencyFullyConsistent:
	default:
		return nil, fmt.Errorf("spicedb: unsupported consistency mode %q (supported: %s|%s|%s)",
			o.consistencyMode, ConsistencyMinimizeLatency, ConsistencyAtLeastAsFresh, ConsistencyFullyConsistent)
	}

	var dialOpts []grpc.DialOption
	switch {
	case o.plain:
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	default:
		tlsCfg := &tls.Config{}
		if len(o.caPEM) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(o.caPEM) {
				return nil, fmt.Errorf("spicedb: WithCA: no certificates parsed from the provided PEM")
			}
			tlsCfg.RootCAs = pool
		}
		if len(o.certPEM) > 0 {
			cert, err := tls.X509KeyPair(o.certPEM, o.keyPEM)
			if err != nil {
				return nil, fmt.Errorf("spicedb: WithClientCert: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	}
	if token != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(bearerToken{token: token}))
	}
	conn, err := grpc.NewClient(endpoint, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("spicedb: dial %q: %w", endpoint, err)
	}
	c := &Client{
		conn:            conn,
		perms:           v1.NewPermissionsServiceClient(conn),
		schema:          v1.NewSchemaServiceClient(conn),
		health:          grpc_health_v1.NewHealthClient(conn),
		timeout:         o.timeout,
		consistencyMode: o.consistencyMode,
		breaker:         o.breaker,
		onTrip:          o.onTrip,
	}
	return c, nil
}

// Close releases the gRPC connection.
func (c *Client) Close() error { return c.conn.Close() }

// Bootstrap writes the authorization model (the embedded
// groundwork.zed). WriteSchema is declarative and idempotent, so
// repeated calls are safe. The result of a successful call is cached; a
// failed call is retried on the next invocation (a transient failure at
// startup must not poison readiness forever).
func (c *Client) Bootstrap(ctx context.Context) error {
	c.bootstrapOnce.Do(func() {
		ctx, cancel := c.withTimeout(ctx)
		defer cancel()
		_, err := c.schema.WriteSchema(ctx, &v1.WriteSchemaRequest{Schema: schema.ZED()})
		c.bootstrapErr = err
		if err != nil {
			c.bootstrapOnce = sync.Once{}
		}
	})
	return c.bootstrapErr
}

// Ready is the deep readiness probe: it checks the standard gRPC health
// service, ensures the authorization model is written, and verifies the
// written schema matches the embedded groundwork.zed (fail closed with
// ErrModelMissing on drift). Wire it into /readyz so a pod never serves
// against a missing or stale model.
func (c *Client) Ready(ctx context.Context) error {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.health.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: ""})
	if err != nil {
		return fmt.Errorf("%w: %v", relationship.ErrBackendUnavailable, err)
	}
	if resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		return fmt.Errorf("%w: spicedb health %s", relationship.ErrBackendUnavailable, resp.GetStatus())
	}
	if err := c.Bootstrap(ctx); err != nil {
		return fmt.Errorf("%w: schema write failed: %v", relationship.ErrModelMissing, err)
	}
	current, err := c.schema.ReadSchema(ctx, &v1.ReadSchemaRequest{})
	if err != nil {
		return fmt.Errorf("%w: %v", relationship.ErrBackendUnavailable, err)
	}
	if !schema.IsUpToDate(current.GetSchemaText()) {
		return fmt.Errorf("%w: spicedb schema drifted from embedded groundwork.zed", relationship.ErrModelMissing)
	}
	return nil
}

// Check implements relationship.Authorizer. Unknown permissions and
// malformed subjects/resources deny without touching the network;
// conditional results deny (fail closed); transport errors are
// classified into the relationship sentinels. The circuit breaker (when
// configured) short-circuits with ErrCircuitOpen before any network
// call.
func (c *Client) Check(ctx context.Context, req relationship.CheckRequest) (bool, error) {
	if err := relationship.ValidateSubject(req.Subject); err != nil {
		return false, nil
	}
	if err := relationship.ValidateResource(req.Resource); err != nil {
		return false, nil
	}
	switch req.Permission {
	case relationship.PermissionView, relationship.PermissionUse, relationship.PermissionExecute:
	default:
		// Unknown permission: deny. No schema name exists to check.
		return false, nil
	}
	err := c.guard(ctx, func(ctx context.Context) error {
		resp, err := c.perms.CheckPermission(ctx, &v1.CheckPermissionRequest{
			Consistency: c.consistency(),
			Resource:    encodeResource(req.TenantID, req.Resource),
			Permission:  checkPermissionName(req.Permission),
			Subject:     encodeSubject(req.TenantID, req.Subject),
		})
		if err != nil {
			return c.classify(err)
		}
		c.observeToken(resp.GetCheckedAt().GetToken())
		switch resp.GetPermissionship() {
		case v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION:
			return nil
		default:
			// NO_PERMISSION and CONDITIONAL_* all fail closed.
			return errDenied
		}
	})
	if errors.Is(err, errDenied) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// errDenied is an internal sentinel marking a successful-but-denied
// check, so the breaker reports the check as a success (a backend that
// answers NO is healthy).
var errDenied = errors.New("spicedb: denied")

// checkPermissionName maps a neutral permission onto the schema name the
// adapter checks. "view" resolves to the computed "view" permission
// (direct viewer ∪ folder inheritance via parent->view); "use"/"execute"
// resolve to the direct-only relations of the same name. The "view" ->
// "viewer" alias from PermissionToRelation does NOT apply here: SpiceDB
// names the computed userset "view", not "viewer".
func checkPermissionName(p string) string {
	return p
}

// Write implements relationship.Store. TOUCH makes writes idempotent;
// batches are chunked at writeChunkSize. The WrittenAt zed token of
// every batch is observed so at_least_as_fresh reads pin to at least
// the newest write — a check right after a write never sees a stale
// snapshot.
func (c *Client) Write(ctx context.Context, tenantID string, rels []relationship.Relationship) error {
	if len(rels) == 0 {
		return nil
	}
	return c.guard(ctx, func(ctx context.Context) error {
		for start := 0; start < len(rels); start += writeChunkSize {
			end := min(start+writeChunkSize, len(rels))
			updates := make([]*v1.RelationshipUpdate, 0, end-start)
			for _, rel := range rels[start:end] {
				updates = append(updates, &v1.RelationshipUpdate{
					Operation:    v1.RelationshipUpdate_OPERATION_TOUCH,
					Relationship: encodeRelationship(tenantID, rel),
				})
			}
			resp, err := c.perms.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{Updates: updates})
			if err != nil {
				return c.classify(err)
			}
			c.observeToken(resp.GetWrittenAt().GetToken())
		}
		return nil
	})
}

// Delete implements relationship.Store. Filter-based deletion is atomic
// per relationship and idempotent (deleting a missing tuple is a no-op).
func (c *Client) Delete(ctx context.Context, tenantID string, rels []relationship.Relationship) error {
	if len(rels) == 0 {
		return nil
	}
	return c.guard(ctx, func(ctx context.Context) error {
		for _, rel := range rels {
			_, err := c.perms.DeleteRelationships(ctx, &v1.DeleteRelationshipsRequest{
				RelationshipFilter: encodeFilter(tenantID, relationship.Filter{
					ResourceType: rel.Resource.Type,
					ResourceID:   rel.Resource.ID,
					Relation:     rel.Relation,
					SubjectType:  rel.Subject.Type,
					SubjectID:    rel.Subject.ID,
				}),
			})
			if err != nil {
				return c.classify(err)
			}
		}
		return nil
	})
}

// List implements relationship.Store. SpiceDB requires a resource type
// in its filter, so a wildcard resource type iterates the known
// relationship-bearing types (user has no relations and is skipped).
// Tenant composition is stripped from every returned relationship.
func (c *Client) List(ctx context.Context, tenantID string, f relationship.Filter) ([]relationship.Relationship, error) {
	types := []string{f.ResourceType}
	if f.ResourceType == "" {
		types = []string{
			relationship.TypeGroup,
			relationship.TypeFolder,
			relationship.TypeDocument,
			relationship.TypeTool,
			relationship.TypeToolAction,
		}
	}
	var out []relationship.Relationship
	err := c.guard(ctx, func(ctx context.Context) error {
		for _, typ := range types {
			stream, err := c.perms.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
				Consistency: c.consistency(),
				RelationshipFilter: encodeFilter(tenantID, relationship.Filter{
					ResourceType: typ,
					ResourceID:   f.ResourceID,
					Relation:     f.Relation,
					SubjectType:  f.SubjectType,
					SubjectID:    f.SubjectID,
				}),
			})
			if err != nil {
				return c.classify(err)
			}
			for {
				resp, err := stream.Recv()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return c.classify(err)
				}
				c.observeToken(resp.GetReadAt().GetToken())
				if rel, ok := decodeRelationship(resp.GetRelationship()); ok {
					out = append(out, rel)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// guard runs fn under the circuit breaker (when configured). Transport
// failures (the ErrBackend* sentinels, which classify produces) trip
// the breaker; everything else — validation, schema, denied — is a
// healthy response. Errors wrapped in errDenied are reported as
// successes and unwrapped for the caller.
func (c *Client) guard(ctx context.Context, fn func(ctx context.Context) error) error {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	if c.breaker != nil {
		if err := c.breaker.Allow(); err != nil {
			return fmt.Errorf("%w: %v", relationship.ErrBackendUnavailable, err)
		}
	}
	err := fn(ctx)
	if c.breaker != nil {
		switch {
		case err == nil || errors.Is(err, errDenied):
			c.breaker.ReportSuccess()
		case errors.Is(err, relationship.ErrBackendUnavailable) || errors.Is(err, relationship.ErrBackendTimeout):
			if c.breaker.ReportFailure() && c.onTrip != nil {
				c.onTrip()
			}
		}
	}
	return err
}

// consistency returns the read consistency for checks and lists based
// on the configured mode. at_least_as_fresh (the default) is
// token-tracked: reads pin to the newest zed token observed so far,
// falling back to minimize_latency until the first token is known.
func (c *Client) consistency() *v1.Consistency {
	switch c.consistencyMode {
	case ConsistencyAtLeastAsFresh:
		c.tokenMu.Lock()
		tok := c.zedToken
		c.tokenMu.Unlock()
		if tok != "" {
			return &v1.Consistency{Requirement: &v1.Consistency_AtLeastAsFresh{AtLeastAsFresh: &v1.ZedToken{Token: tok}}}
		}
		fallthrough
	case "", ConsistencyMinimizeLatency:
		return &v1.Consistency{Requirement: &v1.Consistency_MinimizeLatency{MinimizeLatency: true}}
	case ConsistencyFullyConsistent:
		return &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}}
	default:
		// Unreachable (validated at New); fail closed to a strict read.
		return &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}}
	}
}

// observeToken tracks the newest zed token for at_least_as_fresh reads.
func (c *Client) observeToken(tok string) {
	if c.consistencyMode != ConsistencyAtLeastAsFresh || tok == "" {
		return
	}
	c.tokenMu.Lock()
	c.zedToken = tok
	c.tokenMu.Unlock()
}

// withTimeout wraps ctx with the configured deadline unless it already
// carries one.
func (c *Client) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.timeout)
}

// classify maps gRPC failures onto the relationship sentinels. All other
// errors (validation, permission, schema) pass through unwrapped so
// callers can still distinguish them.
func (c *Client) classify(err error) error {
	switch status.Code(err) {
	case codes.Unavailable, codes.Aborted, codes.FailedPrecondition, codes.Unknown:
		return fmt.Errorf("%w: %v", relationship.ErrBackendUnavailable, err)
	case codes.DeadlineExceeded:
		return fmt.Errorf("%w: %v", relationship.ErrBackendTimeout, err)
	default:
		return err
	}
}

// scopeID composes tenant + id into the on-wire form
// EscapeID(tenant) + "/" + EscapeID(id). EscapeID hex-escapes "/" and
// "=" (plus every byte outside [a-zA-Z0-9_-]), so neither part can
// contain a literal "/" and the first "/" is always the tenant
// boundary — decomposition is unambiguous even for composite IDs like
// tool_action "<tool>:<action>".
func scopeID(tenantID, id string) string {
	if tenantID == "" {
		return relationship.EscapeID(id)
	}
	return relationship.EscapeID(tenantID) + "/" + relationship.EscapeID(id)
}

// unscopeID strips the tenant boundary produced by scopeID.
func unscopeID(scoped string) string {
	if _, raw, ok := strings.Cut(scoped, "/"); ok {
		return relationship.UnescapeID(raw)
	}
	return relationship.UnescapeID(scoped)
}

func encodeResource(tenantID string, r relationship.ResourceRef) *v1.ObjectReference {
	return &v1.ObjectReference{ObjectType: r.Type, ObjectId: scopeID(tenantID, r.ID)}
}

func encodeSubject(tenantID string, s relationship.SubjectRef) *v1.SubjectReference {
	ref := &v1.SubjectReference{
		Object: &v1.ObjectReference{ObjectType: s.Type, ObjectId: scopeID(tenantID, s.ID)},
	}
	if s.Relation != "" {
		ref.OptionalRelation = s.Relation
	}
	return ref
}

func encodeRelationship(tenantID string, rel relationship.Relationship) *v1.Relationship {
	return &v1.Relationship{
		Resource: encodeResource(tenantID, rel.Resource),
		Relation: rel.Relation,
		Subject:  encodeSubject(tenantID, rel.Subject),
	}
}

func encodeFilter(tenantID string, f relationship.Filter) *v1.RelationshipFilter {
	filter := &v1.RelationshipFilter{ResourceType: f.ResourceType}
	if f.ResourceID != "" {
		filter.OptionalResourceId = scopeID(tenantID, f.ResourceID)
	}
	if f.Relation != "" {
		filter.OptionalRelation = f.Relation
	}
	if f.SubjectType != "" || f.SubjectID != "" {
		sf := &v1.SubjectFilter{SubjectType: f.SubjectType}
		if f.SubjectID != "" {
			sf.OptionalSubjectId = scopeID(tenantID, f.SubjectID)
		}
		filter.OptionalSubjectFilter = sf
	}
	return filter
}

func decodeRelationship(r *v1.Relationship) (relationship.Relationship, bool) {
	if r == nil || r.GetResource() == nil || r.GetSubject() == nil || r.GetSubject().GetObject() == nil {
		return relationship.Relationship{}, false
	}
	return relationship.Relationship{
		Resource: relationship.ResourceRef{
			Type: r.GetResource().GetObjectType(),
			ID:   unscopeID(r.GetResource().GetObjectId()),
		},
		Relation: r.GetRelation(),
		Subject: relationship.SubjectRef{
			Type:     r.GetSubject().GetObject().GetObjectType(),
			ID:       unscopeID(r.GetSubject().GetObject().GetObjectId()),
			Relation: r.GetSubject().GetOptionalRelation(),
		},
	}, true
}

// bearerToken attaches the SpiceDB preshared key to every RPC.
type bearerToken struct{ token string }

func (b bearerToken) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + b.token}, nil
}

func (b bearerToken) RequireTransportSecurity() bool { return false }
