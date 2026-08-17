package msgraph

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"groundwork/query-runtime/internal/aclsync"
	"groundwork/query-runtime/internal/aclsync/contract"
)

// TestConnectorContract runs the Milestone 4 contract suite against the
// real HTTP client bound to the fake Graph server (fast delta poll so the
// delta surface emits within the suite window). Every connector must
// pass this suite.
func TestConnectorContract(t *testing.T) {
	srv := newFakeGraphServer()
	srv.users = []GraphUser{
		{ID: "u-fin", Mail: "finance_user"},
		{ID: "u-gen", Mail: "general_user"},
	}
	srv.groups = []GraphGroup{{ID: "finance"}}
	srv.members["finance"] = []GraphMember{{ID: "u-fin", Mail: "finance_user", Type: MemberUser}}
	srv.items = []GraphDriveItem{
		{ID: "finance-folder", IsFolder: true},
		{ID: "security-policy", ParentID: "finance-folder"},
	}
	srv.perms["finance-folder"] = []GraphPermission{{Roles: []string{"read"}, Grantee: GraphGrantee{GroupID: "finance"}}}
	srv.perms["security-policy"] = []GraphPermission{{Roles: []string{"read"}, Grantee: GraphGrantee{UserID: "u-fin"}}}
	srv.deltaLink = "delta-link-1"
	// Seed a deletion so the delta surface emits an event within the
	// suite window (the suite's snapshot refreshes the snapshot store
	// with security-policy's grantee, which the tombstone revokes).
	srv.delta = []GraphDeltaItem{{ID: "security-policy", ParentID: "finance-folder", Deleted: true}}

	ts := httptest.NewServer(srv.handler(nil))
	defer ts.Close()

	cfg := Config{
		TenantID:         "contract_test_tenant",
		ClientID:         "client-id",
		ClientSecret:     "client-secret",
		DriveID:          "drive1",
		AuthorityHost:    ts.URL,
		GraphBaseURL:     ts.URL + "/v1.0",
		DeltaPollSeconds: 1,
		Enabled:          true,
	}
	conn := NewConnector(NewHTTPGraphClient(cfg), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), NewMemoryDeltaTokenStore())
	conn.SetSnapshotStore(NewMemoryPermissionSnapshotStore())
	conn.SetInstallationStore(aclsync.NewMemoryInstallationStore())
	conn.SetDeltaTokenStore(NewMemoryDeltaTokenStore())

	contract.RunContractTests(t, conn)
}

// TestConnectorDescriptorSurface checks the versioned descriptor
// statically (without I/O): auth spec, capabilities, subset.
func TestConnectorDescriptorSurface(t *testing.T) {
	conn := NewConnector(&fakeGraphClient{}, Config{TenantID: "t", DeltaPollSeconds: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	d := conn.Descriptor()
	if d.Provider != "msgraph" {
		t.Fatalf("provider = %q, want msgraph", d.Provider)
	}
	if d.ContractVersion != contract.Version {
		t.Fatalf("contract version = %q", d.ContractVersion)
	}
	if d.Auth.Method != contract.AuthOAuth2ClientCredentials {
		t.Fatalf("auth method = %q", d.Auth.Method)
	}
	if !d.Auth.HasScheme(contract.SchemeKeyring) {
		t.Fatal("must support keyring references")
	}
	if !d.HasCapability(contract.CapabilityDelta) || !d.HasCapability(contract.CapabilityTombstones) {
		t.Fatal("must declare delta + tombstone capabilities")
	}
	if !d.HasCapability(contract.CapabilityEffectivePermissions) {
		t.Fatal("msgraph proves per-user effective permissions and must declare it")
	}
	if !d.FailClosedOutsideSubset || d.SupportedSubset == "" {
		t.Fatal("must document a fail-closed supported subset")
	}
	if err := contract.Validate(conn); err != nil {
		t.Fatalf("descriptor fails contract validation: %v", err)
	}
}

// TestConnectorAuthFailureTaxonomy proves the real client's auth failure
// classifies as KindAuth (fail-closed) through the shared taxonomy.
func TestConnectorAuthFailureTaxonomy(t *testing.T) {
	srv := newFakeGraphServer()
	srv.failAuth = true
	ts := httptest.NewServer(srv.handler(nil))
	defer ts.Close()

	cfg := Config{
		TenantID:      "contract_test_tenant",
		ClientID:      "client-id",
		ClientSecret:  "wrong-secret",
		DriveID:       "drive1",
		AuthorityHost: ts.URL,
		GraphBaseURL:  ts.URL + "/v1.0",
		Enabled:       true,
	}
	conn := NewConnector(NewHTTPGraphClient(cfg), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), NewMemoryDeltaTokenStore())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := conn.Snapshot(ctx, "contract_test_tenant")
	if err == nil {
		t.Fatal("expected auth failure")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
	if contract.KindOf(err) != contract.KindAuth {
		t.Fatalf("auth failure must classify as KindAuth, got %q", contract.KindOf(err))
	}
	if !contract.FailsClosed(err) {
		t.Fatal("auth failure must fail closed")
	}
	if contract.IsRetryable(err) {
		t.Fatal("auth failure must not be retryable")
	}
}

// TestConnectorErrorTaxonomyAndEvidence runs the shared taxonomy and
// evidence-schema checks (same suite every connector runs).
func TestConnectorErrorTaxonomyAndEvidence(t *testing.T) {
	contract.RunErrorTaxonomyTests(t)
	contract.RunEvidenceSchemaTests(t)
}

// fakeGraphClient is the no-op client used for descriptor-only tests.
type fakeGraphClient struct{}

func (f *fakeGraphClient) ListUsers(context.Context) ([]GraphUser, error)   { return nil, nil }
func (f *fakeGraphClient) ListGroups(context.Context) ([]GraphGroup, error) { return nil, nil }
func (f *fakeGraphClient) ListGroupMembers(context.Context, string) ([]GraphMember, error) {
	return nil, nil
}
func (f *fakeGraphClient) ListDriveItems(context.Context) ([]GraphDriveItem, error) { return nil, nil }
func (f *fakeGraphClient) ListItemPermissions(context.Context, string) ([]GraphPermission, error) {
	return nil, nil
}
func (f *fakeGraphClient) DeltaDriveItems(context.Context, string) ([]GraphDeltaItem, string, error) {
	return nil, "", nil
}
