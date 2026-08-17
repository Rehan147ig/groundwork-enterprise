package contract_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"groundwork/query-runtime/internal/aclsync"
	"groundwork/query-runtime/internal/aclsync/contract"
)

// versionedMock is a minimal VersionedConnector used to exercise the
// contract suite itself. It models the aclsync mock's dataset.
type versionedMock struct {
	mu      sync.Mutex
	set     aclsync.PermissionSet
	changes chan aclsync.PermissionChange
}

func newVersionedMock() *versionedMock {
	return &versionedMock{
		changes: make(chan aclsync.PermissionChange, 8),
		set: aclsync.PermissionSet{
			Users: []string{"finance_user", "general_user"},
			Groups: []aclsync.Group{
				{ID: "finance", MemberUsers: []string{"finance_user"}},
				{ID: "employees", MemberUsers: []string{"general_user"}, MemberGroups: []string{"finance"}},
			},
			Folders: []aclsync.Folder{
				{ID: "finance-folder", ViewerGroups: []string{"finance"}},
			},
			Documents: []aclsync.Document{
				{ID: "security-policy", FolderID: "finance-folder"},
			},
		},
	}
}

func (m *versionedMock) Descriptor() contract.ProviderDescriptor {
	return contract.ProviderDescriptor{
		Provider:                "mock",
		ContractVersion:         contract.Version,
		Status:                  contract.ConnectorStatusExperimental,
		Auth:                    contract.AuthSpec{Method: contract.AuthNone},
		Capabilities:            []contract.Capability{contract.CapabilityGroups, contract.CapabilityFolders, contract.CapabilityDelta},
		SupportedSubset:         "mock enterprise source; no external identities",
		FailClosedOutsideSubset: true,
		Retry:                   contract.RetryPolicy{Base: 250 * time.Millisecond, Max: 5 * time.Second, DefaultTimeout: 10 * time.Second},
	}
}

func (m *versionedMock) Snapshot(_ context.Context, tenantID string) (aclsync.PermissionSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ps := m.set
	ps.TenantID = tenantID
	return ps, nil
}

func (m *versionedMock) ListDocuments(_ context.Context, _ string) ([]aclsync.Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]aclsync.Document, len(m.set.Documents))
	copy(out, m.set.Documents)
	return out, nil
}

func (m *versionedMock) GetDocumentPermissions(_ context.Context, _ string, documentID string) (aclsync.DocumentPermissions, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.set.Documents {
		if d.ID == documentID {
			return aclsync.DocumentPermissions{DocumentID: d.ID, FolderID: d.FolderID, ViewerGroups: append([]string{}, d.ViewerGroups...)}, nil
		}
	}
	return aclsync.DocumentPermissions{}, nil
}

func (m *versionedMock) WatchPermissionChanges(_ context.Context, _ string) (<-chan aclsync.PermissionChange, error) {
	return m.changes, nil
}

func (m *versionedMock) WatchEvents(_ context.Context, tenantID string) (<-chan contract.ChangeEvent, error) {
	ch := make(chan contract.ChangeEvent, 4)
	ch <- contract.NewChangeEvent(tenantID, 1, time.Now().UTC(), false, "security-policy",
		aclsync.PermissionChange{Type: aclsync.ChangeAddGroupMember, Subject: "user:finance_user", Object: "group:finance"})
	close(ch)
	return ch, nil
}

var _ contract.VersionedConnector = (*versionedMock)(nil)
var _ contract.EventSource = (*versionedMock)(nil)

func TestRunContractTests(t *testing.T) {
	contract.RunContractTests(t, newVersionedMock())
}

func TestRunErrorTaxonomyTests(t *testing.T) {
	contract.RunErrorTaxonomyTests(t)
}

func TestRunEvidenceSchemaTests(t *testing.T) {
	contract.RunEvidenceSchemaTests(t)
}

func TestValidateRejectsBadDescriptor(t *testing.T) {
	m := newVersionedMock()
	// Break the descriptor: no subset, no fail-closed flag.
	m.set.Groups = m.set.Groups[:0] // keep mock functional; descriptor is what matters
	broken := &descriptorBroken{VersionedConnector: m}
	if err := contract.Validate(broken); err == nil {
		t.Fatal("expected validation failure for a connector without fail-closed subset")
	}
}

// descriptorBroken returns a descriptor that violates the contract.
type descriptorBroken struct {
	contract.VersionedConnector
}

func (b *descriptorBroken) Descriptor() contract.ProviderDescriptor {
	d := b.VersionedConnector.Descriptor()
	d.SupportedSubset = ""
	d.FailClosedOutsideSubset = false
	return d
}

func TestValidateRejectsMissingStatus(t *testing.T) {
	m := newVersionedMock()
	missing := &statusMissing{VersionedConnector: m}
	if err := contract.Validate(missing); err == nil {
		t.Fatal("expected validation failure: connector status must be declared")
	}
}

// statusMissing drops the status classification.
type statusMissing struct {
	contract.VersionedConnector
}

func (s *statusMissing) Descriptor() contract.ProviderDescriptor {
	d := s.VersionedConnector.Descriptor()
	d.Status = ""
	return d
}

func TestValidateRejectsDeltaWithoutEventSource(t *testing.T) {
	m := newVersionedMock()
	noEvents := &noEventSource{VersionedConnector: m}
	if err := contract.Validate(noEvents); err == nil {
		t.Fatal("expected validation failure: delta declared but EventSource missing")
	}
}

// noEventSource hides the EventSource implementation.
type noEventSource struct {
	contract.VersionedConnector
}

func (n *noEventSource) Descriptor() contract.ProviderDescriptor {
	d := n.VersionedConnector.Descriptor()
	d.Capabilities = []contract.Capability{contract.CapabilityDelta}
	return d
}

// TestWrapConnector proves the SDK adapter turns a plain aclsync
// connector into a versioned one without the aclsync package importing
// the contract.
func TestWrapConnector(t *testing.T) {
	plain := newVersionedMock() // implements aclsync.Connector (and EventSource)
	d := plain.Descriptor()
	wrapped := contract.WrapConnector(plain, d)
	if !contract.IsVersioned(wrapped) {
		t.Fatal("WrapConnector must produce a VersionedConnector")
	}
	if contract.ProviderOf(wrapped) != "mock" {
		t.Fatalf("ProviderOf = %q, want mock", contract.ProviderOf(wrapped))
	}
	if err := contract.Validate(wrapped); err != nil {
		t.Fatalf("wrapped connector must validate: %v", err)
	}
}

func TestSecretRefOK(t *testing.T) {
	d := contract.ProviderDescriptor{
		Auth: contract.AuthSpec{
			Method:           contract.AuthOAuth2ClientCredentials,
			SecretRefSchemes: []contract.SecretRefScheme{contract.SchemeKeyring, contract.SchemeSecretsManager},
		},
	}
	if !contract.SecretRefOK(d, "keyring://connector/mock") {
		t.Fatal("keyring ref must be acceptable")
	}
	if !contract.SecretRefOK(d, "aws:secretsmanager:mock/cred") {
		t.Fatal("secrets-manager ref must be acceptable")
	}
	if contract.SecretRefOK(d, "plaintext-secret") {
		t.Fatal("plaintext value must be rejected unless env scheme is allowed")
	}
	env := contract.ProviderDescriptor{Auth: contract.AuthSpec{Method: contract.AuthAPIKey, SecretRefSchemes: []contract.SecretRefScheme{contract.SchemeEnv}}}
	if !contract.SecretRefOK(env, "env://MOCK_TOKEN") {
		t.Fatal("env ref must be acceptable when the env scheme is declared (dev only)")
	}
	if contract.SecretRefOK(env, "keyring://x") {
		t.Fatal("keyring ref must be rejected when not declared")
	}
}
