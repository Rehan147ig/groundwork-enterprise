package connectors

import (
	"context"
	"testing"
	"time"

	"groundwork/query-runtime/internal/runtime"
)

// expiryHarness builds a registry with two connectors (one with a
// keyring secret, one without) and a resolver that can date refs.
func expiryHarness() (*MemoryStore, *fakeSecretResolver) {
	store := NewMemoryStore()
	secrets := &fakeSecretResolver{expires: map[string]time.Time{
		"keyring://stripe_api": time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	}}
	mk := func(id, name, tenantID, secretRef string) runtime.Connector {
		return runtime.Connector{
			ID: id, TenantID: tenantID, Name: name, Type: runtime.ConnectorTypeREST,
			Lifecycle: runtime.ConnectorLifecycleActive, BaseURL: "https://example.com",
			Region: "us", OwnerPrincipalID: "principal:op", SecretRef: secretRef,
			CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}
	}
	_ = store.CreateConnector(context.Background(), mk("conn-0001", "stripe", "tenant-a", "keyring://stripe_api"),
		runtime.ConnectorVersion{ID: "v1", ConnectorID: "conn-0001", TenantID: "tenant-a"},
		[]runtime.ConnectorActionManifest{{Name: "ping"}},
		runtime.ConnectorLifecycleEvent{TenantID: "tenant-a", ConnectorID: "conn-0001", ActionType: "create"})
	_ = store.CreateConnector(context.Background(), mk("conn-0002", "no-secret", "tenant-a", ""),
		runtime.ConnectorVersion{ID: "v1", ConnectorID: "conn-0002", TenantID: "tenant-a"},
		[]runtime.ConnectorActionManifest{{Name: "ping"}},
		runtime.ConnectorLifecycleEvent{TenantID: "tenant-a", ConnectorID: "conn-0002", ActionType: "create"})
	_ = store.CreateConnector(context.Background(), mk("conn-0003", "env", "tenant-b", "env://SLACK_TOKEN"),
		runtime.ConnectorVersion{ID: "v1", ConnectorID: "conn-0003", TenantID: "tenant-b"},
		[]runtime.ConnectorActionManifest{{Name: "ping"}},
		runtime.ConnectorLifecycleEvent{TenantID: "tenant-b", ConnectorID: "conn-0003", ActionType: "create"})
	return store, secrets
}

// TestCredentialExpiryScannerDatesReferences: keyring refs resolve to
// the purpose expiry; env refs and connectors without secrets carry no
// expiry; the scan spans tenants.
func TestCredentialExpiryScannerDatesReferences(t *testing.T) {
	store, secrets := expiryHarness()
	scanner := NewCredentialExpiryScanner(store, secrets)
	reports, err := scanner.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(reports) != 2 {
		t.Fatalf("expected 2 dated connectors (no-secret skipped), got %d", len(reports))
	}
	byID := map[string]CredentialExpiryReport{}
	for _, r := range reports {
		byID[r.ConnectorID] = r
	}
	got := byID["conn-0001"]
	if got.TenantID != "tenant-a" || got.SecretRef != "keyring://stripe_api" {
		t.Fatalf("unexpected report: %+v", got)
	}
	if want := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC); !got.Expiry.Equal(want) {
		t.Fatalf("expiry = %v, want %v", got.Expiry, want)
	}
	if env := byID["conn-0003"]; !env.Expiry.IsZero() {
		t.Fatalf("env:// material has no expiry metadata, got %v", env.Expiry)
	}
}

// TestCredentialExpiryScannerExpiredAndUndated: an expired ref is
// reported (negative days-until feeds the alert); an unknown ref dates
// zero without failing the scan.
func TestCredentialExpiryScannerExpiredAndUndated(t *testing.T) {
	store := NewMemoryStore()
	secrets := &fakeSecretResolver{expires: map[string]time.Time{
		"keyring://stripe_api": time.Now().Add(-48 * time.Hour),
	}}
	mk := func(id, name, ref string) runtime.Connector {
		return runtime.Connector{ID: id, TenantID: "t", Name: name, Type: runtime.ConnectorTypeREST,
			Lifecycle: runtime.ConnectorLifecycleActive, SecretRef: ref,
			CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	}
	_ = store.CreateConnector(context.Background(), mk("conn-0001", "stripe", "keyring://stripe_api"),
		runtime.ConnectorVersion{ID: "v1", ConnectorID: "conn-0001", TenantID: "t"},
		[]runtime.ConnectorActionManifest{{Name: "ping"}}, runtime.ConnectorLifecycleEvent{TenantID: "t", ConnectorID: "conn-0001"})
	_ = store.CreateConnector(context.Background(), mk("conn-0002", "other", "keyring://unknown_purpose"),
		runtime.ConnectorVersion{ID: "v1", ConnectorID: "conn-0002", TenantID: "t"},
		[]runtime.ConnectorActionManifest{{Name: "ping"}}, runtime.ConnectorLifecycleEvent{TenantID: "t", ConnectorID: "conn-0002"})

	reports, err := NewCredentialExpiryScanner(store, secrets).Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	for _, r := range reports {
		if r.ConnectorID == "conn-0001" && r.Expiry.After(time.Now()) {
			t.Fatalf("expired credential must report a past expiry, got %v", r.Expiry)
		}
		if r.ConnectorID == "conn-0002" && !r.Expiry.IsZero() {
			t.Fatalf("undated ref must report zero, got %v", r.Expiry)
		}
	}
}

// TestCredentialExpiryScannerEmptyRegistry: an empty registry yields no
// reports and no error.
func TestCredentialExpiryScannerEmptyRegistry(t *testing.T) {
	reports, err := NewCredentialExpiryScanner(NewMemoryStore(), &fakeSecretResolver{}).Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(reports) != 0 {
		t.Fatalf("expected no reports, got %d", len(reports))
	}
}

// TestListAllConnectorsSpansTenants: the cross-tenant list is the
// monitor's data source (never exposed through tenant handlers).
func TestListAllConnectorsSpansTenants(t *testing.T) {
	store, _ := expiryHarness()
	conns, err := store.ListAllConnectors(context.Background())
	if err != nil {
		t.Fatalf("ListAllConnectors: %v", err)
	}
	if len(conns) != 3 {
		t.Fatalf("expected 3 connectors across tenants, got %d", len(conns))
	}
	tenants := map[string]bool{}
	for _, c := range conns {
		tenants[c.TenantID] = true
	}
	if !tenants["tenant-a"] || !tenants["tenant-b"] {
		t.Fatalf("expected connectors from both tenants, got %v", tenants)
	}
}
