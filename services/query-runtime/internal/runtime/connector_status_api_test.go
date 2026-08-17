package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"groundwork/query-runtime/internal/aclsync"
)

func TestConnectorStatus(t *testing.T) {
	server := newTestServer(Config{})
	store := aclsync.NewMemoryInstallationStore()
	server.SetConnectorStatusStore(store)

	// Tenant scoping: another tenant's installation must never leak.
	if err := store.Upsert(context.Background(), acls[0]); err != nil {
		t.Fatalf("upsert other tenant: %v", err)
	}
	inst := acls[1] // tenant_demo installation
	if err := store.Upsert(context.Background(), inst); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/connectors/status", nil)
	req.Header.Set("X-Groundwork-API-Key", "gw_test_key")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Installations []connectorStatusView `json:"installations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Installations) != 1 {
		t.Fatalf("expected 1 installation (tenant isolation), got %d: %s", len(resp.Installations), rec.Body.String())
	}
	v := resp.Installations[0]
	if v.Provider != "msgraph" {
		t.Fatalf("expected provider msgraph, got %s", v.Provider)
	}
	if v.CredentialScheme != "keyring" {
		t.Fatalf("expected credential scheme keyring, got %s", v.CredentialScheme)
	}
	if !v.DeltaCursor {
		t.Fatalf("expected delta cursor present")
	}
	if v.LastSuccessAgeSec < 0 {
		t.Fatalf("expected last success age >= 0, got %d", v.LastSuccessAgeSec)
	}
	if v.CredentialExpires == "" {
		t.Fatalf("expected credential expiry in view")
	}
}

func TestConnectorStatusUnwired(t *testing.T) {
	server := newTestServer(Config{})
	req := httptest.NewRequest(http.MethodGet, "/v1/connectors/status", nil)
	req.Header.Set("X-Groundwork-API-Key", "gw_test_key")
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no store wired, got %d", rec.Code)
	}
}

// acls is a shared fixture for installation-registry tests.
var acls = []aclsync.Installation{
	{
		TenantID:      "tenant_other",
		Provider:      "msgraph",
		Status:        aclsync.InstallationActive,
		CredentialRef: "keyring://connector/msgraph",
	},
	{
		TenantID:       "tenant_demo",
		Provider:       "msgraph",
		Status:         aclsync.InstallationActive,
		CredentialRef:  "keyring://connector/msgraph",
		CredentialTTL:  time.Now().UTC().Add(30 * 24 * time.Hour),
		DeltaCursor:    "tok123",
		LastSuccessAt:  time.Now().UTC().Add(-90 * time.Second),
		SyncLagSeconds: 12,
		DriftItems:     0,
		Region:         "uk",
	},
}
