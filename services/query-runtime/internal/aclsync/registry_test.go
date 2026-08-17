package aclsync

import (
	"context"
	"testing"
	"time"
)

func TestMemoryInstallationStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryInstallationStore()

	if _, err := store.Get(ctx, "t1", "msgraph"); err != ErrInstallationNotFound {
		t.Fatalf("missing installation: got %v, want ErrInstallationNotFound", err)
	}

	inst := Installation{
		TenantID:      "t1",
		Provider:      "msgraph",
		Status:        InstallationActive,
		CredentialRef: "keyring://connector/msgraph/t1",
		DeltaCursor:   "delta-link-1",
	}
	if err := store.Upsert(ctx, inst); err != nil {
		t.Fatal(err)
	}

	got, err := store.Get(ctx, "t1", "msgraph")
	if err != nil {
		t.Fatal(err)
	}
	if got.CredentialRef != "keyring://connector/msgraph/t1" {
		t.Fatalf("credential ref mismatch: %q", got.CredentialRef)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("created_at must be stamped")
	}

	now := time.Now().UTC()
	if err := store.UpdateHealth(ctx, "t1", "msgraph", HealthUpdate{
		Status:         InstallationDegraded,
		DeltaCursor:    "delta-link-2",
		LastSuccessAt:  now,
		SyncLagSeconds: 42,
		DriftItems:     7,
		LastError:      "graph 500",
	}); err != nil {
		t.Fatal(err)
	}
	got, _ = store.Get(ctx, "t1", "msgraph")
	if got.Status != InstallationDegraded || got.DeltaCursor != "delta-link-2" ||
		got.SyncLagSeconds != 42 || got.DriftItems != 7 || got.LastError != "graph 500" {
		t.Fatalf("health update not applied: %+v", got)
	}

	// UpdateHealth on a missing installation fails closed.
	if err := store.UpdateHealth(ctx, "t1", "s3", HealthUpdate{Status: InstallationActive}); err != ErrInstallationNotFound {
		t.Fatalf("missing health update: got %v, want ErrInstallationNotFound", err)
	}

	list, err := store.List(ctx, "msgraph")
	if err != nil || len(list) != 1 {
		t.Fatalf("list: n=%d err=%v", len(list), err)
	}
	list, _ = store.List(ctx, "s3")
	if len(list) != 0 {
		t.Fatalf("provider filter: got %d, want 0", len(list))
	}
}

func TestUpsertNormalizesInvalidStatus(t *testing.T) {
	store := NewMemoryInstallationStore()
	if err := store.Upsert(context.Background(), Installation{
		TenantID: "t1", Provider: "s3", Status: "bogus",
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(context.Background(), "t1", "s3")
	if got.Status != InstallationPending {
		t.Fatalf("invalid status must normalize to pending, got %q", got.Status)
	}
}

func TestIsKeyringRef(t *testing.T) {
	for _, ref := range []string{
		"keyring://connector/msgraph/t1",
		"secretsmanager://connector/msgraph",
		"aws:secretsmanager:connector-msgraph",
		"gcp:secretmanager:connector-msgraph",
		"vault://secret/connector/msgraph",
	} {
		if !IsKeyringRef(ref) {
			t.Fatalf("%q must be a keyring/secret-manager ref", ref)
		}
	}
	for _, ref := range []string{"", "MS_GRAPH_CLIENT_SECRET", "plaintext-value", "s3://bucket/key"} {
		if IsKeyringRef(ref) {
			t.Fatalf("%q must NOT be a keyring/secret-manager ref", ref)
		}
	}
}
