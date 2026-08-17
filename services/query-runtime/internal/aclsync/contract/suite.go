package contract

import (
	"context"
	"testing"
	"time"

	"groundwork/query-runtime/internal/aclsync"
)

// RunContractTests is the contract test suite every Groundwork
// connector must pass. Connector packages call it from their own test
// files (e.g. TestConnectorContract = contract.RunContractTests(t, c)).
// It verifies the descriptor, the versioned read surface, snapshot
// semantics (tenant binding, stable resource IDs, full inventory),
// delta/tombstone capability claims, and error taxonomy behavior.
//
// The suite never calls the network: providers that need a live source
// must pass a connector bound to their fake server (as msgraph does in
// graph_http_test.go).
func RunContractTests(t testing.TB, c VersionedConnector) {
	t.Helper()

	// --- Descriptor ---
	d := c.Descriptor()
	if err := Validate(c); err != nil {
		t.Fatalf("connector fails contract validation: %v", err)
	}
	if d.ContractVersion != Version {
		t.Fatalf("descriptor contract version = %q, want %q", d.ContractVersion, Version)
	}
	if d.Provider == "" {
		t.Fatal("descriptor provider name is empty")
	}
	if d.SupportedSubset == "" {
		t.Fatal("descriptor must document its supported subset")
	}
	if !d.FailClosedOutsideSubset {
		t.Fatal("descriptor must declare FailClosedOutsideSubset=true (unmodeled features deny)")
	}
	if d.Auth.RequiresSecret() {
		if len(d.Auth.SecretRefSchemes) == 0 {
			t.Fatal("auth requires a secret but no secret-reference schemes are declared")
		}
		if !d.Auth.HasScheme(SchemeKeyring) && !d.Auth.HasScheme(SchemeSecretsManager) {
			t.Fatalf("auth must support keyring or a secrets manager, got %v", d.Auth.SecretRefSchemes)
		}
	}
	if err := d.Retry.Validate(); err != nil {
		t.Fatalf("retry policy invalid: %v", err)
	}

	// --- Snapshot: tenant-bound, complete, stable ---
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	const tenant = "contract_test_tenant"
	ps, err := c.Snapshot(ctx, tenant)
	if err != nil {
		t.Fatalf("Snapshot(%q) failed: %v", tenant, err)
	}
	if ps.TenantID != tenant {
		t.Fatalf("snapshot TenantID = %q, want %q (tenant binding)", ps.TenantID, tenant)
	}
	if ps.Users == nil || ps.Groups == nil || ps.Folders == nil || ps.Documents == nil {
		t.Fatal("snapshot must return complete (non-nil) inventory slices, not partial data")
	}

	// --- Stable source/resource IDs ---
	docs1, err := c.ListDocuments(ctx, tenant)
	if err != nil {
		t.Fatalf("ListDocuments failed: %v", err)
	}
	docs2, err := c.ListDocuments(ctx, tenant)
	if err != nil {
		t.Fatalf("ListDocuments (second call) failed: %v", err)
	}
	if len(docs1) != len(docs2) {
		t.Fatalf("document inventory size changed between reads (%d -> %d)", len(docs1), len(docs2))
	}
	for i := range docs1 {
		if docs1[i].ID != docs2[i].ID {
			t.Fatalf("resource IDs not stable across reads: %q then %q", docs1[i].ID, docs2[i].ID)
		}
	}

	// --- Snapshot maps to tuples without error ---
	tuples := aclsync.PermissionSetToTuples(ps)
	for i, tup := range tuples {
		if tup.User == "" || tup.Relation == "" || tup.Object == "" {
			t.Fatalf("tuple %d malformed: %+v", i, tup)
		}
	}

	// --- Per-document reads ---
	if len(docs1) > 0 {
		perms, err := c.GetDocumentPermissions(ctx, tenant, docs1[0].ID)
		if err != nil {
			t.Fatalf("GetDocumentPermissions failed: %v", err)
		}
		if perms.DocumentID != docs1[0].ID {
			t.Fatalf("GetDocumentPermissions returned document %q, want %q", perms.DocumentID, docs1[0].ID)
		}
	}

	// --- Delta surface (if declared) ---
	if d.HasCapability(CapabilityDelta) {
		es := EventSourceOf(c)
		if es == nil {
			t.Fatal("descriptor declares delta but connector does not implement EventSource")
		}
		evCtx, evCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer evCancel()
		ch, err := es.WatchEvents(evCtx, tenant)
		if err != nil {
			t.Fatalf("WatchEvents failed: %v", err)
		}
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("WatchEvents channel closed immediately")
			}
			if ev.ContractVersion != Version {
				t.Fatalf("event contract version = %q, want %q", ev.ContractVersion, Version)
			}
			if ev.ID == "" {
				t.Fatal("change event must carry a replay-protection ID")
			}
			if ev.Change.Subject == "" || ev.Change.Object == "" {
				t.Fatalf("change event has empty subject/object: %+v", ev.Change)
			}
			if ev.Tombstone && !d.HasCapability(CapabilityTombstones) {
				t.Fatal("tombstone event emitted without declaring CapabilityTombstones")
			}
			if ev.OccurredAt.IsZero() {
				t.Fatal("change event must carry OccurredAt")
			}
		case <-evCtx.Done():
			t.Fatal("WatchEvents produced no event within the suite window (delta declared but silent)")
		}
		if d.HasCapability(CapabilityTombstones) && !d.HasCapability(CapabilityDelta) {
			t.Fatal("tombstones require delta")
		}
	}
}

// RunErrorTaxonomyTests verifies the shared error classification. Every
// connector's tests run it to prove the service-side classification
// works on provider-produced errors.
func RunErrorTaxonomyTests(t testing.TB) {
	t.Helper()
	auth := Wrap(KindAuth, &connErr{msg: "oauth2: token exchange failed: 401 unauthorized"})
	if KindOf(auth) != KindAuth {
		t.Fatalf("KindOf(auth error) = %q, want auth", KindOf(auth))
	}
	if IsRetryable(auth) {
		t.Fatal("auth errors must not be retryable")
	}
	if !FailsClosed(auth) {
		t.Fatal("auth errors must fail closed")
	}

	rate := NewConnectorError(KindRateLimited, "provider throttled")
	if KindOf(rate) != KindRateLimited || !IsRetryable(rate) || FailsClosed(rate) {
		t.Fatalf("rate-limited classification wrong: kind=%q retryable=%v failClosed=%v", KindOf(rate), IsRetryable(rate), FailsClosed(rate))
	}

	unsupported := ErrUnsupportedFeature
	if KindOf(unsupported) != KindUnsupported || !FailsClosed(unsupported) {
		t.Fatalf("unsupported-feature classification wrong: kind=%q failClosed=%v", KindOf(unsupported), FailsClosed(unsupported))
	}

	timeout := Wrap(KindTimeout, &connErr{msg: "context deadline exceeded"})
	if KindOf(timeout) != KindTimeout || !IsRetryable(timeout) {
		t.Fatalf("timeout classification wrong: kind=%q retryable=%v", KindOf(timeout), IsRetryable(timeout))
	}

	if KindOf(&connErr{msg: "http 404 not found"}) != KindNotFound {
		t.Fatal("404 must classify as not_found")
	}
	if KindOf(&connErr{msg: "http 429 too many requests"}) != KindRateLimited {
		t.Fatal("429 must classify as rate_limited")
	}
	if KindOf(&connErr{msg: "unrecognized provider garbage"}) != KindPermanent {
		t.Fatal("unrecognized errors must classify as permanent")
	}
}

// RunEvidenceSchemaTests verifies the evidence event schema mapping.
func RunEvidenceSchemaTests(t testing.TB) {
	t.Helper()
	ev := NewChangeEvent("tenant_1", 7, time.Now().UTC(), false, "doc:7",
		aclsync.PermissionChange{Type: aclsync.ChangeRevokeDocumentViewer, Subject: "user:u", Object: "document:d"})
	evidence := EvidenceForChange("tenant_1", ev)
	if evidence.SchemaVersion != EvidenceEventSchemaVersion {
		t.Fatalf("evidence schema version = %q, want %q", evidence.SchemaVersion, EvidenceEventSchemaVersion)
	}
	if evidence.Action != "revoke" {
		t.Fatalf("evidence action = %q, want revoke", evidence.Action)
	}
	if evidence.EventID != ev.ID {
		t.Fatalf("evidence EventID must match the change event ID")
	}
	tomb := NewChangeEvent("tenant_1", 8, time.Now().UTC(), true, "doc:7",
		aclsync.PermissionChange{Type: aclsync.ChangeRevokeDocumentViewer, Subject: "user:u", Object: "document:d"})
	if EvidenceForChange("tenant_1", tomb).Action != "tombstone" {
		t.Fatal("tombstone events must map to the tombstone action")
	}
}

// connErr is a plain error for taxonomy tests.
type connErr struct{ msg string }

func (e *connErr) Error() string { return e.msg }
