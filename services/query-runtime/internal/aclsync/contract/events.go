package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"groundwork/query-runtime/internal/aclsync"
)

// ChangeEvent is the versioned envelope around a source permission
// change. It extends aclsync.PermissionChange (the tuple-level wire
// form) with the fields the service needs for replay protection,
// ordering, tombstones, and region decisions. The aclsync Service still
// consumes PermissionChange; connectors that declare CapabilityDelta
// surface ChangeEvent via EventSource.WatchEvents.
type ChangeEvent struct {
	// ContractVersion of the envelope.
	ContractVersion string
	// ID is a stable, content-derived event ID used for replay
	// protection and idempotent application (the service drops events
	// whose ID it already applied).
	ID string
	// Sequence is a monotonically increasing per-tenant sequence. The
	// service uses it to detect gaps/out-of-order delivery; 0 when the
	// connector cannot provide one (fail-closed ordering decisions must
	// then rely on ID idempotency alone).
	Sequence int64
	// OccurredAt is when the source change happened (provider clock),
	// UTC.
	OccurredAt time.Time
	// Region carries the source region/residency of the changed
	// resource when the connector declares CapabilityRegionMetadata.
	Region RegionMetadata
	// Tombstone marks deleted source content: every grantee recorded in
	// the last-known snapshot for ResourceID must be revoked. Requires
	// CapabilityTombstones.
	Tombstone bool
	// ResourceID is the stable source resource ID the change applies to.
	ResourceID string
	// Change is the tuple-level change (subject/object/type).
	Change aclsync.PermissionChange
}

// NewChangeEvent wraps a permission change in a versioned envelope,
// deriving a content-addressed ID (sha256 of tenant+type+subject+object
// +occurred time) for replay protection. sequence may be 0 when the
// connector has no ordering guarantee.
func NewChangeEvent(tenantID string, seq int64, occurred time.Time, tombstone bool, resourceID string, change aclsync.PermissionChange) ChangeEvent {
	hash := sha256.Sum256([]byte(tenantID + "\x00" + string(change.Type) + "\x00" + change.Subject + "\x00" + change.Object + "\x00" + occurred.UTC().Format(time.RFC3339Nano)))
	return ChangeEvent{
		ContractVersion: Version,
		ID:              hex.EncodeToString(hash[:16]),
		Sequence:        seq,
		OccurredAt:      occurred.UTC(),
		Tombstone:       tombstone,
		ResourceID:      resourceID,
		Change:          change,
	}
}

// EvidenceEvent is the evidence-event schema for connector-sourced
// changes. It is the schema the service uses when it appends
// connector-applied changes to the tamper-evident evidence ledger: the
// fields are fixed so connectors and the ledger share one wire format.
type EvidenceEvent struct {
	// SchemaVersion is the evidence schema version ("evidence/v1").
	SchemaVersion string
	// EventID matches the ChangeEvent ID (replay protection across the
	// ledger).
	EventID string
	// Provider is the stable provider name (descriptor.Provider).
	Provider string
	// TenantID is the installation-bound tenant.
	TenantID string
	// Action is the applied action: "grant" | "revoke" | "tombstone".
	Action string
	// Subject and Object are relationship-style identifiers
	// ("user:finance_user", "document:security-policy").
	Subject string
	Object  string
	// ResourceID is the stable source resource ID.
	ResourceID string
	// OccurredAt is the source change time (UTC).
	OccurredAt time.Time
	// AppliedAt is when the service applied the change (UTC).
	AppliedAt time.Time
	// Region is the source region/residency (optional).
	Region RegionMetadata
}

// EvidenceEventSchemaVersion is the fixed evidence schema version.
const EvidenceEventSchemaVersion = "evidence/v1"

// EvidenceForChange maps a versioned change event to the evidence schema
// for ledger appends. action is "grant", "revoke", or "tombstone".
func EvidenceForChange(tenantID string, ev ChangeEvent) EvidenceEvent {
	action := "grant"
	if ev.Change.Type == aclsync.ChangeRevokeGroupMember ||
		ev.Change.Type == aclsync.ChangeRevokeFolderViewer ||
		ev.Change.Type == aclsync.ChangeRevokeDocumentViewer ||
		ev.Change.Type == aclsync.ChangeTerminateUser {
		action = "revoke"
	}
	if ev.Tombstone {
		action = "tombstone"
	}
	return EvidenceEvent{
		SchemaVersion: EvidenceEventSchemaVersion,
		EventID:       ev.ID,
		Provider:      "",
		TenantID:      tenantID,
		Action:        action,
		Subject:       ev.Change.Subject,
		Object:        ev.Change.Object,
		ResourceID:    ev.ResourceID,
		OccurredAt:    ev.OccurredAt,
		AppliedAt:     time.Now().UTC(),
		Region:        ev.Region,
	}
}
