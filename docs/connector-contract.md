# Connector SDK and adapter contract (Milestone 4)

This document is the stable, versioned contract every Groundwork
permission connector implements. It exists so provider-specific code
never duplicates security behavior (secret resolution, error
classification, fail-closed rules) — those live once in the contract and
the aclsync service layer.

Code: `services/query-runtime/internal/aclsync/contract` (package
`contract`). The contract builds on the existing `internal/aclsync`
interface (`Connector`, `PermissionSet`, `PermissionChange`,
`TupleSink`, `Syncer`) and extends it only with explicit versioned
contracts — the base interface itself is unchanged.

## Versioning

- `contract.Version = "v1"`; every `ProviderDescriptor` carries
  `ContractVersion`.
- `contract.Validate` refuses descriptors whose version is not in
  `SupportedVersions()`.
- Breaking changes introduce a new version; v1 semantics never silently
  change.

## The contract areas

| Area | Type in `contract` | Guarantee |
|---|---|---|
| Authentication method + secret references | `AuthSpec` (`AuthMethod`, `SecretRefSchemes`, `Scopes`) | Credentials are always references (`keyring://`, `secretsmanager://`, …), never material; `SecretRefOK` gates a deployment's ref against the spec |
| Production-readiness status | `ProviderDescriptor.Status` (`production` \| `experimental`) | A connector may declare `production` only after a verified production hardening review; `scripts/check-connector-production-claims.sh` enforces the allowlist in CI |
| Installation and tenant binding | `aclsync.InstallationStore` + `Snapshot` | Tenant comes from the verified request context; snapshots are tenant-bound; the installation registry records health, lag, credential expiry |
| Content inventory, stable IDs | `aclsync.ListDocuments` / `Snapshot` | Resource IDs are stable across reads (enforced by the contract suite) |
| Source ACL → canonical principals | `aclsync.PermissionSet` mapping (`PermissionSetToTuples`) | Providers emit raw principal keys; the canonical-identity layer (msgraph `canonicalizer`) rewrites to tenant-scoped principals when enabled |
| Snapshot + delta cursor semantics | `aclsync.Snapshot`, `DeltaTokenStore`, `EventSource.WatchEvents` | Full snapshot always precedes reliance on deltas; cursors are durable (Postgres in production) |
| Grant/revoke events | `aclsync.PermissionChange` + `contract.ChangeEvent` | Every change carries a replay-protection ID, sequence, occurrence time, resource ID |
| Content deletion/tombstones | `ChangeEvent.Tombstone` (requires `CapabilityTombstones`) | Deleted content revokes every grantee in its last-known snapshot |
| Region/residency metadata | `RegionMetadata` (requires `CapabilityRegionMetadata`) | Region/jurisdiction flows with snapshots/events for residency decisions |
| Rate-limit/retry/timeout/pagination | `RetryPolicy` + shared `Kind` taxonomy | Bounded backoff (base/max), per-call timeouts, paging inconsistencies are `KindPagination` (fail closed) |
| Health, sync lag, credential expiry, error taxonomy | `Installation`/`HealthUpdate` + `contract` kinds | Every sync updates the installation record; errors classify via `KindOf`/`IsRetryable`/`FailsClosed` |
| Evidence event schema | `EvidenceEvent` (`evidence/v1`) | Fixed schema for ledger appends: EventID (replay protection), provider, tenant, action (grant/revoke/tombstone), subject/object, times, region |
| Contract tests | `RunContractTests`, `RunErrorTaxonomyTests`, `RunEvidenceSchemaTests` | Every connector must pass the suite from its own test package |

## Interfaces

```go
type VersionedConnector interface {
    aclsync.Connector
    Descriptor() contract.ProviderDescriptor
}

type EventSource interface { // required when CapabilityDelta is declared
    WatchEvents(ctx context.Context, tenantID string) (<-chan contract.ChangeEvent, error)
}
```

`contract.Validate(c)` checks static consistency: descriptor well-formed,
delta ⇒ `EventSource` implemented, tombstones ⇒ delta, and the
fail-closed-subset rule (a connector that cannot prove effective
permissions must fail closed outside its documented subset).

## Capabilities (claims, verified by the suite)

`CapabilityDelta`, `CapabilityTombstones`, `CapabilityGroups`,
`CapabilityFolders`, `CapabilityInheritance`,
`CapabilityEffectivePermissions`, `CapabilityRegionMetadata`.

The Service relies only on declared capabilities. In particular,
`CapabilityEffectivePermissions` is the contract-level assertion that
per-user authorization claims are provable from provider data.

## Error taxonomy

Kinds: `auth` (fail closed), `rate_limited` (retry), `timeout` (retry),
`quota` (retry), `not_found`, `invalid_data` (fail closed),
`unsupported` (fail closed), `pagination` (fail closed), `transient`
(retry), `permanent`.

- `contract.Wrap(kind, err)` classifies at the connector boundary.
- `contract.KindOf(err)` classifies any error (heuristics for raw
  provider errors).
- `contract.IsRetryable` / `contract.FailsClosed` drive the service's
  retry and fail-closed behavior. Provider packages never re-implement
  classification.
- Sentinels: `ErrUnsupportedFeature`, `ErrInvalidProviderData` — a
  connector returns these instead of guessing.

## Provider strict subsets (fail closed outside them)

| Provider | Modeled subset | Explicitly NOT modeled (→ deny) |
|---|---|---|
| `s3` | Object ACLs only | Bucket policies, IAM roles/policies, access points, ownership/encryption access |
| `gcs` | Object ACLs only (fine-grained) | Bucket IAM, uniform bucket-level access, inherited grants, encryption access |
| `msgraph` | Entra groups (nested) + SharePoint site/drive item & folder grants, folder→item inheritance, Graph delta | Sharing links, non-read roles, external/guest identities, site policies, conditional access state |
| `sharepoint` | Site/library/folder/item grants + folder→item inheritance | Sharing links, site policies, external sharing |
| `google` | Per-file/per-folder grants + folder inheritance | Link-sharing visibility unless provable per principal |
| `atlassian` | Confluence space/page grants | Anonymous access, unmodeled sharing states |
| `github` | Teams (nested), direct collaborators | Org defaults, outside-collaborator edge cases |
| `notion` | Integration-scoped permissions only; **never claims per-user authorization** | Anything not provable from provider data |
| `snowflake` | Role inheritance + effective grants | Anything not resolvable through the role hierarchy |

Every provider package carries a `doc.go` stating its subset. S3/GCS
deployments relying on bucket-level IAM are out of subset and must not
claim per-user authorization. Notion must never claim per-user
authorization. Snowflake queries must be validated against a real
account before being relied on.

## Contract tests

Each connector's test package runs:

```go
func TestConnectorContract(t *testing.T) {
    contract.RunContractTests(t, conn) // bound to a fake server, never the network
    contract.RunErrorTaxonomyTests(t)
    contract.RunEvidenceSchemaTests(t)
}
```

The suite verifies: descriptor validity; tenant-bound complete
snapshots; stable resource IDs across reads; tuple mapping; per-document
reads; delta surface (events with v1 envelopes, replay IDs, occurrence
times); tombstone/capability consistency; taxonomy classification; and
the evidence schema. msgraph passes the suite against its fake Graph
HTTP server (`TestConnectorContract`).

## Security rules that stay out of provider packages

- Secret resolution and ref validation: `keyring`, `contract.SecretRefOK`,
  `aclsync.IsKeyringRef`, `groundwork doctor`.
- Fail-closed destructive sync: `Syncer` refuses to delete on empty
  snapshots unless explicitly allowed.
- Retry/backoff: the Service (`withRetry`) — connectors only declare
  policy.
- Evidence: the Service appends `EvidenceEvent`s to the ledger; providers
  emit `ChangeEvent`s, never evidence directly.