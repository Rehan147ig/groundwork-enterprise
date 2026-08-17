# Microsoft Graph Connector (Entra + SharePoint)

The first real enterprise connector for Groundwork ACL sync. It reads **Microsoft Entra**
users/groups and **SharePoint** folder/file permissions via Microsoft Graph and maps them
onto the `aclsync` domain model, which the Syncer reconciles into SpiceDB. It implements
`aclsync.Connector` and **feeds SpiceDB only** — it never touches the query engine, auth,
or identity, and it does not bypass SpiceDB.

> Status: **production-grade (Milestone 3)** — real HTTP Graph client with
> least-privilege OAuth, tenant-bound installation registry, encrypted
> credential metadata, durable Postgres delta cursor, delta polls that emit
> concrete revoke events (revocations take effect within one poll interval),
> connector health metrics, and `groundwork doctor` checks. Tested against a
> reliable fake Graph HTTP server including a revocation → live deny proof.

## Azure app registration (required Graph permissions)

Register an Entra application and grant **application** (not delegated) permissions, then
grant admin consent:

| Permission | Why |
|---|---|
| `User.Read.All` | enumerate Entra users |
| `Group.Read.All` | enumerate groups + (nested) membership |
| `Sites.Read.All` | read the SharePoint site/drive structure |
| `Files.Read.All` | read drive items (folders/files) and their permissions |

Use a **client secret** (or certificate). The app should be **read-only** — Groundwork
only reads source permissions and writes SpiceDB tuples; it never modifies SharePoint/Entra.

## Environment variables

| Variable | Purpose |
|---|---|
| `ACL_CONNECTOR_TYPE=msgraph` | select this connector |
| `MS_GRAPH_CONNECTOR_ENABLED=true` | explicit enable (refuses to start otherwise) |
| `MS_GRAPH_TENANT_ID` | Entra tenant id (auth) |
| `MS_GRAPH_CLIENT_ID` | app registration client id |
| `MS_GRAPH_CLIENT_SECRET_REF` | **keyring:// or secret-manager ref** (production; preferred) |
| `MS_GRAPH_CLIENT_SECRET` | app client secret (**dev/local fallback only**; production requires the ref) |
| `MS_GRAPH_SITE_ID` | SharePoint site id |
| `MS_GRAPH_DRIVE_ID` | SharePoint drive id |
| `MS_GRAPH_AUTHORITY_HOST` | default `https://login.microsoftonline.com` |
| `DATABASE_URL` | Postgres for the durable delta cursor + installation registry (migration 032) |

It reuses the sync-service envs (`ACL_SYNC_MODE`, `ACL_SYNC_TENANT_ID`,
`ACL_SYNC_INTERVAL_SECONDS`, `ACL_DRIFT_CHECK_INTERVAL_SECONDS`, `SPICEDB_ENDPOINT`, …) from
`docs/acl-sync-framework.md`.

## Authentication

OAuth 2.0 **client-credentials** flow against
`{authority}/{tenant}/oauth2/v2.0/token` with scope `https://graph.microsoft.com/.default`.
Tokens are cached until shortly before expiry. Token retrieval and all Graph calls **retry
transient failures (5xx/429/network) with exponential backoff + jitter**; a permanent auth
failure (401/403/bad credentials) is **not** retried and propagates so the sync **fails
safely**. **Secrets and access tokens are never logged.**

## How Entra/SharePoint permissions map to SpiceDB

| Source | SpiceDB |
|---|---|
| Entra user | `user:{mail \| userPrincipalName \| id}` |
| Entra group | `group:{object-id}` (keyed by id for stable cross-referencing) |
| user is group member | `user:… member group:…` |
| nested group | `group:{sub-id}#member member group:{parent-id}` |
| SharePoint folder | `folder:{item-id}` |
| SharePoint file | `document:{item-id}` |
| file under folder | `folder:{parent-id} parent document:{file-id}` (inheritance) |
| group can view item | `group:{id}#member viewer folder/document:{item-id}` |
| user can view item | `user:{key} viewer folder/document:{item-id}` |

**Identity key consistency:** users are keyed by `mail` → `userPrincipalName` → object id,
and SharePoint permissions (which reference users by object id) are resolved back to that
same key. **This key MUST match the effective `user_id` your query-time identity token
yields** (`sub`/`email`/`preferred_username`) — otherwise enforced and synced identities
won't line up. Validate this in staging.

**Inheritance:** a file inherits its parent folder's viewers via the `folder → document
parent` relation (the SpiceDB model resolves `viewer from parent`). Graph also returns
inherited permissions on each item, which are captured as direct viewers too.

## Delta / change feed

Uses Graph **drive `delta`** queries to detect new/modified/deleted items. The delta token
is persisted in Postgres (`connector_installations.delta_cursor`, migration 032) so the
connector resumes exactly where it left off across restarts. Each poll **differs the
current item permissions against the last-known snapshot**
(`msgraph.permission_snapshots`) and emits **concrete `acl-sync` revoke events** — the
Service applies them to SpiceDB immediately, so a permission revocation in SharePoint
takes effect within **one poll interval** (the revocation SLO). Deleted items revoke
every grantee recorded in their snapshot. Correctness is backstopped by the Service's
periodic full reconcile + drift check.

## Installation registry, credentials, health (Milestone 3)

- **`connector_installations`** (migration 032) is the tenant-bound installation record:
  status, credential reference, delta cursor, last success, sync lag, drift items,
  credential expiry. Credential material is **never stored in the registry** — only
  `keyring://` or secret-manager references, and encrypted metadata sealed with the
  connector purpose key (`keyring.PurposeConnector`, AES-256-GCM).
- **Secrets**: production must set `MS_GRAPH_CLIENT_SECRET_REF=keyring://connector/msgraph`
  (or an approved secret-manager ref). `groundwork doctor` fails when a plaintext
  `MS_GRAPH_CLIENT_SECRET` is set in production mode.
- **Health**: every sync updates the installation record; `acl-sync` exposes Prometheus
  gauges `groundwork_connector_last_success_age_seconds`, `sync_lag_seconds`,
  `drift_items`, `credential_expiry_seconds`, and `state`. `GET /v1/connectors/status`
  (query scope) surfaces the same health surface in the console — tenant-scoped, never
  credential material.
- **Doctor**: `groundwork doctor` checks the connector's config posture, secret
  reference, and registry health (`status`, last success age).

## Safety rules (preserved)

- **No destructive delete on an unconfirmed source.** Any Graph error returns from
  `Snapshot` (never a partial/empty snapshot), so the Syncer's destructive-delete guard
  (`AllowEmptyDestructive=false`) does not wipe SpiceDB on a Graph outage. Proven by
  `TestGraphAuthFailureDoesNotDeleteTuples`.
- Revocations propagate via a non-empty snapshot missing the grant (reconcile) or an
  explicit revoke event.
- Sync failures are logged and retried.

## Dry-run / mock mode

For local development without Azure: keep `ACL_CONNECTOR_TYPE=mock` (the built-in mock
connector), or point the sync service at an in-memory sink (no `SPICEDB_ENDPOINT`). The
Graph mapping itself is exercised by the unit tests via a fake Graph client.

## Limitations

- One SharePoint site/drive per connector instance (run multiple for multiple sites).
- Permission read is per-item (one Graph call per file/folder) — fine to start; batch/parallelize for large drives.
- Deep folder-tree inheritance relies on each file's `parent` folder plus Graph's
  per-item inherited permissions; multi-level folder→folder inheritance is represented via
  those item permissions, not a folder→folder relation in the model.
- Sharing-link permissions and external/guest identities are mapped conservatively (only
  read-granting roles become viewers).

## Production security warnings

- **Protect the client secret** — resolve it via a secret reference
  (`MS_GRAPH_CLIENT_SECRET_REF`), never plaintext env in production, rotate regularly.
  Prefer a certificate over a secret where possible.
- Grant **least privilege** (read-only Graph scopes above) and scope to the specific
  site/drive.
- Run the connector as its own workload with no inbound exposure; it only needs outbound
  HTTPS to Graph and access to write SpiceDB tuples.
- Never log secrets or tokens (the connector doesn't).
