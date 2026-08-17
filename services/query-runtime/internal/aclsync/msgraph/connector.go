package msgraph

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"groundwork/query-runtime/internal/aclsync"
	"groundwork/query-runtime/internal/aclsync/contract"
	"groundwork/query-runtime/internal/runtime"
)

// contractVersion is the contract version this connector implements.
const contractVersion = contract.Version

// Connector implements aclsync.Connector against Microsoft Graph (Entra + SharePoint).
// It feeds the relationship backend via the Syncer; it never touches the query engine, auth, or identity.
type Connector struct {
	client GraphClient
	cfg    Config
	logger *slog.Logger
	delta  DeltaTokenStore

	// snapshots keeps last-known item permission state so delta polls
	// emit concrete revoke events (diffed against the previous state).
	// Nil disables snapshot diffing (delta detection still logs).
	snapshots PermissionSnapshotStore

	// installations is the tenant-bound installation record (health,
	// last-success, delta cursor, credential expiry). Nil disables
	// health tracking.
	installations aclsync.InstallationStore

	// resolver + canonical drive canonical-principal sync. When canonical is true the
	// connector resolves every directory user to a tenant-scoped principal, upserts its
	// verified aliases, and emits user:principal:<uuid> tuples (see Snapshot). When false
	// it emits raw user:<mail|upn|id> tuples exactly as before (demo / pre-migration mode).
	resolver  runtime.PrincipalResolver
	canonical bool
}

// SetCanonicalIdentity enables canonical-principal sync: the connector pre-provisions a
// principal (and its entra:id / jwt:email / jwt:preferred_username aliases) for every
// directory user and emits canonical user:principal:<uuid> tuples. With canonical=false
// (or a nil resolver) the connector keeps emitting raw user-key tuples.
func (c *Connector) SetCanonicalIdentity(resolver runtime.PrincipalResolver, canonical bool) {
	c.resolver = resolver
	c.canonical = canonical
}

// SetSnapshotStore wires the permission snapshot store used to diff
// delta changes into concrete revoke events. Without it, delta polls
// detect and log changes but do not emit granular revocations.
func (c *Connector) SetSnapshotStore(s PermissionSnapshotStore) {
	c.snapshots = s
}

// SetDeltaTokenStore swaps the durable delta cursor store. Defaults to
// memory; production uses the Postgres-backed store (migration 032).
func (c *Connector) SetDeltaTokenStore(s DeltaTokenStore) {
	if s != nil {
		c.delta = s
	}
}

// SetInstallationStore wires the tenant-bound installation record the
// connector updates after every successful sync (health surface).
func (c *Connector) SetInstallationStore(s aclsync.InstallationStore) {
	c.installations = s
}

// Descriptor implements the versioned connector contract (Milestone 4):
// the msgraph connector authenticates with OAuth2 client credentials
// referenced via keyring or a secrets manager, supports delta + tombstone
// semantics (deletions surface as per-grantee revokes), models groups,
// folders, and inheritance, and proves effective per-user read
// permissions from item + folder grants. Least-privilege scopes below.
func (c *Connector) Descriptor() contract.ProviderDescriptor {
	return contract.ProviderDescriptor{
		Provider:        "msgraph",
		ContractVersion: contractVersion,
		// Literal string: the CI production-claims check audits this.
		Status: "production",
		Auth: contract.AuthSpec{
			Method:           contract.AuthOAuth2ClientCredentials,
			SecretRefSchemes: []contract.SecretRefScheme{contract.SchemeKeyring, contract.SchemeSecretsManager},
			Scopes:           []string{"User.Read.All", "Group.Read.All", "GroupMember.Read.All", "Sites.Read.All"},
			CredentialExpiry: true,
		},
		Capabilities: []contract.Capability{
			contract.CapabilityDelta,
			contract.CapabilityTombstones,
			contract.CapabilityGroups,
			contract.CapabilityFolders,
			contract.CapabilityInheritance,
			contract.CapabilityEffectivePermissions,
		},
		SupportedSubset: "Entra groups (incl. nested) + SharePoint site/drive item and folder " +
			"permissions. Read-granting roles (read/view) become viewers; non-read roles, " +
			"sharing links, and external/guest identities are conservatively skipped (never " +
			"granted). Deleted items revoke every grantee in their last-known snapshot. " +
			"Unmodeled SharePoint features (site policies, anonymous links, conditional " +
			"access state) deny by omission.",
		FailClosedOutsideSubset: true,
		Retry: contract.RetryPolicy{
			Base:           250 * time.Millisecond,
			Max:            30 * time.Second,
			DefaultTimeout: c.cfg.HTTPTimeout,
		},
	}
}

// WatchEvents implements the versioned delta surface: the same delta
// poll loop as WatchPermissionChanges, wrapped in ChangeEvent envelopes
// with replay-protection IDs and a monotonic per-tenant sequence.
func (c *Connector) WatchEvents(ctx context.Context, tenantID string) (<-chan contract.ChangeEvent, error) {
	inner, err := c.WatchPermissionChanges(ctx, tenantID)
	if err != nil {
		return nil, c.graphError(err)
	}
	ch := make(chan contract.ChangeEvent)
	go func() {
		defer close(ch)
		var seq atomic.Int64
		for {
			select {
			case <-ctx.Done():
				return
			case pc, ok := <-inner:
				if !ok {
					return
				}
				ev := contract.NewChangeEvent(tenantID, seq.Add(1), time.Now().UTC(),
					false, resourceIDFromObject(pc.Object), pc)
				select {
				case ch <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch, nil
}

// graphError classifies a Graph client error into the contract
// taxonomy. Authentication failures fail closed (never retried with the
// same credential); everything else follows the shared classification.
func (c *Connector) graphError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrAuthFailed) {
		return contract.Wrap(contract.KindAuth, err)
	}
	return contract.Wrap(contract.KindOf(err), err)
}

// resourceIDFromObject extracts the stable source resource ID from a
// relationship-style object ref ("document:123" -> "123"). Unknown
// prefixes return the object verbatim (fail-safe, never empty for
// events that carry one).
func resourceIDFromObject(object string) string {
	switch {
	case strings.HasPrefix(object, "document:"):
		return strings.TrimPrefix(object, "document:")
	case strings.HasPrefix(object, "folder:"):
		return strings.TrimPrefix(object, "folder:")
	case strings.HasPrefix(object, "group:"):
		return strings.TrimPrefix(object, "group:")
	default:
		return object
	}
}

// NewConnector builds a Graph connector from a GraphClient (real or fake) and config.
func NewConnector(client GraphClient, cfg Config, logger *slog.Logger, delta DeltaTokenStore) *Connector {
	if logger == nil {
		logger = slog.Default()
	}
	if delta == nil {
		delta = NewMemoryDeltaTokenStore()
	}
	return &Connector{client: client, cfg: cfg.withDefaults(), logger: logger, delta: delta}
}

// Snapshot reads the full Entra + SharePoint permission state and maps it to aclsync.
// Any Graph error is returned (never a partial/empty snapshot), so the Syncer's
// destructive-delete guard prevents wiping the backend on a Graph outage.
func (c *Connector) Snapshot(ctx context.Context, tenantID string) (aclsync.PermissionSet, error) {
	users, err := c.client.ListUsers(ctx)
	if err != nil {
		c.recordHealth(ctx, tenantID, false, 0)
		return aclsync.PermissionSet{}, c.graphError(err)
	}
	groups, err := c.client.ListGroups(ctx)
	if err != nil {
		c.recordHealth(ctx, tenantID, false, 0)
		return aclsync.PermissionSet{}, c.graphError(err)
	}

	ps := aclsync.PermissionSet{TenantID: tenantID, Users: mapUsers(users)}
	byID := userKeyByID(users)

	// Canonical mode pre-provisions a principal for every directory user up front (so even
	// users with no current grant can authenticate later) and records userKey -> principal
	// for the rewrite below. Directory users are observed first, so group members and
	// grantees that are directory users collapse onto the same principal.
	var canon *canonicalizer
	if c.canonical && c.resolver != nil {
		canon = newCanonicalizer(ctx, c.resolver, tenantID)
		for _, u := range users {
			if err := canon.observe(u.Mail, u.UserPrincipalName, u.ID); err != nil {
				c.recordHealth(ctx, tenantID, false, 0)
				return aclsync.PermissionSet{}, c.graphError(err)
			}
		}
	}

	for _, g := range groups {
		members, err := c.client.ListGroupMembers(ctx, g.ID)
		if err != nil {
			c.recordHealth(ctx, tenantID, false, 0)
			return aclsync.PermissionSet{}, c.graphError(err)
		}
		if canon != nil {
			for _, m := range members {
				if m.Type == MemberGroup {
					continue
				}
				if err := canon.observe(m.Mail, m.UserPrincipalName, m.ID); err != nil {
					c.recordHealth(ctx, tenantID, false, 0)
					return aclsync.PermissionSet{}, c.graphError(err)
				}
			}
		}
		ps.Groups = append(ps.Groups, mapGroup(g, members))
	}

	items, err := c.client.ListDriveItems(ctx)
	if err != nil {
		c.recordHealth(ctx, tenantID, false, 0)
		return aclsync.PermissionSet{}, c.graphError(err)
	}
	for _, it := range items {
		perms, err := c.client.ListItemPermissions(ctx, it.ID)
		if err != nil {
			c.recordHealth(ctx, tenantID, false, 0)
			return aclsync.PermissionSet{}, c.graphError(err)
		}
		if canon != nil {
			if err := c.observeGrantees(canon, perms, byID); err != nil {
				c.recordHealth(ctx, tenantID, false, 0)
				return aclsync.PermissionSet{}, c.graphError(err)
			}
		}
		if it.IsFolder {
			ps.Folders = append(ps.Folders, mapFolder(it, perms, byID))
		} else {
			ps.Documents = append(ps.Documents, mapDocument(it, perms, byID))
		}
		// Refresh the permission snapshot so the next delta poll diffs
		// against this authoritative state (never a stale one).
		if c.snapshots != nil {
			snap := ItemSnapshot{
				TenantID: tenantID, ItemID: it.ID,
				IsFolder: it.IsFolder, ParentID: it.ParentID,
				Grantees: snapshotGrantees(perms),
			}
			if err := c.snapshots.Save(ctx, snap); err != nil {
				c.logger.Warn("msgraph_snapshot_save_failed", "tenant", tenantID, "item", it.ID, "err", err.Error())
			}
		}
	}

	if canon != nil {
		canon.rewrite(&ps)
	}
	c.recordHealth(ctx, tenantID, true, 0)
	return ps, nil
}

// observeGrantees pre-provisions principals for SharePoint permission grantees. Grantees that
// are directory users were already observed (keyed by the directory userKey via byID), so we
// only need to observe non-directory grantees here, using the same (mail, upn, id) inputs
// granteesFromPerms uses to form their userKey â€” keeping observation and rewrite aligned.
func (c *Connector) observeGrantees(canon *canonicalizer, perms []GraphPermission, byID map[string]string) error {
	for _, p := range perms {
		if !grantsRead(p.Roles) || p.Grantee.UserID == "" && p.Grantee.UserMail == "" && p.Grantee.UserUPN == "" {
			continue
		}
		if _, ok := byID[p.Grantee.UserID]; ok {
			continue // directory user, already observed with its full directory identity
		}
		if err := canon.observe(p.Grantee.UserMail, p.Grantee.UserUPN, p.Grantee.UserID); err != nil {
			return err
		}
	}
	return nil
}

func (c *Connector) ListDocuments(ctx context.Context, _ string) ([]aclsync.Document, error) {
	byID, err := c.userIndex(ctx)
	if err != nil {
		return nil, c.graphError(err)
	}
	items, err := c.client.ListDriveItems(ctx)
	if err != nil {
		return nil, c.graphError(err)
	}
	var docs []aclsync.Document
	for _, it := range items {
		if it.IsFolder {
			continue
		}
		perms, err := c.client.ListItemPermissions(ctx, it.ID)
		if err != nil {
			return nil, c.graphError(err)
		}
		docs = append(docs, mapDocument(it, perms, byID))
	}
	return docs, nil
}

func (c *Connector) GetDocumentPermissions(ctx context.Context, _ string, documentID string) (aclsync.DocumentPermissions, error) {
	byID, err := c.userIndex(ctx)
	if err != nil {
		return aclsync.DocumentPermissions{}, c.graphError(err)
	}
	items, err := c.client.ListDriveItems(ctx)
	if err != nil {
		return aclsync.DocumentPermissions{}, c.graphError(err)
	}
	for _, it := range items {
		if it.ID != documentID || it.IsFolder {
			continue
		}
		perms, err := c.client.ListItemPermissions(ctx, it.ID)
		if err != nil {
			return aclsync.DocumentPermissions{}, c.graphError(err)
		}
		users, groups := granteesFromPerms(perms, byID)
		return aclsync.DocumentPermissions{DocumentID: it.ID, FolderID: it.ParentID, ViewerUsers: users, ViewerGroups: groups}, nil
	}
	return aclsync.DocumentPermissions{}, nil
}

// WatchPermissionChanges streams source permission changes. Delta polls
// diff the current item state against the last-known snapshot and emit
// concrete aclsync.PermissionChange revoke events (which the Service
// applies to SpiceDB immediately â€” the revocation SLO is one poll
// interval). Deleted items revoke every grantee recorded in their
// snapshot. When no snapshot store is wired, detection still runs but no
// granular events are emitted (periodic full reconcile remains the
// correctness backstop).
func (c *Connector) WatchPermissionChanges(ctx context.Context, tenantID string) (<-chan aclsync.PermissionChange, error) {
	ch := make(chan aclsync.PermissionChange)
	go func() {
		defer close(ch)
		ticker := time.NewTicker(time.Duration(c.cfg.DeltaPollSeconds) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.pollDelta(ctx, tenantID, ch)
			}
		}
	}()
	return ch, nil
}

// pollDelta fetches the drive delta, saves the new cursor, and emits
// revoke events for every grantee that lost access (deleted items, or
// changed items whose read-granting permissions were removed).
func (c *Connector) pollDelta(ctx context.Context, tenantID string, ch chan<- aclsync.PermissionChange) {
	token, _ := c.delta.Load(ctx, tenantID)
	items, next, err := c.client.DeltaDriveItems(ctx, token)
	if err != nil {
		c.logger.Warn("msgraph_delta_failed", "tenant", tenantID, "err", err.Error())
		c.recordHealth(ctx, tenantID, false, 0)
		return
	}
	deleted, changed := classifyDelta(items)
	c.logger.Info("msgraph_delta_detected", "tenant", tenantID, "changed", len(changed), "deleted", len(deleted))

	byID, err := c.userIndex(ctx)
	if err != nil {
		c.logger.Warn("msgraph_delta_user_index_failed", "tenant", tenantID, "err", err.Error())
		return
	}

	emitted := 0
	if c.snapshots != nil {
		emitted = c.emitDeltaEvents(ctx, tenantID, deleted, changed, byID, ch)
	}

	if next != "" {
		if err := c.delta.Save(ctx, tenantID, next); err != nil {
			c.logger.Warn("msgraph_delta_token_save_failed", "tenant", tenantID, "err", err.Error())
		}
	}
	c.logger.Info("msgraph_delta_applied", "tenant", tenantID, "revokes_emitted", emitted)
	c.recordHealth(ctx, tenantID, true, 0)
}

// emitDeltaEvents diffs the current item state against the last-known
// permission snapshot and emits revoke changes for lost grants. Returns
// the number of events emitted.
func (c *Connector) emitDeltaEvents(ctx context.Context, tenantID string, deleted, changed []string, byID map[string]string, ch chan<- aclsync.PermissionChange) int {
	emitted := 0
	// Deleted items: revoke every grantee that previously had access.
	for _, id := range deleted {
		snap, err := c.snapshots.Load(ctx, tenantID, id)
		if err != nil {
			c.logger.Warn("msgraph_delta_snapshot_load_failed", "tenant", tenantID, "item", id, "err", err.Error())
			continue
		}
		item := GraphDriveItem{ID: id, IsFolder: snap.IsFolder}
		for _, g := range snap.Grantees {
			chg, ok := snapshotRevokeChange(item, g, byID)
			if !ok {
				continue
			}
			select {
			case ch <- chg:
				emitted++
			case <-ctx.Done():
				return emitted
			}
		}
		if err := c.snapshots.Delete(ctx, tenantID, id); err != nil {
			c.logger.Warn("msgraph_delta_snapshot_delete_failed", "tenant", tenantID, "item", id, "err", err.Error())
		}
	}
	// Changed items: diff current read grants against the snapshot.
	for _, id := range changed {
		perms, err := c.client.ListItemPermissions(ctx, id)
		if err != nil {
			c.logger.Warn("msgraph_delta_permissions_failed", "tenant", tenantID, "item", id, "err", err.Error())
			continue
		}
		prev, err := c.snapshots.Load(ctx, tenantID, id)
		if err != nil {
			c.logger.Warn("msgraph_delta_snapshot_load_failed", "tenant", tenantID, "item", id, "err", err.Error())
			continue
		}
		now := snapshotGrantees(perms)
		for _, g := range prev.Grantees {
			if !containsGrantee(now, g) {
				item := GraphDriveItem{ID: id, IsFolder: prev.IsFolder, ParentID: prev.ParentID}
				chg, ok := snapshotRevokeChange(item, g, byID)
				if !ok {
					continue
				}
				select {
				case ch <- chg:
					emitted++
				case <-ctx.Done():
					return emitted
				}
			}
		}
		snap := ItemSnapshot{TenantID: tenantID, ItemID: id, IsFolder: prev.IsFolder, ParentID: prev.ParentID, Grantees: now}
		if err := c.snapshots.Save(ctx, snap); err != nil {
			c.logger.Warn("msgraph_delta_snapshot_save_failed", "tenant", tenantID, "item", id, "err", err.Error())
		}
	}
	return emitted
}

// recordHealth updates the installation record and health gauges. lag is
// the observed source-change age; pass 0 when unknown. On failure the
// installation is marked degraded/failed with the error message (never a
// secret).
func (c *Connector) recordHealth(ctx context.Context, tenantID string, ok bool, lagSeconds int64) {
	status := aclsync.InstallationActive
	errMsg := ""
	if !ok {
		status = aclsync.InstallationDegraded
		errMsg = "delta poll failed"
	}
	now := time.Now().UTC()
	h := aclsync.HealthUpdate{
		Status:         status,
		CredentialRef:  "keyring://connector/msgraph",
		CredentialTTL:  c.cfg.CredentialExpiry,
		SyncLagSeconds: lagSeconds,
		LastError:      errMsg,
		LastAttemptAt:  now,
	}
	if ok {
		h.LastSuccessAt = now
	}
	if c.installations != nil {
		if err := c.installations.UpdateHealth(ctx, tenantID, "msgraph", h); err != nil {
			if errors.Is(err, aclsync.ErrInstallationNotFound) {
				// First observed run: create the installation record
				// (fail-closed: no record, no health surface).
				inst := aclsync.Installation{
					TenantID:      tenantID,
					Provider:      "msgraph",
					Status:        status,
					CredentialRef: "keyring://connector/msgraph",
					CredentialTTL: c.cfg.CredentialExpiry,
					LastSuccessAt: h.LastSuccessAt,
					LastAttemptAt: h.LastAttemptAt,
					LastError:     h.LastError,
				}
				if err := c.installations.Upsert(ctx, inst); err != nil {
					c.logger.Warn("msgraph_installation_upsert_failed", "tenant", tenantID, "err", err.Error())
				}
				return
			}
			c.logger.Warn("msgraph_health_update_failed", "tenant", tenantID, "err", err.Error())
		}
	}
}

func (c *Connector) userIndex(ctx context.Context) (map[string]string, error) {
	users, err := c.client.ListUsers(ctx)
	if err != nil {
		return nil, c.graphError(err)
	}
	return userKeyByID(users), nil
}

var _ aclsync.Connector = (*Connector)(nil)
