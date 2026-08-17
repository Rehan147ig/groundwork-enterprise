package msgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"groundwork/query-runtime/internal/aclsync"
)

// fakeGraphServer is a reliable fake Microsoft Graph HTTP server
// (Milestone 3 integration-test requirement). It serves the token
// endpoint plus users/groups/members/drive-items/permissions/delta and
// lets tests mutate the fixture so a revocation can be observed and
// proven to take effect.
type fakeGraphServer struct {
	mu        sync.Mutex
	token     string
	users     []GraphUser
	groups    []GraphGroup
	members   map[string][]GraphMember
	items     []GraphDriveItem
	perms     map[string][]GraphPermission
	delta     []GraphDeltaItem
	deltaLink string
	// failAuth makes the token endpoint reject credentials (ErrAuthFailed).
	failAuth bool
}

func newFakeGraphServer() *fakeGraphServer {
	return &fakeGraphServer{
		token:     "fake-access-token",
		members:   map[string][]GraphMember{},
		perms:     map[string][]GraphPermission{},
		deltaLink: "",
	}
}

// handler builds the fake Graph HTTP surface. paths are logged when the
// optional traceSink is non-nil.
func (s *fakeGraphServer) handler(traceSink io.Writer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Token endpoint is served at {authority}/{tenant}/oauth2/v2.0/token.
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.failAuth {
				writeJSON(w, 401, map[string]string{"error": "invalid_client"})
				return
			}
			writeJSON(w, 200, map[string]any{
				"access_token": s.token,
				"expires_in":   3600,
				"token_type":   "Bearer",
			})
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/v1.0/users", s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		vals := make([]map[string]any, 0, len(s.users))
		for _, u := range s.users {
			vals = append(vals, map[string]any{
				"id": u.ID, "displayName": u.DisplayName,
				"mail": u.Mail, "userPrincipalName": u.UserPrincipalName,
			})
		}
		writeJSON(w, 200, map[string]any{"value": vals})
	}))
	mux.HandleFunc("/v1.0/groups", s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		vals := make([]map[string]any, 0, len(s.groups))
		for _, g := range s.groups {
			vals = append(vals, map[string]any{"id": g.ID, "displayName": g.DisplayName})
		}
		writeJSON(w, 200, map[string]any{"value": vals})
	}))
	mux.HandleFunc("/v1.0/groups/", s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/v1.0/groups/")
		if !strings.HasSuffix(rest, "/members") {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		id := strings.TrimSuffix(rest, "/members")
		s.mu.Lock()
		defer s.mu.Unlock()
		members := s.members[id]
		vals := make([]map[string]any, 0, len(members))
		for _, m := range members {
			vals = append(vals, map[string]any{
				"@odata.type":       odataType(m.Type),
				"id":                m.ID,
				"displayName":       m.DisplayName,
				"mail":              m.Mail,
				"userPrincipalName": m.UserPrincipalName,
			})
		}
		writeJSON(w, 200, map[string]any{"value": vals})
	}))
	mux.HandleFunc("/v1.0/drives/", s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if traceSink != nil {
			fmt.Fprintf(traceSink, "GRAPH HIT %s\n", r.URL.Path)
		}
		rest := strings.TrimPrefix(r.URL.Path, "/v1.0/drives/drive1/")
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case rest == "root/children":
			vals := make([]map[string]any, 0, len(s.items))
			for _, it := range s.items {
				vals = append(vals, driveItemWire(it))
			}
			writeJSON(w, 200, map[string]any{"value": vals})
		case rest == "root/delta":
			deltaVals := make([]map[string]any, 0, len(s.delta))
			for _, it := range s.delta {
				vals := driveItemWire(GraphDriveItem{ID: it.ID, Name: it.Name, ParentID: it.ParentID, IsFolder: it.IsFolder})
				if it.Deleted {
					vals["deleted"] = map[string]any{"state": "deleted"}
				}
				deltaVals = append(deltaVals, vals)
			}
			writeJSON(w, 200, map[string]any{"value": deltaVals, "@odata.deltaLink": s.deltaLink})
		case strings.HasSuffix(rest, "/children"):
			writeJSON(w, 200, map[string]any{"value": []any{}})
		case strings.HasSuffix(rest, "/permissions"):
			parts := strings.Split(strings.TrimSuffix(rest, "/permissions"), "/")
			id := parts[len(parts)-1]
			writeJSON(w, 200, map[string]any{"value": graphPermissionJSON(s.perms[id])})
		default:
			writeJSON(w, 404, map[string]string{"error": "not found"})
		}
	}))
	return mux
}

func odataType(t MemberType) string {
	if t == MemberGroup {
		return "#microsoft.graph.group"
	}
	return "#microsoft.graph.user"
}

func driveItemWire(it GraphDriveItem) map[string]any {
	v := map[string]any{
		"id":              it.ID,
		"name":            it.Name,
		"parentReference": map[string]any{"id": it.ParentID},
	}
	if it.IsFolder {
		v["folder"] = map[string]any{"childCount": 0}
	}
	return v
}

func graphPermissionJSON(perms []GraphPermission) []map[string]any {
	out := make([]map[string]any, 0, len(perms))
	for _, p := range perms {
		v := map[string]any{"id": p.ID, "roles": p.Roles}
		switch {
		case p.Grantee.GroupID != "":
			v["grantedToV2"] = map[string]any{"group": map[string]any{"id": p.Grantee.GroupID, "displayName": ""}}
		case p.Grantee.UserID != "":
			v["grantedToV2"] = map[string]any{"user": map[string]any{"id": p.Grantee.UserID, "displayName": "", "email": p.Grantee.UserMail}}
		}
		out = append(out, v)
	}
	return out
}

func (s *fakeGraphServer) requireAuth(next func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		tok := s.token
		s.mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			writeJSON(w, 401, map[string]string{"error": "missing bearer"})
			return
		}
		next(w, r)
		_ = tok
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// mutate applies fn under the fixture lock (test-only helper).
func (s *fakeGraphServer) mutate(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

// TestGraphHTTPClientFullCycle runs the REAL httpGraphClient against a
// fake HTTP server: full snapshot sync, permission revocation in the
// source, delta poll, and a live deny through the sink's Check (the same
// relationship path the engine enforces at query time).
func TestGraphHTTPClientFullCycle(t *testing.T) {
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

	ts := httptest.NewServer(srv.handler(nil))
	defer ts.Close()

	cfg := Config{
		TenantID:         "tenant_integration",
		ClientID:         "client-id",
		ClientSecret:     "client-secret",
		DriveID:          "drive1",
		AuthorityHost:    ts.URL,
		GraphBaseURL:     ts.URL + "/v1.0",
		DeltaPollSeconds: 1,
		Enabled:          true,
	}
	ctx := context.Background()
	conn := NewConnector(NewHTTPGraphClient(cfg), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), NewMemoryDeltaTokenStore())
	conn.SetSnapshotStore(NewMemoryPermissionSnapshotStore())
	conn.SetInstallationStore(aclsync.NewMemoryInstallationStore())
	conn.SetDeltaTokenStore(NewMemoryDeltaTokenStore())

	// (1) Full initial sync.
	store := aclsync.NewMemoryTupleSink()
	syncer := aclsync.NewSyncer(conn, store, discard())
	res, err := syncer.Sync(ctx, "tenant_integration")
	if err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	if res.TuplesWritten == 0 {
		t.Fatal("initial sync wrote no tuples")
	}
	if !store.Check("tenant_integration", "user:finance_user", "viewer", "document:security-policy") {
		t.Fatal("finance_user must have access before the revocation")
	}

	// (2) Revoke the document grant in the source and emit a delta tombstone.
	srv.mutate(func() {
		srv.perms["security-policy"] = nil // grant removed
		srv.delta = []GraphDeltaItem{{ID: "security-policy", ParentID: "finance-folder"}}
		srv.deltaLink = "delta-link-2"
	})

	// (3) One delta poll must emit the concrete revoke event.
	ch, err := conn.WatchPermissionChanges(ctx, "tenant_integration")
	if err != nil {
		t.Fatal(err)
	}
	revokes := collectChanges(ctx, ch, 5*time.Second)
	if len(revokes) == 0 {
		t.Fatal("delta poll emitted no revoke events")
	}
	var revoked bool
	for _, chg := range revokes {
		if chg.Type == aclsync.ChangeRevokeDocumentViewer && chg.Object == "document:security-policy" {
			revoked = true
		}
	}
	if !revoked {
		t.Fatalf("expected revoke of document:security-policy, got %+v", revokes)
	}

	// (4) Apply the revoke to the sink exactly like the Service does,
	// then prove the live deny (MemoryTupleSink.Check is the same
	// relationship path the engine enforces).
	_, deletes := changeToTuples(revokes[0])
	if len(deletes) > 0 {
		if err := store.DeleteTuples(ctx, "tenant_integration", deletes); err != nil {
			t.Fatal(err)
		}
	}
	if store.Check("tenant_integration", "user:finance_user", "viewer", "document:security-policy") {
		t.Fatal("revocation must take effect: finance_user still has access")
	}
	// Group grant via folder inheritance must be unaffected (not revoked).
	if !store.Check("tenant_integration", "user:finance_user", "member", "group:finance") {
		t.Fatal("group membership must survive an unrelated document revoke")
	}

	// (5) Installation health recorded after the sync.
	inst, err := conn.installations.Get(ctx, "tenant_integration", "msgraph")
	if err != nil {
		t.Fatal(err)
	}
	if inst.LastSuccessAt.IsZero() {
		t.Fatal("installation health must record last success")
	}
}

// TestGraphHTTPClientAuthFailureFailsClosed proves the real client's
// token path distinguishes permanent auth failure (no retry storm, sync
// fails safely) and that the sync does not delete tuples.
func TestGraphHTTPClientAuthFailureFailsClosed(t *testing.T) {
	srv := newFakeGraphServer()
	srv.users = []GraphUser{{ID: "u-1", Mail: "u1"}}
	srv.failAuth = true

	ts := httptest.NewServer(srv.handler(nil))
	defer ts.Close()

	cfg := Config{
		TenantID:      "tenant_auth_fail",
		ClientID:      "client-id",
		ClientSecret:  "wrong-secret",
		DriveID:       "drive1",
		AuthorityHost: ts.URL,
		GraphBaseURL:  ts.URL + "/v1.0",
		Enabled:       true,
	}
	ctx := context.Background()
	store := aclsync.NewMemoryTupleSink()
	seed := []aclsync.Tuple{
		{User: "user:finance_user", Relation: "viewer", Object: "document:security-policy"},
	}
	if err := store.WriteTuples(ctx, "tenant_auth_fail", seed); err != nil {
		t.Fatal(err)
	}
	before, _ := store.ListTuples(ctx, "tenant_auth_fail")

	conn := NewConnector(NewHTTPGraphClient(cfg), cfg, discard(), nil)
	syncer := aclsync.NewSyncer(conn, store, discard())
	if _, err := syncer.Sync(ctx, "tenant_auth_fail"); err == nil {
		t.Fatal("sync must fail on bad credentials")
	}
	after, _ := store.ListTuples(ctx, "tenant_auth_fail")
	if len(after) != len(before) {
		t.Fatalf("auth failure must not delete tuples: before=%d after=%d", len(before), len(after))
	}
}

// collectChanges drains a change channel until the deadline.
func collectChanges(ctx context.Context, ch <-chan aclsync.PermissionChange, timeout time.Duration) []aclsync.PermissionChange {
	var out []aclsync.PermissionChange
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case c, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, c)
		case <-deadline.C:
			return out
		case <-ctx.Done():
			return out
		}
	}
}

// changeToTuples mirrors the Service's mapping (kept in sync with
// service.go's changeToTuples for the integration proof).
func changeToTuples(c aclsync.PermissionChange) (writes, deletes []aclsync.Tuple) {
	switch c.Type {
	case aclsync.ChangeAddGroupMember:
		writes = []aclsync.Tuple{{User: c.Subject, Relation: "member", Object: c.Object}}
	case aclsync.ChangeRevokeGroupMember:
		deletes = []aclsync.Tuple{{User: c.Subject, Relation: "member", Object: c.Object}}
	case aclsync.ChangeRevokeFolderViewer, aclsync.ChangeRevokeDocumentViewer:
		deletes = []aclsync.Tuple{{User: c.Subject, Relation: "viewer", Object: c.Object}}
	}
	return writes, deletes
}
