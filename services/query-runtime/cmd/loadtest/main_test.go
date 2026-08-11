package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"groundwork/query-runtime/internal/relationship"
)

// memoryRelWriter is an in-memory relWriter for hermetic tests.
type memoryRelWriter struct{ rels []relationship.Relationship }

func (m *memoryRelWriter) Ready(context.Context) error { return nil }
func (m *memoryRelWriter) Write(_ context.Context, _ string, rels []relationship.Relationship) error {
	m.rels = append(m.rels, rels...)
	return nil
}

// fakeRuntime is an in-process stand-in for the query-runtime HTTP
// surface the tool talks to.
type fakeRuntime struct {
	mu        sync.Mutex
	agents    []fakeAgent
	tools     []fakeTool
	connector atomic.Int64
	dispatch  atomic.Int64
	seq       atomic.Int64
}

type fakeAgent struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	ActiveVersionID string `json:"active_version_id"`
}

type fakeTool struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Lifecycle string       `json:"lifecycle"`
	Actions   []fakeAction `json:"-"`
}

type fakeAction struct {
	ID     string `json:"id"`
	Action string `json:"action"`
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{
		agents: []fakeAgent{{ID: "agent-1", Name: "loadtest-agent", ActiveVersionID: "version-1"}},
		tools:  []fakeTool{{ID: "tool-builtin", Name: "loadtest_search", Lifecycle: "active", Actions: []fakeAction{{ID: "act-search", Action: "search"}}}},
	}
}

func (f *fakeRuntime) mux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/query", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"citations": []map[string]any{{"document_id": "doc-1"}}})
	})

	mux.HandleFunc("GET /v1/agents", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"agents": f.agents, "count": len(f.agents)})
	})
	mux.HandleFunc("POST /v1/agents", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, a := range f.agents {
			if a.Name == body.Name {
				writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{"code": "agent_name_conflict"}})
				return
			}
		}
		a := fakeAgent{ID: fmt.Sprintf("agent-%d", f.seq.Add(1)+1), Name: body.Name}
		f.agents = append(f.agents, a)
		writeJSON(w, http.StatusCreated, map[string]any{"agent": a})
	})
	mux.HandleFunc("GET /v1/agents/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, a := range f.agents {
			if a.ID == r.PathValue("id") {
				versions := []map[string]any{{"id": a.ActiveVersionID, "version": "1.0.0", "status": "active"}}
				writeJSON(w, http.StatusOK, map[string]any{"agent": a, "versions": versions})
				return
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "agent_not_found"}})
	})
	mux.HandleFunc("POST /v1/agents/{id}/versions", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for i := range f.agents {
			if f.agents[i].ID == r.PathValue("id") {
				writeJSON(w, http.StatusCreated, map[string]any{"version": map[string]any{"id": "version-1"}})
				return
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "agent_not_found"}})
	})
	mux.HandleFunc("POST /v1/agents/{id}/activate", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for i := range f.agents {
			if f.agents[i].ID == r.PathValue("id") {
				f.agents[i].ActiveVersionID = "version-1"
				writeJSON(w, http.StatusOK, map[string]any{"agent": f.agents[i]})
				return
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "agent_not_found"}})
	})

	mux.HandleFunc("GET /v1/governance/tools", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := make([]fakeTool, len(f.tools))
		copy(out, f.tools)
		writeJSON(w, http.StatusOK, map[string]any{"tools": out, "count": len(out)})
	})
	mux.HandleFunc("POST /v1/governance/tools", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, t := range f.tools {
			if t.Name == body.Name {
				writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{"code": "tool_name_conflict"}})
				return
			}
		}
		t := fakeTool{ID: fmt.Sprintf("tool-%d", f.seq.Add(1)+1), Name: body.Name, Lifecycle: "draft"}
		f.tools = append(f.tools, t)
		writeJSON(w, http.StatusCreated, map[string]any{"tool": t})
	})
	mux.HandleFunc("GET /v1/governance/tools/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, t := range f.tools {
			if t.ID == r.PathValue("id") {
				writeJSON(w, http.StatusOK, map[string]any{"tool": t, "actions": t.Actions})
				return
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "tool_not_found"}})
	})
	mux.HandleFunc("POST /v1/governance/tools/{id}/actions", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Action string `json:"action"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		defer f.mu.Unlock()
		for i := range f.tools {
			if f.tools[i].ID == r.PathValue("id") {
				a := fakeAction{ID: fmt.Sprintf("act-%d", f.seq.Add(1)+1), Action: body.Action}
				f.tools[i].Actions = append(f.tools[i].Actions, a)
				writeJSON(w, http.StatusCreated, map[string]any{"action": a})
				return
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "tool_not_found"}})
	})
	mux.HandleFunc("POST /v1/governance/tools/{id}/lifecycle", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{})
	})
	mux.HandleFunc("POST /v1/governance/grants", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{"grant": map[string]any{"id": "grant-1"}})
	})

	mux.HandleFunc("POST /v1/governance/delegations", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"grant": map[string]any{"id": fmt.Sprintf("grant-%d", f.seq.Add(1))},
			"token": fmt.Sprintf("tok-%d", f.seq.Add(1)),
		})
	})
	mux.HandleFunc("POST /v1/governance/runs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"run":       map[string]any{"id": fmt.Sprintf("run-%d", f.seq.Add(1))},
			"decisions": []map[string]any{},
		})
	})
	mux.HandleFunc("POST /v1/governance/runs/{id}/evaluate", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"allowed":  true,
			"decision": map[string]any{"decision": "allowed", "status": "passed", "gates": []map[string]any{}},
		})
	})
	mux.HandleFunc("POST /v1/governance/runs/{id}/dispatch", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ToolName string `json:"tool_name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.dispatch.Add(1)
		writeJSON(w, http.StatusOK, map[string]any{
			"allowed": true, "dispatch_mode": "dispatched",
			"decision": map[string]any{"decision": "allowed", "status": "passed", "gates": []map[string]any{}},
		})
	})
	mux.HandleFunc("GET /v1/governance/evidence", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"count": 5, "items": []map[string]any{}})
	})

	mux.HandleFunc("POST /v1/governance/connectors", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := fmt.Sprintf("conn-%d", f.seq.Add(1))
		toolID := fmt.Sprintf("tool-%d", f.seq.Add(1))
		f.mu.Lock()
		f.tools = append(f.tools, fakeTool{ID: toolID, Name: body.Name, Lifecycle: "active", Actions: []fakeAction{{ID: "act-call", Action: "call"}}})
		f.mu.Unlock()
		f.connector.Add(1)
		writeJSON(w, http.StatusCreated, map[string]any{"detail": map[string]any{
			"connector": map[string]any{"id": id, "tool_id": toolID, "name": body.Name},
		}})
	})
	mux.HandleFunc("POST /v1/governance/connectors/{id}/activate", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"detail": map[string]any{
			"connector": map[string]any{"id": r.PathValue("id"), "tool_id": "tool-conn"},
		}})
	})

	// Qdrant subset.
	mux.HandleFunc("PUT /collections/{name}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"result": "ok"})
	})
	mux.HandleFunc("PUT /collections/{name}/points", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"result": map[string]any{"status": "completed"}})
	})

	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func loadConfig(srv *httptest.Server, reportPath string) config {
	return config{
		mode: "load", runtime: srv.URL, relw: &memoryRelWriter{},
		tenant: "acme", region: "us-east-1", apiKey: "admin-key", jwtSecret: "test-secret",
		question: "quarterly finance policy", users: 10, concurrency: 4, duration: 300 * time.Millisecond,
		paths: "query,delegation,dispatch,connector,evidence", report: reportPath,
		owner: "principal:loadtest-owner", subject: "principal:loadtest-subject",
		agent: "loadtest-agent", tool: "loadtest_search", connector: "loadtest_connector",
	}
}

func TestSetupGovernanceIdempotent(t *testing.T) {
	fake := newFakeRuntime()
	srv := httptest.NewServer(fake.mux())
	defer srv.Close()

	c := loadConfig(srv, "")
	c.mode = "setup"
	for i := 0; i < 2; i++ {
		if err := setupGovernance(c); err != nil {
			t.Fatalf("setup pass %d: %v", i+1, err)
		}
	}
}

func TestLoadAllPathsWritesReport(t *testing.T) {
	fake := newFakeRuntime()
	srv := httptest.NewServer(fake.mux())
	defer srv.Close()

	reportPath := filepath.Join(t.TempDir(), "report.json")
	if err := loadTest(loadConfig(srv, reportPath)); err != nil {
		t.Fatalf("loadTest: %v", err)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("report file: %v", err)
	}
	var rep report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("report json: %v", err)
	}
	if rep.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", rep.SchemaVersion)
	}
	if rep.DurationMS <= 0 {
		t.Errorf("duration_ms = %d, want > 0", rep.DurationMS)
	}
	for _, p := range []string{"query", "delegation", "dispatch", "connector", "evidence"} {
		pr, ok := rep.Paths[p]
		if !ok {
			t.Fatalf("report missing path %q", p)
		}
		if pr.Requests == 0 {
			t.Errorf("path %q made 0 requests", p)
		}
		if pr.Errors > 0 {
			t.Errorf("path %q errors = %d, want 0", p, pr.Errors)
		}
	}
	if fake.dispatch.Load() == 0 {
		t.Error("no dispatches recorded")
	}
	if fake.connector.Load() == 0 {
		t.Error("connector path never registered a connector")
	}
	if got := rep.Paths["query"].Allowed; got == 0 {
		t.Error("query path allowed = 0, want > 0 (fake returns citations)")
	}
	if got := rep.Paths["connector"].Allowed; got == 0 {
		t.Error("connector path allowed = 0, want > 0 (stub responds)")
	}
}

func TestSeedIdempotent(t *testing.T) {
	fake := newFakeRuntime()
	srv := httptest.NewServer(fake.mux())
	defer srv.Close()

	c := config{
		mode: "seed", relw: &memoryRelWriter{}, qdrant: srv.URL, collection: "groundwork_chunks",
		tenant: "acme", region: "uk", users: 10, docs: 12, dim: 16,
	}
	for i := 0; i < 2; i++ {
		if err := seed(c); err != nil {
			t.Fatalf("seed pass %d: %v", i+1, err)
		}
	}
}

func TestParsePaths(t *testing.T) {
	paths, err := parsePaths("query, delegation,evidence")
	if err != nil {
		t.Fatal(err)
	}
	if !paths["query"] || !paths["delegation"] || !paths["evidence"] || len(paths) != 3 {
		t.Errorf("unexpected paths: %v", paths)
	}
	if _, err := parsePaths("query,bogus"); err == nil {
		t.Error("bogus path should fail")
	}
}
