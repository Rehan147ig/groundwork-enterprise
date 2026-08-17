package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"groundwork/query-runtime/internal/relationship"
	"groundwork/query-runtime/internal/relationship/spicedb"
)

// spicedbWriter adapts the SpiceDB client to relWriter.
type spicedbWriter struct{ client *spicedb.Client }

func newSpiceDBWriter(c config) (*spicedbWriter, error) {
	if c.spicedbEndpoint == "" {
		return nil, fmt.Errorf("SPICEDB_ENDPOINT is required for seed/setup mode (or -spicedb-endpoint)")
	}
	opts, err := spicedb.EnvOptions()
	if err != nil {
		return nil, err
	}
	if c.spicedbInsecure {
		opts = append(opts, spicedb.WithInsecurePlaintext())
	}
	client, err := spicedb.New(c.spicedbEndpoint, c.spicedbToken, opts...)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.Ready(ctx); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("spicedb not ready (schema ensure failed): %w", err)
	}
	return &spicedbWriter{client: client}, nil
}

func (w *spicedbWriter) Ready(ctx context.Context) error { return w.client.Ready(ctx) }

func (w *spicedbWriter) Write(ctx context.Context, tenantID string, rels []relationship.Relationship) error {
	return w.client.Write(ctx, tenantID, rels)
}

func (w *spicedbWriter) Close() error { return w.client.Close() }

// seed is the -mode=seed entrypoint: idempotently populate Qdrant with
// docs-dim vector chunks for the tenant/region, then grant each of the
// users a view of exactly one document in the relationship backend
// (SpiceDB) so the load run exercises a realistic
// authorized/unauthorized mix.
func seed(c config) error {
	httpc := &http.Client{Timeout: 10 * time.Second}
	j := &jsonClient{httpc: httpc}
	if err := ensureQdrantCollection(j, c.qdrant, c.collection, c.dim); err != nil {
		return err
	}
	if err := seedPoints(j, c.qdrant, c.collection, c.docs, c.dim, c.tenant, c.region); err != nil {
		return err
	}
	rels := make([]relationship.Relationship, 0, c.users)
	for i := 0; i < c.users; i++ {
		rels = append(rels, relationship.Relationship{
			Resource: relationship.DocumentRef(authorizedDoc(i, c.docs)),
			Relation: relationship.RelationViewer,
			Subject:  relationship.UserRef(userID(i)),
		})
	}
	if err := c.relw.Write(context.Background(), c.tenant, rels); err != nil {
		return fmt.Errorf("write grant relationships: %w", err)
	}
	log.Printf("seeded: %d docs (%d-dim), %d users granted in tenant %q", c.docs, c.dim, c.users, c.tenant)
	return nil
}

func ensureQdrantCollection(j *jsonClient, base, name string, dim int) error {
	status, err := j.do(http.MethodPut, strings.TrimRight(base, "/")+"/collections/"+name,
		map[string]any{"vectors": map[string]any{"size": dim, "distance": "Cosine"}}, nil, "", "")
	if err != nil && !(status == http.StatusConflict || strings.Contains(strings.ToLower(err.Error()), "exists")) {
		return fmt.Errorf("create collection: %w", err)
	}
	return nil
}

// seedPoints upserts deterministic, stable vectors so repeated seeds
// converge. Each document is split into 256-token chunks.
func seedPoints(j *jsonClient, base, collection string, docs, dim int, tenant, region string) error {
	const (
		chunkTokens = 256
		batch       = 100
	)
	url := strings.TrimRight(base, "/") + "/collections/" + collection + "/points?wait=true"
	var points []map[string]any
	flush := func() error {
		if len(points) == 0 {
			return nil
		}
		_, err := j.do(http.MethodPut, url, map[string]any{"points": points}, nil, "", "")
		points = nil
		if err != nil {
			return fmt.Errorf("put points: %w", err)
		}
		return nil
	}
	for i := 0; i < docs; i++ {
		nChunks := 3
		for ch := 0; ch < nChunks; ch++ {
			points = append(points, map[string]any{
				"id":     fmt.Sprintf("%s/%d", docID(i), ch),
				"vector": deterministicVector(fmt.Sprintf("doc-%d/chunk-%d", i, ch), dim),
				"payload": map[string]any{
					"document_id": docID(i),
					"chunk_id":    fmt.Sprintf("%s/%d", docID(i), ch),
					"text":        fmt.Sprintf("chunk %d of document %s — quarterly finance policy content used for load testing", ch, docID(i)),
					"page":        1,
					"offset":      ch * chunkTokens,
					"metadata":    map[string]any{"tenant_id": tenant, "region": region},
				},
			})
			if len(points) >= batch {
				if err := flush(); err != nil {
					return err
				}
			}
		}
	}
	return flush()
}

func deterministicVector(seed string, dim int) []float32 {
	h := sha256.Sum256([]byte(seed))
	v := make([]float32, dim)
	var acc uint32
	for i := range v {
		if i%8 == 0 {
			acc = binary.LittleEndian.Uint32(h[4*((i/8)%8):])
		}
		v[i] = float32(acc>>((uint(i)%8)*4)&0xff)/255.0 - 0.5
	}
	return v
}

// setupGovernance is the -mode=setup entrypoint: idempotently provision
// the governed agent, builtin tool + action + grant, and the "use"
// relationship for the delegated subject. Conflicts from re-runs are
// tolerated; anything actually missing is repaired.
func setupGovernance(c config) error {
	j := &jsonClient{httpc: &http.Client{Timeout: 10 * time.Second}, key: c.apiKey}
	assertion := mintJWT(c.jwtSecret, c.owner)
	agentID, versionID, err := ensureAgentVersion(j, c, assertion)
	if err != nil {
		return err
	}
	toolID, err := ensureTool(j, c, c.tool, assertion)
	if err != nil {
		return err
	}
	actionID, err := ensureToolAction(j, c.runtime, toolID, "search", assertion)
	if err != nil {
		return err
	}
	if err := ensureGrant(j, c, agentID, versionID, toolID, actionID); err != nil {
		return err
	}
	if err := ensureUseRelationship(c, toolID); err != nil {
		log.Printf("warning: use relationship not written (delegation path will fail closed): %v", err)
	}
	log.Printf("setup complete: agent=%s version=%s tool=%s action=%s", agentID, versionID, toolID, actionID)
	return nil
}

func ensureAgentVersion(j *jsonClient, c config, assertion string) (agentID, versionID string, err error) {
	var list struct {
		Agents []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"agents"`
	}
	if _, err = j.do(http.MethodGet, c.runtime+"/v1/agents", nil, &list, "", ""); err != nil {
		return "", "", fmt.Errorf("list agents: %w", err)
	}
	for _, a := range list.Agents {
		if a.Name == c.agent {
			agentID = a.ID
			break
		}
	}
	if agentID == "" {
		status, err := j.do(http.MethodPost, c.runtime+"/v1/agents", map[string]any{
			"name": c.agent, "risk_tier": "low", "environment": "production",
			"business_purpose": "load testing",
		}, &struct {
			Agent struct {
				ID string `json:"id"`
			} `json:"agent"`
		}{}, assertion, "lt-setup-agent-"+c.agent)
		if err != nil || status >= 300 {
			return "", "", fmt.Errorf("create agent %s: %w", c.agent, err)
		}
	}
	if versionID, err = activeVersion(j, c, agentID); err != nil {
		return "", "", err
	}
	if versionID != "" {
		return agentID, versionID, nil
	}
	// Version missing or not active: register (tolerate duplicate) then activate (tolerate state).
	status, err := j.do(http.MethodPost, c.runtime+"/v1/agents/"+agentID+"/versions", map[string]any{
		"version": "1.0.0", "model_provider": "anthropic", "model_name": "claude-4",
	}, &struct {
		Version struct {
			ID string `json:"id"`
		} `json:"version"`
	}{}, assertion, "lt-setup-version-"+c.agent)
	if err != nil && !(status == http.StatusConflict) {
		return "", "", fmt.Errorf("register version: %w", err)
	}
	if status, err := j.do(http.MethodPost, c.runtime+"/v1/agents/"+agentID+"/activate",
		map[string]any{"reason": "load testing"}, nil, assertion, "lt-setup-activate-"+c.agent); err != nil && status != http.StatusConflict {
		return "", "", fmt.Errorf("activate agent: %w", err)
	}
	if versionID, err = activeVersion(j, c, agentID); err != nil {
		return "", "", err
	}
	if versionID == "" {
		return "", "", fmt.Errorf("agent %s has no active version after setup", agentID)
	}
	return agentID, versionID, nil
}

// activeVersion returns the agent's active version id ("" if none).
func activeVersion(j *jsonClient, c config, agentID string) (string, error) {
	var detail struct {
		Agent struct {
			ActiveVersionID string `json:"active_version_id"`
		} `json:"agent"`
		Versions []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"versions"`
	}
	if _, err := j.do(http.MethodGet, c.runtime+"/v1/agents/"+agentID, nil, &detail, "", ""); err != nil {
		return "", fmt.Errorf("get agent %s: %w", agentID, err)
	}
	if detail.Agent.ActiveVersionID != "" {
		return detail.Agent.ActiveVersionID, nil
	}
	for _, v := range detail.Versions {
		if v.Status == "active" {
			return v.ID, nil
		}
	}
	return "", nil
}

// ensureTool creates (or finds) the governed builtin tool and brings it
// to the active lifecycle.
func ensureTool(j *jsonClient, c config, name, assertion string) (string, error) {
	find := func() (string, error) {
		var list struct {
			Tools []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"tools"`
		}
		if _, err := j.do(http.MethodGet, c.runtime+"/v1/governance/tools", nil, &list, "", ""); err != nil {
			return "", fmt.Errorf("list tools: %w", err)
		}
		for _, t := range list.Tools {
			if t.Name == name {
				return t.ID, nil
			}
		}
		return "", nil
	}
	toolID, err := find()
	if err != nil {
		return "", err
	}
	if toolID == "" {
		var created struct {
			Tool struct {
				ID string `json:"id"`
			} `json:"tool"`
		}
		status, err := j.do(http.MethodPost, c.runtime+"/v1/governance/tools", map[string]any{
			"name": name, "description": "load test governed search tool", "transport": "builtin",
			"owner_principal_id": c.owner, "region": c.region,
		}, &created, assertion, "lt-setup-tool-"+name)
		if err != nil && status != http.StatusConflict {
			return "", fmt.Errorf("create tool %s: %w", name, err)
		}
		if toolID, err = find(); err != nil {
			return "", err
		}
		if toolID == "" {
			return "", fmt.Errorf("tool %s not found after create", name)
		}
	}
	// Bring to active (tolerate invalid transition when already active).
	if _, err := j.do(http.MethodPost, c.runtime+"/v1/governance/tools/"+toolID+"/lifecycle",
		map[string]any{"lifecycle": "active"}, nil, assertion, "lt-setup-lifecycle-"+name); err != nil {
		return "", fmt.Errorf("activate tool %s: %w", name, err)
	}
	return toolID, nil
}

// ensureToolAction returns the id of the named action on the tool,
// creating it if missing.
func ensureToolAction(j *jsonClient, runtime, toolID, action, assertion string) (string, error) {
	var detail struct {
		Tool struct {
			ID string `json:"id"`
		} `json:"tool"`
		Actions []struct {
			ID     string `json:"id"`
			Action string `json:"action"`
		} `json:"actions"`
	}
	if _, err := j.do(http.MethodGet, runtime+"/v1/governance/tools/"+toolID, nil, &detail, "", ""); err != nil {
		return "", fmt.Errorf("get tool %s: %w", toolID, err)
	}
	for _, a := range detail.Actions {
		if a.Action == action {
			return a.ID, nil
		}
	}
	var created struct {
		Action struct {
			ID string `json:"id"`
		} `json:"action"`
	}
	if _, err := j.do(http.MethodPost, runtime+"/v1/governance/tools/"+toolID+"/actions", map[string]any{
		"action": action, "resource_type": "document", "risk_level": "low", "read_only": true,
	}, &created, assertion, "lt-setup-action-"+toolID+"-"+action); err != nil {
		return "", fmt.Errorf("create action %s on %s: %w", action, toolID, err)
	}
	if created.Action.ID == "" {
		return "", fmt.Errorf("action %s returned no id", action)
	}
	return created.Action.ID, nil
}

func ensureGrant(j *jsonClient, c config, agentID, versionID, toolID, actionID string) error {
	status, err := j.do(http.MethodPost, c.runtime+"/v1/governance/grants", map[string]any{
		"agent_id": agentID, "version_id": versionID, "tool_id": toolID, "action_id": actionID,
	}, nil, mintJWT(c.jwtSecret, c.owner), "lt-setup-grant-"+agentID+"-"+toolID)
	if err != nil && status != http.StatusConflict {
		return fmt.Errorf("create grant: %w", err)
	}
	return nil
}

// ensureUseRelationship grants the delegated subject the "use"
// relation on the tool (the relation the evaluate pipeline checks).
func ensureUseRelationship(c config, toolID string) error {
	return c.relw.Write(context.Background(), c.tenant, []relationship.Relationship{{
		Resource: relationship.ToolRef(toolID),
		Relation: relationship.RelationUse,
		Subject:  relationship.UserRef(c.subject),
	}})
}
