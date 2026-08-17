// Command bank-demo-seed loads the synthetic bank corpus and persona graph into a running
// Groundwork stack. It is the demo-side analog of services/query-runtime/cmd/loadtest -mode=seed:
// same Qdrant point shape, same SpiceDB relationship conventions, so the demo wire-matches
// the production code path exactly.
//
// Flow:
//
//  1. Read examples/bank-demo/personas/personas.json (personas, groups, folders, docs).
//  2. Walk examples/bank-demo/corpus/*.md, parse YAML frontmatter, chunk the body.
//  3. Embed each chunk via the SAME /embed service the runtime uses for queries (so doc
//     and query vectors share one space and nearest-neighbor search is meaningful), then
//     push chunks into Qdrant with the payload the runtime expects (document_id, chunk_id,
//     chunk_hash, tenant_id, region, ...).
//  4. Write the relationships that express groups, folder grants, document parents, and
//     direct viewer grants exactly as a production ACL-sync connector would. Writes go
//     through SpiceDB's HTTP gateway (POST /v1/relationships/write) with the same
//     tenant-scoped IDs the runtime's adapter uses on the wire.
//
// Usage:
//
//	go run ./examples/bank-demo/seed \
//	  -qdrant=http://localhost:6333 -spicedb-endpoint=http://localhost:8443 \
//	  -corpus=./examples/bank-demo/corpus \
//	  -personas=./examples/bank-demo/personas/personas.json
//
// The query-runtime must already be running so its deep readiness has provisioned the
// SpiceDB schema. The seeder is idempotent; re-running it is safe.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	collectionName = "groundwork_chunks"
	vectorDim      = 384
	chunkMaxRunes  = 600
	chunkMinRunes  = 200
)

type personaGraph struct {
	TenantID string `json:"tenant_id"`
	Region   string `json:"region"`
	Personas []struct {
		ID          string   `json:"id"`
		DisplayName string   `json:"display_name"`
		Role        string   `json:"role"`
		Groups      []string `json:"groups"`
	} `json:"personas"`
	Groups []struct {
		ID string `json:"id"`
	} `json:"groups"`
	Folders []struct {
		ID      string   `json:"id"`
		Viewers []string `json:"viewers"`
	} `json:"folders"`
	Documents []struct {
		ID           string   `json:"id"`
		File         string   `json:"file"`
		Folder       string   `json:"folder"`
		ExtraViewers []string `json:"extra_viewers"`
	} `json:"documents"`
}

func main() {
	qdrantURL := flag.String("qdrant", "http://localhost:6333", "Qdrant base URL")
	spicedbEndpoint := flag.String("spicedb-endpoint", "http://localhost:8443", "SpiceDB HTTP gateway base URL")
	spicedbToken := flag.String("spicedb-token", "groundwork-local", "SpiceDB preshared key (Bearer token)")
	corpusDir := flag.String("corpus", "./examples/bank-demo/corpus", "corpus root directory")
	personasFile := flag.String("personas", "./examples/bank-demo/personas/personas.json", "personas.json path")
	embeddingURL := flag.String("embedding", "http://localhost:9000", "embedding service base URL (the demo embedder maps to host port 9000)")
	// PR #21: optional Postgres connection for populating the demo
	// schema (demo.documents + demo.document_permissions). When empty,
	// the seeder skips this step — useful for local Qdrant+SpiceDB-only
	// smoke tests. The Codespace/docker-compose flow sets this to the
	// same DATABASE_URL the runtime uses.
	postgresURL := flag.String("postgres", "", "Postgres URL for demo schema seeding (demo.documents + demo.document_permissions); empty disables")
	flag.Parse()

	graph, err := readPersonaGraph(*personasFile)
	if err != nil {
		log.Fatalf("read personas: %v", err)
	}
	log.Printf("seeding tenant=%s region=%s personas=%d groups=%d folders=%d documents=%d",
		graph.TenantID, graph.Region, len(graph.Personas), len(graph.Groups), len(graph.Folders), len(graph.Documents))

	httpc := &http.Client{Timeout: 30 * time.Second}

	// 1. Qdrant collection
	if err := ensureQdrantCollection(httpc, *qdrantURL); err != nil {
		log.Fatalf("qdrant collection: %v", err)
	}

	// 2. Ingest corpus -> Qdrant points
	totalChunks := 0
	pointID := 1
	for _, doc := range graph.Documents {
		path := filepath.Join(*corpusDir, doc.File)
		body, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("read %s: %v", path, err)
		}
		_, content := splitFrontmatter(body)
		chunks := chunkText(string(content))
		points := make([]map[string]any, 0, len(chunks))
		for ci, chunk := range chunks {
			hash := sha256hex(chunk)
			chunkID := "chk_" + hash[:20]
			vec, err := embed(httpc, *embeddingURL, chunk)
			if err != nil {
				log.Fatalf("embed chunk of %s: %v (is the embedding service up at %s?)", doc.ID, err, *embeddingURL)
			}
			points = append(points, map[string]any{
				"id":     pointID,
				"vector": vec,
				"payload": map[string]any{
					"document_id":     doc.ID,
					"chunk_id":        chunkID,
					"chunk_hash":      hash,
					"text":            chunk,
					"page":            1,
					"offset":          ci * chunkMaxRunes,
					"freshness_score": 1.0,
					"soft_deleted":    false,
					"metadata": map[string]any{
						"tenant_id":      graph.TenantID,
						"region":         graph.Region,
						"source_scope":   "BankCorpus",
						"owner_acl_tags": []string{},
					},
				},
			})
			pointID++
		}
		if err := upsertPoints(httpc, *qdrantURL, points); err != nil {
			log.Fatalf("upsert %s: %v", doc.ID, err)
		}
		totalChunks += len(chunks)
		log.Printf("  ingested %s (%d chunks)", doc.ID, len(chunks))
	}
	log.Printf("Qdrant: %d documents, %d chunks", len(graph.Documents), totalChunks)

	// 3. SpiceDB relationships
	rels := buildRelationships(graph)
	if err := writeRelationships(httpc, *spicedbEndpoint, *spicedbToken, graph.TenantID, rels); err != nil {
		log.Fatalf("spicedb relationships: %v", err)
	}
	log.Printf("SpiceDB: %d relationships written via %s", len(rels), *spicedbEndpoint)

	// 4. (PR #21) Demo schema: documents + permissions for the Leak Report.
	// Optional — skipped when -postgres is empty so local Qdrant+SpiceDB
	// smoke tests stay fast. The Codespace flow always passes -postgres.
	if *postgresURL != "" {
		db, err := sql.Open("pgx", *postgresURL)
		if err != nil {
			log.Fatalf("open postgres %s: %v", redactURL(*postgresURL), err)
		}
		defer db.Close()
		// Surface connectivity problems early — Open is lazy.
		pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := db.PingContext(pingCtx); err != nil {
			cancel()
			log.Fatalf("ping postgres %s: %v (is migration 012 applied? run db-migrate first)", redactURL(*postgresURL), err)
		}
		cancel()
		seedCtx, seedCancel := context.WithTimeout(context.Background(), 60*time.Second)
		if err := seedDemoCorpus(seedCtx, db, graph, *corpusDir); err != nil {
			seedCancel()
			log.Fatalf("seed demo corpus: %v", err)
		}
		seedCancel()
		log.Printf("demo schema: %d documents + permissions written to demo.documents/demo.document_permissions", len(graph.Documents))
	} else {
		log.Printf("demo schema: -postgres not set; skipping demo.documents seeding (Leak Report won't have data)")
	}

	log.Println("done. demo stack ready.")
}

// redactURL strips the password component of a Postgres URL for safe
// logging. The format is "postgres://user:password@host:port/db?...";
// we replace ":password@" with ":***@".
func redactURL(u string) string {
	at := strings.LastIndex(u, "@")
	if at < 0 {
		return u
	}
	colon := strings.LastIndex(u[:at], ":")
	if colon < 0 || colon < strings.Index(u, "://") {
		return u
	}
	return u[:colon+1] + "***" + u[at:]
}

// ---------- persona graph ----------

func readPersonaGraph(path string) (*personaGraph, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var g personaGraph
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func buildRelationships(g *personaGraph) []relationship {
	var rels []relationship

	// Group memberships: user:X member group:Y
	for _, p := range g.Personas {
		for _, grp := range p.Groups {
			rels = append(rels, relationship{
				Subject: "user:" + p.ID, Relation: "member", Object: "group:" + grp,
			})
		}
	}

	// Folder viewers
	for _, f := range g.Folders {
		for _, v := range f.Viewers {
			rels = append(rels, relationship{
				Subject: v, Relation: "viewer", Object: "folder:" + f.ID,
			})
		}
	}

	// Document parents + extra direct viewers
	for _, d := range g.Documents {
		rels = append(rels, relationship{
			Subject: "folder:" + d.Folder, Relation: "parent", Object: "document:" + d.ID,
		})
		for _, v := range d.ExtraViewers {
			rels = append(rels, relationship{
				Subject: v, Relation: "viewer", Object: "document:" + d.ID,
			})
		}
	}
	return rels
}

// ---------- corpus parsing ----------

var frontmatterRe = regexp.MustCompile(`(?s)^---\n.*?\n---\n`)

func splitFrontmatter(body []byte) ([]byte, []byte) {
	loc := frontmatterRe.FindIndex(body)
	if loc == nil {
		return nil, body
	}
	return body[loc[0]:loc[1]], body[loc[1]:]
}

func chunkText(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	// Paragraph-based chunking with size targeting.
	paragraphs := strings.Split(text, "\n\n")
	var chunks []string
	var current strings.Builder
	for _, p := range paragraphs {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if current.Len()+len(p)+2 > chunkMaxRunes && current.Len() >= chunkMinRunes {
			chunks = append(chunks, strings.TrimSpace(current.String()))
			current.Reset()
		}
		if current.Len() > 0 {
			current.WriteString("\n\n")
		}
		current.WriteString(p)
		// Hard cap: if a single paragraph is longer than max, split on sentences.
		for current.Len() > chunkMaxRunes*2 {
			chunks = append(chunks, current.String()[:chunkMaxRunes])
			rest := current.String()[chunkMaxRunes:]
			current.Reset()
			current.WriteString(rest)
		}
	}
	if current.Len() > 0 {
		chunks = append(chunks, strings.TrimSpace(current.String()))
	}
	return chunks
}

// ---------- Qdrant ----------

func ensureQdrantCollection(httpc *http.Client, base string) error {
	url := strings.TrimRight(base, "/") + "/collections/" + collectionName
	body := map[string]any{
		"vectors": map[string]any{"size": vectorDim, "distance": "Cosine"},
	}
	if err := doJSON(httpc, http.MethodPut, url, body, nil, nil); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "already") {
			return nil
		}
		return err
	}
	return nil
}

func upsertPoints(httpc *http.Client, base string, points []map[string]any) error {
	url := strings.TrimRight(base, "/") + "/collections/" + collectionName + "/points?wait=true"
	return doJSON(httpc, http.MethodPut, url, map[string]any{"points": points}, nil, nil)
}

// embed calls the SAME /embed endpoint the runtime uses to embed queries
// (POST {"text": ...} -> {"embedding": [...]}), so document vectors and query vectors live
// in the same embedding space and Qdrant nearest-neighbor search is meaningful. This is
// load-bearing for the demo: the live engine is vector-only, so random/placeholder doc
// vectors would make every query land on arbitrary documents and the keystone moments
// (e.g. "executive compensation framework" -> the exec-comp memo) would not work.
func embed(httpc *http.Client, embeddingURL, text string) ([]float32, error) {
	payload, _ := json.Marshal(map[string]string{"text": text})
	url := strings.TrimRight(embeddingURL, "/") + "/embed"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("embed %s -> %s: %s", url, resp.Status, strings.TrimSpace(string(data)))
	}
	var parsed struct {
		Embedding []float32 `json:"embedding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	if len(parsed.Embedding) == 0 {
		return nil, fmt.Errorf("empty embedding response")
	}
	return parsed.Embedding, nil
}

// ---------- SpiceDB ----------

// relationship is a neutral relationship in "type:id" notation;
// the SpiceDB gateway write below converts it to the tenant-scoped wire form.
type relationship struct {
	Subject  string // "user:alice" or "group:eng#member"
	Relation string
	Object   string // "group:eng" / "folder:top-secret" / "document:POL-001"
}

// writeRelationships POSTs OPERATION_CREATE updates to SpiceDB's HTTP gateway,
// tenant-scoping every object/subject ID exactly like the runtime adapter
// (escape(tenant) + ":" + escape(id), first colon = tenant boundary).
func writeRelationships(httpc *http.Client, base, token, tenant string, rels []relationship) error {
	const batch = 50
	url := strings.TrimRight(base, "/") + "/v1/relationships/write"
	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	for i := 0; i < len(rels); i += batch {
		end := i + batch
		if end > len(rels) {
			end = len(rels)
		}
		var updates []map[string]any
		for _, r := range rels[i:end] {
			subjType, subjID, subjRel := parseSubject(r.Subject)
			objType, objID := parseObject(r.Object)
		subject := map[string]any{
			"object": map[string]any{"object_type": subjType, "object_id": scopeID(tenant, subjID)},
		}
		if subjRel != "" {
			subject["optional_relation"] = subjRel
		}
		updates = append(updates, map[string]any{
			"operation": "OPERATION_CREATE",
			"relationship": map[string]any{
				"resource": map[string]any{
					"object_type": objType, "object_id": scopeID(tenant, objID), "relation": r.Relation,
				},
				"subject": subject,
			},
		})
		}
		if err := doJSON(httpc, http.MethodPost, url, map[string]any{"updates": updates}, nil, headers); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "already") {
				continue
			}
			return fmt.Errorf("write relationships [%d:%d]: %w", i, end, err)
		}
	}
	return nil
}

// parseSubject splits "type:id#relation" into its parts.
func parseSubject(s string) (typ, id, rel string) {
	typ, rest, _ := strings.Cut(s, ":")
	id, rel, _ = strings.Cut(rest, "#")
	return typ, id, rel
}

// parseObject splits "type:id" into its parts.
func parseObject(s string) (typ, id string) {
	typ, id, _ = strings.Cut(s, ":")
	return typ, id
}

// scopeID mirrors the runtime adapter's scopeID: escape(tenant) + "/" + escape(id).
func scopeID(tenant, id string) string {
	if tenant == "" {
		return escapeID(id)
	}
	return escapeID(tenant) + "/" + escapeID(id)
}

// escapeID mirrors relationship.EscapeID: pass [a-zA-Z0-9_-] through,
// hex-escape everything else as "=XX" (no "/", ":", "~", or "=" remains).
func escapeID(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == '-' || c == '_':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "=%02X", c)
		}
	}
	return b.String()
}

// ---------- HTTP helper ----------

func doJSON(httpc *http.Client, method, url string, body, out any, headers map[string]string) error {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s -> %s: %s", method, url, resp.Status, strings.TrimSpace(string(data)))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
