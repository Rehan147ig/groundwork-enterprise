// Command loadtest seeds a bank-shaped dataset, sets up the governed
// agent/tool/delegation plane, and drives concurrency load tests against
// a running Groundwork query runtime across five paths — query, governed
// delegation, tool dispatch, connector dispatch, and evidence — reporting
// p50/p95/p99 latency, throughput, and the fail-closed rate per path. It
// is an operator tool (not part of the service) and talks to everything
// over HTTP, so it can run from any machine against a local or deployed
// stack.
//
// Three modes:
//
//	-mode=seed    Populate Qdrant with N documents and the relationship
//	             backend (SpiceDB) with grants for N users, so the
//	             load run exercises a realistic mix of authorized +
//	             unauthorized queries. The query runtime must already
//	             be running; seed writes through the SpiceDB adapter
//	             (schema is ensured on connect).
//	-mode=setup   Idempotent governance-plane prerequisites for the delegation/dispatch paths:
//	             an agent (loadtest-agent), the governed builtin tool (loadtest_search) with an
//	             active grant, and the "use" relationship that lets the delegated subject use
//	             the tool. Re-run anytime; conflicts are tolerated.
//	-mode=load    Drive every enabled path concurrently (POST /v1/query, delegation mint + run +
//	             evaluate, governed dispatch, connector dispatch through the gateway, evidence
//	             reads) and report per-path stats. Writes a repeatable JSON report (see -report).
//
// Example:
//
//	go run ./cmd/loadtest -mode=seed  -spicedb-endpoint=localhost:50051 -spicedb-insecure \
//	    -qdrant=http://localhost:6333 -tenant=acme -users=500 -docs=2000
//	go run ./cmd/loadtest -mode=setup -runtime=http://localhost:8080 -apikey=$KEY -jwt-secret=$SECRET \
//	    -spicedb-endpoint=localhost:50051 -spicedb-insecure -tenant=acme -region=us-east-1
//	go run ./cmd/loadtest -mode=load  -runtime=http://localhost:8080 -apikey=$KEY \
//	    -jwt-secret=$SECRET -tenant=acme -region=us-east-1 -users=500 -concurrency=50 -duration=30s
//
// The -apikey must be an admin key (or carry the agents + governance
// scopes), and -jwt-secret must be the runtime's GROUNDWORK_JWT_HS_SECRET
// so the tool can mint the verified end-user assertions the governed
// mutations require. -region must match the API key's tenant region.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"groundwork/query-runtime/internal/relationship"
)

type config struct {
	mode            string
	runtime         string
	spicedbEndpoint string
	spicedbToken    string
	spicedbInsecure bool
	qdrant          string
	collection      string
	tenant          string
	region          string
	apiKey          string
	jwtSecret       string
	question        string
	users           int
	docs            int
	dim             int
	concurrency     int
	duration        time.Duration
	paths           string
	report          string
	owner           string
	subject         string
	agent           string
	tool            string
	connector       string
	// relw is the relationship write target for seed/setup. main()
	// wires a live SpiceDB client; tests inject a memory writer.
	relw relWriter
}

// relWriter is the relationship-grant surface seed/setup need.
type relWriter interface {
	Ready(ctx context.Context) error
	Write(ctx context.Context, tenantID string, rels []relationship.Relationship) error
}

func main() {
	var c config
	flag.StringVar(&c.mode, "mode", "load", "seed | setup | load")
	flag.StringVar(&c.runtime, "runtime", "http://localhost:8080", "query-runtime base URL")
	flag.StringVar(&c.spicedbEndpoint, "spicedb-endpoint", os.Getenv("SPICEDB_ENDPOINT"), "SpiceDB gRPC endpoint (default env SPICEDB_ENDPOINT)")
	flag.StringVar(&c.spicedbToken, "spicedb-token", os.Getenv("SPICEDB_TOKEN"), "SpiceDB preshared key (default env SPICEDB_TOKEN)")
	flag.BoolVar(&c.spicedbInsecure, "spicedb-insecure", false, "dial SpiceDB without TLS (dev only)")
	flag.StringVar(&c.qdrant, "qdrant", "http://localhost:6333", "Qdrant base URL (seed)")
	flag.StringVar(&c.collection, "collection", "groundwork_chunks", "Qdrant collection")
	flag.StringVar(&c.tenant, "tenant", "acme", "tenant id")
	flag.StringVar(&c.region, "region", "uk", "region of seeded chunks (must match the API key's region)")
	flag.StringVar(&c.apiKey, "apikey", os.Getenv("GROUNDWORK_API_KEY"), "Groundwork API key (load/setup)")
	flag.StringVar(&c.jwtSecret, "jwt-secret", os.Getenv("GROUNDWORK_JWT_HS_SECRET"), "HS256 secret to mint user JWTs (load/setup)")
	flag.StringVar(&c.question, "question", "quarterly finance policy", "query text")
	flag.IntVar(&c.users, "users", 500, "number of users")
	flag.IntVar(&c.docs, "docs", 2000, "number of documents (seed)")
	flag.IntVar(&c.dim, "dim", 384, "embedding dimension (seed)")
	flag.IntVar(&c.concurrency, "concurrency", 50, "concurrent workers per path (at least one per enabled path)")
	flag.DurationVar(&c.duration, "duration", 30*time.Second, "load duration")
	flag.StringVar(&c.paths, "paths", "query,delegation,dispatch,connector,evidence", "comma-separated load paths")
	flag.StringVar(&c.report, "report", "", `report file (default loadtest-report-<timestamp>.json; "-" = stdout only)`)
	flag.StringVar(&c.owner, "owner", "principal:loadtest-owner", "verified owner principal for governed mutations")
	flag.StringVar(&c.subject, "subject", "principal:loadtest-subject", "delegated subject principal (relationship-checked)")
	flag.StringVar(&c.agent, "agent", "loadtest-agent", "agent name for the governed paths")
	flag.StringVar(&c.tool, "tool", "loadtest_search", "builtin governed tool name")
	flag.StringVar(&c.connector, "connector", "loadtest_connector", "base name for the load-created connector tool")
	flag.Parse()

	if c.mode == "seed" || c.mode == "setup" {
		w, err := newSpiceDBWriter(c)
		if err != nil {
			log.Fatalf("spicedb writer: %v", err)
		}
		defer w.Close()
		c.relw = w
	}
	if c.mode == "load" {
		if c.spicedbEndpoint != "" {
			if w, err := newSpiceDBWriter(c); err != nil {
				log.Printf("warning: spicedb writer unavailable (connector path will fail closed): %v", err)
			} else {
				defer w.Close()
				c.relw = w
			}
		} else {
			log.Printf("warning: SPICEDB_ENDPOINT not set; connector path will fail closed (run -mode=setup against the runtime's SpiceDB)")
		}
	}

	switch c.mode {
	case "seed":
		if err := seed(c); err != nil {
			log.Fatalf("seed failed: %v", err)
		}
	case "setup":
		if c.apiKey == "" || c.jwtSecret == "" {
			log.Fatalf("-apikey and -jwt-secret are required for setup mode")
		}
		if err := setupGovernance(c); err != nil {
			log.Fatalf("setup failed: %v", err)
		}
	case "load":
		if err := loadTest(c); err != nil {
			log.Fatalf("load failed: %v", err)
		}
	default:
		log.Fatalf("unknown -mode %q (want seed|setup|load)", c.mode)
	}
}

// userID / docID are deterministic so seed and load agree on which users are authorized.
func userID(i int) string { return fmt.Sprintf("user_%d@corp.test", i) }
func docID(i int) string  { return fmt.Sprintf("doc-%d", i) }

// authorizedDoc maps each user to the one document they're granted (a simple, deterministic
// scheme: user i can see doc i mod docs). Users beyond the granted set hit the fail-closed path.
func authorizedDoc(userIdx, docs int) string { return docID(userIdx % docs) }

func pct(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx].Round(time.Millisecond)
}

func mintJWT(secret, sub string) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub, "exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, _ := tok.SignedString([]byte(secret))
	return signed
}

// jsonClient wraps HTTP calls with the headers the governed surface
// requires (API key, verified identity assertion, idempotency key).
type jsonClient struct {
	httpc *http.Client
	key   string
}

// do issues one JSON request. Body/out may be nil. Returns the HTTP
// status (0 on transport errors).
func (j *jsonClient) do(method, url string, body, out any, assertion, idem string) (int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, rdr)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if j.key != "" {
		req.Header.Set("X-Groundwork-API-Key", j.key)
	}
	if assertion != "" {
		req.Header.Set("X-Groundwork-User-Assertion", assertion)
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	resp, err := j.httpc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("%s %s -> %s: %s", method, url, resp.Status, strings.TrimSpace(string(data)))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode %s %s: %w (%s)", method, url, err, strings.TrimSpace(string(data)))
		}
	}
	return resp.StatusCode, nil
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sortedLatencies(lat []time.Duration) []time.Duration {
	out := make([]time.Duration, len(lat))
	copy(out, lat)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
