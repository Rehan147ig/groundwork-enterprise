// doctor validates a deployment: configuration rules (deployment.Validate
// fail-closed set), key material, tenancy, and the live dependencies the
// runtime needs (PostgreSQL, SpiceDB, Qdrant, Elasticsearch, outbox
// webhook). Every check reports PASS/WARN/FAIL/SKIP; any FAIL exits
// non-zero so doctor can gate CI or a release.
//
// Environment is taken from the process; --env-file loads additional
// KEY=VALUE pairs (real environment wins over the file). If --env-file
// is not given and .groundwork/groundwork.env exists in the working
// directory, it is used — so `groundwork doctor` inside a scaffolded
// deployment directory just works.
package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"groundwork/query-runtime/internal/deployment"
	"groundwork/query-runtime/internal/governance"
	"groundwork/query-runtime/internal/keyring"
	"groundwork/query-runtime/internal/relationship/spicedb"
	"groundwork/query-runtime/internal/runtime"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type checkResult struct {
	Name   string `json:"name"`
	Status string `json:"status"` // PASS | WARN | FAIL | SKIP
	Detail string `json:"detail,omitempty"`
}

type doctorOptions struct {
	envFile  string
	jsonOut  bool
	timeout  time.Duration
	client   *http.Client
	database string
	spicedb  string
	qdrant   string
	elastic  string
}

func runDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	envFile := fs.String("env-file", "", "path to a KEY=VALUE env file (default: .groundwork/groundwork.env if present)")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	timeoutMs := fs.Int("timeout-ms", 5000, "per-dependency probe timeout in milliseconds")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "doctor: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}

	opts := doctorOptions{
		envFile: *envFile,
		jsonOut: *jsonOut,
		timeout: time.Duration(*timeoutMs) * time.Millisecond,
	}
	if opts.envFile == "" {
		candidate := filepath.Join(".groundwork", "groundwork.env")
		if _, err := os.Stat(candidate); err == nil {
			opts.envFile = candidate
		}
	}
	if opts.envFile != "" {
		if err := loadEnvFile(opts.envFile); err != nil {
			fmt.Fprintf(stderr, "doctor: %v\n", err)
			return exitUsage
		}
	}
	opts.client = &http.Client{Timeout: opts.timeout}
	opts.database = os.Getenv("DATABASE_URL")
	opts.spicedb = os.Getenv("SPICEDB_ENDPOINT")
	opts.qdrant = os.Getenv("QDRANT_URL")
	opts.elastic = os.Getenv("ELASTICSEARCH_URL")

	results := runChecks(opts)
	return reportResults(results, opts.jsonOut, stdout)
}

func reportResults(results []checkResult, jsonOut bool, stdout io.Writer) int {
	failures := 0
	for _, r := range results {
		if r.Status == "FAIL" {
			failures++
		}
	}
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return exitOKOrCheck(failures)
	}
	for _, r := range results {
		fmt.Fprintf(stdout, "%-4s %-12s %s\n", r.Status, r.Name, r.Detail)
	}
	if failures > 0 {
		fmt.Fprintf(stdout, "\nFAILED: %d check(s) failed\n", failures)
		return exitCheck
	}
	fmt.Fprintf(stdout, "\nPASSED: all checks passed\n")
	return exitOK
}

func exitOKOrCheck(failures int) int {
	if failures > 0 {
		return exitCheck
	}
	return exitOK
}

func runChecks(opts doctorOptions) []checkResult {
	results := make([]checkResult, 0, 12)
	results = append(results, checkDeployment(opts))
	results = append(results, checkBootstrapAPIKey())
	results = append(results, checkProductionGates())
	results = append(results, checkTenancy())
	results = append(results, checkIdentityKeys())
	results = append(results, checkDelegationAuthority())
	results = append(results, checkMsgraphConnector(opts))
	results = append(results, checkDatabase(opts))
	results = append(results, checkSpiceDB(opts))
	results = append(results, checkQdrant(opts))
	results = append(results, checkElasticsearch(opts))
	results = append(results, checkWebhook())
	results = append(results, checkShadowMode())
	return results
}

// checkMsgraphConnector validates the Microsoft Graph ACL connector's
// production posture (Milestone 3): credentials must be keyring:// or
// secret-manager references (never plaintext env values in production),
// and the connector scope/drive must be configured. Registry health
// (last success, lag) is checked when DATABASE_URL is set.
//
// In production (GROUNDWORK_ENV=production), additionally validates:
//   - DATABASE_URL is set (for DB-backed keyring)
//   - GROUNDWORK_KEK_REF or GROUNDWORK_KEK_BASE64 is set (for envelope encryption)
//   - TENANT_ID is set (for tenant-scoped connector secret namespace)
//   - MS_GRAPH_CLIENT_SECRET_REF matches keyring://connector/<id>
//   - The keyring reference resolves to a secret in the tenant-scoped namespace
func checkMsgraphConnector(opts doctorOptions) checkResult {
	enabled := os.Getenv("ACL_CONNECTOR_TYPE") == "msgraph" || os.Getenv("MS_GRAPH_CONNECTOR_ENABLED") == "true"
	if !enabled {
		return checkResult{Name: "msgraph", Status: "SKIP", Detail: "Microsoft Graph connector not selected (ACL_CONNECTOR_TYPE != msgraph)"}
	}
	production := strings.EqualFold(os.Getenv("GROUNDWORK_ENV"), "production")
	secret := os.Getenv("MS_GRAPH_CLIENT_SECRET")
	secretRef := os.Getenv("MS_GRAPH_CLIENT_SECRET_REF")
	if production && secret != "" {
		return checkResult{Name: "msgraph", Status: "FAIL", Detail: "MS_GRAPH_CLIENT_SECRET is set as plaintext env; production requires MS_GRAPH_CLIENT_SECRET_REF=keyring://… or a secret-manager ref"}
	}
	if !production && secret == "" && secretRef == "" {
		return checkResult{Name: "msgraph", Status: "WARN", Detail: "no client secret configured (MS_GRAPH_CLIENT_SECRET / MS_GRAPH_CLIENT_SECRET_REF)"}
	}
	if secretRef != "" && !isSecretRef(secretRef) {
		return checkResult{Name: "msgraph", Status: "FAIL", Detail: fmt.Sprintf("MS_GRAPH_CLIENT_SECRET_REF %q is not a keyring:// or secret-manager reference", secretRef)}
	}
	// In production, enforce strict requirements and validate the
	// tenant-scoped keyring resolution.
	var dbOpts *keyring.DBKeyProviderOptions
	if production {
		if opts.database == "" {
			return checkResult{Name: "msgraph", Status: "FAIL", Detail: "production requires DATABASE_URL for DB-backed keyring"}
		}
		if os.Getenv("GROUNDWORK_KEK_REF") == "" && os.Getenv("GROUNDWORK_KEK_BASE64") == "" {
			return checkResult{Name: "msgraph", Status: "FAIL", Detail: "production requires GROUNDWORK_KEK_REF or GROUNDWORK_KEK_BASE64 for key encryption"}
		}
		if os.Getenv("MS_GRAPH_TENANT_ID") == "" {
			return checkResult{Name: "msgraph", Status: "FAIL", Detail: "production requires MS_GRAPH_TENANT_ID for tenant-scoped connector secrets"}
		}
		dbOpts = keyring.BuildDBKeyProviderOptions()
		if dbOpts == nil {
			return checkResult{Name: "msgraph", Status: "FAIL", Detail: "failed to build DB keyring options in production"}
		}
		dbOpts.TenantID = os.Getenv("MS_GRAPH_TENANT_ID")
		defer keyring.CloseDB(dbOpts.DB)
	}
	// Resolve the reference NOW through the keyring resolver — the same
	// gate acl-sync enforces at startup. The outcome and the credential
	// expiry are reported; the secret itself is never printed.
	credentialDetail := ""
	if secretRef != "" {
		resolver, expiry, err := keyring.GuardConnectorSecret(context.Background(), production, secret, secretRef, dbOpts)
		if err != nil {
			return checkResult{Name: "msgraph", Status: "FAIL", Detail: fmt.Sprintf("MS_GRAPH_CLIENT_SECRET_REF does not resolve: %v", err)}
		}
		credentialDetail = "credentials via keyring reference"
		if resolver == nil {
			credentialDetail = "credentials via env reference (local/dev only)"
		}
		if !expiry.IsZero() {
			credentialDetail += "; credential expiry " + expiry.UTC().Format(time.RFC3339)
		}
	}
	required := []struct{ name, value string }{
		{"MS_GRAPH_TENANT_ID", os.Getenv("MS_GRAPH_TENANT_ID")},
		{"MS_GRAPH_CLIENT_ID", os.Getenv("MS_GRAPH_CLIENT_ID")},
		{"MS_GRAPH_DRIVE_ID", os.Getenv("MS_GRAPH_DRIVE_ID")},
	}
	for _, r := range required {
		if r.value == "" {
			return checkResult{Name: "msgraph", Status: "FAIL", Detail: fmt.Sprintf("%s is required when the msgraph connector is selected", r.name)}
		}
	}
	detail := "scope + drive configured"
	if credentialDetail != "" {
		detail += "; " + credentialDetail
	}
	if opts.database == "" {
		return checkResult{Name: "msgraph", Status: "PASS", Detail: detail + " (DATABASE_URL unset: installation registry not checked)"}
	}
	db, err := sql.Open("pgx", opts.database)
	if err != nil {
		return checkResult{Name: "msgraph", Status: "FAIL", Detail: fmt.Sprintf("invalid DATABASE_URL: %v", err)}
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	var lastSuccess sql.NullTime
	var status string
	err = db.QueryRowContext(ctx,
		`SELECT status, last_success_at FROM connector_installations WHERE tenant_id = $1 AND provider = 'msgraph'`,
		os.Getenv("MS_GRAPH_TENANT_ID"),
	).Scan(&status, &lastSuccess)
	if err != nil {
		if err == sql.ErrNoRows {
			return checkResult{Name: "msgraph", Status: "WARN", Detail: detail + "; no installation record yet (run acl-sync once)"}
		}
		return checkResult{Name: "msgraph", Status: "FAIL", Detail: fmt.Sprintf("registry probe: %v", err)}
	}
	if status == "failed" || status == "disabled" {
		return checkResult{Name: "msgraph", Status: "FAIL", Detail: fmt.Sprintf("installation status is %q", status)}
	}
	age := "never succeeded"
	if lastSuccess.Valid {
		age = time.Since(lastSuccess.Time).Truncate(time.Second).String() + " ago"
	}
	return checkResult{Name: "msgraph", Status: "PASS", Detail: fmt.Sprintf("%s; installation %q, last success %s", detail, status, age)}
}

// isSecretRef reports whether ref is a keyring:// or approved
// secret-manager reference (mirrors aclsync.IsKeyringRef without the
// import cycle surface).
func isSecretRef(ref string) bool {
	r := strings.TrimSpace(ref)
	return strings.HasPrefix(r, "keyring://") ||
		strings.HasPrefix(r, "secretsmanager://") ||
		strings.HasPrefix(r, "aws:secretsmanager:") ||
		strings.HasPrefix(r, "gcp:secretmanager:") ||
		strings.HasPrefix(r, "vault://")
}

func checkDeployment(opts doctorOptions) checkResult {
	cfg := deployment.ConfigFromEnvironment()
	production := strings.EqualFold(os.Getenv("GROUNDWORK_ENV"), "production")
	// Local/dev runs without a deployment region are deliberately
	// unvalidated — the runtime behaves the same way (main.go skips the
	// sovereign validation block when DeploymentRegion is empty).
	if cfg.DeploymentRegion == "" && !production {
		return checkResult{Name: "deployment", Status: "PASS", Detail: "no deployment region configured (local mode; sovereign validation deferred)"}
	}
	problems := deployment.Validate(cfg, deployment.ValidateOptions{
		Production:         production,
		StrictKeys:         true,
		ApprovedEgressOnly: true,
	})
	if len(problems) == 0 {
		mode := "local"
		if production {
			mode = "production"
		}
		return checkResult{Name: "deployment", Status: "PASS", Detail: fmt.Sprintf("mode=%s region=%s", mode, cfg.DeploymentRegion)}
	}
	details := make([]string, 0, len(problems))
	for _, p := range problems {
		details = append(details, p.Error())
	}
	return checkResult{Name: "deployment", Status: "FAIL", Detail: strings.Join(details, "; ")}
}

func checkBootstrapAPIKey() checkResult {
	key := os.Getenv("BOOTSTRAP_API_KEY")
	if key == "" {
		key = runtime.DefaultBootstrapAPIKey
	}
	if err := runtime.ValidateBootstrapAPIKey(key, os.Getenv("GROUNDWORK_ENV")); err != nil {
		return checkResult{Name: "bootstrap-api-key", Status: "FAIL", Detail: err.Error()}
	}
	return checkResult{Name: "bootstrap-api-key", Status: "PASS", Detail: "bootstrap key is not the public default"}
}

// checkProductionGates evaluates the consolidated G1-G8 fail-closed
// startup requirements. Local/dev mode passes without checks; a non-local
// environment reports every failing gate.
func checkProductionGates() checkResult {
	cfg := runtime.ProductionConfig{
		Env:                    os.Getenv("GROUNDWORK_ENV"),
		BootstrapKey:           os.Getenv("BOOTSTRAP_API_KEY"),
		BootstrapTenant:        os.Getenv("BOOTSTRAP_TENANT_ID"),
		AuditSalt:              os.Getenv("IMMUTABLE_AUDIT_SALT"),
		OIDCIssuer:             os.Getenv("GROUNDWORK_OIDC_ISSUER"),
		JWTSecret:              os.Getenv("GROUNDWORK_JWT_HS_SECRET"),
		JWTPrivateKey:          os.Getenv("GROUNDWORK_JWT_RS_PRIVATE_KEY"),
		JWTPrivateKeyFile:      os.Getenv("GROUNDWORK_JWT_RS_PRIVATE_KEY_FILE"),
		AllowMemoryAPIKeys:     os.Getenv("ALLOW_MEMORY_API_KEYS") == "true",
		SpiceDBPlaintext:       os.Getenv("SPICEDB_INSECURE_PLAINTEXT") == "true",
		DatabaseURL:            os.Getenv("DATABASE_URL"),
		FirewallMode:           os.Getenv("GW_FIREWALL_MODE"),
		FirewallExplicitOptOut: os.Getenv("GW_FIREWALL_OPT_OUT") == "true",
	}
	gates := runtime.ValidateProductionGates(cfg)
	if len(gates) == 0 {
		if runtime.IsLocalEnv(cfg.Env) {
			return checkResult{Name: "production-gates", Status: "PASS", Detail: "local mode — production gates deferred"}
		}
		return checkResult{Name: "production-gates", Status: "PASS", Detail: "all production gates satisfied"}
	}
	details := make([]string, 0, len(gates))
	for _, g := range gates {
		details = append(details, g.Code+": "+g.Detail)
	}
	return checkResult{Name: "production-gates", Status: "FAIL", Detail: strings.Join(details, "; ")}
}

func checkTenancy() checkResult {
	raw := os.Getenv("GROUNDWORK_TENANT_REGIONS")
	if raw == "" {
		return checkResult{Name: "tenancy", Status: "SKIP", Detail: "GROUNDWORK_TENANT_REGIONS not set (single-region mode)"}
	}
	tenancy, err := deployment.FromEnvironment()
	if err != nil {
		return checkResult{Name: "tenancy", Status: "FAIL", Detail: fmt.Sprintf("invalid GROUNDWORK_TENANT_REGIONS %q: %v", raw, err)}
	}
	regions := make([]string, 0)
	if tenancy != nil {
		for _, t := range tenancy.Tenants() {
			if region, _, ok := tenancy.Resolve(t); ok {
				regions = append(regions, region)
			}
		}
	}
	return checkResult{Name: "tenancy", Status: "PASS", Detail: fmt.Sprintf("regions=%s", strings.Join(regions, ","))}
}

func checkIdentityKeys() checkResult {
	oidc := os.Getenv("GROUNDWORK_OIDC_ISSUER")
	hs := os.Getenv("GROUNDWORK_JWT_HS_SECRET")
	if oidc != "" {
		return checkResult{Name: "identity", Status: "PASS", Detail: fmt.Sprintf("OIDC issuer configured (%s)", oidc)}
	}
	if len(hs) < 32 {
		return checkResult{Name: "identity", Status: "FAIL", Detail: "no OIDC issuer and GROUNDWORK_JWT_HS_SECRET is missing or shorter than 32 characters (console JWT minting needs it)"}
	}
	return checkResult{Name: "identity", Status: "PASS", Detail: "JWT HS secret configured (>= 32 chars)"}
}

func checkDelegationAuthority() checkResult {
	keyringStore := keyring.New(keyring.NewEnvProvider())
	missing := keyringStore.MissingPurposes(context.Background())
	if len(missing) > 0 && strings.EqualFold(os.Getenv("GROUNDWORK_ENV"), "production") {
		return checkResult{Name: "delegation", Status: "FAIL", Detail: fmt.Sprintf("key material missing for purposes: %s", strings.Join(missing, ", "))}
	}
	if _, err := governance.BuildAuthority(); err != nil {
		return checkResult{Name: "delegation", Status: "FAIL", Detail: err.Error()}
	}
	return checkResult{Name: "delegation", Status: "PASS", Detail: "delegation signing key resolves (RS256 preferred, HS256 >= 32 chars accepted)"}
}

func checkDatabase(opts doctorOptions) checkResult {
	if opts.database == "" {
		return checkResult{Name: "database", Status: "SKIP", Detail: "DATABASE_URL not set (in-memory local mode)"}
	}
	db, err := sql.Open("pgx", opts.database)
	if err != nil {
		return checkResult{Name: "database", Status: "FAIL", Detail: fmt.Sprintf("invalid DATABASE_URL: %v", err)}
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return checkResult{Name: "database", Status: "FAIL", Detail: fmt.Sprintf("ping: %v", err)}
	}
	missing, err := missingSchemaTables(ctx, db)
	if err != nil {
		return checkResult{Name: "database", Status: "FAIL", Detail: fmt.Sprintf("schema probe: %v", err)}
	}
	if len(missing) > 0 {
		return checkResult{Name: "database", Status: "FAIL", Detail: fmt.Sprintf("reachable, but tables missing (run migrations): %s", strings.Join(missing, ", "))}
	}
	return checkResult{Name: "database", Status: "PASS", Detail: "reachable; core schema tables present (migrations 003..027)"}
}

// schemaTables is the set of tables the runtime depends on across the
// migration sequence. A doctor FAIL here means migrations were not
// applied to this database.
var schemaTables = []string{
	"audit_log", "agents", "tools", "agent_tool_grants",
	"delegated_authority_grants", "agent_runs", "agent_action_decisions",
	"emergency_controls", "agent_action_budgets", "tenant_regions",
	"connectors", "external_agents", "agent_trust_relationships",
	"external_nonces", "transfer_policies", "consent_records",
	"external_budget_policies", "trust_events",
	"tenants", "tenant_events",
	"api_keys",
}

func missingSchemaTables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	present := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		present[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var missing []string
	for _, table := range schemaTables {
		if !present[table] {
			missing = append(missing, table)
		}
	}
	return missing, nil
}

func checkSpiceDB(opts doctorOptions) checkResult {
	if opts.spicedb == "" {
		return checkResult{Name: "spicedb", Status: "SKIP", Detail: "SPICEDB_ENDPOINT not set (no live relationship checks)"}
	}
	sdbOpts, tlsErr := spicedb.EnvOptions()
	if tlsErr != nil {
		return checkResult{Name: "spicedb", Status: "FAIL", Detail: fmt.Sprintf("transport: %v", tlsErr)}
	}
	sdbOpts = append(sdbOpts, spicedb.WithTimeout(opts.timeout))
	client, err := spicedb.New(opts.spicedb, os.Getenv("SPICEDB_TOKEN"), sdbOpts...)
	if err != nil {
		return checkResult{Name: "spicedb", Status: "FAIL", Detail: fmt.Sprintf("client: %v", err)}
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	// Deep readiness: gRPC health + schema write + schema drift check
	// against the embedded groundwork.zed.
	if err := client.Ready(ctx); err != nil {
		return checkResult{Name: "spicedb", Status: "FAIL", Detail: err.Error()}
	}
	return checkResult{Name: "spicedb", Status: "PASS", Detail: fmt.Sprintf("%s healthy; schema matches embedded groundwork.zed", opts.spicedb)}
}

func checkQdrant(opts doctorOptions) checkResult {
	if opts.qdrant == "" {
		return checkResult{Name: "qdrant", Status: "SKIP", Detail: "QDRANT_URL not set (memory backend)"}
	}
	return probeURL(opts, "qdrant", strings.TrimSuffix(opts.qdrant, "/")+"/healthz")
}

func checkElasticsearch(opts doctorOptions) checkResult {
	if opts.elastic == "" {
		return checkResult{Name: "elasticsearch", Status: "SKIP", Detail: "ELASTICSEARCH_URL not set (memory backend)"}
	}
	return probeURL(opts, "elasticsearch", opts.elastic)
}

func probeURL(opts doctorOptions, name, url string) checkResult {
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return checkResult{Name: name, Status: "FAIL", Detail: fmt.Sprintf("invalid URL %q: %v", url, err)}
	}
	resp, err := opts.client.Do(req)
	if err != nil {
		return checkResult{Name: name, Status: "FAIL", Detail: fmt.Sprintf("%s unreachable: %v", url, err)}
	}
	defer resp.Body.Close()
	// Drain a small body so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return checkResult{Name: name, Status: "PASS", Detail: fmt.Sprintf("%s healthy (%d)", url, resp.StatusCode)}
	}
	return checkResult{Name: name, Status: "FAIL", Detail: fmt.Sprintf("%s unhealthy (HTTP %d)", url, resp.StatusCode)}
}

func checkWebhook() checkResult {
	url := os.Getenv("GROUNDWORK_OUTBOX_WEBHOOK_URL")
	if url == "" {
		return checkResult{Name: "webhook", Status: "SKIP", Detail: "GROUNDWORK_OUTBOX_WEBHOOK_URL not set (outbox worker disabled)"}
	}
	if os.Getenv("GROUNDWORK_OUTBOX_WEBHOOK_SECRET") == "" {
		return checkResult{Name: "webhook", Status: "FAIL", Detail: "GROUNDWORK_OUTBOX_WEBHOOK_URL set but GROUNDWORK_OUTBOX_WEBHOOK_SECRET is missing"}
	}
	return checkResult{Name: "webhook", Status: "PASS", Detail: fmt.Sprintf("configured with HMAC secret (%s)", url)}
}

func checkShadowMode() checkResult {
	if os.Getenv("GROUNDWORK_SHADOW_MODE") == "true" {
		return checkResult{Name: "shadow", Status: "WARN", Detail: "GROUNDWORK_SHADOW_MODE=true — observe-only; nothing is blocked, only logged"}
	}
	return checkResult{Name: "shadow", Status: "PASS", Detail: "shadow mode off"}
}

// loadEnvFile applies KEY=VALUE pairs from a file to the process
// environment. The real environment wins over the file. Lines starting
// with '#' and blank lines are ignored; inline comments after values
// are not stripped (values may legitimately contain '#').
func loadEnvFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read env file: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		eq := strings.IndexByte(text, '=')
		if eq <= 0 {
			return fmt.Errorf("%s:%d: expected KEY=VALUE", path, line)
		}
		key := strings.TrimSpace(text[:eq])
		value := strings.TrimSpace(text[eq+1:])
		value = strings.Trim(value, `"'`)
		if os.Getenv(key) == "" {
			if err := os.Setenv(key, value); err != nil {
				return fmt.Errorf("%s:%d: set %s: %w", path, line, key, err)
			}
		}
	}
	return scanner.Err()
}
