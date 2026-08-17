package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"groundwork/query-runtime/internal/aclsync"
	"groundwork/query-runtime/internal/aclsync/github"
	"groundwork/query-runtime/internal/aclsyncwebhook"
	"groundwork/query-runtime/internal/agentregistry"
	"groundwork/query-runtime/internal/breakglass"
	"groundwork/query-runtime/internal/connectors"
	"groundwork/query-runtime/internal/connectorsvc"
	"groundwork/query-runtime/internal/deployment"
	"groundwork/query-runtime/internal/engine"
	"groundwork/query-runtime/internal/firewall"
	"groundwork/query-runtime/internal/governance"
	"groundwork/query-runtime/internal/hybrid"
	"groundwork/query-runtime/internal/keyring"
	"groundwork/query-runtime/internal/leakreport"
	"groundwork/query-runtime/internal/mcp"
	gwmetrics "groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/notifications"
	"groundwork/query-runtime/internal/outbox"
	"groundwork/query-runtime/internal/policy"
	"groundwork/query-runtime/internal/relationship"
	"groundwork/query-runtime/internal/relationship/spicedb"
	"groundwork/query-runtime/internal/runtime"
	"groundwork/query-runtime/internal/telemetry"
	"groundwork/query-runtime/internal/tenancy"
	"groundwork/query-runtime/internal/usage"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	groundworkEnv := os.Getenv("GROUNDWORK_ENV")
	bootstrapAPIKey := env("BOOTSTRAP_API_KEY", runtime.DefaultBootstrapAPIKey)
	if err := runtime.ValidateBootstrapAPIKey(bootstrapAPIKey, groundworkEnv); err != nil {
		log.Fatalf("startup refused: %v", err)
	}

	cfg := runtime.Config{
		Addr:                  env("QUERY_RUNTIME_ADDR", ":8080"),
		QueryTimeout:          envDuration("QUERY_TIMEOUT_MS", 15*time.Second),
		BackendHTTPTimeout:    envDuration("BACKEND_HTTP_TIMEOUT_MS", 15*time.Second),
		EmbeddingTimeout:      envDuration("EMBEDDING_TIMEOUT_MS", 15*time.Second),
		CircuitOpenTimeout:    envDuration("QDRANT_CIRCUIT_OPEN_TIMEOUT_MS", 10*time.Second),
		CircuitFailureLimit:   envInt("QDRANT_CIRCUIT_FAILURE_LIMIT", 3),
		CircuitHalfOpenLimit:  envInt("QDRANT_CIRCUIT_HALF_OPEN_LIMIT", 1),
		DatabaseURL:           os.Getenv("DATABASE_URL"),
		BootstrapAPIKey:       bootstrapAPIKey,
		BootstrapTenantID:     env("BOOTSTRAP_TENANT_ID", "acme"),
		BootstrapTenantRegion: env("BOOTSTRAP_TENANT_REGION", "US"),
		IDKThreshold:          envFloat("IDK_THRESHOLD", 0.70),
		VectorWeight:          envFloat("VECTOR_WEIGHT", 0.60),
		KeywordWeight:         envFloat("KEYWORD_WEIGHT", 0.40),
	}

	// Relationship authorization backend. The binary constructs the
	// adapter; business logic only consumes the neutral
	// relationship.Authorizer / relationship.Store interfaces.
	//
	// Backend selection:
	//   - SPICEDB_ENDPOINT set -> SpiceDB (tenant-scoped, deep readiness,
	//     circuit breaker, TLS by default)
	//   - unset -> no live backend (in-memory demo/dev, fail-closed
	//     MemoryACLChecker)
	//
	// Shadowing (SHADOW_AUTHORIZER=spicedb + SPICEDB_SHADOW_ENDPOINT):
	// mirrors sampled checks to a second SpiceDB instance while the
	// primary keeps deciding; SPICEDB_SHADOW_FALLBACK=true lets the
	// shadow answer when the primary fails. Retained as an operations
	// tool for staged backend upgrades.
	var relAuth relationship.Authorizer
	var relStore relationship.Store
	var spicedbClient *spicedb.Client

	buildSpiceDB := func(endpoint, token string, breaker *relationship.CircuitBreaker) (*spicedb.Client, error) {
		opts, err := spicedb.EnvOptions()
		if err != nil {
			return nil, fmt.Errorf("spicedb transport: %w", err)
		}
		if mode := os.Getenv("SPICEDB_CONSISTENCY"); mode != "" {
			opts = append(opts, spicedb.WithConsistency(mode))
		}
		if breaker != nil {
			opts = append(opts,
				spicedb.WithCircuitBreaker(breaker),
				spicedb.WithOnCircuitTrip(gwmetrics.RecordSpiceDBCircuitTrip),
			)
		}
		return spicedb.New(endpoint, token, opts...)
	}

	if endpoint := os.Getenv("SPICEDB_ENDPOINT"); endpoint != "" {
		breaker := relationship.NewCircuitBreaker(relationship.CircuitBreakerSettings{
			Name:          "spicedb",
			FailureLimit:  envInt("SPICEDB_CIRCUIT_FAILURE_LIMIT", 5),
			OpenTimeout:   envDuration("SPICEDB_CIRCUIT_OPEN_TIMEOUT_MS", 10*time.Second),
			HalfOpenLimit: envInt("SPICEDB_CIRCUIT_HALF_OPEN_LIMIT", 1),
		})
		var err error
		spicedbClient, err = buildSpiceDB(endpoint, os.Getenv("SPICEDB_TOKEN"), breaker)
		if err != nil {
			log.Fatalf("SPICEDB_ENDPOINT: %v", err)
		}
		defer spicedbClient.Close()
		relAuth = spicedbClient
		relStore = spicedbClient
		cfg.Authorizer = relAuth
		log.Printf("relationship backend: spicedb (%s) consistency=%s circuit_breaker=%t",
			endpoint, env("SPICEDB_CONSISTENCY", spicedb.ConsistencyAtLeastAsFresh), breaker != nil)
	} else {
		log.Printf("relationship backend: none configured (SPICEDB_ENDPOINT unset) — in-memory demo mode")
	}

	// Shadow phase: mirror sampled checks to a second SpiceDB instance
	// behind the live backend (staged backend upgrades). The shadow is
	// wrapped around the primary so the governance service, engine ACL
	// adapter, and MCP server all see the same Authorizer surface.
	if os.Getenv("SHADOW_AUTHORIZER") == "spicedb" {
		if relAuth == nil {
			log.Fatal("SHADOW_AUTHORIZER=spicedb requires SPICEDB_ENDPOINT (primary backend)")
		}
		shadowEndpoint := os.Getenv("SPICEDB_SHADOW_ENDPOINT")
		if shadowEndpoint == "" {
			log.Fatal("SHADOW_AUTHORIZER=spicedb requires SPICEDB_SHADOW_ENDPOINT")
		}
		shadowBreaker := relationship.NewCircuitBreaker(relationship.CircuitBreakerSettings{
			Name:          "spicedb-shadow",
			FailureLimit:  envInt("SPICEDB_CIRCUIT_FAILURE_LIMIT", 5),
			OpenTimeout:   envDuration("SPICEDB_CIRCUIT_OPEN_TIMEOUT_MS", 10*time.Second),
			HalfOpenLimit: envInt("SPICEDB_CIRCUIT_HALF_OPEN_LIMIT", 1),
		})
		shadowClient, err := buildSpiceDB(shadowEndpoint, os.Getenv("SPICEDB_SHADOW_TOKEN"), shadowBreaker)
		if err != nil {
			log.Fatalf("SPICEDB_SHADOW_ENDPOINT: %v", err)
		}
		defer shadowClient.Close()
		relAuth = relationship.NewShadowAuthorizer(relAuth, shadowClient, relationship.ShadowOptions{
			SampleRate:    envFloat("SPICEDB_SHADOW_SAMPLE_RATE", 1.0),
			Fallback:      os.Getenv("SPICEDB_SHADOW_FALLBACK") == "true",
			OnFallback:    gwmetrics.RecordShadowFallback,
			OnShadowError: gwmetrics.RecordShadowError,
			OnMismatch:    gwmetrics.RecordShadowMismatch,
		})
		cfg.Authorizer = relAuth
		log.Printf("shadow authorizer enabled: mirroring checks to %s (sample_rate=%.2f fallback=%t)",
			shadowEndpoint, envFloat("SPICEDB_SHADOW_SAMPLE_RATE", 1.0), os.Getenv("SPICEDB_SHADOW_FALLBACK") == "true")
	}

	// ACL-sync write target: the SpiceDB store (in-memory demo when no
	// backend is configured).
	var syncSink aclsync.TupleSink
	if relStore != nil {
		syncSink = aclsync.NewStoreSink(relStore)
	}

	// Sovereign deployment validation (Phase 4): when a deployment
	// region is configured this runtime is a sovereign regional
	// deployment, and every problem in the fail-closed rule set
	// prevents startup (region/jurisdiction, co-located components,
	// public backends, unapproved egress, production keys, audit
	// storage, demo identity). Local/dev runs (no deployment region)
	// are unaffected.
	deploymentCfg := deployment.ConfigFromEnvironment()
	if deploymentCfg.DeploymentRegion != "" {
		problems := deployment.Validate(deploymentCfg, deployment.ValidateOptions{
			Production:         true,
			StrictKeys:         true,
			ApprovedEgressOnly: true,
		})
		if len(problems) > 0 {
			log.Fatalf("deployment validation failed (fails closed): %v", problems)
		}
		log.Printf("sovereign deployment validated: region=%s jurisdiction=%s tenants=%q",
			deploymentCfg.DeploymentRegion, deploymentCfg.Jurisdiction, os.Getenv("GROUNDWORK_TENANT_REGIONS"))
	}

	// Customer-managed key ring (Phase 4d): resolves key material per
	// purpose (identity, delegation, webhook, audit digest, database,
	// backup). The env provider covers local/dev and KMS-less runs;
	// production validation above already refuses missing purposes.
	// Rotation history lives here for post-rotation verification.
	keyringStore := keyring.New(keyring.NewEnvProvider())
	if missing := keyringStore.MissingPurposes(context.Background()); len(missing) > 0 {
		if deploymentCfg.DeploymentRegion != "" {
			log.Fatalf("key material missing for purposes: %v", missing)
		}
		log.Printf("local/dev: no key material for purposes %v (demo mode)", missing)
	} else {
		log.Printf("key ring provisioned: all purposes have key material (provider=%s)", keyringStore.Provider().Source())
	}

	backend := runtime.NewMemoryBackend()
	if os.Getenv("QDRANT_URL") != "" && os.Getenv("ELASTICSEARCH_URL") != "" {
		backend = runtime.NewHTTPBackend(
			os.Getenv("QDRANT_URL"),
			env("QDRANT_COLLECTION", "groundwork_chunks"),
			os.Getenv("ELASTICSEARCH_URL"),
			env("ELASTICSEARCH_INDEX", "groundwork_chunks"),
			env("EMBEDDING_URL", "http://ingestion:8090"),
			cfg,
		)
	}

	apiKeys, closeAPIKeys, err := runtime.BuildAPIKeyResolver(context.Background(), cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer closeAPIKeys()

	// Audit ledger: synchronous, append-only, tamper-evident. With DATABASE_URL set,
	// every query writes to the immutable Postgres audit_log (hash-chained); otherwise
	// an in-memory trace store is used for local/dev. The engine writes the entry
	// synchronously before returning and fails closed if the write fails.
	//
	// The same AUDIT_TIMEOUT_MS budget is used both for the engine's audit step and for the
	// Postgres writer's own per-write deadline, so the configured timeout is actually honored
	// (the writer no longer caps it at a hardcoded 30ms).
	auditWrite := envDuration("AUDIT_TIMEOUT_MS", auditTimeoutDefault(cfg.DatabaseURL))
	auditor, auditDB, closeAudit, err := buildAuditWriter(cfg.DatabaseURL, backend, auditWrite)
	if err != nil {
		log.Fatal(err)
	}
	defer closeAudit()

	// L-004: bind IMMUTABLE_AUDIT_SALT into every audit digest (write +
	// verify). Predictable values are refused at startup; empty keeps the
	// original v1 formula for local/dev and pre-salt deployments.
	auditSalt := os.Getenv("IMMUTABLE_AUDIT_SALT")
	if err := runtime.ValidateAuditSalt(auditSalt); err != nil {
		log.Fatal(err)
	}
	if auditDB != nil && auditSalt == "" {
		log.Println("warning: IMMUTABLE_AUDIT_SALT is unset with the Postgres ledger — audit digests use the unsalted v1 formula. Set a strong random salt (>=16 chars) in production; never change it after first write (see docs/threat-model.md L-004).")
	} else if w, ok := auditor.(*engine.PostgresAuditWriter); ok && auditSalt != "" {
		w.SetSalt(auditSalt)
		log.Printf("IMMUTABLE_AUDIT_SALT bound into audit write path (%d chars)", len(auditSalt))
	}

	core := &engine.Engine{
		Config: engine.TimeoutConfig{
			Total:        cfg.QueryTimeout,
			Embedding:    cfg.EmbeddingTimeout,
			QdrantSearch: envDuration("QDRANT_TIMEOUT_MS", 15*time.Second),
			ACLCheck:     envDuration("RELATIONSHIP_TIMEOUT_MS", 60*time.Millisecond),
			AuditWrite:   auditWrite,
		},
		Backend: engine.VectorRetrievalClient{Vector: backend.Vector},
		ACL:     backend.ACL,
		Auditor: auditor,
		// Observe-only mode for safe enterprise onboarding: evaluate permissions and
		// log what WOULD be blocked, but do not strip. Tenant/region stay enforced.
		ShadowMode: os.Getenv("GROUNDWORK_SHADOW_MODE") == "true",
	}

	// ---- Blueprint: hybrid authorization (L1 rules + cache, L2 backend) ----
	//
	// GW_POLICY_L1=true wraps the L2 ACL checker in the in-process L1
	// policy layer: Cedar-style rules evaluate in memory (<0.2ms), the
	// decision cache absorbs repeats (95%+ hit rates), and only cache
	// misses touch the L2 backend. Webhook revocations invalidate the
	// cache immediately (< 1s). Rules load from GW_POLICY_RULES_FILE
	// (JSON: [{"id","tenant","user","group","document","scope","effect"}]),
	// defaulting to an empty set (everything falls through to L2).
	var policyGroups *policy.MemoryGroups
	var policyCache *policy.PolicyCache
	if os.Getenv("GW_POLICY_L1") == "true" {
		policyGroups = policy.NewMemoryGroups()
		policyCache = policy.NewPolicyCache(policy.DefaultCacheConfig())
		policySet := policy.NewPolicySet()
		if rulesFile := os.Getenv("GW_POLICY_RULES_FILE"); rulesFile != "" {
			if err := loadPolicyRules(policySet, rulesFile); err != nil {
				log.Fatalf("GW_POLICY_RULES_FILE: %v", err)
			}
		}
		acl := core.ACL
		l1 := &policy.Engine{
			Set:    policySet,
			Cache:  policyCache,
			Groups: policyGroups,
			Backend: policy.BackendFunc(func(ctx context.Context, tenantID, userID, docID string) (bool, error) {
				if acl == nil {
					return false, nil
				}
				return acl.CanAccess(ctx, runtime.QueryRequest{TenantID: tenantID, UserID: userID}, runtime.Chunk{TenantID: tenantID, DocumentID: docID})
			}),
			OnDecision: func(decision policy.Decision) {
				switch decision.Source {
				case policy.SourceRule:
					effect := "deny"
					if decision.Allowed {
						effect = "allow"
					}
					gwmetrics.RecordPolicyRuleDecision("unknown", effect)
				case policy.SourceCache:
					gwmetrics.RecordPolicyL1Hit("unknown")
				case policy.SourceBackend:
					gwmetrics.RecordPolicyL1Miss("unknown")
					outcome := "denied"
					if decision.Allowed {
						outcome = "allowed"
					}
					gwmetrics.RecordPolicyL2Fallback("unknown", outcome)
				case policy.SourceBackendError:
					gwmetrics.RecordPolicyL2Fallback("unknown", "error")
				}
			},
		}
		checker := engine.NewPolicyACLChecker(l1)
		core.ACL = checker
		core.PolicyReporter = checker.Reporter
		log.Printf("L1 policy layer enabled: rules=%d", len(policySet.Rules()))
	}

	// ---- Blueprint: unified hybrid retrieval (dense + BM25, RRF fusion) ----
	//
	// GW_HYBRID_RETRIEVAL=true fuses the vector backend with the
	// in-process BM25 lexical index. Retrieved chunks are mirrored into
	// the index (self-populating, no dual-write sync job); security
	// filters (tenant, region, scope) are pushed into the lexical query
	// planner. The fused result replaces the vector-only backend.
	if os.Getenv("GW_HYBRID_RETRIEVAL") == "true" {
		lexical := hybrid.NewLexicalIndex()
		core.Backend = &hybrid.HybridRetriever{
			Dense:   &hybrid.IndexingRetriever{Dense: hybrid.VectorAdapter{Searcher: backend.Vector}, Index: lexical},
			Lexical: lexical,
			OnFusion: func(dense, lex, fused int) {
				gwmetrics.RecordHybridFusion("unknown")
			},
		}
		log.Printf("hybrid retrieval enabled: dense + BM25 lexical with RRF fusion")
	}

	// ---- Blueprint: zero-trust context firewall ----
	//
	// GW_FIREWALL_MODE=redact|block applies the filter chain to every
	// chunk before it reaches the model: PII/PHI redaction, indirect
	// prompt-injection scan (block excludes the chunk), and provenance
	// watermarking (GW_FIREWALL_WATERMARK_KEY).
	if mode := firewall.Mode(os.Getenv("GW_FIREWALL_MODE")); mode != "" && mode != firewall.ModeOff {
		fw := firewall.New(mode, os.Getenv("GW_FIREWALL_WATERMARK_KEY"))
		fw.OnReport = func(report *firewall.Report) {
			gwmetrics.RecordFirewallRedaction(report.TenantID, "aggregate")
			if report.InjectionHits > 0 {
				gwmetrics.RecordFirewallInjection(report.TenantID, "total")
			}
			for range report.InjectionBlocked {
				gwmetrics.RecordFirewallInjectionBlocked(report.TenantID)
			}
			for range report.Watermarked {
				gwmetrics.RecordFirewallWatermark(report.TenantID)
			}
		}
		core.Firewall = fw
		log.Printf("context firewall enabled: mode=%s watermark=%t", mode, os.Getenv("GW_FIREWALL_WATERMARK_KEY") != "")
	}

	// Verified end-user identity: tenant/region come from the API key, while the
	// effective user is derived from a signed OIDC/JWT assertion (fail closed). A raw
	// demo user_id is honored only when ALLOW_DEMO_IDENTITY=true.
	//
	// Enterprise OIDC (Phase 4): GROUNDWORK_OIDC_ISSUER (+ GROUNDWORK_OIDC_CLIENT_ID,
	// optional GROUNDWORK_OIDC_AUDIENCE/JWKS_URL/ALGORITHMS/TENANT_CLAIM/
	// TENANT_ALLOWLIST/ADMIN_ROLES_CLAIM/ADMIN_ROLES/CANONICAL_CLAIM) takes priority
	// over the JWT/HS secret keys. The verifier performs issuer discovery and JWKS
	// fetch at startup — an unreachable or inconsistent issuer fails startup rather
	// than degrading, and verification failures fail closed on every query.
	identityVerifier, err := runtime.BuildIdentityVerifier()
	if err != nil {
		log.Fatal(err)
	}
	allowDemoIdentity := os.Getenv("ALLOW_DEMO_IDENTITY") == "true"
	if allowDemoIdentity && !isLocalEnv() {
		log.Fatalf("ALLOW_DEMO_IDENTITY=true is forbidden when GROUNDWORK_ENV=%q: the demo identity path has no authentication and must never run outside local/dev (set GROUNDWORK_ENV=local or remove the flag)", os.Getenv("GROUNDWORK_ENV"))
	}
	if os.Getenv("ALLOW_MEMORY_API_KEYS") == "true" && !isLocalEnv() {
		log.Fatalf("ALLOW_MEMORY_API_KEYS=true is forbidden when GROUNDWORK_ENV=%q: in-memory API keys are for local tests only (set GROUNDWORK_ENV=local or remove the flag)", os.Getenv("GROUNDWORK_ENV"))
	}

	// Canonical identity (GROUNDWORK_CANONICAL_IDENTITY=true): resolve each verified end-user
	// to a tenant-scoped principal so the engine checks user:principal:<uuid> instead of the
	// raw token subject. The resolver is Postgres-backed in production and in-memory for
	// local/demo; a short-TTL cache keeps the per-query alias lookup off the hot path. The
	// flag (not the resolver) gates canonicalization, so demo/local mode keeps working when
	// it is off, and a verified-but-unresolved identity fails closed when it is on.
	canonicalIdentity := os.Getenv("GROUNDWORK_CANONICAL_IDENTITY") == "true"
	resolver, closeResolver, err := buildPrincipalResolver(cfg.DatabaseURL, envDuration("GROUNDWORK_PRINCIPAL_CACHE_TTL_MS", time.Minute))
	if err != nil {
		log.Fatal(err)
	}
	defer closeResolver()

	// Agent Registry (Phase 1: Agent Trust and Control Plane): every
	// agent is a tenant-scoped identity with lifecycle state, versions,
	// and a tamper-evident event chain. Postgres-backed when DATABASE_URL
	// is set (agents/agent_versions/agent_lifecycle_events, migration
	// 014); in-memory for local/dev mode so the demo works without a DB.
	// In-memory state is intentionally ephemeral — /v1/agents* then
	// returns the demo registry only.
	agentService := agentregistry.NewService(agentregistry.NewMemoryStore())
	if auditDB != nil {
		agentService = agentregistry.NewService(agentregistry.NewPostgresStore(auditDB))
	}

	// Delegated Authority & Governed Agent Execution (Phase 2): one
	// governance service shared by the REST runtime (/v1/governance*,
	// the /v1/query delegation gate) and the MCP server (delegation
	// tokens on groundwork_search). The delegation authority is fatal
	// at startup when no signing key is configured — a runtime serving
	// governed flows cannot silently start without one (RS256 preferred:
	// GROUNDWORK_DELEGATION_RS_PRIVATE_KEY(_FILE), else HS256 with
	// GROUNDWORK_DELEGATION_HS_SECRET >= 32 chars). The governance store
	// is Postgres-backed alongside the agents registry when DATABASE_URL
	// is set (migration 015), in-memory for local/dev. Relationship
	// check failures fail closed with evidence, so an unreachable/absent
	// backend blocks governed actions rather than allowing them.
	authority, err := governance.BuildAuthority()
	if err != nil {
		log.Fatal(err)
	}
	var authorizer relationship.Authorizer = relAuth
	var govStore governance.Store = governance.NewMemoryStore()
	if auditDB != nil {
		govStore = governance.NewPostgresStore(auditDB)
	}
	governanceService := governance.NewService(govStore, authority, authorizer, agentService)

	// envTenancy is the trusted GROUNDWORK_TENANT_REGIONS configuration
	// (Phase 4). Built early: it constrains connector registration
	// regions below and is wired as the auth-layer region resolver with
	// its tenants seeded into the provisioning directory later.
	envTenancy, err := deployment.FromEnvironment()
	if err != nil {
		log.Fatalf("invalid GROUNDWORK_TENANT_REGIONS: %v", err)
	}

	// Production Connector Gateway (Phase 5): registry, lifecycle, and
	// the invocation pipeline for governed external tools. The gateway
	// NEVER dispatches on its own — governance.DispatchAction calls it
	// only after an allowed decision, and it re-validates lifecycle,
	// region, and manifest state immediately before the outbound
	// connection. Postgres-backed alongside governance when DATABASE_URL
	// is set (migration 018), in-memory for local/dev. Secrets resolve
	// through the Phase 4 keyring (keyring://<purpose>) or the
	// environment (env://<NAME>); raw credentials never enter the
	// registry. When GROUNDWORK_TENANT_REGIONS is configured, a
	// connector may only be registered for a provisioned region —
	// anything else fails closed at registration and dispatch.
	var regionOK func(region string) bool
	if envTenancy != nil {
		provisioned := map[string]bool{}
		for _, t := range envTenancy.Tenants() {
			if r, _, ok := envTenancy.Resolve(t); ok {
				provisioned[r] = true
			}
		}
		regionOK = func(region string) bool { return provisioned[region] }
	}
	var connStore connectors.Store = connectors.NewMemoryStore()
	if auditDB != nil {
		connStore = connectors.NewPostgresStore(auditDB)
	}
	connectorGateway := connectors.NewGateway(
		connStore,
		connectors.NewKeyringSecretResolver(keyringStore),
		regionOK,
	)
	governanceService.SetConnectorDispatcher(connectorGateway)

	// Phase 8.1: usage metering & tenant limits. Counters live
	// Postgres-backed alongside the governance store when DATABASE_URL
	// is set (migration 025), in-memory for local/dev. The runtime
	// records at the HTTP layer (agents, runs, decisions, connector
	// calls, exports) and the outbox worker (deliveries); the usage API
	// (GET /v1/usage*, PUT /v1/usage/limits) exposes the snapshot.
	var usageStore usage.Store = usage.NewMemoryStore()
	if auditDB != nil {
		usageStore = usage.NewPostgresStore(auditDB)
	}
	usageService := usage.NewService(usageStore)

	// Phase 8.4: break-glass operator access. Time-bounded emergency
	// admin grants backed by the same API-key store the auth layer
	// enforces (expiry fails closed at Resolve). Postgres-backed when
	// DATABASE_URL is set (migration 026), in-memory for local/dev.
	var bgStore breakglass.Store = breakglass.NewMemoryStore()
	if auditDB != nil {
		bgStore = breakglass.NewPostgresStore(auditDB)
	}
	var keyMinter breakglass.KeyMinter
	if km, ok := apiKeys.(runtime.APIKeyManager); ok {
		keyMinter = km
	}
	breakGlassService := breakglass.NewService(
		bgStore,
		keyMinter,
		time.Duration(envInt("BREAK_GLASS_MAX_MINUTES", 60))*time.Minute,
	)

	// Milestone 5: notification delivery (Slack/Teams). Webhook URLs
	// are tenant-scoped secret references (SLACK_WEBHOOK_URL[_<TENANT>],
	// TEAMS_WORKFLOW_URL[_<TENANT>]) resolved per tenant at delivery
	// time — never compiled into code. Interactive actions are signed
	// (SLACK_SIGNING_SECRET), replay-protected, and role-checked against
	// SLACK_ADMIN_USER_IDS[_<TENANT>].
	notifier := notifications.NewFromEnv()

	// Phase 8.1: tenant provisioning directory. The operator-managed
	// directory (migration 027) is the tenant lifecycle source of
	// truth: provisioning, disable/enable, and non-destructive
	// deprovisioning, each with hash-chained evidence. Tenants from
	// GROUNDWORK_TENANT_REGIONS are seeded into it at startup (below).
	// Postgres-backed when DATABASE_URL is set, in-memory for
	// local/dev.
	var tenantStore tenancy.Store = tenancy.NewMemoryStore()
	if auditDB != nil {
		tenantStore = tenancy.NewPostgresStore(auditDB)
	}
	var tenantKeys tenancy.KeyMinter
	if km, ok := apiKeys.(runtime.APIKeyManager); ok {
		tenantKeys = km
	}
	tenantService := tenancy.NewService(tenantStore, tenantKeys)

	// MCP mode: run as stdio MCP server for AI agents (Claude Desktop, etc.)
	if os.Getenv("GROUNDWORK_MCP") == "true" {
		mcpServer := mcp.NewServer(
			core,
			env("BOOTSTRAP_TENANT_ID", "tenant_demo"),
			env("BOOTSTRAP_TENANT_REGION", "uk"),
			identityVerifier,
			allowDemoIdentity,
		)
		mcpServer.SetCanonicalIdentity(resolver, canonicalIdentity)
		mcpServer.SetGovernanceService(governanceService)
		log.Println("groundwork MCP server starting (stdio transport)")
		if err := mcpServer.Run(context.Background()); err != nil {
			log.Fatal(err)
		}
		return
	}

	// HTTP mode: REST API + the Cloud MCP endpoint (/mcp) on the same listener. Both
	// reuse the single engine `core`; /mcp authenticates with the same API key resolver.
	// Per-API-key rate limiting (enforces each key's rate_limit_rpm). One shared limiter so a
	// key's budget is consistent across the REST and Cloud MCP endpoints.
	rateLimiter := runtime.NewRateLimiter()

	// Per-tenant noisy-neighbor protections (Roadmap 8.1): a shared
	// requests/minute ceiling across all of a tenant's keys, and a cap on
	// in-flight requests per tenant. Both default to unlimited when the
	// env vars are unset/0, preserving local/demo behavior.
	var tenantLimiter *runtime.TenantRateLimiter
	if rpm := envInt("LIMIT_RPM_PER_TENANT", 0); rpm > 0 {
		tenantLimiter = runtime.NewTenantRateLimiter(rpm)
	}
	var concurrencyLimiter *runtime.TenantConcurrencyLimiter
	if cap := envInt("LIMIT_CONCURRENCY_PER_TENANT", 0); cap > 0 {
		concurrencyLimiter = runtime.NewTenantConcurrencyLimiter(cap)
	}

	// Phase 8.2 capacity model: per-tenant in-flight caps derived from
	// the tenant directory's deployment tier (standard|plus|enterprise).
	// LIMIT_CONCURRENCY_PER_TENANT is the standard-tier cap (and the
	// default for tenants outside the directory); CAPACITY_CONCURRENCY_
	// PLUS/ENTERPRISE override the higher tiers, falling back to the
	// standard cap when unset. All default 0 = unlimited, preserving
	// local/demo behavior.
	standardCap := envInt("LIMIT_CONCURRENCY_PER_TENANT", 0)
	capacityModel := &runtime.CapacityModel{
		DefaultLimit: standardCap,
		Concurrency: map[string]int{
			runtime.CapacityTierStandard:   standardCap,
			runtime.CapacityTierPlus:       envInt("CAPACITY_CONCURRENCY_PLUS", standardCap),
			runtime.CapacityTierEnterprise: envInt("CAPACITY_CONCURRENCY_ENTERPRISE", standardCap),
		},
	}

	// Phase 8.2 overload protection: an instance-wide in-flight cap.
	// Unlike the per-tenant caps, this sheds load when the WHOLE
	// process is saturated (pool exhaustion, slow dependencies) — new
	// requests get an immediate 503 overload_exceeded instead of
	// piling goroutines onto a queue. Default unlimited (0).
	var overloadLimiter *runtime.OverloadLimiter
	if cap := envInt("OVERLOAD_MAX_CONCURRENT_REQUESTS", 0); cap > 0 {
		overloadLimiter = runtime.NewOverloadLimiter(cap)
	}

	server := runtime.NewServerWithExecutor(cfg, backend, apiKeys, core)
	server.SetIdentity(identityVerifier, allowDemoIdentity)
	server.SetCanonicalIdentity(resolver, canonicalIdentity)
	server.SetRateLimiter(rateLimiter)
	server.SetTenantRateLimiter(tenantLimiter)
	server.SetConcurrencyLimiter(concurrencyLimiter)
	server.SetCapacityModel(capacityModel)
	server.SetOverloadLimiter(overloadLimiter)
	// PR #22: wire the read-side Audit API. Off when there's no
	// Postgres (local in-memory mode) — the /v1/audit* endpoints
	// return 503 audit_unavailable in that case, which is the right
	// behavior since the in-memory trace store doesn't hold the
	// hash-chained ledger the read API exposes.
	if auditDB != nil {
		auditReader := engine.NewPostgresAuditReader(auditDB)
		if auditSalt != "" {
			auditReader.SetSalt(auditSalt)
		}
		server.SetAuditReader(auditReader)
		// PR #22 HA fix #3: register a Postgres reachability probe
		// with /readyz so an unreachable DB takes the pod out of
		// rotation. The Pinger context budget is short (1s) — a slow
		// DB is functionally as bad as a dead DB for the query path
		// (audit-write fail-closed) and we want k8s to know quickly.
		server.AddReadinessProbe(runtime.ReadinessProbe{
			Name: "postgres",
			Check: func(ctx context.Context) error {
				pingCtx, cancel := context.WithTimeout(ctx, time.Second)
				defer cancel()
				return auditDB.PingContext(pingCtx)
			},
		})
	}

	// SpiceDB deep readiness: when SpiceDB is the primary authorization
	// backend, /readyz also verifies the schema written to it matches
	// the embedded groundwork.zed (fail closed with ErrModelMissing on
	// drift) so a pod never serves against a missing or stale model. The
	// probe is cheap and idempotent; a shadow-only SpiceDB is
	// intentionally NOT probed (observe-only).
	if spicedbClient != nil && relAuth == spicedbClient {
		server.AddReadinessProbe(runtime.ReadinessProbe{
			Name: "spicedb",
			Check: func(ctx context.Context) error {
				return spicedbClient.Ready(ctx)
			},
		})
	}

	// L1 policy cache readiness: when the in-process L1 layer is
	// enabled, /readyz also verifies the decision cache is fully
	// constructed. A zero-value cache silently bypasses the L1 fast
	// path, so the probe fails and the pod is de-rotated.
	if policyCache != nil {
		server.AddReadinessProbe(runtime.ReadinessProbe{
			Name:  "policy_cache",
			Check: policyCache.Ping,
		})
	}

	// Connector surface for the V1 console: POST /v1/connect/github
	// (re-sync → relationship tuples) and GET /v1/leak-report (exposure scan).
	// Uses a live GitHub client when GITHUB_TOKEN is set, else the Acme
	// MockClient so the offline demo is fully live data, not faked.
	var ghClient github.GitHubClient
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		ghClient = github.NewHTTPClient(token)
	} else {
		ghClient = github.NewMockClient()
	}
	ghOrg := env("GITHUB_ORG", "acme-financial")
	server.SetGitHubService(connectorsvc.New(
		ghClient,
		ghOrg,
		relStore,
	))

	// Background leak-report scheduler: runs the exposure scan on the
	// LEAK_REPORT_CRON cadence, persists every run into Postgres
	// (leak_report_history, migration 031; bootstrapped here so a
	// lagging migration never disables the surface) or memory in
	// offline mode, and powers GET /v1/leak-report/history + /diff.
	// The snapshot source mirrors the live endpoint's connector
	// semantics (same org, same owner map), so scheduled snapshots are
	// directly comparable to a manual scan.
	var lrHistory leakreport.HistoryStore = leakreport.NewMemoryHistoryStore()
	if auditDB != nil {
		lrStore := leakreport.NewPostgresHistoryStore(auditDB)
		bootCtx, cancelBoot := context.WithTimeout(context.Background(), 10*time.Second)
		if err := lrStore.Bootstrap(bootCtx); err != nil {
			log.Printf("leak-report history: bootstrap: %v", err)
		}
		cancelBoot()
		lrHistory = lrStore
	}
	var scanTenants []string
	if envTenancy != nil {
		scanTenants = envTenancy.Tenants()
	}
	if len(scanTenants) == 0 {
		scanTenants = []string{cfg.BootstrapTenantID}
	}
	leakCron := env("LEAK_REPORT_CRON", "@every 6h")
	leakScheduler, err := leakreport.NewScheduler(
		leakCron,
		lrHistory,
		leakreport.SnapshotFunc(func(ctx context.Context, tenantID string) (aclsync.PermissionSet, error) {
			return github.NewConnector(ghClient, ghOrg, nil).Snapshot(ctx, tenantID)
		}),
		scanTenants,
		connectorsvc.AcmeOwners(),
	)
	if err != nil {
		log.Fatalf("leak-report scheduler: %v", err)
	}
	server.SetLeakHistoryService(leakreport.NewHistoryService(lrHistory))

	// Agent Registry + Governance are constructed above and shared by
	// the REST runtime and the Cloud MCP endpoint (single registry, single
	// governance service, single evaluator).
	server.SetAgentRegistry(agentService)
	server.SetGovernanceService(governanceService)
	server.SetConnectorService(connectorGateway)
	server.SetUsageMeter(usageService)
	// Phase 8.1: DispatchAction enforces the connector_calls quota
	// fail-closed before any outbound connection opens.
	governanceService.SetUsageMeter(usageService)
	server.SetBreakGlassService(breakGlassService)
	server.SetNotifier(notifier)

	// Phase 8.2: outbox backpressure. The outbox table is the bounded
	// buffer between decisions and delivery; when the webhook is slow
	// or down, pending events accumulate without limit. The high-water
	// mark turns that into an explicit fail-closed refusal at the
	// evidence boundaries (query audit writes, governed evaluate /
	// dispatch / delegated-query) — HTTP 503 outbox_backpressure —
	// instead of a silent, unbounded backlog. Default disabled (0);
	// enable with OUTBOX_BACKPRESSURE_MAX_PENDING.
	if maxPending := envInt("OUTBOX_BACKPRESSURE_MAX_PENDING", 0); maxPending > 0 {
		if bpStore, ok := govStore.(outbox.BackpressureStore); ok {
			gate := outbox.NewBackpressure(bpStore, maxPending)
			governanceService.SetBackpressure(gate)
			core.Backpressure = gate
			log.Printf("outbox backpressure enabled: max %d pending per tenant", maxPending)
		} else {
			log.Printf("OUTBOX_BACKPRESSURE_MAX_PENDING set but the active store does not support pending counts; gate disabled")
		}
	}

	// Phase 8.1: tenant provisioning surface + auth-layer directory.
	// When the trusted GROUNDWORK_TENANT_REGIONS configuration exists it
	// is wired as the region resolver (Phase 4 — unprovisioned tenants
	// fail closed at the auth layer) and its tenants are seeded into the
	// directory so the directory is the unified tenant view. Seeding is
	// idempotent and never overrides directory state (an operator may
	// disable an env-configured tenant through the API).
	server.SetTenantService(tenantService)
	if envTenancy != nil {
		server.SetRegionResolver(envTenancy)
		seedCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		for _, tenantID := range envTenancy.Tenants() {
			if region, _, ok := envTenancy.Resolve(tenantID); ok {
				if err := tenantService.Seed(seedCtx, tenantID, region, "configured via GROUNDWORK_TENANT_REGIONS"); err != nil {
					log.Printf("tenancy: seed %s into directory: %v", tenantID, err)
				}
			}
		}
		cancel()
	}

	// Phase 8.5: support bundle source. Diagnostics only — key
	// expiries (never material), outbox health, connector registry
	// status. Readiness-probe status is added by the server itself.
	server.SetSupportBundleSource(supportBundleSource{
		keyringStore: keyringStore,
		govStore:     govStore,
		connectors:   connectorGateway,
	})

	// ---- Blueprint: real-time IAM sync webhooks (Entra ID + Okta) ----
	//
	// ACL_SYNC_WEBHOOK_SECRET enables POST /v1/security/acl-sync/{entra|okta}/{tenant_id}.
	// Events are signature-verified (HMAC), applied to the authorization
	// tuple sink (revocations delete tuples, terminations remove every
	// grant; during the SpiceDB cutover the dual sink keeps both
	// backends in sync), mirrored into the L1 group directory, and
	// immediately invalidate the L1 policy cache — sub-second
	// revocation with no polling.
	if secret := os.Getenv("ACL_SYNC_WEBHOOK_SECRET"); secret != "" {
		var sink aclsync.TupleSink
		if syncSink != nil {
			sink = syncSink
		} else {
			sink = aclsync.NewMemoryTupleSink()
		}
		var groups webhook.GroupUpdater
		if policyGroups != nil {
			groups = policyGroups
		} else {
			policyGroups = policy.NewMemoryGroups()
			groups = policyGroups
		}
		var invalidator webhook.CacheInvalidator
		if policyCache != nil {
			invalidator = &policyCacheInvalidator{cache: policyCache}
		}
		newReceiver := func(provider string) *webhook.Receiver {
			return &webhook.Receiver{
				Sink:        sink,
				Groups:      groups,
				Invalidator: invalidator,
				OnApplied: func(tenantID string, applied int) {
					log.Printf("acl-sync webhook (%s): applied %d events for %s", provider, applied, tenantID)
				},
				OnError: func(tenantID string, err error) {
					gwmetrics.RecordACLSyncError(tenantID)
				},
			}
		}
		server.SetACLSyncWebhooks(runtime.NewACLSyncWebhookHandler(newReceiver("entra"), newReceiver("okta"), secret))
		log.Printf("real-time ACL sync webhooks enabled (Entra ID + Okta), signature-authenticated")
	}

	// ---- Milestone 3: connector installation status (console status) ----
	// /v1/connectors/status surfaces tenant connector health (status,
	// last success, lag, drift, credential expiry) from the installation
	// registry. Postgres-backed when DATABASE_URL is set (migration 032),
	// in-memory otherwise.
	server.SetConnectorStatusStore(buildConnectorStatusStore())

	// Phase 3 outbox delivery worker: drains the transactional outbox
	// (governance + agent registry lifecycle events) to the configured
	// webhook, HMAC-signed. Only runs against a store that supports
	// delivery (Postgres; in-memory mode skips the worker — the local
	// outbox is inspectable via /v1/governance/outbox only when a
	// delivery-capable store is active).
	gwmetrics.RegisterPhase3()
	gwmetrics.RegisterPhase8()
	var outboxWorker *outbox.Worker
	if url := os.Getenv("GROUNDWORK_OUTBOX_WEBHOOK_URL"); url != "" {
		delivery, ok := govStore.(governance.OutboxDeliveryStore)
		if !ok {
			log.Printf("outbox webhook configured but the active store does not support delivery; worker disabled")
		} else {
			outboxWorker = outbox.NewWorker(delivery, outbox.Config{
				Endpoint:     url,
				Secret:       []byte(os.Getenv("GROUNDWORK_OUTBOX_WEBHOOK_SECRET")),
				PollInterval: envDuration("GROUNDWORK_OUTBOX_POLL_MS", 5*time.Second),
				MaxAttempts:  envInt("GROUNDWORK_OUTBOX_MAX_ATTEMPTS", 8),
				// Phase 8.1: the outbox_deliveries quota is enforced
				// fail-closed BEFORE delivery: the unit is recorded
				// (atomic check-and-increment) and an over-quota
				// tenant's events stay pending, retried each cycle
				// until the quota is raised. A delivery that then
				// fails still consumes the attempt (counters are
				// never decremented).
				PreDeliver: func(tenantID string) error {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					if err := usageService.Record(ctx, tenantID, usage.MetricOutboxDeliveries, 1); err != nil {
						var qe *usage.QuotaError
						if errors.As(err, &qe) {
							return fmt.Errorf("quota_exceeded:%s", qe.Metric)
						}
						log.Printf("usage: record outbox_deliveries for %s: %v", tenantID, err)
					}
					return nil
				},
			})
			log.Printf("outbox worker enabled: delivering to %s", url)
		}
	}

	mcpHTTP := mcp.NewHTTPServer(core, apiKeys, identityVerifier, allowDemoIdentity)
	mcpHTTP.SetCanonicalIdentity(resolver, canonicalIdentity)
	mcpHTTP.SetGovernanceService(governanceService)
	mcpHTTP.SetRateLimiter(rateLimiter)
	root := http.NewServeMux()
	root.Handle("/", telemetryMiddleware(server.Routes()))
	root.Handle("/mcp", mcpHTTP)

	// Phase 3: run the outbox worker until the process is interrupted.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if outboxWorker != nil {
		go func() {
			if err := outboxWorker.Run(ctx); err != nil {
				log.Printf("outbox worker stopped: %v", err)
			}
		}()
	}

	// Leak-report scheduler background loop (LEAK_REPORT_CRON cadence).
	// Runs for the process lifetime; a cycle failure is logged and the
	// next cadence proceeds. LEAK_REPORT_CRON=off/disabled turns the
	// scheduler off while keeping the history/diff read surface.
	if spec := leakCron; spec != "off" && spec != "disabled" {
		go func() {
			leakScheduler.Run(ctx, func(cycleErr error) {
				log.Printf("leak-report scheduler: %v", cycleErr)
			})
		}()
		log.Printf("leak-report scheduler enabled: cadence %s tenants=%v store=%T",
			leakScheduler.Schedule(), scanTenants, lrHistory)
	}

	// Phase 8.5: key-expiry monitoring. Publishes the expiry timestamp
	// and days-until-expiry gauges for every purpose on a one-minute
	// cadence (zero = no expiry configured). Never fails startup — the
	// gauges simply report 0 when a purpose has no expiry.
	// Phase 8.5: connector credential-expiry monitoring alongside it —
	// the same cadence dates every connector secret reference
	// (keyring://<purpose>; env:// has no metadata → 0) and publishes
	// per-connector gauges for alerting. Observability-only: a scan
	// failure keeps the last published values.
	credentialScanner := connectors.NewCredentialExpiryScanner(connStore, connectorGateway.SecretResolver())
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		refresh := func() {
			for purpose, expiry := range keyringStore.Expiries(ctx) {
				gwmetrics.SetKeyExpiryMetrics(purpose, expiry)
			}
			if _, err := credentialScanner.Refresh(ctx); err != nil {
				log.Printf("credential expiry scan: %v", err)
			}
		}
		refresh()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()

	log.Printf("groundwork query runtime listening on %s (REST + Cloud MCP at POST /mcp)", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, root); err != nil {
		log.Fatal(err)
	}
}

// supportBundleSource implements runtime.SupportBundleSource with the
// diagnostics available at the process boundary: key expiries (never
// key material), outbox health, and the connector registry. Section
// failures are reported per section rather than failing the whole
// archive, so a dead dependency never blocks a support escalation.
type supportBundleSource struct {
	keyringStore *keyring.Keyring
	govStore     governance.Store
	connectors   *connectors.Gateway
}

func (b supportBundleSource) Sections(ctx context.Context, tenantID string) ([]runtime.SupportBundleSection, error) {
	sections := []runtime.SupportBundleSection{
		{Name: "keys", Data: b.keyringStore.Expiries(ctx)},
	}
	if stats, ok := b.govStore.(runtime.OutboxStatsSource); ok {
		outbox, err := stats.OutboxPendingStats(ctx)
		if err == nil {
			sections = append(sections, runtime.SupportBundleSection{Name: "outbox", Data: outbox})
		}
	}
	if conns, err := b.connectors.List(ctx, tenantID); err == nil {
		sections = append(sections, runtime.SupportBundleSection{Name: "connectors", Data: conns})
	}
	return sections, nil
}

// telemetryMiddleware extracts the W3C traceparent header (if present),
// stamps the trace context on the request, and logs trace id + duration
// per request. Dependency-free: no OTel SDK — trace context only.
func telemetryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc := telemetry.NewTraceContext()
		if h := r.Header.Get("traceparent"); h != "" {
			if parsed, ok := telemetry.ParseTraceParent(h); ok {
				tc = parsed
			}
		}
		start := time.Now()
		next.ServeHTTP(w, r.WithContext(telemetry.WithTraceContext(r.Context(), tc)))
		log.Printf("trace %s %s %s (%s)", tc, r.Method, r.URL.Path, time.Since(start))
	})
}

func env(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// isLocalEnv reports whether GROUNDWORK_ENV (unset counts as local) is
// an explicitly local/development/test value. It gates the fail-closed
// startup guards on ALLOW_DEMO_IDENTITY and ALLOW_MEMORY_API_KEYS: those
// flags have no authentication and must never be enabled in a
// production-like deployment.
func isLocalEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GROUNDWORK_ENV"))) {
	case "", "local", "dev", "development", "test", "testing", "demo":
		return true
	default:
		return false
	}
}

func envFloat(key string, fallback float64) float64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return time.Duration(parsed) * time.Millisecond
}

// buildAuditWriter selects the audit sink: the immutable Postgres ledger when
// DATABASE_URL is set, otherwise the in-memory trace store for local/dev.
// Also returns the underlying *sql.DB (or nil for the in-memory case) so the
// caller can construct an audit READER from the same handle — PR #22 wires
// engine.PostgresAuditReader for /v1/audit* against this DB.
// buildConnectorStatusStore returns the connector installation store
// for /v1/connectors/status: Postgres-backed (migration 032) when
// DATABASE_URL is set, in-memory otherwise.
func buildConnectorStatusStore() aclsync.InstallationStore {
	if url := os.Getenv("DATABASE_URL"); url != "" {
		if db, err := sql.Open("pgx", url); err == nil {
			return aclsync.NewPostgresInstallationStore(db)
		}
	}
	return aclsync.NewMemoryInstallationStore()
}

func buildAuditWriter(databaseURL string, backend runtime.Backend, timeout time.Duration) (engine.AuditWriter, *sql.DB, func(), error) {
	if databaseURL == "" {
		return engine.RuntimeTraceAuditWriter{Trace: backend.Trace}, nil, func() {}, nil
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, nil, func() {}, err
	}
	tuneAuditPool(db)
	// Honor the configured AUDIT_TIMEOUT_MS for the per-write deadline. The bare
	// NewPostgresAuditWriter hardcodes a 30ms budget that is too tight for a real Postgres
	// round-trip (advisory lock + select + insert) and would fail audit writes — and thus
	// fail queries closed — under load or on a cold connection.
	return engine.NewPostgresAuditWriterWithTimeout(db, timeout), db, func() { _ = db.Close() }, nil
}

// predictableAuditSalts are IMMUTABLE_AUDIT_SALT values that are trivially
// guessable — exactly the ones an attacker with table-write privileges
// would try first when recomputing digests after tampering (L-004). Any
// non-empty salt on this list is a misconfiguration; the runtime refuses
// to start rather than run with a salt that provides no protection.
//
// Deprecated: use runtime.ValidateAuditSalt / runtime.PredictableAuditSalts.
var predictableAuditSalts = runtime.PredictableAuditSalts

// validateAuditSalt enforces the L-004 guard: predictable non-empty
// IMMUTABLE_AUDIT_SALT values are refused at startup.
//
// Deprecated: use runtime.ValidateAuditSalt.
func validateAuditSalt(salt string) error {
	return runtime.ValidateAuditSalt(salt)
}

// buildPrincipalResolver constructs the canonical principal resolver: the Postgres-backed
// resolver when DATABASE_URL is set (production), otherwise an in-memory resolver for
// local/demo. Both are wrapped in a short-TTL caching resolver so the per-query alias
// lookup does not hit the database on every request. The resolver is always non-nil — the
// GROUNDWORK_CANONICAL_IDENTITY flag, not the resolver, decides whether canonicalization runs.
func buildPrincipalResolver(databaseURL string, ttl time.Duration) (runtime.PrincipalResolver, func(), error) {
	if databaseURL == "" {
		return runtime.NewCachingResolver(runtime.NewMemoryPrincipalResolver(), ttl), func() {}, nil
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, func() {}, err
	}
	tunePrincipalPool(db)
	return runtime.NewCachingResolver(runtime.NewPostgresPrincipalResolver(db), ttl), func() { _ = db.Close() }, nil
}

// tuneAuditPool sets explicit pool limits on the audit-write *sql.DB.
// Defaults from database/sql are unsafe under load: MaxOpenConns=0
// (unbounded — under DB-slow conditions, every concurrent Engine.Execute
// goroutine spawns a new connection and the DB falls over from sheer
// connection count), MaxIdleConns=2 (steady-state traffic constantly
// thrashes connections). The bounded values below are conservative:
//
//	MaxOpenConns      25  — covers ~250 qps per pod at 100ms per audit
//	                       write; tune up if the pod is sized higher
//	MaxIdleConns       5  — keeps the steady-state path warm without
//	                       hoarding idle connections
//	ConnMaxLifetime   1h  — recycle stale connections (load balancer
//	                       and pgbouncer-style proxies can stale them)
//	ConnMaxIdleTime  5m   — return long-idle conns to the pool
//
// Env-tunable via GROUNDWORK_AUDIT_POOL_{MAX,IDLE,LIFETIME_MS,IDLE_MS}
// so operators can adjust without a rebuild. PR #22 HA review fix #1.
func tuneAuditPool(db *sql.DB) {
	db.SetMaxOpenConns(envInt("GROUNDWORK_AUDIT_POOL_MAX", 25))
	db.SetMaxIdleConns(envInt("GROUNDWORK_AUDIT_POOL_IDLE", 5))
	db.SetConnMaxLifetime(envDuration("GROUNDWORK_AUDIT_POOL_LIFETIME_MS", time.Hour))
	db.SetConnMaxIdleTime(envDuration("GROUNDWORK_AUDIT_POOL_IDLE_MS", 5*time.Minute))
}

// tunePrincipalPool sets the same defaults on the canonical-principal
// resolver DB. The resolver is read-mostly + cached, so a smaller cap
// is fine, but uniform sizing makes the operational picture simpler.
func tunePrincipalPool(db *sql.DB) {
	db.SetMaxOpenConns(envInt("GROUNDWORK_PRINCIPAL_POOL_MAX", 10))
	db.SetMaxIdleConns(envInt("GROUNDWORK_PRINCIPAL_POOL_IDLE", 2))
	db.SetConnMaxLifetime(envDuration("GROUNDWORK_PRINCIPAL_POOL_LIFETIME_MS", time.Hour))
	db.SetConnMaxIdleTime(envDuration("GROUNDWORK_PRINCIPAL_POOL_IDLE_MS", 5*time.Minute))
}

// auditTimeoutDefault gives the synchronous audit write a realistic budget: a tight
// 30ms for the in-memory store, but a larger window for a real Postgres round-trip
// (which holds a per-tenant advisory lock). Override with AUDIT_TIMEOUT_MS.
func auditTimeoutDefault(databaseURL string) time.Duration {
	if databaseURL != "" {
		return 2 * time.Second
	}
	return 30 * time.Millisecond
}

// loadPolicyRules reads L1 policy rules from a JSON file:
//
//	[{"id":"term-exec-deny","user":"alice","group":"exec","effect":"deny"},
//	 {"id":"fin-allow","group":"finance","document":"fin-*","scope":"SharePoint","effect":"allow"}]
func loadPolicyRules(set *policy.PolicySet, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var rules []policy.Rule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return err
	}
	for _, rule := range rules {
		if rule.ID == "" || rule.Effect == "" {
			return fmt.Errorf("rule %+v: id and effect are required", rule)
		}
		set.Add(rule)
	}
	return nil
}

// policyCacheInvalidator adapts policy.PolicyCache to the webhook
// receiver's invalidation contract.
type policyCacheInvalidator struct {
	cache *policy.PolicyCache
}

func (p *policyCacheInvalidator) InvalidateUser(_, userID string) {
	p.cache.InvalidateUser(userID)
}

func (p *policyCacheInvalidator) InvalidateTenant(tenantID string) {
	p.cache.InvalidateTenant(tenantID)
}
