// Command spicedb-sync reconciles enterprise source-of-truth permissions
// into SpiceDB. It is the SpiceDB twin of acl-sync: identical
// connector/source surface, different sink.
//
// Before the first sync it bootstraps the authorization model (see
// internal/relationship/schema/groundwork.zed — the single source of
// truth).
//
// Environment:
//
//	ACL_SYNC_MODE                     once|watch          (default once)
//	ACL_SYNC_TENANT_ID                tenant to sync      (default tenant_demo)
//	ACL_SYNC_INTERVAL_SECONDS         reconcile interval  (default 60,  watch mode)
//	ACL_DRIFT_CHECK_INTERVAL_SECONDS  drift interval      (default 300, watch mode)
//	ACL_CONNECTOR_TYPE                mock                (default mock)
//	SPICEDB_ENDPOINT                  SpiceDB gRPC endpoint (required, e.g. 127.0.0.1:50051)
//	SPICEDB_TOKEN                     SpiceDB preshared key (optional)
//	SPICEDB_INSECURE                  true = plaintext gRPC, dev only (default true)
//	SPICEDB_CA_FILE                   custom CA bundle (internal PKI; TLS mode)
//	SPICEDB_CONSISTENCY               read consistency (default at_least_as_fresh)
//	SPICEDB_CIRCUIT_*                 breaker tuning (failure limit / open timeout ms /
//	                                  half-open limit)
//	ACL_SYNC_METRICS_ADDR             expose Prometheus /metrics (optional, e.g. :9090)
package main

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"groundwork/query-runtime/internal/aclsync"
	"groundwork/query-runtime/internal/aclsync/msgraph"
	"groundwork/query-runtime/internal/keyring"
	"groundwork/query-runtime/internal/metrics"
	"groundwork/query-runtime/internal/relationship"
	"groundwork/query-runtime/internal/relationship/spicedb"
	"groundwork/query-runtime/internal/runtime"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg := aclsync.Config{
		Mode:               aclsync.Mode(env("ACL_SYNC_MODE", "once")),
		TenantID:           env("ACL_SYNC_TENANT_ID", "tenant_demo"),
		SyncInterval:       time.Duration(envInt("ACL_SYNC_INTERVAL_SECONDS", 60)) * time.Second,
		DriftCheckInterval: time.Duration(envInt("ACL_DRIFT_CHECK_INTERVAL_SECONDS", 300)) * time.Second,
	}

	// Canonical identity: same resolver contract as acl-sync (see there).
	canonicalIdentity := os.Getenv("GROUNDWORK_CANONICAL_IDENTITY") == "true"
	var resolver runtime.PrincipalResolver
	closeResolver := func() {}
	if canonicalIdentity {
		var err error
		resolver, closeResolver, err = buildSyncResolver(os.Getenv("DATABASE_URL"), logger)
		if err != nil {
			logger.Error("failed to build principal resolver", "err", err)
			os.Exit(1)
		}
	}
	defer closeResolver()

	connectorType := env("ACL_CONNECTOR_TYPE", "mock")
	var connector aclsync.Connector
	switch connectorType {
	case "mock":
		if canonicalIdentity {
			logger.Warn("GROUNDWORK_CANONICAL_IDENTITY=true but connector is mock; mock emits raw user tuples (canonical principals are only synced by real connectors)")
		}
		connector = aclsync.NewMockConnector()
	case "msgraph":
		if os.Getenv("MS_GRAPH_CONNECTOR_ENABLED") != "true" {
			logger.Error("msgraph connector selected but MS_GRAPH_CONNECTOR_ENABLED is not 'true'")
			os.Exit(1)
		}
		graphCfg := msgraph.Config{
			TenantID:         os.Getenv("MS_GRAPH_TENANT_ID"),
			ClientID:         os.Getenv("MS_GRAPH_CLIENT_ID"),
			ClientSecret:     os.Getenv("MS_GRAPH_CLIENT_SECRET"),
			ClientSecretRef:  os.Getenv("MS_GRAPH_CLIENT_SECRET_REF"),
			SiteID:           os.Getenv("MS_GRAPH_SITE_ID"),
			DriveID:          os.Getenv("MS_GRAPH_DRIVE_ID"),
			AuthorityHost:    os.Getenv("MS_GRAPH_AUTHORITY_HOST"),
			DeltaPollSeconds: envInt("ACL_SYNC_INTERVAL_SECONDS", 60),
			Enabled:          true,
		}
		// Credential policy gate: production runs on a resolving
		// keyring:// reference with tenant-scoped resolution.
		// Requirements in production:
		//   - GROUNDWORK_ENV=production
		//   - DATABASE_URL (for DB-backed keyring)
		//   - GROUNDWORK_KEK_REF or GROUNDWORK_KEK_BASE64 (for envelope encryption)
		//   - TENANT_ID (for per-tenant connector secret namespace)
		//   - MS_GRAPH_CLIENT_SECRET_REF matching keyring://connector/<id>
		production := strings.EqualFold(os.Getenv("GROUNDWORK_ENV"), "production")
		graphClient := msgraph.NewHTTPGraphClient(graphCfg)
		if graphCfg.ClientSecretRef != "" {
			var dbOpts *keyring.DBKeyProviderOptions
			if production {
				// Validate required production environment
				if os.Getenv("DATABASE_URL") == "" {
					logger.Error("production requires DATABASE_URL for DB-backed keyring")
					os.Exit(1)
				}
				if os.Getenv("GROUNDWORK_KEK_REF") == "" && os.Getenv("GROUNDWORK_KEK_BASE64") == "" {
					logger.Error("production requires GROUNDWORK_KEK_REF or GROUNDWORK_KEK_BASE64 for key encryption")
					os.Exit(1)
				}
				if cfg.TenantID == "" {
					logger.Error("production requires TENANT_ID (ACL_SYNC_TENANT_ID) for tenant-scoped connector secrets")
					os.Exit(1)
				}
				dbOpts = keyring.BuildDBKeyProviderOptions()
				if dbOpts == nil {
					logger.Error("failed to build DB keyring options in production")
					os.Exit(1)
				}
				dbOpts.TenantID = cfg.TenantID
				defer keyring.CloseDB(dbOpts.DB)
			}
			secretResolver, expiry, err := keyring.GuardConnectorSecret(context.Background(), production, graphCfg.ClientSecret, graphCfg.ClientSecretRef, dbOpts)
			if err != nil {
				logger.Error("connector credential gate failed; refusing to start", "err", err.Error())
				os.Exit(1)
			}
			graphCfg.CredentialExpiry = expiry
			if secretResolver != nil {
				// Scope resolver to the sync tenant for per-tenant keyring lookups
				if production && cfg.TenantID != "" {
					secretResolver = secretResolver.WithTenant(cfg.TenantID)
				}
				graphClient.SetSecretResolver(secretResolver)
				logger.Info("msgraph connector credentials resolve via keyring reference", "ref_scheme", "keyring", "tenant", cfg.TenantID)
			} else {
				graphClient.SetSecretResolver(msgraph.NewEnvSecretResolver())
				logger.Info("msgraph connector credentials resolve via env reference (local/dev only)")
			}
		} else if graphCfg.ClientSecret != "" {
			if production {
				logger.Error("MS_GRAPH_CLIENT_SECRET supplied as plaintext env, which is forbidden in production; set MS_GRAPH_CLIENT_SECRET_REF=keyring://connector/msgraph")
				os.Exit(1)
			}
			logger.Warn("MS_GRAPH_CLIENT_SECRET supplied as plaintext env; production requires MS_GRAPH_CLIENT_SECRET_REF=keyring://…")
		}
		var deltaStore msgraph.DeltaTokenStore = msgraph.NewMemoryDeltaTokenStore()
		if dir := os.Getenv("ACL_DELTA_TOKEN_DIR"); dir != "" {
			deltaStore = msgraph.NewFileDeltaTokenStore(dir)
		}
		graphConnector := msgraph.NewConnector(graphClient, graphCfg, logger, deltaStore)
		graphConnector.SetCanonicalIdentity(resolver, canonicalIdentity)
		connector = graphConnector
		logger.Info("spicedb-sync using Microsoft Graph connector", "site_id", graphCfg.SiteID, "drive_id", graphCfg.DriveID, "canonical_identity", canonicalIdentity)
	default:
		logger.Error("unsupported connector type", "type", connectorType, "supported", "mock|msgraph")
		os.Exit(1)
	}

	endpoint := os.Getenv("SPICEDB_ENDPOINT")
	if endpoint == "" {
		logger.Error("SPICEDB_ENDPOINT is required (e.g. 127.0.0.1:50051)")
		os.Exit(1)
	}
	opts, tlsErr := spicedb.EnvOptions()
	if tlsErr != nil {
		logger.Error("failed to configure spicedb transport", "err", tlsErr)
		os.Exit(1)
	}
	if env("SPICEDB_INSECURE", "") == "true" &&
		os.Getenv("SPICEDB_TLS_CA") == "" && os.Getenv("SPICEDB_TLS_CERT") == "" {
		opts = append(opts, spicedb.WithInsecurePlaintext())
	}
	if mode := os.Getenv("SPICEDB_CONSISTENCY"); mode != "" {
		opts = append(opts, spicedb.WithConsistency(mode))
	}
	opts = append(opts,
		spicedb.WithCircuitBreaker(relationship.NewCircuitBreaker(relationship.CircuitBreakerSettings{
			Name:          "spicedb",
			FailureLimit:  envInt("SPICEDB_CIRCUIT_FAILURE_LIMIT", 5),
			OpenTimeout:   time.Duration(envInt("SPICEDB_CIRCUIT_OPEN_TIMEOUT_MS", 10000)) * time.Millisecond,
			HalfOpenLimit: envInt("SPICEDB_CIRCUIT_HALF_OPEN_LIMIT", 1),
		})),
		spicedb.WithOnCircuitTrip(metrics.RecordSpiceDBCircuitTrip),
	)
	client, err := spicedb.New(endpoint, os.Getenv("SPICEDB_TOKEN"), opts...)
	if err != nil {
		logger.Error("failed to create spicedb client", "err", err)
		os.Exit(1)
	}
	defer func() { _ = client.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Bootstrap the authorization model before the first sync; WriteSchema
	// is declarative and idempotent.
	if err := client.Bootstrap(ctx); err != nil {
		logger.Error("spicedb schema bootstrap failed", "err", err)
		os.Exit(1)
	}
	logger.Info("spicedb authorization model bootstrapped")

	sink := aclsync.NewStoreSink(client)

	metrics.RegisterAll()
	if addr := os.Getenv("ACL_SYNC_METRICS_ADDR"); addr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			if err := http.ListenAndServe(addr, mux); err != nil {
				logger.Error("metrics endpoint stopped", "err", err)
			}
		}()
		logger.Info("metrics endpoint listening", "addr", addr)
	}

	svc := aclsync.NewService(connector, aclsync.NewSyncer(connector, sink, logger), cfg, logger, promMetrics{})
	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		logger.Error("spicedb-sync exited with error", "err", err)
		os.Exit(1)
	}
}

// promMetrics adapts the Prometheus collectors to aclsync.Metrics.
type promMetrics struct{}

func (promMetrics) SyncRun(t string)                       { metrics.RecordACLSyncRun(t) }
func (promMetrics) SyncError(t string)                     { metrics.RecordACLSyncError(t) }
func (promMetrics) DriftItems(t string, n int)             { metrics.SetACLSyncDriftItems(t, n) }
func (promMetrics) SyncDuration(t string, d time.Duration) { metrics.RecordACLSyncDuration(t, d) }

// buildSyncResolver builds the principal resolver the connector uses to mint principals and
// write aliases (Postgres-backed when DATABASE_URL is set, in-memory otherwise).
func buildSyncResolver(databaseURL string, logger *slog.Logger) (runtime.PrincipalResolver, func(), error) {
	if databaseURL == "" {
		logger.Warn("GROUNDWORK_CANONICAL_IDENTITY=true but DATABASE_URL is unset; using in-memory principal resolver (dev only, aliases are NOT shared with the query runtime)")
		return runtime.NewMemoryPrincipalResolver(), func() {}, nil
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, func() {}, err
	}
	return runtime.NewPostgresPrincipalResolver(db), func() { _ = db.Close() }, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
