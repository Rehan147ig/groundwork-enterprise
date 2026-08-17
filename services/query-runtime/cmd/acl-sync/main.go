// Command acl-sync reconciles enterprise source-of-truth permissions into
// the relationship backend (SpiceDB).
//
// ACL_SYNC_MODE=once  (default): perform one full sync and exit.
// ACL_SYNC_MODE=watch        : perform an initial sync, then continuously apply
// permission changes and periodically reconcile + check drift until SIGINT/SIGTERM.
//
// Connectors implement the versioned connector contract
// (internal/aclsync/contract, Milestone 4): at startup the connector's
// descriptor is validated (contract.Validate) and its credential
// reference is checked against its auth spec — a connector that fails
// the contract refuses to run.
//
// Environment:
//
//	ACL_SYNC_MODE                     once|watch          (default once)
//	ACL_SYNC_TENANT_ID                tenant to sync      (default tenant_demo)
//	ACL_SYNC_INTERVAL_SECONDS         reconcile interval  (default 60,  watch mode)
//	ACL_DRIFT_CHECK_INTERVAL_SECONDS  drift interval      (default 300, watch mode)
//	ACL_CONNECTOR_TYPE                mock|msgraph        (default mock)
//	SPICEDB_ENDPOINT                  SpiceDB endpoint; unset -> in-memory sink (dev only)
//	SPICEDB_TOKEN                     SpiceDB preshared key
//	SPICEDB_INSECURE_PLAINTEXT=true   dev only, no TLS
//	SPICEDB_CA_FILE                   custom CA bundle (internal PKI)
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
	"groundwork/query-runtime/internal/aclsync/contract"
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

	// Canonical identity: when enabled, the connector pre-provisions a tenant-scoped principal
	// (and its verified aliases) for every directory user and emits user:principal:<uuid>
	// tuples. The resolver must share the query runtime's Postgres (DATABASE_URL) so the
	// aliases the sync writes are the same ones the runtime resolves at query time.
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
		// The mock source participates in the versioned contract via the
		// SDK adapter (it cannot import the contract package itself —
		// aclsync must stay contract-free).
		connector = contract.WrapConnector(aclsync.NewMockConnector(), contract.ProviderDescriptor{
			Provider:        "mock",
			ContractVersion: contract.Version,
			// Literal string: the CI production-claims check audits this.
			Status: "experimental",
			Auth:   contract.AuthSpec{Method: contract.AuthNone},
			Capabilities: []contract.Capability{
				contract.CapabilityGroups,
				contract.CapabilityFolders,
				contract.CapabilityInheritance,
				contract.CapabilityEffectivePermissions,
			},
			SupportedSubset:         "synthetic enterprise dataset (users, nested groups, folders, documents); no external identities, no deltas — correctness rests on full reconcile",
			FailClosedOutsideSubset: true,
			Retry: contract.RetryPolicy{
				Base:           250 * time.Millisecond,
				Max:            5 * time.Second,
				DefaultTimeout: 10 * time.Second,
			},
		})
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
		// Credential policy gate: in production the connector must run
		// on a keyring:// reference that resolves NOW (plaintext
		// MS_GRAPH_CLIENT_SECRET and env:// refs are startup errors);
		// local/dev keeps the env fallback. The resolver is INJECTED
		// into the Graph client — there is no silent env fallback at
		// token-fetch time.
		production := strings.EqualFold(os.Getenv("GROUNDWORK_ENV"), "production")
		graphClient := msgraph.NewHTTPGraphClient(graphCfg)
		if graphCfg.ClientSecretRef != "" {
			var dbOpts *keyring.DBKeyProviderOptions
			if production {
				dbOpts = keyring.BuildDBKeyProviderOptions()
				if dbOpts == nil {
					logger.Error("production requires DATABASE_URL and GROUNDWORK_KEK_REF (or GROUNDWORK_KEK_BASE64) for DB-backed keyring")
					os.Exit(1)
				}
				dbOpts.TenantID = cfg.TenantID // per-tenant namespace
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
				logger.Info("msgraph connector credentials resolve via keyring reference", "ref_scheme", "keyring")
			} else {
				graphClient.SetSecretResolver(msgraph.NewEnvSecretResolver())
				logger.Info("msgraph connector credentials resolve via env reference (local/dev only)")
			}
			if !expiry.IsZero() {
				logger.Info("msgraph connector credential expiry recorded", "expires_at", expiry.UTC().Format(time.RFC3339))
			}
		} else if graphCfg.ClientSecret != "" {
			if production {
				logger.Error("MS_GRAPH_CLIENT_SECRET supplied as plaintext env, which is forbidden in production; set MS_GRAPH_CLIENT_SECRET_REF=keyring://connector/msgraph")
				os.Exit(1)
			}
			logger.Warn("MS_GRAPH_CLIENT_SECRET supplied as plaintext env; production requires MS_GRAPH_CLIENT_SECRET_REF=keyring://…")
		}
		graphConnector := msgraph.NewConnector(graphClient, graphCfg, logger, nil)
		// Production-grade stores: durable delta cursor + permission
		// snapshots + installation health in Postgres (migration 032)
		// when DATABASE_URL is set; memory stores otherwise (dev/demo).
		if databaseURL := os.Getenv("DATABASE_URL"); databaseURL != "" {
			db, err := sql.Open("pgx", databaseURL)
			if err != nil {
				logger.Error("failed to open database for msgraph stores", "err", err)
				os.Exit(1)
			}
			defer func() { _ = db.Close() }()
			graphConnector.SetInstallationStore(aclsync.NewPostgresInstallationStore(db))
			graphConnector.SetSnapshotStore(msgraph.NewPostgresPermissionSnapshotStore(db))
			graphConnector.SetDeltaTokenStore(msgraph.NewPostgresDeltaTokenStore(db))
			logger.Info("msgraph connector using Postgres delta cursor, snapshots and installation registry")
		} else {
			graphConnector.SetSnapshotStore(msgraph.NewMemoryPermissionSnapshotStore())
			logger.Warn("DATABASE_URL unset; msgraph delta cursor is in-memory and health tracking is disabled (dev only)")
		}
		// Secrets are never logged; only non-sensitive identifiers.
		graphConnector.SetCanonicalIdentity(resolver, canonicalIdentity)
		connector = graphConnector
		logger.Info("acl-sync using Microsoft Graph connector", "site_id", graphCfg.SiteID, "drive_id", graphCfg.DriveID, "canonical_identity", canonicalIdentity)
	default:
		logger.Error("unsupported connector type", "type", connectorType, "supported", "mock|msgraph")
		os.Exit(1)
	}

	// Milestone 4 contract gate: a versioned connector must pass the
	// contract validation at startup (descriptor, capabilities, secret
	// refs) or the sync refuses to run — the contract is enforced at
	// runtime, not just in tests.
	if vc, ok := connector.(contract.VersionedConnector); ok {
		if err := contract.Validate(vc); err != nil {
			logger.Error("connector fails the versioned contract; refusing to run", "err", err.Error())
			os.Exit(1)
		}
		d := vc.Descriptor()
		logger.Info("connector contract validated",
			"provider", d.Provider, "contract_version", d.ContractVersion,
			"capabilities", len(d.Capabilities), "fail_closed_outside_subset", d.FailClosedOutsideSubset)
		if ref := os.Getenv("MS_GRAPH_CLIENT_SECRET_REF"); ref != "" && !contract.SecretRefOK(d, ref) {
			logger.Error("credential reference is not acceptable for the connector's auth spec", "ref", ref)
			os.Exit(1)
		}
	}

	// Write target: SpiceDB.
	//
	//	SPICEDB_ENDPOINT set  -> SpiceDB store sink (production).
	//	unset                 -> in-memory sink (dev/demo, not persisted).
	//
	// SPICEDB_CIRCUIT_* envs flow through to the SpiceDB adapter's
	// circuit breaker so a sick SpiceDB short-circuits the sync instead
	// of hammering it.
	var sink aclsync.TupleSink
	spicedbEndpoint := os.Getenv("SPICEDB_ENDPOINT")

	buildSpiceDB := func() (*spicedb.Client, error) {
		opts, err := spicedb.EnvOptions()
		if err != nil {
			return nil, err
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
		return spicedb.New(spicedbEndpoint, os.Getenv("SPICEDB_TOKEN"), opts...)
	}

	if spicedbEndpoint != "" {
		sdb, err := buildSpiceDB()
		if err != nil {
			logger.Error("failed to build SpiceDB sink", "err", err)
			os.Exit(1)
		}
		defer sdb.Close()
		sink = aclsync.NewStoreSink(sdb)
		logger.Info("acl-sync using SpiceDB store sink", "endpoint", spicedbEndpoint)
	} else {
		sink = aclsync.NewMemoryTupleSink()
		logger.Warn("no SPICEDB_ENDPOINT set; using in-memory sink (dev/demo only, not persisted)")
	}

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

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		logger.Error("acl-sync exited with error", "err", err)
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
// write aliases. It is Postgres-backed when DATABASE_URL is set (shared with the query
// runtime), otherwise an in-memory resolver for local/demo (not shared across processes —
// canonical sync against an in-memory resolver only makes sense in a single-process test).
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
