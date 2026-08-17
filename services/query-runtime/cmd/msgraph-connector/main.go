// Command msgraph-connector enumerates a customer's Microsoft Entra directory
// (users + groups + memberships) and persists the result into the msgraph.*
// catalog tables. PR #19 of the Microsoft Graph pilot — "directory
// enumeration, visibility only".
//
// Explicit non-goals for this build (all deferred to PR #20+):
//   - No SpiceDB writes. No relationship generation.
//   - No SharePoint, site, drive, or document enumeration.
//   - No replay, no shadow mode, no leak report.
//   - No canonical principal resolution; gw_canonical_id is stored as the
//     placeholder "entra:<oid>" for later replacement.
//
// Exit codes:
//
//	0  success
//	1  required env var missing
//	2  reserved
//	3  directory enumeration failed (auth, network, Graph error)
//	4  Postgres unavailable (connection or ping)
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	_ "github.com/jackc/pgx/v5/stdlib" // pgx driver registers itself as "pgx"

	"groundwork/query-runtime/internal/aclsync/msgraph"
	"groundwork/query-runtime/internal/keyring"
)

var requiredEnv = []string{
	"MSGRAPH_TENANT_ID",
	"MSGRAPH_CLIENT_ID",
	"MSGRAPH_CLIENT_SECRET",
	"MSGRAPH_CLIENT_SECRET_REF",
}

// validate returns the names of required env vars that are unset or empty.
// Factored out so tests exercise it without spawning a subprocess.
func validate(getenv func(string) string) []string {
	var missing []string
	for _, k := range requiredEnv {
		if getenv(k) == "" {
			missing = append(missing, k)
		}
	}
	// DATABASE_URL is new in PR #19. Either DATABASE_URL (runtime convention)
	// or POSTGRES_URL (compose convention from PR #17) is acceptable — at
	// least one must be set.
	if getenv("DATABASE_URL") == "" && getenv("POSTGRES_URL") == "" {
		missing = append(missing, "DATABASE_URL_or_POSTGRES_URL")
	}
	return missing
}

// dbURL returns the Postgres connection string, preferring DATABASE_URL
// (runtime convention) over POSTGRES_URL (compose convention).
func dbURL(getenv func(string) string) string {
	if v := getenv("DATABASE_URL"); v != "" {
		return v
	}
	return getenv("POSTGRES_URL")
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	if missing := validate(os.Getenv); len(missing) > 0 {
		logger.Error("missing required env vars", "missing", missing)
		os.Exit(1)
	}

	cfg := msgraph.Config{
		TenantID:        os.Getenv("MSGRAPH_TENANT_ID"),
		ClientID:        os.Getenv("MSGRAPH_CLIENT_ID"),
		ClientSecret:    os.Getenv("MSGRAPH_CLIENT_SECRET"),
		ClientSecretRef: os.Getenv("MSGRAPH_CLIENT_SECRET_REF"),
	}

	// Credential policy gate: production runs on a resolving
	// keyring:// reference with tenant-scoped resolution.
	// Requirements in production:
	//   - GROUNDWORK_ENV=production
	//   - DATABASE_URL (for DB-backed keyring)
	//   - GROUNDWORK_KEK_REF or GROUNDWORK_KEK_BASE64 (for envelope encryption)
	//   - TENANT_ID (MSGRAPH_TENANT_ID used as tenant ID for keyring namespace)
	//   - MSGRAPH_CLIENT_SECRET_REF matching keyring://connector/<id>
	production := strings.EqualFold(os.Getenv("GROUNDWORK_ENV"), "production")
	graphClient := msgraph.NewHTTPGraphClient(cfg)
	if cfg.ClientSecretRef != "" {
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
				logger.Error("production requires MSGRAPH_TENANT_ID for tenant-scoped connector secrets")
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
		secretResolver, expiry, err := keyring.GuardConnectorSecret(context.Background(), production, cfg.ClientSecret, cfg.ClientSecretRef, dbOpts)
		if err != nil {
			logger.Error("connector credential gate failed; refusing to start", "err", err.Error())
			os.Exit(1)
		}
		cfg.CredentialExpiry = expiry
		if secretResolver != nil {
			// Scope resolver to the connector tenant for per-tenant keyring lookups
			if production && cfg.TenantID != "" {
				secretResolver = secretResolver.WithTenant(cfg.TenantID)
			}
			graphClient.SetSecretResolver(secretResolver)
			logger.Info("msgraph connector credentials resolve via keyring reference", "ref_scheme", "keyring", "tenant", cfg.TenantID)
		} else {
			graphClient.SetSecretResolver(msgraph.NewEnvSecretResolver())
			logger.Info("msgraph connector credentials resolve via env reference (local/dev only)")
		}
	} else if cfg.ClientSecret != "" {
		if production {
			logger.Error("MSGRAPH_CLIENT_SECRET supplied as plaintext env, which is forbidden in production; set MSGRAPH_CLIENT_SECRET_REF=keyring://connector/msgraph")
			os.Exit(1)
		}
		logger.Warn("MSGRAPH_CLIENT_SECRET supplied as plaintext env; production requires MSGRAPH_CLIENT_SECRET_REF=keyring://…")
	}

	db, err := sql.Open("pgx", dbURL(os.Getenv))
	if err != nil {
		logger.Error("postgres open failed", "err", err.Error())
		os.Exit(4)
	}
	defer func() { _ = db.Close() }()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		logger.Error("postgres ping failed (is db-migrate up-to-date?)", "err", err.Error())
		os.Exit(4)
	}

	connector := msgraph.NewConnector(graphClient, cfg, logger, nil)
	catalog := msgraph.NewPostgresCatalogWriter(db)

	stats, err := connector.EnumerateDirectory(ctx, cfg.TenantID, catalog)
	if err != nil {
		switch {
		case errors.Is(err, msgraph.ErrAuthFailed):
			logger.Error("microsoft graph authentication failed", "tenant", cfg.TenantID)
		default:
			logger.Error("directory enumeration failed", "tenant", cfg.TenantID, "err", err.Error())
		}
		os.Exit(3)
	}

	// Report totals from the catalog (post-upsert) plus the stats from this
	// run. On a re-run, observed counts may equal the run stats while catalog
	// totals stay flat — that's the idempotency property.
	pTotal, _ := catalog.PrincipalCount(ctx, cfg.TenantID)
	gTotal, _ := catalog.GroupCount(ctx, cfg.TenantID)
	mTotal, _ := catalog.MembershipCount(ctx, cfg.TenantID)

	fmt.Printf(
		"msgraph-connector OK\n"+
			"  tenant_id:           %s\n"+
			"  principals (total):  %d  (this run observed %d)\n"+
			"  groups (total):      %d  (this run observed %d)\n"+
			"  memberships (total): %d  (this run observed %d)\n"+
			"  mode:                directory enumeration (PR #19; no SpiceDB, no SharePoint)\n",
		cfg.TenantID,
		pTotal, stats.PrincipalsUpserted,
		gTotal, stats.GroupsUpserted,
		mTotal, stats.MembershipsUpserted,
	)
}
