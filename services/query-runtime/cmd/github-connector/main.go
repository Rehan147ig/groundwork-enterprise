package main

import (
	"context"
	"flag"
	"log/slog"
	"os"

	"groundwork/query-runtime/internal/aclsync"
	"groundwork/query-runtime/internal/aclsync/github"
	"groundwork/query-runtime/internal/relationship/spicedb"
)

func main() {
	var (
		org       = flag.String("org", "acme-financial", "GitHub Organization to sync")
		spicedbEP = flag.String("spicedb-endpoint", os.Getenv("SPICEDB_ENDPOINT"), "SpiceDB gRPC endpoint (default env SPICEDB_ENDPOINT)")
		spicedbTK = flag.String("spicedb-token", os.Getenv("SPICEDB_TOKEN"), "SpiceDB preshared key (default env SPICEDB_TOKEN)")
		insecure  = flag.Bool("spicedb-insecure", false, "dial without TLS (dev only)")
	)
	flag.Parse()

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		slog.Error("GITHUB_TOKEN environment variable is required")
		os.Exit(1)
	}
	if *spicedbEP == "" {
		slog.Error("SPICEDB_ENDPOINT is required (or --spicedb-endpoint)")
		os.Exit(1)
	}

	logger := slog.Default()
	logger.Info("Starting GitHub connector", "org", *org)

	// Inject the live HTTP client
	client := github.NewHTTPClient(token)
	connector := github.NewConnector(client, *org, logger)

	// Fetch live snapshot from GitHub API
	ctx := context.Background()
	ps, err := connector.Snapshot(ctx, *org)
	if err != nil {
		logger.Error("Failed to fetch permissions from GitHub", "error", err)
		os.Exit(1)
	}

	// Map to Groundwork tuples
	tuples := aclsync.PermissionSetToTuples(ps)
	logger.Info("Successfully fetched permissions", "users", len(ps.Users), "groups", len(ps.Groups), "repos", len(ps.Documents), "tuples", len(tuples))

	// Write to SpiceDB through the relationship store adapter
	opts, tlsErr := spicedb.EnvOptions()
	if tlsErr != nil {
		logger.Error("Failed to configure SpiceDB transport", "error", tlsErr)
		os.Exit(1)
	}
	if *insecure {
		opts = append(opts, spicedb.WithInsecurePlaintext())
	}
	sdb, err := spicedb.New(*spicedbEP, *spicedbTK, opts...)
	if err != nil {
		logger.Error("Failed to build SpiceDB client", "error", err)
		os.Exit(1)
	}
	defer sdb.Close()
	if err := sdb.Ready(ctx); err != nil {
		logger.Error("SpiceDB not ready (schema ensure failed)", "error", err)
		os.Exit(1)
	}
	fgaSink := aclsync.NewStoreSink(sdb)
	if err := fgaSink.WriteTuples(ctx, *org, tuples); err != nil {
		logger.Error("Failed to sync tuples to SpiceDB", "error", err)
		os.Exit(1)
	}

	logger.Info("Sync complete.")
}
