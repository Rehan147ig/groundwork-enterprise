// Command archive is the Phase 8.3 WORM archive CLI: seal audit exports
// and evidence reports into a write-once archive, list sealed artifacts,
// verify integrity (payload digests + the per-tenant manifest chain),
// and restore a verified artifact. Restore refuses to write content
// whose integrity does not verify, so it is safe to use in restore
// drills and DR runbooks.
//
// Payload encryption (envelope AES-256-GCM): pass --kms-ref to seal
// and restore. Seal encrypts the payload before sealing (the artifact
// digest covers the ciphertext); restore decrypts with the same KEK
// reference. Without --kms-ref, payloads are stored plaintext — the
// on-disk digest/chain guarantees integrity either way.
//
// Usage:
//
//	archive seal    --root <dir> --tenant <id> --kind <kind> --file <path> [--meta k=v ...] [--kms-ref env://NAME]
//	archive list    --root <dir> --tenant <id>
//	archive verify  --root <dir> --tenant <id> [--id <artifact-id>]
//	archive restore --root <dir> --tenant <id> --id <artifact-id> --out <path> [--kms-ref env://NAME]
//
// --root defaults to $ARCHIVE_ROOT. Exit codes: 0 ok, 1 integrity
// violation or error, 2 usage.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"groundwork/query-runtime/internal/archive"
	"groundwork/query-runtime/internal/cryptosvc"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "seal":
		err = cmdSeal(args)
	case "list":
		err = cmdList(args)
	case "verify":
		err = cmdVerify(args)
	case "restore":
		err = cmdRestore(args)
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "archive: unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "archive %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `archive — WORM archive CLI (Phase 8.3)

  archive seal    --root <dir> --tenant <id> --kind <kind> --file <path> [--meta k=v ...] [--kms-ref env://NAME]
  archive list    --root <dir> --tenant <id>
  archive verify  --root <dir> --tenant <id> [--id <artifact-id>]
  archive restore --root <dir> --tenant <id> --id <artifact-id> --out <path> [--kms-ref env://NAME]

--root defaults to $ARCHIVE_ROOT. --kms-ref enables envelope encryption
(AES-256-GCM; env://NAME or file://PATH). Exit codes: 0 ok, 1 error, 2 usage.`)
}

func parseMeta(values []string) (map[string]string, error) {
	meta := map[string]string{}
	for _, kv := range values {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			return nil, fmt.Errorf("meta must be k=v, got %q", kv)
		}
		meta[strings.TrimSpace(parts[0])] = parts[1]
	}
	return meta, nil
}

func cmdSeal(args []string) error {
	fs := flag.NewFlagSet("seal", flag.ExitOnError)
	root := fs.String("root", os.Getenv("ARCHIVE_ROOT"), "archive directory (default $ARCHIVE_ROOT)")
	tenantID := fs.String("tenant", "", "tenant id")
	kind := fs.String("kind", "", "artifact kind (e.g. audit_export)")
	file := fs.String("file", "", "payload file to seal")
	kmsRef := fs.String("kms-ref", "", "envelope encryption KEK reference (env://NAME, file://PATH)")
	var metaValues multiFlag
	fs.Var(&metaValues, "meta", "metadata k=v (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*tenantID) == "" || strings.TrimSpace(*kind) == "" || strings.TrimSpace(*file) == "" {
		return fmt.Errorf("--tenant, --kind and --file are required")
	}
	payload, err := os.ReadFile(*file)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	// Envelope encryption at rest: the sealed payload is ciphertext; the
	// raw plaintext never touches the archive.
	if *kmsRef != "" {
		envelope := cryptosvc.NewEnvelope(kmsResolver(), *kmsRef)
		payload, err = envelope.Seal(context.Background(), payload)
		if err != nil {
			return fmt.Errorf("encrypt payload: %w", err)
		}
	}
	meta, err := parseMeta(metaValues)
	if err != nil {
		return err
	}
	if *kmsRef != "" {
		if meta == nil {
			meta = map[string]string{}
		}
		meta["encryption"] = "envelope_aes256gcm"
	}
	store, err := archive.NewFileWORMStore(*root)
	if err != nil {
		return err
	}
	artifact, err := store.Seal(context.Background(), *tenantID, *kind, payload, meta)
	if err != nil {
		return err
	}
	out, err := json.Marshal(artifact)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	root := fs.String("root", os.Getenv("ARCHIVE_ROOT"), "archive directory (default $ARCHIVE_ROOT)")
	tenantID := fs.String("tenant", "", "tenant id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*tenantID) == "" {
		return fmt.Errorf("--tenant is required")
	}
	store, err := archive.NewFileWORMStore(*root)
	if err != nil {
		return err
	}
	rows, err := store.List(context.Background(), *tenantID)
	if err != nil {
		return err
	}
	for _, a := range rows {
		fmt.Printf("%s  kind=%s size=%d chain=%d sealed_at=%s\n", a.ID, a.Kind, a.Size, a.ChainIndex, a.SealedAt)
	}
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	root := fs.String("root", os.Getenv("ARCHIVE_ROOT"), "archive directory (default $ARCHIVE_ROOT)")
	tenantID := fs.String("tenant", "", "tenant id")
	artifactID := fs.String("id", "", "artifact id (empty verifies the whole tenant chain)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*tenantID) == "" {
		return fmt.Errorf("--tenant is required")
	}
	store, err := archive.NewFileWORMStore(*root)
	if err != nil {
		return err
	}
	ctx := context.Background()
	target := strings.TrimSpace(*artifactID)
	if target == "" {
		rows, err := store.List(ctx, *tenantID)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Printf("OK tenant=%s no artifacts\n", *tenantID)
			return nil
		}
		target = rows[len(rows)-1].ID
	}
	artifact, err := store.Verify(ctx, *tenantID, target)
	if err != nil {
		return fmt.Errorf("INTEGRITY tenant=%s: %w", *tenantID, err)
	}
	fmt.Printf("OK tenant=%s artifact=%s chain_index=%d chain_digest=%s\n", *tenantID, artifact.ID, artifact.ChainIndex, artifact.ChainDigest)
	return nil
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	root := fs.String("root", os.Getenv("ARCHIVE_ROOT"), "archive directory (default $ARCHIVE_ROOT)")
	tenantID := fs.String("tenant", "", "tenant id")
	artifactID := fs.String("id", "", "artifact id")
	out := fs.String("out", "", "output file path")
	kmsRef := fs.String("kms-ref", "", "envelope encryption KEK reference (env://NAME, file://PATH)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*tenantID) == "" || strings.TrimSpace(*artifactID) == "" || strings.TrimSpace(*out) == "" {
		return fmt.Errorf("--tenant, --id and --out are required")
	}
	store, err := archive.NewFileWORMStore(*root)
	if err != nil {
		return err
	}
	payload, artifact, err := store.Open(context.Background(), *tenantID, *artifactID)
	if err != nil {
		return fmt.Errorf("INTEGRITY tenant=%s: %w", *tenantID, err)
	}
	if *kmsRef != "" {
		envelope := cryptosvc.NewEnvelope(kmsResolver(), *kmsRef)
		payload, err = envelope.Open(context.Background(), payload)
		if err != nil {
			return fmt.Errorf("decrypt payload (wrong --kms-ref or tampered ciphertext): %w", err)
		}
	}
	if err := os.WriteFile(*out, payload, 0o600); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	fmt.Printf("OK restored tenant=%s artifact=%s bytes=%d\n", *tenantID, artifact.ID, len(payload))
	return nil
}

// multiFlag collects repeatable flags.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// kmsResolver resolves KEK references for envelope encryption: env://NAME
// and file://PATH are built in; AWS KMS / Azure Key Vault / Vault
// adapters can be plugged in behind cryptosvc.KEKResolver.
func kmsResolver() cryptosvc.KEKResolver {
	return cryptosvc.ResolverChain{
		cryptosvc.EnvKEK{},
		cryptosvc.FileKEK{},
	}
}
