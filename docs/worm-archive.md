# Immutable / WORM Archive Interface

Phase 8.3: a write-once archive for audit exports and long-term
retention. Sealed artifacts are **content-addressed**, can never be
overwritten or deleted through the interface, and every seal appends a
row to the tenant's append-only manifest with a **chained digest** — so
edits, deletions, and reorderings are all detected by `Verify`, which
fails closed. Sealing the same payload with the same metadata is
idempotent (returns the original artifact).

| | |
|---|---|
| Interface | `internal/archive/archive.go` (`WORMStore`) |
| File backend | `internal/archive/file_store.go` (`FileWORMStore`) |
| CLI | `cmd/archive` (`seal` / `list` / `verify` / `restore`) |
| Evidence anchors | `GET /v1/governance/audit/verify?create_checkpoint=true` + `docs/break-glass.md` style chains |

## What WORM means here

1. **Write-once.** `Seal` creates the payload blob with `O_EXCL` — an
   existing artifact is never overwritten, and there is **no delete and
   no update method** on the interface. Object-storage equivalents
   (S3 object-lock, Azure immutable blobs) can implement the same
   contract.
2. **Content-addressed.** The artifact id is SHA-256 over the full seal
   input (tenant, kind, metadata, payload), so different content can
   never collide and identical re-seals are idempotent.
3. **Tamper-evident ledger.** Each tenant's `manifest` file is an
   append-only JSONL chain: row *n* carries `prev_digest` (row *n-1*'s
   chain digest) and `chain_digest` (SHA-256 over the row's fields plus
   the previous chain state). Verify recomputes the whole prefix —
   payload digest *and* chain linkage — before reporting success.
4. **Fail-closed reads.** `Open`/`Verify` never return content whose
   digest does not match; they fail with `ErrArchiveIntegrity`.
5. **Tenant isolation.** Paths, manifests, and artifact ids are
   tenant-scoped; invalid tenant ids (traversal, separators, spaces)
   are rejected.

## Layout

```
<root>/<tenant_id>/manifest            append-only JSONL ledger
<root>/<tenant_id>/artifacts/<id>.blob sealed payload (write-once)
```

## CLI

```sh
ARCHIVE_ROOT=/mnt/worm  # or pass --root

# Seal an audit export (e.g. saved from GET /v1/governance/exports/soc2)
archive seal --tenant tenant-acme --kind audit_export \
  --file export.json --meta framework=soc2

# Record the source evidence chain anchor at seal time
archive seal --tenant tenant-acme --kind audit_export --file export.json \
  --meta framework=soc2 \
  --meta source_chain_digest=$(curl -s -H "X-Groundwork-API-Key: $KEY" \
    'http://gw:8080/v1/governance/audit/verify?create_checkpoint=true' | jq -r .chain_digest)

archive list --root /mnt/worm --tenant tenant-acme
archive verify --root /mnt/worm --tenant tenant-acme            # whole tenant chain
archive verify --root /mnt/worm --tenant tenant-acme --id <id>  # prefix through <id>
archive restore --root /mnt/worm --tenant tenant-acme --id <id> --out restored.json
```

Exit codes: `0` ok, `1` integrity violation or error, `2` usage. The
`verify` command fails closed and prints `INTEGRITY ...` with the broken
row/artifact, so it can run in a compliance cron or CI.

## Restore drills and evidence continuity

The restore path is a WORM **read**: `restore` goes through `Open`,
which verifies the payload digest and only then writes the output file.
The archive's `source_chain_digest` metadata (a governance audit
checkpoint digest sealed alongside the export) lets a restore drill
prove **evidence continuity**: after restoring, re-verify the live
evidence chain against the same boundary —

```sh
archive verify --tenant tenant-acme --id <id>
archive restore --tenant tenant-acme --id <id> --out restored-export.json
# compare restored-export.json against a fresh export; verify the live
# chain still matches the sealed source_chain_digest checkpoint
curl -s -H "X-Groundwork-API-Key: $KEY" \
  'http://gw:8080/v1/governance/audit/verify?checkpoint_id=<cp>' | jq .verified
```

A mismatch anywhere (payload edit, manifest edit, deleted artifact,
reordered ledger, or live chain drift) fails closed — the drill reports
failure instead of a silent restore.

## Verification

```sh
cd services/query-runtime
go test ./internal/archive/ -v   # idempotency, tamper, deletion, reorder, isolation
go run ./cmd/archive --help      # CLI surface
python ../scripts/check_migrations.py   # no schema change (archive is external storage)
```
