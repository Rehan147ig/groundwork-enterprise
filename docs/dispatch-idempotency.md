# Dispatch Idempotency

Phase 8.2 durability: a client retry of an **already-executed** logical
mutation must never call the upstream a second time. Every connector
dispatch carries a semantic key; once a success for that key is recorded
as immutable evidence, later retries are answered from the evidence
instead of the network.

| | |
|---|---|
| Semantic key | `Service.dispatchDedupKey` (`internal/governance/service.go`) |
| Replay decision | `DispatchAction` connector path (same file) |
| Dedup storage | `connector_invocations.idempotency_key` (migration 028) + `GetConnectorInvocationByDedupKey` |
| Upstream header | `RESTConnector.Dispatch` → `Idempotency-Key` (`internal/connectors/restconnector.go`) |
| Metrics | `groundwork_connector_dispatch_replays_total{tenant_id}` |

## The gap this closes

The evidence layer already guarantees write-once per `decision_id`, and
the client already gets a decision id back. But a client retry (network
timeout after the call executed, client crash mid-request, a new SDK
session) mints a **new** decision id — the uniqueness guarantee did not
cover the *logical* mutation. The result was the classic
at-least-once window: the upstream executes twice.

## Semantic key

`sha256(tenant | run | tool | action | resource | canonical args)`
(`json.Marshal` sorts map keys, so the same logical call always hashes
identically even when the gateway mints a new decision id). It is:

- **Deliberately not** part of `ConnectorInvocationDigest` — the digest
  stays stable so old rows keep verifying.
- Forwarded upstream as the `Idempotency-Key` header (REST transport
  only; JSON-RPC has no header surface) so the upstream can dedupe the
  crash window between an executed call and its recorded evidence.

## Replay rules

- **Success replays.** If a success for the key is recorded, the retry
  returns `DispatchResponse{DispatchMode: "replayed", Invocation: the
  recorded row}` — **no quota consumed, no connector call, no second
  invocation row**. The caller sees `allowed: true` and the recorded
  outcome (evidence-only, no stored payload).
- **Failures stay retryable.** A failed attempt records failure evidence
  under the key but never blocks the retry: the retry is a fresh
  connector call with a new attempt row. Migration 028 enforces this
  with a **partial unique index** (`WHERE idempotency_key IS NOT NULL
  AND outcome = 'success'`) — at most one success per key, unlimited
  failures.
- **Serialized in process.** A per-key refcounted lock in the Service
  serializes concurrent same-key dispatches so the connector is called
  exactly once; the partial unique index covers the multi-instance
  window (second writer gets `ErrIdempotencyConflict`, re-reads, and
  replays).

## Behavior summary

| Scenario | Behavior |
|---|---|
| First dispatch | quota → connector call → evidence row (`dispatched`) |
| Retry after success | replay from evidence (`replayed`), no quota/call/row |
| Retry after failure | fresh connector call (`dispatched` on success) |
| Same key, different args | different key → fresh call |
| Concurrent same key | one call, rest replay |
| Multi-instance race | unique index rejects second success → re-read → replay |

## Verification

```sh
cd services/query-runtime
go test ./internal/governance/ -run Idempotency   # replay/dedup/concurrency
go test ./internal/connectors/                    # Idempotency-Key header
python ../scripts/check_migrations.py             # migration gate (003..028)
```
