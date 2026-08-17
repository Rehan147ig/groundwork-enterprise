# Notification and Approval Delivery (Milestone 5)

Security-critical notifications (break-glass requests, approvals,
rejections, revocations) are delivered to Slack and Microsoft Teams with
hardened delivery semantics. Interactive Slack actions (approve / reject
/ revoke) drive the four-eyes break-glass flow from a chat surface.

## Requirement coverage

| Requirement | Status |
|---|---|
| Slack webhook config out of code, tenant-scoped secret ref | Done — `SLACK_WEBHOOK_URL[_<TENANT>]`, `TEAMS_WORKFLOW_URL[_<TENANT>]`; placeholder URLs removed |
| Shared hardened HTTP client, deadlines, retry, allowlisted endpoints; no `http.DefaultClient` | Done — `internal/notifications/client.go` (pool + 10s deadline + 2 retries on 429/5xx + https-only allowlist) |
| Signed Slack interactive actions w/ replay protection + server-side role checks | Done — `/v1/security/slack/actions` (HMAC v0 + 5-min timestamp window + `SLACK_ADMIN_USER_IDS[_<TENANT>]`) |
| Microsoft Teams via workflow/action mechanism | Done — AdaptiveCard to Teams workflow webhooks (`internal/notifications/teams.go`) |
| Notification failure → operational evidence + alert | Done — `notification_failed` evidence event on the grant chain + `groundwork_notification_failures_total` metric |

## Configuration (env, per tenant)

| Variable | Purpose |
|---|---|
| `SLACK_WEBHOOK_URL` | Default Slack incoming-webhook URL |
| `SLACK_WEBHOOK_URL_<TENANT>` | Tenant-scoped override (tenant ID uppercased, `-`→`_`) |
| `TEAMS_WORKFLOW_URL` / `TEAMS_WORKFLOW_URL_<TENANT>` | Teams workflow webhook URL(s) |
| `SLACK_SIGNING_SECRET` | Slack app signing secret for interactive action verification |
| `SLACK_ADMIN_USER_IDS` / `SLACK_ADMIN_USER_IDS_<TENANT>` | Comma-separated Slack user IDs allowed to act (server-side role check; empty = fail closed) |
| `NOTIFY_TIMEOUT_MS` | Delivery deadline (default 10s) |
| `GROUNDWORK_NOTIFY_HTTP_POOL_*` | Pool sizing (`MAX_IDLE`, `PER_HOST`, `IDLE_MS`) |

## Four-eyes break-glass flow

- `POST /v1/security/break-glass/grants` with `admin2_id` opens the
  grant in `pending_approval`: **no admin key is minted** (a pending
  grant carries no live key), `approver1` = opener, and the Slack
  message carries Approve/Reject buttons.
- `POST /v1/security/break-glass/grants/{id}/approve` (verified
  identity) or the Slack Approve button activates the grant: the
  admin-scoped key is minted and bound atomically, returned once to the
  approving admin, with `approved_by_admin2` evidence.
- Reject (API or Slack) → `rejected` status + `rejected` evidence.
- Revoke (API or Slack) works on active grants as before.

The actor for Slack actions is recorded as `slack:<user-id>` and must
equal the grant's `pending_approval_by` exactly (open with
`admin2_id: "slack:<user-id>"` to delegate approval to Slack).

## Security model

1. **Signature + replay** — every interactive request must present a
   valid `X-Slack-Signature` (HMAC-SHA256 over `v0:<ts>:<raw body>`,
   constant-time compare) within a 5-minute timestamp window. Rejected
   requests count in `groundwork_notification_signatures_rejected_total`.
2. **Server-side role checks** — the acting Slack user must be in the
   tenant's (or global) admin allowlist; with no allowlist configured,
   actions are denied. The grant must also be waiting on exactly that
   actor.
3. **Endpoint allowlist** — delivery is refused (before any request) to
   any endpoint other than `https://hooks.slack.com/` and
   `https://*.webhook.office.com/`. https-only.
4. **Failure visibility** — a failed delivery appends
   `notification_failed` evidence to the grant's hash-chained event
   stream and increments `groundwork_notification_failures_total{tenant,channel}`.
   An emergency action never silently succeeds without a visible
   delivery attempt.

## Schema

Migration `033_break_glass_approval` widens `break_glass_grants.status`
(`pending_approval`, `rejected`) and `break_glass_events.event_type`
(`approved_by_admin1`, `approved_by_admin2`, `rejected`,
`notification_failed`), adds the approval columns, and makes
`key_id`/`key_prefix` nullable (pending grants have no key).

## Verification

```sh
cd services/query-runtime
go test ./internal/notifications/... ./internal/breakglass/...
go test ./internal/runtime/ -run "SlackAction|BreakGlass"
python ../scripts/check_migrations.py   # 003..033
```