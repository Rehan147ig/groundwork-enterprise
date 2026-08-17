import { auth } from "@/lib/auth";
import { effectiveRole, hasPermission, roleLabel } from "@/lib/rbac";
import { openBreakGlassAction, revokeBreakGlassAction } from "@/app/actions";

// Break Glass (Phase 8.4) standalone page — emergency operator access.
// Role-gated: admins can open/revoke time-bounded grants; every other
// role sees the read-only grants list with the creation form greyed out
// (tooltip "Requires Admin Role"). Fails closed in local demo mode, where
// there is no verified operator identity at all.

const RUNTIME_URL = process.env.QUERY_RUNTIME_URL ?? "http://localhost:8080";
const API_KEY = process.env.GROUNDWORK_API_KEY ?? "";

type Grant = {
  id: string;
  status: string;
  reason: string;
  operator_principal_id?: string;
  duration_minutes?: number;
  key_prefix?: string;
  expires_at?: string;
  requested_at?: string;
  revocation_reason?: string;
};

function fmtDate(raw: string | undefined): string {
  if (!raw) return "—";
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? raw : d.toLocaleString();
}

function statusClass(status: string): string {
  const s = status.toLowerCase();
  if (s.includes("revok")) return "bad";
  if (s.includes("expir")) return "warn";
  return "good";
}

async function listGrants(): Promise<{ grants: Grant[]; error: string | null }> {
  if (!API_KEY) {
    return { grants: [], error: "No API key configured. Set GROUNDWORK_API_KEY on the server." };
  }
  try {
    const res = await fetch(`${RUNTIME_URL}/v1/security/break-glass/grants`, {
      headers: { "X-Groundwork-API-Key": API_KEY },
      cache: "no-store",
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      return { grants: [], error: data.error ?? `break_glass_list_failed (${res.status})` };
    }
    const raw = (data as { grants?: unknown }).grants;
    return { grants: Array.isArray(raw) ? (raw as Grant[]) : [], error: null };
  } catch {
    return { grants: [], error: "Query runtime unreachable — cannot list break-glass grants." };
  }
}

export default async function BreakGlassPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const session = await auth();
  const user = session?.user;
  const role = effectiveRole(user?.roles);
  const canOperate = hasPermission(user?.roles, "break-glass");
  const denied = params.denied !== undefined;
  const failed = params.failed !== undefined;
  const { grants, error } = await listGrants();

  return (
    <div className="shell">
      <main className="main">
      <div className="page-head">
        <div>
          <p className="eyebrow">Security · Emergency Access</p>
          <h1>Break Glass</h1>
          <p>
            Time-bounded emergency admin grants. Open access, minted key shown once, hash-chained
            evidence — every opening and revocation requires a justification.
          </p>
          {user ? (
            <p className="muted">
              Signed in as <strong>{user.name ?? user.email}</strong> —{" "}
              {roleLabel(role)} role.
            </p>
          ) : (
            <p className="muted">No verified session — operator access is disabled.</p>
          )}
        </div>
        <span className={`status ${canOperate ? "good" : "warn"}`}>
          {canOperate ? "Admin — operator access enabled" : "Read-only — Requires Admin Role"}
        </span>
      </div>

      {denied && (
        <div className="mode-banner shadow">
          <strong>Action denied</strong>
          <span>Opening or revoking a break-glass grant requires the Admin role.</span>
        </div>
      )}
      {failed && (
        <div className="mode-banner shadow">
          <strong>Action failed</strong>
          <span>The runtime rejected the request — grants fail closed by design.</span>
        </div>
      )}
      {params.opened !== undefined && (
        <div className="mode-banner enforce">
          <strong>Grant opened</strong>
          <span>
            Emergency admin key was minted once. The raw key is shown only in the Console at open
            time and is never persisted.
          </span>
        </div>
      )}
      {params.revoked !== undefined && (
        <div className="mode-banner enforce">
          <strong>Grant revoked</strong>
          <span>Emergency access terminated early with evidence appended.</span>
        </div>
      )}

      <div className="grid two">
        <div className="card form-panel" title={canOperate ? undefined : "Requires Admin Role"}>
          <h2>Open emergency grant</h2>
          {canOperate ? (
            <p className="fineprint">
              Grants are time-bounded (1–1440 minutes, runtime-capped). A justification of at least
              10 characters is mandatory.
            </p>
          ) : (
            <p className="fineprint">
              This form is disabled for the {roleLabel(role)} role. Breaking glass requires a
              verified operator identity with the Admin role.
            </p>
          )}
          <form action={openBreakGlassAction}>
            <label>
              Justification
              <textarea
                className="input textarea"
                name="reason"
                placeholder="Why is emergency access required?"
                minLength={10}
                required
                disabled={!canOperate}
                title={canOperate ? undefined : "Requires Admin Role"}
              />
            </label>
            <label>
              Duration (minutes)
              <input
                className="input"
                type="number"
                name="duration_minutes"
                defaultValue={15}
                min={1}
                max={1440}
                required
                disabled={!canOperate}
                title={canOperate ? undefined : "Requires Admin Role"}
              />
            </label>
            <button
              className="button"
              type="submit"
              disabled={!canOperate}
              title={canOperate ? undefined : "Requires Admin Role"}
            >
              Open emergency grant
            </button>
          </form>
        </div>

        <div className="card">
          <h2>Active &amp; past grants</h2>
          {error ? (
            <p className="error">{error}</p>
          ) : grants.length === 0 ? (
            <p className="muted">No grants opened yet.</p>
          ) : (
            <div className="grid">
              {grants.map((grant) => (
                <div key={grant.id} className="blocked-item">
                  <div className="blocked-head">
                    <strong>{grant.reason}</strong>
                    <span className={`status ${statusClass(grant.status)}`}>{grant.status}</span>
                  </div>
                  <p className="muted">
                    Operator {grant.operator_principal_id ?? "—"} · requested{" "}
                    {fmtDate(grant.requested_at)} · expires {fmtDate(grant.expires_at)}
                  </p>
                  {grant.status.toLowerCase().includes("revok") && grant.revocation_reason && (
                    <p className="muted">Revoked: {grant.revocation_reason}</p>
                  )}
                  <form action={revokeBreakGlassAction} className="fineprint">
                    <input type="hidden" name="grant_id" value={grant.id} />
                    <label>
                      Revoke with justification
                      <input
                        className="input"
                        type="text"
                        name="reason"
                        placeholder="Why is this grant being revoked?"
                        minLength={10}
                        required
                        disabled={!canOperate || grant.status.toLowerCase().includes("revok")}
                        title={
                          canOperate ? undefined : "Requires Admin Role"
                        }
                      />
                    </label>
                    <button
                      className="button"
                      type="submit"
                      disabled={!canOperate || grant.status.toLowerCase().includes("revok")}
                      title={canOperate ? undefined : "Requires Admin Role"}
                    >
                      Revoke grant
                    </button>
                  </form>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </main>
    </div>
  );
}