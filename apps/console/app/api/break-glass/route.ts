import { NextRequest, NextResponse } from "next/server";
import { mintConsoleAssertion } from "@/lib/jwt";
import { runtimeUserToken } from "@/lib/auth";
import { requireConsolePermission } from "@/lib/consoleAuth";

// Break-glass operator access (Phase 8.4) — the console surface for
// /v1/security/break-glass/grants.
//
//   GET  → list the tenant's grants and the minted admin key is NEVER
//          returned again (the runtime returns it once, at Open).
//   POST → open a time-bounded emergency admin grant (reason mandatory,
//          duration capped by the runtime's BREAK_GLASS_MAX_MINUTES).
//
// Security posture — deliberately NO demo fallback:
//   - reads return the real grants list, or fail with a clear error
//   - mutations require a verified operator identity: with an OIDC
//     session the IdP id_token is forwarded as Authorization: Bearer
//     (the runtime JWKS-verifies it); otherwise a short-lived
//     console-admin assertion (mintConsoleAssertion) is used. There is
//     no demo-mode plain-user_id path for emergency access
// Fail-closed by design: this surface refuses to fabricate data the way
// the read-heavy governance views do, because a fake "grant" or silent
// 503 could mislead an operator during an actual incident.

const RUNTIME_URL = process.env.QUERY_RUNTIME_URL ?? "http://localhost:8080";
const API_KEY = process.env.GROUNDWORK_API_KEY ?? "";

function requireKey(): NextResponse | null {
  if (!API_KEY) {
    return NextResponse.json(
      { error: "No API key configured. Set GROUNDWORK_API_KEY on the server." },
      { status: 500 },
    );
  }
  return null;
}

export async function GET() {
  const denied = await requireConsolePermission("break-glass");
  if (denied) return denied;
  const missing = requireKey();
  if (missing) return missing;
  let res: Response;
  try {
    res = await fetch(`${RUNTIME_URL}/v1/security/break-glass/grants`, {
      headers: { "X-Groundwork-API-Key": API_KEY },
      cache: "no-store",
    });
  } catch {
    return NextResponse.json(
      { error: "Query runtime unreachable — cannot list break-glass grants." },
      { status: 502 },
    );
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    return NextResponse.json(
      { error: data.error ?? `break_glass_list_failed (${res.status})` },
      { status: res.status === 503 ? 503 : 502 },
    );
  }
  return NextResponse.json({ ...data, source: "live" });
}

export async function POST(request: NextRequest) {
  const denied = await requireConsolePermission("break-glass");
  if (denied) return denied;
  const missing = requireKey();
  if (missing) return missing;

  const body = await request.json().catch(() => null);
  const reason = (body?.reason ?? "").toString().trim();
  const durationMinutes = Math.floor(Number(body?.duration_minutes ?? 0));
  if (reason.length < 10) {
    return NextResponse.json(
      { error: "A justification of at least 10 characters is required to open a break-glass grant." },
      { status: 400 },
    );
  }
  if (!Number.isFinite(durationMinutes) || durationMinutes < 1 || durationMinutes > 1440) {
    return NextResponse.json(
      { error: "duration_minutes must be between 1 and 1440." },
      { status: 400 },
    );
  }

  const idToken = await runtimeUserToken();
  let operatorToken: string | null = null;
  if (idToken) {
    operatorToken = idToken; // runtime JWKS-verifies the IdP id_token itself
  } else {
    operatorToken = await mintConsoleAssertion("console-operator");
  }
  if (!operatorToken) {
    return NextResponse.json(
      {
        error:
          "Opening a break-glass grant requires a verified operator identity. Configure OIDC_ISSUER/OIDC_CLIENT_ID/OIDC_CLIENT_SECRET (enterprise) or GROUNDWORK_JWT_RS_PRIVATE_KEY / GROUNDWORK_JWT_HS_SECRET (assertion minting).",
      },
      { status: 503 },
    );
  }

  let res: Response;
  try {
    res = await fetch(`${RUNTIME_URL}/v1/security/break-glass/grants`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Groundwork-API-Key": API_KEY,
        ...(idToken
          ? { Authorization: `Bearer ${idToken}` }
          : { "X-Groundwork-User-Assertion": operatorToken }),
      },
      body: JSON.stringify({ reason, duration_minutes: durationMinutes }),
      cache: "no-store",
    });
  } catch {
    return NextResponse.json(
      { error: "Query runtime unreachable — break-glass grants require a live runtime." },
      { status: 502 },
    );
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    return NextResponse.json(
      { error: data.error ?? `break_glass_open_failed (${res.status})` },
      { status: res.status },
    );
  }
  // The runtime returns { grant, key } — the minted admin key is shown
  // exactly once here; the runtime never persists it.
  return NextResponse.json({ ...data, source: "live" });
}