import { NextRequest, NextResponse } from "next/server";
import { mintConsoleAssertion } from "@/lib/jwt";

// Break-glass early revocation — POST /v1/security/break-glass/grants/{id}/revoke.
// Requires a verified operator identity (same rules as opening a grant)
// and a mandatory reason: every revocation is evidence with an accountable
// rationale. No demo fallback — emergency controls fail closed.

const RUNTIME_URL = process.env.QUERY_RUNTIME_URL ?? "http://localhost:8080";
const API_KEY = process.env.GROUNDWORK_API_KEY ?? "";

export async function POST(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!API_KEY) {
    return NextResponse.json(
      { error: "No API key configured. Set GROUNDWORK_API_KEY on the server." },
      { status: 500 },
    );
  }
  if (!id) {
    return NextResponse.json({ error: "grant id is required." }, { status: 400 });
  }
  const body = await request.json().catch(() => null);
  const reason = (body?.reason ?? "").toString().trim();
  if (reason.length < 10) {
    return NextResponse.json(
      { error: "A justification of at least 10 characters is required to revoke a break-glass grant." },
      { status: 400 },
    );
  }

  const token = await mintConsoleAssertion("console-operator");
  if (!token) {
    return NextResponse.json(
      {
        error:
          "Revoking a break-glass grant requires a signed operator identity. Set GROUNDWORK_JWT_RS_PRIVATE_KEY (production) or GROUNDWORK_JWT_HS_SECRET (local).",
      },
      { status: 503 },
    );
  }

  let res: Response;
  try {
    res = await fetch(`${RUNTIME_URL}/v1/security/break-glass/grants/${encodeURIComponent(id)}/revoke`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Groundwork-API-Key": API_KEY,
        "X-Groundwork-User-Assertion": token,
      },
      body: JSON.stringify({ reason }),
      cache: "no-store",
    });
  } catch {
    return NextResponse.json(
      { error: "Query runtime unreachable — break-glass revocation requires a live runtime." },
      { status: 502 },
    );
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    return NextResponse.json(
      { error: data.error ?? `break_glass_revoke_failed (${res.status})` },
      { status: res.status },
    );
  }
  return NextResponse.json({ ...data, source: "live" });
}