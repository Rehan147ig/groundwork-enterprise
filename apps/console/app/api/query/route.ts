import { NextRequest, NextResponse } from "next/server";
import { QueryResponse, validateConsoleQueryRequest } from "@/lib/contracts";
import { mintConsoleAssertion } from "@/lib/jwt";

// This proxy is the critical security fix for the console. The runtime's /v1/query is
// wrapped by requireVerifiedIdentity: it expects a cryptographically signed end-user
// assertion in X-Groundwork-User-Assertion. So the proxy MINTS a short-lived assertion
// whose `sub` is the selected persona, and sends it alongside the tenant API key.
//
//   - tenant/region come from the API key (X-Groundwork-API-Key) — never from the body
//   - the API key is the server-side GROUNDWORK_API_KEY — a client-supplied api_key is
//     rejected outright (clients must never be able to inject their own key)
//   - end-user identity comes from the signed JWT — never trusted from a plain header
//
// Signing: RS256 (GROUNDWORK_JWT_RS_PRIVATE_KEY[_FILE]) in production, HS256
// (GROUNDWORK_JWT_HS_SECRET) for local/dev. When neither is set the proxy fails closed —
// it only sends a plain body user_id when GROUNDWORK_DEMO_MODE=true explicitly opts in
// (which additionally requires the runtime to run with ALLOW_DEMO_IDENTITY=true). The
// response is tagged with identity_mode so the UI can warn when it's running in the
// weaker demo path.

export async function POST(request: NextRequest) {
  const payload = await request.json().catch(() => null);
  if (!validateConsoleQueryRequest(payload)) {
    return NextResponse.json({ error: "Invalid Groundwork query payload." }, { status: 400 });
  }

  const subject = (payload.persona ?? payload.user_id ?? "").trim();
  if (!subject) {
    return NextResponse.json({ error: "A persona or user_id is required." }, { status: 400 });
  }

  const runtimeUrl = process.env.QUERY_RUNTIME_URL ?? "http://localhost:8080";
  const apiKey = process.env.GROUNDWORK_API_KEY ?? "";
  if (!apiKey) {
    return NextResponse.json(
      { error: "No API key configured. Set GROUNDWORK_API_KEY on the server." },
      { status: 500 },
    );
  }

  // The body the runtime sees. Never include tenant_id/region (resolved from the key),
  // and never accept an api_key from the client payload.
  const body: Record<string, unknown> = { question: payload.question };
  if (payload.source_scopes) body.source_scopes = payload.source_scopes;
  if (payload.idk_threshold !== undefined) body.idk_threshold = payload.idk_threshold;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Groundwork-API-Key": apiKey,
  };

  const token = await mintConsoleAssertion(subject);
  let identityMode: "verified" | "demo";
  if (token) {
    headers["X-Groundwork-User-Assertion"] = token;
    identityMode = "verified";
  } else if (process.env.GROUNDWORK_DEMO_MODE === "true") {
    // Explicit demo opt-in only: runtime must run with ALLOW_DEMO_IDENTITY=true.
    body.user_id = subject;
    identityMode = "demo";
  } else {
    return NextResponse.json(
      { error: "Identity is not configured. Set GROUNDWORK_JWT_RS_PRIVATE_KEY (production) or GROUNDWORK_JWT_HS_SECRET (local), or GROUNDWORK_DEMO_MODE=true for demo only." },
      { status: 503 },
    );
  }

  let response: Response;
  try {
    response = await fetch(`${runtimeUrl}/v1/query`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      cache: "no-store",
    });
  } catch (error: unknown) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Query runtime unavailable" },
      { status: 502 },
    );
  }

  const parsed = await response.json().catch(() => ({ error: "Runtime returned invalid JSON." }));
  if (!response.ok) {
    return NextResponse.json(parsed, { status: response.status });
  }

  const result = parsed as QueryResponse;
  result.identity_mode = identityMode;
  return NextResponse.json(result);
}