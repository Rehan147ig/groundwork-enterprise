import { NextResponse } from "next/server";
import { mintConsoleAssertion } from "@/lib/jwt";
import { runtimeUserToken } from "@/lib/auth";

// Shared plumbing for the console's Agent Registry surface. Mirrors the
// /api/query proxy: the tenant API key and (for mutations) a short-lived
// console-admin assertion are minted server-side so neither the key nor
// the minting secret ever reaches the browser.
//
// Enterprise auth: when the caller holds a verified OIDC session, the
// IdP id_token is forwarded as `Authorization: Bearer <id_token>` — the
// runtime verifies it against the IdP's JWKS and that identity binds the
// mutation to the real user (console-admin minting is skipped).

export type Agent = {
  id: string;
  tenant_id: string;
  name: string;
  description?: string;
  owner_principal_id: string;
  business_purpose?: string;
  risk_tier: string;
  lifecycle_state: string;
  environment: string;
  created_at: string;
  updated_at: string;
  activated_at?: string;
  revoked_at?: string;
  active_version_id?: string;
  active_version?: string;
  version_count: number;
};

export type AgentVersion = {
  id: string;
  agent_id: string;
  version: string;
  model_provider?: string;
  model_name?: string;
  prompt_digest?: string;
  tool_manifest_digest?: string;
  policy_bundle_version?: string;
  artifact_digest?: string;
  status: string;
  created_at: string;
  approved_at?: string;
};

export type LifecycleEvent = {
  id: string;
  tenant_id: string;
  agent_id: string;
  agent_version_id?: string;
  actor_principal_id: string;
  event_type: string;
  previous_state: string;
  new_state: string;
  reason: string;
  immutable_digest: string;
  created_at: string;
};

export function agentRuntimeEnv() {
  return {
    runtimeUrl: process.env.QUERY_RUNTIME_URL ?? "",
    apiKey: process.env.GROUNDWORK_API_KEY ?? "",
    secret: process.env.GROUNDWORK_JWT_HS_SECRET ?? "",
  };
}

// agentHeaders returns the headers a /v1/agents call needs. A verified
// OIDC session forwards the user's id_token as Authorization: Bearer
// (the runtime verifies it against the IdP JWKS). Without a session, a
// console-admin assertion is minted (RS256 when configured, else HS256
// for local/dev). With neither, the header is omitted and the runtime
// must run with ALLOW_DEMO_IDENTITY=true — the same fail-closed contract
// as /api/query.
export async function agentHeaders(_secret: string, apiKey: string): Promise<Record<string, string>> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Groundwork-API-Key": apiKey,
  };
  const idToken = await runtimeUserToken();
  if (idToken) {
    headers["Authorization"] = `Bearer ${idToken}`;
    return headers;
  }
  const token = await mintConsoleAssertion("console-admin");
  if (token) {
    headers["X-Groundwork-User-Assertion"] = token;
  }
  return headers;
}

export function agentError(status: number, message: string) {
  return NextResponse.json({ error: message }, { status });
}