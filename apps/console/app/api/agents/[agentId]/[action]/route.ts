import { NextRequest, NextResponse } from "next/server";
import { agentError, agentHeaders, agentRuntimeEnv } from "@/lib/agentProxy";

// POST /api/agents/[agentId]/[action] — proxies the registry mutation
// endpoints (versions | activate | suspend | revoke | retire). Only the
// console-admin actor can act, enforced by the runtime via the minted
// assertion + tenant API key. Never demo-fakes a mutation: if the
// runtime is not reachable the caller gets an explicit 502.

const ACTIONS = ["versions", "activate", "suspend", "revoke", "retire"] as const;

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ agentId: string; action: string }> },
) {
  const { agentId, action } = await params;
  if (!ACTIONS.includes(action as (typeof ACTIONS)[number])) {
    return agentError(400, `Unknown action "${action}".`);
  }

  const { runtimeUrl, apiKey, secret } = agentRuntimeEnv();
  if (!runtimeUrl || !apiKey) {
    return agentError(400, "No API key. Set GROUNDWORK_API_KEY or pass api_key.");
  }

  const payload = (await request.json().catch(() => ({}))) as Record<string, unknown>;
  const body: Record<string, unknown> = {};
  if (action === "versions") {
    for (const k of ["version", "model_provider", "model_name", "prompt_digest", "tool_manifest_digest", "policy_bundle_version", "artifact_digest"] as const) {
      if (payload[k] !== undefined) body[k] = payload[k];
    }
  } else if (typeof payload.reason === "string") {
    body.reason = payload.reason;
  }

  try {
    const res = await fetch(`${runtimeUrl}/v1/agents/${encodeURIComponent(agentId)}/${action}`, {
      method: "POST",
      headers: await agentHeaders(secret, apiKey),
      body: JSON.stringify(body),
      cache: "no-store",
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      const isVersion = action === "versions";
      return NextResponse.json({
        source: "live",
        ...(isVersion ? { version: data.version } : { agent: data.agent }),
      });
    }
    return NextResponse.json(data, { status: res.status });
  } catch (error: unknown) {
    return agentError(502, error instanceof Error ? error.message : "Query runtime unavailable");
  }
}
