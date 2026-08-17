import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/auth", () => ({
  auth: vi.fn(async () => null),
  demoMode: vi.fn(() => process.env.GROUNDWORK_DEMO_MODE === "true"),
  oidcConfigured: vi.fn(
    () => !!(process.env.OIDC_ISSUER && process.env.OIDC_CLIENT_ID && process.env.OIDC_CLIENT_SECRET),
  ),
  runtimeUserToken: vi.fn(async () => null),
}));
vi.mock("@/lib/jwt", () => ({
  mintConsoleAssertion: vi.fn(async () => "console-test-token"),
}));

import { auth } from "@/lib/auth";

const authMock = vi.mocked(auth);

type FetchCall = { url: string; init?: RequestInit };
let fetchCalls: FetchCall[] = [];

// The auth() export is typed as a Next.js middleware overload by next-auth;
// in tests we drive it as a simple session provider, so the return is
// widened to `any` here.
function sessionWith(roles: string[]): any {
  return {
    expires: new Date(Date.now() + 60_000).toISOString(),
    user: { id: "user-1", name: "Test User", email: "user@example.com", roles },
  };
}

function enterpriseEnv() {
  process.env.OIDC_ISSUER = "https://idp.example.com";
  process.env.OIDC_CLIENT_ID = "client-id";
  process.env.OIDC_CLIENT_SECRET = "client-secret";
  delete process.env.GROUNDWORK_DEMO_MODE;
  process.env.QUERY_RUNTIME_URL = "http://runtime.internal:8080";
  process.env.GROUNDWORK_API_KEY = "server-key";
}

function demoEnv() {
  delete process.env.OIDC_ISSUER;
  delete process.env.OIDC_CLIENT_ID;
  delete process.env.OIDC_CLIENT_SECRET;
  process.env.GROUNDWORK_DEMO_MODE = "true";
}

function clearEnv() {
  delete process.env.OIDC_ISSUER;
  delete process.env.OIDC_CLIENT_ID;
  delete process.env.OIDC_CLIENT_SECRET;
  delete process.env.GROUNDWORK_DEMO_MODE;
  delete process.env.QUERY_RUNTIME_URL;
  delete process.env.GROUNDWORK_API_KEY;
}

async function req(url: string, method: string, body?: unknown): Promise<NextRequest> {
  return new NextRequest(`http://console.test${url}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

type RouteCase = {
  name: string;
  url: string;
  method: string;
  body?: unknown;
  params?: Record<string, string | string[]>;
  handler: (request: NextRequest, params: { params: Promise<Record<string, string | string[]>> }) => Promise<Response>;
};

async function load(method: string, path: string) {
  if (path === "/api/agents") return import("@/app/api/agents/route");
  if (path === "/api/agents/ag_1/activate") return import("@/app/api/agents/[agentId]/[action]/route");
  if (path === "/api/agents/ag_1") return import("@/app/api/agents/[agentId]/route");
  if (path.startsWith("/api/governance")) return import("@/app/api/governance/[...path]/route");
  if (path === "/api/audit") return import("@/app/api/audit/route");
  if (path === "/api/leak-report") return import("@/app/api/leak-report/route");
  if (path === "/api/break-glass") return import("@/app/api/break-glass/route");
  if (path === "/api/break-glass/gr_1/revoke") return import("@/app/api/break-glass/[id]/revoke/route");
  if (path === "/api/connect") return import("@/app/api/connect/route");
  if (path === "/api/query") return import("@/app/api/query/route");
  throw new Error(`no loader for ${path}`);
}

async function invoke(c: RouteCase): Promise<Response> {
  const mod = (await load(c.method, c.url)) as unknown as Record<string, unknown>;
  const handler = mod[c.method] as (
    request: NextRequest,
    params: { params: Promise<Record<string, string | string[]>> },
  ) => Promise<Response>;
  const request = await req(c.url, c.method, c.body);
  const params = { params: Promise.resolve(c.params ?? {}) };
  return handler(request, params);
}

const VALID_REASON = "A genuinely long justification for an emergency action.";

const SENSITIVE_ROUTES: RouteCase[] = [
  { name: "agents list", url: "/api/agents", method: "GET", handler: () => Promise.resolve(new Response()) },
  { name: "agent create", url: "/api/agents", method: "POST", body: { name: "new-agent" }, handler: () => Promise.resolve(new Response()) },
  { name: "agent detail", url: "/api/agents/ag_1", method: "GET", params: { agentId: "ag_1" }, handler: () => Promise.resolve(new Response()) },
  { name: "agent action", url: "/api/agents/ag_1/activate", method: "POST", params: { agentId: "ag_1", action: "activate" }, body: { reason: VALID_REASON }, handler: () => Promise.resolve(new Response()) },
  { name: "governance list", url: "/api/governance/tools", method: "GET", params: { path: ["tools"] }, handler: () => Promise.resolve(new Response()) },
  { name: "governance mutation", url: "/api/governance/tools", method: "POST", params: { path: ["tools"] }, body: { name: "t" }, handler: () => Promise.resolve(new Response()) },
  { name: "governance exports", url: "/api/governance/exports/eu_ai_act", method: "GET", params: { path: ["exports", "eu_ai_act"] }, handler: () => Promise.resolve(new Response()) },
  { name: "audit", url: "/api/audit", method: "GET", handler: () => Promise.resolve(new Response()) },
  { name: "leak report", url: "/api/leak-report", method: "GET", handler: () => Promise.resolve(new Response()) },
  { name: "break-glass list", url: "/api/break-glass", method: "GET", handler: () => Promise.resolve(new Response()) },
  { name: "break-glass open", url: "/api/break-glass", method: "POST", body: { reason: VALID_REASON, duration_minutes: 30 }, handler: () => Promise.resolve(new Response()) },
  { name: "break-glass revoke", url: "/api/break-glass/gr_1/revoke", method: "POST", params: { id: "gr_1" }, body: { reason: VALID_REASON }, handler: () => Promise.resolve(new Response()) },
  { name: "connect", url: "/api/connect", method: "POST", body: { pat: "github_pat_11_test", org: "acme" }, handler: () => Promise.resolve(new Response()) },
  { name: "query", url: "/api/query", method: "POST", body: { persona: "alice", question: "what is the balance" }, handler: () => Promise.resolve(new Response()) },
];

describe("console API authorization (enterprise: OIDC configured, demo disabled)", () => {
  beforeEach(() => {
    fetchCalls = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: unknown, init?: RequestInit) => {
        fetchCalls.push({ url: String(input), init });
        return new Response(JSON.stringify({}), { status: 503 });
      }),
    );
    enterpriseEnv();
    authMock.mockResolvedValue(null as never);
  });

  afterEach(() => {
    clearEnv();
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("unauthenticated requests get 401 on every sensitive route and never reach the runtime", async () => {
    for (const c of SENSITIVE_ROUTES) {
      const res = await invoke(c);
      expect(res.status, `${c.method} ${c.url} should be 401`).toBe(401);
      const body = await res.json().catch(() => ({}));
      expect(body.error, `${c.method} ${c.url} error body`).toBe("authentication_required");
    }
    expect(fetchCalls.length).toBe(0);
  });

  it("viewer can read agents but cannot mutate anything", async () => {
    authMock.mockResolvedValue(sessionWith(["viewer"]));

    // Read-only agent surface is allowed for viewer (proceeds to runtime).
    const read = await invoke(SENSITIVE_ROUTES[0]);
    expect(read.status).not.toBe(401);
    expect(read.status).not.toBe(403);
    expect(fetchCalls.length).toBe(1);

    // Every mutation is denied with 403.
    const mutations: RouteCase[] = [
      SENSITIVE_ROUTES[1], // agent create
      SENSITIVE_ROUTES[3], // agent action
      SENSITIVE_ROUTES[5], // governance mutation
      SENSITIVE_ROUTES[9], // break-glass list
      SENSITIVE_ROUTES[10], // break-glass open
      SENSITIVE_ROUTES[11], // break-glass revoke
      SENSITIVE_ROUTES[12], // connect
      SENSITIVE_ROUTES[13], // query (real, not simulation)
    ];
    for (const c of mutations) {
      const res = await invoke(c);
      expect(res.status, `${c.method} ${c.url} viewer should be 403`).toBe(403);
    }
    // Viewer also cannot read governance evidence or audit surfaces.
    const gov = await invoke(SENSITIVE_ROUTES[4]);
    expect(gov.status).toBe(403);
    const audit = await invoke(SENSITIVE_ROUTES[7]);
    expect(audit.status).toBe(403);
    // No additional runtime calls for any denied request.
    expect(fetchCalls.length).toBe(1);
  });

  it("viewer can run query simulation", async () => {
    authMock.mockResolvedValue(sessionWith(["viewer"]));
    const res = await invoke({
      ...SENSITIVE_ROUTES[13],
      body: { persona: "alice", question: "what is the balance", simulate: true },
    });
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
  });

  it("auditor can read audit/governance evidence but cannot mutate", async () => {
    authMock.mockResolvedValue(sessionWith(["auditor"]));

    const audit = await invoke(SENSITIVE_ROUTES[7]);
    expect(audit.status).not.toBe(401);
    expect(audit.status).not.toBe(403);

    const exports = await invoke(SENSITIVE_ROUTES[6]);
    expect(exports.status).not.toBe(401);
    expect(exports.status).not.toBe(403);

    const gov = await invoke(SENSITIVE_ROUTES[4]);
    expect(gov.status).not.toBe(401);
    expect(gov.status).not.toBe(403);

    // Auditor cannot mutate agents or governance, and cannot run real queries.
    const before = fetchCalls.length;
    const agentCreate = await invoke(SENSITIVE_ROUTES[1]);
    expect(agentCreate.status).toBe(403);
    const govMutation = await invoke(SENSITIVE_ROUTES[5]);
    expect(govMutation.status).toBe(403);
    const query = await invoke(SENSITIVE_ROUTES[13]);
    expect(query.status).toBe(403);
    const leakReport = await invoke(SENSITIVE_ROUTES[8]);
    expect(leakReport.status).not.toBe(401); // auditor-allowed read (leak-report)
    expect(leakReport.status).not.toBe(403);
    expect(fetchCalls.length).toBe(before + 1);
  });

  it("admin can mutate and is never blocked by the console gate", async () => {
    authMock.mockResolvedValue(sessionWith(["admin"]));
    const okFetch = vi.fn(async () => new Response(JSON.stringify({ agent: { id: "a1" } }), { status: 200 }));
    vi.stubGlobal("fetch", okFetch);

    for (const c of SENSITIVE_ROUTES) {
      const res = await invoke(c);
      expect(res.status, `${c.method} ${c.url} admin should not be 401/403`).not.toBe(401);
      expect(res.status, `${c.method} ${c.url} admin should not be 403`).not.toBe(403);
    }
    expect(okFetch.mock.calls.length).toBeGreaterThan(0);
  });

  it("unknown roles fall back to viewer (least privilege)", async () => {
    authMock.mockResolvedValue(sessionWith(["analyst"]));
    const res = await invoke(SENSITIVE_ROUTES[1]); // agent create
    expect(res.status).toBe(403);
  });
});

describe("demo mode gating", () => {
  beforeEach(() => {
    fetchCalls = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: unknown, init?: RequestInit) => {
        fetchCalls.push({ url: String(input), init });
        return new Response(JSON.stringify({}), { status: 503 });
      }),
    );
    authMock.mockResolvedValue(null as never);
  });

  afterEach(() => {
    clearEnv();
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("GROUNDWORK_DEMO_MODE=true keeps demo fallbacks available without a session", async () => {
    demoEnv();
    const res = await invoke(SENSITIVE_ROUTES[0]); // agents list
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.source).toBe("demo");
  });

  it("demo data cannot be fabricated in production (flag unset)", async () => {
    clearEnv();
    process.env.QUERY_RUNTIME_URL = "http://runtime.internal:8080";
    process.env.GROUNDWORK_API_KEY = "server-key";
    const res = await invoke(SENSITIVE_ROUTES[0]); // agents list
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error).toBe("configuration_required");
    expect(body.message).toContain("OIDC authentication must be configured");
  });

  it("enterprise + demo mode still serves no session-less mutations", async () => {
    enterpriseEnv();
    process.env.GROUNDWORK_DEMO_MODE = "true";
    const res = await invoke(SENSITIVE_ROUTES[10]); // break-glass open
    // Break-glass has no demo fallback and no session: hard failure, never
    // a fabricated grant.
    expect(res.status).not.toBe(200);
  });
});

describe("fail-closed configuration gate (no OIDC, no demo)", () => {
  beforeEach(() => {
    fetchCalls = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: unknown, init?: RequestInit) => {
        fetchCalls.push({ url: String(input), init });
        return new Response(JSON.stringify({}), { status: 503 });
      }),
    );
    clearEnv(); // no OIDC, no demo
    process.env.QUERY_RUNTIME_URL = "http://runtime.internal:8080";
    process.env.GROUNDWORK_API_KEY = "server-key";
    authMock.mockResolvedValue(null as never);
  });

  afterEach(() => {
    clearEnv();
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("returns 503 configuration_required on every sensitive route", async () => {
    for (const c of SENSITIVE_ROUTES) {
      const res = await invoke(c);
      expect(res.status, `${c.method} ${c.url} should be 503`).toBe(503);
      const body = await res.json().catch(() => ({}));
      expect(body.error, `${c.method} ${c.url} error body`).toBe("configuration_required");
      expect(body.message).toContain("OIDC authentication must be configured");
    }
    expect(fetchCalls.length).toBe(0);
  });
});
