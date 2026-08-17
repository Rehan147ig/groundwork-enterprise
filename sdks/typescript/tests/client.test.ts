import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  GroundworkClient,
  PermissionDeniedError,
  FailClosedError,
} from "../src";

interface RecordedRequest {
  method: string;
  url: string | undefined;
  headers: Record<string, string | string[] | undefined>;
  body: unknown;
}

const requests: RecordedRequest[] = [];
const flakyAttempts = new Map<string, number>();
let server: ReturnType<typeof createServer>;
let baseUrl = "";

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

beforeAll(async () => {
  server = createServer(async (req, res) => {
    body: {
      const body = (await readBody(req)) as Record<string, unknown>;
      requests.push({ method: req.method ?? "", url: req.url, headers: req.headers, body });
if (req.method === "POST" && req.url === "/v1/query") {
        if (body.question === "flaky") {
          const attempts = (flakyAttempts.get("flaky") ?? 0) + 1;
          flakyAttempts.set("flaky", attempts);
          if (attempts === 1) {
            sendJson(res, 503, { error: { code: "overloaded", message: "try again" } });
            return;
          }
          // subsequent attempts succeed
        }
        if (body.question === "denied") {
          sendJson(res, 403, {
            error: { code: "permission_denied", message: "identity scope missing" },
          });
          return;
        }
        if (body.question === "broken") {
          sendJson(res, 500, { error: { code: "internal", message: "boom" } });
          return;
        }
        if (body.question === "batch") {
          sendJson(res, 200, {
            answer: "full answer",
            confidence: 0.9,
            citations: [
              {
                document_id: "doc-1",
                chunk_hash: "abc123",
                score: 0.95,
                text: "first chunk",
              },
              {
                document_id: "doc-2",
                chunk_hash: "def456",
                score: 0.8,
                text: "second chunk",
              },
              {
                document_id: "doc-3",
                chunk_hash: "ghi789",
                score: 0.7,
                text: "third chunk",
              },
            ],
            trace: {
              trace_id: "trace-1",
              immutable_digest: "digest-1",
              groundedness_check: { passed: true, score: 0.99 },
            },
          });
          return;
        }
        sendJson(res, 200, {
          answer: "hello",
          confidence: 0.9,
          citations: [],
          trace: {
            trace_id: "trace-1",
            immutable_digest: "digest-1",
            groundedness_check: { passed: true, score: 0.99 },
          },
        });
        return;
      }
      if (req.method === "GET" && req.url === "/v1/leak-report") {
        sendJson(res, 200, {
          findings: [
            {
              kind: "in_prompt_history",
              severity: "high",
              title: "Prompt history contains PII",
              detail: "bob@example.com leaked into history payload",
            },
          ],
        });
        return;
      }
      if (req.method === "GET" && req.url === "/v1/audit/verify") {
        sendJson(res, 200, {
          verified: true,
          entries_checked: 42,
          problems: [],
        });
        return;
      }
      sendJson(res, 404, { error: { code: "not_found", message: "no route" } });
    }
  });
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("GroundworkClient", () => {
  it("queries the runtime with api key header and correct body", async () => {
    const client = new GroundworkClient({ endpoint: baseUrl, apiKey: "test-api-key" });
    const result = await client.query("alice", "what's the policy?");
    expect(result).toEqual({
      answer: "hello",
      confidence: 0.9,
      citations: [],
      trace: { trace_id: "trace-1", immutable_digest: "digest-1", groundedness_check: { passed: true, score: 0.99 } },
    });
    const req = requests.findLast((r) => r.url === "/v1/query" && (r.body as any).question === "what's the policy?")!;
    expect(req.method).toBe("POST");
    expect(req.headers["x-groundwork-api-key"]).toBe("test-api-key");
    expect(req.body).toEqual({
      user_id: "alice",
      question: "what's the policy?",
    });
  });

  it("propagates the user assertion and delegation token headers", async () => {
    const client = new GroundworkClient({ endpoint: baseUrl, apiKey: "k" });
    await client.query("alice", "policy?", {
      userAssertion: "jwt-assertion",
      delegationToken: "deleg-1",
      correlationId: "corr-1",
    });
    const req = requests.findLast((r) => r.url === "/v1/query" && (r.body as any).question === "policy?")!;
    expect(req.headers["x-groundwork-user-assertion"]).toBe("jwt-assertion");
    expect(req.headers["x-groundwork-delegation-token"]).toBe("deleg-1");
    expect(req.headers["x-groundwork-correlation-id"]).toBe("corr-1");
  });

  it("retries retryable 503 and succeeds on second attempt", async () => {
    const before = requests.filter((r) => r.url === "/v1/query" && (r.body as any).question === "flaky").length;
    const client = new GroundworkClient({ endpoint: baseUrl, apiKey: "k", maxRetries: 2, backoffFactor: 0.005 });
    const result = await client.query("alice", "flaky");
    const attempts = requests.slice(before).filter((r) => r.url === "/v1/query" && (r.body as any).question === "flaky");
    expect(attempts.length).toBe(2);
    expect(result.answer).toBe("hello");
  });

  it("maps 403 to PermissionDeniedError without retrying", async () => {
    const before = requests.length;
    const client = new GroundworkClient({ endpoint: baseUrl, apiKey: "k", maxRetries: 2, backoffFactor: 0.005 });
    await expect(client.query("alice", "denied")).rejects.toBeInstanceOf(PermissionDeniedError);
    const attempts = requests.slice(before).filter((r) => r.url === "/v1/query" && (r.body as any).question === "denied");
    expect(attempts.length).toBe(1);
  });

  it("maps 5xx to FailClosedError", async () => {
    const client = new GroundworkClient({ endpoint: baseUrl, apiKey: "k", maxRetries: 1, backoffFactor: 0.005 });
    await expect(client.query("alice", "broken")).rejects.toBeInstanceOf(FailClosedError);
  });

  it("slices citations with topK", async () => {
    const client = new GroundworkClient({ endpoint: baseUrl, apiKey: "k" });
    const result = await client.query("alice", "batch", { topK: 2 });
    expect(result.citations.map((c) => c.document_id)).toEqual(["doc-1", "doc-2"]);
    const full = await client.query("alice", "batch");
    expect(full.citations.length).toBe(3);
  });

  it("reports permission leaks from the resource probe", async () => {
    const client = new GroundworkClient({ endpoint: baseUrl, apiKey: "k" });
    const report = await client.leakReport();
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]!.kind).toBe("in_prompt_history");
    const req = requests.findLast((r) => r.url === "/v1/leak-report")!;
    expect(req.method).toBe("GET");
    expect(req.headers["x-groundwork-api-key"]).toBe("k");
  });

  it("verifies the immutable audit chain", async () => {
    const client = new GroundworkClient({ endpoint: baseUrl, apiKey: "k" });
    const result = await client.verifyAudit();
    expect(result.verified).toBe(true);
    expect(result.entries_checked).toBe(42);
    expect(result.problems).toEqual([]);
    const req = requests.findLast((r) => r.url === "/v1/audit/verify")!;
    expect(req.method).toBe("GET");
  });
});
