import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MockLLM } from "@llamaindex/core/llms/mock";
import { RetrieverQueryEngine } from "@llamaindex/core/query-engine";
import { getResponseSynthesizer } from "@llamaindex/core/response-synthesizers";
import { TextNode } from "@llamaindex/core/schema";
import {
  GroundworkClient,
  USER_ASSERTION_HEADER,
  type QueryResponse,
} from "../src";
import { GroundworkLlamaIndexRetriever } from "../src/integrations/llamaindex";

interface RecordedRequest {
  userId: string | undefined;
  question: string | undefined;
  userAssertion: string | undefined;
}

const requests: RecordedRequest[] = [];
let server: ReturnType<typeof createServer>;
let baseUrl = "";

const ALLOWED_CITATIONS = [
  {
    document_id: "doc-0",
    chunk_id: "chunk-0",
    chunk_hash: "hash-0",
    page: 1,
    offset: 0,
    text: "chunk text 0",
    score: 0.8,
    freshness_score: 1.0,
    watermark: "wm-0",
  },
  {
    document_id: "doc-1",
    chunk_id: "chunk-1",
    chunk_hash: "hash-1",
    page: 2,
    offset: 10,
    text: "chunk text 1",
    score: 0.6,
    freshness_score: 0.9,
  },
];

function queryPayload(userId: string, nCitations = 2): QueryResponse {
  const citations =
    userId === "alice" ? ALLOWED_CITATIONS.slice(0, nCitations) : [];
  return {
    answer: "found it",
    confidence: 0.85,
    citations,
    trace: {
      trace_id: "trace-1",
      tenant_id: "tenant-1",
      user_id: userId,
      region: "us-east-1",
      started_at: "2026-01-01T00:00:00Z",
      latency_ms: 5,
      vector_candidates: 10,
      keyword_candidates: 4,
      blocked_by_acl: 0,
      blocked_by_residency: 0,
      reranked_candidates: 8,
      decision_mode: "strict",
      immutable_digest: "chain-digest-1",
      access_decisions: [],
    },
  };
}

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      try {
        resolve(raw ? (JSON.parse(raw) as Record<string, unknown>) : {});
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

beforeAll(async () => {
  server = createServer(async (req, res) => {
    if (req.method === "POST" && req.url === "/v1/query") {
      const body = await readBody(req);
      const userId = typeof body.user_id === "string" ? body.user_id : "";
      const question = typeof body.question === "string" ? body.question : "";
      const header = req.headers[USER_ASSERTION_HEADER.toLowerCase()];
      let userAssertion: string | undefined;
      if (typeof header === "string") {
        userAssertion = header;
      } else if (Array.isArray(header)) {
        userAssertion = header[0];
      } else {
        userAssertion = undefined;
      }
      requests.push({ userId, question, userAssertion });
      const topK = typeof body.top_k === "number" ? body.top_k : 2;
      sendJson(res, 200, queryPayload(userId, topK));
      return;
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterAll(() => {
  server.close();
});

function makeClient() {
  return new GroundworkClient({
    endpoint: baseUrl,
    apiKey: "gw_test_key",
    backoffFactor: 0.0,
  });
}

describe("GroundworkLlamaIndexRetriever", () => {
  it("routes retrieve({ query }) to the runtime and maps citations to nodes", async () => {
    const retriever = new GroundworkLlamaIndexRetriever({
      client: makeClient(),
      userId: "alice",
    });
    const nodes = await retriever.retrieve({ query: "budget question" });

    expect(nodes).toHaveLength(2);
    for (let i = 0; i < nodes.length; i++) {
      const entry = nodes[i];
      expect(entry).toBeDefined();
      expect(entry!.score).toBe(ALLOWED_CITATIONS[i]!.score);
      expect(entry!.node).toBeInstanceOf(TextNode);
      const node = entry!.node as TextNode;
      expect(node.id_).toBe(`chunk-${i}`);
      expect(node.text).toBe(`chunk text ${i}`);
      expect(node.metadata).toMatchObject({
        doc_id: `chunk-${i}`,
        digest: `hash-${i}`,
        document_id: `doc-${i}`,
        page: i + 1,
        offset: i * 10,
        score: ALLOWED_CITATIONS[i]!.score,
        freshness_score: i === 0 ? 1.0 : 0.9,
      });
    }
    expect((nodes[0]!.node as TextNode).metadata.watermark).toBe("wm-0");
    expect(requests.at(-1)).toMatchObject({
      userId: "alice",
      question: "budget question",
    });
  });

  it("accepts a plain string query", async () => {
    const retriever = new GroundworkLlamaIndexRetriever({
      client: makeClient(),
      userId: "alice",
    });
    const nodes = await retriever.retrieve("policy question");
    expect(nodes).toHaveLength(2);
    expect(requests.at(-1)!.question).toBe("policy question");
  });

  it("filters denied citations by user (permission filtering)", async () => {
    const alice = new GroundworkLlamaIndexRetriever({
      client: makeClient(),
      userId: "alice",
    });
    const bob = new GroundworkLlamaIndexRetriever({
      client: makeClient(),
      userId: "bob",
    });

    const aliceNodes = await alice.retrieve({ query: "q" });
    const bobNodes = await bob.retrieve({ query: "q" });

    expect(aliceNodes.map((n) => n.node.id_)).toEqual(["chunk-0", "chunk-1"]);
    expect(bobNodes).toEqual([]);
    expect(requests.at(-1)!.userId).toBe("bob");
  });

  it("forwards topK and the user assertion header", async () => {
    const retriever = new GroundworkLlamaIndexRetriever({
      client: makeClient(),
      userId: "alice",
      topK: 1,
      userAssertion: "jwt-1",
    });
    const nodes = await retriever.retrieve({ query: "q" });

    expect(nodes).toHaveLength(1);
    expect(requests.at(-1)).toMatchObject({
      userId: "alice",
      userAssertion: "jwt-1",
    });
  });

  it("resolves a callable user id per invocation", async () => {
    const current: { id: string } = { id: "alice" };
    const retriever = new GroundworkLlamaIndexRetriever({
      client: makeClient(),
      userId: () => current.id,
    });

    await retriever.retrieve({ query: "first" });
    current.id = "bob";
    await retriever.retrieve({ query: "second" });

    expect(requests.at(-2)!.userId).toBe("alice");
    expect(requests.at(-1)!.userId).toBe("bob");
  });

  it("drives a RetrieverQueryEngine with permission-filtered source nodes", async () => {
    const aliceRetriever = new GroundworkLlamaIndexRetriever({
      client: makeClient(),
      userId: "alice",
    });
    const bobRetriever = new GroundworkLlamaIndexRetriever({
      client: makeClient(),
      userId: "bob",
    });
    const synthesizer = getResponseSynthesizer("refine", {
      llm: new MockLLM(),
    });

    const aliceEngine = new RetrieverQueryEngine(aliceRetriever, synthesizer);
    const bobEngine = new RetrieverQueryEngine(bobRetriever, synthesizer);

    const aliceResponse = await aliceEngine.query({ query: "budget question" });
    const bobResponse = await bobEngine.query({ query: "budget question" });

    expect(aliceResponse.sourceNodes).toHaveLength(2);
    expect(aliceResponse.sourceNodes!.map((n) => n.node.id_)).toEqual([
      "chunk-0",
      "chunk-1",
    ]);

    expect(bobResponse.sourceNodes ?? []).toEqual([]);
    // MockLLM returns a static response; verify bob also gets a response object.
    expect(bobResponse.toString()).toBeTruthy();
  });
});