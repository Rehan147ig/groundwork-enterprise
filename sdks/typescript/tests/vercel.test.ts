import { describe, expect, it, vi } from "vitest";
import { generateText, streamText, simulateReadableStream, stepCountIs } from "ai";
import { MockLanguageModelV2 } from "ai/test";
import type { LanguageModelV2 } from "@ai-sdk/provider";
import {
  GroundworkIdentityError,
  GroundworkClient,
  createGroundworkRetrievalTool,
  redactPII,
  withGroundwork,
} from "../src";
import type { QueryResponse } from "../src";
import { USER_ASSERTION_HEADER } from "../src";

const FAKE_TRACE: QueryResponse["trace"] = {
  trace_id: "trace-1",
  tenant_id: "tenant-1",
  user_id: "alice",
  region: "us-east-1",
  started_at: "2026-01-01T00:00:00Z",
  latency_ms: 42,
  vector_candidates: 10,
  keyword_candidates: 5,
  blocked_by_acl: 0,
  blocked_by_residency: 0,
  reranked_candidates: 15,
  decision_mode: "auto",
  access_decisions: [],
  immutable_digest: "digest-1",
};

const FAKE_CITATION: QueryResponse["citations"][number] = {
  document_id: "doc-1",
  chunk_id: "chunk-1",
  chunk_hash: "abc123",
  page: 3,
  offset: 12,
  text: "The approved expense cap is $500 per month.",
  score: 0.95,
  freshness_score: 0.9,
};

function fakeClient() {
  const query = vi.fn(async (): Promise<QueryResponse> => ({
    answer: "The expense cap is $500 per month.",
    confidence: 0.95,
    citations: [FAKE_CITATION],
    trace: FAKE_TRACE,
  }));
  return query as unknown as GroundworkClient["query"] & { calls: () => typeof query };
}

function groundedRetrievalClient(client: GroundworkClient["query"]): Pick<GroundworkClient, "query"> {
  return { query: client };
}

function textResult(text: string): Awaited<ReturnType<LanguageModelV2["doGenerate"]>> {
  return {
    content: [{ type: "text", text }],
    finishReason: "stop",
    usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
    warnings: [],
    response: { id: "call-2", timestamp: new Date("2026-01-01T00:00:00Z"), modelId: "mock-model" },
  };
}

function toolCallResult(queryArg: string): Awaited<ReturnType<LanguageModelV2["doGenerate"]>> {
  return {
    content: [
      {
        type: "tool-call",
        toolCallId: "tool-1",
        toolName: "retrieve",
        input: JSON.stringify({ query: queryArg }),
        providerExecuted: false,
      },
    ],
    finishReason: "tool-calls",
    usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
    warnings: [],
    response: { id: "call-1", timestamp: new Date("2026-01-01T00:00:00Z"), modelId: "mock-model" },
  };
}

describe("withGroundwork", () => {
  it("intercepts retrieval tool specs, enforces the assertion header, and executes grounded retrieval", async () => {
    const client = fakeClient();
    let modelCalls = 0;
    const model = new MockLanguageModelV2({
      doGenerate: async () => {
        modelCalls += 1;
        return modelCalls === 1
          ? toolCallResult("What is the expense policy?")
          : textResult("The approved expense cap is $500 per month.");
      },
    });

    const wrapped = withGroundwork(model, {
      client: groundedRetrievalClient(client),
      userAssertion: "static-assertion",
      getIdentity: () => ({ userId: "alice", userAssertion: "per-request-assertion" }),
    });

    const result = await generateText({
      model: wrapped,
      prompt: "What is the expense policy?",
      stopWhen: stepCountIs(5),
      tools: {
        retrieve: createGroundworkRetrievalTool({
          client: groundedRetrievalClient(client),
          getIdentity: () => ({ userId: "alice", userAssertion: "per-request-assertion" }),
          topK: 5,
        }),
      },
    });

    expect(result.text).toContain("$500 per month");
    expect(modelCalls).toBe(2);

    // 1. The model-facing spec of the app's `retrieve` tool was grounded.
    const spec = model.doGenerateCalls[0]!.tools!.find(
      (t) => t.type === "function" && t.name === "retrieve",
    ) as any;
    expect(spec.description).toContain("Zero-trust retrieval");
    expect(spec.inputSchema.properties.query.type).toBe("string");
    expect(spec.inputSchema.required).toEqual(["query"]);

    // 2. The assertion header was enforced on every model call.
    expect(model.doGenerateCalls[0]!.headers![USER_ASSERTION_HEADER]).toBe("static-assertion");
    expect(model.doGenerateCalls[1]!.headers![USER_ASSERTION_HEADER]).toBe("static-assertion");

    // 3. The tool execution ran zero-trust retrieval as the asserted user.
    expect(client).toHaveBeenCalledTimes(1);
    expect(client).toHaveBeenCalledWith(
      "alice",
      "What is the expense policy?",
      { userAssertion: "per-request-assertion", topK: 5 },
    );
    const output = (
      result.steps[0]!.toolResults[0] as unknown as {
        output: { documents: Array<{ document_id: string }> };
      }
    ).output;
    expect(output.documents[0]!.document_id).toBe("doc-1");
  });

  it("fails closed before any model call when no assertion source exists", async () => {
    const model = new MockLanguageModelV2({ doGenerate: async () => textResult("nope") });
    const wrapped = withGroundwork(model, {
      client: groundedRetrievalClient(fakeClient()),
    });
    await expect(generateText({ model: wrapped, prompt: "hello" })).rejects.toThrow(
      GroundworkIdentityError,
    );
    expect(model.doGenerateCalls.length).toBe(0);
  });

  it("fails closed during retrieval when the resolved identity has no assertion", async () => {
    const model = new MockLanguageModelV2({
      doGenerate: async () => toolCallResult("any question"),
    });
    const client = fakeClient();
    const wrapped = withGroundwork(model, {
      client: groundedRetrievalClient(client),
      getIdentity: () => ({ userId: "alice" }), // no userAssertion
    });
    const result = await generateText({
      model: wrapped,
      prompt: "hello",
      tools: {
        retrieve: createGroundworkRetrievalTool({
          client: groundedRetrievalClient(client),
          getIdentity: () => ({ userId: "alice" }),
        }),
      },
    });
    // Fail-closed: the unverified retrieval never reached the runtime, and the
    // GroundworkIdentityError surfaced as a tool error in the model output.
    const toolError = (result.steps[0]!.content as Array<Record<string, unknown>>).find(
      (part) => part.type === "tool-error",
    );
    expect(String(toolError?.error)).toContain("no user assertion");
    expect(client).not.toHaveBeenCalled();
  });

  it("redacts PII from generation results", async () => {
    const model = new MockLanguageModelV2({
      doGenerate: async () =>
        textResult("Contact alice@example.com or 555-123-4567 for the SSN 123-45-6789."),
    });
    const wrapped = withGroundwork(model, {
      client: groundedRetrievalClient(fakeClient()),
      userAssertion: "assert",
    });
    const result = await generateText({ model: wrapped, prompt: "who to contact" });
    expect(result.text).toBe("Contact [REDACTED] or [REDACTED] for the SSN [REDACTED].");
  });

  it("redacts PII from streamed deltas", async () => {
    const model = new MockLanguageModelV2({
      doStream: async () => ({
        stream: simulateReadableStream({
          chunks: [
            { type: "stream-start", warnings: [] },
            { type: "text-delta", id: "d1", delta: "Email alice@example.com or call 555-123-4567." },
            {
              type: "finish",
              finishReason: "stop",
              usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
            },
          ],
          chunkDelayInMs: null,
        }),
        warnings: [],
      }),
    });
    const wrapped = withGroundwork(model, {
      client: groundedRetrievalClient(fakeClient()),
      userAssertion: "assert",
    });
    const result = await streamText({ model: wrapped, prompt: "ping" });
    let text = "";
    for await (const chunk of result.textStream) {
      text += chunk;
    }
    expect(text).toBe("Email [REDACTED] or call [REDACTED].");
  });

  it("disables redaction when configured with false", async () => {
    const model = new MockLanguageModelV2({
      doGenerate: async () => textResult("ping alice@example.com"),
    });
    const wrapped = withGroundwork(model, {
      client: groundedRetrievalClient(fakeClient()),
      userAssertion: "assert",
      redaction: false,
    });
    const result = await generateText({ model: wrapped, prompt: "ping" });
    expect(result.text).toBe("ping alice@example.com");
  });

  it("redactPII scrubs known patterns standalone", () => {
    expect(
      redactPII("email a@b.com phone 555-123-4567 ssn 123-45-6789 card 4111 1111 1111 1111"),
    ).toBe("email [REDACTED] phone [REDACTED] ssn [REDACTED] card [REDACTED]");
    expect(
      redactPII("email a@b.com", { patterns: { custom: [/a@b/] }, placeholder: "<x>" }),
    ).toBe("email <x>.com");
  });
});