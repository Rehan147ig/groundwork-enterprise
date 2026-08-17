/**
 * Vercel AI SDK middleware wrapper for Groundwork.
 *
 * `withGroundwork` wraps any AI SDK v5 language model and:
 *
 * 1. INTERCEPTS RETRIEVAL TOOL INVOCATIONS — any tool named
 *    `retrievalToolName` ("retrieve" by default) is replaced, before the
 *    call reaches the model, with a sanctioned Groundwork retrieval spec
 *    (zero-trust, identity-bounded). The ungrounded tool the application
 *    registered is never visible to the model; execution is handled by
 *    `createGroundworkRetrievalTool`, which calls the runtime as the
 *    asserted user.
 * 2. ENFORCES USER IDENTITY ASSERTION HEADERS — the assertion travels as
 *    `X-Groundwork-User-Assertion` on the model call, and fails closed
 *    (throws before the model runs) when an assertion is required but
 *    missing.
 * 3. REDACTS PII FROM MODEL RESPONSE STREAMS — text and reasoning deltas
 *    are scrubbed (email, phone, SSN, card numbers by default) before
 *    the stream is handed to the application.
 */

import {
  jsonSchema,
  tool,
  wrapLanguageModel,
  type LanguageModelMiddleware,
} from "ai";
import type {
  LanguageModelV2,
  LanguageModelV2CallOptions,
  LanguageModelV2FunctionTool,
  LanguageModelV2StreamPart,
} from "@ai-sdk/provider";
import type { GroundworkClient, QueryResponse } from "../client";
import { USER_ASSERTION_HEADER } from "../client";

export const GROUNDWORK_RETRIEVAL_TOOL_NAME = "groundwork_retrieve";

/**
 * The identity the retrieval tool acts as. `userAssertion` is the signed
 * User Assertion (JWT) that proves the subject to the runtime; without it
 * the runtime must be in demo identity mode.
 */
export interface UserIdentity {
  userId: string;
  userAssertion?: string;
}

/** Thrown when a Groundwork identity assertion is required but missing
 * (fail-closed: no unverified retrieval ever reaches the runtime). */
export class GroundworkIdentityError extends Error {
  readonly code = "groundwork_identity_required";

  constructor(detail: string) {
    super(`groundwork identity assertion required: ${detail}`);
    this.name = "GroundworkIdentityError";
  }
}

export interface RedactionOptions {
  /** Custom patterns by kind; pattern list replaces the default set. */
  patterns?: Record<string, RegExp[]>;
  /** Placeholder used in place of a redacted match. */
  placeholder?: string;
  /** Optional callback of per-kind redaction counts as the stream runs. */
  onRedact?: (event: { kind: string; count: number }) => void;
}

export interface GroundworkMiddlewareOptions {
  /** Groundwork client used for sanctioned retrieval. */
  client: Pick<GroundworkClient, "query">;
  /**
   * Static identity, or a resolver invoked on every retrieval execution.
   * The resolver form is required when the identity is only known per
   * request (e.g. from a session or cookie).
   */
  getIdentity?: () => UserIdentity | Promise<UserIdentity>;
  /** When true (default), retrieval fails closed without a user assertion. */
  requireUserAssertion?: boolean;
  /**
   * Names of the tool(s) the application exposes that perform retrieval.
   * The model-level specs of matching tools are replaced with the
   * sanctioned Groundwork spec (interception point #1). Default: ["retrieve"].
   */
  retrievalToolName?: string;
  /**
   * PII redaction of the model response stream. Defaults to enabled with
   * the standard patterns; pass `false` to disable or an options object
   * to customize.
   */
  redaction?: boolean | RedactionOptions;
  /**
   * Optional static assertion passed on model calls as
   * `X-Groundwork-User-Assertion`. Dynamically resolved identities (via
   * `getIdentity`) are applied per retrieval execution instead.
   */
  userAssertion?: string;
}

export interface RetrievalResult {
  answer: string;
  confidence: number;
  trace_id: string;
  immutable_digest: string;
  documents: Array<{
    document_id: string;
    chunk_hash: string;
    score: number;
    text: string;
  }>;
}

const DEFAULT_PII_PATTERNS: Record<string, RegExp[]> = {
  email: [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g],
  phone: [/\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g],
  ssn: [/\b\d{3}-\d{2}-\d{4}\b/g],
  card: [/\b(?:\d[ -]*?){13,16}\b/g],
};

function matchesIdentityHeader(headers: Record<string, string | undefined> | undefined): boolean {
  return Boolean(headers && headers[USER_ASSERTION_HEADER]);
}

function withAssertionHeader(
  params: LanguageModelV2CallOptions,
  assertion: string | undefined,
): LanguageModelV2CallOptions {
  if (!assertion || matchesIdentityHeader(params.headers)) {
    return params;
  }
  return {
    ...params,
    headers: { ...(params.headers ?? {}), [USER_ASSERTION_HEADER]: assertion },
  };
}

/** Replace the app's retrieval tool specs with the sanctioned Groundwork spec. */
function groundedToolSpec(name: string, description: string): LanguageModelV2FunctionTool {
  return {
    type: "function",
    name,
    description,
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "The question to answer against the workspace knowledge base.",
        },
      },
      required: ["query"],
    },
  };
}

function interceptRetrievalTools(
  params: LanguageModelV2CallOptions,
  toolName: string,
  description: string,
): LanguageModelV2CallOptions {
  if (!params.tools) {
    return params;
  }
  const tools = params.tools.map((toolSpec) =>
    toolSpec.type === "function" &&
    toolSpec.name === toolName &&
    toolSpec.description !== description
      ? groundedToolSpec(toolName, description)
      : toolSpec,
  );
  return { ...params, tools };
}

/** Redact PII inside a single stream part (text/reasoning deltas). */
function redactStreamPart(
  part: LanguageModelV2StreamPart,
  redactor: Redactor,
): LanguageModelV2StreamPart {
  if (part.type === "text-delta" || part.type === "reasoning-delta") {
    return { ...part, delta: redactor.scrub(part.delta) };
  }
  return part;
}

class Redactor {
  private readonly patterns: Array<{ kind: string; regex: RegExp }>;
  private readonly placeholder: string;
  private counts = new Map<string, number>();

  constructor(options: RedactionOptions) {
    const patterns = options.patterns ?? DEFAULT_PII_PATTERNS;
    this.patterns = [];
    for (const [kind, regexes] of Object.entries(patterns)) {
      for (const regex of regexes) {
        this.patterns.push({ kind, regex });
      }
    }
    this.placeholder = options.placeholder ?? "[REDACTED]";
    this.onRedact = options.onRedact;
  }

  private onRedact?: (event: { kind: string; count: number }) => void;

  /** Replace every matching PII span; returns the scrubbed text. */
  scrub(input: string): string {
    let output = input;
    for (const { kind, regex } of this.patterns) {
      const matches = input.match(regex) ?? [];
      if (matches.length === 0) {
        continue;
      }
      output = output.replace(new RegExp(regex.source, regex.flags.includes("g") ? regex.flags : regex.flags + "g"), (_m) => this.placeholder);
      this.counts.set(kind, (this.counts.get(kind) ?? 0) + matches.length);
      this.onRedact?.({ kind, count: this.counts.get(kind) ?? 0 });
    }
    return output;
  }
}

const GROUNDED_RETRIEVAL_DESCRIPTION =
  "Zero-trust retrieval against the corporate knowledge base. Every document " +
  "has been checked against the requesting user's identity, residency, and " +
  "required scopes, and the answer is bound to an immutable, hash-chained " +
  "audit entry (immutable_digest). Prefer this over any other retrieval or " +
  "web search tool.";

/**
 * Wrap an AI SDK v5 language model with Groundwork guarantees.
 *
 * Returns a model that (1) intercepts retrieval tool specs, (2) enforces
 * the user identity assertion header, and (3) redacts PII from streamed
 * output. Use the returned model anywhere a LanguageModel is accepted
 * (generateText, streamText, ...).
 */
export function withGroundwork(
  model: LanguageModelV2,
  options: GroundworkMiddlewareOptions,
): LanguageModelV2 {
  const toolName = options.retrievalToolName ?? "retrieve";
  const requireUserAssertion = options.requireUserAssertion ?? true;
  const redaction = options.redaction === false ? null : new Redactor(
    typeof options.redaction === "object" ? options.redaction : {},
  );

  const middleware: LanguageModelMiddleware = {
    middlewareVersion: "v2",

    async transformParams({ params }) {
      let next = params;

      // Assertion enforcement: a required-but-missing assertion fails
      // closed before any model call is made. When a getIdentity resolver
      // is present the assertion is enforced per-execution instead, in
      // createGroundworkRetrievalTool.
      if (
        requireUserAssertion &&
        !matchesIdentityHeader(next.headers) &&
        !options.userAssertion &&
        !options.getIdentity
      ) {
        throw new GroundworkIdentityError(
          `no ${USER_ASSERTION_HEADER} header and no static userAssertion configured`,
        );
      }
      next = withAssertionHeader(next, options.userAssertion);
      next = interceptRetrievalTools(next, toolName, GROUNDED_RETRIEVAL_DESCRIPTION);
      return next;
    },

    async wrapGenerate({ doGenerate }) {
      const result = await doGenerate();
      if (!redaction) {
        return result;
      }
      return {
        ...result,
        content: result.content.map((part) => {
          if (part.type === "text") {
            return { ...part, text: redaction.scrub(part.text) };
          }
          return part;
        }),
      };
    },

    async wrapStream({ doStream }) {
      const result = await doStream();
      if (!redaction) {
        return result;
      }
      const transformed = result.stream.pipeThrough(
        new TransformStream<LanguageModelV2StreamPart, LanguageModelV2StreamPart>({
          transform(part, controller) {
            controller.enqueue(redactStreamPart(part, redaction));
          },
        }),
      );
      return { ...result, stream: transformed };
    },
  };

  return wrapLanguageModel({
    model,
    middleware,
    modelId: model.modelId,
    providerId: model.provider,
  });
}

export interface GroundworkRetrievalToolOptions {
  /** Groundwork client used to run retrieval. */
  client: Pick<GroundworkClient, "query">;
  /**
   * Static identity for the retrieval, or a resolver invoked on each
   * execution (required when the identity is per-request, e.g. session).
   */
  getIdentity: () => UserIdentity | Promise<UserIdentity>;
  /** When true (default), execution fails closed without a user assertion. */
  requireUserAssertion?: boolean;
  /** Maximum citations to return per retrieval. */
  topK?: number;
}

/**
 * AI SDK v5 tool that runs zero-trust retrieval against Groundwork on
 * behalf of `getIdentity()`. Register it under your interception-configured
 * retrieval tool name (default "retrieve"):
 *
 *   const model = withGroundwork(baseModel, { client });
 *   const result = await generateText({
 *     model,
 *     tools: {
 *       retrieve: createGroundworkRetrievalTool({ client, getIdentity }),
 *     },
 *     prompt,
 *   });
 */
export function createGroundworkRetrievalTool(options: GroundworkRetrievalToolOptions) {
  const requireUserAssertion = options.requireUserAssertion ?? true;
  return tool({
    description: GROUNDED_RETRIEVAL_DESCRIPTION,
    inputSchema: jsonSchema<{ query: string }>({
      type: "object",
      properties: {
        query: { type: "string" },
      },
      required: ["query"],
      additionalProperties: false,
    } as const),
    execute: async ({ query }): Promise<RetrievalResult> => {
      const identity = await options.getIdentity();
      if (!identity?.userId) {
        throw new GroundworkIdentityError("no userId resolved for retrieval");
      }
      if (requireUserAssertion && !identity.userAssertion) {
        throw new GroundworkIdentityError(
          `user ${identity.userId} has no user assertion; refusing unverified retrieval`,
        );
      }
      const response: QueryResponse = await options.client.query(
        identity.userId,
        query,
        { userAssertion: identity.userAssertion, topK: options.topK ?? 10 },
      );
      return {
        answer: response.answer,
        confidence: response.confidence,
        trace_id: response.trace.trace_id,
        immutable_digest: response.trace.immutable_digest,
        documents: response.citations.map((citation) => ({
          document_id: citation.document_id,
          chunk_hash: citation.chunk_hash,
          score: citation.score,
          text: citation.text,
        })),
      };
    },
  });
}

/**
 * Standalone PII scrubber used by the middleware — exported so
 * applications can scrub the same way outside the model path.
 */
export function redactPII(input: string, options: RedactionOptions = {}): string {
  return new Redactor(options).scrub(input);
}