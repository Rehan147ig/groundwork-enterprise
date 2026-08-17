/**
 * LlamaIndex.ts integration: a `BaseRetriever` backed by Groundwork.
 *
 * Every retrieved node has already passed the runtime's zero-trust checks
 * (identity, residency, required scopes) before it is handed to the agent,
 * so unpermitted citations are never surfaced to the downstream index. Each
 * node's metadata carries `doc_id` (the chunk id to cite), `digest` (the
 * chunk's audit-chain hash for provenance verification) and `score` (the
 * runtime retrieval score); the same value is also exposed as the node's
 * `NodeWithScore.score`.
 *
 * Usage:
 *
 *   const retriever = new GroundworkLlamaIndexRetriever({
 *     client,
 *     userId: () => session.userId,
 *     topK: 5,
 *   });
 *   const engine = new RetrieverQueryEngine(retriever);
 *   const response = await engine.query({ query: "..." });
 */

import { BaseRetriever } from "@llamaindex/core/retriever";
import type { QueryBundle } from "@llamaindex/core/query-engine";
import { TextNode, type NodeWithScore } from "@llamaindex/core/schema";
import type { GroundworkClient } from "../client";

/** Static user id, or a callable resolving the current subject per
 * invocation (e.g. from a request session), so a single retriever can
 * serve many users. */
export type GroundworkUserId = string | (() => string);

export interface GroundworkLlamaIndexRetrieverOptions {
  /** Groundwork client used to answer retrieval calls. */
  client: GroundworkClient;
  /** Identity the retrieval runs as. */
  userId: GroundworkUserId;
  /** Maximum number of nodes to return per retrieval. */
  topK?: number;
  /** Optional signed User Assertion (JWT) sent as
   * `X-Groundwork-User-Assertion`; without it the runtime must be in
   * demo identity mode for a plain user id to be accepted. */
  userAssertion?: string;
}

/** Flatten a query bundle's message content to the plain question string. */
function queryText(query: QueryBundle["query"]): string {
  if (typeof query === "string") {
    return query;
  }
  return query
    .filter((part) => part.type === "text")
    .map((part) => part.text)
    .join("\n");
}

/**
 * LlamaIndex.ts retriever that answers on behalf of a user through
 * Groundwork. Implements `retrieve({ query })` (via the abstract
 * `_retrieve`) by routing the question to `client.query()` and mapping the
 * runtime's citations to `NodeWithScore<TextNode>` entries.
 */
export class GroundworkLlamaIndexRetriever extends BaseRetriever {
  private readonly client: GroundworkClient;
  private readonly userId: GroundworkUserId;
  private readonly topK: number;
  private readonly userAssertion?: string;

  constructor(options: GroundworkLlamaIndexRetrieverOptions) {
    super();
    this.client = options.client;
    this.userId = options.userId;
    this.topK = options.topK ?? 10;
    this.userAssertion = options.userAssertion;
  }

  _retrieve(params: QueryBundle): Promise<NodeWithScore[]> {
    const userId =
      typeof this.userId === "function" ? this.userId() : this.userId;
    return this.client
      .query(userId, queryText(params.query), {
        topK: this.topK,
        userAssertion: this.userAssertion,
      })
      .then((response) =>
        response.citations.map((citation) => ({
          node: new TextNode({
            id_: citation.chunk_id,
            text: citation.text,
            metadata: {
              doc_id: citation.chunk_id,
              digest: citation.chunk_hash,
              document_id: citation.document_id,
              page: citation.page,
              offset: citation.offset,
              score: citation.score,
              freshness_score: citation.freshness_score,
              ...(citation.watermark
                ? { watermark: citation.watermark }
                : {}),
            },
          }),
          score: citation.score,
        })),
      );
  }
}