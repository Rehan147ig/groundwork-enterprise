/**
 * HTTP client for the Groundwork query runtime.
 *
 * The runtime enforces zero-trust access control at the request boundary:
 * every document returned to an agent has already been checked against the
 * subject's identity, residency, and required scopes, and every request is
 * appended to an immutable, hash-chained audit log (SHA-256 chain, each
 * entry bound to its predecessor).
 */

export const API_KEY_HEADER = "X-Groundwork-API-Key";
export const USER_ASSERTION_HEADER = "X-Groundwork-User-Assertion";
export const DELEGATION_TOKEN_HEADER = "X-Groundwork-Delegation-Token";
export const CORRELATION_ID_HEADER = "X-Groundwork-Correlation-Id";

const USER_AGENT = "groundwork-typescript/0.1.0";

/** Transient statuses that warrant a retry with backoff. 5xx business
 * failures (notably 500) are FAIL-CLOSED and never retried. */
const RETRYABLE_STATUS = new Set([429, 502, 503, 504]);

/** Base error for all Groundwork SDK failures. */
export class GroundworkError extends Error {}

/** The runtime returned a non-2xx, non-special status. */
export class GroundworkHTTPError extends GroundworkError {
  constructor(
    readonly statusCode: number,
    readonly detail: string,
  ) {
    super(`${statusCode}: ${detail}`);
    this.name = "GroundworkHTTPError";
  }
}

/** The identity was recognized but access was denied (403). */
export class PermissionDeniedError extends GroundworkHTTPError {
  constructor(statusCode: number, detail: string) {
    super(statusCode, detail);
    this.name = "PermissionDeniedError";
  }
}

/** The runtime could not safely answer and failed closed (500+). */
export class FailClosedError extends GroundworkHTTPError {
  constructor(statusCode: number, detail: string) {
    super(statusCode, detail);
    this.name = "FailClosedError";
  }
}

export interface Citation {
  document_id: string;
  chunk_id: string;
  chunk_hash: string;
  page: number;
  offset: number;
  text: string;
  score: number;
  freshness_score: number;
  /** Provenance signature from the context firewall; empty when unset. */
  watermark?: string;
}

export interface RuntimeTrace {
  trace_id: string;
  tenant_id: string;
  user_id: string;
  region: string;
  started_at: string;
  latency_ms: number;
  vector_candidates: number;
  keyword_candidates: number;
  blocked_by_acl: number;
  blocked_by_residency: number;
  reranked_candidates: number;
  decision_mode: string;
  shadow_mode?: boolean;
  would_block_by_acl?: number;
  failure_stage?: string;
  error_code?: string;
  error_message?: string;
  access_decisions: Array<{
    chunk_id: string;
    chunk_hash: string;
    document_id: string;
    allowed: boolean;
    reason: string;
    region: string;
    required_scope: string;
  }>;
  immutable_digest: string;
}

export interface QueryResponse {
  answer: string;
  confidence: number;
  citations: Citation[];
  trace: RuntimeTrace;
}

export interface LeakFinding {
  kind: string;
  severity: string;
  title: string;
  detail: string;
}

export interface LeakReportResponse {
  findings: LeakFinding[];
}

export interface AuditChainProblem {
  index: number;
  trace_id: string;
  kind: string;
  detail: string;
}

export interface AuditVerificationResponse {
  verified: boolean;
  entries_checked: number;
  problems: AuditChainProblem[];
}

export interface QueryOptions {
  /** Optional signed User Assertion (JWT) proving the subject to the
   * runtime. Without it the runtime must be in demo identity mode for a
   * plain user_id to be accepted. */
  userAssertion?: string;
  /** Maximum number of citations to return. */
  topK?: number;
  /** Correlation id propagated into the audit trace (optional). */
  correlationId?: string;
  /** Delegation token for service-to-service access (optional). */
  delegationToken?: string;
}

export interface GroundworkClientOptions {
  /** Runtime base URL, e.g. https://runtime.example.com */
  endpoint: string;
  /** Tenant API key sent as X-Groundwork-API-Key. */
  apiKey: string;
  /** Timeout per request attempt, in milliseconds. */
  timeoutMs?: number;
  /** Number of retries for transient failures (429/502/503/504). */
  maxRetries?: number;
  /** Backoff base (seconds) for exponential jitter: delay ∈ [0, factor·2^attempt). */
  backoffFactor?: number;
  /** Custom fetch implementation (defaults to globalThis.fetch). */
  fetch?: typeof fetch;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function asNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

/**
 * Minimal, typed client for the Groundwork query runtime.
 *
 * Retries transient failures (429/502/503/504 and transport errors) with
 * exponential backoff plus random jitter. 403 and 5xx responses surface as
 * PermissionDeniedError and FailClosedError respectively and are never
 * retried (the runtime fails closed).
 */
export class GroundworkClient {
  readonly endpoint: string;
  readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly backoffFactor: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: GroundworkClientOptions) {
    this.endpoint = options.endpoint.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.maxRetries = options.maxRetries ?? 3;
    this.backoffFactor = options.backoffFactor ?? 0.5;
    this.fetchImpl = options.fetch ?? globalThis.fetch;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  private async request(
    method: string,
    path: string,
    body?: unknown,
    options: QueryOptions = {},
  ): Promise<unknown> {
    const headers: Record<string, string> = {
      [API_KEY_HEADER]: this.apiKey,
      "User-Agent": USER_AGENT,
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (options.userAssertion) {
      headers[USER_ASSERTION_HEADER] = options.userAssertion;
    }
    if (options.correlationId) {
      headers[CORRELATION_ID_HEADER] = options.correlationId;
    }
    if (options.delegationToken) {
      headers[DELEGATION_TOKEN_HEADER] = options.delegationToken;
    }

    let lastError: unknown = null;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const response = await this.fetchImpl(`${this.endpoint}${path}`, {
          method,
          headers,
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: controller.signal,
        });
        return await this.decode(response);
      } catch (error) {
        const retryable =
          isRetryableTransportError(error) &&
          attempt < this.maxRetries;
        if (!retryable) {
          if (error instanceof GroundworkHTTPError) throw error;
          throw new GroundworkError(
            `request to ${method} ${path} failed: ${
              error instanceof Error ? error.message : String(error)
            }`,
          );
        }
        lastError = error;
        await this.sleep(
          Math.floor(this.backoffFactor * 2 ** attempt * Math.random() * 1000),
        );
      } finally {
        clearTimeout(timer);
      }
    }
    // Unreachable: the last attempt either returned or threw.
    throw lastError instanceof Error
      ? lastError
      : new GroundworkError(`request to ${method} ${path} failed`);
  }

  private async decode(response: Response): Promise<unknown> {
    let payload: unknown;
    let raw = "";
    try {
      raw = await response.text();
      payload = JSON.parse(raw);
    } catch {
      payload = { error: raw.slice(0, 200) || response.statusText };
    }
    const detail = isObject(payload) && typeof payload.error === "string"
      ? payload.error
      : JSON.stringify(payload).slice(0, 200) || "unknown error";
    if (response.status === 403) {
      throw new PermissionDeniedError(response.status, detail);
    }
    if (response.status >= 500) {
      throw new FailClosedError(response.status, detail);
    }
    if (response.status >= 400) {
      throw new GroundworkHTTPError(response.status, detail);
    }
    return payload;
  }

  /**
   * Ask the runtime a question on behalf of `user_id`. Every citation has
   * already passed the runtime's zero-trust checks and can be verified
   * against the audit chain via its chunk_hash.
   */
  async query(
    userId: string,
    question: string,
    options: QueryOptions = {},
  ): Promise<QueryResponse> {
    const payload = await this.request("POST", "/v1/query", {
      user_id: userId,
      question,
    }, options);
    if (!isObject(payload)) {
      throw new GroundworkError("unexpected query response body");
    }
    const citations = Array.isArray(payload.citations)
      ? payload.citations.map<Citation>((c) => {
          if (!isObject(c)) {
            return {
              document_id: "", chunk_id: "", chunk_hash: "", page: 0,
              offset: 0, text: "", score: 0, freshness_score: 0,
            };
          }
          return {
            document_id: asString(c.document_id),
            chunk_id: asString(c.chunk_id),
            chunk_hash: asString(c.chunk_hash),
            page: asNumber(c.page),
            offset: asNumber(c.offset),
            text: asString(c.text),
            score: asNumber(c.score),
            freshness_score: asNumber(c.freshness_score),
            ...(typeof c.watermark === "string"
              ? { watermark: c.watermark }
              : {}),
          };
        })
      : [];
    const topK = Math.max(options.topK ?? citations.length, 0);
    const trace = isObject(payload.trace) ? payload.trace : {};
    return {
      answer: asString(payload.answer),
      confidence: asNumber(payload.confidence),
      citations: citations.slice(0, topK),
      trace: trace as unknown as RuntimeTrace,
    };
  }

  /** Fetch the tenant's unapproved-leak report (requires audit scope). */
  async leakReport(): Promise<LeakReportResponse> {
    const payload = await this.request("GET", "/v1/leak-report");
    if (!isObject(payload)) {
      throw new GroundworkError("unexpected leak-report response body");
    }
    const findings = Array.isArray(payload.findings)
      ? payload.findings.map<LeakFinding>((f) => {
          if (!isObject(f)) {
            return { kind: "", severity: "", title: "", detail: "" };
          }
          return {
            kind: asString(f.kind),
            severity: asString(f.severity),
            title: asString(f.title),
            detail: asString(f.detail),
          };
        })
      : [];
    return { findings };
  }

  /** Verify the tenant's immutable audit hash chain. */
  async verifyAudit(): Promise<AuditVerificationResponse> {
    const payload = await this.request("GET", "/v1/audit/verify");
    if (!isObject(payload)) {
      throw new GroundworkError("unexpected audit verify response body");
    }
    const problems = Array.isArray(payload.problems)
      ? payload.problems.map<AuditChainProblem>((p) => {
          if (!isObject(p)) {
            return { index: 0, trace_id: "", kind: "", detail: "" };
          }
          return {
            index: asNumber(p.index),
            trace_id: asString(p.trace_id),
            kind: asString(p.kind),
            detail: asString(p.detail),
          };
        })
      : [];
    return {
      verified: payload.verified === true,
      entries_checked: asNumber(payload.entries_checked),
      problems,
    };
  }
}

function isRetryableTransportError(error: unknown): boolean {
  if (error instanceof GroundworkHTTPError) {
    return RETRYABLE_STATUS.has(error.statusCode);
  }
  return error instanceof DOMException && error.name === "AbortError";
}