/**
 * Official groundwtypescript SDK for the Groundwork query runtime.
 *
 * - `GroundworkClient`: zero-trust query, leak report, and immutable
 *   audit-chain verification against the runtime.
 * - `withGroundwork` / `createGroundworkRetrievalTool`: Vercel AI SDK v5
 *   middleware that intercepts retrieval tool invocations, enforces user
 *   identity assertion headers, and redacts PII from model response
 *   streams.
 */

export {
  API_KEY_HEADER,
  USER_ASSERTION_HEADER,
  DELEGATION_TOKEN_HEADER,
  CORRELATION_ID_HEADER,
  GroundworkClient,
  GroundworkError,
  GroundworkHTTPError,
  PermissionDeniedError,
  FailClosedError,
} from "./client";
export type {
  Citation,
  RuntimeTrace,
  QueryResponse,
  LeakFinding,
  LeakReportResponse,
  AuditChainProblem,
  AuditVerificationResponse,
  QueryOptions,
  GroundworkClientOptions,
} from "./client";
export {
  withGroundwork,
  createGroundworkRetrievalTool,
  redactPII,
  GroundworkIdentityError,
  GROUNDWORK_RETRIEVAL_TOOL_NAME,
} from "./middleware/vercel";
export type {
  UserIdentity,
  RedactionOptions,
  GroundworkMiddlewareOptions,
  GroundworkRetrievalToolOptions,
  RetrievalResult,
} from "./middleware/vercel";