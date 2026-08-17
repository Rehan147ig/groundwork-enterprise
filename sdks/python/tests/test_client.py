"""Tests for the Groundwork Python SDK against mock HTTP responses."""

from __future__ import annotations

import httpx
import pytest

from groundwork import (
    AuditChainProblem,
    AuditVerificationResponse,
    Citation,
    FailClosedEngineError,
    FailClosedError,
    GroundworkClient,
    GroundworkError,
    GroundworkHTTPError,
    LeakFinding,
    LeakReportResponse,
    PermissionDeniedError,
    QueryResponse,
)

API_KEY = "gw_test_key"
ENDPOINT = "http://runtime.test"


def make_client(handler, **kwargs) -> GroundworkClient:
    transport = httpx.MockTransport(handler)
    return GroundworkClient(
        ENDPOINT, API_KEY, transport=transport, backoff_factor=0.0, **kwargs
    )


def query_payload(n_citations: int = 2) -> dict:
    citations = [
        {
            "document_id": f"doc-{i}",
            "chunk_id": f"chunk-{i}",
            "chunk_hash": f"hash-{i}",
            "page": 1,
            "offset": i * 100,
            "text": f"chunk text {i}",
            "score": 0.9 - i * 0.1,
            "freshness_score": 1.0,
        }
        for i in range(n_citations)
    ]
    return {
        "answer": "found it",
        "confidence": 0.85,
        "citations": citations,
        "trace": {
            "trace_id": "trace-1",
            "user_id": "alice",
            "immutable_digest": "chain-digest-1",
        },
    }


def test_constructor_defaults() -> None:
    client = GroundworkClient(ENDPOINT, API_KEY)
    assert client.endpoint == ENDPOINT
    assert client.api_key == API_KEY
    assert client._timeout_seconds == 10.0
    assert client._max_retries == 3
    assert client._client is None
    assert client._async_client is None
    client.close()


def test_query_parses_response_and_slices_top_k() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["body"] = request.read()
        seen["key"] = request.headers["X-Groundwork-API-Key"]
        return httpx.Response(200, json=query_payload(n_citations=4))

    client = make_client(handler)
    result = client.query("alice", "what is the budget?", top_k=2)

    assert seen["method"] == "POST"
    assert seen["path"] == "/v1/query"
    assert seen["key"] == API_KEY
    assert "alice" in seen["body"].decode()
    assert "what is the budget?" in seen["body"].decode()
    assert isinstance(result, QueryResponse)
    assert result.answer == "found it"
    assert result.confidence == 0.85
    assert result.trace_id == "trace-1"
    assert result.immutable_digest == "chain-digest-1"
    assert len(result.citations) == 2
    citation = result.citations[0]
    assert isinstance(citation, Citation)
    assert citation.document_id == "doc-0"
    assert citation.chunk_hash == "hash-0"
    assert citation.watermark is None


def test_citation_id_and_digest_properties() -> None:
    citation = Citation.from_dict(
        {"document_id": "d", "chunk_id": "c-7", "chunk_hash": "h-9"}
    )
    assert citation.id == "c-7"
    assert citation.digest == "h-9"


def test_query_ok_without_trace() -> None:
    client = make_client(
        lambda request: httpx.Response(200, json={"answer": "x", "confidence": 0.1})
    )
    result = client.query("alice", "hi")
    assert result.trace_id is None
    assert result.citations == []


def test_query_sends_user_assertion_header() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["assertion"] = request.headers.get("X-Groundwork-User-Assertion")
        return httpx.Response(200, json=query_payload(0))

    client = make_client(handler)
    client.query("alice", "q", user_token="jwt-abc")
    assert seen["assertion"] == "jwt-abc"


def test_query_without_token_sends_no_assertion_header() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["has"] = "X-Groundwork-User-Assertion" in request.headers
        return httpx.Response(200, json=query_payload(0))

    client = make_client(handler)
    client.query("alice", "q")
    assert seen["has"] is False


def test_top_k_zero_and_negative() -> None:
    client = make_client(
        lambda request: httpx.Response(200, json=query_payload(n_citations=3))
    )
    assert client.query("a", "q", top_k=0).citations == []
    assert client.query("a", "q", top_k=-5).citations == []


def test_leak_report_parses_findings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "findings": [
                    {
                        "kind": "so-d",
                        "severity": "high",
                        "title": "mutual exclusion",
                        "detail": "alice approved own change",
                    }
                ]
            },
        )

    result = make_client(handler).leak_report()
    assert isinstance(result, LeakReportResponse)
    finding = result.findings[0]
    assert isinstance(finding, LeakFinding)
    assert finding.kind == "so-d"
    assert finding.severity == "high"
    assert finding.title == "mutual exclusion"


def test_leak_report_empty_findings() -> None:
    client = make_client(lambda request: httpx.Response(200, json={}))
    assert client.leak_report().findings == []


def test_verify_audit_with_problems() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "verified": False,
                "entries_checked": 3,
                "problems": [
                    {
                        "index": 1,
                        "trace_id": "trace-x",
                        "kind": "mismatch",
                        "detail": "digest mismatch",
                    }
                ],
            },
        )

    result = make_client(handler).verify_audit()
    assert isinstance(result, AuditVerificationResponse)
    assert result.verified is False
    assert result.entries_checked == 3
    problem = result.problems[0]
    assert isinstance(problem, AuditChainProblem)
    assert problem.index == 1
    assert problem.trace_id == "trace-x"
    assert problem.kind == "mismatch"


def test_verify_audit_clean() -> None:
    client = make_client(
        lambda request: httpx.Response(
            200, json={"verified": True, "entries_checked": 42}
        )
    )
    result = client.verify_audit()
    assert result.verified is True
    assert result.entries_checked == 42
    assert result.problems == []


def test_403_raises_permission_denied() -> None:
    client = make_client(
        lambda request: httpx.Response(403, json={"error": "identity_cannot_change"})
    )
    with pytest.raises(PermissionDeniedError) as excinfo:
        client.query("alice", "q")
    assert excinfo.value.status_code == 403
    assert "identity_cannot_change" in str(excinfo.value)


def test_500_raises_fail_closed_engine() -> None:
    client = make_client(
        lambda request: httpx.Response(500, json={"error": "authz_backend_down"})
    )
    with pytest.raises(FailClosedEngineError) as excinfo:
        client.query("alice", "q")
    assert excinfo.value.status_code == 500
    assert FailClosedError is FailClosedEngineError


def test_other_status_raises_http_error() -> None:
    client = make_client(
        lambda request: httpx.Response(401, json={"error": "invalid_api_key"})
    )
    with pytest.raises(GroundworkHTTPError) as excinfo:
        client.query("alice", "q")
    assert excinfo.value.status_code == 401
    assert "invalid_api_key" in excinfo.value.detail


def test_non_json_error_body() -> None:
    client = make_client(
        lambda request: httpx.Response(404, text="not found page")
    )
    with pytest.raises(GroundworkHTTPError) as excinfo:
        client.query("alice", "q")
    assert "not found" in excinfo.value.detail


def test_retries_then_succeeds() -> None:
    attempts: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request.url.path)
        if len(attempts) < 3:
            return httpx.Response(503, json={"error": "overloaded"})
        return httpx.Response(200, json=query_payload(0))

    client = make_client(handler, max_retries=4)
    result = client.query("alice", "q")
    assert len(attempts) == 3
    assert result.answer == "found it"


def test_retries_exhausted_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "overloaded"})

    client = make_client(handler, max_retries=2)
    with pytest.raises(GroundworkHTTPError):
        client.query("alice", "q")


def test_transport_error_retries_then_succeeds() -> None:
    attempts: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request.url.path)
        if len(attempts) < 3:
            raise httpx.ConnectError("connection refused")
        return httpx.Response(200, json=query_payload(0))

    client = make_client(handler, max_retries=3)
    assert client.query("alice", "q").answer == "found it"
    assert len(attempts) == 3


def test_transport_error_exhausted_raises_groundwork_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("still down")

    client = make_client(handler, max_retries=1)
    with pytest.raises(GroundworkError):
        client.query("alice", "q")


def test_non_retryable_500_is_not_retried() -> None:
    attempts: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request.url.path)
        return httpx.Response(500, json={"error": "fail_closed"})

    client = make_client(handler, max_retries=3)
    with pytest.raises(FailClosedEngineError):
        client.query("alice", "q")
    assert len(attempts) == 1


def test_unexpected_body_raises() -> None:
    client = make_client(lambda request: httpx.Response(200, json=["not", "a", "dict"]))
    with pytest.raises(GroundworkError):
        client.query("alice", "q")


def test_context_manager_and_close() -> None:
    with make_client(lambda request: httpx.Response(200, json=query_payload(0))) as gw:
        assert gw.query("alice", "q").answer == "found it"
    assert gw._client is None


def test_endpoint_trailing_slash_stripped() -> None:
    client = GroundworkClient("http://runtime.test/", API_KEY)
    assert client.endpoint == "http://runtime.test"
    assert client._client is None
    client.close()


# ---------------------------------------------------------------------------
# Async request paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aquery_parses_response_and_forwards_assertion() -> None:
    seen: dict = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["assertion"] = request.headers.get("X-Groundwork-User-Assertion")
        seen["body"] = request.read().decode()
        return httpx.Response(200, json=query_payload(n_citations=3))

    client = make_client(handler)
    result = await client.aquery("bob", "async question?", top_k=1, user_token="jwt-9")

    assert seen["method"] == "POST"
    assert seen["path"] == "/v1/query"
    assert seen["assertion"] == "jwt-9"
    assert '"user_id":"bob"' in seen["body"]
    assert isinstance(result, QueryResponse)
    assert result.answer == "found it"
    assert len(result.citations) == 1
    assert client._async_client is not None
    await client.aclose()
    assert client._async_client is None


@pytest.mark.asyncio
async def test_aquery_retries_then_succeeds() -> None:
    attempts: list = []

    async def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request.url.path)
        if len(attempts) < 3:
            return httpx.Response(503, json={"error": "overloaded"})
        return httpx.Response(200, json=query_payload(0))

    client = make_client(handler, max_retries=4)
    result = await client.aquery("alice", "q")
    assert len(attempts) == 3
    assert result.answer == "found it"
    await client.aclose()


@pytest.mark.asyncio
async def test_aquery_403_and_500_map_errors() -> None:
    denied = make_client(
        lambda request: httpx.Response(403, json={"error": "no_scope"})
    )
    with pytest.raises(PermissionDeniedError):
        await denied.aquery("alice", "q")

    broken = make_client(
        lambda request: httpx.Response(500, json={"error": "boom"})
    )
    with pytest.raises(FailClosedEngineError):
        await broken.aquery("alice", "q")
    await denied.aclose()
    await broken.aclose()


@pytest.mark.asyncio
async def test_aquery_transport_error_exhausted() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    client = make_client(handler, max_retries=1)
    with pytest.raises(GroundworkError):
        await client.aquery("alice", "q")
    await client.aclose()


@pytest.mark.asyncio
async def test_async_leak_report_and_verify_audit() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/leak-report":
            return httpx.Response(
                200,
                json={
                    "findings": [
                        {
                            "kind": "creds-env",
                            "severity": "critical",
                            "title": "creds",
                            "detail": "secrets in env",
                        }
                    ]
                },
            )
        return httpx.Response(
            200,
            json={"verified": True, "entries_checked": 7, "problems": []},
        )

    client = make_client(handler)
    report = await client.aleak_report()
    assert report.findings[0].kind == "creds-env"
    verification = await client.averify_audit()
    assert verification.verified is True
    assert verification.entries_checked == 7
    assert verification.problems == []
    await client.aclose()


@pytest.mark.asyncio
async def test_async_context_manager() -> None:
    async with make_client(
        lambda request: httpx.Response(200, json=query_payload(0))
    ) as gw:
        result = await gw.aquery("alice", "q")
        assert result.answer == "found it"
    assert gw._async_client is None