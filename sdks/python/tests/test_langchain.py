"""Tests for the LangChain integration (GroundworkRetriever)."""

from __future__ import annotations

from typing import Callable, Optional

import httpx
from langchain_core.documents import Document

from groundwork import GroundworkClient
from groundwork.integrations.langchain import GroundworkRetriever

API_KEY = "gw_test_key"
ENDPOINT = "http://runtime.test"


def query_payload(n_citations: int = 2) -> dict:
    citations = [
        {
            "document_id": f"doc-{i}",
            "chunk_id": f"chunk-{i}",
            "chunk_hash": f"hash-{i}",
            "page": i + 1,
            "offset": i * 10,
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
        "trace": {"trace_id": "trace-1", "immutable_digest": "chain-digest-1"},
    }


def make_client(handler) -> GroundworkClient:
    return GroundworkClient(
        ENDPOINT, API_KEY, transport=httpx.MockTransport(handler), backoff_factor=0.0
    )


def test_maps_citations_to_documents_with_spec_metadata() -> None:
    client = make_client(lambda request: httpx.Response(200, json=query_payload(2)))
    retriever = GroundworkRetriever(client=client, user_id="alice")
    docs = retriever.invoke("budget question")

    assert isinstance(docs, list)
    assert len(docs) == 2
    for i, doc in enumerate(docs):
        assert isinstance(doc, Document)
        assert doc.page_content == f"chunk text {i}"
        assert doc.metadata == {
            "doc_id": f"chunk-{i}",
            "score": 0.9 - i * 0.1,
            "digest": f"hash-{i}",
        }


def test_empty_response_returns_empty_list() -> None:
    client = make_client(lambda request: httpx.Response(200, json=query_payload(0)))
    retriever = GroundworkRetriever(client=client, user_id="alice")
    assert retriever.invoke("nothing here") == []


def test_forwards_top_k_and_user_token() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["assertion"] = request.headers.get("X-Groundwork-User-Assertion")
        seen["body"] = request.read().decode()
        return httpx.Response(200, json=query_payload(n_citations=5))

    retriever = GroundworkRetriever(
        client=make_client(handler),
        user_id="alice",
        top_k=2,
        user_token="jwt-1",
    )
    docs = retriever.invoke("policy question")

    assert seen["assertion"] == "jwt-1"
    assert "alice" in seen["body"]
    assert "policy question" in seen["body"]
    assert len(docs) == 2


def test_callable_user_id_resolves_per_invocation() -> None:
    current_user: dict = {"id": "alice"}

    def handler(request: httpx.Request) -> httpx.Response:
        payload = request.read().decode()
        assert '"user_id":"%s"' % current_user["id"] in payload
        return httpx.Response(200, json=query_payload(1))

    retriever = GroundworkRetriever(
        client=make_client(handler),
        user_id=lambda: current_user["id"],
    )
    retriever.invoke("first")
    current_user["id"] = "bob"
    docs = retriever.invoke("second")
    # A fresh callable still produces valid documents; the identity header
    # was asserted by the handler for both calls.
    assert docs[0].page_content == "chunk text 0"


def test_run_manager_kwarg_is_accepted() -> None:
    from langchain_core.callbacks import BaseCallbackHandler

    class FakeRunManager(BaseCallbackHandler):
        def on_retriever_end(self, documents: list, **kwargs: object) -> None:
            assert documents

    client = make_client(lambda request: httpx.Response(200, json=query_payload(1)))
    retriever = GroundworkRetriever(client=client, user_id="alice")
    docs = retriever.invoke("q", config={"callbacks": [FakeRunManager()]})
    assert docs[0].metadata["doc_id"] == "chunk-0"


def test_get_relevant_documents_direct_call_with_run_manager() -> None:
    client = make_client(lambda request: httpx.Response(200, json=query_payload(1)))
    retriever = GroundworkRetriever(client=client, user_id="alice")
    docs = retriever._get_relevant_documents("direct", run_manager=None)
    assert docs[0].metadata["digest"] == "hash-0"


def test_retriever_is_a_base_retriever() -> None:
    from langchain_core.retrievers import BaseRetriever

    client = make_client(lambda request: httpx.Response(200, json=query_payload(0)))
    retriever = GroundworkRetriever(client=client, user_id="alice")
    assert isinstance(retriever, BaseRetriever)