"""Tests for the LlamaIndex integration (GroundworkLlamaIndexRetriever)."""

from __future__ import annotations

import json

import httpx
from llama_index.core.schema import NodeWithScore, QueryBundle, TextNode

from groundwork import GroundworkClient
from groundwork.integrations.llamaindex import GroundworkLlamaIndexRetriever

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


def test_maps_citations_to_nodes_with_spec_metadata() -> None:
    client = make_client(lambda request: httpx.Response(200, json=query_payload(2)))
    retriever = GroundworkLlamaIndexRetriever(client=client, user_id="alice")
    nodes = retriever.retrieve("budget question")

    assert isinstance(nodes, list)
    assert len(nodes) == 2
    for i, node_with_score in enumerate(nodes):
        assert isinstance(node_with_score, NodeWithScore)
        assert node_with_score.score == 0.9 - i * 0.1
        node = node_with_score.node
        assert isinstance(node, TextNode)
        assert node.id_ == f"chunk-{i}"
        assert node.text == f"chunk text {i}"
        assert node.metadata == {
            "doc_id": f"chunk-{i}",
            "score": 0.9 - i * 0.1,
            "digest": f"hash-{i}",
            "document_id": f"doc-{i}",
            "page": i + 1,
            "offset": i * 10,
            "freshness_score": 1.0,
        }


def test_query_bundle_retrieve_path() -> None:
    client = make_client(lambda request: httpx.Response(200, json=query_payload(1)))
    retriever = GroundworkLlamaIndexRetriever(client=client, user_id="alice")
    nodes = retriever.retrieve(QueryBundle(query="budget question"))
    assert nodes[0].node.text == "chunk text 0"


def test_empty_response_returns_empty_list() -> None:
    client = make_client(lambda request: httpx.Response(200, json=query_payload(0)))
    retriever = GroundworkLlamaIndexRetriever(client=client, user_id="alice")
    assert retriever.retrieve("nothing here") == []


def test_forwards_top_k_and_user_token() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["assertion"] = request.headers.get("X-Groundwork-User-Assertion")
        seen["body"] = request.read().decode()
        return httpx.Response(200, json=query_payload(n_citations=5))

    retriever = GroundworkLlamaIndexRetriever(
        client=make_client(handler),
        user_id="alice",
        top_k=2,
        user_token="jwt-1",
    )
    nodes = retriever.retrieve("policy question")

    assert seen["assertion"] == "jwt-1"
    assert "alice" in seen["body"]
    assert "policy question" in seen["body"]
    assert len(nodes) == 2


def test_callable_user_id_resolves_per_invocation() -> None:
    current_user: dict = {"id": "alice"}

    def handler(request: httpx.Request) -> httpx.Response:
        payload = request.read().decode()
        assert '"user_id":"%s"' % current_user["id"] in payload
        return httpx.Response(200, json=query_payload(1))

    retriever = GroundworkLlamaIndexRetriever(
        client=make_client(handler),
        user_id=lambda: current_user["id"],
    )
    retriever.retrieve("first")
    current_user["id"] = "bob"
    nodes = retriever.retrieve("second")
    # A fresh callable still produces valid nodes; the identity was
    # asserted by the handler for both calls.
    assert nodes[0].node.text == "chunk text 0"


def test_retriever_is_a_base_retriever() -> None:
    from llama_index.core.retrievers import BaseRetriever

    client = make_client(lambda request: httpx.Response(200, json=query_payload(0)))
    retriever = GroundworkLlamaIndexRetriever(client=client, user_id="alice")
    assert isinstance(retriever, BaseRetriever)


def test_engine_integration_filters_by_permissions() -> None:
    from llama_index.core.llms import MockLLM
    from llama_index.core.query_engine import RetrieverQueryEngine

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.read())
        n_citations = 2 if body["user_id"] == "alice" else 0
        return httpx.Response(200, json=query_payload(n_citations))

    alice_engine = RetrieverQueryEngine.from_args(
        retriever=GroundworkLlamaIndexRetriever(
            client=make_client(handler), user_id="alice"
        ),
        llm=MockLLM(),
        response_mode="refine",
    )
    alice_response = alice_engine.query("budget question")
    assert len(alice_response.source_nodes) == 2
    assert [s.node.id_ for s in alice_response.source_nodes] == [
        "chunk-0",
        "chunk-1",
    ]

    bob_engine = RetrieverQueryEngine.from_args(
        retriever=GroundworkLlamaIndexRetriever(
            client=make_client(handler), user_id="bob"
        ),
        llm=MockLLM(),
        response_mode="refine",
    )
    bob_response = bob_engine.query("budget question")
    # Bob has no permissions for these chunks: nothing is surfaced.
    assert bob_response.source_nodes == []