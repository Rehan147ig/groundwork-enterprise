"""LlamaIndex integration: a ``BaseRetriever`` backed by Groundwork.

Every retrieved node has already passed the runtime's zero-trust checks
(identity, residency, required scopes) before it is handed to the agent,
so unpermitted citations are never surfaced to the downstream index. Each
node's metadata carries:

- ``doc_id``: the chunk id (``citation.id``) the agent can cite,
- ``score``: the retrieval score from the runtime,
- ``digest``: the chunk's audit-chain hash for provenance checks,

plus the remaining citation fields (``document_id``, ``page``, ``offset``,
``freshness_score``). The retrieval score is mirrored on the
:class:`~llama_index.core.schema.NodeWithScore` itself.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Union

try:
    from llama_index.core.retrievers import BaseRetriever
    from llama_index.core.schema import NodeWithScore, QueryBundle, TextNode
except ImportError as exc:  # pragma: no cover - depends on optional extra
    raise ImportError(
        "groundwork's LlamaIndex integration requires the optional extra: "
        "pip install 'groundwork-python[llamaindex]'"
    ) from exc  # pragma: no cover - depends on optional extra

from groundwork.client import GroundworkClient

__all__ = ["GroundworkLlamaIndexRetriever"]

UserId = Union[str, Callable[[], str]]


class GroundworkLlamaIndexRetriever(BaseRetriever):
    """Retrieve nodes through Groundwork on behalf of a user.

    ``user_id`` may be a static string or a callable resolving the
    current subject per invocation (e.g. from a request session), so a
    single retriever instance can serve many users.
    """

    client: GroundworkClient
    user_id: UserId
    user_token: Optional[str] = None
    top_k: int = 10

    def _retrieve(self, query_bundle: QueryBundle) -> List[NodeWithScore]:
        user_id = self.user_id() if callable(self.user_id) else self.user_id
        response = self.client.query(
            user_id=user_id,
            query=query_bundle.query_str,
            top_k=self.top_k,
            user_token=self.user_token,
        )
        return [
            NodeWithScore(
                node=TextNode(
                    id_=citation.id,
                    text=citation.text,
                    metadata={
                        "doc_id": citation.id,
                        "score": citation.score,
                        "digest": citation.digest,
                        "document_id": citation.document_id,
                        "page": citation.page,
                        "offset": citation.offset,
                        "freshness_score": citation.freshness_score,
                    },
                ),
                score=citation.score,
            )
            for citation in response.citations
        ]