"""LangChain integration: a ``BaseRetriever`` backed by Groundwork.

Every retrieved document has already passed the runtime's zero-trust
checks (identity, residency, required scopes) and carries its chunk hash
in ``metadata["digest"]`` for provenance verification against the audit
chain.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Union

try:
    from langchain_core.documents import Document
    from langchain_core.retrievers import BaseRetriever
except ImportError as exc:  # pragma: no cover - depends on optional extra
    raise ImportError(
        "groundwork's LangChain integration requires the optional extra: "
        "pip install 'groundwork-python[langchain]'"
    ) from exc  # pragma: no cover - depends on optional extra

from groundwork.client import GroundworkClient

__all__ = ["GroundworkRetriever"]

UserId = Union[str, Callable[[], str]]


class GroundworkRetriever(BaseRetriever):
    """Retrieve documents through Groundwork on behalf of a user.

    ``user_id`` may be a static string or a callable resolving the
    current subject per invocation (e.g. from a request session), so a
    single retriever instance can serve many users.

    Each result is a LangChain :class:`Document` whose ``page_content``
    is the chunk text and whose metadata carries:

    - ``doc_id``: the chunk id (``citation.id``) the agent can cite,
    - ``score``: the retrieval score from the runtime,
    - ``digest``: the chunk's audit-chain hash for provenance checks.
    """

    client: GroundworkClient
    user_id: UserId
    user_token: Optional[str] = None
    top_k: int = 10

    def _get_relevant_documents(
        self, query: str, *, run_manager: Optional[object] = None
    ) -> List[Document]:
        user_id = self.user_id() if callable(self.user_id) else self.user_id
        response = self.client.query(
            user_id=user_id,
            query=query,
            top_k=self.top_k,
            user_token=self.user_token,
        )
        return [
            Document(
                page_content=citation.text,
                metadata={
                    "doc_id": citation.id,
                    "score": citation.score,
                    "digest": citation.digest,
                },
            )
            for citation in response.citations
        ]