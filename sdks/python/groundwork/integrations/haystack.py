"""Haystack v2.0 integration: a ``@component`` that runs a permission‑filtered
search through Groundwork and returns ``Document`` objects.

Every document has already passed the runtime's zero‑trust checks
(identity, residency, required scopes) and carries its chunk hash in
``metadata["digest"]`` for provenance verification against the audit chain.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from haystack.dataclasses import Document

from groundwork.client import GroundworkClient

logger = logging.getLogger(__name__)


try:
    from haystack import component
except ImportError as exc:  # pragma: no cover - depends on optional extra
    raise ImportError(
        "groundwork's Haystack integration requires the optional extra: "
        "pip install 'groundwork-python[haystack]'"
    ) from exc  # pragma: no cover - depends on optional extra


__all__ = ["GroundworkSecurityNode"]


@component(
    output_types={"documents": List[Document], "denied_count": int}
)
class GroundworkSecurityNode:
    """A Haystack v2.0 component that executes a Groundwork‑filtered query
    and returns ``Document`` objects together with a count of denied requests.

    The component receives a free‑text ``query``, a ``user_id`` that identifies
    the requesting agent, and an optional ``top_k`` (default ``10``) that
    limits the number of retrieved chunks.

    The Groundwork client is injected at construction time; if the runtime
    returns a ``denied_count`` attribute it is forwarded, otherwise ``0`` is
    used.
    """

    def __init__(self, client: GroundworkClient) -> None:
        self.client = client

    def run(self, query: str, user_id: str, top_k: int = 10) -> Dict[str, Any]:
        """Run a Groundwork‑filtered query and return Haystack ``Document``s.

        Parameters
        ----------
        query : str
            The free‑text question or search query.
        user_id : str
            The identity of the requesting user / agent.
        top_k : int, default ``10``
            Maximum number of citation chunks to return.

        Returns
        -------
        dict[str, Any]
            A dictionary with two keys:

            - ``documents``: a list of ``haystack.dataclasses.Document``\ s
              containing the retrieved chunk text and metadata.
            - ``denied_count``: an ``int`` counting how many requests were
              denied (typically zero when the caller has a valid token).
        """
        try:
            result = self.client.query(
                user_id=user_id,
                query=query,
                top_k=top_k,
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Groundwork query failed: %s", exc)
            return {"documents": [], "denied_count": 0}

        # Map the runtime citations to Haystack Document objects.
        docs: List[Document] = []
        for citation in getattr(result, "citations", []):
            metadata: Dict[str, Any] = {
                "doc_id": getattr(citation, "id", ""),
                "score": getattr(citation, "score", 0.0),
                "digest": getattr(citation, "digest", ""),
                "document_id": getattr(citation, "document_id", ""),
                "page": getattr(citation, "page", None),
                "offset": getattr(citation, "offset", None),
                "freshness_score": getattr(citation, "freshness_score", None),
                "watermark": getattr(citation, "watermark", None),
            }
            doc = Document(
                content=getattr(citation, "text", ""),
                id=getattr(citation, "chunk_id", ""),
                meta=metadata,
            )
            docs.append(doc)

        # The runtime may expose a ``denied_count``; fall back to 0.
        denied_count: int = getattr(result, "denied_count", 0)

        return {"documents": docs, "denied_count": denied_count}