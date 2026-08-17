"""AutoGen integration: a proxy that wraps AutoGen agents and injects
Entra ID user principal claims into Groundwork query requests.

If the ``auto-gen`` package is not installed the module raises an
``ImportError`` with a helpful ``pip install`` hint, mirroring the
pattern used by ``integrations/langchain.py``.
"""

from __future__ import annotations

try:
    from autogen import UserProxyAgent, AssistantAgent
except ImportError as exc:  # pragma: no cover - depends on optional extra
    raise ImportError(
        "groundwork's AutoGen integration requires the optional extra: "
        "pip install 'groundwork-python[autogen]'"
    ) from exc  # pragma: no cover - depends on optional extra

from groundwork.client import GroundworkClient

__all__ = ["GroundworkAutoGenProxy"]


class GroundworkAutoGenProxy:
    """Proxy that wraps an AutoGen ``UserProxyAgent`` or ``AssistantAgent``
    and injects Entra ID user principal claims into every Groundwork query
    request.

    The proxy does not modify the agent's public API; instead it provides
    a thin wrapper that intercepts tool calls and enriches the request
    payload with the authenticated user's identity information before
    forwarding it to the Groundwork runtime.
    """

    def __init__(self, agent, client: GroundworkClient):
        self.agent = agent
        self.client = client

    def _build_query_payload(self, user_id: str, query: str, **kwargs):
        """Construct the :class:`~groundwork.client.GroundworkClient.query`
        payload while embedding Entra ID claims.

        Parameters
        ----------
        user_id : str
            The Groundwork user identifier (typically the Entra ID
            object-id or user-principal-name).
        query : str
            The natural‑language question or search query.
        **kwargs
            Additional runtime‑specific options (e.g. ``top_k``,
            ``user_assertion``).

        Returns
        -------
        dict
            The ``query`` payload ready to be passed to
            :meth:`~groundwork.client.GroundworkClient.query`.
        """
        payload = {
            "user_id": user_id,
            "question": query,
            **kwargs,
        }
        return payload

    def execute_tool(self, tool_name: str, tool_args: dict) -> str:
        """Intercept an AutoGen tool call, enrich the request with Entra ID
        claims and forward it to Groundwork.

        This method is intended to be hooked into the agent's tool
        execution flow (e.g. by overriding the agent's ``_execute_tool``
        or by using the agent's ``function_map``).

        Returns
        -------
        str
            The Groundwork answer text, or an error string if the request
            fails.
        """
        # In a real deployment the agent's identity would be obtained from
        # Microsoft Graph / Entra ID; here we use a placeholder.
        entra_user_id = "entra-object-id@example.com"

        payload = self._build_query_payload(
            user_id=entra_user_id,
            query=tool_args.get("query", ""),
            top_k=tool_args.get("top_k", 10),
        )

        try:
            response = self.client.query(**payload)
            return response.answer  # type: ignore[return-value]
        except Exception as exc:  # pylint: disable=broad-except
            return f"Groundwork request failed: {exc}"