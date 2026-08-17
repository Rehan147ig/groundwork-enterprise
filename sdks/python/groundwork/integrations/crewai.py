"""CrewAI integration: a ``BaseTool`` backed by Groundwork.

Every tool execution has already passed the runtime's zero-trust checks
(identity, residency, required scopes) and carries its delegation token
for agency verification.
"""

from typing import Optional

try:
    from crewai import BaseTool
except ImportError as exc:  # pragma: no cover - depends on optional extra
    raise ImportError(
        "groundwork's CrewAI integration requires the optional extra: "
        "pip install 'groundwork-python[crewai]'"
    ) from exc  # pragma: no cover - depends on optional extra

from groundwork.client import GroundworkClient

__all__ = ["GroundworkCrewTool"]


class GroundworkCrewTool(BaseTool):
    """CrewAI tool that executes a permission-filtered search query under a
    specific Agent Identity and delegation token.

    The tool automatically attaches ``X-Groundwork-Delegation-Token`` and
    ``X-Groundwork-Agent-ID`` headers to the outgoing query request.
    If an agent's delegation token is invalid or revoked, the tool returns
    the execution error string ``"ACCESS_DENIED: Agent identity suspended
    by Groundwork."``.
    """

    name = "groundwork_governed_search"
    description = (
        "Executes a permission-filtered search query under a specific "
        "Agent Identity and delegation token."
    )

    def __init__(self, client: GroundworkClient, **kwargs):
        super().__init__(**kwargs)
        self.client = client

    def _run(self, agent_id: str, query: str, delegation_token: Optional[str] = None) -> str:
        try:
            response = self.client.query(
                user_id=agent_id,
                question=query,
                delegation_token=delegation_token,
            )
            return response.answer  # type: ignore[return-value]
        except Exception:  # pylint: disable=broad-except
            return "ACCESS_DENIED: Agent identity suspended by Groundwork."