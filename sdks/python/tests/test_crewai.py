"""Tests for the CrewAI integration (GroundworkCrewTool)."""

from groundwork import GroundworkClient
from groundwork.integrations.crewai import GroundworkCrewTool


def test_fails_closed_on_revoked_agent() -> None:
    """When the delegation token is invalid or revoked the tool must fail closed."""

    # Build a minimal GroundworkClient; the exact transport isn't important
    # because we will replace ``query`` with a stub that always raises.
    client = GroundworkClient(
        endpoint="http://runtime.test",
        apiKey="test_key",
    )

    tool = GroundworkCrewTool(client=client)

    # Replace ``query`` with a stub that simulates a revoked delegation token
    original_query = tool.client.query

    def failing_query(*_args, **_kwargs):
        raise Exception("token revoked")

    tool.client.query = failing_query

    result = tool._run(agent_id="alice", query="budget 2025")
    assert (
        result
        == "ACCESS_DENIED: Agent identity suspended by Groundwork."
    ), f"Expected ACCESS_DENIED string, got: {result!r}"


def test_successful_query_returns_answer() -> None:
    """When the runtime responds successfully the tool returns the answer."""

    # A client that returns a mock QueryResponse
    from groundwork import QueryResponse

    def returning_query(*_args, **_kwargs) -> QueryResponse:
        return QueryResponse(
            answer="found it",
            confidence=0.9,
            citations=[],
            trace={"trace_id": "t-1", "immutable_digest": "chain-1"},
        )

    client = GroundworkClient(
        endpoint="http://runtime.test",
        apiKey="test_key",
    )
    tool = GroundworkCrewTool(client=client)
    tool.client.query = returning_query

    result = tool._run(agent_id="alice", query="what is the budget?")
    assert result == "found it", f"Expected 'found it', got: {result!r}"