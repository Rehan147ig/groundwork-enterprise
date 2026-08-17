"""Groundwork: zero-trust access control for AI agents."""

from groundwork.client import (
    FailClosedEngineError,
    FailClosedError,
    GroundworkClient,
    GroundworkError,
    GroundworkHTTPError,
    PermissionDeniedError,
)
from groundwork.types import (
    AuditChainProblem,
    AuditVerificationResponse,
    Citation,
    LeakFinding,
    LeakReportResponse,
    QueryResponse,
)

__version__ = "0.1.0"

__all__ = [
    "GroundworkClient",
    "GroundworkError",
    "GroundworkHTTPError",
    "PermissionDeniedError",
    "FailClosedEngineError",
    "FailClosedError",
    "QueryResponse",
    "Citation",
    "LeakReportResponse",
    "LeakFinding",
    "AuditVerificationResponse",
    "AuditChainProblem",
    "__version__",
]