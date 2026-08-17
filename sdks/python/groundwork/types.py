"""Typed response models for the Groundwork query runtime.

Every document returned by the runtime has already passed its zero-trust
access-control checks (identity, residency, required scopes) and every
request is appended to an immutable, hash-chained audit log (SHA-256
chain, each entry bound to its predecessor).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

__all__ = [
    "Citation",
    "QueryResponse",
    "LeakFinding",
    "LeakReportResponse",
    "AuditChainProblem",
    "AuditVerificationResponse",
]


@dataclass
class Citation:
    """A single chunk Groundwork selected for the answer."""

    document_id: str
    chunk_id: str
    chunk_hash: str
    page: int
    offset: int
    text: str
    score: float
    freshness_score: float
    watermark: Optional[str] = None

    @property
    def id(self) -> str:
        """Alias for ``chunk_id``; the identifier an agent cites."""
        return self.chunk_id

    @property
    def digest(self) -> str:
        """Alias for ``chunk_hash``; the audit-chain binding for the chunk."""
        return self.chunk_hash

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Citation":
        return cls(
            document_id=data["document_id"],
            chunk_id=data["chunk_id"],
            chunk_hash=data["chunk_hash"],
            page=data.get("page", 0),
            offset=data.get("offset", 0),
            text=data.get("text", ""),
            score=data.get("score", 0.0),
            freshness_score=data.get("freshness_score", 0.0),
            watermark=data.get("watermark"),
        )


@dataclass
class QueryResponse:
    """Deserialized response from ``POST /v1/query``."""

    answer: str
    confidence: float
    citations: List[Citation] = field(default_factory=list)
    trace_id: Optional[str] = None
    immutable_digest: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QueryResponse":
        trace = data.get("trace") or {}
        return cls(
            answer=data.get("answer", ""),
            confidence=data.get("confidence", 0.0),
            citations=[Citation.from_dict(c) for c in data.get("citations", [])],
            trace_id=trace.get("trace_id"),
            immutable_digest=trace.get("immutable_digest"),
        )


@dataclass
class LeakFinding:
    """A single leak-report finding surfaced by the runtime."""

    kind: str
    severity: str
    title: str
    detail: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LeakFinding":
        return cls(
            kind=data.get("kind", ""),
            severity=data.get("severity", ""),
            title=data.get("title", ""),
            detail=data.get("detail", ""),
        )


@dataclass
class LeakReportResponse:
    """Deserialized response from ``GET /v1/leak-report``."""

    findings: List[LeakFinding] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LeakReportResponse":
        return cls(
            findings=[LeakFinding.from_dict(f) for f in data.get("findings", [])]
        )


@dataclass
class AuditChainProblem:
    """A single hash-chain violation reported by ``/v1/audit/verify``."""

    index: int
    trace_id: str
    kind: str
    detail: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditChainProblem":
        return cls(
            index=data.get("index", 0),
            trace_id=data.get("trace_id", ""),
            kind=data.get("kind", ""),
            detail=data.get("detail", ""),
        )


@dataclass
class AuditVerificationResponse:
    """Deserialized response from ``GET /v1/audit/verify``."""

    verified: bool
    entries_checked: int
    problems: List[AuditChainProblem] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditVerificationResponse":
        return cls(
            verified=data.get("verified", False),
            entries_checked=data.get("entries_checked", 0),
            problems=[
                AuditChainProblem.from_dict(p) for p in data.get("problems", [])
            ],
        )