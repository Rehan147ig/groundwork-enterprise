"""HTTP client for the Groundwork query runtime.

The runtime enforces zero-trust access control at the request boundary:
every document returned to an agent has already been checked against the
subject's identity, residency, and required scopes, and every request is
appended to an immutable, hash-chained audit log (SHA-256 chain, each
entry bound to its predecessor).
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from typing import Any, Dict, Optional, Union

import httpx

from groundwork.types import (
    AuditVerificationResponse,
    LeakReportResponse,
    QueryResponse,
)

__all__ = [
    "GroundworkClient",
    "GroundworkError",
    "GroundworkHTTPError",
    "PermissionDeniedError",
    "FailClosedEngineError",
    "FailClosedError",
]

_USER_AGENT = "groundwork-python/0.1.0"
_API_KEY_HEADER = "X-Groundwork-API-Key"
_ASSERTION_HEADER = "X-Groundwork-User-Assertion"

# Transient statuses that warrant a retry with backoff. 5xx business
# failures (notably 500) are FAIL-CLOSED and never retried.
_RETRYABLE_STATUS = frozenset({429, 502, 503, 504})


class GroundworkError(Exception):
    """Base error for all Groundwork SDK failures."""


class GroundworkHTTPError(GroundworkError):
    """The runtime returned a non-2xx, non-special status."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"{status_code}: {detail}")


class PermissionDeniedError(GroundworkHTTPError):
    """The identity was recognized but access was denied (403)."""


class FailClosedEngineError(GroundworkHTTPError):
    """The runtime could not safely answer and failed closed (500)."""


# Backwards-compatible alias for the official error name.
FailClosedError = FailClosedEngineError


class GroundworkClient:
    """Typed client for the Groundwork query runtime.

    Sync and async request paths are provided via httpx. Transient
    failures (429/502/503/504 and transport errors) are retried with
    exponential backoff plus random jitter. 403 and 500 responses are
    surfaced as :class:`PermissionDeniedError` and
    :class:`FailClosedEngineError` respectively and are never retried.
    """

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        timeout_seconds: float = 10.0,
        *,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._backoff_factor = backoff_factor
        self._transport = transport
        self._client: Optional[httpx.Client] = None
        self._async_client: Optional[httpx.AsyncClient] = None

    def _build_client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.endpoint,
            timeout=httpx.Timeout(self._timeout_seconds),
            transport=self._transport,
            headers={
                _API_KEY_HEADER: self.api_key,
                "User-Agent": _USER_AGENT,
            },
        )

    def _build_async_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.endpoint,
            timeout=httpx.Timeout(self._timeout_seconds),
            transport=self._transport,
            headers={
                _API_KEY_HEADER: self.api_key,
                "User-Agent": _USER_AGENT,
            },
        )

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    @property
    def async_client(self) -> httpx.AsyncClient:
        if self._async_client is None:
            self._async_client = self._build_async_client()
        return self._async_client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    async def aclose(self) -> None:
        if self._async_client is not None:
            await self._async_client.aclose()
            self._async_client = None

    def __enter__(self) -> "GroundworkClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    async def __aenter__(self) -> "GroundworkClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    def _sleep(self, attempt: int) -> None:
        # Exponential backoff with full jitter:
        # delay in [0, backoff_factor * 2**attempt).
        time.sleep(self._backoff_factor * (2 ** attempt) * random.random())

    async def _asleep(self, attempt: int) -> None:
        await asyncio.sleep(
            self._backoff_factor * (2 ** attempt) * random.random()
        )

    def _build_headers(self, assertion: Optional[str]) -> Optional[Dict[str, str]]:
        return {_ASSERTION_HEADER: assertion} if assertion else None

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        assertion: Optional[str] = None,
    ) -> Dict[str, Any]:
        headers = self._build_headers(assertion)
        for attempt in range(self._max_retries + 1):
            try:
                resp = self.client.request(
                    method, path, headers=headers, json=json_body
                )
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                if attempt >= self._max_retries:
                    raise GroundworkError(
                        f"request to {method} {path} failed: {exc}"
                    ) from exc
                self._sleep(attempt)
                continue
            if resp.status_code in _RETRYABLE_STATUS and attempt < self._max_retries:
                self._sleep(attempt)
                continue
            return self._decode(resp)

    async def _arequest(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        assertion: Optional[str] = None,
    ) -> Dict[str, Any]:
        headers = self._build_headers(assertion)
        for attempt in range(self._max_retries + 1):
            try:
                resp = await self.async_client.request(
                    method, path, headers=headers, json=json_body
                )
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                if attempt >= self._max_retries:
                    raise GroundworkError(
                        f"request to {method} {path} failed: {exc}"
                    ) from exc
                await self._asleep(attempt)
                continue
            if resp.status_code in _RETRYABLE_STATUS and attempt < self._max_retries:
                await self._asleep(attempt)
                continue
            return self._decode(resp)

    @staticmethod
    def _decode(resp: httpx.Response) -> Dict[str, Any]:
        try:
            payload: Any = resp.json()
        except (json.JSONDecodeError, ValueError):
            payload = {"error": resp.text[:200] or resp.reason_phrase}
        detail = (
            payload.get("error")
            if isinstance(payload, dict)
            else str(payload)[:200]
        ) or "unknown error"
        if resp.status_code == 403:
            raise PermissionDeniedError(resp.status_code, str(detail))
        if resp.status_code >= 500:
            raise FailClosedEngineError(resp.status_code, str(detail))
        if resp.status_code >= 400:
            raise GroundworkHTTPError(resp.status_code, str(detail))
        if not isinstance(payload, dict):
            raise GroundworkError(f"unexpected response body: {payload!r}")
        return payload

    def query(
        self,
        user_id: str,
        query: str,
        top_k: int = 10,
        user_token: Optional[str] = None,
    ) -> QueryResponse:
        """Ask the runtime a question on behalf of ``user_id``.

        ``user_token`` is an (optional) signed User Assertion (JWT)
        proving the subject to the runtime. Without it the runtime must
        be in demo identity mode for plain ``user_id`` to be accepted.

        ``top_k`` limits the number of citations returned; the runtime
        returns all candidates and the SDK slices the list.
        """
        payload = self._request(
            "POST",
            "/v1/query",
            json_body={"user_id": user_id, "question": query},
            assertion=user_token,
        )
        response = QueryResponse.from_dict(payload)
        response.citations = response.citations[:max(top_k, 0)]
        return response

    async def aquery(
        self,
        user_id: str,
        query: str,
        top_k: int = 10,
        user_token: Optional[str] = None,
    ) -> QueryResponse:
        """Async variant of :meth:`query`."""
        payload = await self._arequest(
            "POST",
            "/v1/query",
            json_body={"user_id": user_id, "question": query},
            assertion=user_token,
        )
        response = QueryResponse.from_dict(payload)
        response.citations = response.citations[:max(top_k, 0)]
        return response

    def leak_report(self) -> LeakReportResponse:
        """Fetch the tenant's unapproved-leak report (requires audit scope)."""
        return LeakReportResponse.from_dict(
            self._request("GET", "/v1/leak-report")
        )

    async def aleak_report(self) -> LeakReportResponse:
        """Async variant of :meth:`leak_report`."""
        return LeakReportResponse.from_dict(
            await self._arequest("GET", "/v1/leak-report")
        )

    def verify_audit(self) -> AuditVerificationResponse:
        """Verify the tenant's immutable audit hash chain."""
        return AuditVerificationResponse.from_dict(
            self._request("GET", "/v1/audit/verify")
        )

    async def averify_audit(self) -> AuditVerificationResponse:
        """Async variant of :meth:`verify_audit`."""
        return AuditVerificationResponse.from_dict(
            await self._arequest("GET", "/v1/audit/verify")
        )