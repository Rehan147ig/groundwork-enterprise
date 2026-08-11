from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class SpiceDBAuthorizer:
    """SpiceDB client for the ingestion service.

    Scope intentionally narrow: this client writes relationships (group
    memberships, per-document grants) through SpiceDB's HTTP gateway
    (POST /v1/relationships/write). It does NOT write the schema —
    ``services/query-runtime`` is the sole owner of the SpiceDB schema (its
    deep readiness provisions and drift-checks it on boot).

    Every object and subject ID is tenant-scoped the same way the query-runtime
    adapter scopes them on the wire: ``escape(tenant) + ":" + escape(id)`` with
    ``~3A``/``~7E`` escaping, so the first literal colon is always the tenant
    boundary. Writes that land unscoped would be invisible to the runtime's
    tenant-scoped checks.

    The gateway (``SPICEDB_HTTP_ADDR``) must be enabled on the SpiceDB server;
    the compose files and the all-in-one entrypoint already set it.
    """

    endpoint: str
    token: str = ""
    timeout: float = 2.0
    demo_tenant_id: str = "acme-financial"

    def __post_init__(self) -> None:
        self.endpoint = self.endpoint.rstrip("/")
        self.ready = False

    def ensure(self) -> None:
        if self.ready:
            return
        # Default demo memberships. These are also written by the connector sync
        # and the seed tool for the demo tenant, so the runtime guarantees they
        # exist even if this write is skipped because the schema has not been
        # provisioned yet at bootstrap.
        self._write_relationships(
            self.demo_tenant_id,
            [
                {"subject_type": "user", "subject_id": "finance_user", "relation": "member", "object_type": "group", "object_id": "finance"},
                {"subject_type": "user", "subject_id": "executive_user", "relation": "member", "object_type": "group", "object_id": "executive"},
                {"subject_type": "user", "subject_id": "security_user", "relation": "member", "object_type": "group", "object_id": "security"},
            ],
        )
        self.ready = True

    def grant_document(self, tenant_id: str, document_id: str, owner_acl_tags: list[str]) -> None:
        self.ensure()
        self._write_relationships(
            tenant_id,
            [
                {
                    "subject_type": "group",
                    "subject_id": normalize_relation_part(tag),
                    "subject_relation": "member",
                    "relation": "viewer",
                    "object_type": "document",
                    "object_id": document_id,
                }
                for tag in owner_acl_tags
                if tag.strip()
            ],
        )

    def _write_relationships(self, tenant_id: str, tuples: list[dict[str, str]]) -> None:
        if not tuples:
            return
        updates = []
        for t in tuples:
            subject: dict[str, Any] = {
                "object": {"object_type": t["subject_type"], "object_id": scope_id(tenant_id, t["subject_id"])}
            }
            if t.get("subject_relation"):
                subject["optional_relation"] = t["subject_relation"]
            updates.append(
                {
                    "operation": "OPERATION_CREATE",
                    "relationship": {
                        "resource": {
                            "object_type": t["object_type"],
                            "object_id": scope_id(tenant_id, t["object_id"]),
                            "relation": t["relation"],
                        },
                        "subject": subject,
                    },
                }
            )
        try:
            self._post("/v1/relationships/write", {"updates": updates})
        except requests.HTTPError as exc:
            text = (exc.response.text if exc.response is not None else "").lower()
            code = exc.response.status_code if exc.response is not None else 0
            # Tolerated:
            #   - 409 ALREADY_EXISTS -> idempotent re-write.
            #   - 400/404 "object definition not found" / "unknown relation" ->
            #     query-runtime has not yet provisioned its schema. These are
            #     best-effort defaults that the sync/seed path also writes;
            #     skip and continue.
            tolerated = (
                code == 409
                or "already exists" in text
                or "already" in text
                or "object definition not found" in text
                or "unknown relation" in text
            )
            if tolerated:
                return
            raise

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        response = requests.post(f"{self.endpoint}{path}", json=payload, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        if not response.content:
            return {}
        return response.json()


def scope_id(tenant_id: str, raw: str) -> str:
    """Mirrors the query-runtime adapter's scopeID: escape(tenant) + ":" + escape(id)."""
    if not tenant_id:
        return escape(raw)
    return f"{escape(tenant_id)}:{escape(raw)}"


def escape(value: str) -> str:
    """Mirrors relationship.EscapeID: escape "~" and ":" so no colon remains."""
    if "~" not in value and ":" not in value:
        return value
    return "".join("~3A" if ch == ":" else "~7E" if ch == "~" else ch for ch in value)


def normalize_relation_part(value: str) -> str:
    return value.strip().lower().replace(" ", "_")
