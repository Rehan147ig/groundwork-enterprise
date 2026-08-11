"""Zero-dependency Groundwork API client (stdlib urllib).

Mirrors the TypeScript ``GroundworkClient`` surface method-for-method:
same paths, same headers (``X-Groundwork-API-Key``,
``X-Groundwork-User-Assertion``, ``Idempotency-Key``), same envelope
handling, same error semantics. Pass a custom ``transport`` to stub
requests in tests.
"""

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Awaitable, Callable, Dict, Optional

from .errors import GroundworkError, parse_error_response

AssertionProvider = Callable[[], "str | Awaitable[str]"]
Transport = Callable[
    [str, str, Dict[str, str], Optional[bytes]],
    "tuple[int, Dict[str, str], bytes]",
]


def _default_transport(method, url, headers, body, timeout):
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
            return resp.status, dict(resp.headers.items()), payload
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        return exc.code, dict(exc.headers.items()), payload


class GroundworkClient:
    """Typed client for the Groundwork query runtime API."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        assertion: Optional["str | AssertionProvider"] = None,
        timeout_ms: int = 30_000,
        transport: Optional[Transport] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.assertion = assertion
        self.timeout_ms = timeout_ms
        self._transport = transport if transport is not None else _default_transport

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _resolve_assertion(self):
        if self.assertion is None:
            return None
        assertion = self.assertion
        if callable(assertion):
            assertion = assertion()
            if hasattr(assertion, "__await__"):
                import asyncio

                assertion = asyncio.get_event_loop().run_until_complete(assertion)
        return assertion

    def request(
        self,
        method: str,
        path: str,
        query: Optional[Dict[str, Any]] = None,
        body: Optional[dict] = None,
        idempotency_key: Optional[str] = None,
    ) -> Any:
        url = self.base_url + path
        if query:
            params = {
                key: value
                for key, value in query.items()
                if value is not None
            }
            if params:
                url = url + "?" + urllib.parse.urlencode(params)

        headers = {"X-Groundwork-API-Key": self.api_key}
        assertion = self._resolve_assertion()
        if assertion:
            headers["X-Groundwork-User-Assertion"] = assertion
        payload = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(body).encode("utf-8")
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        try:
            status, resp_headers, resp_body = self._transport(
                method, url, headers, payload, self.timeout_ms
            )
        except TimeoutError:
            raise GroundworkError(
                "Groundwork API request timed out after %dms" % self.timeout_ms,
                0,
                "timeout",
            ) from None
        except Exception as exc:  # network-level failures
            raise GroundworkError(
                "Groundwork API request failed: %s" % exc, 0, "network"
            ) from None

        if status >= 400:
            raise parse_error_response(status, resp_headers, resp_body)
        if status == 204 or not resp_body:
            return None
        try:
            return json.loads(resp_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return resp_body.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # health / query / audit / admin
    # ------------------------------------------------------------------

    def health(self):
        return self.request("GET", "/healthz")

    def query(self, body: dict):
        return self.request("POST", "/v1/query", body=body)

    def audit(self, filters: Optional[dict] = None):
        filters = filters or {}
        return self.request(
            "GET",
            "/v1/audit",
            query={
                "trace_id": filters.get("trace_id"),
                "tenant_id": filters.get("tenant_id"),
                "agent_id": filters.get("agent_id"),
                "decision": filters.get("decision"),
                "reason": filters.get("reason"),
                "from": filters.get("from_") or filters.get("from"),
                "to": filters.get("to"),
                "limit": filters.get("limit"),
                "cursor": filters.get("cursor"),
            },
        )

    def list_api_keys(self):
        return self.request("GET", "/v1/admin/api-keys")

    def create_api_key(self, body: dict):
        return self.request("POST", "/v1/admin/api-keys", body=body)

    def revoke_api_key(self, key_id: str):
        return self.request(
            "POST", "/v1/admin/api-keys/%s/revoke" % urllib.parse.quote(key_id, safe="")
        )

    # ------------------------------------------------------------------
    # agents
    # ------------------------------------------------------------------

    def list_agents(self, state: Optional[str] = None, environment: Optional[str] = None):
        return self.request(
            "GET", "/v1/agents", query={"state": state, "environment": environment}
        )

    def create_agent(self, body: dict):
        return self.request("POST", "/v1/agents", body=body)

    def get_agent(self, agent_id: str):
        return self.request("GET", "/v1/agents/%s" % urllib.parse.quote(agent_id, safe=""))

    def update_agent(self, agent_id: str, body: dict):
        return self.request(
            "PATCH", "/v1/agents/%s" % urllib.parse.quote(agent_id, safe=""), body=body
        )

    def _agent_transition(self, agent_id: str, transition: str, reason: str):
        return self.request(
            "POST",
            "/v1/agents/%s/%s" % (urllib.parse.quote(agent_id, safe=""), transition),
            body={"reason": reason},
        )

    def activate_agent(self, agent_id: str, reason: str):
        return self._agent_transition(agent_id, "activate", reason)

    def suspend_agent(self, agent_id: str, reason: str):
        return self._agent_transition(agent_id, "suspend", reason)

    def revoke_agent(self, agent_id: str, reason: str):
        return self._agent_transition(agent_id, "revoke", reason)

    def retire_agent(self, agent_id: str, reason: str):
        return self._agent_transition(agent_id, "retire", reason)

    def add_agent_version(self, agent_id: str, body: dict):
        return self.request(
            "POST",
            "/v1/agents/%s/versions" % urllib.parse.quote(agent_id, safe=""),
            body=body,
        )

    # ------------------------------------------------------------------
    # governance: tools
    # ------------------------------------------------------------------

    def list_tools(self):
        return self.request("GET", "/v1/governance/tools")

    def register_tool(self, body: dict):
        return self.request("POST", "/v1/governance/tools", body=body)

    def get_tool(self, tool_id: str):
        return self.request(
            "GET", "/v1/governance/tools/%s" % urllib.parse.quote(tool_id, safe="")
        )

    def register_tool_action(self, tool_id: str, body: dict):
        return self.request(
            "POST",
            "/v1/governance/tools/%s/actions" % urllib.parse.quote(tool_id, safe=""),
            body=body,
        )

    def list_tool_actions(self, tool_id: str):
        return self.request(
            "GET", "/v1/governance/tools/%s/actions" % urllib.parse.quote(tool_id, safe="")
        )

    def tool_lifecycle(self, tool_id: str, body: dict):
        return self.request(
            "POST",
            "/v1/governance/tools/%s/lifecycle" % urllib.parse.quote(tool_id, safe=""),
            body=body,
        )

    def kill_switch_tool(self, tool_id: str, reason: str, scope: Optional[str] = None):
        return self._control_mutation(
            "/v1/governance/tools/%s/kill-switch" % urllib.parse.quote(tool_id, safe=""),
            reason,
            scope,
        )

    def resume_tool(self, tool_id: str, reason: str, scope: Optional[str] = None):
        return self._control_mutation(
            "/v1/governance/tools/%s/resume" % urllib.parse.quote(tool_id, safe=""),
            reason,
            scope,
        )

    # ------------------------------------------------------------------
    # governance: grants
    # ------------------------------------------------------------------

    def grant_tool(self, body: dict):
        return self.request("POST", "/v1/governance/grants", body=body)

    def list_agent_grants(self, agent_id: str):
        return self.request(
            "GET",
            "/v1/governance/agents/%s/grants" % urllib.parse.quote(agent_id, safe=""),
        )

    def revoke_grant(self, grant_id: str, reason: str):
        return self.request(
            "POST",
            "/v1/governance/grants/%s/revoke" % urllib.parse.quote(grant_id, safe=""),
            body={"reason": reason},
        )

    # ------------------------------------------------------------------
    # governance: delegations
    # ------------------------------------------------------------------

    def mint_delegation(self, body: dict, idempotency_key: str):
        return self.request(
            "POST", "/v1/governance/delegations", body=body, idempotency_key=idempotency_key
        )

    def list_delegation_grants(self):
        return self.request("GET", "/v1/governance/delegations")

    def get_delegation_chain(self, grant_id: str):
        return self.request(
            "GET",
            "/v1/governance/delegations/%s/chain" % urllib.parse.quote(grant_id, safe=""),
        )

    def revoke_delegation(self, grant_id: str, reason: str, scope: Optional[str] = None):
        return self._control_mutation(
            "/v1/governance/delegations/%s/chain/revoke" % urllib.parse.quote(grant_id, safe=""),
            reason,
            scope,
        )

    def suspend_delegation_chain(self, grant_id: str, reason: str, scope: Optional[str] = None):
        return self._control_mutation(
            "/v1/governance/delegations/%s/chain/suspend" % urllib.parse.quote(grant_id, safe=""),
            reason,
            scope,
        )

    def resume_delegation_chain(self, grant_id: str, reason: str, scope: Optional[str] = None):
        return self._control_mutation(
            "/v1/governance/delegations/%s/chain/resume" % urllib.parse.quote(grant_id, safe=""),
            reason,
            scope,
        )

    def get_run_delegation_chain(self, run_id: str):
        return self.request(
            "GET",
            "/v1/governance/runs/%s/delegation-chain" % urllib.parse.quote(run_id, safe=""),
        )

    # ------------------------------------------------------------------
    # governance: runs
    # ------------------------------------------------------------------

    def create_run(self, body: dict, idempotency_key: Optional[str] = None):
        return self.request(
            "POST", "/v1/governance/runs", body=body, idempotency_key=idempotency_key
        )

    def list_runs(self, query: Optional[dict] = None):
        query = query or {}
        return self.request(
            "GET",
            "/v1/governance/runs",
            query={
                "agent_id": query.get("agent_id"),
                "status": query.get("status"),
                "cursor": query.get("cursor"),
                "limit": query.get("limit"),
            },
        )

    def get_run(self, run_id: str):
        return self.request(
            "GET", "/v1/governance/runs/%s" % urllib.parse.quote(run_id, safe="")
        )

    def evaluate_action(self, body: dict):
        return self.request(
            "POST",
            "/v1/governance/runs/%s/evaluate" % urllib.parse.quote(body["run_id"], safe=""),
            body=body,
        )

    def simulate_action(self, body: dict):
        return self.request("POST", "/v1/governance/simulate", body=body)

    def approve_action(self, run_id: str, action_id: str, resource_ref: str):
        return self.request(
            "POST",
            "/v1/governance/runs/%s/approve/%s"
            % (urllib.parse.quote(run_id, safe=""), urllib.parse.quote(action_id, safe="")),
            body={"resource_ref": resource_ref},
        )

    def deny_action(self, run_id: str, action_id: str, resource_ref: str):
        return self.request(
            "POST",
            "/v1/governance/runs/%s/deny/%s"
            % (urllib.parse.quote(run_id, safe=""), urllib.parse.quote(action_id, safe="")),
            body={"resource_ref": resource_ref},
        )

    def dispatch(self, body: dict):
        return self.request("POST", "/v1/governance/dispatch", body=body)

    def terminate_run(self, run_id: str, reason: str, scope: Optional[str] = None):
        return self._control_mutation(
            "/v1/governance/runs/%s/terminate" % urllib.parse.quote(run_id, safe=""),
            reason,
            scope,
        )

    def kill_switch_agent(self, agent_id: str, reason: str, scope: Optional[str] = None):
        return self._control_mutation(
            "/v1/governance/agents/%s/kill-switch" % urllib.parse.quote(agent_id, safe=""),
            reason,
            scope,
        )

    def resume_agent(self, agent_id: str, reason: str, scope: Optional[str] = None):
        return self._control_mutation(
            "/v1/governance/agents/%s/resume" % urllib.parse.quote(agent_id, safe=""),
            reason,
            scope,
        )

    def kill_switch_agent_version(self, version_id: str, reason: str, scope: Optional[str] = None):
        return self._control_mutation(
            "/v1/governance/agent-versions/%s/kill-switch" % urllib.parse.quote(version_id, safe=""),
            reason,
            scope,
        )

    def resume_agent_version(self, version_id: str, reason: str, scope: Optional[str] = None):
        return self._control_mutation(
            "/v1/governance/agent-versions/%s/resume" % urllib.parse.quote(version_id, safe=""),
            reason,
            scope,
        )

    def list_emergency_controls(self):
        return self.request("GET", "/v1/governance/emergency-controls")

    def _control_mutation(self, path: str, reason: str, scope: Optional[str] = None):
        body = {"reason": reason}
        if scope:
            body["scope"] = scope
        return self.request("POST", path, body=body)

    # ------------------------------------------------------------------
    # governance: budgets
    # ------------------------------------------------------------------

    def upsert_budget(self, body: dict):
        return self.request("POST", "/v1/governance/budgets", body=body)

    def get_effective_budget(self):
        return self.request("GET", "/v1/governance/budgets/effective")

    def list_budgets(self):
        return self.request("GET", "/v1/governance/budgets")

    # ------------------------------------------------------------------
    # governance: evidence
    # ------------------------------------------------------------------

    def query_evidence(self, query: Optional[dict] = None):
        query = query or {}
        return self.request(
            "GET",
            "/v1/governance/evidence",
            query={
                "tenant_id": query.get("tenant_id"),
                "kind": query.get("kind"),
                "entity_id": query.get("entity_id"),
                "from": query.get("from"),
                "to": query.get("to"),
                "cursor": query.get("cursor"),
                "limit": query.get("limit"),
            },
        )

    def get_evidence_event(self, event_id: str):
        return self.request(
            "GET", "/v1/governance/evidence/%s" % urllib.parse.quote(event_id, safe="")
        )

    def get_evidence_provenance(self, event_id: str):
        return self.request(
            "GET",
            "/v1/governance/evidence/%s/provenance" % urllib.parse.quote(event_id, safe=""),
        )

    def get_run_timeline(self, run_id: str):
        return self.request(
            "GET",
            "/v1/governance/runs/%s/timeline" % urllib.parse.quote(run_id, safe=""),
        )

    def get_agent_activity(self, agent_id: str):
        return self.request(
            "GET",
            "/v1/governance/agents/%s/activity" % urllib.parse.quote(agent_id, safe=""),
        )

    def verify_audit_chain(self):
        return self.request("GET", "/v1/governance/audit/verify")

    def list_checkpoints(self):
        return self.request("GET", "/v1/governance/audit/checkpoints")

    # ------------------------------------------------------------------
    # governance: outbox
    # ------------------------------------------------------------------

    def list_outbox(self, query: Optional[dict] = None):
        query = query or {}
        return self.request(
            "GET",
            "/v1/governance/outbox",
            query={
                "status": query.get("status"),
                "cursor": query.get("cursor"),
                "limit": query.get("limit"),
            },
        )

    def retry_outbox_event(self, event_id: str):
        return self.request(
            "POST", "/v1/governance/outbox/%s/retry" % urllib.parse.quote(event_id, safe="")
        )

    def get_export(self, framework: str):
        return self.request(
            "GET", "/v1/governance/exports/%s" % urllib.parse.quote(framework, safe="")
        )

    # ------------------------------------------------------------------
    # governance: connectors
    # ------------------------------------------------------------------

    def list_connectors(self):
        return self.request("GET", "/v1/governance/connectors")

    def register_connector(self, body: dict):
        return self.request("POST", "/v1/governance/connectors", body=body)

    def get_connector(self, connector_id: str):
        return self.request(
            "GET", "/v1/governance/connectors/%s" % urllib.parse.quote(connector_id, safe="")
        )

    def get_connector_manifest(self, connector_id: str):
        return self.request(
            "GET",
            "/v1/governance/connectors/%s/manifest" % urllib.parse.quote(connector_id, safe=""),
        )

    def _connector_transition(self, connector_id: str, transition: str, reason: str):
        return self.request(
            "POST",
            "/v1/governance/connectors/%s/%s"
            % (urllib.parse.quote(connector_id, safe=""), transition),
            body={"reason": reason},
        )

    def activate_connector(self, connector_id: str, reason: str):
        return self._connector_transition(connector_id, "activate", reason)

    def suspend_connector(self, connector_id: str, reason: str):
        return self._connector_transition(connector_id, "suspend", reason)

    def revoke_connector(self, connector_id: str, reason: str):
        return self._connector_transition(connector_id, "revoke", reason)

    def update_connector_config(self, connector_id: str, body: dict):
        return self.request(
            "POST",
            "/v1/governance/connectors/%s/config" % urllib.parse.quote(connector_id, safe=""),
            body=body,
        )

    def connector_health(self, connector_id: str):
        return self.request(
            "GET",
            "/v1/governance/connectors/%s/health" % urllib.parse.quote(connector_id, safe=""),
        )

    # ------------------------------------------------------------------
    # governance: trust relationships (Phase 6)
    # ------------------------------------------------------------------

    def create_trust_relationship(self, body: dict, idempotency_key: str):
        return self.request(
            "POST",
            "/v1/governance/trust-relationships",
            body=body,
            idempotency_key=idempotency_key,
        )

    def list_trust_relationships(self):
        return self.request("GET", "/v1/governance/trust-relationships")

    def get_trust_relationship(self, relationship_id: str):
        return self.request(
            "GET",
            "/v1/governance/trust-relationships/%s" % urllib.parse.quote(relationship_id, safe=""),
        )

    def trust_relationship_transition(
        self, relationship_id: str, transition: str, reason: str, idempotency_key: str
    ):
        return self.request(
            "POST",
            "/v1/governance/trust-relationships/%s/%s"
            % (urllib.parse.quote(relationship_id, safe=""), transition),
            body={"reason": reason},
            idempotency_key=idempotency_key,
        )

    # ------------------------------------------------------------------
    # governance: external agents
    # ------------------------------------------------------------------

    def create_external_agent(self, body: dict, idempotency_key: str):
        return self.request(
            "POST",
            "/v1/governance/external-agents",
            body=body,
            idempotency_key=idempotency_key,
        )

    def list_external_agents(self):
        return self.request("GET", "/v1/governance/external-agents")

    def get_external_agent(self, external_agent_id: str):
        return self.request(
            "GET",
            "/v1/governance/external-agents/%s" % urllib.parse.quote(external_agent_id, safe=""),
        )

    def external_agent_health(self, external_agent_id: str):
        return self.request(
            "GET",
            "/v1/governance/external-agents/%s/health" % urllib.parse.quote(external_agent_id, safe=""),
        )

    def external_agent_transition(
        self, external_agent_id: str, transition: str, reason: str, idempotency_key: str
    ):
        return self.request(
            "POST",
            "/v1/governance/external-agents/%s/%s"
            % (urllib.parse.quote(external_agent_id, safe=""), transition),
            body={"reason": reason},
            idempotency_key=idempotency_key,
        )

    # ------------------------------------------------------------------
    # governance: external runs
    # ------------------------------------------------------------------

    def create_external_run(self, body: dict, idempotency_key: Optional[str] = None):
        return self.request(
            "POST",
            "/v1/governance/external-runs",
            body=body,
            idempotency_key=idempotency_key,
        )

    def list_external_runs(self, query: Optional[dict] = None):
        query = query or {}
        return self.request(
            "GET",
            "/v1/governance/external-runs",
            query={
                "external_agent_id": query.get("external_agent_id"),
                "status": query.get("status"),
                "cursor": query.get("cursor"),
                "limit": query.get("limit"),
            },
        )

    def get_external_run(self, run_id: str):
        return self.request(
            "GET", "/v1/governance/external-runs/%s" % urllib.parse.quote(run_id, safe="")
        )

    def terminate_external_run(self, run_id: str, reason: str, idempotency_key: str):
        return self.request(
            "POST",
            "/v1/governance/external-runs/%s/terminate" % urllib.parse.quote(run_id, safe=""),
            body={"reason": reason},
            idempotency_key=idempotency_key,
        )

    # ------------------------------------------------------------------
    # governance: consents
    # ------------------------------------------------------------------

    def create_consent(self, body: dict, idempotency_key: str):
        return self.request(
            "POST", "/v1/governance/consents", body=body, idempotency_key=idempotency_key
        )

    def list_consents(self):
        return self.request("GET", "/v1/governance/consents")

    def get_consent(self, consent_id: str):
        return self.request(
            "GET", "/v1/governance/consents/%s" % urllib.parse.quote(consent_id, safe="")
        )

    def revoke_consent(self, consent_id: str, reason: str, idempotency_key: str):
        return self.request(
            "POST",
            "/v1/governance/consents/%s/revoke" % urllib.parse.quote(consent_id, safe=""),
            body={"reason": reason},
            idempotency_key=idempotency_key,
        )

    # ------------------------------------------------------------------
    # governance: transfer policies
    # ------------------------------------------------------------------

    def upsert_transfer_policy(self, body: dict, idempotency_key: str):
        return self.request(
            "POST",
            "/v1/governance/transfer-policies",
            body=body,
            idempotency_key=idempotency_key,
        )

    def list_transfer_policies(self):
        return self.request("GET", "/v1/governance/transfer-policies")

    def transfer_policy_transition(
        self, policy_id: str, transition: str, reason: str, idempotency_key: str
    ):
        return self.request(
            "POST",
            "/v1/governance/transfer-policies/%s/%s"
            % (urllib.parse.quote(policy_id, safe=""), transition),
            body={"reason": reason},
            idempotency_key=idempotency_key,
        )

    # ------------------------------------------------------------------
    # governance: external budgets
    # ------------------------------------------------------------------

    def list_external_budgets(self):
        return self.request("GET", "/v1/governance/external-budgets")

    def upsert_external_budget(self, external_agent_id: str, body: dict, idempotency_key: str):
        return self.request(
            "PUT",
            "/v1/governance/external-budgets/%s" % urllib.parse.quote(external_agent_id, safe=""),
            body=body,
            idempotency_key=idempotency_key,
        )

    # ------------------------------------------------------------------
    # usage metering
    # ------------------------------------------------------------------

    def usage(self) -> dict:
        return self.request("GET", "/v1/usage")

    def usage_limits(self) -> dict:
        return self.request("GET", "/v1/usage/limits")

    def set_usage_limits(self, body: dict, idempotency_key: str) -> dict:
        return self.request(
            "PUT",
            "/v1/usage/limits",
            body=body,
            idempotency_key=idempotency_key,
        )
