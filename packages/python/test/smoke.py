"""Live smoke test mirroring packages/typescript/test/smoke.mjs.

Requires the demo runtime on :18080 (ALLOW_DEMO_IDENTITY=true,
ALLOW_MEMORY_API_KEYS=true, key gw_local_acme_key).

Run with:  python test/smoke.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from groundwork.client import GroundworkClient
from groundwork.errors import GroundworkError

BASE_URL = os.environ.get("GW_BASE_URL", "http://127.0.0.1:18080")
API_KEY = os.environ.get("GW_API_KEY", "gw_local_acme_key")

failures = 0


def check(label, ok, extra=""):
    global failures
    print("PASS  %s" % label if ok else "FAIL  %s" % label, end="")
    if extra:
        print("  (%s)" % extra, end="")
    print()
    if not ok:
        failures += 1


client = GroundworkClient(base_url=BASE_URL, api_key=API_KEY, timeout_ms=15000)

# 1. healthz
health = client.health()
check("healthz returns ok", health.get("status") == "ok", health.get("status"))

# 2. create agent (demo identity) -> {agent}
created = client.create_agent(
    {
        "name": "sdk-smoke-agent-%d" % int(time.time() * 1000),
        "business_purpose": "live smoke test via groundwork-sdk (python)",
        "risk_tier": "low",
    }
)
agent = created["agent"]
check("create agent returns {agent}", bool(agent.get("id")), agent.get("id", "")[:8])

# 3. list agents with count envelope
listing = client.list_agents()
check(
    "list agents has count envelope",
    isinstance(listing.get("count"), int) and isinstance(listing.get("agents"), list),
    "count=%s" % listing.get("count"),
)

# 4. get agent detail envelope {agent, versions, lifecycle_events}
detail = client.get_agent(agent["id"])
check(
    "agent detail has agent/versions/lifecycle_events",
    "agent" in detail and isinstance(detail.get("versions"), list) and isinstance(detail.get("lifecycle_events"), list),
)

# 4b. add a draft version
version_res = client.add_agent_version(
    agent["id"],
    {
        "version": "1.0.0",
        "model_provider": "acme",
        "model_name": "research-1",
        "prompt_digest": "sha256:smoke-prompt",
        "tool_manifest_digest": "sha256:smoke-manifest",
        "policy_bundle_version": "2026.01",
        "artifact_digest": "sha256:smoke-artifact",
    },
)
version_id = version_res["version"]["id"]
check("add agent version returns id", bool(version_id), version_id[:8])

activated_agent = client.activate_agent(agent["id"], "smoke activate")
check(
    "activate agent returns active state",
    activated_agent.get("agent", {}).get("lifecycle_state") == "active",
    activated_agent.get("agent", {}).get("lifecycle_state"),
)

# 5. register tool + action + grant
tool = client.register_tool(
    {
        "name": "sdk-smoke-tool-%d" % int(time.time() * 1000),
        "description": "tool registered by the python SDK smoke test",
        "transport": "http",
        "endpoint_or_server": "http://internal-service:8080",
        "owner_principal_id": "demo@groundwork.local",
        "region": "US",
    }
)["tool"]
check("register tool returns {tool}", isinstance(tool.get("id"), str), tool.get("id", "")[:8])

action_res = client.register_tool_action(
    tool["id"],
    {
        "action": "read_health",
        "resource_type": "health",
        "risk_level": "low",
        "read_only": True,
        "requires_human_approval": False,
    },
)
action_id = action_res["action"]["id"]
check("register tool action returns id", bool(action_id), action_id[:8])

tool_detail = client.get_tool(tool["id"])
check("tool detail has actions", isinstance(tool_detail.get("actions"), list), "actions=%d" % len(tool_detail.get("actions", [])))

grant_res = client.grant_tool(
    {
        "agent_id": agent["id"],
        "version_id": version_id,
        "tool_id": tool["id"],
        "action_id": action_id,
        "resource_scope": "*",
        "region_constraint": "US",
        "call_limit_per_run": 10,
    }
)
check("grant tool returns grant", bool(grant_res.get("grant", {}).get("id")), grant_res.get("grant", {}).get("id", "")[:8])

agent_grants = client.list_agent_grants(agent["id"])
check(
    "list agent grants has count",
    isinstance(agent_grants.get("count"), int) and isinstance(agent_grants.get("grants"), list),
    "count=%s" % agent_grants.get("count"),
)

tools = client.list_tools()
check(
    "list tools has count envelope",
    isinstance(tools.get("count"), int) and isinstance(tools.get("tools"), list),
    "count=%s" % tools.get("count"),
)

# 5b. activate the tool, then exercise the policy simulator
activated = client.tool_lifecycle(tool["id"], {"lifecycle": "active"})["tool"]
check("activate tool returns active lifecycle", activated.get("lifecycle") == "active", activated.get("lifecycle"))

sim_allowed = client.simulate_action(
    {
        "agent_id": agent["id"],
        "tool_name": tool["name"],
        "action": "read_health",
        "resource_ref": "health:check",
    }
)["simulation"]
check(
    "simulate would-allow with simulated flag",
    sim_allowed.get("allowed") and sim_allowed.get("decision") == "allowed" and sim_allowed.get("simulated") is True,
    "%s gates=%d" % (sim_allowed.get("decision"), len(sim_allowed.get("checks", []))),
)
check(
    "simulate explains grant gate as passed",
    isinstance(sim_allowed.get("checks"), list) and any(c.get("gate") == "grant" and c.get("status") == "passed" for c in sim_allowed["checks"]),
    "gates=%d" % len(sim_allowed.get("checks", [])),
)

sim_fail_closed = client.simulate_action(
    {
        "agent_id": agent["id"],
        "tool_name": tool["name"],
        "action": "read_health",
        "resource_ref": "health:check",
        "principal_id": "principal:bob",
    }
)["simulation"]
check(
    "simulate fails closed without permission backend",
    not sim_fail_closed.get("allowed") and sim_fail_closed.get("decision") == "fail_closed",
    "%s: %s" % (sim_fail_closed.get("decision"), sim_fail_closed.get("reason")),
)

sim_no_grant = client.simulate_action(
    {
        "agent_id": agent["id"],
        "tool_name": "unregistered-tool",
        "action": "read_health",
        "resource_ref": "health:check",
    }
)["simulation"]
check(
    "simulate denies unknown tool",
    not sim_no_grant.get("allowed") and sim_no_grant.get("decision") == "denied",
    "%s: %s" % (sim_no_grant.get("decision"), sim_no_grant.get("reason")),
)

# 6. emergency controls (read)
controls = client.list_emergency_controls()
check(
    "list emergency controls",
    isinstance(controls.get("controls"), list) and isinstance(controls.get("count"), int),
    "count=%s" % controls.get("count"),
)

# 7. budgets (read)
budgets = client.list_budgets()
check(
    "list budgets",
    isinstance(budgets.get("budgets"), list) and isinstance(budgets.get("count"), int),
    "count=%s" % budgets.get("count"),
)

# 8. evidence + outbox (read)
evidence = client.query_evidence()
check(
    "query evidence returns page",
    isinstance(evidence.get("events"), list) and isinstance(evidence.get("count"), int),
    "events=%d" % len(evidence.get("events", [])),
)

outbox = client.list_outbox()
check(
    "list outbox returns page",
    isinstance(outbox.get("events"), list) and isinstance(outbox.get("count"), int),
    "count=%s" % outbox.get("count"),
)

# 9. connectors (read)
connectors = client.list_connectors()
check(
    "list connectors has count",
    isinstance(connectors.get("count"), int) and isinstance(connectors.get("connectors"), list),
    "count=%s" % connectors.get("count"),
)

# 10. audit 503 in memory mode
try:
    client.audit({"limit": 10})
    check("audit fails in memory mode", False, "expected 503")
except GroundworkError as exc:
    check(
        "audit 503 audit_unavailable envelope",
        exc.status == 503 and exc.code == "audit_unavailable",
        "%d %s" % (exc.status, exc.code),
    )

# 11. wrong key rejected
try:
    bad = GroundworkClient(base_url=BASE_URL, api_key="wrong-key", timeout_ms=5000)
    bad.list_agents()
    check("wrong key rejected", False)
except GroundworkError as exc:
    check("wrong key rejected 401", exc.status == 401, "%d %s" % (exc.status, exc.code))

# 12. Phase 6 reads
trust = client.list_trust_relationships()
check(
    "list trust relationships",
    isinstance(trust.get("relationships"), list) and isinstance(trust.get("count"), int),
    "count=%s" % trust.get("count"),
)

external_agents = client.list_external_agents()
check(
    "list external agents",
    isinstance(external_agents.get("agents"), list) and isinstance(external_agents.get("count"), int),
    "count=%s" % external_agents.get("count"),
)

consents = client.list_consents()
check(
    "list consents",
    isinstance(consents.get("consents"), list) and isinstance(consents.get("count"), int),
    "count=%s" % consents.get("count"),
)

transfer_policies = client.list_transfer_policies()
check(
    "list transfer policies",
    isinstance(transfer_policies.get("policies"), list) and isinstance(transfer_policies.get("count"), int),
    "count=%s" % transfer_policies.get("count"),
)

external_budgets = client.list_external_budgets()
check(
    "list external budgets",
    isinstance(external_budgets.get("budgets"), list) and isinstance(external_budgets.get("count"), int),
    "count=%s" % external_budgets.get("count"),
)

usage = client.usage()
check(
    "get usage returns envelope with agents and runs",
    isinstance(usage.get("tenant_id"), str)
    and isinstance(usage.get("usage"), list)
    and any(m.get("metric") == "agents" and m.get("count", 0) >= 1 for m in usage.get("usage", []))
    and any(m.get("metric") == "runs" and m.get("period") == "monthly" for m in usage.get("usage", [])),
    "metrics=%d" % len(usage.get("usage", [])),
)

usage_limits = client.usage_limits()
check(
    "get usage limits returns envelope",
    isinstance(usage_limits.get("tenant_id"), str) and isinstance(usage_limits.get("limits"), list),
)

agent_metric = next(m for m in usage.get("usage", []) if m.get("metric") == "agents" and m.get("period") == "monthly")
client.set_usage_limits(
    {"limits": [{"metric": "agents", "period": "monthly", "limit": agent_metric.get("count", 0)}]},
    "idem-usage-smoke-%d" % int(time.time()),
)
try:
    client.create_agent({"name": "sdk-smoke-overquota-%d" % int(time.time()), "business_purpose": "should be blocked"})
    check("agents quota blocks create", False, "expected 403")
except GroundworkError as exc:
    check(
        "agents quota 403 quota_exceeded envelope",
        exc.status == 403 and exc.code == "quota_exceeded:agents",
        "%s %s" % (exc.status, exc.code),
    )
client.set_usage_limits(
    {"limits": [{"metric": "agents", "period": "monthly", "limit": 0}]},
    "idem-usage-clear-%d" % int(time.time()),
)
agents_entry = next(m for m in client.usage().get("usage", []) if m.get("metric") == "agents" and m.get("period") == "monthly")
check(
    "clearing agents limit restores unlimited",
    agents_entry.get("limit") == 0 and agents_entry.get("remaining") == -1,
    "limit=%s remaining=%s" % (agents_entry.get("limit"), agents_entry.get("remaining")),
)

print()
if failures:
    print("SMOKE FAILED (%d failures)" % failures)
    sys.exit(1)
print("SMOKE OK")
