import { GroundworkClient, GroundworkError } from '../dist/index.js';

const baseUrl = process.env.GW_BASE_URL ?? 'http://127.0.0.1:18080';
const apiKey = process.env.GW_API_KEY ?? 'gw_local_acme_key';

const client = new GroundworkClient({ baseUrl, apiKey, timeoutMs: 15_000 });

let failures = 0;
function check(label, ok, extra = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${extra ? `  (${extra})` : ''}`);
  if (!ok) failures += 1;
}

// 1. healthz (no scopes)
const health = await client.health();
check('healthz returns ok', health.status === 'ok', health.status);

// 2. create agent (demo identity, mutation) -> {agent}
const created = await client.createAgent({
  name: `sdk-smoke-agent-${Date.now()}`,
  business_purpose: 'live smoke test via @groundwork/sdk',
  risk_tier: 'low',
});
const agent = created.agent;
check('create agent returns {agent}', !!agent.id, agent.id?.slice(0, 8));

// 3. list agents with count envelope
const list = await client.listAgents();
check('list agents has count envelope', typeof list.count === 'number' && Array.isArray(list.agents), `count=${list.count}`);

// 4. get agent detail envelope {agent, versions, lifecycle_events}
const detail = await client.getAgent(agent.id);
check('agent detail has agent/versions/lifecycle_events', !!detail.agent && Array.isArray(detail.versions) && Array.isArray(detail.lifecycle_events));

// 4b. add a draft version so the grant has an agent version to bind to
const versionRes = await client.addAgentVersion(agent.id, {
  version: '1.0.0',
  model_provider: 'acme',
  model_name: 'research-1',
  prompt_digest: 'sha256:smoke-prompt',
  tool_manifest_digest: 'sha256:smoke-manifest',
  policy_bundle_version: '2026.01',
  artifact_digest: 'sha256:smoke-artifact',
});
const versionId = versionRes.version.id;
check('add agent version returns id', !!versionId, versionId?.slice(0, 8));

const activatedAgent = await client.activateAgent(agent.id, 'smoke activate');
check('activate agent returns active state', activatedAgent.agent?.lifecycle_state === 'active', activatedAgent.agent?.lifecycle_state);

// 5. register tool (real shape: transport + owner_principal_id) + action + grant
const tool = (await client.registerTool({
  name: `sdk-smoke-tool-${Date.now()}`,
  description: 'tool registered by the SDK smoke test',
  transport: 'http',
  endpoint_or_server: 'http://internal-service:8080',
  owner_principal_id: 'demo@groundwork.local',
  region: 'US',
})).tool;
check('register tool returns {tool}', typeof tool.id === 'string', tool.id?.slice(0, 8));

const actionRes = await client.registerToolAction(tool.id, {
  action: 'read_health',
  resource_type: 'health',
  risk_level: 'low',
  read_only: true,
  requires_human_approval: false,
});
const actionId = actionRes.action.id;
check('register tool action returns id', !!actionId, actionId?.slice(0, 8));

const toolDetail = await client.getTool(tool.id);
check('tool detail has actions', Array.isArray(toolDetail.actions), `actions=${toolDetail.actions.length}`);

const grantRes = await client.grantTool({
  agent_id: agent.id,
  version_id: versionId,
  tool_id: tool.id,
  action_id: actionId,
  resource_scope: '*',
  region_constraint: 'US',
  call_limit_per_run: 10,
});
check('grant tool returns grant', !!grantRes.grant.id, grantRes.grant.id?.slice(0, 8));

const agentGrants = await client.listAgentGrants(agent.id);
check('list agent grants has count', typeof agentGrants.count === 'number' && Array.isArray(agentGrants.grants), `count=${agentGrants.count}`);

const tools = await client.listTools();
check('list tools has count envelope', typeof tools.count === 'number' && Array.isArray(tools.tools), `count=${tools.count}`);

// 5b. activate the tool, then exercise the policy simulator (read-only analysis)
const activated = (await client.toolLifecycle(tool.id, { lifecycle: 'active' })).tool;
check('activate tool returns active lifecycle', activated.lifecycle === 'active', activated.lifecycle);

const simAllowed = (await client.simulateAction({
  agent_id: agent.id,
  tool_name: tool.name,
  action: 'read_health',
  resource_ref: 'health:check',
})).simulation;
check(
  'simulate would-allow with simulated flag',
  simAllowed.allowed && simAllowed.decision === 'allowed' && simAllowed.simulated === true,
  `${simAllowed.decision} gates=${simAllowed.checks.length}`,
);
check(
  'simulate explains grant gate as passed',
  Array.isArray(simAllowed.checks) && simAllowed.checks.some((c) => c.gate === 'grant' && c.status === 'passed'),
  `gates=${simAllowed.checks.length}`,
);

const simFailClosed = (await client.simulateAction({
  agent_id: agent.id,
  tool_name: tool.name,
  action: 'read_health',
  resource_ref: 'health:check',
  principal_id: 'principal:bob',
})).simulation;
check(
  'simulate fails closed without permission backend',
  !simFailClosed.allowed && simFailClosed.decision === 'fail_closed',
  `${simFailClosed.decision}: ${simFailClosed.reason}`,
);

const simNoGrant = (await client.simulateAction({
  agent_id: agent.id,
  tool_name: 'unregistered-tool',
  action: 'read_health',
  resource_ref: 'health:check',
})).simulation;
check(
  'simulate denies unknown tool',
  !simNoGrant.allowed && simNoGrant.decision === 'denied',
  `${simNoGrant.decision}: ${simNoGrant.reason}`,
);

// 6. emergency controls (Phase 3, read)
const controls = await client.listEmergencyControls();
check('list emergency controls', Array.isArray(controls.controls) && typeof controls.count === 'number', `count=${controls.count}`);

// 7. budgets (Phase 3, read)
const budgets = await client.listBudgets();
check('list budgets', Array.isArray(budgets.budgets) && typeof budgets.count === 'number', `count=${budgets.count}`);

// 8. evidence read model (Phase 3, read)
const evidence = await client.queryEvidence();
check('query evidence returns page', Array.isArray(evidence.events) && typeof evidence.count === 'number', `events=${evidence.events.length}`);

// 9. outbox (Phase 3, read)
const outbox = await client.listOutbox();
check('list outbox returns page', Array.isArray(outbox.events) && typeof outbox.count === 'number', `count=${outbox.count}`);

// 10. connectors (Phase 5, read)
const connectors = await client.listConnectors();
check('list connectors has count', typeof connectors.count === 'number' && Array.isArray(connectors.connectors), `count=${connectors.count}`);

// 11. audit in memory mode -> 503 audit_unavailable error envelope
try {
  await client.audit({ limit: 5 });
  check('audit fails in memory mode', false, 'expected 503');
} catch (err) {
  check(
    'audit 503 audit_unavailable envelope',
    err instanceof GroundworkError && err.status === 503 && err.code === 'audit_unavailable',
    `${err.status} ${err.code}`,
  );
}

// 12. unknown key -> 401 envelope
try {
  const bad = new GroundworkClient({ baseUrl, apiKey: 'gw_wrong_key' });
  await bad.listAgents();
  check('wrong key rejected', false);
} catch (err) {
  check('wrong key rejected 401', err instanceof GroundworkError && err.status === 401, `${err.status} ${err.code}`);
}

// 13. Phase 6 reads (trust model)
const trustRelationships = await client.listTrustRelationships();
check('list trust relationships', Array.isArray(trustRelationships.relationships) && typeof trustRelationships.count === 'number', `count=${trustRelationships.count}`);

const externalAgents = await client.listExternalAgents();
check('list external agents', Array.isArray(externalAgents.agents) && typeof externalAgents.count === 'number', `count=${externalAgents.count}`);

const consents = await client.listConsents();
check('list consents', Array.isArray(consents.consents) && typeof consents.count === 'number', `count=${consents.count}`);

const transferPolicies = await client.listTransferPolicies();
check('list transfer policies', Array.isArray(transferPolicies.policies) && typeof transferPolicies.count === 'number', `count=${transferPolicies.count}`);

const externalBudgets = await client.listExternalBudgets();
check('list external budgets', Array.isArray(externalBudgets.budgets) && typeof externalBudgets.count === 'number', `count=${externalBudgets.count}`);

// 14. usage metering (Phase 8.1)
const usage = await client.getUsage();
check(
  'get usage returns envelope with agents and runs',
  typeof usage.tenant_id === 'string' && Array.isArray(usage.usage) && usage.usage.some((m) => m.metric === 'agents' && m.count >= 1) && usage.usage.some((m) => m.metric === 'runs' && m.period === 'monthly'),
  `metrics=${usage.usage.length}`,
);

const limitsBefore = await client.getUsageLimits();
check('get usage limits returns envelope', typeof limitsBefore.tenant_id === 'string' && Array.isArray(limitsBefore.limits));

const agentMetric = usage.usage.find((m) => m.metric === 'agents' && m.period === 'monthly');
await client.putUsageLimits({ limits: [{ metric: 'agents', period: 'monthly', limit: agentMetric.count }] }, `idem-usage-smoke-${Date.now()}`);
try {
  await client.createAgent({ name: `sdk-smoke-overquota-${Date.now()}`, business_purpose: 'should be blocked by quota' });
  check('agents quota blocks create', false, 'expected 403');
} catch (err) {
  check('agents quota 403 quota_exceeded envelope', err instanceof GroundworkError && err.status === 403 && err.code === 'quota_exceeded:agents', `${err.status} ${err.code}`);
}
await client.putUsageLimits({ limits: [{ metric: 'agents', period: 'monthly', limit: 0 }] }, `idem-usage-clear-${Date.now()}`);
const agentsEntry = (await client.getUsage()).usage.find((m) => m.metric === 'agents' && m.period === 'monthly');
check('clearing agents limit restores unlimited', agentsEntry.limit === 0 && agentsEntry.remaining === -1, `limit=${agentsEntry.limit} remaining=${agentsEntry.remaining}`);

console.log(failures === 0 ? 'SMOKE OK' : `SMOKE FAILED (${failures} failures)`);
process.exit(failures === 0 ? 0 : 1);
