import test from 'node:test';
import assert from 'node:assert/strict';
import { GroundworkClient } from '../dist/index.js';
import { GroundworkError } from '../dist/errors.js';

function stubFetch(status, body, headers = {}) {
  return async (url, init) => {
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json', ...headers },
    });
  };
}

test('sends API key header and parses agents list with count', async () => {
  let seenHeaders;
  const client = new GroundworkClient({
    baseUrl: 'http://localhost:8080',
    apiKey: 'gw_test_key',
    fetch: async (url, init) => {
      seenHeaders = init.headers;
      return new Response(JSON.stringify({ agents: [], count: 0 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });

  const result = await client.listAgents();
  assert.equal(result.count, 0);
  assert.deepEqual(result.agents, []);
  assert.equal(seenHeaders['X-Groundwork-API-Key'], 'gw_test_key');
});

test('sends user assertion when provided as provider', async () => {
  let seenHeaders;
  const client = new GroundworkClient({
    baseUrl: 'http://localhost:8080',
    apiKey: 'gw_test_key',
    assertion: () => 'assertion-token-123',
    fetch: async (url, init) => {
      seenHeaders = init.headers;
      return new Response(JSON.stringify({ agent: {} }), { status: 201, headers: { 'content-type': 'application/json' } });
    },
  });

  await client.createAgent({
    name: 'research-agent',
    business_purpose: 'read-only research',
  });
  assert.equal(seenHeaders['X-Groundwork-User-Assertion'], 'assertion-token-123');
  assert.equal(seenHeaders['Content-Type'], 'application/json');
});

test('posts JSON body with query endpoint', async () => {
  let seenBody;
  const client = new GroundworkClient({
    baseUrl: 'http://localhost:8080',
    apiKey: 'gw_test_key',
    fetch: async (url, init) => {
      seenBody = JSON.parse(init.body);
      return new Response(JSON.stringify({ answer: 'ok', trace_id: 't1' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });

  await client.query({ query: 'summarize incidents', top_k: 3 });
  assert.deepEqual(seenBody, { query: 'summarize incidents', top_k: 3 });
});

test('error envelope surfaces code and status', async () => {
  const client = new GroundworkClient({
    baseUrl: 'http://localhost:8080',
    apiKey: 'gw_test_key',
    fetch: stubFetch(503, { error: 'audit_unavailable' }),
  });

  await assert.rejects(
    () => client.audit({ limit: 10 }),
    (err) => {
      assert.ok(err instanceof GroundworkError);
      assert.equal(err.code, 'audit_unavailable');
      assert.equal(err.status, 503);
      return true;
    },
  );
});

test('network failure wraps into GroundworkError', async () => {
  const client = new GroundworkClient({
    baseUrl: 'http://localhost:8080',
    apiKey: 'gw_test_key',
    fetch: async () => {
      throw new TypeError('fetch failed');
    },
  });

  await assert.rejects(
    () => client.health(),
    (err) => {
      assert.ok(err instanceof GroundworkError);
      assert.equal(err.code, 'network');
      return true;
    },
  );
});

test('trailing slash on baseUrl is normalized', async () => {
  let seenUrl;
  const client = new GroundworkClient({
    baseUrl: 'http://localhost:8080/',
    apiKey: 'gw_test_key',
    fetch: async (url) => {
      seenUrl = url;
      return new Response(JSON.stringify({ status: 'ok', service: 'query-runtime' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });

  await client.health();
  assert.equal(seenUrl, 'http://localhost:8080/healthz');
});

test('mintUserAssertion produces a verifiable HS256 JWT', async () => {
  const { mintUserAssertion } = await import('../dist/index.js');
  const token = await mintUserAssertion({
    hsSecret: 'test-secret-at-least-32-chars-long!!',
    subject: 'user-1',
    tenantId: 'tenant-acme',
  });

  const [h, p, s] = token.split('.');
  assert.ok(h && p && s, 'token has three parts');

  const { createHmac } = await import('node:crypto');
  const expected = createHmac('sha256', 'test-secret-at-least-32-chars-long!!')
    .update(`${h}.${p}`)
    .digest('base64url');
  assert.equal(s, expected);

  const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  assert.equal(payload.sub, 'user-1');
  assert.equal(payload.tenant_id, 'tenant-acme');
  assert.ok(payload.exp > Math.floor(Date.now() / 1000));
});

test('usage methods hit the usage endpoints', async () => {
  const calls = [];
  const client = new GroundworkClient({
    baseUrl: 'http://localhost:8080',
    apiKey: 'gw_test_key',
    fetch: async (url, init) => {
      calls.push({ url, method: init.method, body: init.body ? JSON.parse(init.body) : null, key: init.headers?.['Idempotency-Key'] });
      if (init.method === 'GET') {
        return new Response(JSON.stringify({ tenant_id: 'tenant-acme', limits: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      return new Response(
        JSON.stringify({
          tenant_id: 'tenant-acme',
          limits: [{ metric: 'runs', period: 'monthly', limit: 1000 }],
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    },
  });

  await client.getUsage();
  await client.getUsageLimits();
  await client.putUsageLimits({ limits: [{ metric: 'runs', period: 'monthly', limit: 1000 }] }, 'idem-usage-1');

  assert.deepEqual(calls[0].url, 'http://localhost:8080/v1/usage');
  assert.equal(calls[0].method, 'GET');
  assert.deepEqual(calls[1].url, 'http://localhost:8080/v1/usage/limits');
  assert.equal(calls[1].method, 'GET');
  assert.deepEqual(calls[2].url, 'http://localhost:8080/v1/usage/limits');
  assert.equal(calls[2].method, 'PUT');
  assert.deepEqual(calls[2].body, { limits: [{ metric: 'runs', period: 'monthly', limit: 1000 }] });
  assert.equal(calls[2].key, 'idem-usage-1');
});
