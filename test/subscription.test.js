import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const dataDir = mkdtempSync(join(tmpdir(), 'vps-subscription-test-'));
process.env.DATA_DIR = dataDir;

const [{ app }, db, tokenModule] = await Promise.all([
  import('../src/app.js'),
  import('../src/db.js'),
  import('../src/subscription-token.js')
]);

let server;
let baseUrl;
let localServer;
let inboundNode;
let outboundNode;
let disabledNode;
let subscription;

async function request(path, options = {}) {
  const response = await fetch(baseUrl + path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }
  });
  const text = await response.text();
  let body = text;
  try { body = text ? JSON.parse(text) : null; } catch { /* plain text */ }
  return { response, body, text };
}

before(async () => {
  server = createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;

  localServer = (await request('/api/servers', {
    method: 'POST',
    body: JSON.stringify({ name: '测试服务器', host: '198.51.100.10', username: 'root', password: 'local-only' })
  })).body;

  inboundNode = (await request(`/api/servers/${localServer.id}/nodes`, {
    method: 'POST',
    body: JSON.stringify({
      name: '入口 VLESS', server_id: localServer.id, protocol: 'vless', role: 'inbound',
      port: 443, network: 'tcp', security: 'none', enabled: true,
      clients: [{ email: 'inbound-user', secret: 'inbound-secret' }]
    })
  })).body;

  outboundNode = (await request(`/api/servers/${localServer.id}/nodes`, {
    method: 'POST',
    body: JSON.stringify({
      name: '出口 VLESS', server_id: localServer.id, protocol: 'vless', role: 'outbound',
      port: 8443, network: 'tcp', security: 'none', enabled: true,
      clients: [{ email: 'outbound-user', secret: 'outbound-secret' }]
    })
  })).body;

  disabledNode = (await request(`/api/servers/${localServer.id}/nodes`, {
    method: 'POST',
    body: JSON.stringify({
      name: '禁用 VLESS', server_id: localServer.id, protocol: 'vless', role: 'inbound',
      port: 9443, network: 'tcp', security: 'none', enabled: false,
      clients: [{ email: 'disabled-user', secret: 'disabled-secret' }]
    })
  })).body;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  db.closeDatabase();
  rmSync(dataDir, { recursive: true, force: true });
});

test('creates a subscription with a one-time token and stores only its hash', async () => {
  const result = await request('/api/subscriptions', {
    method: 'POST',
    body: JSON.stringify({ name: '入口订阅', default_format: 'base64', enabled: true })
  });
  assert.equal(result.response.status, 201);
  assert.match(result.body.token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(result.body.subscription.token_hash, undefined);
  assert.equal(result.body.subscription.node_count, 1);

  const raw = db.getSubscriptionByTokenHash(tokenModule.hashSubscriptionToken(result.body.token));
  assert.ok(raw);
  assert.equal(raw.token_hash, tokenModule.hashSubscriptionToken(result.body.token));
  assert.notEqual(raw.token_hash, result.body.token);
  subscription = result.body.subscription;
});

test('default subscription keeps stable copyable paths across reloads', async () => {
  const first = await request('/api/subscriptions');
  const second = await request('/api/subscriptions');
  assert.equal(first.response.status, 200);
  assert.equal(first.body.length, 1);
  assert.equal(first.body[0].id, subscription.id);
  assert.match(first.body[0].subscription_path, /^\/sub\/[A-Za-z0-9_-]{43}$/);
  assert.match(first.body[0].subscription_uri_path, /^\/sub\/[A-Za-z0-9_-]{43}\?format=uri$/);
  assert.equal(second.body[0].subscription_path, first.body[0].subscription_path);
  const raw = db.getSubscriptionRecord(subscription.id);
  assert.ok(raw.token_ciphertext);
  assert.notEqual(raw.token_ciphertext, raw.token_hash);
});

test('preview includes only enabled inbound nodes and explains exclusions', async () => {
  const result = await request(`/api/subscriptions/${subscription.id}/preview`);
  assert.equal(result.response.status, 200);
  assert.equal(result.body.node_count, 1);
  assert.equal(result.body.nodes[0].id, inboundNode.id);
  assert.equal(result.body.nodes[0].has_share_links, true);
  assert.deepEqual(
    result.body.excluded.map((node) => [node.id, node.reason]).sort(),
    [[disabledNode.id, '节点已禁用'], [outboundNode.id, '出站节点不纳入订阅']].sort()
  );
});

test('public subscription returns base64 and URI formats', async () => {
  const base64 = await request(`/sub/${subscription.token || ''}`);
  assert.equal(base64.response.status, 404);

  const created = await request('/api/subscriptions', {
    method: 'POST',
    body: JSON.stringify({ name: '公开入口订阅', default_format: 'base64' })
  });
  const token = created.body.token;
  const encoded = await request(`/sub/${token}`);
  assert.equal(encoded.response.status, 200);
  const uriText = Buffer.from(encoded.text, 'base64').toString('utf8');
  assert.match(uriText, /^vless:\/\/inbound-secret@198\.51\.100\.10:443/m);
  assert.doesNotMatch(uriText, /outbound-secret|disabled-secret/);
  assert.equal(encoded.response.headers.get('x-subscription-node-count'), '1');

  const raw = await request(`/sub/${token}?format=uri`);
  assert.equal(raw.response.status, 200);
  assert.match(raw.text, /^vless:\/\/inbound-secret@198\.51\.100\.10:443/);
  assert.equal(raw.response.headers.get('content-type'), 'text/plain; charset=utf-8');
});

test('subscription QR endpoint renders locally and accepts only subscription URLs', async () => {
  const created = await request('/api/subscriptions', {
    method: 'POST',
    body: JSON.stringify({ name: '二维码订阅' })
  });
  const token = created.body.token;
  const qr = await request('/api/subscriptions/qr', {
    method: 'POST',
    body: JSON.stringify({ url: `${baseUrl}/sub/${token}` })
  });
  assert.equal(qr.response.status, 200);
  assert.match(qr.body.data_url, /^data:image\/png;base64,/);

  const rejected = await request('/api/subscriptions/qr', {
    method: 'POST',
    body: JSON.stringify({ url: 'https://example.com/not-a-subscription' })
  });
  assert.equal(rejected.response.status, 400);
});

test('invalid and disabled subscriptions are rejected while expiry is ignored', async () => {
  const created = await request('/api/subscriptions', {
    method: 'POST',
    body: JSON.stringify({ name: '受控订阅' })
  });
  const token = created.body.token;

  assert.equal((await request('/sub/not-a-valid-token')).response.status, 404);
  assert.equal((await request(`/api/subscriptions/${created.body.subscription.id}/disable`, { method: 'POST' })).response.status, 200);
  assert.equal((await request(`/sub/${token}`)).response.status, 404);

  await request(`/api/subscriptions/${created.body.subscription.id}`, {
    method: 'PUT',
    body: JSON.stringify({ name: '受控订阅', expires_at: '2020-01-01T00:00:00.000Z', enabled: true, default_format: 'base64' })
  });
  assert.equal((await request(`/sub/${token}`)).response.status, 200);
});

test('rotating a token invalidates the old address and updates access metadata', async () => {
  const created = await request('/api/subscriptions', {
    method: 'POST',
    body: JSON.stringify({ name: '轮换订阅' })
  });
  const oldToken = created.body.token;
  const rotated = await request(`/api/subscriptions/${created.body.subscription.id}/rotate`, { method: 'POST' });
  assert.equal(rotated.response.status, 200);
  assert.notEqual(rotated.body.token, oldToken);
  assert.equal((await request(`/sub/${oldToken}`)).response.status, 404);
  assert.equal((await request(`/sub/${rotated.body.token}`)).response.status, 200);

  const detail = await request(`/api/subscriptions/${created.body.subscription.id}`);
  assert.ok(detail.body.last_access_at);
  assert.ok(detail.body.access_count >= 1);
});

test('deleting a subscription invalidates its address and empty subscriptions stay successful', async () => {
  const created = await request('/api/subscriptions', {
    method: 'POST',
    body: JSON.stringify({ name: '空订阅' })
  });
  const token = created.body.token;
  await request(`/api/nodes/${inboundNode.id}`, {
    method: 'PUT',
    body: JSON.stringify({
      name: inboundNode.name, server_id: localServer.id, protocol: 'vless', role: 'inbound',
      port: 443, network: 'tcp', security: 'none', enabled: false,
      clients: [{ email: 'inbound-user', secret: 'inbound-secret' }]
    })
  });
  const empty = await request(`/sub/${token}`);
  assert.equal(empty.response.status, 200);
  assert.equal(empty.text, '');
  assert.equal(empty.response.headers.get('x-subscription-empty'), 'true');

  assert.equal((await request(`/api/subscriptions/${created.body.subscription.id}`, { method: 'DELETE' })).response.status, 204);
  assert.equal((await request(`/sub/${token}`)).response.status, 404);
});
