import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSingboxConfig, buildSingboxInbound, canUseReality,
  generateRealityKeypair, nodeLinks
} from '../src/singbox.js';
import { buildNodeStatuses } from '../src/remote.js';

const makeNode = (overrides = {}) => ({
  id: 'one', name: '测试节点', server_id: 'server-1',
  protocol: 'vless', role: 'inbound', port: 443, network: 'tcp',
  security: 'reality', sni: 'www.microsoft.com',
  dest: 'www.microsoft.com:443', server_names: 'www.microsoft.com',
  private_key: 'private-secret', public_key: 'public-key',
  short_ids: '01234567', enabled: 1,
  clients: [{ email: 'one', secret: 'bf000d23-0752-40b4-affe-68f7707a9661' }],
  ...overrides
});

test('VLESS Reality Vision generates Sing-box inbound schema', () => {
  const inbound = buildSingboxInbound(makeNode());
  assert.equal(inbound.type, 'vless');
  assert.equal(inbound.listen_port, 443);
  assert.equal(inbound.users[0].flow, 'xtls-rprx-vision');
  assert.equal(inbound.tls.reality.private_key, 'private-secret');
  assert.deepEqual(inbound.tls.reality.short_id, ['01234567']);
  assert.equal(inbound.tls.reality.handshake.server, 'www.microsoft.com');
  assert.equal(inbound.tls.reality.handshake.server_port, 443);
  assert.equal(inbound.transport, undefined);
  assert.equal(inbound.protocol, undefined);
});

test('gRPC Reality does not force incompatible Vision flow', () => {
  const inbound = buildSingboxInbound(makeNode({ network: 'grpc', path: 'grpc-svc' }));
  assert.equal(inbound.transport.type, 'grpc');
  assert.equal(inbound.transport.service_name, 'grpc-svc');
  assert.equal(inbound.users[0].flow, undefined);
  assert.equal(canUseReality('vless', 'xhttp'), false);
});

test('Hysteria2 uses UDP-capable inbound and TLS cert without domain', () => {
  const inbound = buildSingboxInbound(makeNode({
    protocol: 'hysteria2', network: 'tcp', security: 'tls', sni: '',
    hy2_up: 150, hy2_down: 300
  }));
  assert.equal(inbound.type, 'hysteria2');
  assert.equal(inbound.users[0].password, makeNode().clients[0].secret);
  assert.equal(inbound.tls.certificate_path, '/usr/local/etc/sing-box/cert/cert.pem');
  assert.deepEqual(inbound.tls.alpn, ['h3']);
  assert.equal(inbound.up_mbps, 150);
});

test('TUIC and AnyTLS use native Sing-box user fields', () => {
  const tuic = buildSingboxInbound(makeNode({ protocol: 'tuic', security: 'tls' }));
  assert.equal(tuic.type, 'tuic');
  assert.equal(tuic.users[0].uuid, makeNode().clients[0].secret);
  assert.equal(tuic.users[0].password, makeNode().clients[0].secret);
  const anytls = buildSingboxInbound(makeNode({ protocol: 'anytls', security: 'tls' }));
  assert.equal(anytls.users[0].password, makeNode().clients[0].secret);
});

test('Shadowsocks uses one password and a standard method', () => {
  const inbound = buildSingboxInbound(makeNode({ protocol: 'shadowsocks', security: 'none', method: 'aes-256-gcm' }));
  assert.equal(inbound.type, 'shadowsocks');
  assert.equal(inbound.method, 'aes-256-gcm');
  assert.equal(inbound.password, makeNode().clients[0].secret);
  assert.equal(inbound.users, undefined);
});

test('Cloudflare Quick Tunnel binds only loopback and keeps WebSocket transport', () => {
  const inbound = buildSingboxInbound(makeNode({ security: 'none', network: 'ws', tunnel: 1, path: '/edge' }));
  assert.equal(inbound.listen, '127.0.0.1');
  assert.equal(inbound.transport.type, 'ws');
  assert.equal(inbound.transport.path, '/edge');
  assert.equal(inbound.tls, undefined);
  assert.deepEqual(nodeLinks(makeNode({ security: 'none', network: 'ws', tunnel: 1 }),
    { host: '198.51.100.10', argo_domain: '' }), []);
});

test('Routes use sing-box route action and outbound tags', () => {
  const incoming = makeNode();
  const remote = makeNode({ id: 'out', role: 'outbound', security: 'none', protocol: 'shadowsocks', method: 'aes-256-gcm' });
  const config = buildSingboxConfig([incoming], [{
    inbound_node_id: incoming.id, outbound_node: remote,
    outbound_server: { host: '203.0.113.10' }
  }]);
  assert.equal(config.outbounds[0].type, 'direct');
  assert.equal(config.outbounds[2].server, '203.0.113.10');
  assert.deepEqual(config.route.rules[0], {
    inbound: ['node-one'], action: 'route', outbound: 'out-out'
  });
  assert.equal(config.routing, undefined);
});

test('Node inspection uses sing-box listen_port/type and UDP listener', () => {
  const n = makeNode({ protocol: 'tuic', port: 5443, security: 'tls' });
  const result = buildNodeStatuses([n], {
    inbounds: [{ type: 'tuic', listen_port: 5443, tag: 'node-one' }]
  }, [], [5443]);
  assert.equal(result[0].in_config, true);
  assert.equal(result[0].listening_udp, true);
  assert.equal(result[0].listening, true);
  assert.equal(result[0].listening_tcp, false);
});

test('Existing custom Xray XHTTP transport is rejected instead of silently breaking', () => {
  assert.throws(() => buildSingboxInbound(makeNode({ network: 'xhttp' })), /不支持/);
});

test('Reality key generator outputs URL-safe X25519 key pair', () => {
  const pair = generateRealityKeypair();
  assert.match(pair.privateKey, /^[A-Za-z0-9_-]{43}$/);
  assert.match(pair.publicKey, /^[A-Za-z0-9_-]{43}$/);
});

test('Share link output uses the right proxy protocol', () => {
  const link = nodeLinks(makeNode(), { host: '198.51.100.10' })[0].link;
  assert.match(link, /^vless:///);
  assert.match(link, /pbk=public-key/);
});
