import test from 'node:test';
import assert from 'node:assert/strict';
import { buildXrayConfig, generateRealityKeypair, nodeLinks } from '../src/xray.js';

test('buildXrayConfig emits supported inbound protocols', () => {
  const nodes = [
    {
      id: 'n1',
      name: 'vless-reality',
      protocol: 'vless',
      port: 443,
      network: 'tcp',
      security: 'reality',
      sni: 'www.microsoft.com',
      path: '',
      cert_file: '',
      key_file: '',
      dest: 'www.microsoft.com:443',
      server_names: 'www.microsoft.com, www.bing.com',
      private_key: 'server-private',
      public_key: 'client-public',
      short_ids: 'abcd',
      enabled: 1,
      clients: [{ email: 'u1', secret: 'uuid-1', flow: 'xtls-rprx-vision' }]
    },
    {
      id: 'n2',
      name: 'vmess-ws',
      protocol: 'vmess',
      port: 8443,
      network: 'ws',
      security: 'tls',
      sni: 'example.com',
      path: '/ws',
      cert_file: '/etc/ssl/fullchain.pem',
      key_file: '/etc/ssl/privkey.pem',
      dest: '',
      server_names: '',
      private_key: '',
      public_key: '',
      short_ids: '',
      enabled: 1,
      clients: [{ email: 'u2', secret: 'uuid-2', flow: '' }]
    },
    {
      id: 'n3',
      name: 'trojan-tcp',
      protocol: 'trojan',
      port: 443,
      network: 'tcp',
      security: 'tls',
      sni: 'example.com',
      path: '',
      cert_file: '/etc/ssl/fullchain.pem',
      key_file: '/etc/ssl/privkey.pem',
      dest: '',
      server_names: '',
      private_key: '',
      public_key: '',
      short_ids: '',
      enabled: 1,
      clients: [{ email: 'u3', secret: 'trojan-pass', flow: '' }]
    },
    {
      id: 'n4',
      name: 'ss-grpc',
      protocol: 'shadowsocks',
      port: 8388,
      network: 'grpc',
      security: 'none',
      sni: '',
      path: 'svc',
      cert_file: '',
      key_file: '',
      dest: '',
      server_names: '',
      private_key: '',
      public_key: '',
      short_ids: '',
      enabled: 0,
      clients: [{ email: 'u4', secret: 'ss-pass', flow: '' }]
    }
  ];

  const config = buildXrayConfig(nodes);
  assert.equal(config.inbounds.length, 3);
  assert.deepEqual(config.inbounds.map((inbound) => inbound.protocol), ['vless', 'vmess', 'trojan']);
  assert.equal(config.inbounds[0].streamSettings.realitySettings.serverNames[0], 'www.microsoft.com');
  assert.equal(config.inbounds[0].streamSettings.realitySettings.shortIds[0], 'abcd');
  assert.equal(config.inbounds[1].streamSettings.wsSettings.path, '/ws');
  assert.equal(config.inbounds[1].streamSettings.tlsSettings.certificates[0].certificateFile, '/etc/ssl/fullchain.pem');
});

test('reality server config defaults to xtls-rprx-vision when client flow is empty', () => {
  const node = {
    name: 'vless-reality',
    protocol: 'vless',
    port: 443,
    network: 'tcp',
    security: 'reality',
    dest: 'www.microsoft.com:443',
    server_names: 'www.microsoft.com',
    private_key: 'server-private',
    public_key: 'client-public',
    short_ids: '',
    enabled: 1,
    clients: [{ email: '', secret: 'uuid-1', flow: '' }]
  };
  const config = buildXrayConfig([node]);
  assert.equal(config.inbounds[0].settings.clients[0].flow, 'xtls-rprx-vision');
});

test('generateRealityKeypair returns a local X25519 keypair', () => {
  const pair = generateRealityKeypair();
  assert.match(pair.privateKey, /^[A-Za-z0-9_-]{43}$/);
  assert.match(pair.publicKey, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(pair.privateKey, pair.publicKey);
});

test('nodeLinks builds reality and shadowsocks links', () => {
  const node = {
    id: 'n1',
    name: 'hk-443',
    protocol: 'vless',
    port: 443,
    network: 'tcp',
    security: 'reality',
    sni: 'www.microsoft.com',
    path: '',
    cert_file: '',
    key_file: '',
    dest: 'www.microsoft.com:443',
    server_names: 'www.microsoft.com',
    private_key: 'server-private',
    public_key: 'client-public',
    short_ids: 'abcd',
    enabled: 1,
    clients: [{ email: 'u1', secret: 'uuid-1', flow: 'xtls-rprx-vision' }]
  };
  const server = { host: '203.0.113.10' };

  const [vlessLink] = nodeLinks(node, server);
  assert.match(vlessLink.link, /^vless:\/\/uuid-1@203\.0\.113\.10:443/);
  assert.match(vlessLink.link, /security=reality/);
  assert.match(vlessLink.link, /pbk=client-public/);
  assert.match(vlessLink.link, /sid=abcd/);

  const ssNode = {
    ...node,
    name: 'ss1',
    protocol: 'shadowsocks',
    security: 'none',
    clients: [{ email: 's1', secret: 'ss-pass', flow: '' }]
  };
  const [ssLink] = nodeLinks(ssNode, server);
  assert.match(ssLink.link, /^ss:\/\/YWVzLTI1Ni1nY206c3MtcGFzcw@203\.0\.113\.10:443/);
});

test('builds socks5 inbound and share link', () => {
  const node = {
    id: 'n5',
    name: 'socks1',
    protocol: 'socks',
    port: 1080,
    network: 'tcp',
    security: 'none',
    sni: '',
    path: '',
    cert_file: '',
    key_file: '',
    dest: '',
    server_names: '',
    private_key: '',
    public_key: '',
    short_ids: '',
    enabled: 1,
    clients: [{ email: 'u1', secret: 'pass1', flow: '' }]
  };
  const config = buildXrayConfig([node]);
  const inbound = config.inbounds[0];
  assert.equal(inbound.protocol, 'socks');
  assert.equal(inbound.settings.auth, 'password');
  assert.deepEqual(inbound.settings.accounts, [{ user: 'u1', pass: 'pass1' }]);
  assert.equal(inbound.settings.udp, true);
  const [link] = nodeLinks(node, { host: '203.0.113.10' });
  assert.equal(link.link, 'socks://u1:pass1@203.0.113.10:1080#socks1');
});

test('buildXrayConfig adds routed outbound and inbound routing rule', () => {
  const inbound = {
    id: 'in1',
    name: 'inbound',
    protocol: 'vless',
    port: 10001,
    network: 'tcp',
    security: 'none',
    sni: '',
    path: '',
    cert_file: '',
    key_file: '',
    dest: '',
    server_names: '',
    private_key: '',
    public_key: '',
    short_ids: '',
    enabled: 1,
    role: 'inbound',
    clients: [{ email: 'u1', secret: 'uuid-1', flow: '' }]
  };
  const outbound = {
    id: 'out1',
    name: 'outbound',
    protocol: 'vless',
    port: 20002,
    network: 'tcp',
    security: 'none',
    sni: '',
    path: '',
    cert_file: '',
    key_file: '',
    dest: '',
    server_names: '',
    private_key: '',
    public_key: '',
    short_ids: '',
    enabled: 1,
    role: 'outbound',
    clients: [{ email: 'u2', secret: 'uuid-2', flow: '' }]
  };
  const config = buildXrayConfig([inbound], [
    {
      inbound_node_id: 'in1',
      outbound_node: outbound,
      outbound_server: { host: '203.0.113.20' }
    }
  ]);
  const routed = config.outbounds.find((item) => item.tag === 'out-out1');
  assert.ok(routed);
  assert.equal(routed.settings.vnext[0].address, '203.0.113.20');
  assert.equal(routed.settings.vnext[0].port, 20002);
  assert.deepEqual(
    config.routing.rules.find((rule) => rule.outboundTag === 'out-out1'),
    { type: 'field', inboundTag: ['vless-10001'], outboundTag: 'out-out1' }
  );
});

test('buildXrayConfig routes vless inbound to socks outbound', () => {
  const inbound = {
    id: 'in-socks',
    name: 'inbound',
    protocol: 'vless',
    port: 11443,
    network: 'tcp',
    security: 'reality',
    sni: 'www.apple.com',
    path: '',
    cert_file: '',
    key_file: '',
    dest: 'www.apple.com:443',
    server_names: 'www.apple.com',
    private_key: 'server-private',
    public_key: 'client-public',
    short_ids: '',
    enabled: 1,
    role: 'inbound',
    clients: [{ email: 'u1', secret: 'uuid-1', flow: '' }]
  };
  const outbound = {
    id: 'out-socks',
    name: 'outbound',
    protocol: 'socks',
    port: 8443,
    network: 'tcp',
    security: 'none',
    sni: '',
    path: '',
    cert_file: '',
    key_file: '',
    dest: '',
    server_names: '',
    private_key: '',
    public_key: '',
    short_ids: '',
    enabled: 1,
    role: 'outbound',
    clients: [{ email: 'lllppp', secret: 'lpc187027', flow: '' }]
  };
  const config = buildXrayConfig([inbound], [
    {
      inbound_node_id: 'in-socks',
      outbound_node: outbound,
      outbound_server: { host: '43.212.14.10' }
    }
  ]);
  const routed = config.outbounds.find((item) => item.tag === 'out-out-socks');
  assert.equal(routed.settings.servers[0].address, '43.212.14.10');
  assert.equal(routed.settings.servers[0].port, 8443);
  assert.deepEqual(routed.settings.servers[0].users, [{ user: 'lllppp', pass: 'lpc187027' }]);
});
