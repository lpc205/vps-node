import { randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildSingboxConfig, generateRealityKeypair } from '../../src/singbox.js';

const target = process.argv[2];
if (!target) throw new Error('Usage: node test/fixtures/generate-singbox-fixtures.mjs <output-dir>');
mkdirSync(target, { recursive: true });
const pair = generateRealityKeypair();
const cert = join(target, 'cert.pem');
const key = join(target, 'key.pem');
const base = {
  id: 'inbound', name: 'fixture', server_id: 'local',
  protocol: 'vless', role: 'inbound', port: 23456, enabled: 1,
  network: 'tcp', security: 'reality',
  dest: 'www.microsoft.com:443', server_names: 'www.microsoft.com',
  sni: 'www.microsoft.com', private_key: pair.privateKey, public_key: pair.publicKey,
  short_ids: '0123456789abcdef',
  cert_file: cert, key_file: key,
  clients: [{ email: 'fixture', secret: randomUUID() }]
};
const configs = new Map([
  ['vless-reality-vision', { ...base }],
  ['vless-grpc-reality', { ...base, network: 'grpc', path: 'grpc-fixture' }],
  ['vless-http-reality', { ...base, network: 'http', path: '/fixture' }],
  ['hysteria2', { ...base, protocol: 'hysteria2', security: 'tls', network: 'tcp', hy2_up: 200, hy2_down: 400 }],
  ['tuic', { ...base, protocol: 'tuic', security: 'tls', network: 'tcp' }],
  ['anytls', { ...base, protocol: 'anytls', security: 'tls', network: 'tcp' }],
  ['trojan', { ...base, protocol: 'trojan', security: 'tls', network: 'tcp' }],
  ['shadowsocks-2022', { ...base, protocol: 'shadowsocks', security: 'none', network: 'tcp',
    method: '2022-blake3-aes-128-gcm',
    clients: [{ email: 'fixture', secret: randomBytes(16).toString('base64') }] }],
  ['vless-argo-ws', { ...base, protocol: 'vless', security: 'none', network: 'ws', path: '/ws-fixture', tunnel: 1 }],
  ['vmess-argo-ws', { ...base, protocol: 'vmess', security: 'none', network: 'ws', path: '/ws-fixture', tunnel: 1 }]
]);
for (const [name, node] of configs) {
  const config = buildSingboxConfig([node]);
  writeFileSync(join(target, `${name}.json`), JSON.stringify(config, null, 2));
}
const inbound = configs.get('vless-reality-vision');
const outbound = {
  ...configs.get('shadowsocks-2022'), id: 'remote', role: 'outbound', port: 34201
};
const routed = buildSingboxConfig([inbound], [{
  inbound_node_id: inbound.id, outbound_node: outbound,
  outbound_server: { host: '203.0.113.10' }
}]);
writeFileSync(join(target, 'routed.json'), JSON.stringify(routed, null, 2));
console.log(`Generated ${configs.size + 1} configs for sing-box check`);
