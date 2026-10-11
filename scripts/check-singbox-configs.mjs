import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { buildSingboxConfig, generateRealityKeypair } from '../src/singbox.js';

const work = mkdtempSync(join(tmpdir(), 'vps-node-singbox-validation-'));
try {
  const cert = join(work, 'cert.pem');
  const key = join(work, 'key.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-keyout', key, '-out', cert, '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'
  ], { stdio: 'ignore' });

  const pair = generateRealityKeypair();
  const user = { email: 'runner', secret: randomUUID() };
  const base = {
    id: 'smoke', name: 'Smoke', server_id: 'test-vps',
    protocol: 'vless', role: 'inbound', port: 28443,
    network: 'tcp', security: 'reality', enabled: 1,
    sni: 'www.microsoft.com', dest: 'www.microsoft.com:443',
    server_names: 'www.microsoft.com', private_key: pair.privateKey,
    public_key: pair.publicKey, short_ids: '01234567',
    cert_file: cert, key_file: key,
    clients: [user]
  };

  const specs = [
    ['reality-vision', {}],
    ['reality-grpc', { network: 'grpc', path: 'my-grpc' }],
    ['reality-http', { network: 'http', path: '/' }],
    ['hysteria2', { protocol: 'hysteria2', network: 'tcp', security: 'tls' }],
    ['tuic', { protocol: 'tuic', network: 'tcp', security: 'tls' }],
    ['anytls', { protocol: 'anytls', network: 'tcp', security: 'tls' }],
    ['trojan', { protocol: 'trojan', network: 'tcp', security: 'tls' }],
    ['shadowsocks', { protocol: 'shadowsocks', security: 'none', method: 'aes-256-gcm' }],
    ['shadowsocks-2022', { protocol: 'shadowsocks', security: 'none', method: '2022-blake3-aes-128-gcm',
      clients: [{ email: 'ss', secret: randomBytes(16).toString('base64') }] }],
    ['vless-argo-ws', { protocol: 'vless', network: 'ws', tunnel: 1, security: 'none', path: '/ws-smoke' }],
    ['vmess-argo-ws', { protocol: 'vmess', network: 'ws', tunnel: 1, security: 'none', path: '/ws-smoke' }]
  ];

  for (const [name, overrides] of specs) {
    const config = buildSingboxConfig([{ ...base, ...overrides }]);
    const path = join(work, name + '.json');
    writeFileSync(path, JSON.stringify(config, null, 2));
    try {
      const result = execFileSync('sing-box', ['check', '-c', path], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000 });
      process.stdout.write('PASS ' + name + ' ' + result.trim() + '\n');
    } catch (error) {
      process.stderr.write('FAIL ' + name + ': ' + String(error.stderr || error.message) + '\n');
      process.exitCode = 1;
    }
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}
