import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCertificateScript,
  buildCloudflaredInstallScript,
  buildNginxConfig,
  certPathFor,
  needsSelfSignedCert,
  tunnelRequired,
  withSelfSignedPaths
} from '../src/argo.js';

const tunnelNode = {
  id: 't1',
  name: 'argo-ws',
  protocol: 'vless',
  port: 30000,
  network: 'ws',
  path: '/argox-vl',
  tunnel: 1,
  enabled: 1,
  clients: [{ email: 'u1', secret: 'uuid-1', flow: '' }]
};

test('nginx config routes tunnel ws nodes to local xray ports', () => {
  const server = { host: '203.0.113.10', nginx_port: 0, argo_mode: 'quick' };
  const config = buildNginxConfig(server, [tunnelNode]);
  assert.match(config, /listen 8080;/);
  assert.match(config, /location \^~ \/argox-vl/);
  assert.match(config, /proxy_pass http:\/\/127\.0\.0\.1:30000;/);
  assert.match(config, /proxy_set_header Upgrade \$http_upgrade;/);
  assert.doesNotMatch(config, /server_name localhost/);
});

test('nginx config skips non tunnel nodes', () => {
  const server = { host: '203.0.113.10', nginx_port: 18080, argo_mode: 'quick' };
  const direct = { ...tunnelNode, tunnel: 0 };
  const config = buildNginxConfig(server, [direct]);
  assert.match(config, /listen 18080;/);
  assert.doesNotMatch(config, /location/);
});

test('tunnelRequired follows the node tunnel flag', () => {
  assert.equal(tunnelRequired({}, [{ ...tunnelNode, tunnel: 1 }]), true);
  assert.equal(tunnelRequired({}, [{ ...tunnelNode, tunnel: 0 }]), false);
  assert.equal(tunnelRequired({}, []), false);
});

test('self signed helpers fill certificate paths', () => {
  const hy2 = { protocol: 'hysteria2', self_signed: 0, cert_file: '', key_file: '' };
  assert.equal(needsSelfSignedCert([hy2]), true);
  const [patched] = withSelfSignedPaths([hy2]);
  assert.equal(patched.cert_file, certPathFor(hy2).certFile);
  assert.equal(patched.key_file, certPathFor(hy2).keyFile);
});

test('certificate script creates a long lived self signed pair', () => {
  const script = buildCertificateScript('/tmp/cert.pem', '/tmp/key.pem', 'example.com');
  assert.match(script, /openssl ecparam/);
  assert.match(script, /-days 36500/);
  assert.match(script, /DNS = example\.com/);
});

test('cloudflared script starts a quick tunnel pointed at nginx', () => {
  const quick = buildCloudflaredInstallScript({ nginx_port: 8080 }, [tunnelNode]);
  assert.match(quick, /--url http:\/\/localhost:8080/);
  assert.match(quick, /--metrics 127\.0\.0\.1:49312/);
  assert.doesNotMatch(quick, /tunnel\.yml/);
  assert.doesNotMatch(quick, /cloudflared\.env/);
});

test('cloudflared script stops argo service when tunnel is disabled', () => {
  const script = buildCloudflaredInstallScript({}, [{ ...tunnelNode, tunnel: 0 }]);
  assert.match(script, /CLOUDFLARED_MODE=none/);
  assert.match(script, /systemctl stop argo/);
});
