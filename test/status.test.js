import test from 'node:test';
import assert from 'node:assert/strict';
import { buildStatusRecord, deriveDriftType, deriveServerState } from '../src/status.js';
import { repairActionFor } from '../src/repair.js';

test('deriveServerState covers drift and healthy states', () => {
  assert.equal(deriveServerState(null), 'unknown');
  assert.equal(deriveServerState({ ssh_reachable: 0 }), 'offline');
  assert.equal(deriveServerState({ ssh_reachable: 1, xray_bin_present: 0 }), 'binary_missing');
  assert.equal(deriveServerState({ ssh_reachable: 1, xray_bin_present: 1, config_present: 0 }), 'config_missing');
  assert.equal(deriveServerState({ ssh_reachable: 1, xray_bin_present: 1, config_present: 1, config_match: 0 }), 'config_mismatch');
  assert.equal(deriveServerState({ ssh_reachable: 1, xray_bin_present: 1, config_present: 1, config_match: 1, service_active: 0 }), 'service_stopped');
  assert.equal(deriveServerState({ ssh_reachable: 1, xray_bin_present: 1, config_present: 1, config_match: 1, service_active: 1, ports_listening: 0 }), 'ports_down');
  assert.equal(deriveServerState({ ssh_reachable: 1, xray_bin_present: 1, config_present: 1, config_match: 1, service_active: 1, ports_listening: 1 }), 'running');
});

test('deriveDriftType only reports actual drift', () => {
  const healthy = { ssh_reachable: 1, xray_bin_present: 1, config_present: 1, config_match: 1, service_active: 1, ports_listening: 1 };
  assert.equal(deriveDriftType({ ...healthy, service_active: 0 }), 'service_stopped');
  assert.equal(deriveDriftType({ ssh_reachable: 1, xray_bin_present: 0 }), 'binary_missing');
  assert.equal(deriveDriftType({ ...healthy, config_present: 0 }), 'config_missing');
  assert.equal(deriveDriftType({ ...healthy, config_match: 0 }), 'config_mismatch');
  assert.equal(deriveDriftType(healthy), null);
  assert.equal(deriveDriftType({ ssh_reachable: 0 }), null);
});

test('buildStatusRecord detects config sha mismatch and port state', () => {
  const result = {
    ssh: { connected: true },
    xray: { installed: true, bin_present: true, running: true },
    config: { exists: true, sha256: 'abc' },
    nodes: [
      { id: 'n1', enabled: 1, in_config: true, listening: true },
      { id: 'n2', enabled: 1, in_config: true, listening: false }
    ]
  };

  const matched = buildStatusRecord(result, 'abc');
  assert.equal(matched.ssh_reachable, 1);
  assert.equal(matched.xray_bin_present, 1);
  assert.equal(matched.config_match, 1);
  assert.equal(matched.ports_listening, 0);
  assert.equal(matched.last_error, '');

  const mismatched = buildStatusRecord(result, 'def');
  assert.equal(mismatched.config_match, 0);

  const offline = buildStatusRecord(
    { ssh: { connected: false, error: 'SSH 认证失败：请检查用户名、密码或私钥' } },
    'abc'
  );
  assert.equal(offline.ssh_reachable, 0);
  assert.equal(offline.xray_bin_present, 0);
  assert.equal(offline.config_present, 0);
  assert.equal(offline.config_match, 0);
  assert.match(offline.last_error, /认证失败/);
});

test('repairActionFor maps drift types to remote actions', () => {
  assert.equal(repairActionFor('service_stopped'), 'restart');
  assert.equal(repairActionFor('config_missing'), 'write_config_restart');
  assert.equal(repairActionFor('config_mismatch'), 'write_config_restart');
  assert.equal(repairActionFor('binary_missing'), 'redeploy');
  assert.equal(repairActionFor('offline'), null);
  assert.equal(repairActionFor('running'), null);
});
