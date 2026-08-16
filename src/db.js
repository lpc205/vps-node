import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { dataDir } from './paths.js';
import { decryptText, encryptText, newId } from './crypto.js';
import { canUseReality } from './xray.js';
import { createSubscriptionToken, hashSubscriptionToken, subscriptionTokenPrefix } from './subscription-token.js';

mkdirSync(dataDir, { recursive: true });
const db = new DatabaseSync(join(dataDir, 'panel.db'));

export function closeDatabase() {
  db.close();
}

db.exec(`
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS servers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 22,
  username TEXT NOT NULL,
  auth_type TEXT NOT NULL DEFAULT 'password',
  password TEXT NOT NULL DEFAULT '',
  private_key TEXT NOT NULL DEFAULT '',
  passphrase TEXT NOT NULL DEFAULT '',
  sudo_password TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'inbound',
  port INTEGER NOT NULL,
  network TEXT NOT NULL DEFAULT 'tcp',
  security TEXT NOT NULL DEFAULT 'none',
  sni TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  cert_file TEXT NOT NULL DEFAULT '',
  key_file TEXT NOT NULL DEFAULT '',
  dest TEXT NOT NULL DEFAULT '',
  server_names TEXT NOT NULL DEFAULT '',
  private_key TEXT NOT NULL DEFAULT '',
  public_key TEXT NOT NULL DEFAULT '',
  short_ids TEXT NOT NULL DEFAULT '',
  clients_json TEXT NOT NULL DEFAULT '[]',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nodes_server ON nodes(server_id);

CREATE TABLE IF NOT EXISTS routes (
  id TEXT PRIMARY KEY,
  inbound_node_id TEXT NOT NULL,
  outbound_node_id TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(inbound_node_id)
);

CREATE INDEX IF NOT EXISTS idx_routes_inbound ON routes(inbound_node_id);
CREATE INDEX IF NOT EXISTS idx_routes_outbound ON routes(outbound_node_id);

CREATE TABLE IF NOT EXISTS server_status (
  server_id TEXT PRIMARY KEY,
  ssh_reachable INTEGER NOT NULL DEFAULT 0,
  xray_bin_present INTEGER NOT NULL DEFAULT 0,
  xray_installed INTEGER NOT NULL DEFAULT 0,
  service_active INTEGER NOT NULL DEFAULT 0,
  config_present INTEGER NOT NULL DEFAULT 0,
  config_match INTEGER NOT NULL DEFAULT 0,
  ports_listening INTEGER NOT NULL DEFAULT 0,
  last_checked_at TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  node_status_json TEXT NOT NULL DEFAULT '[]',
  failure_count INTEGER NOT NULL DEFAULT 0,
  next_check_at TEXT,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS repair_logs (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL,
  server_name TEXT NOT NULL DEFAULT '',
  drift_type TEXT NOT NULL,
  action TEXT NOT NULL,
  result TEXT NOT NULL DEFAULT '',
  success INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_repair_logs_server ON repair_logs(server_id);
CREATE INDEX IF NOT EXISTS idx_repair_logs_created ON repair_logs(created_at);

CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  token_prefix TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  default_format TEXT NOT NULL DEFAULT 'base64',
  expires_at TEXT,
  last_access_at TEXT,
  access_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_updated ON subscriptions(updated_at);
`);

const nodeColumns = db.prepare('PRAGMA table_info(nodes)').all();
if (!nodeColumns.some((column) => column.name === 'role')) {
  db.exec("ALTER TABLE nodes ADD COLUMN role TEXT NOT NULL DEFAULT 'inbound'");
}
if (!nodeColumns.some((column) => column.name === 'method')) {
  db.exec("ALTER TABLE nodes ADD COLUMN method TEXT NOT NULL DEFAULT 'aes-256-gcm'");
}
if (!nodeColumns.some((column) => column.name === 'ss_network')) {
  db.exec("ALTER TABLE nodes ADD COLUMN ss_network TEXT NOT NULL DEFAULT 'tcp'");
}

const statusColumns = db.prepare('PRAGMA table_info(server_status)').all();
if (!statusColumns.some((column) => column.name === 'xray_bin_present')) {
  db.exec('ALTER TABLE server_status ADD COLUMN xray_bin_present INTEGER NOT NULL DEFAULT 0');
  db.exec('UPDATE server_status SET xray_bin_present = xray_installed');
}
db.exec('UPDATE server_status SET xray_bin_present = xray_installed WHERE xray_bin_present = 0 AND xray_installed = 1');

const now = () => new Date().toISOString();

function publicServer(row) {
  if (!row) return null;
  const { password, private_key, passphrase, sudo_password, ...safe } = row;
  return {
    ...safe,
    has_password: Boolean(password),
    has_private_key: Boolean(private_key),
    has_passphrase: Boolean(passphrase),
    has_sudo_password: Boolean(sudo_password)
  };
}

function parseNode(row) {
  if (!row) return null;
  return { ...row, clients: JSON.parse(row.clients_json || '[]') };
}

export function listServers() {
  return db.prepare('SELECT * FROM servers ORDER BY created_at DESC').all().map(publicServer);
}

export function getServerRecord(id) {
  return db.prepare('SELECT * FROM servers WHERE id = ?').get(id) || null;
}

export function getServerPublic(id) {
  return publicServer(getServerRecord(id));
}

export function saveServer(input, id = null) {
  const existing = id ? getServerRecord(id) : null;
  const timestamp = now();
  const authType = input.auth_type === 'key' ? 'key' : 'password';
  const password = authType === 'password'
    ? (input.password ? encryptText(input.password) : (existing && !input.clear_password ? existing.password : ''))
    : '';
  const privateKey = authType === 'key'
    ? (input.private_key ? encryptText(input.private_key) : (existing && !input.clear_private_key ? existing.private_key : ''))
    : '';
  const passphrase = authType === 'key'
    ? (input.passphrase ? encryptText(input.passphrase) : (existing && !input.clear_passphrase ? existing.passphrase : ''))
    : '';
  const sudoPassword = input.sudo_password
    ? encryptText(input.sudo_password)
    : (existing && !input.clear_sudo_password ? existing.sudo_password : '');

  const data = {
    name: String(input.name || '').trim(),
    host: String(input.host || '').trim(),
    port: Number(input.port || 22),
    username: String(input.username || '').trim(),
    auth_type: authType,
    password,
    private_key: privateKey,
    passphrase,
    sudo_password: sudoPassword,
    notes: String(input.notes || '').trim()
  };

  if (!data.name || !data.host || !data.username) {
    const error = new Error('name, host and username are required');
    error.status = 400;
    throw error;
  }
  if (!Number.isInteger(data.port) || data.port < 1 || data.port > 65535) {
    const error = new Error('port must be between 1 and 65535');
    error.status = 400;
    throw error;
  }
  if (authType === 'key' && !data.private_key) {
    const error = new Error('private key is required for key auth');
    error.status = 400;
    throw error;
  }

  if (existing) {
    db.prepare(`
      UPDATE servers SET
        name = ?, host = ?, port = ?, username = ?, auth_type = ?,
        password = ?, private_key = ?, passphrase = ?, sudo_password = ?,
        notes = ?, updated_at = ?
      WHERE id = ?
    `).run(data.name, data.host, data.port, data.username, data.auth_type,
      data.password, data.private_key, data.passphrase, data.sudo_password,
      data.notes, timestamp, id);
    return getServerPublic(id);
  }

  const serverId = newId();
  db.prepare(`
    INSERT INTO servers
      (id, name, host, port, username, auth_type, password, private_key, passphrase, sudo_password, notes, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(serverId, data.name, data.host, data.port, data.username, data.auth_type,
    data.password, data.private_key, data.passphrase, data.sudo_password,
    data.notes, timestamp, timestamp);
  return getServerPublic(serverId);
}

export function deleteServer(id) {
  const tx = db.exec('BEGIN');
  try {
    db.prepare(`
      DELETE FROM routes
      WHERE inbound_node_id IN (SELECT id FROM nodes WHERE server_id = ?)
         OR outbound_node_id IN (SELECT id FROM nodes WHERE server_id = ?)
    `).run(id, id);
    db.prepare('DELETE FROM nodes WHERE server_id = ?').run(id);
    db.prepare('DELETE FROM server_status WHERE server_id = ?').run(id);
    db.prepare('DELETE FROM repair_logs WHERE server_id = ?').run(id);
    const result = db.prepare('DELETE FROM servers WHERE id = ?').run(id);
    db.exec('COMMIT');
    return result.changes > 0;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

export function listNodes(serverId) {
  return db.prepare('SELECT * FROM nodes WHERE server_id = ? ORDER BY port ASC').all(serverId).map(parseNode);
}

export function getNode(id) {
  return parseNode(db.prepare('SELECT * FROM nodes WHERE id = ?').get(id));
}

function normalizeClients(input) {
  const VMESS_SECURITIES = ['auto', 'aes-128-gcm', 'chacha20-poly1305'];
  const clients = Array.isArray(input) && input.length > 0
    ? input.map((client) => ({
        email: String(client.email || '').trim(),
        secret: String(client.secret || '').trim(),
        flow: String(client.flow || '').trim(),
        security: VMESS_SECURITIES.includes(client.security) ? client.security : 'auto'
      }))
    : [{ email: '', secret: newId(), flow: '', security: 'auto' }];
  return clients.map((client) => ({
    ...client,
    secret: client.secret || newId(),
    flow: client.flow || '',
    security: client.security || 'auto'
  }));
}
export function saveNode(input, id = null) {
  const existing = id ? getNode(id) : null;
  const timestamp = now();
  const protocol = String(input.protocol || '').trim();
  const role = input.role === 'outbound' ? 'outbound' : 'inbound';
  const network = String(input.network || 'tcp').trim();
  const security = String(input.security || 'none').trim();
  const port = Number(input.port);
  const SS_METHODS = [
    'aes-128-gcm',
    'aes-256-gcm',
    'chacha20-poly1305',
    'chacha20-ietf-poly1305',
    'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm',
    '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305'
  ];
  const method = protocol === 'shadowsocks' && SS_METHODS.includes(String(input.method || '')) ? String(input.method) : 'aes-256-gcm';
  const ssNetwork = protocol === 'shadowsocks' && ['tcp', 'udp', 'tcp,udp'].includes(String(input.ss_network || '')) ? String(input.ss_network) : 'tcp';

  if (!['vmess', 'vless', 'trojan', 'shadowsocks', 'socks'].includes(protocol)) {
    const error = new Error('unsupported protocol');
    error.status = 400;
    throw error;
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    const error = new Error('port must be between 1 and 65535');
    error.status = 400;
    throw error;
  }
  if (!['tcp', 'ws', 'grpc', 'httpupgrade'].includes(network)) {
    const error = new Error('unsupported network');
    error.status = 400;
    throw error;
  }
  if (!['none', 'tls', 'reality'].includes(security)) {
    const error = new Error('unsupported security');
    error.status = 400;
    throw error;
  }
  if (security === 'reality' && !canUseReality(protocol, network)) {
    const error = new Error('reality is only supported for vless on tcp, grpc or httpupgrade');
    error.status = 400;
    throw error;
  }

  const data = {
    name: String(input.name || '').trim(),
    protocol,
    role,
    network,
    security,
    port,
    method,
    ss_network: ssNetwork,
    sni: String(input.sni || input.server_name || '').trim(),
    path: String(input.path || '').trim(),
    cert_file: String(input.cert_file || '').trim(),
    key_file: String(input.key_file || '').trim(),
    dest: String(input.dest || '').trim(),
    server_names: String(input.server_names || '').trim(),
    private_key: String(input.private_key || '').trim(),
    public_key: String(input.public_key || '').trim(),
    short_ids: String(input.short_ids || '').trim(),
    clients_json: JSON.stringify(normalizeClients(input.clients)),
    enabled: input.enabled === false || input.enabled === 0 ? 0 : 1
  };

  if (!data.name) {
    const error = new Error('node name is required');
    error.status = 400;
    throw error;
  }

  if (existing) {
    if (existing.role !== data.role) {
      db.prepare('DELETE FROM routes WHERE inbound_node_id = ? OR outbound_node_id = ?').run(id, id);
    }
    db.prepare(`
      UPDATE nodes SET
        server_id = ?, name = ?, protocol = ?, role = ?, port = ?, network = ?,
        security = ?, method = ?, ss_network = ?, sni = ?, path = ?,
        cert_file = ?, key_file = ?, dest = ?, server_names = ?, private_key = ?,
        short_ids = ?, public_key = ?,
        clients_json = ?, enabled = ?, updated_at = ?
      WHERE id = ?
    `).run(existing.server_id, data.name, data.protocol, data.role, data.port, data.network,
      data.security, data.method, data.ss_network, data.sni, data.path,
      data.cert_file, data.key_file, data.dest, data.server_names, data.private_key,
      data.short_ids, data.public_key,
      data.clients_json, data.enabled, timestamp, id);
    return getNode(id);
  }

  const nodeId = newId();
  db.prepare(`
    INSERT INTO nodes
      (id, server_id, name, protocol, role, port, network, security, method,
       ss_network, sni, path, cert_file, key_file, dest, server_names,
       private_key, short_ids, public_key,
       clients_json, enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(nodeId, input.server_id, data.name, data.protocol, data.role, data.port, data.network,
    data.security, data.method, data.ss_network, data.sni, data.path,
    data.cert_file, data.key_file, data.dest, data.server_names,
    data.private_key, data.short_ids, data.public_key,
    data.clients_json, data.enabled, timestamp, timestamp);
  return getNode(nodeId);
}

export function deleteNode(id) {
  const tx = db.exec('BEGIN');
  try {
    db.prepare('DELETE FROM routes WHERE inbound_node_id = ? OR outbound_node_id = ?').run(id, id);
    const result = db.prepare('DELETE FROM nodes WHERE id = ?').run(id);
    db.exec('COMMIT');
    return result.changes > 0;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

function publicSubscription(row, nodeCount = null) {
  if (!row) return null;
  const { token_hash, ...safe } = row;
  const result = {
    ...safe,
    enabled: Boolean(row.enabled),
    access_count: Number(row.access_count || 0)
  };
  if (nodeCount !== null) result.node_count = Number(nodeCount || 0);
  return result;
}

function subscriptionNodeCount() {
  return db.prepare(`
    SELECT COUNT(*) AS count
    FROM nodes
    WHERE role = 'inbound' AND enabled = 1
  `).get().count;
}

function normalizeSubscriptionInput(input = {}) {
  const name = String(input.name || '').trim();
  const defaultFormat = input.default_format === 'uri' ? 'uri' : 'base64';
  const expiresAt = input.expires_at ? String(input.expires_at).trim() : null;
  if (!name) {
    const error = new Error('subscription name is required');
    error.status = 400;
    throw error;
  }
  if (expiresAt && !Number.isFinite(Date.parse(expiresAt))) {
    const error = new Error('expires_at must be a valid date');
    error.status = 400;
    throw error;
  }
  return {
    name,
    enabled: input.enabled === false || input.enabled === 0 ? 0 : 1,
    default_format: defaultFormat,
    expires_at: expiresAt
  };
}

export function listSubscriptions() {
  const count = subscriptionNodeCount();
  return db.prepare('SELECT * FROM subscriptions ORDER BY created_at DESC').all()
    .map((row) => publicSubscription(row, count));
}

export function getSubscription(id) {
  const row = db.prepare('SELECT * FROM subscriptions WHERE id = ?').get(id) || null;
  return publicSubscription(row, subscriptionNodeCount());
}

export function getSubscriptionRecord(id) {
  return db.prepare('SELECT * FROM subscriptions WHERE id = ?').get(id) || null;
}

export function getSubscriptionByTokenHash(tokenHash) {
  return db.prepare('SELECT * FROM subscriptions WHERE token_hash = ?').get(tokenHash) || null;
}

export function createSubscription(input = {}) {
  const data = normalizeSubscriptionInput(input);
  const id = newId();
  const token = createSubscriptionToken();
  const timestamp = now();
  db.prepare(`
    INSERT INTO subscriptions
      (id, name, token_hash, token_prefix, enabled, default_format, expires_at,
       last_access_at, access_count, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, data.name, hashSubscriptionToken(token), subscriptionTokenPrefix(token),
    data.enabled, data.default_format, data.expires_at, null, 0, timestamp, timestamp);
  return { subscription: getSubscription(id), token };
}

export function updateSubscription(id, input = {}) {
  const existing = getSubscriptionRecord(id);
  if (!existing) return null;
  const data = normalizeSubscriptionInput(input);
  db.prepare(`
    UPDATE subscriptions SET
      name = ?, enabled = ?, default_format = ?, expires_at = ?, updated_at = ?
    WHERE id = ?
  `).run(data.name, data.enabled, data.default_format, data.expires_at, now(), id);
  return getSubscription(id);
}

export function rotateSubscription(id) {
  const existing = getSubscriptionRecord(id);
  if (!existing) return null;
  const token = createSubscriptionToken();
  db.prepare(`
    UPDATE subscriptions SET token_hash = ?, token_prefix = ?, updated_at = ?
    WHERE id = ?
  `).run(hashSubscriptionToken(token), subscriptionTokenPrefix(token), now(), id);
  return { subscription: getSubscription(id), token };
}

export function setSubscriptionEnabled(id, enabled) {
  const existing = getSubscriptionRecord(id);
  if (!existing) return null;
  db.prepare('UPDATE subscriptions SET enabled = ?, updated_at = ? WHERE id = ?')
    .run(enabled ? 1 : 0, now(), id);
  return getSubscription(id);
}

export function deleteSubscription(id) {
  return db.prepare('DELETE FROM subscriptions WHERE id = ?').run(id).changes > 0;
}

export function touchSubscriptionAccess(id) {
  const timestamp = now();
  db.prepare(`
    UPDATE subscriptions
    SET last_access_at = ?, access_count = access_count + 1
    WHERE id = ?
  `).run(timestamp, id);
  return getSubscriptionRecord(id);
}

export function getStats() {
  const serverCount = db.prepare('SELECT COUNT(*) AS count FROM servers').get().count;
  const nodeCount = db.prepare('SELECT COUNT(*) AS count FROM nodes').get().count;
  const enabledCount = db.prepare('SELECT COUNT(*) AS count FROM nodes WHERE enabled = 1').get().count;
  return { servers: serverCount, nodes: nodeCount, enabledNodes: enabledCount };
}

export function listServerStatuses() {
  return db.prepare('SELECT * FROM server_status').all().map((row) => ({
    ...row,
    node_status: JSON.parse(row.node_status_json || '[]')
  }));
}

export function getServerStatus(serverId) {
  const row = db.prepare('SELECT * FROM server_status WHERE server_id = ?').get(serverId) || null;
  if (!row) return null;
  return { ...row, node_status: JSON.parse(row.node_status_json || '[]') };
}

export function upsertServerStatus(serverId, status) {
  const timestamp = now();
  const data = {
    ssh_reachable: status.ssh_reachable ? 1 : 0,
    xray_installed: status.xray_installed ? 1 : 0,
    xray_bin_present: status.xray_bin_present ? 1 : 0,
    service_active: status.service_active ? 1 : 0,
    config_present: status.config_present ? 1 : 0,
    config_match: status.config_match ? 1 : 0,
    ports_listening: status.ports_listening ? 1 : 0,
    last_checked_at: status.last_checked_at || timestamp,
    last_error: String(status.last_error || ''),
    node_status_json: JSON.stringify(status.node_status || []),
    failure_count: Number(status.failure_count) || 0,
    next_check_at: status.next_check_at || '',
    updated_at: timestamp
  };
  db.prepare(`
    INSERT INTO server_status (
      server_id, ssh_reachable, xray_installed, xray_bin_present, service_active, config_present,
      config_match, ports_listening, last_checked_at, last_error, node_status_json,
      failure_count, next_check_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(server_id) DO UPDATE SET
      ssh_reachable = excluded.ssh_reachable,
      xray_installed = excluded.xray_installed,
      xray_bin_present = excluded.xray_bin_present,
      service_active = excluded.service_active,
      config_present = excluded.config_present,
      config_match = excluded.config_match,
      ports_listening = excluded.ports_listening,
      last_checked_at = excluded.last_checked_at,
      last_error = excluded.last_error,
      node_status_json = excluded.node_status_json,
      failure_count = excluded.failure_count,
      next_check_at = excluded.next_check_at,
      updated_at = excluded.updated_at
  `).run(serverId, data.ssh_reachable, data.xray_installed, data.xray_bin_present, data.service_active, data.config_present,
    data.config_match, data.ports_listening, data.last_checked_at, data.last_error, data.node_status_json,
    data.failure_count, data.next_check_at, data.updated_at);
  return getServerStatus(serverId);
}

export function addRepairLog(entry) {
  const id = newId();
  const timestamp = now();
  db.prepare(`
    INSERT INTO repair_logs
      (id, server_id, server_name, drift_type, action, result, success, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, entry.server_id, String(entry.server_name || ''), String(entry.drift_type || ''),
    String(entry.action || ''), String(entry.result || ''), entry.success ? 1 : 0, timestamp);
  return db.prepare('SELECT * FROM repair_logs WHERE id = ?').get(id);
}

export function listRepairLogs(limit = 100) {
  const count = Number.isInteger(limit) ? Math.max(1, Math.min(limit, 500)) : 100;
  return db.prepare('SELECT * FROM repair_logs ORDER BY created_at DESC LIMIT ?').all(count);
}

export function listRoutes() {
  return db.prepare('SELECT * FROM routes ORDER BY created_at DESC').all();
}

export function getRoute(id) {
  return db.prepare('SELECT * FROM routes WHERE id = ?').get(id) || null;
}

export function listRoutesForServer(serverId) {
  return db.prepare(`
    SELECT r.* FROM routes r
    JOIN nodes n ON n.id = r.inbound_node_id
    WHERE n.server_id = ?
    ORDER BY r.created_at DESC
  `).all(serverId);
}

export function saveRoute(input) {
  const inboundNode = getNode(String(input.inbound_node_id || '').trim());
  const outboundNode = getNode(String(input.outbound_node_id || '').trim());
  if (!inboundNode || !outboundNode) {
    const error = new Error('inbound and outbound nodes are required');
    error.status = 400;
    throw error;
  }
  if (inboundNode.id === outboundNode.id) {
    const error = new Error('inbound and outbound nodes must be different');
    error.status = 400;
    throw error;
  }
  if (inboundNode.role !== 'inbound') {
    const error = new Error('selected inbound node is not marked as inbound');
    error.status = 400;
    throw error;
  }
  if (outboundNode.role !== 'outbound') {
    const error = new Error('selected outbound node is not marked as outbound');
    error.status = 400;
    throw error;
  }

  const existing = db.prepare('SELECT * FROM routes WHERE inbound_node_id = ?').get(inboundNode.id);
  const timestamp = now();
  if (existing) {
    db.prepare('UPDATE routes SET outbound_node_id = ?, enabled = 1, updated_at = ? WHERE id = ?')
      .run(outboundNode.id, timestamp, existing.id);
    return getRoute(existing.id);
  }

  const routeId = newId();
  db.prepare(`
    INSERT INTO routes
      (id, inbound_node_id, outbound_node_id, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `).run(routeId, inboundNode.id, outboundNode.id, timestamp, timestamp);
  return getRoute(routeId);
}

export function deleteRoute(id) {
  return db.prepare('DELETE FROM routes WHERE id = ?').run(id).changes > 0;
}

export function listAllNodes() {
  return db.prepare(`
    SELECT n.*, s.name AS server_name, s.host AS server_host
    FROM nodes n JOIN servers s ON s.id = n.server_id
    ORDER BY n.created_at DESC
  `).all().map(parseNode);
}
