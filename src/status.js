import { createHash } from 'node:crypto';
import {
  getNode,
  getServerPublic,
  getServerRecord,
  getServerStatus,
  listNodes,
  listRoutesForServer,
  listServers,
  upsertServerStatus
} from './db.js';
import { xrayStatus } from './remote.js';
import { buildXrayConfig } from './xray.js';

const DEFAULT_INTERVAL_SECONDS = 60;
const DEFAULT_CONCURRENCY = 3;
const MAX_BACKOFF_MS = 30 * 60 * 1000;

export function getStatusIntervalSeconds() {
  const raw = Number(process.env.PANEL_STATUS_INTERVAL);
  return Number.isFinite(raw) && raw >= 5 ? Math.floor(raw) : DEFAULT_INTERVAL_SECONDS;
}

function getConcurrency() {
  const raw = Number(process.env.PANEL_STATUS_CONCURRENCY);
  return Number.isInteger(raw) && raw >= 1 && raw <= 10 ? raw : DEFAULT_CONCURRENCY;
}

export function deriveServerState(status) {
  if (!status) return 'unknown';
  if (!status.ssh_reachable) return 'offline';
  if (!status.xray_bin_present) return 'binary_missing';
  if (!status.config_present) return 'config_missing';
  if (!status.config_match) return 'config_mismatch';
  if (!status.service_active) return 'service_stopped';
  if (!status.ports_listening) return 'ports_down';
  return 'running';
}

const DRIFT_TYPES = ['service_stopped', 'config_missing', 'config_mismatch', 'binary_missing'];

export function deriveDriftType(status) {
  const state = deriveServerState(status);
  return DRIFT_TYPES.includes(state) ? state : null;
}

export function buildStatusRecord(result, expectedSha) {
  const sshReachable = Boolean(result?.ssh?.connected);
  const installed = Boolean(result?.xray?.installed);
  const serviceActive = Boolean(result?.xray?.running);
  const configPresent = Boolean(result?.config?.exists);
  const configMatch = configPresent && Boolean(expectedSha) && result?.config?.sha256 === expectedSha;
  const nodeStatus = Array.isArray(result?.nodes) ? result.nodes : [];
  const enabledNodes = nodeStatus.filter((node) => node.enabled !== 0 && node.enabled !== false);
  const portsListening = enabledNodes.length === 0
    ? 1
    : enabledNodes.every((node) => node.listening) ? 1 : 0;
  const binPresent = Boolean(result?.xray?.bin_present);

  return {
    ssh_reachable: sshReachable ? 1 : 0,
    xray_installed: installed ? 1 : 0,
    xray_bin_present: binPresent ? 1 : 0,
    service_active: serviceActive ? 1 : 0,
    config_present: configPresent ? 1 : 0,
    config_match: configMatch ? 1 : 0,
    ports_listening: portsListening ? 1 : 0,
    last_checked_at: result?.checked_at || new Date().toISOString(),
    last_error: sshReachable ? '' : (result?.ssh?.error || 'SSH 不可达'),
    node_status: nodeStatus
  };
}

export function expectedConfigSha256(serverId) {
  const nodes = listNodes(serverId);
  const routes = listRoutesForServer(serverId).map((route) => {
    const outboundNode = getNode(route.outbound_node_id);
    return {
      ...route,
      outbound_node: outboundNode,
      outbound_server: outboundNode ? getServerPublic(outboundNode.server_id) : null
    };
  }).filter((route) => route.outbound_node && route.outbound_server);
  const config = buildXrayConfig(nodes, routes);
  return createHash('sha256').update(JSON.stringify(config, null, 2)).digest('hex');
}

let timer = null;
let stopping = false;
let active = 0;
const queue = [];
const inFlight = new Set();

function enqueue(task) {
  queue.push(task);
  drain();
}

function drain() {
  while (active < getConcurrency() && queue.length > 0) {
    const task = queue.shift();
    active += 1;
    task().catch(() => {}).finally(() => {
      active -= 1;
      drain();
    });
  }
}

function nextCheckFor(cached, failed) {
  const intervalMs = getStatusIntervalSeconds() * 1000;
  const failures = (cached?.failure_count || 0) + (failed ? 1 : 0);
  const delayMs = failed
    ? Math.min(intervalMs * (2 ** (failures - 1)), MAX_BACKOFF_MS)
    : intervalMs;
  return { failures, nextCheckAt: new Date(Date.now() + delayMs).toISOString() };
}

async function checkServer(server) {
  if (inFlight.has(server.id)) return;
  inFlight.add(server.id);
  const cached = getServerStatus(server.id);
  const previousState = deriveServerState(cached);
  let result = null;
  let thrownError = '';
  try {
    const record = getServerRecord(server.id);
    if (!record) return;
    result = await xrayStatus(record, listNodes(server.id), { timeout: 15000 });
  } catch (error) {
    thrownError = error?.message || String(error);
  } finally {
    inFlight.delete(server.id);
  }

  const failed = !result?.ok || !result?.ssh?.connected;
  const { failures, nextCheckAt } = nextCheckFor(cached, failed);

  const record = failed
    ? {
        ssh_reachable: 0,
        xray_installed: 0,
        xray_bin_present: 0,
        service_active: 0,
        config_present: 0,
        config_match: 0,
        ports_listening: 0,
        last_checked_at: new Date().toISOString(),
        last_error: result?.ssh?.error || thrownError || 'SSH 检查失败',
        node_status: []
      }
    : buildStatusRecord(result, expectedConfigSha256(server.id));

  upsertServerStatus(server.id, {
    ...record,
    failure_count: failures,
    next_check_at: nextCheckAt
  });

  const currentState = deriveServerState(record);
  if (failed || currentState !== previousState) {
    console.log(`[status] server=${server.name} (${server.host}) state=${currentState}${failed ? ` error=${record.last_error}` : ''}`);
  }
}

function runTick() {
  if (stopping) return;
  const now = Date.now();
  listServers().forEach((server, index) => {
    const cached = getServerStatus(server.id);
    if (cached?.next_check_at && new Date(cached.next_check_at).getTime() > now) return;
    const delay = cached ? 0 : Math.min(index * 750, 6000);
    setTimeout(() => {
      if (stopping) return;
      enqueue(() => checkServer(server));
    }, delay);
  });
}

export function startStatusSweeper() {
  if (timer) return timer;
  stopping = false;
  runTick();
  const intervalMs = getStatusIntervalSeconds() * 1000;
  timer = setInterval(runTick, intervalMs);
  if (timer.unref) timer.unref();
  console.log(`[status] sweeper started interval=${getStatusIntervalSeconds()}s concurrency=${getConcurrency()}`);
  return timer;
}

export function stopStatusSweeper() {
  stopping = true;
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}
