import { addRepairLog, getNode, getServerPublic, listNodes, listRoutesForServer } from './db.js';
import { deployServer, restartXray, writeXrayConfig } from './remote.js';

const DRIFT_ACTIONS = {
  service_stopped: 'restart',
  config_missing: 'write_config_restart',
  config_mismatch: 'write_config_restart',
  binary_missing: 'redeploy'
};

export function repairActionFor(driftType) {
  return DRIFT_ACTIONS[driftType] || null;
}

export function routesForServer(serverId) {
  return listRoutesForServer(serverId).map((route) => {
    const outboundNode = getNode(route.outbound_node_id);
    return {
      ...route,
      outbound_node: outboundNode,
      outbound_server: outboundNode ? getServerPublic(outboundNode.server_id) : null
    };
  }).filter((route) => route.outbound_node && route.outbound_server);
}

export async function performRepair(server, driftType) {
  const action = repairActionFor(driftType);
  if (!action) {
    const error = new Error(`unsupported drift type: ${driftType}`);
    error.status = 400;
    throw error;
  }

  const startedAt = Date.now();
  try {
    let result;
    if (action === 'restart') {
      result = await restartXray(server);
    } else if (action === 'write_config_restart') {
      const nodes = listNodes(server.id);
      const routes = routesForServer(server.id);
      await writeXrayConfig(server, nodes, routes);
      result = await restartXray(server);
    } else {
      const nodes = listNodes(server.id);
      const routes = routesForServer(server.id);
      result = await deployServer(server, nodes, { routes });
    }
    const log = addRepairLog({
      server_id: server.id,
      server_name: server.name,
      drift_type: driftType,
      action,
      result: 'ok',
      success: 1
    });
    return {
      ok: true,
      drift_type: driftType,
      action,
      elapsed_ms: Date.now() - startedAt,
      log,
      result
    };
  } catch (error) {
    const message = error?.message || String(error);
    const log = addRepairLog({
      server_id: server.id,
      server_name: server.name,
      drift_type: driftType,
      action,
      result: message,
      success: 0
    });
    return {
      ok: false,
      drift_type: driftType,
      action,
      elapsed_ms: Date.now() - startedAt,
      log,
      error: message
    };
  }
}
