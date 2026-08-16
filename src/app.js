import express from 'express';
import QRCode from 'qrcode';
import { dirname, join } from 'node:path';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  deleteNode,
  deleteRoute,
  deleteServer,
  getNode,
  getServerPublic,
  getServerRecord,
  getStats,
  getServerStatus,
  listAllNodes,
  listNodes,
  listRoutes,
  listRoutesForServer,
  listServers,
  listServerStatuses,
  listRepairLogs,
  createSubscription,
  deleteSubscription,
  getSubscription,
  listSubscriptions,
  rotateSubscription,
  saveNode,
  saveRoute,
  saveServer,
  setSubscriptionEnabled,
  updateSubscription
} from './db.js';
import { deployServer, installXray, probeServer, restartXray, xrayLogs, xrayStatus } from './remote.js';
import { deriveServerState, getStatusIntervalSeconds } from './status.js';
import { deriveDriftType } from './status.js';
import { performRepair, routesForServer } from './repair.js';
import { generateRealityKeypair, nodeLinks } from './xray.js';
import {
  buildSubscriptionNodes,
  isSubscriptionExpired,
  markSubscriptionAccess,
  renderBase64Subscription,
  renderUriList,
  resolvePublicSubscription,
  subscriptionContent
} from './subscriptions.js';

const here = dirname(fileURLToPath(import.meta.url));

const DRIFT_REASONS = {
  service_stopped: 'Xray 服务未运行',
  config_missing: 'config.json 不存在',
  config_mismatch: 'config.json 与面板期望不一致',
  binary_missing: '/usr/local/bin/xray 不存在'
};
const publicDir = join(here, '..', 'public');
const lucidePath = join(here, '..', 'node_modules', 'lucide', 'dist', 'umd', 'lucide.js');
const lucideMinPath = join(here, '..', 'node_modules', 'lucide', 'dist', 'umd', 'lucide.min.js');
const xtermJsPath = join(here, '..', 'node_modules', '@xterm', 'xterm', 'lib', 'xterm.js');
const xtermCssPath = join(here, '..', 'node_modules', '@xterm', 'xterm', 'css', 'xterm.css');
const xtermFitPath = join(here, '..', 'node_modules', '@xterm', 'addon-fit', 'lib', 'addon-fit.js');

export const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

app.use((req, res, next) => {
  if (!req.path.startsWith('/api/')) return next();
  const start = Date.now();
  res.on('finish', () => {
    console.log(`[api] ${req.method} ${req.originalUrl} ${res.statusCode} ${Date.now() - start}ms`);
  });
  next();
});

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

function decorateNode(node) {
  if (!node) return null;
  const server = getServerRecord(node.server_id);
  return { ...node, links: server ? nodeLinks(node, server) : [] };
}

function decorateRoute(route) {
  const inboundNode = getNode(route.inbound_node_id);
  const outboundNode = getNode(route.outbound_node_id);
  if (!inboundNode || !outboundNode) return null;
  return {
    ...route,
    inbound_node: { ...inboundNode, server: getServerPublic(inboundNode.server_id) },
    outbound_node: { ...outboundNode, server: getServerPublic(outboundNode.server_id) }
  };
}

function subscriptionWithToken(subscription, token) {
  return {
    subscription,
    token,
    subscription_path: `/sub/${token}`
  };
}

function subscriptionPreview(id) {
  const subscription = getSubscription(id);
  if (!subscription) return null;
  const { included, excluded } = buildSubscriptionNodes();
  return {
    subscription: {
      ...subscription,
      node_count: included.length
    },
    node_count: included.length,
    link_count: included.reduce((count, node) => count + node.links.length, 0),
    nodes: included.map(({ links, ...node }) => ({
      ...node,
      has_share_links: links.length > 0
    })),
    excluded
  };
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'vps-node-console', version: '0.1.0' });
});

app.get('/api/stats', (req, res) => {
  res.json(getStats());
});

app.get('/api/status', (req, res) => {
  const statusRows = new Map(listServerStatuses().map((row) => [row.server_id, row]));
  const servers = listServers().map((server) => {
    const cached = statusRows.get(server.id) || null;
    const { node_status: cachedNodeStatus, node_status_json: _, ...cachedFields } = cached || {};
    const nodes = listNodes(server.id).map((node) => {
      const nodeStatus = (cachedNodeStatus || []).find((item) => item.id === node.id) || null;
      return {
        id: node.id,
        name: node.name,
        protocol: node.protocol,
        port: node.port,
        role: node.role,
        enabled: node.enabled,
        ...(nodeStatus || {})
      };
    });
    const drift = deriveDriftType(cached);
    return {
      server,
      state: deriveServerState(cached),
      drift,
      drift_reason: drift ? DRIFT_REASONS[drift] : null,
      status: cachedFields || null,
      nodes
    };
  });
  res.json({
    generated_at: new Date().toISOString(),
    interval_seconds: getStatusIntervalSeconds(),
    servers
  });
});

app.get('/api/servers', (req, res) => {
  res.json(listServers());
});

app.get('/api/servers/:id', (req, res) => {
  const server = getServerPublic(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });
  res.json(server);
});

app.post('/api/servers', (req, res) => {
  res.status(201).json(saveServer(req.body || {}));
});

app.put('/api/servers/:id', (req, res) => {
  if (!getServerRecord(req.params.id)) {
    return res.status(404).json({ error: 'server not found' });
  }
  res.json(saveServer(req.body || {}, req.params.id));
});

app.delete('/api/servers/:id', (req, res) => {
  if (!deleteServer(req.params.id)) {
    return res.status(404).json({ error: 'server not found' });
  }
  res.status(204).end();
});

app.post('/api/servers/:id/test', asyncHandler(async (req, res) => {
  const server = getServerRecord(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });
  const probe = await probeServer(server);
  res.json(probe);
}));

app.get('/api/servers/:id/status', asyncHandler(async (req, res) => {
  const server = getServerRecord(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });
  res.json(await xrayStatus(server, listNodes(req.params.id)));
}));

app.post('/api/servers/:id/install', asyncHandler(async (req, res) => {
  const server = getServerRecord(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });
  res.json(await installXray(server, { force: req.body?.force === true }));
}));

app.post('/api/servers/:id/restart', asyncHandler(async (req, res) => {
  const server = getServerRecord(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });
  res.json(await restartXray(server));
}));

app.post('/api/servers/:id/x25519', asyncHandler(async (req, res) => {
  const server = getServerRecord(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });
  res.json({ ok: true, ...generateRealityKeypair() });
}));

app.post('/api/servers/:id/deploy', asyncHandler(async (req, res) => {
  const server = getServerRecord(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });
  const nodes = listNodes(req.params.id);
  if (!nodes.length) return res.status(400).json({ error: 'add at least one node before deploy' });
  const routes = routesForServer(req.params.id);
  res.json(await deployServer(server, nodes, { routes }));
}));

app.post('/api/servers/:id/repair', asyncHandler(async (req, res) => {
  const server = getServerRecord(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });
  const cached = getServerStatus(server.id);
  if (!cached) return res.status(400).json({ error: '尚无状态缓存，请等待巡检完成后再试' });
  if (!cached.ssh_reachable) return res.status(409).json({ error: '服务器离线，无法执行修复' });
  const drift = deriveDriftType(cached);
  if (!drift) return res.status(400).json({ error: '当前没有需要修复的漂移' });
  if (req.body?.drift_type && req.body.drift_type !== drift) {
    return res.status(409).json({ error: '漂移类型已变化，请刷新后重试' });
  }
  res.json(await performRepair(server, drift));
}));

app.get('/api/repair-logs', (req, res) => {
  res.json(listRepairLogs(Number(req.query.limit || 100)));
});

app.get('/api/subscriptions', (req, res) => {
  res.json(listSubscriptions());
});

app.post('/api/subscriptions', (req, res) => {
  const result = createSubscription(req.body || {});
  res.status(201).json(subscriptionWithToken(result.subscription, result.token));
});

app.get('/api/subscriptions/:id', (req, res) => {
  const subscription = getSubscription(req.params.id);
  if (!subscription) return res.status(404).json({ error: 'subscription not found' });
  res.json(subscription);
});

app.put('/api/subscriptions/:id', (req, res) => {
  const subscription = updateSubscription(req.params.id, req.body || {});
  if (!subscription) return res.status(404).json({ error: 'subscription not found' });
  res.json(subscription);
});

app.delete('/api/subscriptions/:id', (req, res) => {
  if (!deleteSubscription(req.params.id)) {
    return res.status(404).json({ error: 'subscription not found' });
  }
  res.status(204).end();
});

app.post('/api/subscriptions/:id/rotate', (req, res) => {
  const result = rotateSubscription(req.params.id);
  if (!result) return res.status(404).json({ error: 'subscription not found' });
  res.json(subscriptionWithToken(result.subscription, result.token));
});

app.post('/api/subscriptions/:id/enable', (req, res) => {
  const subscription = setSubscriptionEnabled(req.params.id, true);
  if (!subscription) return res.status(404).json({ error: 'subscription not found' });
  res.json(subscription);
});

app.post('/api/subscriptions/:id/disable', (req, res) => {
  const subscription = setSubscriptionEnabled(req.params.id, false);
  if (!subscription) return res.status(404).json({ error: 'subscription not found' });
  res.json(subscription);
});

app.get('/api/subscriptions/:id/preview', (req, res) => {
  const preview = subscriptionPreview(req.params.id);
  if (!preview) return res.status(404).json({ error: 'subscription not found' });
  res.json(preview);
});

app.post('/api/subscriptions/qr', asyncHandler(async (req, res) => {
  const value = String(req.body?.url || '').trim();
  let url;
  try {
    url = new URL(value);
  } catch {
    return res.status(400).json({ error: '无效的订阅地址' });
  }
  if (!['http:', 'https:'].includes(url.protocol) || !url.pathname.startsWith('/sub/')) {
    return res.status(400).json({ error: '只支持面板订阅地址' });
  }
  const dataUrl = await QRCode.toDataURL(url.toString(), {
    errorCorrectionLevel: 'M',
    margin: 2,
    width: 320
  });
  res.json({ data_url: dataUrl });
}));

app.get('/sub/:token', (req, res) => {
  const subscription = resolvePublicSubscription(req.params.token);
  if (!subscription || !subscription.enabled || isSubscriptionExpired(subscription)) {
    return res.status(404).type('text/plain').send('subscription unavailable');
  }

  const requestedFormat = req.query.format ? String(req.query.format).toLowerCase() : subscription.default_format;
  if (!['base64', 'uri'].includes(requestedFormat)) {
    return res.status(400).type('text/plain').send('unsupported subscription format');
  }

  const { included } = buildSubscriptionNodes();
  const content = subscriptionContent({ ...subscription, default_format: requestedFormat }, included);
  res.set('Cache-Control', 'no-cache');
  res.set('ETag', content.etag);
  res.set('X-Subscription-Node-Count', String(included.length));
  res.set('X-Subscription-Empty', included.length ? 'false' : 'true');
  markSubscriptionAccess(subscription.id);
  if (req.headers['if-none-match'] === content.etag) return res.status(304).end();
  res.type('text/plain').send(content.body);
});

app.get('/api/servers/:id/logs', asyncHandler(async (req, res) => {
  const server = getServerRecord(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });
  const lines = Number(req.query.lines || 100);
  res.json(await xrayLogs(server, lines));
}));

app.get('/api/servers/:id/nodes', (req, res) => {
  if (!getServerRecord(req.params.id)) {
    return res.status(404).json({ error: 'server not found' });
  }
  res.json(listNodes(req.params.id).map(decorateNode));
});

app.post('/api/servers/:id/nodes', (req, res) => {
  if (!getServerRecord(req.params.id)) {
    return res.status(404).json({ error: 'server not found' });
  }
  const node = saveNode({ ...req.body, server_id: req.params.id });
  res.status(201).json(decorateNode(node));
});

app.put('/api/nodes/:id', (req, res) => {
  if (!getNode(req.params.id)) {
    return res.status(404).json({ error: 'node not found' });
  }
  res.json(decorateNode(saveNode(req.body || {}, req.params.id)));
});

app.delete('/api/nodes/:id', (req, res) => {
  if (!deleteNode(req.params.id)) {
    return res.status(404).json({ error: 'node not found' });
  }
  res.status(204).end();
});

app.get('/api/nodes', (req, res) => {
  res.json(listAllNodes().map(decorateNode));
});

app.get('/api/routes', (req, res) => {
  res.json(listRoutes().map(decorateRoute).filter(Boolean));
});

app.post('/api/routes', (req, res) => {
  res.status(201).json(decorateRoute(saveRoute(req.body || {})));
});

app.delete('/api/routes/:id', (req, res) => {
  if (!deleteRoute(req.params.id)) {
    return res.status(404).json({ error: 'route not found' });
  }
  res.status(204).end();
});

app.use(express.static(publicDir));

app.get('/vendor/lucide.js', (req, res) => {
  const file = existsSync(lucideMinPath) ? lucideMinPath : lucidePath;
  res.sendFile(file);
});

app.get('/vendor/xterm.js', (req, res) => res.sendFile(xtermJsPath));
app.get('/vendor/xterm.css', (req, res) => res.sendFile(xtermCssPath));
app.get('/vendor/xterm-fit.js', (req, res) => res.sendFile(xtermFitPath));

app.use((err, req, res, next) => {
  const status = err.status || 500;
  const payload = { error: err.message || 'internal error' };
  const loggedUrl = req.path.startsWith('/sub/') ? '/sub/[token]' : req.originalUrl;
  console.error(`[api-error] ${req.method} ${loggedUrl} server=${req.params.id || '-'} ${err.message}`);
  if (err.message?.includes('All configured authentication methods failed')) {
    payload.error = 'SSH 认证失败：请检查用户名、密码或私钥';
  }
  if (err.remote) payload.remote = err.remote;
  res.status(status).json(payload);
});
