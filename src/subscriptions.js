import { createHash } from 'node:crypto';
import {
  getServerPublic,
  getSubscriptionByTokenHash,
  touchSubscriptionAccess
} from './db.js';
import { listAllNodes } from './db.js';
import { hashSubscriptionToken } from './subscription-token.js';
import { nodeLinks } from './xray.js';

const PROTOCOL_PREFIXES = {
  vmess: 'vmess://',
  vless: 'vless://',
  trojan: 'trojan://',
  shadowsocks: 'ss://',
  socks: 'socks://'
};

function nodeSummary(node, server) {
  return {
    id: node.id,
    name: node.name,
    protocol: node.protocol,
    server_id: node.server_id,
    server_name: server?.name || '',
    server_host: server?.host || '',
    port: node.port,
    network: node.network || 'tcp',
    security: node.security || 'none'
  };
}

function hasValidLink(link, protocol) {
  const prefix = PROTOCOL_PREFIXES[protocol];
  return Boolean(prefix && typeof link === 'string' && link.startsWith(prefix) && link.length > prefix.length);
}

function excludedNode(node, server, reason) {
  return {
    ...nodeSummary(node, server),
    included: false,
    has_share_links: false,
    reason
  };
}

export function buildSubscriptionNodes(nodes = listAllNodes(), serverResolver = getServerPublic) {
  const included = [];
  const excluded = [];

  for (const node of nodes) {
    const server = serverResolver(node.server_id);
    if (node.role !== 'inbound') {
      excluded.push(excludedNode(node, server, '出站节点不纳入订阅'));
      continue;
    }
    if (node.enabled !== 1) {
      excluded.push(excludedNode(node, server, '节点已禁用'));
      continue;
    }
    if (!server) {
      excluded.push(excludedNode(node, null, '服务器不存在'));
      continue;
    }

    try {
      const links = nodeLinks(node, server).filter((item) => hasValidLink(item?.link, node.protocol));
      if (!links.length) {
        excluded.push(excludedNode(node, server, '无法生成分享链接'));
        continue;
      }
      included.push({
        ...nodeSummary(node, server),
        included: true,
        has_share_links: true,
        links
      });
    } catch {
      excluded.push(excludedNode(node, server, '分享链接生成失败'));
    }
  }

  return { included, excluded };
}

export function renderUriList(nodes) {
  return nodes
    .flatMap((node) => (node.links || []).map((item) => item.link))
    .filter(Boolean)
    .join('\n');
}

export function renderBase64Subscription(nodes) {
  return Buffer.from(renderUriList(nodes), 'utf8').toString('base64');
}

export function subscriptionContent(subscription, nodes) {
  const uri = renderUriList(nodes);
  const base64 = Buffer.from(uri, 'utf8').toString('base64');
  const format = subscription.default_format === 'uri' ? 'uri' : 'base64';
  const body = format === 'uri' ? uri : base64;
  const etag = `"${createHash('sha256').update(`${subscription.updated_at}:${format}:${body}`).digest('hex')}"`;
  return { format, uri, base64, body, etag };
}

export function isSubscriptionExpired(subscription, now = Date.now()) {
  if (!subscription?.expires_at) return false;
  const timestamp = Date.parse(subscription.expires_at);
  return Number.isFinite(timestamp) && timestamp <= now;
}

export function resolvePublicSubscription(token) {
  const value = String(token || '');
  if (!value || value.length < 32 || value.length > 128) return null;
  return getSubscriptionByTokenHash(hashSubscriptionToken(value));
}

export function markSubscriptionAccess(subscriptionId) {
  return touchSubscriptionAccess(subscriptionId);
}
