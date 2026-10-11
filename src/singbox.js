import { generateKeyPairSync, randomUUID } from 'node:crypto';

const CERT_DIR = '/usr/local/etc/sing-box/cert';
export const CERT_FILE = `${CERT_DIR}/cert.pem`;
export const KEY_FILE = `${CERT_DIR}/private.key`;

const list = (value) => String(value || '').split(',').map((v) => v.trim()).filter(Boolean);
const on = (node) => node.enabled !== 0 && node.enabled !== false;
const tagged = (node) => `node-${node.id || node.port}`;
const tunnel = (node) => Boolean(node.tunnel) && node.network === 'ws';

export function canUseReality(protocol, network) {
  return protocol === 'vless' && ['tcp', 'grpc', 'http'].includes(network);
}

export function isTunnelNode(node) { return tunnel(node); }
export function isSelfSignedNode(node) {
  return ['hysteria2', 'tuic', 'anytls', 'trojan'].includes(node?.protocol) || Boolean(node?.self_signed);
}

function transport(node) {
  if (node.network === 'ws') return { type: 'ws', path: node.path || '/' };
  if (node.network === 'grpc') return { type: 'grpc', service_name: node.path || 'grpc' };
  if (node.network === 'http') return { type: 'http', path: node.path || '/', host: [] };
  return undefined;
}

function realityTarget(node) {
  const candidate = String(node.dest || 'www.microsoft.com:443');
  const i = candidate.lastIndexOf(':');
  return {
    server: i > 0 ? candidate.slice(0, i) : candidate,
    server_port: i > 0 && Number(candidate.slice(i + 1)) ? Number(candidate.slice(i + 1)) : 443
  };
}

function inboundTLS(node) {
  if (node.security === 'reality') {
    if (!node.private_key) throw new Error('Reality 私钥缺失，请先生成密钥');
    return {
      enabled: true,
      server_name: list(node.server_names)[0] || node.sni || realityTarget(node).server,
      reality: {
        enabled: true,
        handshake: realityTarget(node),
        private_key: node.private_key,
        short_id: list(node.short_ids).length ? list(node.short_ids) : ['']
      }
    };
  }
  if (node.security === 'tls' || isSelfSignedNode(node)) {
    return {
      enabled: true,
      certificate_path: node.cert_file || CERT_FILE,
      key_path: node.key_file || KEY_FILE,
      ...(node.protocol === 'hysteria2' || node.protocol === 'tuic' ? { alpn: ['h3'] } : {})
    };
  }
  return undefined;
}

function inboundUsers(node) {
  return (node.clients || []).map((client) => {
    const name = client.email || 'user';
    switch (node.protocol) {
      case 'vless': return { name, uuid: client.secret, ...(node.security === 'reality' && node.network === 'tcp' ? { flow: 'xtls-rprx-vision' } : {}) };
      case 'vmess': return { name, uuid: client.secret, alterId: 0 };
      case 'tuic': return { name, uuid: client.secret, password: client.secret };
      default: return { name, password: client.secret };
    }
  });
}

export function buildSingboxInbound(node) {
  if (!on(node) || node.role === 'outbound') return null;
  if (node.network === 'xhttp' || node.network === 'httpupgrade') {
    throw new Error('Sing-box 不支持该 Xray 传输模式，请修改节点部署组合');
  }
  const base = {
    type: node.protocol,
    tag: tagged(node),
    listen: tunnel(node) ? '127.0.0.1' : '::',
    listen_port: Number(node.port)
  };
  if (node.protocol === 'socks') {
    return { ...base, users: inboundUsers(node).map((user) => ({ username: user.name, password: user.password })) };
  }
  if (node.protocol === 'shadowsocks') {
    const clients = node.clients || [];
    if (clients.length > 1) throw new Error('Shadowsocks 节点当前仅支持单用户');
    return { ...base, method: node.method || 'aes-256-gcm', password: clients[0]?.secret || '' };
  }
  const inbound = { ...base, users: inboundUsers(node) };
  const tls = inboundTLS(node);
  if (tls) inbound.tls = tls;
  if (node.protocol === 'hysteria2') {
    if (node.hy2_up > 0) inbound.up_mbps = Number(node.hy2_up);
    if (node.hy2_down > 0) inbound.down_mbps = Number(node.hy2_down);
  }
  if (node.protocol === 'tuic') inbound.congestion_control = 'bbr';
  if (['vless', 'vmess', 'trojan'].includes(node.protocol)) {
    const t = transport(node);
    if (t) inbound.transport = t;
  } else if (node.network !== 'tcp') {
    throw new Error(`${node.protocol} 不支持该传输模式`);
  }
  return inbound;
}

function outboundTLS(node) {
  if (node.security === 'reality') return {
    enabled: true,
    server_name: node.sni || list(node.server_names)[0] || realityTarget(node).server,
    reality: { enabled: true, public_key: node.public_key, short_id: list(node.short_ids)[0] || '' }
  };
  if (node.security === 'tls' || isSelfSignedNode(node)) {
    return { enabled: true, server_name: node.sni || '', insecure: true };
  }
  return undefined;
}

function buildOutbound(node, server) {
  const user = node.clients?.[0];
  if (!user) throw new Error('出口节点缺少客户端');
  const result = {
    type: node.protocol,
    tag: `out-${node.id}`,
    server: server.host,
    server_port: Number(node.port)
  };
  if (['vless', 'vmess', 'tuic'].includes(node.protocol)) result.uuid = user.secret;
  if (['trojan', 'hysteria2', 'anytls', 'tuic', 'shadowsocks'].includes(node.protocol)) result.password = user.secret;
  if (node.protocol === 'shadowsocks') result.method = node.method || 'aes-256-gcm';
  if (node.protocol === 'vless' && node.security === 'reality' && node.network === 'tcp') result.flow = 'xtls-rprx-vision';
  if (node.protocol === 'socks') {
    result.username = user.email || 'user';
    result.password = user.secret;
  }
  const tls = outboundTLS(node);
  if (tls) result.tls = tls;
  if (['vless', 'vmess', 'trojan'].includes(node.protocol)) {
    const t = transport(node);
    if (t) result.transport = t;
  }
  return result;
}

export function buildSingboxConfig(nodes, routes = []) {
  const enabled = nodes.filter(on);
  const inbounds = enabled.map(buildSingboxInbound).filter(Boolean);
  const outbounds = [{ type: 'direct', tag: 'direct' }, { type: 'block', tag: 'blocked' }];
  const rules = [];
  for (const route of routes) {
    const inbound = enabled.find((node) => node.id === route.inbound_node_id && node.role !== 'outbound');
    const remote = route.outbound_node;
    if (!inbound || !remote || !on(remote) || !route.outbound_server) continue;
    const outbound = buildOutbound(remote, route.outbound_server);
    if (!outbounds.some((x) => x.tag === outbound.tag)) outbounds.push(outbound);
    rules.push({ inbound: [tagged(inbound)], action: 'route', outbound: outbound.tag });
  }
  return { log: { level: 'warn' }, inbounds, outbounds, route: { rules, final: 'direct' } };
}

function preferredAddress(input) {
  const raw = String(input || '').trim();
  if (!raw) return null;
  const ipv6 = raw.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (ipv6) return { host: ipv6[1], port: Number(ipv6[2] || 443) };
  const match = raw.match(/^([^:]+):(\d+)$/);
  return match ? { host: match[1], port: Number(match[2]) } : { host: raw, port: 443 };
}

export function nodeLinks(node, server) {
  const viaTunnel = tunnel(node) && Boolean(server?.argo_domain);
  if (tunnel(node) && !viaTunnel) return [];
  const preferred = viaTunnel ? preferredAddress(node.preferred_address) : null;
  const host = viaTunnel ? (preferred?.host || server.argo_domain) : server?.host;
  const port = viaTunnel ? (preferred?.port || 443) : node.port;
  if (!host) return [];
  const name = encodeURIComponent(node.name || 'sing-box');
  const net = node.network || 'tcp';
  return (node.clients || []).map((client) => {
    const secret = encodeURIComponent(client.secret);
    let link = '';
    if (node.protocol === 'vless') {
      const params = new URLSearchParams({ encryption: 'none', security: viaTunnel ? 'tls' : (node.security || 'none'), type: net });
      if (viaTunnel) {
        params.set('host', server.argo_domain);
        params.set('sni', server.argo_domain);
        params.set('path', node.path || '/');
      } else {
        if (node.sni) params.set('sni', node.sni);
        if (net === 'grpc') params.set('serviceName', node.path || 'grpc');
        if (net === 'http') params.set('path', node.path || '/');
        if (node.security === 'reality') {
          params.set('pbk', node.public_key || '');
          params.set('sid', list(node.short_ids)[0] || '');
          params.set('fp', 'chrome');
          if (net === 'tcp') params.set('flow', 'xtls-rprx-vision');
        }
      }
      link = `vless://${secret}@${host}:${port}?${params}#${name}`;
    } else if (node.protocol === 'vmess') {
      const payload = { v: '2', ps: node.name, add: host, port, id: client.secret, aid: '0', net, type: 'none', host: viaTunnel ? server.argo_domain : (node.sni || ''), path: node.path || '/', tls: viaTunnel ? 'tls' : '', sni: viaTunnel ? server.argo_domain : (node.sni || '') };
      link = `vmess://${Buffer.from(JSON.stringify(payload)).toString('base64')}`;
    } else if (node.protocol === 'hysteria2') {
      const params = new URLSearchParams({ insecure: '1', sni: node.sni || '' });
      link = `hysteria2://${secret}@${host}:${port}?${params}#${name}`;
    } else if (node.protocol === 'tuic') {
      const params = new URLSearchParams({ congestion_control: 'bbr', allow_insecure: '1' });
      link = `tuic://${secret}:${secret}@${host}:${port}?${params}#${name}`;
    } else if (node.protocol === 'trojan' || node.protocol === 'anytls') {
      const params = new URLSearchParams({ security: 'tls', allowInsecure: '1' });
      link = `${node.protocol}://${secret}@${host}:${port}?${params}#${name}`;
    } else if (node.protocol === 'shadowsocks') {
      const userinfo = Buffer.from(`${node.method || 'aes-256-gcm'}:${client.secret}`).toString('base64url');
      link = `ss://${userinfo}@${host}:${port}#${name}`;
    } else if (node.protocol === 'socks') {
      link = `socks://${encodeURIComponent(client.email || 'user')}:${secret}@${host}:${port}#${name}`;
    }
    return { email: client.email || '', secret: client.secret, flow: client.flow || '', link };
  }).filter((entry) => entry.link);
}

export function freshClient() { return { email: '', secret: randomUUID(), flow: '' }; }
export function generateRealityKeypair() {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  const priv = privateKey.export({ format: 'der', type: 'pkcs8' });
  const pub = publicKey.export({ format: 'der', type: 'spki' });
  return {
    privateKey: priv.subarray(priv.length - 32).toString('base64url'),
    publicKey: pub.subarray(pub.length - 32).toString('base64url')
  };
}
