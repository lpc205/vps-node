import { generateKeyPairSync, randomUUID } from 'node:crypto';

function splitList(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function parsePreferredAddress(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  const match = raw.match(/^\[([^\]]+)\](?::(\d+))?$/) || raw.match(/^([^:]+):(\d+)$/);
  if (match) {
    const port = Number(match[2]);
    return {
      host: match[1],
      port: Number.isInteger(port) && port > 0 && port <= 65535 ? port : 443
    };
  }
  return { host: raw, port: 443 };
}

export function canUseReality(protocol, network) {
  return protocol === 'vless' && network !== 'ws';
}

export function isTunnelNode(node) {
  return Boolean(node?.tunnel) && ['ws', 'xhttp'].includes(node?.network);
}

export function isSelfSignedNode(node) {
  return Boolean(node?.self_signed) || (node?.protocol === 'hysteria2');
}

function wsSettings(node) {
  const settings = {
    path: node.path || '/'
  };
  if (node.sni && !isTunnelNode(node)) settings.headers = { Host: node.sni };
  return settings;
}

function xhttpSettings(node) {
  const settings = {
    mode: node.xhttp_mode || 'auto',
    path: node.path || '/'
  };
  if (node.sni && !isTunnelNode(node)) settings.host = node.sni;
  return settings;
}

function streamFor(node, { inbound = true } = {}) {
  const stream = {
    network: node.network,
    security: node.security || 'none'
  };

  if (node.protocol === 'hysteria2') {
    return {
      network: 'hysteria',
      security: 'tls',
      tlsSettings: {
        serverName: node.sni || '',
        alpn: ['h3'],
        certificates: [
          {
            certificateFile: node.cert_file || '/usr/local/etc/xray/cert/cert.pem',
            keyFile: node.key_file || '/usr/local/etc/xray/cert/private.key'
          }
        ]
      }
    };
  }

  if (node.network === 'ws') stream.wsSettings = wsSettings(node);
  if (node.network === 'xhttp') stream.xhttpSettings = xhttpSettings(node);
  if (node.network === 'grpc') {
    stream.grpcSettings = {
      serviceName: node.path || 'grpc'
    };
  }
  if (node.network === 'httpupgrade') {
    stream.httpUpgradeSettings = {
      path: node.path || '/'
    };
  }

  if (node.security === 'tls') {
    if (inbound) {
      stream.tlsSettings = {
        serverName: node.sni || '',
        alpn: node.protocol === 'hysteria2' ? ['h3'] : undefined,
        certificates: [
          {
            certificateFile: node.cert_file || '/usr/local/etc/xray/cert/cert.pem',
            keyFile: node.key_file || '/usr/local/etc/xray/cert/private.key'
          }
        ]
      };
    } else {
      stream.tlsSettings = {
        serverName: node.sni || '',
        allowInsecure: false,
        fingerprint: 'chrome'
      };
    }
  }

  if (node.security === 'reality') {
    if (inbound) {
      stream.realitySettings = {
        show: false,
        dest: node.dest || 'www.microsoft.com:443',
        xver: 0,
        serverNames: splitList(node.server_names),
        privateKey: node.private_key,
        shortIds: splitList(node.short_ids).length ? splitList(node.short_ids) : [''],
        ...(node.network === 'xhttp' ? { alpn: ['h2'] } : {})
      };
    } else {
      stream.realitySettings = {
        serverName: node.sni || '',
        fingerprint: 'chrome',
        publicKey: node.public_key || '',
        shortId: splitList(node.short_ids)[0] || '',
        spiderX: '/'
      };
    }
  }

  return stream;
}

const buildStreamSettings = (node) => streamFor(node, { inbound: true });
const buildOutboundStreamSettings = (node) => streamFor(node, { inbound: false });

function buildOutbound(node, server) {
  const client = node.clients?.[0] || {};
  const address = server?.host || '';
  const port = Number(node.port);
  const protocol = node.protocol;
  const settings = {};
  if (protocol === 'vless' || protocol === 'vmess') {
    const user = { id: client.secret, level: 0 };
    if (protocol === 'vless') {
      user.encryption = 'none';
      if (node.security === 'reality') user.flow = client.flow || 'xtls-rprx-vision';
    } else {
      user.alterId = 0;
      user.security = client.security || 'auto';
    }
    settings.vnext = [{ address, port, users: [user] }];
  }
  if (protocol === 'trojan') {
    settings.servers = [{ address, port, password: client.secret, level: 0 }];
  }
  if (protocol === 'shadowsocks') {
    settings.servers = [{ address, port, method: node.method || 'aes-256-gcm', password: client.secret, level: 0 }];
  }
  if (protocol === 'socks') {
    settings.servers = [{ address, port, users: [{ user: client.email || 'user', pass: client.secret }] }];
  }
  return {
    protocol,
    tag: `out-${node.id}`,
    settings,
    streamSettings: buildOutboundStreamSettings(node)
  };
}

function buildInbound(node) {
  const clients = node.clients || [];
  const settings = {
    clients: clients.map((client) => ({
      email: client.email || '',
      id: client.secret,
      flow: node.protocol === 'vless' && node.security === 'reality' ? (client.flow || 'xtls-rprx-vision') : (client.flow || '')
    })),
    decryption: 'none'
  };

  if (node.protocol === 'hysteria2') {
    delete settings.decryption;
    settings.version = 2;
    settings.clients = clients.map((client) => ({
      auth: client.secret,
      email: client.email || ''
    }));
  }

  if (node.protocol === 'vmess') {
    settings.clients = clients.map((client) => ({
      id: client.secret,
      email: client.email || '',
      level: 0,
      alterId: 0,
      security: client.security || 'auto'
    }));
  }

  if (node.protocol === 'trojan') {
    settings.clients = clients.map((client) => ({
      password: client.secret,
      email: client.email || ''
    }));
  }

  if (node.protocol === 'shadowsocks') {
    const method = node.method || 'aes-256-gcm';
    settings.method = method;
    settings.password = clients[0]?.secret || '';
    settings.network = node.ss_network || 'tcp';
    settings.clients = clients.map((client) => ({
      email: client.email || '',
      method,
      password: client.secret
    }));
  }

  if (node.protocol === 'socks') {
    delete settings.clients;
    delete settings.decryption;
    settings.auth = 'password';
    settings.accounts = clients.map((client) => ({
      user: client.email || 'user',
      pass: client.secret
    }));
    settings.udp = true;
  }

  const inbound = {
    tag: `${node.protocol}-${node.port}`,
    port: node.port,
    protocol: node.protocol,
    settings,
    streamSettings: buildStreamSettings(node),
    sniffing: {
      enabled: true,
      destOverride: ['http', 'tls', 'quic']
    }
  };

  if (isTunnelNode(node)) {
    inbound.listen = '127.0.0.1';
    inbound.streamSettings.security = 'none';
    if (inbound.streamSettings.wsSettings) delete inbound.streamSettings.wsSettings.headers;
    if (inbound.streamSettings.xhttpSettings) delete inbound.streamSettings.xhttpSettings.host;
  }

  if (node.protocol === 'hysteria2') {
    inbound.streamSettings = {
      network: 'hysteria',
      security: 'tls',
      tlsSettings: {
        serverName: node.sni || '',
        alpn: ['h3'],
        certificates: [
          {
            certificateFile: node.cert_file,
            keyFile: node.key_file
          }
        ]
      }
    };
  }

  return inbound;
}

export function buildXrayConfig(nodes, routes = []) {
  const enabledNodes = nodes.filter((node) => node.enabled !== 0 && node.enabled !== false);
  const routeOutbounds = [];
  const routeRules = [];
  for (const route of routes || []) {
    const inboundNode = enabledNodes.find((node) => node.id === route.inbound_node_id);
    const outboundNode = route.outbound_node;
    const outboundServer = route.outbound_server;
    if (!inboundNode || !outboundNode || !outboundServer) continue;
    if (outboundNode.enabled === 0 || outboundNode.enabled === false) continue;
    const outbound = buildOutbound(outboundNode, outboundServer);
    routeOutbounds.push(outbound);
    routeRules.push({
      type: 'field',
      inboundTag: [buildInbound(inboundNode).tag],
      outboundTag: outbound.tag
    });
  }
  return {
    log: {
      loglevel: 'warning'
    },
    inbounds: enabledNodes.map(buildInbound),
    outbounds: [
      {
        protocol: 'freedom',
        tag: 'direct'
      },
      {
        protocol: 'blackhole',
        tag: 'blocked'
      },
      ...routeOutbounds
    ],
    routing: {
      domainStrategy: 'AsIs',
      rules: [
        {
          type: 'field',
          protocol: ['bittorrent'],
          outboundTag: 'blocked'
        },
        ...routeRules
      ]
    }
  };
}

export function nodeLinks(node, server) {
  const tunnel = isTunnelNode(node) && server?.argo_domain;
  const preferred = tunnel ? parsePreferredAddress(node.preferred_address) : null;
  const host = tunnel ? (preferred?.host || server.argo_domain) : (server?.host || '');
  const port = tunnel ? (preferred?.port || 443) : node.port;
  const clients = node.clients || [];
  const remark = encodeURIComponent(`${node.name}${clients.length > 1 ? `-${clients[0].email || '1'}` : ''}`);
  const network = node.network || 'tcp';
  const security = tunnel ? 'tls' : (node.security || 'none');

  return clients.map((client) => {
    let link = '';
    if (node.protocol === 'vmess') {
      const payload = {
        v: '2',
        ps: decodeURIComponent(remark),
        add: host,
        port: Number(port),
        id: client.secret,
        aid: '0',
        scy: client.security || 'auto',
        net: network,
        type: 'none',
        host: tunnel ? server.argo_domain : (node.sni || host),
        path: node.path || '',
        tls: security === 'tls' ? 'tls' : '',
        sni: tunnel ? server.argo_domain : (node.sni || '')
      };
      link = `vmess://${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
    }

    if (node.protocol === 'vless') {
      const params = new URLSearchParams({
        encryption: 'none',
        security,
        type: network
      });
      if (tunnel) {
        params.set('host', server.argo_domain);
        params.set('sni', server.argo_domain);
      } else if (node.sni) {
        params.set('sni', node.sni);
      }
      params.set('fp', 'chrome');
      if (node.path && network !== 'tcp') {
        params.set('path', tunnel && network === 'ws' ? `${node.path}?ed=2560` : node.path);
      }
      if (network === 'grpc') params.set('serviceName', node.path || 'grpc');
      if (network === 'xhttp' && node.xhttp_mode) params.set('mode', node.xhttp_mode);
      if (security === 'reality') {
        params.set('pbk', node.public_key || '');
        params.set('sid', splitList(node.short_ids)[0] || '');
        params.set('spx', '/');
        params.set('flow', client.flow || 'xtls-rprx-vision');
      }
      link = `vless://${client.secret}@${host}:${port}?${params.toString()}#${remark}`;
    }

    if (node.protocol === 'trojan') {
      const params = new URLSearchParams();
      params.set('security', security === 'tls' ? 'tls' : '');
      if (tunnel) {
        params.set('sni', server.argo_domain);
        params.set('host', server.argo_domain);
      } else if (node.sni) {
        params.set('sni', node.sni);
      }
      params.set('type', network);
      if (node.path && network !== 'tcp') {
        params.set('path', tunnel && network === 'ws' ? `${node.path}?ed=2560` : node.path);
      }
      link = `trojan://${client.secret}@${host}:${port}?${params.toString()}#${remark}`;
    }

    if (node.protocol === 'shadowsocks') {
      const method = node.method || 'aes-256-gcm';
      const userinfo = Buffer.from(`${method}:${client.secret}`).toString('base64url');
      if (tunnel) {
        const plugin = Buffer.from(JSON.stringify({
          mode: 'websocket',
          tls: true,
          host: server.argo_domain,
          path: node.path || '/',
          peer: server.argo_domain
        })).toString('base64');
        link = `ss://${userinfo}@${host}:${port}?plugin=v2ray-plugin%3B${encodeURIComponent(plugin)}#${remark}`;
      } else {
        link = `ss://${userinfo}@${host}:${port}#${remark}`;
      }
    }

    if (node.protocol === 'socks') {
      const user = encodeURIComponent(client.email || 'user');
      const pass = encodeURIComponent(client.secret || '');
      link = `socks://${user}:${pass}@${host}:${port}#${remark}`;
    }

    if (node.protocol === 'hysteria2') {
      const params = new URLSearchParams();
      params.set('security', 'tls');
      params.set('sni', node.sni || '');
      params.set('insecure', '1');
      if (node.hy2_up) params.set('upmbps', String(node.hy2_up));
      if (node.hy2_down) params.set('downmbps', String(node.hy2_down));
      link = `hysteria2://${encodeURIComponent(client.secret)}@${host}:${port}?${params.toString()}#${remark}`;
    }

    return {
      email: client.email || '',
      secret: client.secret,
      flow: client.flow || '',
      link
    };
  });
}

export function freshClient() {
  return { email: '', secret: randomUUID(), flow: '' };
}

export function generateRealityKeypair() {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  const privateDer = privateKey.export({ format: 'der', type: 'pkcs8' });
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  return {
    privateKey: privateDer.subarray(privateDer.length - 32).toString('base64url'),
    publicKey: publicDer.subarray(publicDer.length - 32).toString('base64url')
  };
}
