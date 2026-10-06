import { runChecked, runScript, runSudo } from './ssh.js';

export const DEFAULT_NGINX_PORT = 8080;
export const DEFAULT_TUNNEL_DOMAIN = '';

const CERT_DIR = '/usr/local/etc/xray/cert';
export const DEFAULT_CERT_FILE = `${CERT_DIR}/cert.pem`;
export const DEFAULT_KEY_FILE = `${CERT_DIR}/private.key`;

export function isTunnelNode(node) {
  return Boolean(node?.tunnel) && ['ws', 'xhttp'].includes(node?.network);
}

export function certPathFor(node) {
  if (!node) return { certFile: DEFAULT_CERT_FILE, keyFile: DEFAULT_KEY_FILE };
  return {
    certFile: node.cert_file || DEFAULT_CERT_FILE,
    keyFile: node.key_file || DEFAULT_KEY_FILE
  };
}

export function withSelfSignedPaths(nodes = []) {
  return nodes.map((node) => {
    if (node.self_signed !== 1 && node.protocol !== 'hysteria2') return node;
    const { certFile, keyFile } = certPathFor(node);
    return { ...node, cert_file: certFile, key_file: keyFile };
  });
}

export function needsSelfSignedCert(nodes = []) {
  return nodes.some((node) => node.self_signed === 1 || node.protocol === 'hysteria2');
}

export function tunnelNodes(nodes = []) {
  return nodes.filter((node) => isTunnelNode(node));
}

export function tunnelRequired(server, nodes = []) {
  if (tunnelNodes(nodes).length > 0) return true;
  return ['quick', 'token', 'json'].includes(server?.argo_mode);
}

function escapeNginxPath(value) {
  return String(value || '/').replace(/[\r\n]/g, '');
}

export function buildNginxConfig(server, nodes = []) {
  const port = Number(server?.nginx_port) > 0 ? Number(server.nginx_port) : DEFAULT_NGINX_PORT;
  const locations = [];

  for (const node of tunnelNodes(nodes)) {
    const path = escapeNginxPath(node.path || '/');
    if (node.network === 'ws') {
      locations.push(`
    location ^~ ${path} {
      if ($http_upgrade != "websocket") {
        return 404;
      }
      proxy_pass http://127.0.0.1:${node.port};
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header Host $host;
      proxy_redirect off;
      proxy_buffering off;
      proxy_read_timeout 1h;
      proxy_send_timeout 1h;
    }
`);
    } else if (node.network === 'xhttp') {
      locations.push(`
    location ^~ ${path} {
      if ($http_upgrade != "websocket") {
        return 404;
      }
      proxy_pass http://127.0.0.1:${node.port};
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header Host $host;
      proxy_redirect off;
      proxy_buffering off;
      proxy_request_buffering off;
      proxy_read_timeout 1h;
      proxy_send_timeout 1h;
    }
`);
    }
  }

  return `# Managed by VPS 节点控制台. Do not edit by hand.
worker_processes auto;
pid /usr/local/etc/xray/nginx.pid;
error_log /var/log/xray-nginx-error.log warn;

events {
  worker_connections 2048;
}

http {
  access_log off;
  sendfile on;
  keepalive_timeout 65;
  server_tokens off;

  server {
    listen ${port};
    listen [::]:${port};
    server_name _;
${locations.join('')}
  }
}
`;
}

export function buildNginxInstallScript(server, nodes = []) {
  const config = buildNginxConfig(server, nodes);
  const b64 = Buffer.from(config, 'utf8').toString('base64');
  return `
set -e

NGINX_BIN=""
for CANDIDATE in /usr/sbin/nginx /usr/local/sbin/nginx /usr/bin/nginx /usr/local/bin/nginx; do
  if [ -x "$CANDIDATE" ]; then NGINX_BIN="$CANDIDATE"; break; fi
done
if [ -z "$NGINX_BIN" ] && command -v nginx >/dev/null 2>&1; then
  NGINX_BIN="$(command -v nginx)"
fi
if [ -z "$NGINX_BIN" ]; then
  echo "NGINX_INSTALLING=yes"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx >/dev/null 2>&1
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q nginx >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q nginx >/dev/null 2>&1
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache nginx >/dev/null 2>&1
  fi
  for CANDIDATE in /usr/sbin/nginx /usr/local/sbin/nginx /usr/bin/nginx /usr/local/bin/nginx; do
    if [ -x "$CANDIDATE" ]; then NGINX_BIN="$CANDIDATE"; break; fi
  done
  if [ -z "$NGINX_BIN" ] && command -v nginx >/dev/null 2>&1; then
    NGINX_BIN="$(command -v nginx)"
  fi
fi
if [ -z "$NGINX_BIN" ]; then
  echo "NGINX_INSTALL_FAILED=yes"
  exit 1
fi

# 关闭发行版自带 nginx 服务，避免与面板托管实例抢占端口
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop nginx >/dev/null 2>&1 || true
  systemctl disable nginx >/dev/null 2>&1 || true
elif command -v rc-service >/dev/null 2>&1; then
  rc-service nginx stop >/dev/null 2>&1 || true
  rc-update del nginx >/dev/null 2>&1 || true
fi

mkdir -p /usr/local/etc/xray
cat > /var/tmp/argo-nginx.b64 <<'EOF'
${b64}
EOF
base64 -d /var/tmp/argo-nginx.b64 > /usr/local/etc/xray/nginx.conf
rm -f /var/tmp/argo-nginx.b64

"$NGINX_BIN" -t -c /usr/local/etc/xray/nginx.conf
if [ -s /usr/local/etc/xray/nginx.pid ] && kill -0 "$(cat /usr/local/etc/xray/nginx.pid)" 2>/dev/null; then
  "$NGINX_BIN" -s reload -c /usr/local/etc/xray/nginx.conf
else
  "$NGINX_BIN" -c /usr/local/etc/xray/nginx.conf
fi

if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/argo-nginx.service <<SERVICE
[Unit]
Description=Panel managed nginx reverse proxy
After=network.target

[Service]
Type=forking
PIDFile=/usr/local/etc/xray/nginx.pid
ExecStart=$NGINX_BIN -c /usr/local/etc/xray/nginx.conf
ExecReload=$NGINX_BIN -s reload -c /usr/local/etc/xray/nginx.conf
ExecStop=$NGINX_BIN -s stop -c /usr/local/etc/xray/nginx.conf
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE
  systemctl daemon-reload
  systemctl enable argo-nginx >/dev/null 2>&1 || true
fi

echo "NGINX_READY=ok"
echo "NGINX_BIN=$NGINX_BIN"
`;
}

export function buildCertificateScript(certFile = DEFAULT_CERT_FILE, keyFile = DEFAULT_KEY_FILE, sni = 'localhost') {
  const safeSni = String(sni || 'localhost').replace(/[^A-Za-z0-9.*-]/g, '') || 'localhost';
  return `
set -e
mkdir -p "$(dirname '${certFile}')"
if [ ! -s '${certFile}' ] || [ ! -s '${keyFile}' ]; then
  openssl ecparam -genkey -name prime256v1 -out '${keyFile}' 2>/dev/null
  cat > /var/tmp/panel-cert.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${safeSni}

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS = ${safeSni}
EOF
  openssl req -new -x509 -days 36500 \\
    -key '${keyFile}' \\
    -out '${certFile}' \\
    -config /var/tmp/panel-cert.cnf \\
    -subj "/CN=${safeSni}" \\
    -extensions v3_req 2>/dev/null
  rm -f /var/tmp/panel-cert.cnf
fi
chmod 600 '${keyFile}' 2>/dev/null || true
echo "CERT_READY=ok"
`;
}

function cloudflaredBinaryScript() {
  return `
CF_BIN=""
if [ -x /usr/local/bin/cloudflared ]; then CF_BIN=/usr/local/bin/cloudflared; fi
if [ -z "$CF_BIN" ]; then
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) CF_ARCH=amd64 ;;
    aarch64|arm64) CF_ARCH=arm64 ;;
    armv7l|armhf) CF_ARCH=arm ;;
    *) echo "CLOUDFLARED_UNSUPPORTED=$ARCH"; exit 1 ;;
  esac
  mkdir -p /var/tmp/panel-argo
  ATTEMPT=0
  while [ "$ATTEMPT" -lt 3 ]; do
    ATTEMPT=$((ATTEMPT + 1))
    if curl -fsSL --connect-timeout 20 -o /var/tmp/panel-argo/cloudflared \\
      "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-\${CF_ARCH}"; then
      break
    fi
  done
  if [ ! -s /var/tmp/panel-argo/cloudflared ]; then
    echo "CLOUDFLARED_DOWNLOAD_FAILED=yes"
    exit 1
  fi
  install -m 0755 /var/tmp/panel-argo/cloudflared /usr/local/bin/cloudflared
  rm -rf /var/tmp/panel-argo
  CF_BIN=/usr/local/bin/cloudflared
fi
echo "CLOUDFLARED_BIN=$CF_BIN"
`;
}

export function buildCloudflaredInstallScript(server, nodes = []) {
  const mode = ['quick', 'token', 'json'].includes(server?.argo_mode) ? server.argo_mode : 'none';
  if (mode === 'none' || tunnelNodes(nodes).length === 0) {
    return `
set +e
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop argo >/dev/null 2>&1 || true
  systemctl disable argo >/dev/null 2>&1 || true
fi
rm -f /etc/systemd/system/argo.service
echo "CLOUDFLARED_MODE=none"
`;
  }

  const token = String(server?.argo_token || '');
  const port = Number(server?.nginx_port) > 0 ? Number(server.nginx_port) : DEFAULT_NGINX_PORT;
  let tunnelConfigBlock = '';
  if (mode === 'token') {
    tunnelConfigBlock = `
cat > /usr/local/etc/xray/cloudflared.env <<'EOF'
${token}
EOF
chmod 600 /usr/local/etc/xray/cloudflared.env
`;
  } else if (mode === 'json') {
    const credentials = JSON.parse(String(server?.argo_json || '{}'));
    const tunnelId = String(credentials?.TunnelID || credentials?.tunnel_id || '').trim();
    const credentialsB64 = Buffer.from(JSON.stringify(credentials), 'utf8').toString('base64');
    tunnelConfigBlock = `
mkdir -p /usr/local/etc/xray
cat > /var/tmp/argo-creds.b64 <<'EOF'
${credentialsB64}
EOF
base64 -d /var/tmp/argo-creds.b64 > /usr/local/etc/xray/tunnel.json
chmod 600 /usr/local/etc/xray/tunnel.json
rm -f /var/tmp/argo-creds.b64
cat > /usr/local/etc/xray/tunnel.yml <<EOF
tunnel: ${tunnelId}
credentials-file: /usr/local/etc/xray/tunnel.json

ingress:
  - hostname: ${String(server?.argo_domain || '')}
    service: http://localhost:${port}
  - service: http_status:404
EOF
`;
  }

  const execStart = mode === 'token'
    ? `/usr/local/bin/cloudflared tunnel --edge-ip-version auto --protocol http2 run --token $(cat /usr/local/etc/xray/cloudflared.env)`
    : mode === 'json'
      ? `/usr/local/bin/cloudflared tunnel --edge-ip-version auto --protocol http2 --config /usr/local/etc/xray/tunnel.yml run`
      : `/usr/local/bin/cloudflared tunnel --edge-ip-version auto --protocol http2 --no-autoupdate --metrics 127.0.0.1:49312 --url http://localhost:${port}`;

  return `
set -e
${cloudflaredBinaryScript()}
${tunnelConfigBlock}
if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/argo.service <<'SERVICE'
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
NoNewPrivileges=yes
TimeoutStartSec=0
ExecStart=${execStart}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
SERVICE
  systemctl daemon-reload
  systemctl enable argo >/dev/null 2>&1 || true
  systemctl restart argo
elif command -v rc-service >/dev/null 2>&1; then
  cat > /etc/init.d/argo <<'OPENRC'
#!/sbin/openrc-run

name="argo"
description="Cloudflare Tunnel"

command="/usr/local/bin/cloudflared"
command_args="\${execStart#/usr/local/bin/cloudflared }"
command_background="yes"
pidfile="/run/\${RC_SVCNAME}.pid"
output_log="/var/log/cloudflared.log"
error_log="/var/log/cloudflared.log"

depend() {
  need net
}
OPENRC
  chmod 0755 /etc/init.d/argo
  rc-update add argo default >/dev/null 2>&1 || true
  rc-service argo restart
else
  pkill -f '/usr/local/bin/cloudflared' >/dev/null 2>&1 || true
  sleep 1
  if command -v setsid >/dev/null 2>&1; then
    setsid ${execStart} </dev/null >/var/log/cloudflared.log 2>&1 &
  else
    nohup ${execStart} </dev/null >/var/log/cloudflared.log 2>&1 &
  fi
  sleep 2
fi
echo "CLOUDFLARED_MODE=${mode}"
`;
}

export function buildQuickTunnelDomainScript(server) {
  const port = Number(server?.nginx_port) > 0 ? Number(server.nginx_port) : DEFAULT_NGINX_PORT;
  return `
set +e
DOMAIN=""
for ATTEMPT in $(seq 1 20); do
  DOMAIN="$(curl -fsS --max-time 3 "http://127.0.0.1:49312/quicktunnel" 2>/dev/null | sed -n 's/.*"hostname":"\\([^"]*\\)".*/\\1/p')"
  if [ -n "$DOMAIN" ]; then break; fi
  sleep 2
done
if [ -n "$DOMAIN" ]; then
  echo "ARGO_DOMAIN=$DOMAIN"
else
  echo "ARGO_DOMAIN_ERROR=quick tunnel domain unavailable"
fi
echo "ARGO_NGINX_PORT=${port}"
`;
}

export async function deployTunnel(server, nodes, options = {}) {
  const requiresTunnel = tunnelRequired(server, nodes);
  if (!requiresTunnel) return { ok: true, skipped: true };

  const tunnelNodeList = tunnelNodes(nodes);
  const outputs = {};

  if (tunnelNodeList.length > 0) {
    const nginx = await runChecked(runSudo(server, buildNginxInstallScript(server, nodes), { timeout: 180000 }));
    outputs.nginx = nginx.stdout.trim();
  }

  if (server?.argo_mode !== 'none' && tunnelNodeList.length > 0) {
    const cloudflared = await runChecked(runSudo(server, buildCloudflaredInstallScript(server, nodes), { timeout: 240000 }));
    outputs.cloudflared = cloudflared.stdout.trim();
  }

  if (server?.argo_mode === 'quick' && tunnelNodeList.length > 0) {
    const quick = await runChecked(runSudo(server, buildQuickTunnelDomainScript(server), { timeout: 90000 }));
    const match = quick.stdout.match(/^ARGO_DOMAIN=(.*)$/m);
    if (!match || !match[1]) {
      const error = new Error('无法获取临时隧道域名，请稍后重试或改用 Token 隧道');
      error.status = 502;
      throw error;
    }
    outputs.argo_domain = match[1].trim();
  }

  return { ok: true, ...outputs };
}

export async function readTunnelStatus(server) {
  const script = `
set +e
if [ -x /usr/local/bin/cloudflared ]; then
  echo "CLOUDFLARED_PRESENT=yes"
else
  echo "CLOUDFLARED_PRESENT=no"
fi
if command -v systemctl >/dev/null 2>&1; then
  echo "ARGO_ACTIVE=$(systemctl is-active argo 2>/dev/null || echo inactive)"
  echo "NGINX_ACTIVE=$(systemctl is-active argo-nginx 2>/dev/null || echo unknown)"
elif command -v rc-service >/dev/null 2>&1; then
  rc-service argo status >/dev/null 2>&1 && echo "ARGO_ACTIVE=started" || echo "ARGO_ACTIVE=stopped"
  rc-service argo-nginx status >/dev/null 2>&1 && echo "NGINX_ACTIVE=started" || echo "NGINX_ACTIVE=unknown"
else
  pgrep -f '/usr/local/bin/cloudflared' >/dev/null 2>&1 && echo "ARGO_ACTIVE=active" || echo "ARGO_ACTIVE=inactive"
  echo "NGINX_ACTIVE=unknown"
fi
if [ -f /usr/local/etc/xray/nginx.pid ]; then
  echo "NGINX_PID_PRESENT=yes"
else
  echo "NGINX_PID_PRESENT=no"
fi
if command -v ss >/dev/null 2>&1; then
  echo "ARGO_CONNECTIONS=$(ss -tnp 2>/dev/null | grep -c cloudflared)"
fi
`;
  const result = await runScript(server, script, { timeout: 15000 });
  const fields = {};
  for (const line of result.stdout.split(/\r?\n/)) {
    const match = line.match(/^([A-Z][A-Z0-9_]*)=(.*)$/);
    if (match) fields[match[1]] = match[2];
  }
  return {
    cloudflared_present: fields.CLOUDFLARED_PRESENT === 'yes',
    argo_active: fields.ARGO_ACTIVE || 'unknown',
    nginx_active: fields.NGINX_ACTIVE || 'unknown',
    nginx_pid_present: fields.NGINX_PID_PRESENT === 'yes',
    argo_connections: Number(fields.ARGO_CONNECTIONS || 0)
  };
}

export async function uninstallTunnel(server) {
  const script = `
set +e
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop argo >/dev/null 2>&1 || true
  systemctl disable argo >/dev/null 2>&1 || true
  systemctl stop argo-nginx >/dev/null 2>&1 || true
  systemctl disable argo-nginx >/dev/null 2>&1 || true
elif command -v rc-service >/dev/null 2>&1; then
  rc-service argo stop >/dev/null 2>&1 || true
  rc-update del argo default >/dev/null 2>&1 || true
  rc-service argo-nginx stop >/dev/null 2>&1 || true
fi
rm -f /etc/systemd/system/argo.service /etc/systemd/system/argo-nginx.service
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ -s /usr/local/etc/xray/nginx.pid ]; then
  kill "$(cat /usr/local/etc/xray/nginx.pid)" >/dev/null 2>&1 || true
fi
rm -f /usr/local/etc/xray/nginx.conf /usr/local/etc/xray/nginx.pid
rm -f /usr/local/etc/xray/tunnel.json /usr/local/etc/xray/tunnel.yml /usr/local/etc/xray/cloudflared.env
rm -f /usr/local/bin/cloudflared
rm -f /var/log/xray-nginx-error.log /var/log/cloudflared.log
echo "TUNNEL_UNINSTALLED=ok"
`;
  const result = await runChecked(runSudo(server, script, { timeout: 60000 }));
  return { ok: true, stdout: result.stdout, stderr: result.stderr };
}
