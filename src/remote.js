import { runChecked, runScript, runSudo } from './ssh.js';
import { buildSingboxConfig } from './singbox.js';
import { createHash } from 'node:crypto';
import {
  buildCertificateScript,
  deployTunnel,
  needsSelfSignedCert,
  readTunnelStatus,
  tunnelRequired,
  withSelfSignedPaths
} from './argo.js';
import { getServerRecord, updateServerArgoDomain } from './db.js';


const PROBE_SCRIPT = `
set -e
printf 'HOSTNAME=%s\\n' "$(hostname 2>/dev/null || echo unknown)"
printf 'UNAME=%s\\n' "$(uname -a 2>/dev/null)"
printf 'OS=%s\\n' "$(cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME=' | cut -d= -f2- | tr -d '"')"
printf 'ARCH=%s\\n' "$(uname -m)"
printf 'UPTIME=%s\\n' "$(uptime 2>/dev/null)"
printf 'MEMORY=%s\\n' "$(free -m 2>/dev/null | awk 'NR==2 {print $2 ":" $3 ":" $4}')"
printf 'DISK=%s\\n' "$(df -h / 2>/dev/null | awk 'NR==2 {print $2 ":" $3 ":" $4 ":" $5}')"
if command -v sing-box >/dev/null 2>&1; then
  printf 'SINGBOX_BIN=%s\\n' "$(command -v sing-box)"
  if /usr/local/bin/sing-box version >/dev/null 2>&1; then
    printf 'SINGBOX_VERSION=%s\\n' "$(/usr/local/bin/sing-box version 2>/dev/null | head -1)"
  else
    printf 'SINGBOX_VERSION=broken\\n'
  fi
else
  printf 'SINGBOX_BIN=not-installed\\n'
  printf 'SINGBOX_VERSION=\\n'
fi
if command -v systemctl >/dev/null 2>&1; then
  printf 'SINGBOX_ACTIVE=%s\\n' "$(systemctl is-active sing-box 2>/dev/null || echo unknown)"
elif command -v rc-service >/dev/null 2>&1; then
  if rc-service sing-box status >/dev/null 2>&1; then
    printf 'SINGBOX_ACTIVE=started\\n'
  else
    printf 'SINGBOX_ACTIVE=stopped\\n'
  fi
else
  printf 'SINGBOX_ACTIVE=unknown\\n'
fi
`;

const INSTALL_SCRIPT = `
set -e
SINGBOX_BIN="/usr/local/bin/sing-box"
if [ -x "$SINGBOX_BIN" ] && [ "$SINGBOX_FORCE" != "1" ] && "$SINGBOX_BIN" version >/dev/null 2>&1; then
  echo "INSTALL_STATE=already-installed"
else
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) SINGBOX_ARCH="amd64" ;;
    aarch64|arm64) SINGBOX_ARCH="arm64" ;;
    armv7l|armhf) SINGBOX_ARCH="armv7" ;;
    i386|i686) SINGBOX_ARCH="386" ;;
    *) echo "UNSUPPORTED_ARCH=$ARCH"; exit 1 ;;
  esac
  if ! command -v curl >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates tar
    elif command -v apk >/dev/null 2>&1; then apk add --no-cache curl ca-certificates tar
    elif command -v dnf >/dev/null 2>&1; then dnf install -y -q curl ca-certificates tar
    elif command -v yum >/dev/null 2>&1; then yum install -y -q curl ca-certificates tar
    else echo "DEPENDENCIES_MISSING"; exit 1; fi
  fi
  RELEASE="$(curl -fsSL --connect-timeout 10 --max-time 30 https://api.github.com/repos/SagerNet/sing-box/releases/latest)"
  VERSION="$(printf '%s' "$RELEASE" | grep -m1 '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')"
  test -n "$VERSION" || { echo "VERSION_RESOLUTION_FAILED"; exit 1; }
  URL="https://github.com/SagerNet/sing-box/releases/download/v$VERSION/sing-box-$VERSION-linux-$SINGBOX_ARCH.tar.gz"
  mkdir -p /var/tmp/vps-node-singbox /usr/local/bin /usr/local/etc/sing-box
  curl -fL --retry 2 --connect-timeout 10 --max-time 120 -o /var/tmp/vps-node-singbox/archive.tar.gz "$URL"
  tar -xzf /var/tmp/vps-node-singbox/archive.tar.gz -C /var/tmp/vps-node-singbox
  EXTRACTED="$(find /var/tmp/vps-node-singbox -type f -name sing-box | head -1)"
  test -n "$EXTRACTED" && "$EXTRACTED" version >/dev/null 2>&1 || { echo "SINGBOX_BINARY_CHECK=failed"; exit 1; }
  install -m 0755 "$EXTRACTED" "$SINGBOX_BIN"
  rm -rf /var/tmp/vps-node-singbox
  echo "INSTALL_STATE=installed"
fi
mkdir -p /usr/local/etc/sing-box
if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/sing-box.service <<'SERVICE'
[Unit]
Description=Sing-box Proxy Service (managed by VPS-Node)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /usr/local/etc/sing-box/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
SERVICE
  systemctl daemon-reload
  systemctl enable sing-box >/dev/null 2>&1 || true
elif command -v rc-service >/dev/null 2>&1; then
  cat > /etc/init.d/sing-box <<'OPENRC'
#!/sbin/openrc-run
name="sing-box"
command="/usr/local/bin/sing-box"
command_args="run -c /usr/local/etc/sing-box/config.json"
command_background="yes"
pidfile="/run/sing-box.pid"
output_log="/var/log/sing-box.log"
error_log="/var/log/sing-box.log"
OPENRC
  chmod 0755 /etc/init.d/sing-box
  rc-update add sing-box default >/dev/null 2>&1 || true
fi
echo "SINGBOX_VERSION=$("$SINGBOX_BIN" version 2>/dev/null | head -1)"
`;
export async function probeServer(server) {
  const result = await runChecked(runScript(server, PROBE_SCRIPT));
  const fields = {};
  for (const line of result.stdout.split(/\r?\n/)) {
    const match = line.match(/^([A-Z][A-Z0-9_]*)=(.*)$/);
    if (match) fields[match[1]] = match[2];
  }
  const [memoryTotal, memoryUsed, memoryFree] = String(fields.MEMORY || '').split(':');
  const [diskTotal, diskUsed, diskFree, diskUsePercent] = String(fields.DISK || '').split(':');
  return {
    ok: true,
    hostname: fields.HOSTNAME || '',
    uname: fields.UNAME || '',
    os: fields.OS || '',
    arch: fields.ARCH || '',
    uptime: fields.UPTIME || '',
    memory: { total: memoryTotal, used: memoryUsed, free: memoryFree },
    disk: { total: diskTotal, used: diskUsed, free: diskFree, usePercent: diskUsePercent },
    sing-box: {
      installed: fields.SINGBOX_BIN !== 'not-installed',
      bin: fields.SINGBOX_BIN,
      version: fields.SINGBOX_VERSION,
      active: fields.SINGBOX_ACTIVE
    }
  };
}

export async function installSingbox(server, { force = false } = {}) {
  const prefix = force ? 'SINGBOX_FORCE=1\n' : '';
  const result = await runChecked(runSudo(server, prefix + INSTALL_SCRIPT, { timeout: 120000 }));
  return { ok: true, stdout: result.stdout, stderr: result.stderr };
}

export async function writeSingboxConfig(server, nodes, routes = []) {
  const config = buildSingboxConfig(withSelfSignedPaths(nodes), routes);
  const json = JSON.stringify(config, null, 2);
  const b64 = Buffer.from(json).toString('base64');
  const script = `
set -e
mkdir -p /usr/local/etc/sing-box
umask 077
STAGED="$(mktemp /usr/local/etc/sing-box/.config.XXXXXX)"
printf '%s' '${b64}' | base64 -d > "$STAGED"
if ! /usr/local/bin/sing-box check -c "$STAGED"; then
  rm -f "$STAGED"
  echo "CONFIG_CHECK_FAILED"
  exit 1
fi
if [ -f /usr/local/etc/sing-box/config.json ]; then
  cp -p /usr/local/etc/sing-box/config.json /usr/local/etc/sing-box/config.json.bak
fi
mv "$STAGED" /usr/local/etc/sing-box/config.json
chmod 600 /usr/local/etc/sing-box/config.json
echo "CONFIG_WRITTEN=ok"
`;
  const result = await runChecked(runSudo(server, script, { timeout: 30000 }));
  return { ok: true, stdout: result.stdout, stderr: result.stderr };
}
export async function restartSingbox(server) {
  const script = `
set -e
SINGBOX_BIN="/usr/local/bin/sing-box"
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable sing-box >/dev/null 2>&1 || true
  if ! systemctl restart sing-box || ! systemctl is-active --quiet sing-box; then
    if [ -f /usr/local/etc/sing-box/config.json.bak ]; then
      cp -p /usr/local/etc/sing-box/config.json.bak /usr/local/etc/sing-box/config.json
      systemctl restart sing-box || true
    fi
    echo "SINGBOX_RESTART_FAILED_ROLLED_BACK"
    exit 1
  fi
  systemctl is-active sing-box
elif command -v rc-service >/dev/null 2>&1; then
  pkill -f 'sing-box run -c' 2>/dev/null || true
  rc-update add sing-box default >/dev/null 2>&1 || true
  rc-service sing-box restart
  rc-service sing-box status || true
else
  pkill -f 'sing-box run -c' 2>/dev/null || true
  sleep 1
  if command -v setsid >/dev/null 2>&1; then
    setsid "$SINGBOX_BIN" run -c /usr/local/etc/sing-box/config.json </dev/null >/var/log/sing-box.log 2>&1 &
  else
    nohup "$SINGBOX_BIN" run -c /usr/local/etc/sing-box/config.json </dev/null >/var/log/sing-box.log 2>&1 &
  fi
  sleep 1
fi
echo "SINGBOX_RESTARTED=ok"
`;
  const result = await runChecked(runSudo(server, script, { timeout: 60000 }));
  return { ok: true, stdout: result.stdout, stderr: result.stderr };
}

const UNINSTALL_SCRIPT = `
set +e

# Remove only the Singbox installation managed by this panel.
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop sing-box >/dev/null 2>&1 || true
  systemctl disable sing-box >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/sing-box.service
  systemctl daemon-reload >/dev/null 2>&1 || true
elif command -v rc-service >/dev/null 2>&1; then
  rc-service sing-box stop >/dev/null 2>&1 || true
  rc-update del sing-box default >/dev/null 2>&1 || true
  rm -f /etc/init.d/sing-box
elif command -v pkill >/dev/null 2>&1; then
  pkill -f 'sing-box run -c' >/dev/null 2>&1 || true
fi

rm -f /usr/local/bin/sing-box
rm -f /etc/sing-box/config.json
rm -f /usr/local/etc/sing-box/config.json
rmdir /etc/sing-box >/dev/null 2>&1 || true
rmdir /usr/local/etc/sing-box >/dev/null 2>&1 || true
rm -f /var/log/sing-box.log
echo "SINGBOX_UNINSTALLED=ok"
`;

export async function uninstallSingbox(server) {
  const result = await runChecked(runSudo(server, UNINSTALL_SCRIPT, { timeout: 60000 }));
  return { ok: true, stdout: result.stdout, stderr: result.stderr };
}

const STATUS_SCRIPT = `
set +e
if command -v sing-box >/dev/null 2>&1 || [ -x /usr/local/bin/sing-box ]; then
  SINGBOX_BIN="$(command -v sing-box 2>/dev/null || echo /usr/local/bin/sing-box)"
  echo "SINGBOX_BIN=$SINGBOX_BIN"
  if "$SINGBOX_BIN" version >/dev/null 2>&1; then
    echo "SINGBOX_VERSION=$("$SINGBOX_BIN" version 2>/dev/null | head -1)"
  else
    echo "SINGBOX_VERSION=broken"
  fi
else
  echo "SINGBOX_BIN=not-installed"
fi
if [ -x /usr/local/bin/sing-box ]; then
  echo "SINGBOX_BIN_PRESENT=yes"
else
  echo "SINGBOX_BIN_PRESENT=no"
fi
if command -v systemctl >/dev/null 2>&1; then
  echo "SINGBOX_ACTIVE=$(systemctl is-active sing-box 2>/dev/null || echo inactive)"
  echo "SINGBOX_ENABLED=$(systemctl is-enabled sing-box 2>/dev/null || echo disabled)"
elif command -v rc-service >/dev/null 2>&1; then
  if rc-service sing-box status >/dev/null 2>&1; then
    echo "SINGBOX_ACTIVE=started"
  else
    echo "SINGBOX_ACTIVE=stopped"
  fi
  if rc-update show default 2>/dev/null | grep -q sing-box; then
    echo "SINGBOX_ENABLED=enabled"
  else
    echo "SINGBOX_ENABLED=disabled"
  fi
else
  echo "SINGBOX_ACTIVE=unknown"
fi
CONFIG_PATH=""
if command -v systemctl >/dev/null 2>&1; then
  CONFIG_PATH="$(systemctl show -p ExecStart --value sing-box 2>/dev/null | sed -n 's/.*-c[ =]*\\([^ ]*\\).*/\\1/p')"
fi
if [ -z "$CONFIG_PATH" ] && command -v ps >/dev/null 2>&1; then
  CONFIG_PATH="$(ps -ef 2>/dev/null | grep '[x]ray run' | head -1 | sed -n 's/.*-c[ =]*\\([^ ]*\\).*/\\1/p')"
fi
if [ -z "$CONFIG_PATH" ]; then
  for CANDIDATE in /usr/local/etc/sing-box/config.json /etc/sing-box/config.json /usr/local/etc/v2ray/config.json; do
    if [ -f "$CANDIDATE" ]; then CONFIG_PATH="$CANDIDATE"; break; fi
  done
fi
if [ -z "$CONFIG_PATH" ]; then CONFIG_PATH="/usr/local/etc/sing-box/config.json"; fi
echo "CONFIG_PATH=$CONFIG_PATH"
if [ -f "$CONFIG_PATH" ]; then
  echo "CONFIG_EXISTS=yes"
  CONFIG_B64="$(base64 -w0 "$CONFIG_PATH" 2>/dev/null | tr -d '\\n')"
  if [ -z "$CONFIG_B64" ]; then
    CONFIG_B64="$(busybox base64 -w0 "$CONFIG_PATH" 2>/dev/null | tr -d '\\n')"
  fi
  if [ -z "$CONFIG_B64" ]; then
    CONFIG_B64="$(openssl base64 -A -in "$CONFIG_PATH" 2>/dev/null | tr -d '\\n')"
  fi
  if [ -n "$CONFIG_B64" ]; then
    echo "CONFIG_B64=$CONFIG_B64"
  else
    echo "CONFIG_READABLE=no"
  fi
else
  echo "CONFIG_EXISTS=no"
fi
if command -v ss >/dev/null 2>&1; then
  echo "TCP_PORTS=$(ss -lnt 2>/dev/null | awk 'NR>1 {n=split($4,a,":"); print a[length(a)]}' | sort -n -u | tr '\\n' ',')"
  echo "UDP_PORTS=$(ss -lnu 2>/dev/null | awk 'NR>1 {n=split($4,a,":"); print a[length(a)]}' | sort -n -u | tr '\\n' ',')"
elif command -v netstat >/dev/null 2>&1; then
  echo "TCP_PORTS=$(netstat -lnt 2>/dev/null | awk 'NR>2 {n=split($4,a,":"); print a[length(a)]}' | sort -n -u | tr '\\n' ',')"
  echo "UDP_PORTS=$(netstat -lnu 2>/dev/null | awk 'NR>2 {n=split($4,a,":"); print a[length(a)]}' | sort -n -u | tr '\\n' ',')"
fi
echo "STATUS_DONE=yes"
`;

const READ_CONFIG_AS_ROOT_SCRIPT = (configPath) => `
set +e
CONFIG_PATH='${configPath}'
if [ -f "$CONFIG_PATH" ] && [ -r "$CONFIG_PATH" ]; then
  CONFIG_B64="$(base64 -w0 "$CONFIG_PATH" 2>/dev/null | tr -d '\\n')"
  if [ -z "$CONFIG_B64" ]; then
    CONFIG_B64="$(busybox base64 -w0 "$CONFIG_PATH" 2>/dev/null | tr -d '\\n')"
  fi
  if [ -z "$CONFIG_B64" ]; then
    CONFIG_B64="$(openssl base64 -A -in "$CONFIG_PATH" 2>/dev/null | tr -d '\\n')"
  fi
  if [ -n "$CONFIG_B64" ]; then
    echo "CONFIG_B64=$CONFIG_B64"
    echo "CONFIG_READABLE=yes"
  else
    echo "CONFIG_READABLE=no"
  fi
else
  echo "CONFIG_READABLE=no"
fi
`;

export function parseStatusOutput(stdout) {
  const fields = {};
  for (const line of String(stdout || '').split(/\r?\n/)) {
    const match = line.match(/^([A-Z][A-Z0-9_]*)=(.*)$/);
    if (match) fields[match[1]] = match[2];
  }
  return fields;
}

function parsePortList(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .map(Number)
    .filter((port) => Number.isInteger(port) && port > 0 && port <= 65535);
}

export function classifySshError(error) {
  const message = String(error?.message || error || '');
  if (/All configured authentication methods failed|Permission denied|Authentication failed|Unable to authenticate|Cannot parse privateKey/i.test(message)) {
    return 'SSH 认证失败：请检查用户名、密码或私钥';
  }
  if (/timed out|timeout|ETIMEDOUT/i.test(message)) {
    return 'SSH 连接超时：请检查服务器地址或防火墙';
  }
  if (/ECONNREFUSED|Connection refused/i.test(message)) {
    return 'SSH 连接被拒绝：请确认端口和 SSH 服务';
  }
  if (/ENOTFOUND|getaddrinfo|Name or service not known/i.test(message)) {
    return '无法解析服务器地址：请检查主机名或 IP';
  }
  if (/EHOSTUNREACH|ENETUNREACH|No route to host/i.test(message)) {
    return '服务器不可达：请检查网络或防火墙';
  }
  if (/ECONNRESET|socket hang up|Connection reset|Connection lost before handshake/i.test(message)) {
    return 'SSH 连接中断：服务器在握手前关闭了连接或端口不正确';
  }
  if (/sudo password is required/i.test(message)) {
    return '缺少 sudo 密码：该服务器需要 sudo 权限';
  }
  return `SSH 连接失败：${message}`;
}

function canUseSudo(server) {
  if (!server || server.username === 'root') return false;
  return Boolean(server.sudo_password || server.auth_type === 'password');
}

export function buildNodeStatuses(nodes = [], configData = null, tcpPorts = [], udpPorts = []) {
  const tcpSet = new Set(tcpPorts.map(Number));
  const udpSet = new Set(udpPorts.map(Number));
  const inbounds = Array.isArray(configData?.inbounds) ? configData.inbounds : [];
  return (nodes || []).map((node) => {
    const port = Number(node.port);
    const inbound = inbounds.find((item) => Number(item.port) === port && String(item.protocol) === String(node.protocol));
    return {
      id: node.id,
      name: node.name,
      protocol: node.protocol,
      port,
      role: node.role || 'inbound',
      enabled: node.enabled,
      in_config: Boolean(inbound),
      config_tag: inbound?.tag || '',
      listening_tcp: tcpSet.has(port),
      listening_udp: udpSet.has(port),
      listening: tcpSet.has(port) || udpSet.has(port)
    };
  });
}

export async function singboxStatus(server, nodes = [], options = {}) {
  const startedAt = Date.now();
  let result;
  try {
    const timeout = options.timeout || 20000;
    result = await runScript(server, STATUS_SCRIPT, { timeout });
  } catch (error) {
    return {
      ok: false,
      checked_at: new Date().toISOString(),
      ssh: { connected: false, error: classifySshError(error) },
      sing-box: null,
      config: null,
      ports: [],
      nodes: [],
      tunnel: null,
      elapsed_ms: Date.now() - startedAt,
      listening: ''
    };
  }

  let tunnel = null;
  const tunnelNeeded = tunnelRequired(server, nodes);
  if (tunnelNeeded) {
    try {
      tunnel = await readTunnelStatus(server);
    } catch {
      tunnel = { error: 'tunnel status unavailable' };
    }
  }

  const fields = parseStatusOutput(result.stdout);
  const tcpPorts = parsePortList(fields.TCP_PORTS);
  const udpPorts = parsePortList(fields.UDP_PORTS);

  let configB64 = fields.CONFIG_B64 || '';
  if (fields.CONFIG_EXISTS === 'yes' && !configB64 && canUseSudo(server)) {
    try {
      const configPath = fields.CONFIG_PATH || '/usr/local/etc/sing-box/config.json';
      const sudoResult = await runSudo(server, READ_CONFIG_AS_ROOT_SCRIPT(configPath), { timeout: 15000 });
      const sudoFields = parseStatusOutput(sudoResult.stdout);
      if (sudoFields.CONFIG_B64) configB64 = sudoFields.CONFIG_B64;
    } catch { /* keep the config marked unreadable */ }
  }

  let configData = null;
  let configValid = null;
  let configSha256 = null;
  if (configB64) {
    try {
      const configRaw = Buffer.from(configB64, 'base64');
      configSha256 = createHash('sha256').update(configRaw).digest('hex');
      configData = JSON.parse(configRaw.toString('utf8'));
      configValid = Boolean(configData);
    } catch {
      configValid = false;
    }
  }

  const installed = fields.SINGBOX_BIN !== 'not-installed';
  const active = fields.SINGBOX_ACTIVE || 'unknown';
  const running = ['active', 'started'].includes(active);
  const allPorts = [...new Set([...tcpPorts, ...udpPorts])];

  return {
    ok: true,
    checked_at: new Date().toISOString(),
    ssh: {
      connected: true,
      host: server.host,
      port: Number(server.port || 22),
      username: server.username
    },
    sing-box: {
      installed,
      bin_present: fields.SINGBOX_BIN_PRESENT === 'yes',
      bin: installed ? fields.SINGBOX_BIN : '',
      version: fields.SINGBOX_VERSION || '',
      active,
      enabled: fields.SINGBOX_ENABLED || 'unknown',
      running
    },
    config: {
      exists: fields.CONFIG_EXISTS === 'yes',
      readable: Boolean(configB64),
      valid: configValid,
      path: fields.CONFIG_PATH || '/usr/local/etc/sing-box/config.json'
      ,
      sha256: configSha256
    },
    ports: {
      available: fields.TCP_PORTS !== undefined || fields.UDP_PORTS !== undefined,
      tcp: tcpPorts,
      udp: udpPorts
    },
    nodes: buildNodeStatuses(nodes, configData, tcpPorts, udpPorts),
    tunnel,
    elapsed_ms: Date.now() - startedAt,
    listening: allPorts.join(', ')
  };
}

export async function singboxLogs(server, lines = 100) {
  const count = Number.isInteger(lines) ? Math.max(1, Math.min(lines, 500)) : 100;
  const script = `
if command -v journalctl >/dev/null 2>&1; then
  journalctl -u sing-box -n ${count} --no-pager 2>/dev/null || true
elif [ -f /var/log/sing-box.log ]; then
  tail -n ${count} /var/log/sing-box.log
else
  echo "NO_LOGS_AVAILABLE"
fi
`;
  const result = await runScript(server, script);
  return { ok: true, stdout: result.stdout, stderr: result.stderr };
}

export async function deployServer(server, nodes, options = {}) {
  const routes = options.routes || [];
  const enabledNodes = nodes.filter((node) => node.enabled !== 0 && node.enabled !== false);
  const report = typeof options.onProgress === 'function' ? options.onProgress : () => {};
  const step = async (id, task) => {
    report(id, 'running');
    const result = await task();
    report(id, 'done');
    return result;
  };

  if (needsSelfSignedCert(enabledNodes)) {
    const sni = enabledNodes.find((node) => node.self_signed === 1 || node.protocol === 'hysteria2')?.sni || 'localhost';
    await step('certificate', () => runChecked(runSudo(server, buildCertificateScript(undefined, undefined, sni), { timeout: 60000 })));
  }
  await step('install-sing-box', () => installSingbox(server, options));
  await step('write-config', () => writeSingboxConfig(server, nodes, routes));
  const restart = await step('restart-sing-box', () => restartSingbox(server));

  let tunnel = null;
  if (tunnelRequired(server, enabledNodes)) {
    tunnel = await deployTunnel(server, enabledNodes, options);
    if (tunnel?.argo_domain) {
      updateServerArgoDomain(server.id, tunnel.argo_domain);
      server = getServerRecord(server.id) || server;
    }
  }

  const status = await step('status', () => singboxStatus(server, nodes));
  return { ok: true, restart, tunnel, status };
}
