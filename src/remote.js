import { runChecked, runScript, runSudo } from './ssh.js';
import { buildXrayConfig } from './xray.js';
import { createHash } from 'node:crypto';


const PROBE_SCRIPT = `
set -e
printf 'HOSTNAME=%s\\n' "$(hostname 2>/dev/null || echo unknown)"
printf 'UNAME=%s\\n' "$(uname -a 2>/dev/null)"
printf 'OS=%s\\n' "$(cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME=' | cut -d= -f2- | tr -d '"')"
printf 'ARCH=%s\\n' "$(uname -m)"
printf 'UPTIME=%s\\n' "$(uptime 2>/dev/null)"
printf 'MEMORY=%s\\n' "$(free -m 2>/dev/null | awk 'NR==2 {print $2 ":" $3 ":" $4}')"
printf 'DISK=%s\\n' "$(df -h / 2>/dev/null | awk 'NR==2 {print $2 ":" $3 ":" $4 ":" $5}')"
if command -v xray >/dev/null 2>&1; then
  printf 'XRAY_BIN=%s\\n' "$(command -v xray)"
  if /usr/local/bin/xray version >/dev/null 2>&1; then
    printf 'XRAY_VERSION=%s\\n' "$(/usr/local/bin/xray version 2>/dev/null | head -1)"
  else
    printf 'XRAY_VERSION=broken\\n'
  fi
else
  printf 'XRAY_BIN=not-installed\\n'
  printf 'XRAY_VERSION=\\n'
fi
if command -v systemctl >/dev/null 2>&1; then
  printf 'XRAY_ACTIVE=%s\\n' "$(systemctl is-active xray 2>/dev/null || echo unknown)"
elif command -v rc-service >/dev/null 2>&1; then
  if rc-service xray status >/dev/null 2>&1; then
    printf 'XRAY_ACTIVE=started\\n'
  else
    printf 'XRAY_ACTIVE=stopped\\n'
  fi
else
  printf 'XRAY_ACTIVE=unknown\\n'
fi
`;

const INSTALL_SCRIPT = `
set -e

XRAY_FORCE="\${XRAY_FORCE:-0}"
XRAY_BIN="/usr/local/bin/xray"
ALREADY_INSTALLED=0

if [ -x "$XRAY_BIN" ]; then
  if [ "$XRAY_FORCE" = "1" ]; then
    echo "INSTALL_STATE=force-reinstall"
    rm -f "$XRAY_BIN"
  elif "$XRAY_BIN" version >/dev/null 2>&1; then
    echo "INSTALL_STATE=already-installed"
    "$XRAY_BIN" version 2>/dev/null | head -1
    ALREADY_INSTALLED=1
  else
    echo "INSTALL_STATE=broken-binary"
    rm -f "$XRAY_BIN"
  fi
fi

if [ "$ALREADY_INSTALLED" != "1" ]; then
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) XRAY_ARCH="64" ;;
    aarch64|arm64) XRAY_ARCH="arm64-v8a" ;;
    armv7l|armhf) XRAY_ARCH="arm32-v7a" ;;
    i386|i686) XRAY_ARCH="32" ;;
    *) echo "UNSUPPORTED_ARCH=$ARCH"; exit 1 ;;
  esac

  echo "INSTALL_STATE=installing arch=$XRAY_ARCH"

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq curl unzip
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q curl unzip
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl unzip
  else
    echo "NO_PACKAGE_MANAGER"
    exit 1
  fi

  mkdir -p /var/tmp/xray-pkg /usr/local/bin /usr/local/etc/xray

  attempt=0
  while [ "$attempt" -lt 3 ]; do
    attempt=$((attempt + 1))
    rm -rf /var/tmp/xray-pkg
    mkdir -p /var/tmp/xray-pkg
    if curl -fsSL -o /var/tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-\${XRAY_ARCH}.zip" \
      && unzip -qo /var/tmp/xray.zip -d /var/tmp/xray-pkg \
      && [ -f /var/tmp/xray-pkg/xray ] \
      && /var/tmp/xray-pkg/xray version >/dev/null 2>&1; then
      break
    fi
    echo "XRAY_DOWNLOAD_ATTEMPT=$attempt failed"
    rm -f /var/tmp/xray.zip
  done

  if [ ! -f /var/tmp/xray-pkg/xray ] || ! /var/tmp/xray-pkg/xray version >/dev/null 2>&1; then
    echo "XRAY_BINARY_CHECK=failed"
    exit 1
  fi

  install -m 0755 /var/tmp/xray-pkg/xray "$XRAY_BIN"
  rm -rf /var/tmp/xray-pkg /var/tmp/xray.zip
  echo "XRAY_VERSION=$("$XRAY_BIN" version 2>/dev/null | head -1)"
fi

if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/xray.service <<'SERVICE'
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SERVICE

  systemctl daemon-reload
  systemctl enable xray >/dev/null 2>&1 || true
  if [ -f /usr/local/etc/xray/config.json ]; then
    systemctl restart xray
    echo "INSTALL_STATE=started"
  else
    echo "INSTALL_STATE=installed-waiting-config"
  fi
elif command -v rc-service >/dev/null 2>&1; then
  cat > /etc/init.d/xray <<'OPENRC'
#!/sbin/openrc-run

name="xray"
description="Xray service"

command="/usr/local/bin/xray"
command_args="run -config /usr/local/etc/xray/config.json"
command_background="yes"
pidfile="/run/\${RC_SVCNAME}.pid"
output_log="/var/log/xray.log"
error_log="/var/log/xray.log"
OPENRC
  chmod 0755 /etc/init.d/xray
  rc-update add xray default >/dev/null 2>&1 || true
  if [ -f /usr/local/etc/xray/config.json ]; then
    rc-service xray restart
    echo "INSTALL_STATE=started"
  else
    echo "INSTALL_STATE=installed-waiting-config"
  fi
else
  echo "INSTALL_STATE=installed"
fi
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
    xray: {
      installed: fields.XRAY_BIN !== 'not-installed',
      bin: fields.XRAY_BIN,
      version: fields.XRAY_VERSION,
      active: fields.XRAY_ACTIVE
    }
  };
}

export async function installXray(server, { force = false } = {}) {
  const prefix = force ? 'XRAY_FORCE=1\n' : '';
  const result = await runChecked(runSudo(server, prefix + INSTALL_SCRIPT, { timeout: 120000 }));
  return { ok: true, stdout: result.stdout, stderr: result.stderr };
}

export async function writeXrayConfig(server, nodes, routes = []) {
  const config = buildXrayConfig(nodes, routes);
  const json = JSON.stringify(config, null, 2);
  const b64 = Buffer.from(json).toString('base64');
  const script = `
set -e
mkdir -p /usr/local/etc/xray
cat > /var/tmp/xray-config.b64 <<'EOF'
${b64}
EOF
base64 -d /var/tmp/xray-config.b64 > /usr/local/etc/xray/config.json
chmod 600 /usr/local/etc/xray/config.json
rm -f /var/tmp/xray-config.b64
echo "CONFIG_WRITTEN=ok"
`;
  const result = await runChecked(runSudo(server, script, { timeout: 60000 }));
  return { ok: true, stdout: result.stdout, stderr: result.stderr };
}

export async function restartXray(server) {
  const script = `
set -e
XRAY_BIN="/usr/local/bin/xray"
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray
  systemctl is-active xray
elif command -v rc-service >/dev/null 2>&1; then
  pkill -f 'xray run -config' 2>/dev/null || true
  rc-update add xray default >/dev/null 2>&1 || true
  rc-service xray restart
  rc-service xray status || true
else
  pkill -f 'xray run -config' 2>/dev/null || true
  sleep 1
  if command -v setsid >/dev/null 2>&1; then
    setsid "$XRAY_BIN" run -config /usr/local/etc/xray/config.json </dev/null >/var/log/xray.log 2>&1 &
  else
    nohup "$XRAY_BIN" run -config /usr/local/etc/xray/config.json </dev/null >/var/log/xray.log 2>&1 &
  fi
  sleep 1
fi
echo "XRAY_RESTARTED=ok"
`;
  const result = await runChecked(runSudo(server, script, { timeout: 60000 }));
  return { ok: true, stdout: result.stdout, stderr: result.stderr };
}

const STATUS_SCRIPT = `
set +e
if command -v xray >/dev/null 2>&1 || [ -x /usr/local/bin/xray ]; then
  XRAY_BIN="$(command -v xray 2>/dev/null || echo /usr/local/bin/xray)"
  echo "XRAY_BIN=$XRAY_BIN"
  if "$XRAY_BIN" version >/dev/null 2>&1; then
    echo "XRAY_VERSION=$("$XRAY_BIN" version 2>/dev/null | head -1)"
  else
    echo "XRAY_VERSION=broken"
  fi
else
  echo "XRAY_BIN=not-installed"
fi
if [ -x /usr/local/bin/xray ]; then
  echo "XRAY_BIN_PRESENT=yes"
else
  echo "XRAY_BIN_PRESENT=no"
fi
if command -v systemctl >/dev/null 2>&1; then
  echo "XRAY_ACTIVE=$(systemctl is-active xray 2>/dev/null || echo inactive)"
  echo "XRAY_ENABLED=$(systemctl is-enabled xray 2>/dev/null || echo disabled)"
elif command -v rc-service >/dev/null 2>&1; then
  if rc-service xray status >/dev/null 2>&1; then
    echo "XRAY_ACTIVE=started"
  else
    echo "XRAY_ACTIVE=stopped"
  fi
  if rc-update show default 2>/dev/null | grep -q xray; then
    echo "XRAY_ENABLED=enabled"
  else
    echo "XRAY_ENABLED=disabled"
  fi
else
  echo "XRAY_ACTIVE=unknown"
fi
CONFIG_PATH=""
if command -v systemctl >/dev/null 2>&1; then
  CONFIG_PATH="$(systemctl show -p ExecStart --value xray 2>/dev/null | sed -n 's/.*-config[ =]*\\([^ ]*\\).*/\\1/p')"
fi
if [ -z "$CONFIG_PATH" ] && command -v ps >/dev/null 2>&1; then
  CONFIG_PATH="$(ps -ef 2>/dev/null | grep '[x]ray run' | head -1 | sed -n 's/.*-config[ =]*\\([^ ]*\\).*/\\1/p')"
fi
if [ -z "$CONFIG_PATH" ]; then
  for CANDIDATE in /usr/local/etc/xray/config.json /etc/xray/config.json /usr/local/etc/v2ray/config.json; do
    if [ -f "$CANDIDATE" ]; then CONFIG_PATH="$CANDIDATE"; break; fi
  done
fi
if [ -z "$CONFIG_PATH" ]; then CONFIG_PATH="/usr/local/etc/xray/config.json"; fi
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
  if (/ECONNRESET|socket hang up|Connection reset/i.test(message)) {
    return 'SSH 连接中断：服务器可能关闭了连接';
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

export async function xrayStatus(server, nodes = [], options = {}) {
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
      xray: null,
      config: null,
      ports: [],
      nodes: [],
      elapsed_ms: Date.now() - startedAt,
      listening: ''
    };
  }

  const fields = parseStatusOutput(result.stdout);
  const tcpPorts = parsePortList(fields.TCP_PORTS);
  const udpPorts = parsePortList(fields.UDP_PORTS);

  let configB64 = fields.CONFIG_B64 || '';
  if (fields.CONFIG_EXISTS === 'yes' && !configB64 && canUseSudo(server)) {
    try {
      const configPath = fields.CONFIG_PATH || '/usr/local/etc/xray/config.json';
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

  const installed = fields.XRAY_BIN !== 'not-installed';
  const active = fields.XRAY_ACTIVE || 'unknown';
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
    xray: {
      installed,
      bin_present: fields.XRAY_BIN_PRESENT === 'yes',
      bin: installed ? fields.XRAY_BIN : '',
      version: fields.XRAY_VERSION || '',
      active,
      enabled: fields.XRAY_ENABLED || 'unknown',
      running
    },
    config: {
      exists: fields.CONFIG_EXISTS === 'yes',
      readable: Boolean(configB64),
      valid: configValid,
      path: fields.CONFIG_PATH || '/usr/local/etc/xray/config.json'
      ,
      sha256: configSha256
    },
    ports: {
      available: fields.TCP_PORTS !== undefined || fields.UDP_PORTS !== undefined,
      tcp: tcpPorts,
      udp: udpPorts
    },
    nodes: buildNodeStatuses(nodes, configData, tcpPorts, udpPorts),
    elapsed_ms: Date.now() - startedAt,
    listening: allPorts.join(', ')
  };
}

export async function xrayLogs(server, lines = 100) {
  const count = Number.isInteger(lines) ? Math.max(1, Math.min(lines, 500)) : 100;
  const script = `
if command -v journalctl >/dev/null 2>&1; then
  journalctl -u xray -n ${count} --no-pager 2>/dev/null || true
elif [ -f /var/log/xray.log ]; then
  tail -n ${count} /var/log/xray.log
else
  echo "NO_LOGS_AVAILABLE"
fi
`;
  const result = await runScript(server, script);
  return { ok: true, stdout: result.stdout, stderr: result.stderr };
}

export async function deployServer(server, nodes, options = {}) {
  const routes = options.routes || [];
  await installXray(server, options);
  await writeXrayConfig(server, nodes, routes);
  const restart = await restartXray(server);
  const status = await xrayStatus(server);
  return { ok: true, restart, status };
}
