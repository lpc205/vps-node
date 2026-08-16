import { runChecked, runScript, runSudo } from './ssh.js';
import { buildXrayConfig } from './xray.js';

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
    const match = line.match(/^([A-Z_]+)=(.*)$/);
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

export async function xrayStatus(server) {
  const script = `
if command -v xray >/dev/null 2>&1; then
  XRAY_BIN="$(command -v xray)"
  echo "XRAY_BIN=$XRAY_BIN"
  if "$XRAY_BIN" version >/dev/null 2>&1; then
    echo "XRAY_VERSION=$("$XRAY_BIN" version 2>/dev/null | head -1)"
  else
    echo "XRAY_VERSION=broken"
  fi
else
  echo "XRAY_BIN=not-installed"
fi
if command -v systemctl >/dev/null 2>&1; then
  echo "XRAY_ACTIVE=$(systemctl is-active xray 2>/dev/null || echo inactive)"
  echo "XRAY_ENABLED=$(systemctl is-enabled xray 2>/dev/null || echo unknown)"
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
if command -v ss >/dev/null 2>&1; then
  ss -lntp 2>/dev/null | grep -E 'xray|:11443' || true
fi
`;
  const result = await runScript(server, script);
  const fields = {};
  for (const line of result.stdout.split(/\r?\n/)) {
    const match = line.match(/^([A-Z_]+)=(.*)$/);
    if (match) fields[match[1]] = match[2];
  }
  return {
    ok: true,
    xray: {
      installed: fields.XRAY_BIN !== 'not-installed',
      bin: fields.XRAY_BIN,
      version: fields.XRAY_VERSION,
      active: fields.XRAY_ACTIVE,
      enabled: fields.XRAY_ENABLED
    },
    listening: result.stdout
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
