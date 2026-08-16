const state = {
  servers: [],
  nodes: [],
  routes: [],
  subscriptions: [],
  subscriptionTokens: {},
  probes: {},
  statuses: {},
  autoRepairNotified: new Set(),
  selectedInboundId: null,
  selectedOutboundId: null,
  selectedServerId: null,
  stats: { servers: 0, nodes: 0, enabledNodes: 0 }
};

let terminalSession = null;

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

const REALITY_PRESETS = [
  { name: 'Microsoft', dest: 'www.microsoft.com:443', serverNames: 'www.microsoft.com', sni: 'www.microsoft.com' },
  { name: 'Apple', dest: 'www.apple.com:443', serverNames: 'www.apple.com', sni: 'www.apple.com' },
  { name: 'Cloudflare', dest: 'www.cloudflare.com:443', serverNames: 'www.cloudflare.com', sni: 'www.cloudflare.com' },
  { name: 'Google', dest: 'dl.google.com:443', serverNames: 'dl.google.com', sni: 'dl.google.com' },
  { name: 'Amazon', dest: 'www.amazon.com:443', serverNames: 'www.amazon.com', sni: 'www.amazon.com' },
  { name: 'Mozilla', dest: 'addons.mozilla.org:443', serverNames: 'addons.mozilla.org', sni: 'addons.mozilla.org' },
  { name: 'Bing', dest: 'www.bing.com:443', serverNames: 'www.bing.com', sni: 'www.bing.com' },
  { name: 'GitHub', dest: 'github.com:443', serverNames: 'github.com', sni: 'github.com' }
];

const SS_METHODS = [
  'aes-128-gcm',
  'aes-256-gcm',
  'chacha20-poly1305',
  'chacha20-ietf-poly1305',
  'xchacha20-ietf-poly1305',
  '2022-blake3-aes-128-gcm',
  '2022-blake3-aes-256-gcm',
  '2022-blake3-chacha20-poly1305'
];

function decodeBase64Text(value) {
  let input = String(value || '').trim().replace(/-/g, '+').replace(/_/g, '/');
  try { input = decodeURIComponent(input); } catch { /* keep raw base64 */ }
  while (input.length % 4) input += '=';
  try {
    const binary = atob(input);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch { return ''; }
}

function parseV2rayClientLink(raw) {
  const text = String(raw || '').trim();
  if (!text) return null;
  if (text.startsWith('vmess://')) {
    const payload = text.slice(8);
    const decoded = decodeBase64Text(payload.split('#')[0]) || payload;
    try {
      const data = JSON.parse(decoded);
      return {
        email: String(data.ps || data.remark || '').trim(),
        secret: String(data.id || '').trim(),
        security: String(data.scy || data.security || 'auto').trim() || 'auto',
        flow: String(data.flow || '').trim()
      };
    } catch { return null; }
  }
  const schemes = [
    ['vless://', 8], ['trojan://', 9], ['ss://', 5], ['socks5://', 9], ['socks://', 8]
  ];
  const scheme = schemes.find(([prefix]) => text.startsWith(prefix));
  if (!scheme) return null;
  const prefix = scheme[0];
  const after = text.slice(prefix.length);
  const hashIndex = after.indexOf('#');
  const fragment = hashIndex >= 0 ? after.slice(hashIndex + 1) : '';
  const main = hashIndex >= 0 ? after.slice(0, hashIndex) : after;
  const queryIndex = main.indexOf('?');
  const queryPart = queryIndex >= 0 ? main.slice(queryIndex + 1) : '';
  const authority = queryIndex >= 0 ? main.slice(0, queryIndex) : main;
  const params = new URLSearchParams(queryPart);
  let email = '';
  try { email = decodeURIComponent(fragment); } catch { email = fragment; }
  email = email.trim() || params.get('remark') || '';
  if (prefix === 'ss://') {
    const atIndex = authority.indexOf('@');
    const encodedUser = atIndex >= 0 ? authority.slice(0, atIndex) : authority;
    const decodedInfo = decodeBase64Text(encodedUser);
    const userInfo = decodedInfo && SS_METHODS.some((method) => decodedInfo.startsWith(`${method}:`))
      ? decodedInfo
      : encodedUser;
    const colonIndex = userInfo.lastIndexOf(':');
    if (colonIndex <= 0) return null;
    let secret = userInfo.slice(colonIndex + 1);
    try { secret = decodeURIComponent(secret); } catch { /* keep */ }
    return { email, secret, security: '', flow: '' };
  }
  if (prefix === 'socks://' || prefix === 'socks5://') {
    const atIndex = authority.lastIndexOf('@');
    const userInfo = atIndex >= 0 ? authority.slice(0, atIndex) : '';
    const colonIndex = userInfo.indexOf(':');
    const user = colonIndex >= 0 ? userInfo.slice(0, colonIndex) : '';
    const pass = colonIndex >= 0 ? userInfo.slice(colonIndex + 1) : '';
    let decodedUser = user;
    try { decodedUser = decodeURIComponent(user); } catch { /* keep */ }
    let decodedPass = pass;
    try { decodedPass = decodeURIComponent(pass); } catch { /* keep */ }
    return { email: decodedUser || email, secret: decodedPass, security: '', flow: '' };
  }
  const atIndex = authority.indexOf('@');
  if (atIndex < 0) return null;
  let secret = authority.slice(0, atIndex);
  try { secret = decodeURIComponent(secret); } catch { /* keep */ }
  const security = params.get('security') || '';
  return {
    email,
    secret,
    security: security === 'tls' || security === 'reality' ? 'auto' : '',
    flow: params.get('flow') || ''
  };
}

function randomClientSecret() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function randomClientPassword() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = new Uint8Array(18);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join('');
}

function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char]));
}

function parseServerInfo(raw) {
  const result = { host: '', port: 22, username: '', password: '' };
  const text = String(raw || '').trim();
  if (!text) return result;

  try {
    const json = JSON.parse(text);
    if (json && typeof json === 'object') {
      result.host = String(json.host || json.ip || json['主机'] || '').trim();
      result.port = Number(json.port || json.ssh_port || json['端口'] || 22);
      result.username = String(json.username || json.user || json['用户名'] || '').trim();
      result.password = String(json.password || json.pass || json['密码'] || '').trim();
      if (result.host) return result;
    }
  } catch { /* not JSON */ }

  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const joined = lines.join(' ');
  const atMatch = text.match(/(?:ssh:\/\/)?([^\s@:\/]+)@([^\s\/:@]+)(?::(\d{1,5}))?/i);
  if (atMatch) {
    result.username = atMatch[1];
    result.host = atMatch[2];
    if (atMatch[3]) result.port = Number(atMatch[3]);
    const tail = text.slice(text.indexOf(atMatch[0]) + atMatch[0].length);
    const passwordMatch = tail.match(/(?:password|pass|密码)[:=：]\s*(\S+)/i)
      || tail.match(/(?:-p\s+\d{1,5}\s*)?(\S+)/);
    if (passwordMatch) result.password = passwordMatch[1];
  } else {
    const colonMatch = text.match(/^\s*([^\s:]+):(\d{1,5}):([^:\s]+):(.*)$/m);
    if (colonMatch) {
      result.host = colonMatch[1];
      result.port = Number(colonMatch[2]);
      result.username = colonMatch[3];
      result.password = colonMatch[4].trim();
    } else {
      const hostMatch = text.match(/\b((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,})\b/i);
      if (hostMatch) result.host = hostMatch[1];
      if (result.host) {
        const tokens = joined.replace(/[,，;；]/g, ' ').split(/\s+/).filter(Boolean)
          .map((token) => token.replace(/^['"`]|['"`]$/g, ''));
        const hostIndex = tokens.findIndex((token) => token === result.host);
        if (hostIndex >= 0) tokens.splice(hostIndex, 1);
        const portIndex = tokens.findIndex((token) => /^\d{1,5}$/.test(token) && Number(token) >= 1 && Number(token) <= 65535);
        if (portIndex >= 0) {
          result.port = Number(tokens[portIndex]);
          tokens.splice(portIndex, 1);
        }
        const userIndex = tokens.findIndex((token) => !/^(password|pass|密码|pwd)$/i.test(token));
        if (userIndex >= 0) result.username = tokens[userIndex];
        const remaining = tokens.filter((_, index) => index !== userIndex)
          .filter((token) => !/^(password|pass|密码|pwd)$/i.test(token));
        if (remaining.length) result.password = remaining.join(' ');
      }
    }
  }

  const portFlag = text.match(/(?:-p|-P)\s+(\d{1,5})/i);
  if (portFlag) result.port = Number(portFlag[1]);
  const labeledPassword = text.match(/(?:password|pass|密码)[:=：]\s*(\S+)/i);
  if (labeledPassword) result.password = labeledPassword[1];
  if (!Number.isInteger(result.port) || result.port < 1 || result.port > 65535) result.port = 22;
  return result;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  });
  if (!response.ok) {
    let payload;
    try {
      payload = await response.json();
    } catch {
      payload = { error: response.statusText };
    }
    throw new Error(payload.error || `request failed (${response.status})`);
  }
  if (response.status === 204) return null;
  return response.json();
}

function toast(message, type = 'info') {
  const item = document.createElement('div');
  item.className = `toast ${type}`;
  item.setAttribute('role', type === 'error' ? 'alert' : 'status');
  item.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');
  const icon = { success: 'check-circle-2', error: 'circle-alert', info: 'info' }[type] || 'info';
  item.innerHTML = `<i data-lucide="${icon}"></i><span></span>`;
  item.querySelector('span').textContent = message;
  $('#toast-root').appendChild(item);
  refreshIcons();
  setTimeout(() => item.classList.add('leaving'), 3700);
  setTimeout(() => item.remove(), 4200);
}

async function withBusy(button, busyText, fn) {
  if (!button) return fn();
  const original = button.innerHTML;
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  button.innerHTML = `<span class="btn-loading"><i data-lucide="loader-circle"></i>${escapeHtml(busyText)}</span>`;
  refreshIcons();
  try {
    return await fn();
  } finally {
    button.disabled = false;
    button.removeAttribute('aria-busy');
    button.innerHTML = original;
    refreshIcons();
  }
}

function setPage(title, subtitle) {
  const titleElement = $('#page-title');
  const subtitleElement = $('#page-subtitle');
  titleElement.textContent = title;
  subtitleElement.textContent = subtitle;
  [titleElement, subtitleElement].forEach((element) => {
    element.classList.remove('text-swap');
    void element.offsetWidth;
    element.classList.add('text-swap');
  });
}

function refreshIcons() {
  if (window.lucide?.createIcons && window.lucide.icons) {
    window.lucide.createIcons({ icons: window.lucide.icons });
  }
}

function setModal(html) {
  $('#modal-root').innerHTML = html;
  refreshIcons();
}

function animateNumber(element, value) {
  if (!element) return;
  const next = Number(value) || 0;
  const previous = Number(element.dataset.value ?? element.textContent) || 0;
  element.dataset.value = String(next);
  if (previous === next || window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) {
    element.textContent = String(next);
    return;
  }
  if (element._countAnimationFrame) cancelAnimationFrame(element._countAnimationFrame);
  const startedAt = performance.now();
  const duration = 280;
  const tick = (now) => {
    const progress = Math.min(1, (now - startedAt) / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    element.textContent = String(Math.round(previous + (next - previous) * eased));
    if (progress < 1) element._countAnimationFrame = requestAnimationFrame(tick);
  };
  element._countAnimationFrame = requestAnimationFrame(tick);
}

function animateCollection(container, selector) {
  if (!container) return;
  container.querySelectorAll(selector).forEach((item, index) => {
    item.style.setProperty('--stagger', `${Math.min(index, 8) * 36}ms`);
    item.classList.add('stagger-in');
  });
}

function closeModal() {
  closeTerminalSession();
  const root = $('#modal-root');
  const backdrop = root.querySelector('.modal-backdrop');
  if (!backdrop) {
    root.innerHTML = '';
    return;
  }
  backdrop.classList.add('closing');
  backdrop.querySelector('.modal')?.classList.add('closing');
  window.setTimeout(() => {
    if (root.contains(backdrop)) root.innerHTML = '';
  }, 160);
}

function closeTerminalSession() {
  if (!terminalSession) return;
  try { terminalSession.ws?.close(); } catch { /* ignore */ }
  try { terminalSession.term?.dispose(); } catch { /* ignore */ }
  terminalSession = null;
}

function emptyState(text, options = {}) {
  const icon = options.icon || 'inbox';
  const action = options.action || '';
  const actionLabel = options.actionLabel || '';
  return `
    <div class="empty-state">
      <i data-lucide="${icon}"></i>
      <p>${escapeHtml(text)}</p>
      ${action ? `<button type="button" class="btn primary sm" data-empty-action="${escapeHtml(action)}">${escapeHtml(actionLabel)}</button>` : ''}
    </div>
  `;
}

function badge(text, tone = '', title = '') {
  const attrs = title ? ` title="${escapeHtml(title)}"` : '';
  return `<span class="badge ${tone}"${attrs}>${escapeHtml(text)}</span>`;
}

function protocolLabel(protocol) {
  return {
    vmess: 'VMess',
    vless: 'VLESS',
    trojan: 'Trojan',
    shadowsocks: 'Shadowsocks',
    socks: 'SOCKS5'
  }[protocol] || protocol;
}

const STATUS_META = {
  running: { label: '在线运行', tone: 'green' },
  service_stopped: { label: '服务停止', tone: 'amber' },
  offline: { label: '离线', tone: 'red' },
  config_mismatch: { label: '配置不一致', tone: 'amber' },
  config_missing: { label: '配置缺失', tone: 'red' },
  binary_missing: { label: '二进制缺失', tone: 'red' },
  ports_down: { label: '端口未监听', tone: 'amber' },
  unknown: { label: '未知', tone: 'muted' }
};

function statusMeta(state) {
  return STATUS_META[state] || STATUS_META.unknown;
}

function statusDot(state, titleExtra = '') {
  const meta = statusMeta(state);
  const title = `${meta.label}${titleExtra ? ` · ${titleExtra}` : ''}`;
  return `<span class="status-dot ${meta.tone}" title="${escapeHtml(title)}" aria-label="${escapeHtml(meta.label)}"></span>`;
}

function statusPill(state, titleExtra = '') {
  const meta = statusMeta(state);
  const title = `${meta.label}${titleExtra ? ` · ${titleExtra}` : ''}`;
  return `<span class="status-pill ${meta.tone}" title="${escapeHtml(title)}"><span class="status-dot ${meta.tone}"></span>${escapeHtml(meta.label)}</span>`;
}

function nodeLiveState(serverItem, node) {
  const state = serverItem?.state || 'unknown';
  if (['offline', 'binary_missing', 'config_missing', 'config_mismatch', 'service_stopped', 'ports_down'].includes(state)) return state;
  if (state !== 'running') return 'unknown';
  const nodeStatus = serverItem?.nodes?.find((item) => item.id === node.id);
  if (!nodeStatus) return 'unknown';
  if (!nodeStatus.in_config) return 'config_missing';
  if (!nodeStatus.listening) return 'ports_down';
  return 'running';
}

const REPAIR_SUMMARIES = {
  service_stopped: '仅启动/重启 Xray 服务，不写入或覆盖 config.json',
  config_missing: '重新生成 config.json 并写入服务器，然后重启 Xray',
  config_mismatch: '用面板期望配置覆盖 config.json，然后重启 Xray',
  binary_missing: '重新下载并安装 Xray 二进制，写入配置后重启'
};

const REPAIR_ACTION_LABELS = {
  service_stopped: '恢复服务',
  config_missing: '恢复配置',
  config_mismatch: '恢复配置',
  binary_missing: '重新部署'
};

function repairActionLabel(driftType) {
  return REPAIR_ACTION_LABELS[driftType] || '一键修复';
}

function cachedStatusTitle(live) {
  const time = formatTime(live?.status?.last_checked_at);
  return `缓存 · ${time}`;
}

function isAutoRepairEnabled() {
  return localStorage.getItem('auto_repair_enabled') === '1';
}

function setAutoRepairEnabled(value) {
  localStorage.setItem('auto_repair_enabled', value ? '1' : '0');
}

const STATUS_HISTORY_KEY = 'vps_status_history';
const STATUS_HISTORY_WINDOW_MS = 24 * 60 * 60 * 1000;

function readStatusHistory() {
  try { return JSON.parse(localStorage.getItem(STATUS_HISTORY_KEY) || '{}'); } catch { return {}; }
}

function pruneStatusHistory(entries, now) {
  return (Array.isArray(entries) ? entries : [])
    .filter((entry) => entry?.state && now - new Date(entry.at).getTime() <= STATUS_HISTORY_WINDOW_MS)
    .slice(-48);
}

function recordStatusHistory(serverId, state, at = new Date().toISOString()) {
  if (!serverId || !state) return;
  const history = readStatusHistory();
  const now = Date.parse(at) || Date.now();
  const entries = pruneStatusHistory(history[serverId] || [], now);
  const last = entries[entries.length - 1];
  if (!last || last.state !== state) {
    entries.push({ state, at: new Date(now).toISOString() });
    history[serverId] = pruneStatusHistory(entries, now);
    try { localStorage.setItem(STATUS_HISTORY_KEY, JSON.stringify(history)); } catch { /* keep memory only */ }
  }
}

function statusHistoryFor(serverId) {
  return pruneStatusHistory(readStatusHistory()[serverId] || [], Date.now());
}

function lastNormalTime(serverId) {
  const entries = statusHistoryFor(serverId);
  for (let index = entries.length - 1; index >= 0; index -= 1) {
    if (entries[index].state === 'running') return entries[index].at;
  }
  return '';
}

const THEME_ICONS = { light: 'sun', dark: 'moon', system: 'monitor' };
const THEME_LABELS = { light: '亮色', dark: '暗色', system: '跟随系统' };

function currentThemeMode() {
  return localStorage.getItem('theme_preference') || 'system';
}

function systemPrefersDark() {
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches === true;
}

function setTheme() {
  const mode = currentThemeMode();
  const dark = mode === 'dark' || (mode === 'system' && systemPrefersDark());
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  const button = $('#theme-toggle');
  if (button) {
    button.innerHTML = `<i data-lucide="${THEME_ICONS[mode]}"></i>`;
    button.title = `主题：${THEME_LABELS[mode]}，点击切换`;
  }
  refreshIcons();
}

async function loadAll() {
  try {
    const [servers, nodes, stats, routes, subscriptions] = await Promise.all([
      api('/api/servers'),
      api('/api/nodes'),
      api('/api/stats'),
      api('/api/routes'),
      api('/api/subscriptions')
    ]);
    state.servers = servers;
    state.nodes = nodes;
    state.stats = stats;
    state.routes = routes;
    state.subscriptions = subscriptions;
    if (!state.selectedServerId && servers.length) {
      state.selectedServerId = servers[0].id;
    }
    if (state.selectedServerId && !servers.some((server) => server.id === state.selectedServerId)) {
      state.selectedServerId = servers[0]?.id || null;
    }
    renderAll({ motion: true });
    loadStatus();
  } catch (error) {
    toast(error.message, 'error');
  }
}

async function loadStatus() {
  try {
    const payload = await api('/api/status');
    const hadStatuses = Object.keys(state.statuses).length > 0;
    state.statuses = Object.fromEntries(payload.servers.map((item) => [item.server.id, item]));
    for (const item of payload.servers) {
      recordStatusHistory(item.server.id, item.state, item.status?.last_checked_at || item.status?.updated_at || payload.generated_at);
    }
    if (isAutoRepairEnabled()) {
      for (const item of payload.servers) {
        if (item.state === 'service_stopped' && item.server && !state.autoRepairNotified.has(item.server.id)) {
          state.autoRepairNotified.add(item.server.id);
          toast(`检测到「${item.server.name}」服务停止，等待确认修复`, 'info');
          openRepairConfirmModal(item.server, item.drift, item.drift_reason);
          break;
        }
      }
    }
    const motion = !hadStatuses;
    renderOverview({ motion });
    renderServers({ motion });
    renderNodes({ motion });
    refreshIcons();
  } catch { /* keep last known status on transient errors */ }
}

function renderAll({ motion = true } = {}) {
  renderOverview({ motion });
  renderServers({ motion });
  renderNodes({ motion });
  renderRoutes({ motion });
  refreshIcons();
}

function renderOverview({ motion = true } = {}) {
  animateNumber($('#metric-servers'), state.stats.servers || 0);
  animateNumber($('#metric-nodes'), state.stats.nodes || 0);
  animateNumber($('#metric-enabled'), state.stats.enabledNodes || 0);

  const recent = state.nodes.slice(0, 6);
  const overview = $('#overview-nodes');
  overview.innerHTML = recent.length
    ? recent.map((node) => {
        const server = state.servers.find((item) => item.id === node.server_id);
        const live = server ? state.statuses[server.id] : null;
        return `
          <div class="overview-row" data-node-id="${escapeHtml(node.id)}">
            <span class="name">${statusDot(live?.state || 'unknown', cachedStatusTitle(live))}${escapeHtml(node.name)}</span>
            <span class="muted">${escapeHtml(server ? `${server.name} · ${server.host}` : '未知服务器')}</span>
            <span class="muted">${escapeHtml(protocolLabel(node.protocol))} / ${escapeHtml(node.port)}</span>
            ${node.enabled === 1 ? badge('启用', 'green') : badge('停用')}
          </div>
        `;
      }).join('')
    : emptyState('还没有节点，先添加服务器和节点', { icon: 'network', action: 'go-servers', actionLabel: '添加服务器' });
  if (motion) animateCollection(overview, '.overview-row, .empty-state');
  renderSubscriptions({ motion });
}

function renderServers({ motion = true } = {}) {
  const grid = $('#server-grid');
  if (!state.servers.length) {
    grid.innerHTML = emptyState('还没有服务器，点击“添加服务器”', { icon: 'server', action: 'add-server', actionLabel: '添加服务器' });
    if (motion) animateCollection(grid, '.empty-state');
    return;
  }
  grid.innerHTML = state.servers.map((server) => {
    const probe = state.probes[server.id];
    const nodeCount = state.nodes.filter((node) => node.server_id === server.id).length;
    const live = state.statuses[server.id];
    const statusBadge = live ? statusPill(live.state, cachedStatusTitle(live)) : statusPill('unknown');
    const drift = live?.drift || null;
    const lastNormal = drift ? lastNormalTime(server.id) : '';
    const authLabel = server.auth_type === 'key' ? 'SSH Key' : '密码';
    return `
      <div class="server-card">
        <div class="server-card-head">
          <h3 title="${escapeHtml(server.name)}">${escapeHtml(server.name)}</h3>
          <div class="card-head-badges">
            ${badge('SSH')}
            ${statusBadge}
          </div>
        </div>
        <div class="server-body">
          <div class="kv-grid">
            <div class="kv">
              <span class="kv-label">地址</span>
              <span class="kv-value" title="${escapeHtml(server.host)}">${escapeHtml(server.host)}:${escapeHtml(server.port)}</span>
            </div>
            <div class="kv">
              <span class="kv-label">用户</span>
              <span class="kv-value">${escapeHtml(server.username)}</span>
            </div>
            <div class="kv">
              <span class="kv-label">认证</span>
              <span class="kv-value">${escapeHtml(authLabel)}</span>
            </div>
            <div class="kv">
              <span class="kv-label">节点</span>
              <span class="kv-value">${nodeCount} 个</span>
            </div>
          </div>
          ${server.notes ? `<div class="hint">${escapeHtml(server.notes)}</div>` : ''}
          ${live?.status?.last_checked_at ? `<div class="status-checked"><span>最近检查</span><span>${escapeHtml(formatTime(live.status.last_checked_at))}</span><span class="hint">缓存</span></div>` : ''}
          ${drift ? `<div class="drift-banner"><span class="badge red">已漂移</span><span>${escapeHtml(live.drift_reason || '')}</span>${lastNormal ? `<span class="hint">上次正常 ${escapeHtml(formatTime(lastNormal))}</span>` : ''}</div>` : ''}
        </div>
        <div class="card-actions">
          ${drift ? `<button class="btn sm danger" data-action="repair" data-id="${escapeHtml(server.id)}" data-drift="${escapeHtml(drift)}" title="${escapeHtml(repairActionLabel(drift))}"><i data-lucide="wrench"></i>${escapeHtml(repairActionLabel(drift))}</button>` : ''}
          <button class="btn sm" data-action="status" data-id="${escapeHtml(server.id)}" title="实时检查 SSH、Xray 与配置状态"><i data-lucide="activity"></i>状态</button>
          <button class="btn sm" data-action="terminal" data-id="${escapeHtml(server.id)}" title="打开 SSH 终端 (T)"><i data-lucide="terminal"></i>终端</button>
          <button class="btn sm" data-action="logs" data-id="${escapeHtml(server.id)}" title="查看 Xray 日志"><i data-lucide="scroll-text"></i>日志</button>
          <button class="btn sm ghost" data-action="edit" data-id="${escapeHtml(server.id)}" title="编辑服务器配置"><i data-lucide="pencil"></i>编辑</button>
          <button class="icon-btn" data-action="delete" data-id="${escapeHtml(server.id)}" title="删除" aria-label="删除"><i data-lucide="trash-2"></i></button>
        </div>
      </div>
    `;
  }).join('');
  if (motion) animateCollection(grid, '.server-card');
}

function renderNodes({ motion = true } = {}) {
  const grid = $('#node-grid');
  $('#add-node-btn').disabled = !state.servers.length;

  if (!state.servers.length) {
    grid.innerHTML = emptyState('请先添加服务器，再创建节点', { icon: 'server', action: 'go-servers', actionLabel: '添加服务器' });
    if (motion) animateCollection(grid, '.empty-state');
    return;
  }

  if (!state.nodes.length) {
    grid.innerHTML = emptyState('还没有节点，点击“添加节点”', { icon: 'network', action: 'add-node', actionLabel: '添加节点' });
    if (motion) animateCollection(grid, '.empty-state');
    return;
  }

  const renderNodeCard = (node) => {
    const security = node.security === 'reality' ? 'Reality' : node.security === 'tls' ? 'TLS' : '无加密';
    const clientCount = node.clients?.length || 0;
    const live = state.statuses[node.server_id];
    const drift = live?.drift || null;
    const lastNormal = drift ? lastNormalTime(node.server_id) : '';
    const server = state.servers.find((item) => item.id === node.server_id);
    const serverLabel = server ? `${server.name} · ${server.host}` : '未知服务器';
    const protocolRows = node.protocol === 'socks' ? '' : `
            <div class="kv">
              <span class="kv-label">传输</span>
              <span class="kv-value">${escapeHtml(node.network.toUpperCase())}</span>
            </div>
            <div class="kv">
              <span class="kv-label">安全</span>
              <span class="kv-value">${escapeHtml(security)}</span>
            </div>
            <div class="kv">
              <span class="kv-label">SNI</span>
              <span class="kv-value">${escapeHtml(node.sni || '—')}</span>
            </div>
    `;
    return `
      <div class="node-card">
        <div class="node-card-head">
          <h3 title="${escapeHtml(node.name)}">${escapeHtml(node.name)}</h3>
          <div class="card-head-badges">
            ${statusPill(nodeLiveState(state.statuses[node.server_id], node), cachedStatusTitle(live))}
            ${node.role === 'outbound' ? badge('出站', 'amber') : badge('入站')}
            ${node.enabled === 1 ? badge('启用', 'green') : badge('停用')}
          </div>
        </div>
        <div class="node-body">
          <div class="node-server-label" title="${escapeHtml(serverLabel)}"><i data-lucide="server"></i><span>${escapeHtml(serverLabel)}</span></div>
          <div class="kv-grid">
            <div class="kv">
              <span class="kv-label">协议</span>
              <span class="kv-value">${escapeHtml(protocolLabel(node.protocol))}</span>
            </div>
            <div class="kv">
              <span class="kv-label">端口</span>
              <span class="kv-value">${escapeHtml(node.port)}</span>
            </div>
            <div class="kv">
              <span class="kv-label">客户端</span>
              <span class="kv-value">${clientCount} 个</span>
            </div>
            ${protocolRows}
          </div>
          ${live?.status?.last_checked_at ? `<div class="status-checked"><span>最近检查</span><span>${escapeHtml(formatTime(live.status.last_checked_at))}</span><span class="hint">缓存</span></div>` : ''}
          ${drift ? `<div class="drift-banner"><span class="badge red">已漂移</span><span>${escapeHtml(live.drift_reason || '')}</span>${lastNormal ? `<span class="hint">上次正常 ${escapeHtml(formatTime(lastNormal))}</span>` : ''}</div>` : ''}
        </div>
        <div class="card-actions">
          ${drift ? `<button class="btn sm danger" data-action="repair" data-id="${escapeHtml(node.id)}" data-drift="${escapeHtml(drift)}" title="${escapeHtml(repairActionLabel(drift))}"><i data-lucide="wrench"></i>${escapeHtml(repairActionLabel(drift))}</button>` : ''}
          <button class="btn sm" data-action="status" data-id="${escapeHtml(node.id)}" title="实时检查该服务器状态"><i data-lucide="activity"></i>状态</button>
          <button class="btn sm" data-action="share" data-id="${escapeHtml(node.id)}" title="查看分享链接"><i data-lucide="share-2"></i>分享</button>
          <button class="btn sm" data-action="edit" data-id="${escapeHtml(node.id)}" title="编辑节点配置"><i data-lucide="pencil"></i>编辑</button>
          <button class="btn sm danger" data-action="delete" data-id="${escapeHtml(node.id)}" title="删除面板中的节点配置"><i data-lucide="trash-2"></i>删除</button>
        </div>
      </div>
    `;
  };

  const renderRoleSection = (role, title, description, tone) => {
    const roleNodes = state.nodes.filter((node) => node.role === role);
    if (!roleNodes.length) {
      return `
        <section class="node-role-section node-role-empty-section">
          <div class="node-role-head">
            <div class="node-role-title"><span class="role-mark ${role}"></span><div><h2>${title}</h2><span class="hint">${description}</span></div></div>
            ${badge('0 个节点', tone)}
          </div>
          <div class="node-role-empty">暂无${title}节点</div>
        </section>
      `;
    }

    const serverIds = [...new Set(roleNodes.map((node) => node.server_id))];
    const serverGroups = serverIds.map((serverId) => {
      const server = state.servers.find((item) => item.id === serverId);
      const serverNodes = roleNodes.filter((node) => node.server_id === serverId);
      return {
        server,
        serverNodes,
        serverLabel: server ? `${server.name} · ${server.host}` : '未知服务器'
      };
    });
    const groupedRoleNodes = serverGroups.flatMap((group) => group.serverNodes);
    return `
      <section class="node-role-section">
        <div class="node-role-head">
          <div class="node-role-title"><span class="role-mark ${role}"></span><div><h2>${title}</h2><span class="hint">${description}</span></div></div>
          ${badge(`${roleNodes.length} 个节点`, tone)}
        </div>
        <div class="node-server-groups">
          <div class="node-server-toolbar">
            ${serverGroups.map(({ server, serverNodes, serverLabel }) => `
              <div class="node-server-group-head">
                <div class="node-server-heading">
                  <strong>${escapeHtml(serverLabel)}</strong>
                  <span class="hint">${serverNodes.length} 个${title}节点</span>
                </div>
                ${server ? `<button class="btn sm accent" data-deploy-server="${escapeHtml(server.id)}" title="写入该服务器的全部节点配置并重启 Xray"><i data-lucide="upload-cloud"></i>部署</button>` : ''}
              </div>
            `).join('')}
          </div>
          <div class="node-grid node-group-grid">${groupedRoleNodes.map(renderNodeCard).join('')}</div>
        </div>
      </section>
    `;
  };

  grid.innerHTML = [
    renderRoleSection('inbound', '入站', '客户端连接到这些节点', ''),
    renderRoleSection('outbound', '出站', '这些节点作为转发出口', 'amber')
  ].join('');
  if (motion) animateCollection(grid, '.node-card, .node-role-section');
}

const SUBSCRIPTION_FORMAT_LABELS = { base64: 'Base64', uri: '原始 URI' };

function subscriptionFormatLabel(format) {
  return SUBSCRIPTION_FORMAT_LABELS[format] || 'Base64';
}

function subscriptionAddress(token, format = 'base64') {
  if (!token) return '';
  return `${location.origin}/sub/${encodeURIComponent(token)}${format === 'uri' ? '?format=uri' : ''}`;
}

function subscriptionExpiryLabel(value) {
  if (!value) return '永不过期';
  const expired = Date.parse(value) <= Date.now();
  return `${expired ? '已过期 · ' : ''}${formatTime(value)}`;
}

function renderSubscriptions({ motion = true } = {}) {
  const grid = $('#subscription-grid');
  if (!grid) return;
  if (!state.subscriptions.length) {
    grid.innerHTML = emptyState('还没有订阅，创建后会自动包含所有启用的入口节点', {
      icon: 'rss',
      action: 'add-subscription',
      actionLabel: '创建订阅'
    });
    if (motion) animateCollection(grid, '.empty-state');
    return;
  }
  grid.innerHTML = state.subscriptions.map((subscription) => {
    const token = state.subscriptionTokens[subscription.id] || '';
    const address = subscriptionAddress(token);
    const enabled = Boolean(subscription.enabled);
    return `
      <article class="subscription-card">
        <div class="subscription-card-head">
          <div>
            <h3 title="${escapeHtml(subscription.name)}">${escapeHtml(subscription.name)}</h3>
            <span class="hint">自动同步入口节点</span>
          </div>
          <div class="card-head-badges">
            ${badge(subscriptionFormatLabel(subscription.default_format), 'indigo')}
            ${enabled ? badge('已启用', 'green') : badge('已禁用')}
          </div>
        </div>
        <div class="subscription-body">
          <div class="kv-grid">
            <div class="kv">
              <span class="kv-label">当前节点</span>
              <span class="kv-value">${escapeHtml(subscription.node_count ?? 0)} 个入口</span>
            </div>
            <div class="kv">
              <span class="kv-label">默认格式</span>
              <span class="kv-value">${escapeHtml(subscriptionFormatLabel(subscription.default_format))}</span>
            </div>
            <div class="kv">
              <span class="kv-label">过期时间</span>
              <span class="kv-value">${escapeHtml(subscriptionExpiryLabel(subscription.expires_at))}</span>
            </div>
            <div class="kv">
              <span class="kv-label">访问次数</span>
              <span class="kv-value">${escapeHtml(subscription.access_count || 0)}</span>
            </div>
          </div>
          <div class="subscription-meta-row">
            <span>最近访问 ${escapeHtml(formatTime(subscription.last_access_at))}</span>
            <span>创建于 ${escapeHtml(formatTime(subscription.created_at))}</span>
          </div>
          <div class="subscription-address-preview ${address ? '' : 'missing'}">
            <i data-lucide="link"></i>
            <span>${address ? escapeHtml(address) : '完整地址仅在创建或重新生成 Token 后显示'}</span>
          </div>
        </div>
        <div class="card-actions subscription-actions">
          <button class="btn sm" data-sub-action="details" data-id="${escapeHtml(subscription.id)}" title="查看订阅详情"><i data-lucide="eye"></i>详情</button>
          <button class="btn sm" data-sub-action="edit" data-id="${escapeHtml(subscription.id)}" title="编辑订阅设置"><i data-lucide="pencil"></i>编辑</button>
          <button class="btn sm" data-sub-action="copy" data-id="${escapeHtml(subscription.id)}" title="复制 Base64 订阅地址" ${address ? '' : 'disabled'}><i data-lucide="copy"></i>复制地址</button>
          <button class="btn sm" data-sub-action="toggle" data-id="${escapeHtml(subscription.id)}" title="${enabled ? '禁用订阅' : '启用订阅'}"><i data-lucide="${enabled ? 'pause' : 'play'}"></i>${enabled ? '禁用' : '启用'}</button>
          <button class="btn sm danger" data-sub-action="rotate" data-id="${escapeHtml(subscription.id)}" title="重新生成 Token，旧地址立即失效"><i data-lucide="key-round"></i>重生成</button>
          <button class="icon-btn" data-sub-action="delete" data-id="${escapeHtml(subscription.id)}" title="删除订阅，地址立即失效" aria-label="删除订阅"><i data-lucide="trash-2"></i></button>
        </div>
      </article>
    `;
  }).join('');
  if (motion) animateCollection(grid, '.subscription-card');
}

function formatDateTimeLocal(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  const pad = (number) => String(number).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function openSubscriptionForm(subscription = null) {
  const isEdit = Boolean(subscription);
  setModal(`
    <div class="modal-backdrop">
      <div class="modal subscription-form-modal">
        <div class="modal-head">
          <h2>${isEdit ? '编辑订阅' : '创建订阅'}</h2>
          <button class="icon-btn" data-close title="关闭" aria-label="关闭"><i data-lucide="x"></i></button>
        </div>
        <form id="subscription-form" class="modal-body">
          <div class="form-section">
            <div class="form-section-title">订阅设置</div>
            <div class="form-grid">
              <div class="field full">
                <label for="subscription-name">订阅名称</label>
                <input id="subscription-name" name="name" required maxlength="80" value="${escapeHtml(subscription?.name || '')}" placeholder="例如：我的入口订阅">
              </div>
              <div class="field">
                <label for="subscription-format">默认格式</label>
                <select id="subscription-format" name="default_format">
                  <option value="base64" ${subscription?.default_format !== 'uri' ? 'selected' : ''}>Base64</option>
                  <option value="uri" ${subscription?.default_format === 'uri' ? 'selected' : ''}>原始 URI</option>
                </select>
              </div>
              <div class="field">
                <label for="subscription-expires">过期时间</label>
                <input id="subscription-expires" name="expires_at" type="datetime-local" value="${escapeHtml(formatDateTimeLocal(subscription?.expires_at))}">
                <span class="hint">留空表示永不过期</span>
              </div>
              <div class="field full">
                <label class="checkbox-field">
                  <input type="checkbox" name="enabled" ${subscription?.enabled !== false ? 'checked' : ''}>
                  <span>创建后立即启用订阅</span>
                </label>
              </div>
            </div>
          </div>
          <div class="subscription-form-note">
            <i data-lucide="info"></i>
            <span>订阅将自动包含所有已启用的入口节点，不需要手动选择节点。</span>
          </div>
        </form>
        <div class="modal-foot">
          <button class="btn ghost" data-close>取消</button>
          <button class="btn primary" id="save-subscription-btn" title="保存订阅设置"><i data-lucide="save"></i>${isEdit ? '保存' : '创建并生成地址'}</button>
        </div>
      </div>
    </div>
  `);
  $$('#modal-root [data-close]').forEach((button) => button.addEventListener('click', closeModal));
  $('#save-subscription-btn').addEventListener('click', async (event) => {
    event.preventDefault();
    const form = $('#subscription-form');
    if (!form.reportValidity()) return;
    const data = Object.fromEntries(new FormData(form).entries());
    data.enabled = form.querySelector('[name="enabled"]').checked;
    await withBusy(event.currentTarget, isEdit ? '保存中...' : '创建中...', async () => {
      try {
        const result = await api(isEdit ? `/api/subscriptions/${subscription.id}` : '/api/subscriptions', {
          method: isEdit ? 'PUT' : 'POST',
          body: JSON.stringify(data)
        });
        if (result.token && result.subscription?.id) state.subscriptionTokens[result.subscription.id] = result.token;
        toast(isEdit ? '订阅设置已保存' : '订阅已创建，地址已生成', 'success');
        closeModal();
        await loadAll();
        if (!isEdit && result.subscription?.id) openSubscriptionDetails(result.subscription.id);
      } catch (error) {
        toast(error.message, 'error');
      }
    });
  });
}

function subscriptionAddressRow(subscriptionId, format, label) {
  const token = state.subscriptionTokens[subscriptionId] || '';
  const address = subscriptionAddress(token, format);
  return `
    <div class="subscription-address-row">
      <div class="subscription-address-label">${escapeHtml(label)}</div>
      <input readonly value="${escapeHtml(address || '创建或重新生成 Token 后显示')}" aria-label="${escapeHtml(label)}">
      <button class="btn sm ghost" data-sub-copy="${escapeHtml(subscriptionId)}" data-format="${format}" title="复制${escapeHtml(label)}" ${address ? '' : 'disabled'}><i data-lucide="copy"></i>复制</button>
      <button class="icon-btn" data-sub-qr="${escapeHtml(subscriptionId)}" data-format="${format}" title="显示${escapeHtml(label)}二维码" aria-label="显示${escapeHtml(label)}二维码" ${address ? '' : 'disabled'}><i data-lucide="qr-code"></i></button>
    </div>
  `;
}

function renderSubscriptionDetails(preview) {
  const subscription = preview.subscription;
  const token = state.subscriptionTokens[subscription.id] || '';
  const status = subscription.enabled ? badge('已启用', 'green') : badge('已禁用');
  const nodeRows = preview.nodes.length
    ? preview.nodes.map((node) => `
        <div class="subscription-node-row">
          <div class="subscription-node-main">
            <strong>${escapeHtml(node.name)}</strong>
            <span class="hint">${escapeHtml(node.server_name || node.server_host)} · ${escapeHtml(node.network.toUpperCase())}</span>
          </div>
          <span>${escapeHtml(protocolLabel(node.protocol))}</span>
          <span>${escapeHtml(node.server_host)}:${escapeHtml(node.port)}</span>
          <span>${escapeHtml(node.security || 'none')}</span>
          ${badge('已包含', 'green')}
        </div>
      `).join('')
    : emptyState('当前没有可生成分享链接的入口节点', { icon: 'network' });
  const excludedRows = preview.excluded.length
    ? `
      <details class="subscription-excluded">
        <summary>查看被排除节点（${preview.excluded.length}）</summary>
        <div class="subscription-excluded-list">
          ${preview.excluded.map((node) => `<div><span>${escapeHtml(node.name)}</span><span>${escapeHtml(node.reason)}</span></div>`).join('')}
        </div>
      </details>
    `
    : '';
  setModal(`
    <div class="modal-backdrop">
      <div class="modal wide subscription-detail-modal">
        <div class="modal-head">
          <div>
            <h2>${escapeHtml(subscription.name)}</h2>
            <span class="hint">订阅详情 · ${escapeHtml(subscription.node_count)} 个入口节点</span>
          </div>
          <button class="icon-btn" data-close title="关闭" aria-label="关闭"><i data-lucide="x"></i></button>
        </div>
        <div class="modal-body">
          <div class="status-summary subscription-summary">
            <div class="status-summary-item"><span class="status-summary-label">状态</span><span class="status-summary-value">${status}</span></div>
            <div class="status-summary-item"><span class="status-summary-label">当前入口节点</span><span class="status-summary-value">${escapeHtml(preview.node_count)} 个</span></div>
            <div class="status-summary-item"><span class="status-summary-label">过期时间</span><span class="status-summary-value">${escapeHtml(subscriptionExpiryLabel(subscription.expires_at))}</span></div>
            <div class="status-summary-item"><span class="status-summary-label">最近访问</span><span class="status-summary-value">${escapeHtml(formatTime(subscription.last_access_at))}</span></div>
          </div>
          <div class="subscription-addresses">
            <div class="status-section-head"><span>订阅地址</span><span>${token ? '当前页面临时保留 Token' : '明文 Token 不会从数据库恢复'}</span></div>
            ${subscriptionAddressRow(subscription.id, 'base64', '通用 Base64 地址')}
            ${subscriptionAddressRow(subscription.id, 'uri', '原始 URI 地址')}
          </div>
          <div class="status-section-head"><span>节点预览</span><span>${escapeHtml(preview.link_count)} 条分享链接</span></div>
          <div class="subscription-node-list">${nodeRows}</div>
          ${excludedRows}
        </div>
        <div class="modal-foot">
          <button class="btn ghost" data-close>关闭</button>
          <button class="btn ghost" data-sub-detail-edit="${escapeHtml(subscription.id)}" title="编辑订阅设置"><i data-lucide="pencil"></i>编辑</button>
          <button class="btn danger" data-sub-detail-rotate="${escapeHtml(subscription.id)}" title="重新生成 Token，旧地址立即失效"><i data-lucide="key-round"></i>重新生成 Token</button>
        </div>
      </div>
    </div>
  `);
  $$('#modal-root [data-close]').forEach((button) => button.addEventListener('click', closeModal));
  $$('#modal-root [data-sub-copy]').forEach((button) => button.addEventListener('click', () => copySubscriptionAddress(button.dataset.subCopy, button.dataset.format, button)));
  $$('#modal-root [data-sub-qr]').forEach((button) => button.addEventListener('click', () => openSubscriptionQr(button.dataset.subQr, button.dataset.format)));
  $('#modal-root [data-sub-detail-edit]')?.addEventListener('click', () => {
    const item = state.subscriptions.find((entry) => entry.id === subscription.id);
    if (item) openSubscriptionForm(item);
  });
  $('#modal-root [data-sub-detail-rotate]')?.addEventListener('click', () => confirmRotateSubscription(subscription.id));
}

async function openSubscriptionDetails(subscriptionId) {
  setModal(`
    <div class="modal-backdrop">
      <div class="modal subscription-detail-modal">
        <div class="modal-head"><h2>订阅详情</h2></div>
        <div class="modal-body"><div class="status-loading">正在加载订阅详情...</div></div>
      </div>
    </div>
  `);
  try {
    renderSubscriptionDetails(await api(`/api/subscriptions/${subscriptionId}/preview`));
  } catch (error) {
    closeModal();
    toast(error.message, 'error');
  }
}

async function copyText(value) {
  if (!value) return false;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch {
    // HTTP origins may reject the Clipboard API; use the legacy command below.
  }
  const textarea = document.createElement('textarea');
  textarea.value = value;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.top = '0';
  textarea.style.left = '-9999px';
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  textarea.setSelectionRange(0, textarea.value.length);
  let copied = false;
  try {
    copied = document.execCommand('copy');
  } catch {
    copied = false;
  }
  textarea.remove();
  return copied;
}

function selectSubscriptionAddress(button) {
  const input = button?.closest('.subscription-address-row')?.querySelector('input');
  if (!input) return;
  input.focus();
  input.select();
  input.setSelectionRange(0, input.value.length);
}

async function copySubscriptionAddress(subscriptionId, format = 'base64', button = null) {
  const address = subscriptionAddress(state.subscriptionTokens[subscriptionId], format);
  if (!address) {
    toast('当前页面没有可复制的明文 Token，请先重新生成 Token', 'info');
    return;
  }
  if (await copyText(address)) {
    toast('订阅地址已复制', 'success');
  } else {
    selectSubscriptionAddress(button);
    toast('自动复制失败，地址已选中，请按 Ctrl+C 复制', 'info');
  }
}

async function openSubscriptionQr(subscriptionId, format = 'base64') {
  const token = state.subscriptionTokens[subscriptionId];
  if (!token) {
    toast('当前页面没有可生成二维码的明文 Token，请先重新生成 Token', 'info');
    return;
  }
  const address = subscriptionAddress(token, format);
  const formatLabel = format === 'uri' ? '原始 URI 地址' : '通用 Base64 地址';
  setModal(`
    <div class="modal-backdrop">
      <div class="modal subscription-qr-modal">
        <div class="modal-head">
          <div>
            <h2>订阅二维码</h2>
            <span class="hint">${escapeHtml(formatLabel)}</span>
          </div>
          <button class="icon-btn" data-close title="关闭" aria-label="关闭"><i data-lucide="x"></i></button>
        </div>
        <div class="modal-body subscription-qr-body">
          <div class="subscription-qr-loading"><i data-lucide="loader-circle"></i><span>正在生成二维码...</span></div>
          <img class="subscription-qr-image" data-sub-qr-image alt="订阅二维码" hidden>
          <div class="subscription-qr-address" title="订阅地址">${escapeHtml(address)}</div>
          <p class="hint">请使用客户端扫码导入，二维码内容不会上传到第三方服务。</p>
        </div>
        <div class="modal-foot"><button class="btn ghost" data-close>关闭</button></div>
      </div>
    </div>
  `);
  $$('#modal-root [data-close]').forEach((button) => button.addEventListener('click', closeModal));
  try {
    const result = await api('/api/subscriptions/qr', {
      method: 'POST',
      body: JSON.stringify({ url: address })
    });
    const image = $('#modal-root [data-sub-qr-image]');
    const loading = $('#modal-root .subscription-qr-loading');
    if (!image || !loading) return;
    image.src = result.data_url;
    image.hidden = false;
    loading.hidden = true;
  } catch (error) {
    closeModal();
    toast(error.message || '二维码生成失败', 'error');
  }
}

async function runSubscriptionToggle(subscriptionId, button) {
  const subscription = state.subscriptions.find((item) => item.id === subscriptionId);
  if (!subscription) return;
  const action = subscription.enabled ? 'disable' : 'enable';
  await withBusy(button, subscription.enabled ? '禁用中...' : '启用中...', async () => {
    try {
      await api(`/api/subscriptions/${subscriptionId}/${action}`, { method: 'POST' });
      toast(subscription.enabled ? '订阅已禁用' : '订阅已启用', 'success');
      await loadAll();
    } catch (error) {
      toast(error.message, 'error');
    }
  });
}

function confirmRotateSubscription(subscriptionId) {
  const subscription = state.subscriptions.find((item) => item.id === subscriptionId);
  if (!subscription) return;
  openConfirmModal({
    title: '重新生成订阅 Token',
    message: [
      `将为「${subscription.name}」生成新的订阅地址。`,
      '旧订阅地址会立即失效，已经导入客户端的旧地址需要重新替换。'
    ],
    confirmText: '重新生成',
    onConfirm: () => runRotateSubscription(subscriptionId)
  });
}

async function runRotateSubscription(subscriptionId) {
  openProgressModal('重新生成 Token', '正在生成新的订阅地址...');
  try {
    const result = await api(`/api/subscriptions/${subscriptionId}/rotate`, { method: 'POST' });
    state.subscriptionTokens[subscriptionId] = result.token;
    closeProgressModal();
    toast('Token 已重新生成，旧地址已失效', 'success');
    await loadAll();
    openSubscriptionDetails(subscriptionId);
  } catch (error) {
    closeProgressModal();
    toast(error.message, 'error');
  }
}

function confirmDeleteSubscription(subscriptionId, button = null) {
  const subscription = state.subscriptions.find((item) => item.id === subscriptionId);
  if (!subscription) return;
  openConfirmModal({
    title: '删除订阅',
    message: [
      `将删除订阅「${subscription.name}」。`,
      '删除后订阅地址立即失效，节点本身不会被删除。'
    ],
    confirmText: '删除订阅',
    onConfirm: async () => {
      await withBusy(button, '删除中...', async () => {
        try {
          await api(`/api/subscriptions/${subscriptionId}`, { method: 'DELETE' });
          delete state.subscriptionTokens[subscriptionId];
          toast('订阅已删除', 'success');
          await loadAll();
        } catch (error) {
          toast(error.message, 'error');
        }
      });
    }
  });
}

function runSubscriptionAction(action, subscriptionId, button) {
  const subscription = state.subscriptions.find((item) => item.id === subscriptionId);
  if (!subscription) return;
  if (action === 'details') openSubscriptionDetails(subscriptionId);
  if (action === 'edit') openSubscriptionForm(subscription);
  if (action === 'copy') copySubscriptionAddress(subscriptionId);
  if (action === 'toggle') runSubscriptionToggle(subscriptionId, button);
  if (action === 'rotate') confirmRotateSubscription(subscriptionId);
  if (action === 'delete') confirmDeleteSubscription(subscriptionId, button);
}

function openServerModal(server = null) {
  const isEdit = Boolean(server);
  const authType = server?.auth_type || 'password';
  setModal(`
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-head">
          <h2>${isEdit ? '编辑服务器' : '添加服务器'}</h2>
          <button class="icon-btn" data-close title="关闭" aria-label="关闭"><i data-lucide="x"></i></button>
        </div>
        <form id="server-form" class="modal-body">
          <div class="form-section">
            <div class="form-section-title">连接信息</div>
            <div class="form-grid">
              <div class="field full">
                <label>快速粘贴服务器信息</label>
                <textarea id="server-paste" placeholder="支持：root@1.2.3.4:22 密码；1.2.3.4:22:root:密码；1.2.3.4 22 root 密码"></textarea>
                <div class="paste-actions">
                  <button type="button" class="btn ghost sm" id="parse-server-btn" title="解析粘贴内容并填充表单"><i data-lucide="wand-2"></i>识别并填充</button>
                  <button type="button" class="btn primary sm" id="quick-save-server-btn" title="解析粘贴内容并直接保存"><i data-lucide="zap"></i>识别并保存</button>
                </div>
              </div>
              <div class="field full">
                <label>名称</label>
                <input name="name" required value="${escapeHtml(server?.name || '')}" placeholder="例如 香港主节点">
              </div>
              <div class="field">
                <label>主机</label>
                <input name="host" required value="${escapeHtml(server?.host || '')}" placeholder="IP 或域名">
              </div>
              <div class="field">
                <label>SSH 端口</label>
                <input name="port" type="number" min="1" max="65535" required value="${escapeHtml(server?.port || 22)}">
              </div>
              <div class="field full">
                <label>用户名</label>
                <input name="username" required value="${escapeHtml(server?.username || '')}" placeholder="root 或普通用户">
              </div>
            </div>
          </div>

          <div class="form-section">
            <div class="form-section-title">认证方式</div>
            <div class="form-grid">
              <div class="field full">
                <label>认证方式</label>
                <div class="segmented">
                  <button type="button" data-auth="password" class="${authType === 'password' ? 'active' : ''}">密码</button>
                  <button type="button" data-auth="key" class="${authType === 'key' ? 'active' : ''}">SSH Key</button>
                </div>
              </div>
              <div class="field full auth-password" style="${authType === 'key' ? 'display:none' : ''}">
                <label>密码</label>
                <div class="field-row">
                  <input name="password" type="password" autocomplete="new-password" placeholder="${isEdit ? '留空则保持现有密码' : 'SSH 登录密码'}">
                  <button type="button" class="reveal-btn" data-reveal="input[name='password']">显示</button>
                </div>
                ${isEdit && server.has_password ? '<span class="hint">已保存密码，留空则保持不变。</span>' : ''}
              </div>
              <div class="field full auth-key" style="${authType === 'password' ? 'display:none' : ''}">
                <label>私钥</label>
                <div class="field-row">
                  <textarea name="private_key" class="masked" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
                  <button type="button" class="reveal-btn" data-reveal="textarea[name='private_key']">显示</button>
                </div>
                ${isEdit && server.has_private_key ? '<span class="hint">已保存密钥，留空则保持不变。</span>' : ''}
              </div>
              <div class="field auth-key" style="${authType === 'password' ? 'display:none' : ''}">
                <label>密钥口令</label>
                <input name="passphrase" type="password" autocomplete="new-password" placeholder="可选">
              </div>
              <div class="field">
                <label>sudo 密码</label>
                <div class="field-row">
                  <input name="sudo_password" type="password" autocomplete="new-password" placeholder="${server?.has_sudo_password ? '留空则保持不变' : '非 root 时填写'}">
                  <button type="button" class="reveal-btn" data-reveal="input[name='sudo_password']">显示</button>
                </div>
              </div>
            </div>
          </div>

          <div class="form-section">
            <div class="form-section-title">备注</div>
            <div class="form-grid">
              <div class="field full">
                <label>备注</label>
                <textarea name="notes" placeholder="机房、用途等">${escapeHtml(server?.notes || '')}</textarea>
              </div>
            </div>
          </div>
        </form>
        <div class="modal-foot">
          <button class="btn ghost" data-close>取消</button>
          <button class="btn primary" type="submit" form="server-form"><i data-lucide="save"></i>保存</button>
        </div>
      </div>
    </div>
  `);

  $$('#modal-root [data-close]').forEach((button) => button.addEventListener('click', closeModal));
  $$('#modal-root .segmented button').forEach((button) => {
    button.addEventListener('click', () => {
      const auth = button.dataset.auth;
      $$('#modal-root .segmented button').forEach((item) => item.classList.toggle('active', item === button));
      $('#modal-root .auth-password').style.display = auth === 'password' ? '' : 'none';
      $('#modal-root .auth-key').style.display = auth === 'key' ? '' : 'none';
    });
  });

  $$('#modal-root [data-reveal]').forEach((button) => {
    button.addEventListener('click', () => {
      const target = $(button.dataset.reveal);
      if (!target) return;
      if (target.tagName === 'TEXTAREA') {
        const revealed = target.classList.toggle('revealed');
        button.textContent = revealed ? '隐藏' : '显示';
      } else {
        const revealed = target.type === 'text';
        target.type = revealed ? 'password' : 'text';
        button.textContent = revealed ? '显示' : '隐藏';
      }
    });
  });

  function readServerPayload() {
    const form = $('#server-form');
    const data = Object.fromEntries(new FormData(form).entries());
    data.auth_type = $('#modal-root .segmented button.active').dataset.auth;
    data.port = Number(data.port);
    if (data.auth_type === 'password' && !data.password) delete data.password;
    if (data.auth_type === 'key' && !data.private_key) delete data.private_key;
    if (!data.passphrase) delete data.passphrase;
    if (!data.sudo_password) delete data.sudo_password;
    return data;
  }

  async function persistServer(data) {
    if (isEdit) return api(`/api/servers/${server.id}`, { method: 'PUT', body: JSON.stringify(data) });
    return api('/api/servers', { method: 'POST', body: JSON.stringify(data) });
  }

  function fillServerFromParsed(parsed, forceName = false) {
    const form = $('#server-form');
    if (forceName || !form.elements.name.value.trim()) form.elements.name.value = parsed.host;
    form.elements.host.value = parsed.host;
    form.elements.port.value = parsed.port;
    form.elements.username.value = parsed.username;
    if (parsed.password) {
      const passwordButton = $('#modal-root .segmented button[data-auth="password"]');
      if (passwordButton) passwordButton.click();
      form.elements.password.value = parsed.password;
    }
  }

  $('#parse-server-btn').addEventListener('click', () => {
    const parsed = parseServerInfo($('#server-paste').value);
    if (!parsed.host) {
      toast('未识别到 IP 或域名', 'error');
      return;
    }
    fillServerFromParsed(parsed);
    toast('已识别并填充，可确认后保存');
  });

  $('#quick-save-server-btn').addEventListener('click', async () => {
    const parsed = parseServerInfo($('#server-paste').value);
    if (!parsed.host) {
      toast('未识别到 IP 或域名', 'error');
      return;
    }
    fillServerFromParsed(parsed, true);
    withBusy($('#quick-save-server-btn'), '保存中...', async () => {
      await persistServer(readServerPayload());
      closeModal();
      await loadAll();
      toast(isEdit ? '服务器已更新' : '服务器已添加', 'success');
    }).catch((error) => toast(error.message, 'error'));
  });

  $('#server-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    withBusy($('button[type="submit"][form="server-form"]'), '保存中...', async () => {
      await persistServer(readServerPayload());
      closeModal();
      await loadAll();
      toast(isEdit ? '服务器已更新' : '服务器已添加', 'success');
    }).catch((error) => toast(error.message, 'error'));
  });
}

function openNodeModal(serverId, node = null) {
  const isEdit = Boolean(node);
  const initialServerId = node?.server_id || serverId || state.servers[0]?.id || '';
  const serverOptions = state.servers.length
    ? state.servers.map((server) => `
        <option value="${escapeHtml(server.id)}" ${server.id === initialServerId ? 'selected' : ''}>
          ${escapeHtml(server.name)} (${escapeHtml(server.host)})
        </option>
      `).join('')
    : '<option value="">暂无服务器</option>';
  const clients = node?.clients?.length
    ? node.clients.map((client) => ({ ...client, security: client.security || 'auto' }))
    : [{ email: '', secret: '', flow: '', security: 'auto' }];
  const security = node?.security || 'none';
  const network = node?.network || 'tcp';

  setModal(`
    <div class="modal-backdrop">
      <div class="modal wide">
        <div class="modal-head">
          <h2>${isEdit ? '编辑节点' : '添加节点'}</h2>
          <button class="icon-btn" data-close title="关闭" aria-label="关闭"><i data-lucide="x"></i></button>
        </div>
        <form id="node-form" class="modal-body">
          <div class="form-grid">
            <div class="field full">
              <label>名称</label>
              <input name="name" required value="${escapeHtml(node?.name || '')}" placeholder="例如 香港 443">
            </div>
            <div class="field full node-server-field">
              <label for="node-server-id">使用服务器</label>
              <select id="node-server-id" name="server_id" required ${isEdit ? 'disabled' : ''}>
                ${serverOptions}
              </select>
              <span class="hint">${isEdit ? '编辑节点时不能更换所属服务器。' : '节点将保存到这里选择的服务器。'}</span>
            </div>
            <div class="field">
              <label>节点类型</label>
              <div class="segmented" id="node-role-segmented">
                <button type="button" data-role="inbound" class="${(node?.role || 'inbound') === 'inbound' ? 'active' : ''}">入站</button>
                <button type="button" data-role="outbound" class="${(node?.role || 'inbound') === 'outbound' ? 'active' : ''}">出站</button>
              </div>
            </div>
            <div class="field">
              <label>协议</label>
              <select name="protocol">
                ${['vmess', 'vless', 'trojan', 'shadowsocks', 'socks'].map((protocol) => `
                  <option value="${protocol}" ${(node?.protocol || 'vless') === protocol ? 'selected' : ''}>${escapeHtml(protocolLabel(protocol))}</option>
                `).join('')}
              </select>
            </div>
            <div class="field">
              <label>端口</label>
              <input name="port" type="number" min="1" max="65535" required value="${escapeHtml(node?.port || '')}" placeholder="443">
            </div>
            <div class="field full ss-field" style="display:none">
              <label>加密方式</label>
              <select name="method">
                ${SS_METHODS.map((item) => `
                  <option value="${item}" ${(node?.method || 'aes-256-gcm') === item ? 'selected' : ''}>${escapeHtml(item)}</option>
                `).join('')}
              </select>
            </div>
            <div class="field full ss-field" style="display:none">
              <label>网络</label>
              <select name="ss_network">
                ${['tcp', 'udp', 'tcp,udp'].map((item) => `
                  <option value="${item}" ${(node?.ss_network || 'tcp') === item ? 'selected' : ''}>${escapeHtml(item.toUpperCase())}</option>
                `).join('')}
              </select>
            </div>
            <div class="field">
              <label>传输</label>
              <select name="network">
                ${['tcp', 'ws', 'grpc', 'httpupgrade'].map((item) => `
                  <option value="${item}" ${network === item ? 'selected' : ''}>${escapeHtml(item.toUpperCase())}</option>
                `).join('')}
              </select>
            </div>
            <div class="field">
              <label>安全</label>
              <select name="security">
                ${[['none', '无加密'], ['tls', 'TLS'], ['reality', 'Reality']].map(([value, label]) => `
                  <option value="${value}" ${security === value ? 'selected' : ''}>${escapeHtml(label)}</option>
                `).join('')}
              </select>
            </div>
            <div class="field tls-field" style="${security === 'tls' ? '' : 'display:none'}">
              <label>证书路径</label>
              <input name="cert_file" value="${escapeHtml(node?.cert_file || '')}" placeholder="/etc/ssl/fullchain.pem">
            </div>
            <div class="field tls-field" style="${security === 'tls' ? '' : 'display:none'}">
              <label>私钥路径</label>
              <input name="key_file" value="${escapeHtml(node?.key_file || '')}" placeholder="/etc/ssl/privkey.pem">
            </div>
            <div class="field full reality-field" style="${security === 'reality' ? '' : 'display:none'}">
              <label>Reality 伪装站点预设</label>
              <div class="reality-preset-row">
                <select id="reality-preset-select">
                  <option value="">选择预设</option>
                  ${REALITY_PRESETS.map((preset) => `<option value="${escapeHtml(preset.name)}">${escapeHtml(preset.name)}</option>`).join('')}
                </select>
                <button type="button" class="btn ghost" id="random-reality-btn" title="随机轮换 Reality 伪装站点"><i data-lucide="shuffle"></i>随机</button>
              </div>
            </div>
            <div class="field full reality-field" style="${security === 'reality' ? '' : 'display:none'}">
              <label>Reality 目标</label>
              <input name="dest" value="${escapeHtml(node?.dest || '')}" placeholder="www.microsoft.com:443">
            </div>
            <div class="field full reality-field" style="${security === 'reality' ? '' : 'display:none'}">
              <label>serverNames</label>
              <input name="server_names" value="${escapeHtml(node?.server_names || '')}" placeholder="逗号分隔，例如 www.microsoft.com">
            </div>
            <div class="field full reality-field" style="${security === 'reality' ? '' : 'display:none'}">
              <label>Reality 私钥</label>
              <input name="private_key" value="${escapeHtml(node?.private_key || '')}" placeholder="由 xray x25519 生成">
            </div>
            <div class="field full reality-field" style="${security === 'reality' ? '' : 'display:none'}">
              <label>Reality 公钥</label>
              <input name="public_key" value="${escapeHtml(node?.public_key || '')}" placeholder="客户端分享链接使用">
            </div>
            <div class="field full reality-field" style="${security === 'reality' ? '' : 'display:none'}">
              <button type="button" class="btn ghost" id="gen-reality-btn" title="生成本地 X25519 Reality 密钥对"><i data-lucide="key-round"></i>生成 Reality 密钥对</button>
            </div>
            <div class="field full reality-field" style="${security === 'reality' ? '' : 'display:none'}">
              <label>shortIds</label>
              <input name="short_ids" value="${escapeHtml(node?.short_ids || '')}" placeholder="可选，逗号分隔">
            </div>
            <div class="field full">
              <label id="sni-label">SNI / serverName</label>
              <input name="sni" value="${escapeHtml(node?.sni || '')}" placeholder="域名或目标站点">
            </div>
            <div class="field full path-field" style="${network === 'tcp' ? 'display:none' : ''}">
              <label id="path-label">路径 / serviceName</label>
              <input name="path" value="${escapeHtml(node?.path || '')}" placeholder="例如 /ws 或 grpc">
            </div>
            <div class="field full">
              <label>客户端</label>
              <div class="client-toolbar">
                <button type="button" class="btn ghost sm" id="bulk-gen-clients-btn" title="为当前客户端批量生成 UUID 或密码"><i data-lucide="wand-2"></i>批量生成</button>
                <button type="button" class="btn ghost sm" id="import-clients-btn" title="从 v2rayN 分享链接导入客户端"><i data-lucide="download"></i>导入链接</button>
              </div>
              <div id="client-import-box" class="client-import-box" style="display:none">
                <textarea id="client-import-input" placeholder="粘贴 v2rayN 分享链接，每行一个"></textarea>
                <div class="paste-actions">
                  <button type="button" class="btn ghost sm" id="client-import-cancel" title="取消导入">取消</button>
                  <button type="button" class="btn primary sm" id="client-import-confirm" title="解析并导入客户端"><i data-lucide="download"></i>导入</button>
                </div>
              </div>
              <div id="clients-editor"></div>
              <button type="button" class="btn ghost sm" id="add-client-btn" title="添加一个客户端账号"><i data-lucide="user-plus"></i>添加客户端</button>
            </div>
            <div class="field">
              <label class="hint">启用</label>
              <input type="checkbox" name="enabled" ${node?.enabled === 0 ? '' : 'checked'} style="width:auto;height:20px">
            </div>
          </div>
        </form>
        <div class="modal-foot">
          <button class="btn ghost" data-close>取消</button>
          <button class="btn primary" type="submit" form="node-form" id="save-node-btn" title="仅保存节点配置"><i data-lucide="save"></i>保存</button>
          <button class="btn accent" type="submit" form="node-form" id="save-deploy-node-btn" title="保存节点并写入服务器配置后重启 Xray"><i data-lucide="upload-cloud"></i>保存并部署</button>
        </div>
      </div>
    </div>
  `);

  const initialClients = clients.map((client) => ({ ...client }));
  function clientFieldCount() {
    const protocol = $('select[name="protocol"]')?.value;
    if (protocol === 'vmess') return 4;
    if (protocol === 'vless' && $('select[name="security"]')?.value === 'reality') return 4;
    return 3;
  }
  function clientRowFieldsHtml(client) {
    const protocol = $('select[name="protocol"]')?.value;
    const isSocks = protocol === 'socks';
    const isVmess = protocol === 'vmess';
    const isVlessReality = protocol === 'vless' && $('select[name="security"]')?.value === 'reality';
    const secretPlaceholder = isSocks || protocol === 'trojan' || protocol === 'shadowsocks' ? '密码' : 'UUID';
    const flow = isVlessReality ? (client.flow || 'xtls-rprx-vision') : '';
    return `
        <input name="client_email" placeholder="${isSocks ? '用户名' : '备注'}" value="${escapeHtml(client.email)}">
        <input name="client_secret" placeholder="${secretPlaceholder}" value="${escapeHtml(client.secret)}" required>
        ${isVmess ? `
        <select name="client_security">
          ${['auto', 'aes-128-gcm', 'chacha20-poly1305'].map((item) => `
            <option value="${item}" ${(client.security || 'auto') === item ? 'selected' : ''}>${escapeHtml(item)}</option>
          `).join('')}
        </select>` : ''}
        ${isVlessReality ? `
        <select name="client_flow">
          ${['xtls-rprx-vision', 'xtls-rprx-vision-udp443', ''].map((item) => `
            <option value="${item}" ${flow === item ? 'selected' : ''}>${item ? escapeHtml(item) : '无'}</option>
          `).join('')}
        </select>` : ''}
    `;
  }
  function renderClientRows(valuesOverride = null) {
    const rows = $$('#clients-editor .client-row');
    const values = valuesOverride || (rows.length
      ? rows.map((row) => ({
        email: row.querySelector('[name="client_email"]').value,
        secret: row.querySelector('[name="client_secret"]').value,
        flow: row.querySelector('[name="client_flow"]')?.value || '',
        security: row.querySelector('[name="client_security"]')?.value || 'auto'
      }))
      : initialClients);
    $('#clients-editor').innerHTML = values.map((client) => `
      <div class="client-row cols-${clientFieldCount()}">
        ${clientRowFieldsHtml(client)}
        <button type="button" class="icon-btn" data-remove-client title="移除" aria-label="移除"><i data-lucide="x"></i></button>
      </div>
    `).join('');
    refreshIcons();
  }

  renderClientRows();

  function applyProtocolVisibility(protocol) {
    const isSocks = protocol === 'socks';
    const isSs = protocol === 'shadowsocks';
    const network = $('select[name="network"]')?.value || 'tcp';
    let security = $('select[name="security"]')?.value || 'none';
    const networkField = $('select[name="network"]').closest('.field');
    const securityField = $('select[name="security"]').closest('.field');
    const sniField = $('input[name="sni"]').closest('.field');
    const sniLabel = $('#sni-label');
    const pathLabel = $('#path-label');
    const pathField = $('.path-field');

    $$('.ss-field').forEach((field) => field.style.display = isSs ? '' : 'none');

    const realityOption = $('select[name="security"] option[value="reality"]');
    const canReality = protocol === 'vless' && network !== 'ws';
    if (realityOption) realityOption.disabled = !canReality;
    if (security === 'reality' && !canReality) {
      $('select[name="security"]').value = 'none';
      security = 'none';
    }

    if (isSocks || isSs) {
      $('select[name="network"]').value = 'tcp';
      $('select[name="security"]').value = 'none';
      $('input[name="sni"]').value = '';
      $('input[name="path"]').value = '';
      ['cert_file', 'key_file', 'dest', 'server_names', 'private_key', 'public_key', 'short_ids'].forEach((name) => {
        const input = $(`input[name="${name}"]`);
        if (input) input.value = '';
      });
      networkField.style.display = 'none';
      securityField.style.display = 'none';
      sniField.style.display = 'none';
      if (pathField) pathField.style.display = 'none';
      $$('.tls-field').forEach((field) => field.style.display = 'none');
      $$('.reality-field').forEach((field) => field.style.display = 'none');
      return;
    }

    networkField.style.display = '';
    securityField.style.display = '';
    const showSni = security !== 'none' || network !== 'tcp';
    sniField.style.display = showSni ? '' : 'none';
    if (sniLabel) {
      sniLabel.textContent = network !== 'tcp' && security === 'none' ? 'Host / 伪装域名' : 'SNI / serverName';
    }
    if (pathLabel) {
      pathLabel.textContent = network === 'grpc' ? 'serviceName' : network === 'ws' || network === 'httpupgrade' ? '路径 / Host' : '路径';
    }
    if (pathField) pathField.style.display = network === 'tcp' ? 'none' : '';
    $$('.tls-field').forEach((field) => field.style.display = security === 'tls' ? '' : 'none');
    $$('.reality-field').forEach((field) => field.style.display = security === 'reality' ? '' : 'none');
  }

  applyProtocolVisibility(node?.protocol || 'vless');


  $$('#node-role-segmented button').forEach((button) => {
    button.addEventListener('click', () => {
      $$('#node-role-segmented button').forEach((item) => item.classList.toggle('active', item === button));
    });
  });

  $('#clients-editor').addEventListener('click', (event) => {
    const removeButton = event.target.closest('[data-remove-client]');
    if (!removeButton) return;
    if ($$('#clients-editor .client-row').length === 1) {
  renderClientRows();

      return;
    }
    removeButton.closest('.client-row').remove();
  });

  $$('#modal-root [data-close]').forEach((button) => button.addEventListener('click', closeModal));

  $('#add-client-btn').addEventListener('click', () => {
    $('#clients-editor').insertAdjacentHTML('beforeend', `
      <div class="client-row">
        ${clientRowFieldsHtml({ email: '', secret: '', flow: '' })}
        <button type="button" class="icon-btn" data-remove-client title="移除" aria-label="移除"><i data-lucide="x"></i></button>
      </div>
    `);
    refreshIcons();
  });

  const bulkGenButton = $('#bulk-gen-clients-btn');
  if (bulkGenButton) {
    bulkGenButton.addEventListener('click', () => {
      const protocol = $('select[name="protocol"]')?.value || 'vless';
      const rows = $$('#clients-editor .client-row');
      const current = rows.length
        ? rows.map((row) => ({
          email: row.querySelector('[name="client_email"]').value,
          secret: row.querySelector('[name="client_secret"]').value,
          flow: row.querySelector('[name="client_flow"]')?.value || '',
          security: row.querySelector('[name="client_security"]')?.value || 'auto'
        }))
        : initialClients;
      const useUuid = protocol === 'vmess' || protocol === 'vless';
      const next = current.map((client) => ({ ...client, secret: useUuid ? randomClientSecret() : randomClientPassword() }));
      renderClientRows(next);
      toast(`已生成 ${next.length} 个${useUuid ? ' UUID' : ' 密码'}`, 'success');
    });
  }

  const importButton = $('#import-clients-btn');
  const importBox = $('#client-import-box');
  if (importButton && importBox) {
    importButton.addEventListener('click', () => {
      importBox.style.display = '';
      $('#client-import-input')?.focus();
    });
    $('#client-import-cancel')?.addEventListener('click', () => {
      importBox.style.display = 'none';
      $('#client-import-input').value = '';
    });
    $('#client-import-confirm')?.addEventListener('click', () => {
      const textarea = $('#client-import-input');
      const imported = String(textarea?.value || '').split(/\r?\n/)
        .map((line) => line.trim())
        .map((line) => parseV2rayClientLink(line))
        .filter(Boolean);
      if (!imported.length) {
        toast('未识别到有效 v2rayN 分享链接', 'error');
        return;
      }
      const rows = $$('#clients-editor .client-row');
      const current = rows.length
        ? rows.map((row) => ({
          email: row.querySelector('[name="client_email"]').value,
          secret: row.querySelector('[name="client_secret"]').value,
          flow: row.querySelector('[name="client_flow"]')?.value || '',
          security: row.querySelector('[name="client_security"]')?.value || 'auto'
        }))
        : initialClients;
      const next = current.map((client) => ({ ...client }));
      imported.forEach((client, index) => {
        if (index < next.length) Object.assign(next[index], client);
        else next.push({ ...client, security: client.security || 'auto', flow: client.flow || '' });
      });
      renderClientRows(next);
      importBox.style.display = 'none';
      if (textarea) textarea.value = '';
      toast(`已导入 ${imported.length} 个客户端`, 'success');
    });
  }

  const realityButton = $('#gen-reality-btn');
  if (realityButton) {
    realityButton.addEventListener('click', async () => {
      const targetServerId = $('#node-server-id')?.value || initialServerId;
      if (!targetServerId) {
        toast('请先选择服务器后再生成 Reality 密钥对', 'error');
        return;
      }
      withBusy(realityButton, '生成中...', async () => {
        const pair = await api(`/api/servers/${targetServerId}/x25519`, { method: 'POST' });
        $('input[name="private_key"]').value = pair.privateKey;
        $('input[name="public_key"]').value = pair.publicKey;
        toast('Reality 密钥对已生成', 'success');
      }).catch((error) => toast(error.message, 'error'));
    });
  }

  const presetSelect = $('#reality-preset-select');
  const randomRealityButton = $('#random-reality-btn');
  let realityPresetIndex = 0;

  function applyRealityPreset(preset) {
    $('input[name="dest"]').value = preset.dest;
    $('input[name="server_names"]').value = preset.serverNames;
    $('input[name="sni"]').value = preset.sni;
  }

  if (presetSelect) {
    presetSelect.addEventListener('change', () => {
      const index = REALITY_PRESETS.findIndex((preset) => preset.name === presetSelect.value);
      if (index < 0) return;
      realityPresetIndex = index;
      applyRealityPreset(REALITY_PRESETS[index]);
      toast(`已选择 ${REALITY_PRESETS[index].name} 伪装站点`);
    });
  }

  if (randomRealityButton) {
    randomRealityButton.addEventListener('click', () => {
      realityPresetIndex = (realityPresetIndex + 1) % REALITY_PRESETS.length;
      const preset = REALITY_PRESETS[realityPresetIndex];
      applyRealityPreset(preset);
      if (presetSelect) presetSelect.value = preset.name;
      toast(`已轮换到 ${preset.name} 伪装站点`);
    });
  }

  const securitySelect = $('select[name="security"]');
  const networkSelect = $('select[name="network"]');
  const protocolSelect = $('select[name="protocol"]');
  securitySelect.addEventListener('change', () => applyProtocolVisibility(protocolSelect.value));
  securitySelect.addEventListener('change', () => {
    applyProtocolVisibility(protocolSelect.value);
    if (protocolSelect.value === 'vless') renderClientRows();
  });
  networkSelect.addEventListener('change', () => {
    applyProtocolVisibility(protocolSelect.value);
    if (protocolSelect.value === 'vless') renderClientRows();
  });
  protocolSelect.addEventListener('change', () => {
    applyProtocolVisibility(protocolSelect.value);
    renderClientRows();
  });

  async function saveAndDeploy(deploy) {
    const form = $('#node-form');
    const targetServerId = isEdit ? serverId : form.querySelector('[name="server_id"]')?.value;
    if (!targetServerId) throw new Error('请选择使用的服务器');
    const data = Object.fromEntries(new FormData(form).entries());
    data.role = $('#node-role-segmented button.active').dataset.role;
    data.port = Number(data.port);
    data.enabled = form.querySelector('[name="enabled"]').checked;
    data.clients = $$('#clients-editor .client-row').map((row) => ({
      email: row.querySelector('[name="client_email"]').value,
      secret: row.querySelector('[name="client_secret"]').value,
      flow: row.querySelector('[name="client_flow"]')?.value || '',
      security: row.querySelector('[name="client_security"]')?.value || 'auto'
    }));
    data.method = form.querySelector('[name="method"]')?.value || 'aes-256-gcm';
    data.ss_network = form.querySelector('[name="ss_network"]')?.value || 'tcp';
    data.server_id = targetServerId;
    try {
      let saved;
      if (isEdit) saved = await api(`/api/nodes/${node.id}`, { method: 'PUT', body: JSON.stringify(data) });
      else saved = await api(`/api/servers/${targetServerId}/nodes`, { method: 'POST', body: JSON.stringify(data) });
      closeModal();
      await loadAll();
      if (deploy) {
        openProgressModal('保存并部署', '正在部署服务器...');
        try {
          const result = await api(`/api/servers/${targetServerId}/deploy`, { method: 'POST' });
          closeProgressModal();
          openResultModal('部署结果', result.restart?.stdout + '\n' + result.status?.listening || 'ok');
        } catch (error) {
          closeProgressModal();
          toast(error.message, 'error');
        } finally {
          await loadAll();
        }
      } else {
        toast('节点已保存', 'success');
      }
    } catch (error) {
      toast(error.message, 'error');
    }
  }

  $('#save-node-btn').addEventListener('click', (event) => {
    event.preventDefault();
    withBusy($('#save-node-btn'), '保存中...', () => saveAndDeploy(false)).catch((error) => toast(error.message, 'error'));
  });
  $('#save-deploy-node-btn').addEventListener('click', (event) => {
    event.preventDefault();
    withBusy($('#save-deploy-node-btn'), '部署中...', () => saveAndDeploy(true)).catch((error) => toast(error.message, 'error'));
  });
}


function routeNodeCard(node, role) {
  const selected = role === 'inbound' ? state.selectedInboundId === node.id : state.selectedOutboundId === node.id;
  const connected = role === 'inbound'
    ? state.routes.some((route) => route.inbound_node_id === node.id)
    : state.routes.some((route) => route.outbound_node_id === node.id);
  const server = state.servers.find((item) => item.id === node.server_id);
  return `
    <div class="route-node ${selected ? 'selected' : ''} ${connected ? 'connected' : ''}" data-route-role="${role}" data-node-id="${escapeHtml(node.id)}" role="button" title="${role === 'inbound' ? '选择入站节点' : '选择出站节点'}" aria-pressed="${selected}">
      <div class="route-node-main">
        <span class="route-node-name">${escapeHtml(node.name)}</span>
        <span class="hint">${escapeHtml(server ? server.name + ' · ' + server.host : '')}</span>
      </div>
      <div class="route-node-meta">
        <span>${escapeHtml(protocolLabel(node.protocol))} / ${escapeHtml(node.port)}</span>
        ${connected ? badge('已连接', 'green') : ''}
      </div>
    </div>
  `;
}

function renderRoutes({ motion = true } = {}) {
  const inboundList = $('#route-inbound-list');
  if (!inboundList) return;
  const inboundNodes = state.nodes.filter((node) => node.role === 'inbound');
  const outboundNodes = state.nodes.filter((node) => node.role === 'outbound');
  $('#inbound-count').textContent = inboundNodes.length + ' 个';
  $('#outbound-count').textContent = outboundNodes.length + ' 个';
  inboundList.innerHTML = inboundNodes.length
    ? inboundNodes.map((node) => routeNodeCard(node, 'inbound')).join('')
    : emptyState('还没有入站节点，请先添加', { icon: 'log-in', action: 'go-nodes', actionLabel: '添加节点' });
  $('#route-outbound-list').innerHTML = outboundNodes.length
    ? outboundNodes.map((node) => routeNodeCard(node, 'outbound')).join('')
    : emptyState('还没有出站节点，请先添加', { icon: 'log-out', action: 'go-nodes', actionLabel: '添加节点' });
  $('#route-link-list').innerHTML = state.routes.length
    ? state.routes.map((route) => {
        const inbound = state.nodes.find((node) => node.id === route.inbound_node_id);
        const outbound = state.nodes.find((node) => node.id === route.outbound_node_id);
        return `
          <div class="route-link-row">
            <div class="route-link-pair">
              <span>${escapeHtml(inbound?.name || route.inbound_node?.name || '未知')}</span>
              <i data-lucide="arrow-right"></i>
              <span>${escapeHtml(outbound?.name || route.outbound_node?.name || '未知')}</span>
              <span class="hint">${escapeHtml(inbound?.server?.host || route.inbound_node?.server?.host || '')}:${escapeHtml(inbound?.port || route.inbound_node?.port || '')} → ${escapeHtml(outbound?.server?.host || route.outbound_node?.server?.host || '')}:${escapeHtml(outbound?.port || route.outbound_node?.port || '')}</span>
            </div>
            <button class="btn sm danger" data-remove-route="${escapeHtml(route.id)}" title="断开该链路并重新部署入站服务器"><i data-lucide="trash-2"></i>断开</button>
          </div>
        `;
      }).join('')
    : emptyState('还没有连接，选择入站和出站后点击“连接所选节点”', { icon: 'route', action: 'go-nodes', actionLabel: '去节点页' });
  $('#create-route-btn').disabled = !(state.selectedInboundId && state.selectedOutboundId);
  if (motion) {
    animateCollection(inboundList, '.route-node, .empty-state');
    animateCollection($('#route-outbound-list'), '.route-node, .empty-state');
    animateCollection($('#route-link-list'), '.route-link-row, .empty-state');
  }
  refreshIcons();
}

function openProgressModal(title, message) {
  setModal(`
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-head">
          <h2>${escapeHtml(title)}</h2>
        </div>
        <div class="modal-body">
          <div class="progress-line">
            <span class="spin"><i data-lucide="refresh-cw"></i></span>
            <span id="progress-text">${escapeHtml(message)}</span>
          </div>
        </div>
      </div>
    </div>
  `);
}

function updateProgress(message) {
  const text = $('#progress-text');
  if (text) text.textContent = message;
}

function closeProgressModal() {
  if ($('#progress-text')) closeModal();
}

async function createSelectedRoute() {
  if (!state.selectedInboundId || !state.selectedOutboundId) return;
  const inboundNode = state.nodes.find((node) => node.id === state.selectedInboundId);
  const outboundNode = state.nodes.find((node) => node.id === state.selectedOutboundId);
  if (!inboundNode || !outboundNode) return;
  const button = $('#create-route-btn');
  const original = button.innerHTML;
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  button.innerHTML = '<span class="btn-loading"><i data-lucide="loader-circle"></i>连接中...</span>';
  refreshIcons();
  openProgressModal('连接路由', '正在保存路由关系...');
  try {
    await api('/api/routes', {
      method: 'POST',
      body: JSON.stringify({
        inbound_node_id: state.selectedInboundId,
        outbound_node_id: state.selectedOutboundId
      })
    });
    if (outboundNode.server_id !== inboundNode.server_id) {
      updateProgress('正在检查出站服务器...');
      const outboundStatus = await api(`/api/servers/${outboundNode.server_id}/status`).catch(() => null);
      const outboundActive = ['active', 'started'].includes(outboundStatus?.xray?.active);
      if (!outboundActive) {
        updateProgress('正在部署出站服务器...');
        await api(`/api/servers/${outboundNode.server_id}/deploy`, { method: 'POST' });
      }
    }
    updateProgress('正在部署入站服务器...');
    const result = await api(`/api/servers/${inboundNode.server_id}/deploy`, { method: 'POST' });
    closeProgressModal();
    openResultModal('路由已连接', result.restart?.stdout + '\n' + result.status?.listening || '完成');
    state.selectedInboundId = null;
    state.selectedOutboundId = null;
    await loadAll();
  } catch (error) {
    closeProgressModal();
    toast(error.message, 'error');
    state.selectedInboundId = null;
    state.selectedOutboundId = null;
    await loadAll();
  }
  finally {
    button.disabled = false;
    button.removeAttribute('aria-busy');
    button.innerHTML = original;
    refreshIcons();
  }
}

async function removeRoute(routeId, button = null) {
  const route = state.routes.find((item) => item.id === routeId);
  const inboundNode = route && (state.nodes.find((node) => node.id === route.inbound_node_id) || route.inbound_node);
  if (!route || !inboundNode?.server_id) return;
  openConfirmModal({
    title: '断开路由',
    message: [
      '将删除该入站到出站的连接关系。',
      '会重新部署入站服务器，出站链路随即停止转发。'
    ],
    confirmText: '断开',
    onConfirm: async () => {
      if (button) {
        const original = button.innerHTML;
        button.disabled = true;
        button.setAttribute('aria-busy', 'true');
        button.innerHTML = '<span class="btn-loading"><i data-lucide="loader-circle"></i>断开中...</span>';
        refreshIcons();
        try {
          await runDisconnect(routeId, inboundNode);
        } finally {
          button.disabled = false;
          button.removeAttribute('aria-busy');
          button.innerHTML = original;
          refreshIcons();
        }
      } else {
        await runDisconnect(routeId, inboundNode);
      }
    }
  });
}

async function runDisconnect(routeId, inboundNode) {
  openProgressModal('断开路由', '正在删除路由关系...');
  try {
    await api('/api/routes/' + routeId, { method: 'DELETE' });
    updateProgress('正在重新部署入站服务器...');
    const result = await api(`/api/servers/${inboundNode.server_id}/deploy`, { method: 'POST' });
    closeProgressModal();
    openResultModal('路由已断开', result.restart?.stdout + '\n' + result.status?.listening || '完成');
    await loadAll();
  } catch (error) {
    closeProgressModal();
    toast(error.message, 'error');
    await loadAll();
  }
}

function openShareModal(node) {
  const links = node.links || [];
  setModal(`
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-head">
          <h2>${escapeHtml(node.name)} 分享链接</h2>
          <button class="icon-btn" data-close title="关闭" aria-label="关闭"><i data-lucide="x"></i></button>
        </div>
        <div class="modal-body">
          <div class="share-list">
            ${links.length ? links.map((client, index) => `
              <div class="share-item">
                <div>
                  <div class="hint">${escapeHtml(client.email || `客户端 ${index + 1}`)}</div>
                  <code>${escapeHtml(client.link)}</code>
                </div>
                <button class="btn sm ghost" data-copy="${escapeHtml(client.link)}" title="复制分享链接"><i data-lucide="copy"></i>复制</button>
              </div>
            `).join('') : emptyState('该节点没有客户端')}
          </div>
        </div>
        <div class="modal-foot">
          <button class="btn ghost" data-close>关闭</button>
        </div>
      </div>
    </div>
  `);
  $$('#modal-root [data-close]').forEach((button) => button.addEventListener('click', closeModal));
  $$('#modal-root [data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      try {
        if (await copyText(button.dataset.copy)) {
          toast('已复制', 'success');
        } else {
          toast('自动复制失败，请手动选择链接', 'info');
        }
      } catch {
        toast('复制失败，请手动选择链接', 'error');
      }
    });
  });
}

function openResultModal(title, text, raw = false) {
  setModal(`
    <div class="modal-backdrop">
      <div class="modal wide">
        <div class="modal-head">
          <h2>${escapeHtml(title)}</h2>
          <button class="icon-btn" data-close title="关闭" aria-label="关闭"><i data-lucide="x"></i></button>
        </div>
        <div class="modal-body">
          ${raw
            ? `<pre class="log-view">${escapeHtml(text)}</pre>`
            : `<div class="share-list">${(Array.isArray(text) ? text : String(text).split(/\n/)).filter(Boolean).map((line) => `<div class="share-item"><code>${escapeHtml(line)}</code></div>`).join('')}</div>`}
        </div>
        <div class="modal-foot">
          <button class="btn ghost" data-close>关闭</button>
        </div>
      </div>
    </div>
  `);
  $$('#modal-root [data-close]').forEach((button) => button.addEventListener('click', closeModal));
}
function startTerminalSession(server) {
  if (!server) return;
  closeTerminalSession();
  const host = $('#terminal-host');
  const statusEl = $('#terminal-status');
  if (!host || !statusEl) return;
  host.innerHTML = '';
  statusEl.textContent = '连接中...';
  statusEl.classList.remove('error');

  const term = new Terminal({
    cursorBlink: true,
    fontSize: 13,
    fontFamily: '"Cascadia Code", Consolas, "Courier New", monospace',
    scrollback: 5000,
    theme: {
      background: '#0f1720',
      foreground: '#d7e3ea',
      cursor: '#5eead4',
      selectionBackground: '#334155'
    }
  });
  const FitAddonClass = typeof FitAddon === 'function' ? FitAddon : FitAddon?.FitAddon;
  const fitAddon = new FitAddonClass();
  term.loadAddon(fitAddon);
  term.open(host);
  try { fitAddon.fit(); } catch { /* terminal may not have layout yet */ }
  term.focus();

  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws/terminal?serverId=${encodeURIComponent(server.id)}&cols=${term.cols}&rows=${term.rows}`);
  terminalSession = { ws, term, fitAddon };

  function setStatus(text, error = false) {
    const el = $('#terminal-status');
    if (!el) return;
    el.textContent = text;
    el.classList.toggle('error', error);
  }

  function sendResize() {
    if (ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
  }

  ws.addEventListener('open', () => {
    setStatus('已连接');
    fitAddon.fit();
    sendResize();
    term.focus();
  });

  ws.addEventListener('message', (event) => {
    if (typeof event.data === 'string') {
      try {
        const message = JSON.parse(event.data);
        if (message.type === 'error') {
          setStatus('连接失败', true);
          term.writeln(`\r\n\x1b[31m${message.message || 'SSH 连接失败'}\x1b[0m`);
          return;
        }
        if (message.type === 'ready') setStatus('已连接');
        if (message.type === 'closed') {
          setStatus('已断开', true);
          term.writeln(`\r\n\x1b[33m${message.message || 'SSH session closed'}\x1b[0m`);
        }
        return;
      } catch { /* raw terminal output */ }
      term.write(event.data);
      return;
    }
    event.data.text().then((text) => term.write(text));
  });

  ws.addEventListener('close', () => {
    if (terminalSession?.term === term) {
      setStatus('已断开', true);
      term.writeln('\r\n\x1b[33m连接已关闭\x1b[0m');
    }
  });

  ws.addEventListener('error', () => {
    setStatus('连接失败', true);
  });

  term.onData((data) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(data);
  });

  term.onResize(() => {
    sendResize();
  });
}

function openTerminalModal(server) {
  if (!server) return;
  closeTerminalSession();
  setModal(`
    <div class="modal-backdrop">
      <div class="modal terminal-modal" id="terminal-modal">
        <div class="modal-head">
          <h2>${escapeHtml(server.name)} SSH 终端</h2>
          <div class="terminal-head-side">
            <span id="terminal-status" class="terminal-status">连接中...</span>
            <button type="button" class="icon-btn" data-terminal-fullscreen title="全屏" aria-label="全屏"><i data-lucide="maximize-2"></i></button>
            <button type="button" class="icon-btn" data-terminal-reconnect title="重新连接" aria-label="重新连接"><i data-lucide="refresh-cw"></i></button>
            <button type="button" class="icon-btn" data-close title="关闭" aria-label="关闭"><i data-lucide="x"></i></button>
          </div>
        </div>
        <div class="modal-body terminal-body">
          <div id="terminal-host"></div>
        </div>
        <div class="terminal-foot">
          <span>${escapeHtml(server.username)}@${escapeHtml(server.host)}:${escapeHtml(server.port)}</span>
        </div>
      </div>
    </div>
  `);

  const modal = $('#terminal-modal');
  const fullscreenButton = $('#modal-root [data-terminal-fullscreen]');
  $$('#modal-root [data-close]').forEach((button) => button.addEventListener('click', closeModal));
  if (fullscreenButton) {
    fullscreenButton.addEventListener('click', () => {
      const isFullscreen = modal.classList.toggle('fullscreen');
      fullscreenButton.innerHTML = `<i data-lucide="${isFullscreen ? 'minimize-2' : 'maximize-2'}"></i>`;
      fullscreenButton.title = isFullscreen ? '退出全屏' : '全屏';
      fullscreenButton.setAttribute('aria-label', fullscreenButton.title);
      refreshIcons();
      requestAnimationFrame(() => {
        if (terminalSession?.fitAddon) {
          try { terminalSession.fitAddon.fit(); } catch { /* ignore */ }
        }
      });
    });
  }
  $('#modal-root [data-terminal-reconnect]')?.addEventListener('click', () => startTerminalSession(server));
  startTerminalSession(server);
}

function formatTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString('zh-CN', { hour12: false });
}

async function checkServerStatus(serverId) {
  const server = state.servers.find((item) => item.id === serverId);
  if (!server) return;
  const body = $('#status-modal-body');
  if (body) body.innerHTML = '<div class="status-loading">正在检查服务器状态...</div>';
  try {
    const status = await api(`/api/servers/${serverId}/status`);
    state.probes[serverId] = status;
    renderServers();
    openStatusModal(server, status);
  } catch (error) {
    if (body) {
      body.innerHTML = `<div class="status-error"><strong>检查失败</strong><span>${escapeHtml(error.message)}</span></div>`;
    } else {
      toast(error.message, 'error');
    }
  }
}

function openStatusModal(server, status) {
  if (!server) return;
  const nodes = state.nodes.filter((node) => node.server_id === server.id);
  const sshOk = Boolean(status?.ssh?.connected);
  const xrayRunning = Boolean(status?.xray?.running);
  const xrayInstalled = status?.xray?.installed === true;
  const config = status?.config;
  const sshBadge = sshOk
    ? badge('已连接', 'green')
    : badge('连接失败', 'red', status?.ssh?.error || '');
  const xrayBadge = !status?.xray?.bin_present
    ? badge('二进制缺失', 'red')
    : !xrayInstalled
      ? badge('未安装', 'red')
      : xrayRunning
        ? badge('运行中', 'green')
        : badge('服务停止', 'amber');
  const configBadge = !config?.exists
    ? badge('缺失', 'red')
    : !config?.readable
      ? badge('不可读', 'amber', '配置文件存在但当前用户无法读取')
      : config?.valid
        ? badge('有效', 'green')
        : badge('无效', 'red');
  const ports = status?.ports || { tcp: [], udp: [] };
  const allPorts = [...new Set([...ports.tcp, ...ports.udp])];
  const listeningLabel = allPorts.length ? allPorts.join(', ') : '无';
  const chip = (text, ok) => `<span class="status-chip ${ok ? 'ok' : 'bad'}">${escapeHtml(text)}</span>`;
  const mutedChip = (text) => `<span class="status-chip muted">${escapeHtml(text)}</span>`;

  const nodeRows = nodes.length
    ? nodes.map((node) => {
        const nodeStatus = status?.nodes?.find((item) => item.id === node.id);
        let stateBadge;
        if (!sshOk || !status) stateBadge = badge('未检查', '');
        else if (!xrayRunning) stateBadge = badge('服务停止', 'amber');
        else if (!nodeStatus?.in_config) stateBadge = badge('配置缺失', 'red');
        else if (!nodeStatus?.listening) stateBadge = badge('端口未监听', 'red');
        else stateBadge = badge('监听正常', 'green');
        const wantsUdp = node.protocol === 'socks' || String(node.ss_network || '').includes('udp');
        const udpChip = wantsUdp
          ? chip(`UDP ${nodeStatus?.listening_udp ? '监听' : '未监听'}`, Boolean(nodeStatus?.listening_udp))
          : '';
        return `
          <div class="status-node-row">
            <div class="status-node-main">
              <strong>${escapeHtml(node.name)}</strong>
              <span class="muted">${escapeHtml(protocolLabel(node.protocol))} · 端口 ${escapeHtml(node.port)} · ${node.role === 'outbound' ? '出站' : '入站'}</span>
            </div>
            <div class="status-node-chips">
              ${nodeStatus ? chip(`配置 ${nodeStatus.in_config ? '已写入' : '缺失'}`, nodeStatus.in_config) : mutedChip('配置 —')}
              ${nodeStatus ? chip(`TCP ${nodeStatus.listening_tcp ? '监听' : '未监听'}`, nodeStatus.listening_tcp) : mutedChip('TCP —')}
              ${udpChip}
            </div>
            ${stateBadge}
          </div>
        `;
      }).join('')
    : emptyState('该服务器还没有节点', { icon: 'network' });

  setModal(`
    <div class="modal-backdrop">
      <div class="modal wide status-modal">
        <div class="modal-head">
          <h2>${escapeHtml(server.name)} 状态</h2>
          <button class="icon-btn" data-close title="关闭" aria-label="关闭"><i data-lucide="x"></i></button>
        </div>
        <div class="modal-body" id="status-modal-body">
          ${!status ? `<div class="status-loading">正在检查...</div>` : ''}
          ${status && !sshOk ? `<div class="status-error"><strong>SSH 检查失败</strong><span>${escapeHtml(status.ssh?.error || '未知错误')}</span></div>` : ''}
          ${status ? `
          <div class="status-summary">
            <div class="status-summary-item">
              <span class="status-summary-label">SSH 连接</span>
              <span class="status-summary-value">${sshBadge}</span>
            </div>
            <div class="status-summary-item">
              <span class="status-summary-label">Xray 服务</span>
              <span class="status-summary-value">${xrayBadge}</span>
            </div>
            <div class="status-summary-item">
              <span class="status-summary-label">配置文件</span>
              <span class="status-summary-value">${configBadge}</span>
            </div>
            <div class="status-summary-item">
              <span class="status-summary-label">监听端口</span>
              <span class="status-summary-value status-port-value">${escapeHtml(listeningLabel)}</span>
            </div>
          </div>
          <div class="status-section-head">
            <span>节点实际状态</span>
            <span>实时 · 最近检查 ${escapeHtml(formatTime(status.checked_at))}</span>
          </div>
          <div class="status-section-head">
            <span>最近 24 小时状态变化</span>
            <span>面板缓存</span>
          </div>
          <div class="status-history-list">
            ${statusHistoryFor(server.id).slice().reverse().slice(0, 6).map((entry) => `
              <div class="status-history-row">
                ${statusPill(entry.state)}
                <span>${escapeHtml(formatTime(entry.at))}</span>
              </div>
            `).join('') || '<div class="status-history-empty">暂无变化记录</div>'}
          </div>
          <div class="status-node-list">${nodeRows}</div>
          ` : ''}
        </div>
        <div class="modal-foot">
          <button class="btn ghost" data-close>关闭</button>
          <button class="btn primary" id="recheck-status-btn" title="重新实时检查"><i data-lucide="refresh-cw"></i>重新检查</button>
        </div>
      </div>
    </div>
  `);
  $$('#modal-root [data-close]').forEach((button) => button.addEventListener('click', closeModal));
  $('#recheck-status-btn').addEventListener('click', () => checkServerStatus(server.id));
}

function openRepairConfirmModal(server, driftType, driftReason) {
  if (!server || !driftType) return;
  const summary = REPAIR_SUMMARIES[driftType] || '执行远程修复操作';
  setModal(`
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-head">
          <h2>确认${repairActionLabel(driftType)}</h2>
          <button class="icon-btn" data-close title="关闭" aria-label="关闭"><i data-lucide="x"></i></button>
        </div>
        <div class="modal-body">
          <div class="repair-summary">
            <div class="repair-row"><span class="repair-label">服务器</span><strong>${escapeHtml(server.name)}</strong><span class="muted">${escapeHtml(server.host)}:${escapeHtml(server.port)}</span></div>
            <div class="repair-row"><span class="repair-label">漂移类型</span>${statusPill(driftType)}<span>${escapeHtml(driftReason || '')}</span></div>
            <div class="repair-row"><span class="repair-label">执行操作</span><span>${escapeHtml(summary)}</span></div>
          </div>
        </div>
        <div class="modal-foot">
          <button class="btn ghost" data-close>取消</button>
          <button class="btn danger" id="confirm-repair-btn" title="确认执行"><i data-lucide="wrench"></i>确认${repairActionLabel(driftType)}</button>
        </div>
      </div>
    </div>
  `);
  $$('#modal-root [data-close]').forEach((button) => button.addEventListener('click', closeModal));
  $('#confirm-repair-btn').addEventListener('click', () => runRepair(server, driftType));
}

function openConfirmModal({ title, message = [], confirmText = '确认', danger = true, onConfirm }) {
  const lines = Array.isArray(message) ? message : [message];
  setModal(`
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-head">
          <h2>${escapeHtml(title)}</h2>
          <button class="icon-btn" data-close title="关闭" aria-label="关闭"><i data-lucide="x"></i></button>
        </div>
        <div class="modal-body">
          <div class="confirm-message">${lines.map((line) => `<p>${escapeHtml(line)}</p>`).join('')}</div>
        </div>
        <div class="modal-foot">
          <button class="btn ghost" data-close>取消</button>
          <button class="btn ${danger ? 'danger' : 'primary'}" id="confirm-action-btn" title="确认执行">${escapeHtml(confirmText)}</button>
        </div>
      </div>
    </div>
  `);
  $$('#modal-root [data-close]').forEach((button) => button.addEventListener('click', closeModal));
  $('#confirm-action-btn').addEventListener('click', () => {
    closeModal();
    onConfirm();
  });
}

function handleEmptyAction(action) {
  if (action === 'add-server') openServerModal();
  if (action === 'add-node') openNodeModal();
  if (action === 'add-subscription') openSubscriptionForm();
  if (action === 'go-servers') $$('.nav-item[data-view="servers"]')[0]?.click();
  if (action === 'go-nodes') $$('.nav-item[data-view="nodes"]')[0]?.click();
}

async function runRepair(server, driftType) {
  if (!server || !driftType) return;
  openProgressModal(`正在${repairActionLabel(driftType)}`, `正在对「${server.name}」执行${repairActionLabel(driftType)}...`);
  try {
    const result = await api(`/api/servers/${server.id}/repair`, {
      method: 'POST',
      body: JSON.stringify({ drift_type: driftType })
    });
    closeProgressModal();
    if (result.ok) {
      openResultModal('修复完成', [
        `服务器：${server.name}`,
        `漂移类型：${statusMeta(driftType).label}`,
        `执行操作：${REPAIR_SUMMARIES[driftType] || result.action}`,
        '修复成功，下一轮巡检会自动确认状态'
      ]);
    } else {
      openResultModal('修复失败', `${result.error || '未知错误'}\n\n动作：${result.action}`, true);
    }
    await loadAll();
  } catch (error) {
    closeProgressModal();
    toast(error.message, 'error');
    await loadAll();
  }
}

async function runServerAction(action, serverId, button) {
  if (action === 'terminal') {
    const server = state.servers.find((item) => item.id === serverId);
    openTerminalModal(server);
    return;
  }
  const original = button.innerHTML;
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  button.innerHTML = '<span class="btn-loading"><i data-lucide="loader-circle"></i>执行中...</span>';
  refreshIcons();
  try {
    if (action === 'status') {
      await checkServerStatus(serverId);
    }
    if (action === 'repair') {
      const server = state.servers.find((item) => item.id === serverId);
      const live = state.statuses[serverId];
      openRepairConfirmModal(server, live?.drift, live?.drift_reason);
    }
    if (action === 'logs') {
      const logs = await api(`/api/servers/${serverId}/logs?lines=200`);
      openResultModal('远程日志', logs.stdout || '没有日志', true);
    }
    if (action === 'edit') {
      const server = state.servers.find((item) => item.id === serverId);
      openServerModal(server);
    }
    if (action === 'delete') {
      const server = state.servers.find((item) => item.id === serverId);
      openConfirmModal({
        title: '删除服务器',
        message: [
          `将删除「${server?.name || ''}」的本地配置，以及该服务器下的全部节点和路由。`,
          '不会影响 VPS 上已运行的服务。'
        ],
        confirmText: '删除',
        onConfirm: async () => {
          await withBusy(button, '删除中...', async () => {
            try {
              await api(`/api/servers/${serverId}`, { method: 'DELETE' });
              toast('服务器已删除', 'success');
              await loadAll();
            } catch (error) {
              toast(error.message, 'error');
            }
          });
        }
      });
    }
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    button.disabled = false;
    button.removeAttribute('aria-busy');
    button.innerHTML = original;
    refreshIcons();
  }
}

async function runNodeAction(action, nodeId, button) {
  const node = state.nodes.find((item) => item.id === nodeId);
  if (!node) return;
  if (action === 'status') {
    await checkServerStatus(node.server_id);
    return;
  }
  if (action === 'repair') {
    const server = state.servers.find((item) => item.id === node.server_id);
    const live = state.statuses[node.server_id];
    openRepairConfirmModal(server, live?.drift, live?.drift_reason);
    return;
  }
  if (action === 'share') openShareModal(node);
  if (action === 'edit') openNodeModal(node.server_id, node);
  if (action === 'delete') {
    openConfirmModal({
      title: '删除节点',
      message: [
        `将删除面板中的节点「${node.name}」配置。`,
        '不影响服务器上已部署的 Xray，重新部署服务器后该入站才会被移除。'
      ],
      confirmText: '删除',
      onConfirm: async () => {
        await withBusy(button, '删除中...', async () => {
          try {
            await api(`/api/nodes/${nodeId}`, { method: 'DELETE' });
            toast('节点已删除', 'success');
            await loadAll();
          } catch (error) {
            toast(error.message, 'error');
          }
        });
      }
    });
  }
}

async function deployServerNodes(serverId, button) {
  const server = state.servers.find((item) => item.id === serverId);
  if (!server) return;
  await withBusy(button, '部署中...', async () => {
    openProgressModal('部署节点', `正在部署「${server.name}」的全部节点...`);
    try {
      const result = await api(`/api/servers/${serverId}/deploy`, { method: 'POST' });
      closeProgressModal();
      openResultModal('部署结果', result.restart?.stdout + '\n' + result.status?.listening || '完成');
      await loadAll();
    } catch (error) {
      closeProgressModal();
      toast(error.message, 'error');
      await loadAll();
    }
  });
}

function wireEvents() {
  $$('.nav-item').forEach((item) => {
    item.addEventListener('click', () => {
      $$('.nav-item').forEach((nav) => nav.classList.toggle('active', nav === item));
      $$('.view').forEach((view) => view.classList.toggle('active', view.id === `view-${item.dataset.view}`));
      const titles = {
        overview: ['总览', 'SSH 远程节点管理'],
        servers: ['服务器', 'SSH 连接与远程部署'],
        nodes: ['节点', 'Xray 入站配置'],
        routes: ['路由', '入站与出站链路']
      };
      const [title, subtitle] = titles[item.dataset.view];
      setPage(title, subtitle);
    });
  });

  $('#refresh-btn').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.classList.add('loading');
    button.disabled = true;
    try {
      await loadAll();
    } finally {
      button.classList.remove('loading');
      button.disabled = false;
    }
  });
  const themeButton = $('#theme-toggle');
  if (themeButton) {
    themeButton.addEventListener('click', () => {
      const modes = ['light', 'dark', 'system'];
      const next = modes[(modes.indexOf(currentThemeMode()) + 1) % modes.length];
      localStorage.setItem('theme_preference', next);
      setTheme();
    });
    window.matchMedia?.('(prefers-color-scheme: dark)')?.addEventListener?.('change', () => {
      if (currentThemeMode() === 'system') setTheme();
    });
  }
  setTheme();
  $('#add-server-btn').addEventListener('click', () => openServerModal());
  const autoRepairSwitch = $('#auto-repair-switch');
  if (autoRepairSwitch) {
    autoRepairSwitch.checked = isAutoRepairEnabled();
    autoRepairSwitch.addEventListener('change', () => {
      setAutoRepairEnabled(autoRepairSwitch.checked);
      if (autoRepairSwitch.checked) {
        state.autoRepairNotified = new Set();
        loadStatus();
      }
    });
  }
  $('#add-node-btn').addEventListener('click', () => openNodeModal());
  $('#add-subscription-btn').addEventListener('click', () => openSubscriptionForm());
  $('#overview-go-nodes').addEventListener('click', () => {
    $$('.nav-item[data-view="nodes"]')[0].click();
  });

  $('#server-grid').addEventListener('click', (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    runServerAction(button.dataset.action, button.dataset.id, button);
  });

  $('#node-grid').addEventListener('click', (event) => {
    const deployButton = event.target.closest('[data-deploy-server]');
    if (deployButton) {
      deployServerNodes(deployButton.dataset.deployServer, deployButton);
      return;
    }
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    runNodeAction(button.dataset.action, button.dataset.id, button);
  });

  $('#subscription-grid').addEventListener('click', (event) => {
    const button = event.target.closest('[data-sub-action]');
    if (!button) return;
    runSubscriptionAction(button.dataset.subAction, button.dataset.id, button);
  });

  $('#route-inbound-list').addEventListener('click', (event) => {
    const card = event.target.closest('[data-route-role="inbound"]');
    if (!card) return;
    state.selectedInboundId = state.selectedInboundId === card.dataset.nodeId ? null : card.dataset.nodeId;
    renderRoutes({ motion: false });
  });

  $('#route-outbound-list').addEventListener('click', (event) => {
    const card = event.target.closest('[data-route-role="outbound"]');
    if (!card) return;
    state.selectedOutboundId = state.selectedOutboundId === card.dataset.nodeId ? null : card.dataset.nodeId;
    renderRoutes({ motion: false });
  });

  $('#create-route-btn').addEventListener('click', createSelectedRoute);

  $('#clear-route-selection-btn').addEventListener('click', () => {
    state.selectedInboundId = null;
    state.selectedOutboundId = null;
    renderRoutes({ motion: false });
  });

  $('#route-link-list').addEventListener('click', (event) => {
    const button = event.target.closest('[data-remove-route]');
    if (!button) return;
    removeRoute(button.dataset.removeRoute, button);
  });

  $('#overview-nodes').addEventListener('click', (event) => {
    const row = event.target.closest('[data-node-id]');
    if (!row) return;
    const node = state.nodes.find((item) => item.id === row.dataset.nodeId);
    if (node) openShareModal(node);
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && $('#modal-root').innerHTML) {
      closeModal();
      return;
    }
    const typingTarget = event.target?.matches?.('input, textarea, select') || event.target?.isContentEditable;
    if (typingTarget || event.ctrlKey || event.metaKey || event.altKey) return;
    const key = event.key.toLowerCase();
    if (key === 'r') {
      event.preventDefault();
      loadAll();
    }
    if (key === 't') {
      const server = state.servers.find((item) => item.id === state.selectedServerId) || state.servers[0];
      event.preventDefault();
      if (server) openTerminalModal(server);
    }
  }, true);

  $('#modal-root').addEventListener('click', (event) => {
    if (event.target.classList.contains('modal-backdrop')) closeModal();
  });

  document.addEventListener('click', (event) => {
    const button = event.target.closest('[data-empty-action]');
    if (button) handleEmptyAction(button.dataset.emptyAction);
  });
}

wireEvents();
loadAll();
setInterval(loadStatus, 20000);
