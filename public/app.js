const state = {
  servers: [],
  nodes: [],
  routes: [],
  probes: {},
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
  item.className = `toast ${type === 'error' ? 'error' : ''}`;
  item.textContent = message;
  $('#toast-root').appendChild(item);
  setTimeout(() => item.remove(), 4200);
}

function setPage(title, subtitle) {
  $('#page-title').textContent = title;
  $('#page-subtitle').textContent = subtitle;
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

function closeModal() {
  closeTerminalSession();
  $('#modal-root').innerHTML = '';
}

function closeTerminalSession() {
  if (!terminalSession) return;
  try { terminalSession.ws?.close(); } catch { /* ignore */ }
  try { terminalSession.term?.dispose(); } catch { /* ignore */ }
  terminalSession = null;
}

function emptyState(text) {
  return `<div class="empty-state">${escapeHtml(text)}</div>`;
}

function badge(text, tone = '') {
  return `<span class="badge ${tone}">${escapeHtml(text)}</span>`;
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

async function loadAll() {
  try {
    const [servers, nodes, stats, routes] = await Promise.all([
      api('/api/servers'),
      api('/api/nodes'),
      api('/api/stats'),
      api('/api/routes')
    ]);
    state.servers = servers;
    state.nodes = nodes;
    state.stats = stats;
    state.routes = routes;
    if (!state.selectedServerId && servers.length) {
      state.selectedServerId = servers[0].id;
    }
    if (state.selectedServerId && !servers.some((server) => server.id === state.selectedServerId)) {
      state.selectedServerId = servers[0]?.id || null;
    }
    renderAll();
  } catch (error) {
    toast(error.message, 'error');
  }
}

function renderAll() {
  renderOverview();
  renderServers();
  renderNodes();
  renderRoutes();
  refreshIcons();
}

function renderOverview() {
  $('#metric-servers').textContent = state.stats.servers || 0;
  $('#metric-nodes').textContent = state.stats.nodes || 0;
  $('#metric-enabled').textContent = state.stats.enabledNodes || 0;

  const recent = state.nodes.slice(0, 6);
  $('#overview-nodes').innerHTML = recent.length
    ? recent.map((node) => {
        const server = state.servers.find((item) => item.id === node.server_id);
        return `
          <div class="overview-row" data-node-id="${escapeHtml(node.id)}">
            <span class="name">${escapeHtml(node.name)}</span>
            <span class="muted">${escapeHtml(server ? `${server.name} · ${server.host}` : '未知服务器')}</span>
            <span class="muted">${escapeHtml(protocolLabel(node.protocol))} / ${escapeHtml(node.port)}</span>
            ${node.enabled === 1 ? badge('启用', 'green') : badge('停用')}
          </div>
        `;
      }).join('')
    : emptyState('还没有节点，先添加服务器和节点');
}

function renderServers() {
  const grid = $('#server-grid');
  if (!state.servers.length) {
    grid.innerHTML = emptyState('还没有服务器，点击右上角添加');
    return;
  }
  grid.innerHTML = state.servers.map((server) => {
    const probe = state.probes[server.id];
    const nodeCount = state.nodes.filter((node) => node.server_id === server.id).length;
    const statusBadge = probe
      ? probe.xray?.active === 'active'
        ? badge('运行中', 'green')
        : probe.xray?.installed
          ? badge('已安装', 'amber')
          : badge('未安装', 'red')
      : badge('未检测');
    const authLabel = server.auth_type === 'key' ? 'SSH Key' : '密码';
    return `
      <div class="server-card">
        <div class="server-card-head">
          <h3 title="${escapeHtml(server.name)}">${escapeHtml(server.name)}</h3>
          ${statusBadge}
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
        </div>
        <div class="card-actions">
          <button class="btn sm" data-action="terminal" data-id="${escapeHtml(server.id)}"><i data-lucide="terminal"></i>终端</button>
          <button class="btn sm" data-action="logs" data-id="${escapeHtml(server.id)}"><i data-lucide="scroll-text"></i>日志</button>
          <button class="btn sm ghost" data-action="edit" data-id="${escapeHtml(server.id)}"><i data-lucide="pencil"></i>编辑</button>
          <button class="icon-btn" data-action="delete" data-id="${escapeHtml(server.id)}" title="删除" aria-label="删除"><i data-lucide="trash-2"></i></button>
        </div>
      </div>
    `;
  }).join('');
}

function renderNodes() {
  const select = $('#node-server-select');
  select.innerHTML = state.servers.length
    ? state.servers.map((server) => `
        <option value="${escapeHtml(server.id)}" ${server.id === state.selectedServerId ? 'selected' : ''}>
          ${escapeHtml(server.name)} (${escapeHtml(server.host)})
        </option>
      `).join('')
    : '<option value="">暂无服务器</option>';

  $('#add-node-btn').disabled = !state.selectedServerId;
  $('#deploy-server-btn').disabled = !state.selectedServerId;

  const grid = $('#node-grid');
  const nodes = state.nodes.filter((node) => node.server_id === state.selectedServerId);
  if (!state.selectedServerId) {
    grid.innerHTML = emptyState('请先添加并选择服务器');
    return;
  }
  if (!nodes.length) {
    grid.innerHTML = emptyState('该服务器还没有节点，点击添加节点');
    return;
  }
  grid.innerHTML = nodes.map((node) => {
    const security = node.security === 'reality' ? 'Reality' : node.security === 'tls' ? 'TLS' : '无加密';
    const clientCount = node.clients?.length || 0;
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
            ${node.role === 'outbound' ? badge('出站', 'amber') : badge('入站')}
            ${node.enabled === 1 ? badge('启用', 'green') : badge('停用')}
          </div>
        </div>
        <div class="node-body">
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
        </div>
        <div class="card-actions">
          <button class="btn sm" data-action="share" data-id="${escapeHtml(node.id)}"><i data-lucide="share-2"></i>分享</button>
          <button class="btn sm" data-action="edit" data-id="${escapeHtml(node.id)}"><i data-lucide="pencil"></i>编辑</button>
          <button class="btn sm danger" data-action="delete" data-id="${escapeHtml(node.id)}"><i data-lucide="trash-2"></i>删除</button>
        </div>
      </div>
    `;
  }).join('');
}

function openServerModal(server = null) {
  const isEdit = Boolean(server);
  const authType = server?.auth_type || 'password';
  setModal(`
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-head">
          <h2>${isEdit ? '编辑服务器' : '添加服务器'}</h2>
          <button class="icon-btn" data-close><i data-lucide="x"></i></button>
        </div>
        <form id="server-form" class="modal-body">
          <div class="form-grid">
            <div class="field full">
              <label>快速粘贴服务器信息</label>
              <textarea id="server-paste" placeholder="支持：root@1.2.3.4:22 密码；1.2.3.4:22:root:密码；1.2.3.4 22 root 密码"></textarea>
              <div class="paste-actions">
                <button type="button" class="btn ghost sm" id="parse-server-btn"><i data-lucide="wand-2"></i>识别并填充</button>
                <button type="button" class="btn primary sm" id="quick-save-server-btn"><i data-lucide="zap"></i>识别并保存</button>
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
            <div class="field full">
              <label>认证方式</label>
              <div class="segmented">
                <button type="button" data-auth="password" class="${authType === 'password' ? 'active' : ''}">密码</button>
                <button type="button" data-auth="key" class="${authType === 'key' ? 'active' : ''}">SSH Key</button>
              </div>
            </div>
            <div class="field full auth-password" style="${authType === 'key' ? 'display:none' : ''}">
              <label>密码</label>
              <input name="password" type="password" autocomplete="new-password" placeholder="${isEdit ? '留空则保持现有密码' : 'SSH 登录密码'}">
              ${isEdit && server.has_password ? '<span class="hint">已保存密码，留空则保持不变。</span>' : ''}
            </div>
            <div class="field full auth-key" style="${authType === 'password' ? 'display:none' : ''}">
              <label>私钥</label>
              <textarea name="private_key" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
              ${isEdit && server.has_private_key ? '<span class="hint">已保存密钥，留空则保持不变。</span>' : ''}
            </div>
            <div class="field auth-key" style="${authType === 'password' ? 'display:none' : ''}">
              <label>密钥口令</label>
              <input name="passphrase" type="password" autocomplete="new-password" placeholder="可选">
            </div>
            <div class="field">
              <label>sudo 密码</label>
              <input name="sudo_password" type="password" autocomplete="new-password" placeholder="${server?.has_sudo_password ? '留空则保持不变' : '非 root 时填写'}">
            </div>
            <div class="field full">
              <label>备注</label>
              <textarea name="notes" placeholder="机房、用途等">${escapeHtml(server?.notes || '')}</textarea>
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
    try {
      await persistServer(readServerPayload());
      closeModal();
      await loadAll();
      toast(isEdit ? '服务器已更新' : '服务器已添加');
    } catch (error) {
      toast(error.message, 'error');
    }
  });

  $('#server-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      await persistServer(readServerPayload());
      closeModal();
      await loadAll();
      toast(isEdit ? '服务器已更新' : '服务器已添加');
    } catch (error) {
      toast(error.message, 'error');
    }
  });
}

function openNodeModal(serverId, node = null) {
  const isEdit = Boolean(node);
  const clients = node?.clients?.length ? node.clients : [{ email: '', secret: '', flow: '' }];
  const security = node?.security || 'none';
  const network = node?.network || 'tcp';

  setModal(`
    <div class="modal-backdrop">
      <div class="modal wide">
        <div class="modal-head">
          <h2>${isEdit ? '编辑节点' : '添加节点'}</h2>
          <button class="icon-btn" data-close><i data-lucide="x"></i></button>
        </div>
        <form id="node-form" class="modal-body">
          <div class="form-grid">
            <div class="field full">
              <label>名称</label>
              <input name="name" required value="${escapeHtml(node?.name || '')}" placeholder="例如 香港 443">
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
                <button type="button" class="btn ghost" id="random-reality-btn"><i data-lucide="shuffle"></i>随机</button>
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
              <button type="button" class="btn ghost" id="gen-reality-btn"><i data-lucide="key-round"></i>生成 Reality 密钥对</button>
            </div>
            <div class="field full reality-field" style="${security === 'reality' ? '' : 'display:none'}">
              <label>shortIds</label>
              <input name="short_ids" value="${escapeHtml(node?.short_ids || '')}" placeholder="可选，逗号分隔">
            </div>
            <div class="field full">
              <label>SNI / serverName</label>
              <input name="sni" value="${escapeHtml(node?.sni || '')}" placeholder="域名或目标站点">
            </div>
            <div class="field full path-field" style="${network === 'tcp' ? 'display:none' : ''}">
              <label>路径 / serviceName</label>
              <input name="path" value="${escapeHtml(node?.path || '')}" placeholder="例如 /ws 或 grpc">
            </div>
            <div class="field full">
              <label>客户端</label>
              <div id="clients-editor"></div>
              <button type="button" class="btn ghost sm" id="add-client-btn"><i data-lucide="user-plus"></i>添加客户端</button>
            </div>
            <div class="field">
              <label class="hint">启用</label>
              <input type="checkbox" name="enabled" ${node?.enabled === 0 ? '' : 'checked'} style="width:auto;height:20px">
            </div>
          </div>
        </form>
        <div class="modal-foot">
          <button class="btn ghost" data-close>取消</button>
          <button class="btn primary" type="submit" form="node-form" id="save-node-btn"><i data-lucide="save"></i>保存</button>
          <button class="btn accent" type="submit" form="node-form" id="save-deploy-node-btn"><i data-lucide="upload-cloud"></i>保存并部署</button>
        </div>
      </div>
    </div>
  `);

  const initialClients = clients.map((client) => ({ ...client }));
  function clientRowFieldsHtml(client) {
    const socks = $('select[name="protocol"]')?.value === 'socks';
    return `
        <input name="client_email" placeholder="${socks ? '用户名' : '备注'}" value="${escapeHtml(client.email)}">
        <input name="client_secret" placeholder="${socks ? '密码' : 'UUID / 密码'}" value="${escapeHtml(client.secret)}" required>
        <input name="client_flow" placeholder="flow" value="${escapeHtml(client.flow)}" ${socks ? 'style="display:none"' : ''}>
    `;
  }
  function renderClientRows() {
    const rows = $$('#clients-editor .client-row');
    const values = rows.length
      ? rows.map((row) => ({
        email: row.querySelector('[name="client_email"]').value,
        secret: row.querySelector('[name="client_secret"]').value,
        flow: row.querySelector('[name="client_flow"]').value
      }))
      : initialClients;
    $('#clients-editor').innerHTML = values.map((client, index) => `
      <div class="client-row">
        ${clientRowFieldsHtml(client)}
        <button type="button" class="icon-btn" data-remove-client title="移除" aria-label="移除"><i data-lucide="x"></i></button>
      </div>
    `).join('');
    refreshIcons();
  }

  renderClientRows();

  function applyProtocolVisibility(protocol) {
    const socks = protocol === 'socks';
    const networkField = $('select[name="network"]').closest('.field');
    const securityField = $('select[name="security"]').closest('.field');
    const sniField = $('input[name="sni"]').closest('.field');
    if (socks) {
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
      $('.path-field').style.display = 'none';
      $$('.tls-field').forEach((field) => field.style.display = 'none');
      $$('.reality-field').forEach((field) => field.style.display = 'none');
      return;
    }
    networkField.style.display = '';
    securityField.style.display = '';
    sniField.style.display = '';
    $('.path-field').style.display = $('select[name="network"]').value === 'tcp' ? 'none' : '';
    const security = $('select[name="security"]').value;
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

  const realityButton = $('#gen-reality-btn');
  if (realityButton) {
    realityButton.addEventListener('click', async () => {
      if (!serverId) return;
      realityButton.disabled = true;
      realityButton.textContent = '生成中...';
      try {
        const pair = await api(`/api/servers/${serverId}/x25519`, { method: 'POST' });
        $('input[name="private_key"]').value = pair.privateKey;
        $('input[name="public_key"]').value = pair.publicKey;
        toast('Reality 密钥对已生成');
      } catch (error) {
        toast(error.message, 'error');
      } finally {
        realityButton.disabled = false;
        realityButton.innerHTML = '<i data-lucide="key-round"></i>生成 Reality 密钥对';
        refreshIcons();
      }
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
  networkSelect.addEventListener('change', () => applyProtocolVisibility(protocolSelect.value));
  protocolSelect.addEventListener('change', () => {
    applyProtocolVisibility(protocolSelect.value);
    renderClientRows();
  });

  async function saveAndDeploy(deploy) {
    const form = $('#node-form');
    const data = Object.fromEntries(new FormData(form).entries());
    data.role = $('#node-role-segmented button.active').dataset.role;
    data.port = Number(data.port);
    data.enabled = form.querySelector('[name="enabled"]').checked;
    data.clients = $$('#clients-editor .client-row').map((row) => ({
      email: row.querySelector('[name="client_email"]').value,
      secret: row.querySelector('[name="client_secret"]').value,
      flow: row.querySelector('[name="client_flow"]').value
    }));
    data.server_id = serverId;
    try {
      let saved;
      if (isEdit) saved = await api(`/api/nodes/${node.id}`, { method: 'PUT', body: JSON.stringify(data) });
      else saved = await api(`/api/servers/${serverId}/nodes`, { method: 'POST', body: JSON.stringify(data) });
      closeModal();
      await loadAll();
      if (deploy) {
        openProgressModal('保存并部署', '正在部署服务器...');
        try {
          const result = await api(`/api/servers/${serverId}/deploy`, { method: 'POST' });
          closeProgressModal();
          openResultModal('部署结果', result.restart?.stdout + '\n' + result.status?.listening || 'ok');
        } catch (error) {
          closeProgressModal();
          toast(error.message, 'error');
        } finally {
          await loadAll();
        }
      } else {
        toast('节点已保存');
      }
    } catch (error) {
      toast(error.message, 'error');
    }
  }

  $('#save-node-btn').addEventListener('click', (event) => {
    event.preventDefault();
    saveAndDeploy(false);
  });
  $('#save-deploy-node-btn').addEventListener('click', (event) => {
    event.preventDefault();
    saveAndDeploy(true);
  });
}


function routeNodeCard(node, role) {
  const selected = role === 'inbound' ? state.selectedInboundId === node.id : state.selectedOutboundId === node.id;
  const connected = role === 'inbound'
    ? state.routes.some((route) => route.inbound_node_id === node.id)
    : state.routes.some((route) => route.outbound_node_id === node.id);
  const server = state.servers.find((item) => item.id === node.server_id);
  return `
    <div class="route-node ${selected ? 'selected' : ''} ${connected ? 'connected' : ''}" data-route-role="${role}" data-node-id="${escapeHtml(node.id)}">
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

function renderRoutes() {
  const inboundList = $('#route-inbound-list');
  if (!inboundList) return;
  const inboundNodes = state.nodes.filter((node) => node.role === 'inbound');
  const outboundNodes = state.nodes.filter((node) => node.role === 'outbound');
  $('#inbound-count').textContent = inboundNodes.length + ' 个';
  $('#outbound-count').textContent = outboundNodes.length + ' 个';
  inboundList.innerHTML = inboundNodes.length
    ? inboundNodes.map((node) => routeNodeCard(node, 'inbound')).join('')
    : emptyState('还没有入站节点，请先添加');
  $('#route-outbound-list').innerHTML = outboundNodes.length
    ? outboundNodes.map((node) => routeNodeCard(node, 'outbound')).join('')
    : emptyState('还没有出站节点，请先添加');
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
            <button class="btn sm danger" data-remove-route="${escapeHtml(route.id)}"><i data-lucide="trash-2"></i>断开</button>
          </div>
        `;
      }).join('')
    : emptyState('还没有连接，选择入站和出站后点击“连接所选节点”');
  $('#create-route-btn').disabled = !(state.selectedInboundId && state.selectedOutboundId);
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
}

async function removeRoute(routeId) {
  const route = state.routes.find((item) => item.id === routeId);
  const inboundNode = route && (state.nodes.find((node) => node.id === route.inbound_node_id) || route.inbound_node);
  if (!route || !inboundNode?.server_id) return;
  if (!window.confirm('断开这条入站到出站的连接？')) return;
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
          <button class="icon-btn" data-close><i data-lucide="x"></i></button>
        </div>
        <div class="modal-body">
          <div class="share-list">
            ${links.length ? links.map((client, index) => `
              <div class="share-item">
                <div>
                  <div class="hint">${escapeHtml(client.email || `客户端 ${index + 1}`)}</div>
                  <code>${escapeHtml(client.link)}</code>
                </div>
                <button class="btn sm ghost" data-copy="${escapeHtml(client.link)}"><i data-lucide="copy"></i>复制</button>
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
        await navigator.clipboard.writeText(button.dataset.copy);
        toast('已复制');
      } catch {
        toast('复制失败，请手动选择', 'error');
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
          <button class="icon-btn" data-close><i data-lucide="x"></i></button>
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

function openTerminalModal(server) {
  if (!server) return;
  closeTerminalSession();
  setModal(`
    <div class="modal-backdrop">
      <div class="modal terminal-modal">
        <div class="modal-head">
          <h2>${escapeHtml(server.name)} SSH 终端</h2>
          <div class="terminal-head-side">
            <span id="terminal-status" class="terminal-status">连接中...</span>
            <button class="icon-btn" data-close title="关闭" aria-label="关闭"><i data-lucide="x"></i></button>
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

  $$('#modal-root [data-close]').forEach((button) => button.addEventListener('click', closeModal));

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
  term.open($('#terminal-host'));
  fitAddon.fit();
  term.focus();

  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws/terminal?serverId=${encodeURIComponent(server.id)}&cols=${term.cols}&rows=${term.rows}`);
  terminalSession = { ws, term };

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

async function runServerAction(action, serverId, button) {
  if (action === 'terminal') {
    const server = state.servers.find((item) => item.id === serverId);
    openTerminalModal(server);
    return;
  }
  const original = button.innerHTML;
  button.disabled = true;
  button.textContent = '执行中...';
  try {
    if (action === 'logs') {
      const logs = await api(`/api/servers/${serverId}/logs?lines=200`);
      openResultModal('远程日志', logs.stdout || '没有日志', true);
    }
    if (action === 'edit') {
      const server = state.servers.find((item) => item.id === serverId);
      openServerModal(server);
    }
    if (action === 'delete') {
      if (!window.confirm(`删除服务器「${state.servers.find((item) => item.id === serverId)?.name || ''}」？其节点也会一并删除。`)) return;
      await api(`/api/servers/${serverId}`, { method: 'DELETE' });
      toast('服务器已删除');
      await loadAll();
    }
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    button.disabled = false;
    button.innerHTML = original;
    refreshIcons();
  }
}

async function runNodeAction(action, nodeId, button) {
  const node = state.nodes.find((item) => item.id === nodeId);
  if (!node) return;
  if (action === 'share') openShareModal(node);
  if (action === 'edit') openNodeModal(node.server_id, node);
  if (action === 'delete') {
    if (!window.confirm(`删除节点「${node.name}」？`)) return;
    button.disabled = true;
    try {
      await api(`/api/nodes/${nodeId}`, { method: 'DELETE' });
      toast('节点已删除');
      await loadAll();
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      button.disabled = false;
    }
  }
}

function wireEvents() {
  $$('.nav-item').forEach((item) => {
    item.addEventListener('click', () => {
      $$('.nav-item').forEach((nav) => nav.classList.toggle('active', nav === item));
      $$('.view').forEach((view) => view.classList.toggle('active', view.id === `view-${item.dataset.view}`));
      const titles = { overview: ['总览', 'SSH 远程节点管理'], servers: ['服务器', 'SSH 连接与远程部署'], nodes: ['节点', 'Xray 入站配置'], routes: ['路由', '入站与出站链路'] };
      const [title, subtitle] = titles[item.dataset.view];
      setPage(title, subtitle);
    });
  });

  $('#refresh-btn').addEventListener('click', loadAll);
  $('#add-server-btn').addEventListener('click', () => openServerModal());
  $('#add-node-btn').addEventListener('click', () => openNodeModal(state.selectedServerId));
  $('#overview-go-nodes').addEventListener('click', () => {
    $$('.nav-item[data-view="nodes"]')[0].click();
  });

  $('#node-server-select').addEventListener('change', (event) => {
    state.selectedServerId = event.target.value;
    renderNodes();
  });

  $('#deploy-server-btn').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    if (!state.selectedServerId) return;
    button.disabled = true;
    openProgressModal('部署全部节点', '正在连接服务器并部署...');
    try {
      const result = await api(`/api/servers/${state.selectedServerId}/deploy`, { method: 'POST' });
      closeProgressModal();
      openResultModal('部署结果', result.restart?.stdout + '\n' + result.status?.listening || '完成');
      await loadAll();
    } catch (error) {
      closeProgressModal();
      toast(error.message, 'error');
      await loadAll();
    } finally {
      button.disabled = false;
      button.innerHTML = '<i data-lucide="upload-cloud"></i>部署全部节点';
      refreshIcons();
    }
  });

  $('#server-grid').addEventListener('click', (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    runServerAction(button.dataset.action, button.dataset.id, button);
  });

  $('#node-grid').addEventListener('click', (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    runNodeAction(button.dataset.action, button.dataset.id, button);
  });

  $('#route-inbound-list').addEventListener('click', (event) => {
    const card = event.target.closest('[data-route-role="inbound"]');
    if (!card) return;
    state.selectedInboundId = state.selectedInboundId === card.dataset.nodeId ? null : card.dataset.nodeId;
    renderRoutes();
  });

  $('#route-outbound-list').addEventListener('click', (event) => {
    const card = event.target.closest('[data-route-role="outbound"]');
    if (!card) return;
    state.selectedOutboundId = state.selectedOutboundId === card.dataset.nodeId ? null : card.dataset.nodeId;
    renderRoutes();
  });

  $('#create-route-btn').addEventListener('click', createSelectedRoute);

  $('#clear-route-selection-btn').addEventListener('click', () => {
    state.selectedInboundId = null;
    state.selectedOutboundId = null;
    renderRoutes();
  });

  $('#route-link-list').addEventListener('click', (event) => {
    const button = event.target.closest('[data-remove-route]');
    if (!button) return;
    removeRoute(button.dataset.removeRoute);
  });

  $('#overview-nodes').addEventListener('click', (event) => {
    const row = event.target.closest('[data-node-id]');
    if (!row) return;
    const node = state.nodes.find((item) => item.id === row.dataset.nodeId);
    if (node) openShareModal(node);
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && $('#modal-root').innerHTML) closeModal();
  });

  $('#modal-root').addEventListener('click', (event) => {
    if (event.target.classList.contains('modal-backdrop')) closeModal();
  });
}

wireEvents();
loadAll();
