import { WebSocketServer } from 'ws';
import { Client } from 'ssh2';
import { app } from './app.js';
import { getServerRecord } from './db.js';
import { sshConnectOptions } from './ssh.js';

const port = Number(process.env.PORT || 3000);
const server = app.listen(port, '0.0.0.0', () => {
  console.log(`vps-node-console listening on http://0.0.0.0:${port}`);
});

const wss = new WebSocketServer({ server, path: '/ws/terminal' });

function sendJson(ws, payload) {
  if (ws.readyState === 1) {
    ws.send(JSON.stringify(payload));
  }
}

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const serverId = url.searchParams.get('serverId');
  const serverRecord = serverId ? getServerRecord(serverId) : null;
  if (!serverRecord) {
    sendJson(ws, { type: 'error', message: 'server not found' });
    ws.close(1008, 'server not found');
    return;
  }

  const conn = new Client();
  let shellStream = null;
  let closed = false;

  const cleanup = () => {
    if (closed) return;
    closed = true;
    try {
      if (shellStream) shellStream.end();
    } catch { /* ignore */ }
    try { conn.end(); } catch { /* ignore */ }
    if (ws.readyState === 0 || ws.readyState === 1) ws.close();
  };

  ws.on('close', cleanup);
  ws.on('error', cleanup);

  conn.on('ready', () => {
    const cols = Math.max(2, Number(url.searchParams.get('cols')) || 80);
    const rows = Math.max(1, Number(url.searchParams.get('rows')) || 24);
    conn.shell({ term: 'xterm-256color', cols, rows }, (error, stream) => {
      if (error) {
        sendJson(ws, { type: 'error', message: error.message });
        cleanup();
        return;
      }
      shellStream = stream;
      sendJson(ws, { type: 'ready' });
      stream.on('data', (chunk) => {
        if (!closed && ws.readyState === 1) ws.send(chunk);
      });
      stream.on('close', () => {
        if (!closed) {
          sendJson(ws, { type: 'closed', message: 'SSH session closed' });
          cleanup();
        }
      });
      stream.on('error', (error) => {
        if (!closed) {
          sendJson(ws, { type: 'error', message: error.message });
          cleanup();
        }
      });
    });
  });

  conn.on('error', (error) => {
    if (!closed) {
      sendJson(ws, { type: 'error', message: error.message });
      cleanup();
    }
  });

  conn.on('close', () => {
    if (!closed) {
      sendJson(ws, { type: 'closed', message: 'SSH connection closed' });
      cleanup();
    }
  });

  ws.on('message', (raw) => {
    if (closed) return;
    const text = raw.toString();
    if (text.startsWith('{')) {
      try {
        const message = JSON.parse(text);
        if (message.type === 'resize' && shellStream) {
          shellStream.setWindow(
            Math.max(1, Number(message.rows) || 24),
            Math.max(2, Number(message.cols) || 80),
            0,
            0
          );
          return;
        }
      } catch { /* not a protocol message */ }
    }
    if (shellStream && shellStream.writable) shellStream.write(text);
  });

  try {
    conn.connect(sshConnectOptions(serverRecord));
  } catch (error) {
    sendJson(ws, { type: 'error', message: error.message });
    cleanup();
  }
});
