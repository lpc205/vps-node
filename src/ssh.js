import { Client } from 'ssh2';
import { decryptText } from './crypto.js';

export function sshConnectOptions(server) {
  const options = {
    host: server.host,
    port: Number(server.port || 22),
    username: server.username,
    readyTimeout: 15000,
    keepaliveInterval: 10000
  };

  if (server.auth_type === 'password') {
    options.password = decryptText(server.password);
  } else {
    options.privateKey = decryptText(server.private_key);
    if (server.passphrase) {
      options.passphrase = decryptText(server.passphrase);
    }
  }

  return options;
}

export function sshExec(server, command, { stdin = null, timeout = 45000 } = {}) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let settled = false;
    let stdout = '';
    let stderr = '';

    const fail = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { conn.end(); } catch { /* ignore */ }
      reject(error);
    };

    const timer = setTimeout(() => {
      fail(new Error(`SSH command timed out after ${timeout}ms`));
    }, timeout);

    conn.on('ready', () => {
      conn.exec(command, (error, stream) => {
        if (error) return fail(error);
        stream
          .on('close', (code) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            conn.end();
            resolve({ code, stdout, stderr });
          })
          .on('data', (chunk) => {
            stdout += chunk.toString();
          });
        stream.stderr.on('data', (chunk) => {
          stderr += chunk.toString();
        });
        if (stdin) {
          stream.stdin.write(stdin);
          stream.stdin.end();
        }
      });
    });

    conn.on('error', fail);

    conn.connect(sshConnectOptions(server));
  });
}

export function runScript(server, script, options = {}) {
  const { reuse, ...settings } = options;
  return reuse ? sshExecPooled(server, 'sh -s', { ...settings, stdin: script }) : sshExec(server, 'sh -s', { ...settings, stdin: script });
}

export function runSudo(server, script, options = {}) {
  if (server.username === 'root') {
    return sshExec(server, 'sh -s', { ...options, stdin: script });
  }
  const sudoPassword = server.sudo_password
    ? decryptText(server.sudo_password)
    : server.auth_type === 'password'
      ? decryptText(server.password)
      : '';
  if (!sudoPassword) {
    return Promise.reject(new Error('sudo password is required for non-root servers'));
  }
  return sshExec(server, 'sudo -S -p "" sh -s', {
    ...options,
    stdin: `${sudoPassword}\n${script}\n`
  });
}

export async function runChecked(runner) {
  const result = await runner;
  if (result.code !== 0) {
    const error = new Error(result.stderr.trim() || result.stdout.trim() || `remote command exited with ${result.code}`);
    error.remote = result;
    throw error;
  }
  return result;
}

const pooledConnections = new Map();
const POOL_IDLE_MS = 90_000;

function dropPooledConnection(key, entry) {
  if (pooledConnections.get(key) !== entry) return;
  pooledConnections.delete(key);
  clearTimeout(entry.idle);
  try { entry.conn.end(); } catch { /* connection already gone */ }
}

// Reuse one SSH transport per managed server while allowing concurrent exec
// channels. This is only used by non-mutating health checks.
function getPooledConnection(server) {
  const key = String(server.id || `${server.host}:${server.port}:${server.username}`);
  const existing = pooledConnections.get(key);
  if (existing) return existing.promise;
  const conn = new Client();
  const entry = { conn, idle: null, promise: null };
  entry.promise = new Promise((resolve, reject) => {
    let ready = false;
    const connectionTimeout = setTimeout(() => {
      if (!ready) {
        dropPooledConnection(key, entry);
        reject(new Error('SSH health connection timed out'));
      }
    }, 6000);
    const onError = (error) => {
      if (!ready) {
        clearTimeout(connectionTimeout);
        reject(error);
      }
      dropPooledConnection(key, entry);
    };
    conn.once('ready', () => {
      ready = true;
      clearTimeout(connectionTimeout);
      resolve({ key, entry });
    });
    conn.on('error', onError);
    conn.on('close', () => onError(new Error('SSH health connection closed')));
    try {
      conn.connect({ ...sshConnectOptions(server), readyTimeout: 5000, keepaliveInterval: 15000 });
    } catch (error) {
      onError(error);
    }
  });
  pooledConnections.set(key, entry);
  return entry.promise;
}

export async function sshExecPooled(server, command, { stdin = null, timeout = 8000 } = {}) {
  const { key, entry } = await getPooledConnection(server);
  clearTimeout(entry.idle);
  const touchIdle = () => {
    clearTimeout(entry.idle);
    entry.idle = setTimeout(() => dropPooledConnection(key, entry), POOL_IDLE_MS);
    entry.idle.unref?.();
  };
  try {
    return await new Promise((resolve, reject) => {
      let done = false;
      let stdout = '';
      let stderr = '';
      const finish = (error, result) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        entry.conn.off('close', onClose);
        if (error) reject(error);
        else resolve(result);
      };
      const onClose = () => finish(new Error('SSH health connection closed'));
      const timer = setTimeout(() => {
        dropPooledConnection(key, entry);
        finish(new Error('SSH health command timed out'));
      }, timeout);
      entry.conn.once('close', onClose);
      entry.conn.exec(command, (error, stream) => {
        if (error) return finish(error);
        stream.on('data', (chunk) => { stdout += chunk.toString(); });
        stream.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
        stream.on('error', (error) => finish(error));
        stream.on('close', (code) => finish(null, { code, stdout, stderr }));
        if (stdin !== null) {
          stream.stdin.end(stdin);
        }
      });
    });
  } finally {
    if (pooledConnections.get(key) === entry) touchIdle();
  }
}
