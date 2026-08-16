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
  return sshExec(server, 'sh -s', { ...options, stdin: script });
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
