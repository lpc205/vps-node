import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { dataDir } from './paths.js';

let secretKey;

function getSecretKey() {
  if (secretKey) return secretKey;
  const keyPath = join(dataDir, '.secret');
  if (!existsSync(keyPath)) {
    secretKey = randomBytes(32);
    writeFileSync(keyPath, secretKey, { mode: 0o600 });
  } else {
    secretKey = readFileSync(keyPath);
  }
  return secretKey;
}

export function encryptText(plain) {
  if (!plain) return '';
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', getSecretKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, encrypted].map((part) => part.toString('base64url')).join('.');
}

export function decryptText(payload) {
  if (!payload) return '';
  const [iv, tag, encrypted] = payload.split('.').map((part) => Buffer.from(part, 'base64url'));
  const decipher = createDecipheriv('aes-256-gcm', getSecretKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

export function newId() {
  return randomUUID();
}
