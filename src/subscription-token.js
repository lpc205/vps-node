import { createHash, randomBytes } from 'node:crypto';

export function createSubscriptionToken() {
  return randomBytes(32).toString('base64url');
}

export function hashSubscriptionToken(token) {
  return createHash('sha256').update(String(token || ''), 'utf8').digest('hex');
}

export function subscriptionTokenPrefix(token) {
  return String(token || '').slice(0, 8);
}
