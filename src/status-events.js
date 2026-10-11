import { EventEmitter } from 'node:events';

// A process-local event bus. Payloads contain only identifiers: clients fetch
// the normal sanitized /api/status response after notification.
const events = new EventEmitter();
events.setMaxListeners(0);

export function publishStatusChange(serverId) {
  events.emit('status', String(serverId));
}

export function subscribeStatusChanges(listener) {
  events.on('status', listener);
  return () => events.off('status', listener);
}
