/**
 * How an element finds its client.
 *
 * Three ways, most specific winning: the `client` property, an
 * `<overslash-provider>` ancestor, or a module-global default. The property
 * covers a React `ref`, the provider covers a subtree, and the global covers a
 * page that just wants it to work.
 */

import { OverslashClient, type OverslashClientOptions } from '../client.js';
import { SseEvents, type EventsTransport } from '../controllers/events.js';

export interface OverslashContext {
  client: OverslashClient;
  events: EventsTransport;
}

let globalContext: OverslashContext | null = null;

/**
 * Set the page-wide default.
 *
 * Also builds the shared `SseEvents`, which matters: one connection for the
 * page rather than one per element, against a per-identity cap of four.
 */
export function configureOverslash(
  options: OverslashClientOptions | OverslashContext,
): OverslashContext {
  if ('client' in options && 'events' in options) {
    globalContext = options;
    return globalContext;
  }
  const client = new OverslashClient(options as OverslashClientOptions);
  globalContext = { client, events: new SseEvents(client) };
  return globalContext;
}

export function getGlobalContext(): OverslashContext | null {
  return globalContext;
}

/** Tear down the global context's stream. Mostly for tests and hot reload. */
export function resetOverslash(): void {
  globalContext?.events.close();
  globalContext = null;
}

/**
 * The event an element fires to ask its ancestors for a context.
 *
 * Composed, so it crosses shadow boundaries — a provider in one shadow root can
 * answer a card in another. The listener assigns to `detail.context`; there is
 * no reply event, because the whole exchange is synchronous.
 */
export const CONTEXT_REQUEST = 'overslash:context-request';

export interface ContextRequestDetail {
  context: OverslashContext | null;
}

/**
 * Resolve a context for an element, in precedence order.
 *
 * Returns null when nothing is configured, which is a legitimate state: an
 * element can be in the DOM before its host has credentials. It renders a quiet
 * placeholder rather than an error.
 */
export function resolveContext(
  el: HTMLElement,
  own: OverslashContext | null,
): OverslashContext | null {
  if (own) return own;

  const detail: ContextRequestDetail = { context: null };
  el.dispatchEvent(
    new CustomEvent<ContextRequestDetail>(CONTEXT_REQUEST, {
      detail,
      bubbles: true,
      composed: true,
    }),
  );
  if (detail.context) return detail.context;

  return globalContext;
}
