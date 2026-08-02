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
 * Whether we built the current context's stream, and so own closing it.
 *
 * A caller-supplied context belongs to the caller — they may still hold it and
 * use it elsewhere — so replacing the global must not close it out from under
 * them. One we built is unreachable once replaced, and closing it is the only
 * thing that can.
 */
let ownsEvents = false;

/**
 * Set the page-wide default.
 *
 * Also builds the shared `SseEvents`, which matters: one connection for the
 * page rather than one per element, against a per-identity cap of four.
 *
 * Calling this again — a credential refresh, a hot reload — replaces the
 * previous context. Any stream this module built for it is closed first: a
 * leaked one keeps its socket and its reconnect timers alive forever, and four
 * such leaks exhaust the cap without a single element being on screen.
 */
export function configureOverslash(
  options: OverslashClientOptions | OverslashContext,
): OverslashContext {
  closeOwnedEvents();

  if ('client' in options && 'events' in options) {
    globalContext = options;
    ownsEvents = false;
    notifyContextChanged();
    return globalContext;
  }
  const client = new OverslashClient(options as OverslashClientOptions);
  globalContext = { client, events: new SseEvents(client) };
  ownsEvents = true;
  notifyContextChanged();
  return globalContext;
}

export function getGlobalContext(): OverslashContext | null {
  return globalContext;
}

/**
 * Elements that want to know when a context appears.
 *
 * An element resolves its context when it connects, but a host almost always
 * assigns one *after* mount — a React `ref` effect, a Svelte `bind:this`, a
 * `<script>` at the end of the body. Without this, everything that connected
 * first is stuck on the "nothing configured" placeholder forever, which is
 * exactly what a real page does.
 */
const contextListeners = new Set<() => void>();

export function onContextChanged(listener: () => void): () => void {
  contextListeners.add(listener);
  return () => contextListeners.delete(listener);
}

/** Tell every live element to re-resolve. Called when a context is set. */
export function notifyContextChanged(): void {
  for (const listener of [...contextListeners]) {
    try {
      listener();
    } catch (e) {
      if (typeof console !== 'undefined' && console.error) console.error('[overslash-sdk]', e);
    }
  }
}

/**
 * Drop the page-wide default, closing the stream if it is ours. Used by tests
 * and hot reload; a caller-supplied context is left for its owner to close.
 */
export function resetOverslash(): void {
  closeOwnedEvents();
  globalContext = null;
}

function closeOwnedEvents(): void {
  if (ownsEvents) globalContext?.events.close();
  ownsEvents = false;
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
