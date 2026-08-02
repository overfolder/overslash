/**
 * `<overslash-provider>` — holds a client for a subtree.
 *
 * Renders nothing. It exists so a host can scope credentials to part of a page,
 * and so a widget token can be minted lazily from the host's own endpoint
 * rather than being handed to the page as a string.
 */

import { OverslashClient } from '../client.js';
import { SseEvents, type StreamStatus } from '../controllers/events.js';
import {
  CONTEXT_REQUEST,
  notifyContextChanged,
  type ContextRequestDetail,
  type OverslashContext,
} from './context.js';

export class OverslashProvider extends HTMLElement {
  private built: OverslashContext | null = null;
  private assigned: OverslashContext | null = null;
  private statusOff: (() => void) | null = null;

  static get observedAttributes(): string[] {
    return ['base-url', 'token-endpoint', 'api-key', 'as'];
  }

  connectedCallback(): void {
    this.style.display = 'contents';
    this.addEventListener(CONTEXT_REQUEST, this.answer as EventListener);
    this.rebuild();
  }

  disconnectedCallback(): void {
    this.removeEventListener(CONTEXT_REQUEST, this.answer as EventListener);
    this.statusOff?.();
    this.built?.events.close();
    this.built = null;
  }

  attributeChangedCallback(): void {
    if (this.isConnected) this.rebuild();
  }

  /** Assign a fully-built context, bypassing the attributes entirely. */
  set context(value: OverslashContext | null) {
    this.assigned = value;
    this.watchStatus();
    // Descendants resolved their context when they connected, which for a host
    // that assigns this property after mount is before it existed.
    notifyContextChanged();
  }

  get context(): OverslashContext | null {
    return this.assigned ?? this.built;
  }

  /** Current stream state, for a host that renders a "live" indicator. */
  get streamStatus(): StreamStatus {
    return this.context?.events.status ?? 'idle';
  }

  private answer = (event: Event): void => {
    const ctx = this.context;
    if (!ctx) return;
    const detail = (event as CustomEvent<ContextRequestDetail>).detail;
    // First provider up the tree wins; do not overwrite a nearer answer.
    if (detail.context) return;
    detail.context = ctx;
    event.stopPropagation();
  };

  private rebuild(): void {
    this.statusOff?.();
    this.built?.events.close();
    this.built = null;

    const baseUrl = this.getAttribute('base-url') ?? undefined;
    const tokenEndpoint = this.getAttribute('token-endpoint');
    const apiKey = this.getAttribute('api-key');
    const as = this.getAttribute('as') ?? undefined;

    if (apiKey && typeof window !== 'undefined') {
      // An `osk_` key is an org-wide credential. Putting one in an attribute
      // publishes it to every script and every screenshot on the page.
      console.warn(
        '[overslash-sdk] <overslash-provider api-key> puts an org-wide credential in the DOM. ' +
          'Use token-endpoint, or give the element a client built with a transport.',
      );
    }

    let client: OverslashClient | null = null;
    if (tokenEndpoint && baseUrl) {
      client = new OverslashClient({
        baseUrl,
        ...(as ? { as } : {}),
        // A function, not a string: the token is short-lived, and re-minting is
        // the host's job. The SDK re-invokes this when one expires.
        auth: { token: () => fetchToken(tokenEndpoint) },
      });
    } else if (apiKey && baseUrl) {
      client = new OverslashClient({ baseUrl, ...(as ? { as } : {}), auth: { apiKey } });
    }

    if (!client) return;
    this.built = { client, events: new SseEvents(client) };
    this.watchStatus();
    notifyContextChanged();
  }

  private watchStatus(): void {
    this.statusOff?.();
    const ctx = this.context;
    if (!ctx) return;
    this.statusOff = ctx.events.onStatusChange((status) => {
      this.setAttribute('stream-status', status);
      this.dispatchEvent(
        new CustomEvent('stream-status', { detail: { status }, bubbles: true, composed: true }),
      );
    });
  }
}

async function fetchToken(endpoint: string): Promise<string> {
  const res = await fetch(endpoint, { credentials: 'include' });
  if (!res.ok) throw new Error(`token endpoint returned ${res.status}`);
  const body = (await res.json()) as { token?: string };
  if (!body.token) throw new Error('token endpoint returned no `token`');
  return body.token;
}
