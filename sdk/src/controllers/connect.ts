/**
 * OAuth connect.
 *
 * Ported from `dashboard/src/lib/oauth-connect.ts`. The popup opens the
 * Overslash-gated `/connect-authorize` URL, never a raw provider authorize URL,
 * so a forwarded link cannot connect someone else's account.
 *
 * Completion arrives over the stream (`connection.created` / `updated`) when
 * one is available, with the list poll retained as the fallback — the popup is
 * cross-origin, so there is no message to listen for, and the gateway's own
 * `return_url` is subject to an operator allow-list the SDK cannot assume.
 */

import type { OverslashClient } from '../client.js';
import type { ConnectionSummary, InitiateConnectionRequest } from '../types/connections.js';
import { AuthActionError, PopupBlockedError, pickApiError } from '../errors.js';
import { createStore, type Store } from './store.js';
import { PollScheduler } from './poll.js';
import type { EventsTransport } from './events.js';

export type ConnectStatus =
  | 'idle'
  | 'starting'
  | 'awaiting_user'
  | 'connected'
  | 'popup_blocked'
  | 'needs_external_auth'
  | 'timed_out'
  | 'error';

export interface ConnectState {
  status: ConnectStatus;
  connection: ConnectionSummary | null;
  /** The gated URL, so a host can offer a link when the popup was blocked. */
  authUrl: string | null;
  error: string | null;
}

export interface ConnectOptions extends InitiateConnectionRequest {
  events?: EventsTransport;
  /** Give up after this long. The user may simply have wandered off. */
  timeoutMs?: number;
  pollIntervalMs?: number;
  /**
   * Called when the org is headless (D21): no gated URL exists, because its end
   * users have no Overslash session. The integration runs its own OAuth dance
   * and re-imports the tokens. Without this, a headless org has no connect path
   * and the controller can only report why.
   */
  onNeedsExternalAuth?: (info: {
    provider?: string;
    requiredScopes?: string[];
    accountEmail?: string;
  }) => void;
  /** Injected in tests. Defaults to `window.open`. */
  openWindow?: (url: string) => { closed: boolean; close(): void } | null;
}

export interface ConnectController extends Store<ConnectState> {
  start(): Promise<ConnectionSummary | null>;
  cancel(): void;
}

export function createConnectController(
  client: OverslashClient,
  options: ConnectOptions,
): ConnectController {
  const { events, timeoutMs, pollIntervalMs, onNeedsExternalAuth, openWindow, ...request } =
    options;

  const store = createStore<ConnectState>({
    status: 'idle',
    connection: null,
    authUrl: null,
    error: null,
  });

  let popup: { closed: boolean; close(): void } | null = null;
  let beforeIds = new Set<string>();
  let deadline = 0;
  let settle: ((c: ConnectionSummary | null) => void) | null = null;

  function finish(status: ConnectStatus, connection: ConnectionSummary | null): void {
    poller.stop();
    unsubscribeEvents?.();
    popup?.close();
    popup = null;
    store.set({ status, connection });
    settle?.(connection);
    settle = null;
  }

  /** Look for a connection that was not there when we started. */
  async function checkForNew(): Promise<void> {
    if (Date.now() > deadline) {
      finish('timed_out', null);
      return;
    }
    // The user closing the popup is not proof of failure — some providers close
    // it themselves on success — so check once more before giving up.
    const popupClosed = popup?.closed ?? false;

    const connections = await client.connections.list();
    const fresh = connections.find(
      (c) => !beforeIds.has(c.id) && c.provider_key === request.provider,
    );
    if (fresh) {
      finish('connected', fresh);
      return;
    }
    if (popupClosed) finish('timed_out', null);
  }

  const poller = new PollScheduler(checkForNew, {
    intervalMs: pollIntervalMs ?? 1500,
    shouldSkip: () => events?.live ?? false,
    // The user is looking at a popup, not this tab. Pausing here would stall
    // the flow exactly when it is progressing.
    pauseWhenHidden: false,
  });

  const unsubscribeEvents = events?.subscribe(
    ['connection.created', 'connection.updated'],
    () => {
      // The payload names a connection id, but the summary the caller wants
      // comes from the list — and the event may be for a connection that
      // predates this flow. Re-check rather than trust it.
      void checkForNew();
    },
  );

  async function start(): Promise<ConnectionSummary | null> {
    store.set({ status: 'starting', error: null, connection: null });

    try {
      beforeIds = new Set((await client.connections.list()).map((c) => c.id));
      const flow = await client.connections.initiate(request);
      store.set({ authUrl: flow.auth_url });

      const opened = (openWindow ?? defaultOpenWindow)(flow.auth_url);
      if (!opened) {
        // Not fatal: the host can render the URL as a link the user clicks,
        // which browsers allow because it is a user gesture.
        store.set({ status: 'popup_blocked', error: new PopupBlockedError().message });
        return null;
      }
      popup = opened;
      deadline = Date.now() + (timeoutMs ?? 90_000);
      store.set({ status: 'awaiting_user' });
      poller.restart();

      return await new Promise<ConnectionSummary | null>((resolve) => {
        settle = resolve;
      });
    } catch (e) {
      if (e instanceof AuthActionError && e.headless) {
        store.set({ status: 'needs_external_auth', error: null });
        onNeedsExternalAuth?.({
          ...(e.provider ? { provider: e.provider } : {}),
          ...(e.requiredScopes ? { requiredScopes: e.requiredScopes } : {}),
          ...(e.accountEmail ? { accountEmail: e.accountEmail } : {}),
        });
        return null;
      }
      store.set({ status: 'error', error: pickApiError(e, 'Could not start the connection') });
      return null;
    }
  }

  return {
    getState: store.getState,
    subscribe: store.subscribe,
    dispose() {
      poller.stop();
      unsubscribeEvents?.();
      popup?.close();
      settle?.(null);
      store.markDisposed();
    },
    start,
    cancel: () => finish('idle', null),
  };
}

function defaultOpenWindow(url: string): { closed: boolean; close(): void } | null {
  if (typeof window === 'undefined' || !window.open) return null;
  return window.open(url, 'oss_oauth', 'width=520,height=680');
}
