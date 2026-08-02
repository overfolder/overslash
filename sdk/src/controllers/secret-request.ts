/**
 * Mint a secret request and watch for it being fulfilled.
 *
 * The fulfilment watch is what makes this worth a controller: before D45 added
 * `secret_request.fulfilled`, the agent blocked on a missing credential had no
 * way to learn the value arrived except polling.
 */

import type { OverslashClient } from '../client.js';
import type { CreateSecretRequest, CreateSecretRequestResponse } from '../types/secrets.js';
import type { SecretRequestEventData } from '../types/events.js';
import { ApiError, pickApiError } from '../errors.js';
import { createStore, type Store } from './store.js';
import { PollScheduler } from './poll.js';
import type { EventsTransport } from './events.js';

export interface SecretRequestState {
  status: 'idle' | 'minting' | 'awaiting' | 'fulfilled' | 'expired' | 'error';
  request: CreateSecretRequestResponse | null;
  error: string | null;
}

export interface SecretRequestOptions extends CreateSecretRequest {
  events?: EventsTransport;
  pollIntervalMs?: number;
}

export interface SecretRequestController extends Store<SecretRequestState> {
  /** Mint (or re-mint, after an expiry) the request. */
  create(): Promise<CreateSecretRequestResponse | null>;
}

export function createSecretRequestController(
  client: OverslashClient,
  options: SecretRequestOptions,
): SecretRequestController {
  const { events, pollIntervalMs, ...body } = options;

  const store = createStore<SecretRequestState>({
    status: 'idle',
    request: null,
    error: null,
  });

  /**
   * Fallback watch: the public metadata endpoint starts answering
   * `410 already_fulfilled` once the value lands, which is a perfectly good
   * completion signal and needs no extra permission.
   */
  const poller = new PollScheduler(
    async () => {
      const request = store.getState().request;
      if (!request) return;
      try {
        await client.secretRequests.getProvide(request.id, request.token);
      } catch (e) {
        if (e instanceof ApiError && e.status === 410) {
          store.set({ status: e.code === 'already_fulfilled' ? 'fulfilled' : 'expired' });
          poller.stop();
        }
      }
    },
    {
      intervalMs: pollIntervalMs ?? 3000,
      shouldSkip: () => events?.live ?? false,
    },
  );

  const unsubscribe = events?.subscribe<SecretRequestEventData>(
    ['secret_request.fulfilled'],
    (event) => {
      if (event.data?.request_id !== store.getState().request?.id) return;
      store.set({ status: 'fulfilled' });
      poller.stop();
    },
  );

  async function create(): Promise<CreateSecretRequestResponse | null> {
    store.set({ status: 'minting', error: null });
    try {
      const request = await client.secretRequests.create(body);
      store.set({ status: 'awaiting', request });
      poller.restart();
      return request;
    } catch (e) {
      store.set({ status: 'error', error: pickApiError(e, 'Could not create the request') });
      return null;
    }
  }

  return {
    getState: store.getState,
    subscribe: store.subscribe,
    dispose() {
      poller.stop();
      unsubscribe?.();
      store.markDisposed();
    },
    create,
  };
}
