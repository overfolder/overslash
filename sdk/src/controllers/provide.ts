/**
 * The public secret-provide state machine.
 *
 * Ported from `dashboard/src/routes/secrets/provide/[req_id]/+page.ts`. The
 * error codes it maps are stable and neutral by design — `410` for both expired
 * and already-fulfilled, `400` for a bad token — and every consumer would
 * otherwise re-derive the same mapping from HTTP statuses.
 */

import type { OverslashClient } from '../client.js';
import { ApiError } from '../errors.js';
import type { ProvideMetadata } from '../types/secrets.js';
import { createStore, type Store } from './store.js';

export type ProvideStatus =
  | 'loading'
  | 'ready'
  | 'expired'
  | 'already_fulfilled'
  | 'invalid'
  | 'missing_token'
  | 'server_error'
  | 'submitting'
  | 'submitted';

export interface ProvideState {
  status: ProvideStatus;
  metadata: ProvideMetadata | null;
  /** Set on a failed submit; the form stays usable so the user can retry. */
  error: string | null;
  /**
   * True when the org required a signed provide and no session is present. The
   * value cannot be submitted until the visitor signs in.
   */
  needsSignIn: boolean;
}

export interface ProvideControllerOptions {
  reqId: string;
  token?: string;
}

export interface ProvideController extends Store<ProvideState> {
  load(): Promise<void>;
  submit(value: string): Promise<boolean>;
}

export function createProvideController(
  client: OverslashClient,
  options: ProvideControllerOptions,
): ProvideController {
  const store = createStore<ProvideState>({
    status: options.token ? 'loading' : 'missing_token',
    metadata: null,
    error: null,
    needsSignIn: false,
  });

  let aborter: AbortController | null = null;

  async function load(): Promise<void> {
    if (!options.token) {
      store.set({ status: 'missing_token' });
      return;
    }
    aborter?.abort();
    aborter = new AbortController();
    store.set({ status: 'loading', error: null });

    try {
      const metadata = await client.secretRequests.getProvide(options.reqId, options.token, {
        signal: aborter.signal,
      });
      store.set({
        status: 'ready',
        metadata,
        needsSignIn: metadata.require_user_session && metadata.viewer === null,
      });
    } catch (e) {
      if (aborter.signal.aborted) return;
      store.set({ status: mapLoadError(e) });
    }
  }

  async function submit(value: string): Promise<boolean> {
    if (!options.token) {
      store.set({ status: 'missing_token' });
      return false;
    }
    if (!value) {
      store.set({ error: 'Enter a value.' });
      return false;
    }

    store.set({ status: 'submitting', error: null });
    try {
      await client.secretRequests.submitProvide(options.reqId, options.token, value);
      store.set({ status: 'submitted', error: null });
      return true;
    } catch (e) {
      const terminal = mapSubmitError(e);
      if (terminal) {
        // Someone else filled it, or the window closed. The form is over.
        store.set({ status: terminal });
      } else {
        store.set({ status: 'ready', error: submitMessage(e) });
      }
      return false;
    }
  }

  void load();

  return {
    getState: store.getState,
    subscribe: store.subscribe,
    dispose() {
      aborter?.abort();
      store.markDisposed();
    },
    load,
    submit,
  };
}

function mapLoadError(e: unknown): ProvideStatus {
  if (!(e instanceof ApiError)) return 'server_error';
  if (e.status === 410) {
    return e.code === 'already_fulfilled' ? 'already_fulfilled' : 'expired';
  }
  if (e.status === 400) return 'invalid';
  if (e.status === 404) return 'invalid';
  if (e.status >= 500) return 'server_error';
  return 'invalid';
}

/** Terminal submit failures. Anything else leaves the form usable. */
function mapSubmitError(e: unknown): ProvideStatus | null {
  if (!(e instanceof ApiError)) return null;
  if (e.status === 410) {
    return e.code === 'already_fulfilled' ? 'already_fulfilled' : 'expired';
  }
  return null;
}

function submitMessage(e: unknown): string {
  if (e instanceof ApiError && e.status === 401 && e.code === 'user_session_required') {
    return 'This request must be completed while signed in.';
  }
  if (e instanceof ApiError) {
    return e.code ?? `Could not save the value (${e.status})`;
  }
  return 'Could not save the value.';
}
