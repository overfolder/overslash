/**
 * The approval queue.
 *
 * Subscribes `approval.pending` — the derived "is this waiting on me *now*"
 * event — rather than reconstructing that answer from `created` and `bubbled`,
 * which is exactly why D45 added it.
 */

import type { OverslashClient } from '../client.js';
import type { ApprovalResponse, ApprovalScope, ApprovalStatus } from '../types/approvals.js';
import { pickApiError } from '../errors.js';
import { createStore, type Store } from './store.js';
import { PollScheduler } from './poll.js';
import type { EventsTransport } from './events.js';

const WATCHED_EVENTS = [
  'approval.created',
  'approval.pending',
  'approval.bubbled',
  'approval.resolved',
  'approval.executed',
  'approval.execution_failed',
  'approval.execution_cancelled',
  'stream.resync',
] as const;

export interface ApprovalListState {
  approvals: ApprovalResponse[];
  loading: boolean;
  error: string | null;
  lastRefreshedAt: number | null;
}

export interface ApprovalListOptions {
  scope?: ApprovalScope | null;
  status?: ApprovalStatus;
  events?: EventsTransport;
  /** Interval for the fallback poll. Skipped while the stream is live. */
  pollIntervalMs?: number;
  /**
   * Coalesce bursts. An agent that trips three approvals in a row should cost
   * one refetch, not three.
   */
  debounceMs?: number;
}

export interface ApprovalListController extends Store<ApprovalListState> {
  refresh(): Promise<void>;
  setFilters(filters: { scope?: ApprovalScope | null; status?: ApprovalStatus }): void;
  /**
   * Drop a resolved approval and everything its rule cascaded over, without
   * waiting for a refetch. The cascade ids matter: those sibling rows are gone
   * server-side, and leaving them on screen invites a click that 404s.
   */
  dropResolved(approval: ApprovalResponse): void;
}

export function createApprovalListController(
  client: OverslashClient,
  options: ApprovalListOptions = {},
): ApprovalListController {
  let scope: ApprovalScope | null = options.scope === undefined ? 'assigned' : options.scope;
  let status: ApprovalStatus | undefined = options.status;

  const store = createStore<ApprovalListState>({
    approvals: [],
    loading: true,
    error: null,
    lastRefreshedAt: null,
  });

  let debounceTimer: ReturnType<typeof setTimeout> | null = null;
  let inFlight: AbortController | null = null;

  async function refresh(): Promise<void> {
    // Supersede a slower in-flight refresh rather than racing it: two responses
    // could otherwise land out of order and leave the older list on screen.
    inFlight?.abort();
    const controller = new AbortController();
    inFlight = controller;

    try {
      const approvals = await client.approvals.list(
        { scope, ...(status ? { status } : {}) },
        { signal: controller.signal },
      );
      if (controller.signal.aborted) return;
      store.set({ approvals, loading: false, error: null, lastRefreshedAt: Date.now() });
    } catch (e) {
      if (controller.signal.aborted) return;
      store.set({ loading: false, error: pickApiError(e, 'Could not load approvals') });
    } finally {
      if (inFlight === controller) inFlight = null;
    }
  }

  function scheduleRefresh(): void {
    const wait = options.debounceMs ?? 300;
    if (debounceTimer !== null) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      void refresh();
    }, wait);
  }

  const poller = new PollScheduler(refresh, {
    intervalMs: options.pollIntervalMs ?? 15_000,
    shouldSkip: () => options.events?.live ?? false,
  });
  poller.start();

  const unsubscribeEvents = options.events?.subscribe(WATCHED_EVENTS, () => {
    // Any approval event can change this list — one raised by an agent, or
    // resolved by a colleague in another tab, neither of which polling alone
    // surfaced promptly. The payload is not consulted: the list is refetched
    // wholesale, so there is nothing to route on.
    scheduleRefresh();
  });

  void refresh();

  return {
    getState: store.getState,
    subscribe: store.subscribe,
    dispose() {
      poller.stop();
      if (debounceTimer !== null) clearTimeout(debounceTimer);
      inFlight?.abort();
      unsubscribeEvents?.();
      store.markDisposed();
    },
    refresh,
    setFilters(filters) {
      if (filters.scope !== undefined) scope = filters.scope;
      if ('status' in filters) status = filters.status;
      store.set({ loading: true });
      void refresh();
    },
    dropResolved(approval) {
      const gone = new Set<string>([approval.id, ...(approval.cascaded_approval_ids ?? [])]);
      store.set({
        approvals: store.getState().approvals.filter((a) => !gone.has(a.id)),
      });
    },
  };
}
