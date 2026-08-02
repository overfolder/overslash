/**
 * Single-approval controller.
 *
 * A port of `dashboard/src/lib/approvals/resolution.svelte.ts`, which is the
 * proven implementation and was only unreachable because it is written in
 * Svelte runes. The behaviour it encodes is not incidental: `/resolve allow`
 * returns as soon as the verdict is recorded while the replay runs in a spawned
 * task, so the execution reaching a terminal state *has* to arrive out of band.
 * Stream first, bounded poll as the fallback.
 */

import type { OverslashClient } from '../client.js';
import type {
  ApprovalResponse,
  ExecutionSummary,
  ResolveApprovalRequest,
} from '../types/approvals.js';
import type { PendingApproval } from '../types/actions.js';
import { pickApiError } from '../errors.js';
import { createStore, type Store } from './store.js';
import { PollScheduler } from './poll.js';
import type { EventsTransport } from './events.js';
import type { ApprovalEventData } from '../types/events.js';

/** Execution states past which nothing more will happen. */
const TERMINAL = new Set(['executed', 'failed', 'cancelled', 'expired']);

/**
 * A hand-up changes who may act, which is what the controls are bound to, so it
 * needs a refetch as much as a verdict does.
 */
const WATCHED_EVENTS = [
  'approval.resolved',
  'approval.executed',
  'approval.execution_failed',
  'approval.execution_cancelled',
  'approval.bubbled',
  'stream.resync',
] as const;

export interface ApprovalState {
  approval: ApprovalResponse | null;
  loading: boolean;
  submitting: boolean;
  error: string | null;
  isPending: boolean;
  execution: ExecutionSummary | null;
  executionPending: boolean;
  executionRunning: boolean;
  executionTerminal: boolean;
}

export interface ApprovalControllerOptions {
  /** Seed with an approval you already have, to render without a round trip. */
  approval?: ApprovalResponse;
  /** Or fetch it by id. */
  id?: string;
  events?: EventsTransport;
  onResolved?: (approval: ApprovalResponse) => void;
  /** How long to keep polling for a non-terminal execution. */
  executionPollDeadlineMs?: number;
  pollIntervalMs?: number;
}

export interface ApprovalController extends Store<ApprovalState> {
  refresh(): Promise<void>;
  resolve(body: ResolveApprovalRequest): Promise<ApprovalResponse | null>;
  triggerCall(): Promise<ApprovalResponse | null>;
  cancelExecution(): Promise<ApprovalResponse | null>;
  clearError(): void;
}

export function createApprovalController(
  client: OverslashClient,
  options: ApprovalControllerOptions,
): ApprovalController {
  const id: string | undefined = options.approval?.id ?? options.id;
  if (id === undefined) {
    throw new Error('createApprovalController: pass either `approval` or `id`');
  }
  const approvalId: string = id;

  const store = createStore<ApprovalState>({
    ...derive(options.approval ?? null),
    loading: !options.approval,
    submitting: false,
    error: null,
  });

  const setApproval = (approval: ApprovalResponse) => {
    // Ignore a response for an approval we have since moved off.
    if (approval.id !== approvalId) return;
    store.set({ ...derive(approval), loading: false });
  };

  async function refresh(): Promise<void> {
    // Skip while a user action is in flight: its response is more authoritative
    // than a poll started before it.
    if (store.getState().submitting) return;
    try {
      setApproval(await client.approvals.get(approvalId));
    } catch {
      // Transient. Do not stomp `error`, which belongs to user actions.
    }
  }

  const poller = new PollScheduler(refresh, {
    intervalMs: options.pollIntervalMs ?? 1500,
    deadlineMs: options.executionPollDeadlineMs ?? 30_000,
    // Polling on top of a working stream is duplicate requests. Keeping the
    // timer armed but skipped is what makes the fallback instant when the
    // stream dies.
    shouldSkip: () => options.events?.live ?? false,
  });

  function syncPolling(): void {
    const s = store.getState();
    const needed = !s.isPending && !!s.execution && !s.executionTerminal;
    if (needed && !poller.running) poller.start();
    if (!needed && poller.running) poller.stop();
  }

  const unsubscribeStore = store.subscribe(syncPolling);
  // The subscription only fires on a *change*, so a controller seeded with an
  // approval that is already mid-execution would otherwise never start its
  // fallback poll — it would wait for a state change that only the poll it
  // never started could produce.
  syncPolling();

  const unsubscribeEvents = options.events?.subscribe<ApprovalEventData>(
    WATCHED_EVENTS,
    (event) => {
      // `stream.resync` names no approval — it means "you may have missed
      // events", so it always warrants a refetch.
      if (event.type !== 'stream.resync' && event.data?.approval_id !== approvalId) return;
      void refresh();
    },
  );

  async function mutate(
    run: () => Promise<ApprovalResponse>,
  ): Promise<ApprovalResponse | null> {
    store.set({ submitting: true, error: null });
    try {
      const updated = await run();
      // Optimistic adoption: the server's response is authoritative and lands
      // before any event could.
      store.set({ ...derive(updated), submitting: false });
      options.onResolved?.(updated);
      return updated;
    } catch (e) {
      store.set({ submitting: false, error: pickApiError(e, 'Network error') });
      return null;
    }
  }

  if (!options.approval) void refresh();

  return {
    getState: store.getState,
    subscribe: store.subscribe,
    dispose() {
      poller.stop();
      unsubscribeStore();
      unsubscribeEvents?.();
      store.markDisposed();
    },
    refresh,
    resolve: (body) => mutate(() => client.approvals.resolve(approvalId, body)),
    triggerCall: () => mutate(() => client.approvals.call(approvalId)),
    cancelExecution: () => mutate(() => client.approvals.cancel(approvalId)),
    clearError: () => store.set({ error: null }),
  };
}

function derive(approval: ApprovalResponse | null): Omit<
  ApprovalState,
  'loading' | 'submitting' | 'error'
> {
  const execution = approval?.execution ?? null;
  return {
    approval,
    isPending: approval?.status === 'pending',
    execution,
    executionPending: execution?.status === 'pending',
    executionRunning: execution?.status === 'executing',
    executionTerminal: !!execution && TERMINAL.has(execution.status),
  };
}

/**
 * Adapt a `pending_approval` call result into a renderable approval.
 *
 * This is the point of returning that arm as a value: the tool call that
 * triggered the approval already carries what the card draws, so a host can
 * render immediately and let `refresh()` fill in the rest.
 *
 * Fields the call result does not carry (`derived_keys`, `identity_path`, the
 * resolver) are left empty rather than guessed — a card should show what it
 * knows, not a plausible fiction.
 */
export function fromPendingCall(pending: PendingApproval): ApprovalResponse {
  return {
    id: pending.approval_id,
    identity_id: '',
    requesting_identity_id: '',
    current_resolver_identity_id: '',
    identity_path: null,
    identity_path_ids: [],
    action_summary: pending.action_description,
    tags: [],
    permission_keys: pending.permission_keys,
    derived_keys: [],
    suggested_tiers: pending.suggested_tiers,
    action_detail: pending.action_detail ?? null,
    action_detail_truncated: pending.action_detail_truncated,
    action_detail_size_bytes: pending.action_detail_size_bytes,
    ...(pending.disclosed_fields ? { disclosed_fields: pending.disclosed_fields } : {}),
    status: 'pending',
    token: '',
    expires_at: pending.expires_at,
    created_at: new Date().toISOString(),
    risk: pending.risk,
    relationship: pending.relationship,
  };
}
