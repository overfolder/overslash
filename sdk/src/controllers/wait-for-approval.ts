/**
 * Block until an approval settles.
 *
 * This exists because of a real constraint in the single-agent case: an agent
 * run loop with no pause/resume must block inside the tool's `execute()` or the
 * approval never happens. Waiting on the stream is the difference between a
 * tool that resumes in two seconds and one that waits out a poll interval.
 */

import type { OverslashClient } from '../client.js';
import type { ApprovalResponse } from '../types/approvals.js';
import type { ApprovalEventData } from '../types/events.js';
import { WaitTimeoutError } from '../errors.js';
import type { EventsTransport } from './events.js';

const TERMINAL_EXECUTION = new Set(['executed', 'failed', 'cancelled', 'expired']);

export interface WaitForApprovalOptions {
  /**
   * `execution-terminal` (the default) waits for the replayed call to finish,
   * which is what a tool needs before it can return a result.
   * `resolved` returns as soon as a human decides, which is what a UI needs.
   */
  until?: 'resolved' | 'execution-terminal';
  timeoutMs?: number;
  pollIntervalMs?: number;
  events?: EventsTransport;
  signal?: AbortSignal;
}

export async function waitForApproval(
  client: OverslashClient,
  approvalId: string,
  options: WaitForApprovalOptions = {},
): Promise<ApprovalResponse> {
  const until = options.until ?? 'execution-terminal';
  const timeoutMs = options.timeoutMs ?? 300_000;
  const pollIntervalMs = options.pollIntervalMs ?? 1500;
  const deadline = Date.now() + timeoutMs;

  const settled = (a: ApprovalResponse): boolean => {
    if (a.status === 'pending') return false;
    if (until === 'resolved') return true;
    // Denied or bubbled approvals never produce an execution, so waiting for
    // one would hang until the deadline.
    if (a.status !== 'allowed') return true;
    // `auto_call_on_approve` off means nobody will replay it for us.
    if (!a.execution) return false;
    return TERMINAL_EXECUTION.has(a.execution.status);
  };

  const first = await client.approvals.get(approvalId, wrapSignal(options.signal));
  if (settled(first)) return first;

  // Wake on any event naming this approval, and fall back to polling. Both
  // paths refetch — the payload is a routing hint, not state.
  let wake: (() => void) | null = null;
  const unsubscribe = options.events?.subscribe<ApprovalEventData>(
    [
      'approval.resolved',
      'approval.executed',
      'approval.execution_failed',
      'approval.execution_cancelled',
      'stream.resync',
    ],
    (event) => {
      if (event.type !== 'stream.resync' && event.data?.approval_id !== approvalId) return;
      wake?.();
    },
  );

  try {
    for (;;) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new WaitTimeoutError(approvalId, timeoutMs);

      await sleep(Math.min(pollIntervalMs, remaining), (resolve) => {
        wake = resolve;
      }, options.signal);
      wake = null;

      const current = await client.approvals.get(approvalId, wrapSignal(options.signal));
      if (settled(current)) return current;
    }
  } finally {
    unsubscribe?.();
  }
}

/** Sleep, but return early when woken or aborted. */
function sleep(
  ms: number,
  register: (resolve: () => void) => void,
  signal?: AbortSignal,
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    // `addEventListener('abort')` never fires on a signal that has already
    // aborted, so without this the sleep runs its full interval and the caller
    // is cancelled a poll-tick late — or a whole tick after aborting mid-loop.
    if (signal?.aborted) {
      reject(abortError());
      return;
    }

    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      resolve();
    };
    const onAbort = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      reject(abortError());
    };
    const timer = setTimeout(finish, ms);
    register(finish);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function abortError(): Error {
  const e = new Error('waitForApproval aborted');
  // Matches what `fetch` rejects with, so a caller can branch on one name
  // whether the abort landed on a request or between polls.
  e.name = 'AbortError';
  return e;
}

function wrapSignal(signal?: AbortSignal): { signal?: AbortSignal } {
  return signal ? { signal } : {};
}
