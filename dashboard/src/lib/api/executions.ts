/**
 * Dashboard execution API client.
 *
 * Executions are addressable in their own right (`/v1/executions`), not only
 * through the approval that produced them — an async call may have no approval
 * at all. Reads are gated server-side by `services::execution_access`: the
 * requester, anyone above them in the chain with write access, and org admins.
 * A viewer outside that set still sees the row, with `result_redacted: true`
 * and no body.
 */
import { session } from '$lib/session';
import type { ExecutionDetail, ExecutionListItem } from '$lib/session';

export interface ExecutionQuery {
	/** `mine` (default) or `subtree` — the caller plus their descendants. */
	scope?: 'mine' | 'subtree';
	status?: string;
	origin?: 'approval' | 'async_call';
	limit?: number;
}

const qs = (q: ExecutionQuery): string => {
	const p = new URLSearchParams();
	if (q.scope) p.set('scope', q.scope);
	if (q.status) p.set('status', q.status);
	if (q.origin) p.set('origin', q.origin);
	if (q.limit !== undefined) p.set('limit', String(q.limit));
	const s = p.toString();
	return s ? `?${s}` : '';
};

export const listExecutions = (q: ExecutionQuery = {}, signal?: AbortSignal) =>
	session.get<ExecutionListItem[]>(`/v1/executions${qs(q)}`, signal);

/** Fetching the detail is also what stamps `result_viewed_at` for the requester. */
export const getExecution = (id: string, signal?: AbortSignal) =>
	session.get<ExecutionDetail>(`/v1/executions/${encodeURIComponent(id)}`, signal);

/**
 * Cooperative cancel. A `pending` execution is cancelled outright; an
 * `executing` one stops being waited on, but its upstream request has already
 * been sent and cannot be recalled. 409 once the row is terminal.
 */
export const cancelExecution = (id: string) =>
	session.post<ExecutionDetail>(`/v1/executions/${encodeURIComponent(id)}/cancel`, {});
