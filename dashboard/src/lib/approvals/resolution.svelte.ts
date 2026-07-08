import {
	session,
	ApiError,
	type ApprovalResponse,
	type ResolveApprovalRequest
} from '$lib/session';

/**
 * Shared resolution controller for approvals.
 *
 * Owns the async + lifecycle machinery so the surfaces that resolve a single
 * approval — the full-page `ApprovalDetail` and the compact `ApprovalResolver`
 * embedded in the agents tree — run the *same* proven implementation:
 * optimistic `override`, the 30s auto-call poll
 * (a `/resolve allow` returns immediately while the auto-call runs in a spawned
 * task, so we poll `/v1/approvals/{id}` to catch the execution reaching a
 * terminal state), and consistent error extraction.
 *
 * Must be called during component setup — it registers a `$effect` for polling.
 */
export function createResolution(
	getApproval: () => ApprovalResponse,
	onResolved?: (a: ApprovalResponse) => void
) {
	let override = $state<ApprovalResponse | null>(null);
	let submitting = $state(false);
	let error = $state<string | null>(null);

	const current = $derived(override ?? getApproval());

	const isPending = $derived(current.status === 'pending');
	const execution = $derived(current.execution ?? null);
	const executionPending = $derived(execution?.status === 'pending');
	const executionRunning = $derived(execution?.status === 'executing');
	const executionTerminal = $derived(
		!!execution &&
			(execution.status === 'executed' ||
				execution.status === 'failed' ||
				execution.status === 'cancelled' ||
				execution.status === 'expired')
	);

	// `pollStartedAt` is anchored outside the reactive scope so the cap is a
	// wall-clock window from when polling first became active, not from the
	// latest poll response.
	let pollStartedAt: number | null = null;
	let pollApprovalId: string | null = null;
	$effect(() => {
		const id = current.id;
		if (isPending || !execution || executionTerminal) {
			pollStartedAt = null;
			pollApprovalId = null;
			return;
		}
		if (pollApprovalId !== id) {
			pollApprovalId = id;
			pollStartedAt = Date.now();
		}
		const startedAt = pollStartedAt!;
		if (Date.now() - startedAt > 30_000) return;
		const handle = setInterval(async () => {
			if (submitting) return;
			if (Date.now() - startedAt > 30_000) {
				clearInterval(handle);
				return;
			}
			try {
				const fresh = await session.get<ApprovalResponse>(`/v1/approvals/${id}`);
				if (id !== current.id) return;
				override = fresh;
			} catch {
				// transient — keep polling; don't stomp `error` (user-action only)
			}
		}, 1500);
		return () => clearInterval(handle);
	});

	function pickError(e: unknown, status?: number): string {
		if (e instanceof ApiError) {
			const body = e.body as { error?: string } | string;
			if (typeof body === 'object' && body && 'error' in body) {
				return body.error ?? `Error ${e.status}`;
			}
			return typeof body === 'string' ? body : `Error ${e.status}`;
		}
		return status ? `Error ${status}` : 'Network error';
	}

	async function resolve(body: ResolveApprovalRequest) {
		submitting = true;
		error = null;
		try {
			const updated = await session.post<ApprovalResponse>(
				`/v1/approvals/${current.id}/resolve`,
				body
			);
			override = updated;
			onResolved?.(updated);
			return updated;
		} catch (e) {
			error = pickError(e);
			return null;
		} finally {
			submitting = false;
		}
	}

	async function triggerCall() {
		submitting = true;
		error = null;
		try {
			const updated = await session.post<ApprovalResponse>(
				`/v1/approvals/${current.id}/call`,
				{}
			);
			override = updated;
			onResolved?.(updated);
			return updated;
		} catch (e) {
			error = pickError(e);
			return null;
		} finally {
			submitting = false;
		}
	}

	async function cancelExecution() {
		submitting = true;
		error = null;
		try {
			const updated = await session.post<ApprovalResponse>(
				`/v1/approvals/${current.id}/cancel`,
				{}
			);
			override = updated;
			onResolved?.(updated);
			return updated;
		} catch (e) {
			error = pickError(e);
			return null;
		} finally {
			submitting = false;
		}
	}

	/** Imperatively clear a stale error (e.g. when the user edits a form field). */
	function clearError() {
		error = null;
	}

	return {
		get current() {
			return current;
		},
		get submitting() {
			return submitting;
		},
		get error() {
			return error;
		},
		get isPending() {
			return isPending;
		},
		get execution() {
			return execution;
		},
		get executionPending() {
			return executionPending;
		},
		get executionRunning() {
			return executionRunning;
		},
		get executionTerminal() {
			return executionTerminal;
		},
		resolve,
		triggerCall,
		cancelExecution,
		clearError
	};
}

export type ResolutionController = ReturnType<typeof createResolution>;
