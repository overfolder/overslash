import { session, type ApprovalResponse, type ResolveApprovalRequest } from '$lib/session';
import { pickApiError } from '$lib/approvals/format';
import { type ApprovalEventData, eventStream, onEvent } from '$lib/stores/events.svelte';

/**
 * Shared resolution controller for approvals.
 *
 * Owns the async + lifecycle machinery so the surfaces that resolve a single
 * approval — the full-page `ApprovalDetail` and the `ApprovalRow` shared by the
 * queue and the agents tree — run the *same* proven implementation:
 * optimistic `override`, live refresh from the event stream with the 30s
 * auto-call poll as fallback (a `/resolve allow` returns immediately while the
 * auto-call runs in a spawned task, so the execution reaching a terminal state
 * has to arrive out-of-band), and consistent error extraction.
 *
 * Must be called during component setup — it registers `$effect`s.
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

	/**
	 * Pull the authoritative approval and adopt it. Shared by the fallback poll
	 * and the stream subscription so both carry the same guards: skip while a
	 * user action is in flight, and drop the response if the caller moved to a
	 * different approval while it was in the air.
	 */
	async function refetch(id: string) {
		if (submitting) return;
		try {
			const fresh = await session.get<ApprovalResponse>(`/v1/approvals/${id}`);
			if (id !== current.id) return;
			override = fresh;
		} catch {
			// transient — don't stomp `error` (user-action only)
		}
	}

	// Stream-driven updates. Events are notifications, so refetch rather than
	// trust the payload — and this catches resolutions made in another tab or by
	// another operator, which polling never did: it only ran while *this* tab was
	// waiting on an execution it had itself just triggered.
	$effect(() =>
		onEvent(
			[
				'approval.resolved',
				'approval.executed',
				'approval.execution_failed',
				'approval.execution_cancelled'
			],
			(event) => {
				const data = event.data as ApprovalEventData;
				if (data?.approval_id !== current.id) return;
				void refetch(current.id);
			}
		)
	);

	// Fallback poll, for when the stream is unavailable.
	//
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
		const handle = setInterval(() => {
			// The stream already delivers these transitions; polling on top of it
			// would just be duplicate requests.
			if (eventStream.live) return;
			if (Date.now() - startedAt > 30_000) {
				clearInterval(handle);
				return;
			}
			void refetch(id);
		}, 1500);
		return () => clearInterval(handle);
	});

	const pickError = (e: unknown) => pickApiError(e, 'Network error');

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

	/**
	 * Adopt an approval the caller fetched itself — used for gap recovery after
	 * the stream reconnects without a cursor. Ignores anything that isn't the
	 * approval currently on screen.
	 */
	function applyServerUpdate(fresh: ApprovalResponse) {
		if (fresh.id === current.id) override = fresh;
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
		clearError,
		applyServerUpdate
	};
}

export type ResolutionController = ReturnType<typeof createResolution>;
