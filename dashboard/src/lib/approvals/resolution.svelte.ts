import { session, type ApprovalResponse, type ResolveApprovalRequest } from '$lib/session';
import { pickApiError } from '$lib/approvals/format';
import {
	EXECUTION_EVENT_TYPES,
	type ApprovalEventData,
	eventStream,
	onEvent
} from '$lib/stores/events.svelte';

/** The `executions` topic payload. Carries `approval_id` for a gated call. */
interface ExecutionEventData {
	execution_id: string;
	status: string;
	approval_id?: string;
}

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
	 * This replay belongs to the async worker. `pending` then means "queued",
	 * not "waiting for someone to press Call" — so the surfaces must not offer a
	 * trigger, and the wait can legitimately run for minutes.
	 */
	const executionQueued = $derived(execution?.queued === true);
	/** The gated call asked for `execution: "async"` — true before it is approved. */
	const willRunInBackground = $derived(current.execution_mode === 'async');

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
		onEvent<ApprovalEventData>(
			[
				'approval.resolved',
				'approval.executed',
				'approval.execution_failed',
				'approval.execution_cancelled',
				// A hand-up changes who may act, which is what the controls
				// are bound to — so it needs a refetch as much as a verdict.
				'approval.bubbled'
			],
			(event) => {
				if (event.data?.approval_id !== current.id) return;
				void refetch(current.id);
			}
		)
	);

	// A queued replay finishes on the worker, which announces itself on the
	// `executions` topic — the approval events above only cover replays that ran
	// on a request. Without this subscription a backgrounded call shows "Queued"
	// until the page is reloaded.
	$effect(() =>
		onEvent<ExecutionEventData>(EXECUTION_EVENT_TYPES, (event) => {
			if (event.data?.approval_id !== current.id) return;
			void refetch(current.id);
		})
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
		// An inline auto-call is bounded by the request cap, so 30s covers it. A
		// queued one is bounded by the async ceiling instead and may legitimately
		// run for minutes — capping it at 30s would strand the page on "Running"
		// for every job that outlives the window.
		const window = executionQueued ? 15 * 60_000 : 30_000;
		if (Date.now() - startedAt > window) return;
		const handle = setInterval(() => {
			// The stream already delivers these transitions; polling on top of it
			// would just be duplicate requests.
			if (eventStream.live) return;
			if (Date.now() - startedAt > window) {
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
		get executionQueued() {
			return executionQueued;
		},
		get willRunInBackground() {
			return willRunInBackground;
		},
		resolve,
		triggerCall,
		cancelExecution,
		clearError,
		applyServerUpdate
	};
}

export type ResolutionController = ReturnType<typeof createResolution>;
