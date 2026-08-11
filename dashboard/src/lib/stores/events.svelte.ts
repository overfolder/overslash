// Live server events, over one SSE connection shared by the whole app.
//
// The server hangs up every 30 seconds by design (SPEC.md §10). Native
// `EventSource` reconnects on its own and replays the `Last-Event-ID` cursor,
// so the routine close is lossless and invisible — do not "fix" it by treating
// every `error` as a fault. The one lossy case is the browser giving up
// entirely (a fatal status, or a network that stays down): the cursor dies with
// the EventSource, so on the next successful open we announce `stream.resync`
// and subscribers refetch instead of trusting their possibly-stale state.
//
// Events are notifications, not state. Handlers should refetch the resource
// they care about; the payloads here are for routing, not for rendering.

export type StreamStatus = 'idle' | 'connecting' | 'live' | 'down';

export const APPROVAL_EVENT_TYPES = [
	'approval.created',
	// Fired after creation and after every hand-up, so it alone answers
	// "is something waiting on me?" without diffing the other two.
	'approval.pending',
	'approval.bubbled',
	'approval.resolved',
	'approval.executed',
	'approval.execution_failed',
	'approval.execution_cancelled'
] as const;

const CONNECTION_EVENT_TYPES = [
	'connection.created',
	'connection.updated',
	'connection.scopes_upgraded',
	'connection.deleted'
] as const;

const SECRET_EVENT_TYPES = ['secret_request.created', 'secret_request.fulfilled'] as const;

/**
 * Async (worker-run) executions. Distinct from the `approval.execution_*`
 * names on purpose: those are keyed on an approval, and an async call may not
 * have one. See DECISIONS D62.
 */
export const EXECUTION_EVENT_TYPES = [
	'execution.completed',
	'execution.failed',
	'execution.cancelled'
] as const;

/**
* Per-call traffic, feeding the Live Map. Only emitted by a build with
 * `OVERSLASH_LIVE_MAP` set (dev), so on every other deployment these names
 * are subscribed but never arrive.
 *
 * The pair is not ordered — the two events bracket the upstream call, so each
 * is emitted by its own task and `.completed` can land first. Consumers pair
 * them by `call_id` and must tolerate either arrival order.
 */
export const ACTIVITY_EVENT_TYPES = ['action.called', 'action.completed'] as const;

/** Every event name the server can put on the wire. */
const WIRE_EVENT_TYPES = [
	...APPROVAL_EVENT_TYPES,
	...CONNECTION_EVENT_TYPES,
	...SECRET_EVENT_TYPES,
	...EXECUTION_EVENT_TYPES,
	...ACTIVITY_EVENT_TYPES
] as const;

/**
 * `stream.resync` is synthesised client-side, never sent by the server. It
 * means "you may have missed events" and is the cue to refetch.
 */
export type StreamEventType = (typeof WIRE_EVENT_TYPES)[number] | 'stream.resync';

/** The SSE `data:` envelope — identical to the webhook envelope. */
export interface StreamEvent<T = Record<string, unknown>> {
	id: string;
	type: string;
	created_at: string;
	data: T;
}

export interface ApprovalEventData {
	approval_id: string;
	execution?: { id: string; status: string };
	cascaded_approval_ids?: string[];
}

// `connections` and `secrets` stay unsubscribed: nothing in the dashboard
// reacts to them yet, and a narrower subscription means less work per event on
// both sides. Widening is a one-line change.
//
// This filter is explicit, so a new server-side topic is invisible here until
// it is named — omitting `executions` would leave /executions silently dead
// rather than merely stale.
//
// `activity` is subscribed unconditionally rather than only when the Live Map
// is enabled. This connection opens at layout mount, long before
// `/v1/version` says whether the build emits `action.*` at all, and a build
// with the flag off emits nothing — so gating here would buy no traffic
// reduction and cost a reconnect.
const STREAM_URL = '/v1/events/stream?topics=approvals,activity,executions';

/**
 * How long to tolerate a reconnect before admitting the stream is down. The
 * server closes every 30s and the browser reconnects immediately, so a brief
 * `CONNECTING` gap is the normal case — flipping the indicator to "down" on it
 * would make the UI flicker twice a minute.
 */
const RECONNECT_GRACE_MS = 8_000;

const BACKOFF_START_MS = 1_000;
const BACKOFF_MAX_MS = 30_000;

interface Subscription {
	types: ReadonlySet<string>;
	handler: (event: StreamEvent<never>) => void;
}

let source: EventSource | null = null;
// Connection status is held twice on purpose. `status` is a plain variable and
// is what every branch in this module reads; `uiStatus` is the rune the UI
// binds to, and is only ever written. Reading a rune here would be a trap:
// `startEventStream`/`stopEventStream` are called from an `$effect` in the
// root layout, so a synchronous rune *read* inside them would make that effect
// depend on state these same functions write — an infinite effect loop that
// takes down every page, not just the ones using the stream.
let status: StreamStatus = 'idle';
let uiStatus = $state<StreamStatus>('idle');
let retryDelay = BACKOFF_START_MS;
let retryTimer: ReturnType<typeof setTimeout> | null = null;
let graceTimer: ReturnType<typeof setTimeout> | null = null;
/** Set when we drop the EventSource ourselves, losing its resume cursor. */
let hadGap = false;

const subscribers = new Set<Subscription>();

/** The single writer for both copies of the status. */
function setStatus(next: StreamStatus): void {
	status = next;
	uiStatus = next;
}

/** Reactive connection state, for UI that reports liveness. */
export const eventStream = {
	get state(): StreamStatus {
		return uiStatus;
	},
	get live(): boolean {
		return uiStatus === 'live';
	}
};

/**
 * Subscribe to one or more event types. Returns an unsubscribe function; call
 * it from an `$effect` teardown.
 *
 * `T` is the payload shape the subscriber expects (e.g. `ApprovalEventData`).
 * It is an assertion, not a guarantee — the wire payload is untyped JSON — so
 * subscribers should treat it as a routing hint and refetch the resource
 * rather than render straight from it.
 */
export function onEvent<T = Record<string, unknown>>(
	types: readonly StreamEventType[],
	handler: (event: StreamEvent<T>) => void
): () => void {
	const subscription: Subscription = {
		types: new Set(types),
		handler: handler as (event: StreamEvent<never>) => void
	};
	subscribers.add(subscription);
	return () => {
		subscribers.delete(subscription);
	};
}

function dispatch(event: StreamEvent): void {
	for (const subscription of subscribers) {
		if (!subscription.types.has(event.type)) continue;
		try {
			subscription.handler(event as StreamEvent<never>);
		} catch (e) {
			// One bad handler must not stop delivery to the others.
			console.error('[events] subscriber threw', e);
		}
	}
}

function clearTimer(timer: ReturnType<typeof setTimeout> | null) {
	if (timer !== null) clearTimeout(timer);
	return null;
}

function markLive(): void {
	graceTimer = clearTimer(graceTimer);
	retryDelay = BACKOFF_START_MS;
	setStatus('live');

	if (hadGap) {
		hadGap = false;
		dispatch({
			id: '',
			type: 'stream.resync',
			created_at: new Date().toISOString(),
			data: {}
		});
	}
}

/** Jittered so a server restart doesn't bring every tab back simultaneously. */
function nextDelay(): number {
	const jitter = Math.random() * 0.3 + 0.85;
	const delay = Math.round(retryDelay * jitter);
	retryDelay = Math.min(retryDelay * 2, BACKOFF_MAX_MS);
	return delay;
}

function connect(): void {
	retryTimer = clearTimer(retryTimer);
	if (status !== 'live') setStatus('connecting');

	const es = new EventSource(STREAM_URL, { withCredentials: true });
	source = es;

	es.onopen = () => markLive();
	// The server names every frame, and named events never reach `onmessage`.
	es.addEventListener('stream.open', () => markLive());
	for (const type of WIRE_EVENT_TYPES) {
		es.addEventListener(type, (raw) => {
			markLive();
			try {
				dispatch(JSON.parse((raw as MessageEvent).data) as StreamEvent);
			} catch (e) {
				console.error('[events] unparseable frame', e);
			}
		});
	}

	es.onerror = () => {
		if (source !== es) return;

		if (es.readyState === EventSource.CLOSED) {
			// Fatal — the browser will not retry. Rebuild the connection
			// ourselves, and remember that the resume cursor went with it.
			es.close();
			source = null;
			hadGap = true;
			setStatus('down');
			retryTimer = setTimeout(connect, nextDelay());
			return;
		}

		// Reconnecting natively (the routine 30s close, or a blip). Keep
		// claiming live until the grace window expires.
		if (graceTimer === null) {
			graceTimer = setTimeout(() => {
				graceTimer = null;
				if (source === es && es.readyState !== EventSource.OPEN) setStatus('down');
			}, RECONNECT_GRACE_MS);
		}
	};
}

/**
 * Idempotent — safe to call from an effect that re-runs.
 *
 * Deliberately does not clear `hadGap`. If the stream died fatally and the user
 * then passed through a standalone route (`/login`, a consent screen), the stop
 * on the way out and the start on the way back would otherwise erase the fact
 * that events were missed, and `markLive` would skip the `stream.resync` that
 * tells subscribers to refetch. Only a successful open clears it.
 */
export function startEventStream(): void {
	if (typeof window === 'undefined') return;
	if (source !== null || retryTimer !== null) return;
	connect();
}

export function stopEventStream(): void {
	retryTimer = clearTimer(retryTimer);
	graceTimer = clearTimer(graceTimer);
	source?.close();
	source = null;
	setStatus('idle');
	retryDelay = BACKOFF_START_MS;
}

// Vite keeps the old module instance alive across a hot update, and with it a
// second EventSource counting against the per-identity connection cap.
if (import.meta.hot) {
	import.meta.hot.dispose(() => stopEventStream());
}
