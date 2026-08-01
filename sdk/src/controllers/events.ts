/**
 * Realtime delivery.
 *
 * `EventsTransport` has two implementations: `SseEvents` over D45's stream, and
 * `PollingEvents` for when that is unavailable — an older server, a proxy that
 * breaks SSE, a host transport that buffers instead of streaming. The interface
 * is what lets controllers not care which one they got.
 *
 * Events are notifications, not state. Every subscriber should refetch the
 * resource an event names; the payloads route, they do not render.
 */

import type { OverslashClient } from '../client.js';
import type { EventEnvelope, Topic } from '../types/events.js';
import { SUPPORTED_STREAM_VERSION, topicForEvent } from '../types/events.js';
import { readSseStream } from './sse-parse.js';
import { reportError } from './store.js';

export type StreamStatus = 'idle' | 'connecting' | 'live' | 'down';

export interface EventsTransport {
  /**
   * Subscribe to event types. Returns an unsubscribe function.
   *
   * Topics are derived from the requested types, and the transport subscribes
   * the union across all subscribers — a page with a list, two cards and a
   * connect button opens **one** connection, which matters because the
   * per-identity cap is four.
   *
   * `T` is the payload shape the subscriber expects. It is an assertion, not a
   * guarantee — the wire payload is untyped JSON — which is why the contract is
   * "refetch the resource, do not render from the payload". The one unavoidable
   * cast lives in the dispatch loop, where the untyped JSON actually arrives,
   * rather than at every call site.
   */
  subscribe<T = Record<string, unknown>>(
    types: readonly string[],
    handler: (event: EventEnvelope<T>) => void,
  ): () => void;
  /** Whether push delivery is currently working. Poll fallbacks consult this. */
  readonly live: boolean;
  readonly status: StreamStatus;
  /** Observe connection state, e.g. to render a "live" indicator. */
  onStatusChange(listener: (status: StreamStatus) => void): () => void;
  close(): void;
}

interface Subscription {
  types: ReadonlySet<string>;
  handler: (event: EventEnvelope<never>) => void;
}

export interface SseEventsOptions {
  /**
   * How long to tolerate a reconnect before admitting the stream is down. The
   * server closes every 30s and we reconnect at once, so a brief gap is the
   * normal case — reporting "down" on it would flicker an indicator twice a
   * minute.
   */
  reconnectGraceMs?: number;
  backoffStartMs?: number;
  backoffMaxMs?: number;
  /**
   * Below this, a clean close is treated as a fault and backed off rather than
   * reconnected instantly. See `MIN_HEALTHY_CONNECTION_MS`.
   */
  minHealthyConnectionMs?: number;
  /** Injected in tests. Defaults to `Math.random`. */
  random?: () => number;
}

const DEFAULTS = {
  reconnectGraceMs: 8_000,
  backoffStartMs: 1_000,
  backoffMaxMs: 30_000,
};

/**
 * Below this, a "clean" close is not the routine 30-second ceiling — it is a
 * server or proxy hanging up immediately, and reconnecting at once would spin.
 *
 * The immediate-reconnect path exists because the ceiling is by design and a
 * delay there would add latency to every event twice a minute. That reasoning
 * only holds for a connection that actually lived; a connection that ended in
 * milliseconds gets the backoff instead.
 */
const MIN_HEALTHY_CONNECTION_MS = 1_000;

/**
 * The stream, with reconnection and cursor tracking.
 *
 * Connection lifecycle mirrors what the dashboard settled on, because those
 * semantics are correct: the routine 30-second close is not an error, a grace
 * window precedes reporting `down`, backoff is jittered so a server restart
 * does not bring every client back simultaneously, and `Retry-After` is honoured
 * on a 429 (the per-identity stream cap is a real ceiling).
 *
 * The difference is the cursor. We hold it, so a reconnect after *any* failure
 * resumes precisely, and `stream.resync` — the "you may have missed events,
 * refetch" signal — fires only when reconnecting having never received one.
 */
export class SseEvents implements EventsTransport {
  private readonly subscribers = new Set<Subscription>();
  private readonly statusListeners = new Set<(s: StreamStatus) => void>();
  private readonly opts: Required<SseEventsOptions>;

  private state: StreamStatus = 'idle';
  private controller: AbortController | null = null;
  private cursor: string | undefined;
  private retryDelay: number;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private graceTimer: ReturnType<typeof setTimeout> | null = null;
  private closed = false;
  /** True when we lost the connection without a cursor to resume from. */
  private blind = false;
  /** Topics the open connection was built for; a change forces a reconnect. */
  private connectedTopics = '';
  private connectScheduled = false;

  constructor(
    private readonly client: OverslashClient,
    options: SseEventsOptions = {},
  ) {
    this.opts = {
      reconnectGraceMs: options.reconnectGraceMs ?? DEFAULTS.reconnectGraceMs,
      backoffStartMs: options.backoffStartMs ?? DEFAULTS.backoffStartMs,
      backoffMaxMs: options.backoffMaxMs ?? DEFAULTS.backoffMaxMs,
      minHealthyConnectionMs: options.minHealthyConnectionMs ?? MIN_HEALTHY_CONNECTION_MS,
      random: options.random ?? Math.random,
    };
    this.retryDelay = this.opts.backoffStartMs;
  }

  get live(): boolean {
    return this.state === 'live';
  }

  get status(): StreamStatus {
    return this.state;
  }

  subscribe<T = Record<string, unknown>>(
    types: readonly string[],
    handler: (event: EventEnvelope<T>) => void,
  ): () => void {
    const subscription: Subscription = {
      types: new Set(types),
      handler: handler as (event: EventEnvelope<never>) => void,
    };
    this.subscribers.add(subscription);
    this.ensureConnected();
    return () => {
      this.subscribers.delete(subscription);
      // Deliberately keeps the connection open: subscribers come and go with
      // component lifecycles, and tearing down a stream to rebuild it a tick
      // later would burn the reconnect budget and the per-identity cap.
    };
  }

  onStatusChange(listener: (status: StreamStatus) => void): () => void {
    this.statusListeners.add(listener);
    return () => this.statusListeners.delete(listener);
  }

  close(): void {
    this.closed = true;
    this.clearTimers();
    this.controller?.abort();
    this.controller = null;
    this.subscribers.clear();
    this.setStatus('idle');
    this.statusListeners.clear();
  }

  /** Topics currently wanted, as the union across subscribers. */
  private topics(): Topic[] {
    const wanted = new Set<Topic>();
    for (const sub of this.subscribers) {
      for (const type of sub.types) {
        const topic = topicForEvent(type);
        if (topic) wanted.add(topic);
      }
    }
    return [...wanted].sort();
  }

  /**
   * Coalesced on a microtask.
   *
   * A page mounts several controllers in one tick, each subscribing to a
   * different topic. Reacting synchronously would open a connection, abort it
   * for the second subscriber, abort that for the third — three opens against a
   * cap of four, to end up where one open would have. Deferring to the end of
   * the tick lets the topic set settle first.
   */
  private ensureConnected(): void {
    if (this.closed || this.connectScheduled) return;
    this.connectScheduled = true;
    queueMicrotask(() => {
      this.connectScheduled = false;
      this.reconcile();
    });
  }

  private reconcile(): void {
    if (this.closed) return;
    const topics = this.topics().join(',');
    // Nothing to subscribe to. A subscriber interested only in the synthetic
    // `stream.resync` names no topic, and so cannot on its own justify a
    // connection.
    if (!topics) return;

    if (this.controller && topics !== this.connectedTopics) {
      // A subscriber wants a topic this connection does not carry.
      this.controller.abort();
      this.controller = null;
    }
    if (this.controller || this.retryTimer !== null) return;
    void this.connect();
  }

  private async connect(): Promise<void> {
    if (this.closed) return;

    const topics = this.topics();
    if (!topics.length) return;
    this.connectedTopics = topics.join(',');

    const controller = new AbortController();
    this.controller = controller;
    if (this.state !== 'live') this.setStatus('connecting');

    try {
      const res = await this.client.events.open(topics, {
        signal: controller.signal,
        ...(this.cursor === undefined ? {} : { lastEventId: this.cursor }),
      });

      if (res.status === 429) {
        // Not malformed — early. A slot frees within one connection lifetime.
        const retryAfter = Number(res.headers.get('retry-after'));
        this.scheduleReconnect(
          Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : undefined,
        );
        return;
      }

      if (res.status < 200 || res.status >= 300 || !res.body) {
        // 403 (no identity-bound credential), 404 (server predates the stream),
        // or a proxy that buffered the body away. Either way there is no push
        // channel; the caller's poll fallback takes over.
        this.fail();
        return;
      }

      const openedAt = Date.now();
      this.markLive();

      for await (const frame of readSseStream(res.body, controller.signal)) {
        // Per-frame, exactly as the server's replay ordering requires: the
        // open frame advertises where the client *is*, and each replayed row
        // advances the cursor as it lands, so a connection dying mid-replay
        // does not skip the rows it never delivered.
        if (frame.id) this.cursor = frame.id;
        this.markLive();
        this.handleFrame(frame.event, frame.data);
      }

      // The stream ended cleanly — normally the routine 30s ceiling, where
      // reconnecting at once is right because the cursor makes it lossless.
      if (this.controller === controller) {
        this.controller = null;
        this.enterGrace();
        if (Date.now() - openedAt < this.opts.minHealthyConnectionMs) {
          // Not the ceiling: something is hanging up on us. Back off.
          this.scheduleReconnect();
        } else {
          void this.connect();
        }
      }
    } catch (e) {
      if (controller.signal.aborted) return;
      reportError(e);
      this.fail();
    }
  }

  private handleFrame(type: string, data: string): void {
    if (type === 'stream.open') {
      const parsed = safeParse(data) as { v?: number } | undefined;
      if (parsed?.v !== undefined && parsed.v > SUPPORTED_STREAM_VERSION) {
        // Newer framing than we understand. Stop rather than misinterpret it;
        // the poll fallback still works.
        reportError(
          new Error(`event stream protocol v${parsed.v} is newer than v${SUPPORTED_STREAM_VERSION}`),
        );
        this.close();
      }
      return;
    }

    const envelope = safeParse(data) as EventEnvelope | undefined;
    if (!envelope) return;
    this.dispatch({ ...envelope, type: envelope.type || type });
  }

  private dispatch(event: EventEnvelope): void {
    for (const sub of [...this.subscribers]) {
      if (!sub.types.has(event.type)) continue;
      try {
        // The assertion the subscriber asked for, made once, here.
        sub.handler(event as EventEnvelope<never>);
      } catch (e) {
        // One bad handler must not stop delivery to the others.
        reportError(e);
      }
    }
  }

  private markLive(): void {
    this.clearGrace();
    this.retryDelay = this.opts.backoffStartMs;
    const wasBlind = this.blind;
    this.blind = false;
    this.setStatus('live');

    if (wasBlind) {
      this.dispatch({
        id: '',
        type: 'stream.resync',
        created_at: new Date().toISOString(),
        data: {},
      });
    }
  }

  /**
   * A connection ended without delivering anything usable. If we never held a
   * cursor, subscribers must be told to refetch once we are back.
   */
  private fail(): void {
    this.controller = null;
    if (this.cursor === undefined) this.blind = true;
    this.setStatus('down');
    this.scheduleReconnect();
  }

  /**
   * Between connections. Keep claiming `live` until the grace window expires,
   * so the twice-a-minute reconnect does not read as an outage.
   */
  private enterGrace(): void {
    if (this.graceTimer !== null) return;
    this.graceTimer = setTimeout(() => {
      this.graceTimer = null;
      if (this.state !== 'live') return;
      if (this.controller === null) this.setStatus('down');
    }, this.opts.reconnectGraceMs);
  }

  private scheduleReconnect(explicitDelayMs?: number): void {
    if (this.closed || this.retryTimer !== null) return;
    const delay = explicitDelayMs ?? this.nextDelay();
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      void this.connect();
    }, delay);
  }

  /** Jittered, so a server restart does not bring every client back at once. */
  private nextDelay(): number {
    const jitter = this.opts.random() * 0.3 + 0.85;
    const delay = Math.round(this.retryDelay * jitter);
    this.retryDelay = Math.min(this.retryDelay * 2, this.opts.backoffMaxMs);
    return delay;
  }

  private clearGrace(): void {
    if (this.graceTimer !== null) {
      clearTimeout(this.graceTimer);
      this.graceTimer = null;
    }
  }

  private clearTimers(): void {
    this.clearGrace();
    if (this.retryTimer !== null) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }

  private setStatus(next: StreamStatus): void {
    if (this.state === next) return;
    this.state = next;
    for (const listener of [...this.statusListeners]) {
      try {
        listener(next);
      } catch (e) {
        reportError(e);
      }
    }
  }
}

/**
 * The fallback: no push channel, so controllers poll.
 *
 * It delivers nothing itself. Reporting `live: false` is the whole contract —
 * that is what tells each controller's `PollScheduler` to keep ticking.
 */
export class PollingEvents implements EventsTransport {
  readonly live = false;
  readonly status: StreamStatus = 'down';

  subscribe<T = Record<string, unknown>>(
    _types: readonly string[],
    _handler: (event: EventEnvelope<T>) => void,
  ): () => void {
    return () => {};
  }

  onStatusChange(listener: (status: StreamStatus) => void): () => void {
    listener('down');
    return () => {};
  }

  close(): void {}
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch (e) {
    reportError(e);
    return undefined;
  }
}
