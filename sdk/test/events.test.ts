import { afterEach, describe, expect, it, vi } from 'vitest';
import { OverslashClient } from '../src/client.js';
import { SseEvents } from '../src/controllers/events.js';
import type { EventEnvelope } from '../src/types/events.js';
import type { Transport, TransportResponse } from '../src/transport.js';

/**
 * A response whose body streams the given chunks, then closes.
 *
 * A factory, not a value: a `ReadableStream` can only be consumed once, and
 * every reconnect opens a new one. Handing the same object back twice models a
 * server that hangs up instantly — which is a real case, but not the one most
 * of these tests are about.
 */
function sseResponse(chunks: string[], status = 200, headers: Record<string, string> = {}) {
  return () => {
    const encoder = new TextEncoder();
    return {
      status,
      headers: { get: (n: string) => headers[n.toLowerCase()] ?? null },
      text: async () => chunks.join(''),
      body: new ReadableStream<Uint8Array>({
        start(controller) {
          for (const c of chunks) controller.enqueue(encoder.encode(c));
          controller.close();
        },
      }),
    } satisfies TransportResponse;
  };
}

/** A 200 whose body never closes — a healthy connection, mid-life. */
function openForever(): () => TransportResponse {
  return () => ({
    status: 200,
    headers: { get: () => null },
    text: async () => '',
    body: new ReadableStream<Uint8Array>({ start() {} }),
  });
}

function plainResponse(status: number): () => TransportResponse {
  return () => ({ status, headers: { get: () => null }, text: async () => '' });
}

/**
 * A transport that answers stream opens from a queue and records the
 * `Last-Event-ID` each attempt carried.
 *
 * Once the queue is exhausted it parks on an open connection rather than
 * repeating the last response, so a test that does not care about later
 * reconnects does not accidentally drive an unbounded loop.
 */
function streamTransport(responses: Array<() => TransportResponse>) {
  const cursors: Array<string | undefined> = [];
  const paths: string[] = [];
  let i = 0;
  const transport: Transport = async (req) => {
    paths.push(req.path);
    cursors.push(req.headers['last-event-id']);
    const make = responses[i] ?? openForever();
    i += 1;
    return make();
  };
  return { transport, cursors, paths };
}

function frame(type: string, id: number, data: Record<string, unknown>): string {
  return `event: ${type}\nid: ${id}\ndata: ${JSON.stringify({ id: `e${id}`, type, created_at: '', data })}\n\n`;
}

/** Let queued microtasks and the async stream generator settle. */
const settle = () => new Promise((r) => setTimeout(r, 0));

let open: SseEvents[] = [];
afterEach(() => {
  for (const e of open) e.close();
  open = [];
  vi.useRealTimers();
});

function makeEvents(transport: Transport, options = {}) {
  const client = new OverslashClient({ auth: { transport } });
  // `minHealthyConnectionMs: 0` opts out of the "the server hung up instantly"
  // guard, which every mocked stream would otherwise trip — its body closes in
  // microseconds, where a real one lives ~30s. The guard has its own test.
  const events = new SseEvents(client, {
    random: () => 0.5,
    minHealthyConnectionMs: 0,
    ...options,
  });
  open.push(events);
  return events;
}

describe('SseEvents', () => {
  it('subscribes only the topics its subscribers actually want', async () => {
    const { transport, paths } = streamTransport([sseResponse([])]);
    const events = makeEvents(transport);

    events.subscribe(['approval.pending'], () => {});
    await settle();

    expect(paths[0]).toBe('/v1/events/stream?topics=approvals');
  });

  it('opens one connection for subscribers spanning several topics', async () => {
    // The per-identity cap is 4 concurrent streams, so a page with a list, two
    // cards and a connect button must not open one each.
    // A healthy connection that stays open, so nothing reconnects and the
    // count reflects only what mounting cost.
    const { transport, paths } = streamTransport([openForever()]);
    const events = makeEvents(transport);

    // Three controllers mounting in the same tick, as a page does.
    events.subscribe(['approval.pending'], () => {});
    events.subscribe(['connection.created'], () => {});
    events.subscribe(['approval.resolved'], () => {});
    await settle();

    expect(paths).toHaveLength(1);
    expect(paths[0]).toBe('/v1/events/stream?topics=approvals,connections');
  });

  it('delivers parsed envelopes to matching subscribers only', async () => {
    const { transport } = streamTransport([
      sseResponse([
        frame('stream.open', 100, {}),
        frame('approval.pending', 101, { approval_id: 'a1' }),
        frame('connection.created', 102, { connection_id: 'c1' }),
      ]),
    ]);
    const events = makeEvents(transport);

    const approvals: EventEnvelope[] = [];
    const connections: EventEnvelope[] = [];
    events.subscribe(['approval.pending'], (e) => approvals.push(e));
    events.subscribe(['connection.created'], (e) => connections.push(e));
    await settle();

    expect(approvals).toHaveLength(1);
    expect(approvals[0]?.type).toBe('approval.pending');
    expect(connections).toHaveLength(1);
  });

  it('resumes from the last cursor it saw, per frame', async () => {
    // The server advertises the *current* position on stream.open and advances
    // it per replayed row, so a connection dying mid-replay must not skip rows.
    const { transport, cursors } = streamTransport([
      sseResponse([frame('stream.open', 100, {}), frame('approval.pending', 101, {})]),
      sseResponse([]),
    ]);
    const events = makeEvents(transport);
    events.subscribe(['approval.pending'], () => {});
    await settle();
    await settle();

    expect(cursors[0]).toBeUndefined();
    expect(cursors[1]).toBe('101');
  });

  it('treats the routine 30s close as normal and reconnects at once', async () => {
    const { transport, paths } = streamTransport([
      sseResponse([frame('stream.open', 1, {})]),
      sseResponse([frame('stream.open', 1, {})]),
    ]);
    const events = makeEvents(transport);
    events.subscribe(['approval.pending'], () => {});
    await settle();
    await settle();

    // Reconnected without waiting out any backoff, and never reported down.
    expect(paths.length).toBeGreaterThanOrEqual(2);
    expect(events.status).toBe('live');
  });

  it('backs off instead of spinning when a connection closes immediately', async () => {
    // The immediate-reconnect path is right for the 30s ceiling and catastrophic
    // for a proxy that hangs up at once: without a floor it is a tight loop that
    // hammers the server and pins a CPU.
    vi.useFakeTimers();
    // Both attempts close immediately; without the floor this never yields.
    const { transport, paths } = streamTransport([
      sseResponse([frame('stream.open', 1, {})]),
      sseResponse([frame('stream.open', 1, {})]),
    ]);
    const client = new OverslashClient({ auth: { transport } });
    const events = new SseEvents(client, { random: () => 0.5, backoffStartMs: 1_000 });
    open.push(events);

    events.subscribe(['approval.pending'], () => {});
    await vi.advanceTimersByTimeAsync(0);
    const afterFirst = paths.length;

    // Time passes with no reconnect attempt until the backoff elapses.
    await vi.advanceTimersByTimeAsync(500);
    expect(paths.length).toBe(afterFirst);

    await vi.advanceTimersByTimeAsync(1_000);
    expect(paths.length).toBe(afterFirst + 1);
  });

  it('does not announce a resync when the cursor survived the reconnect', async () => {
    const { transport } = streamTransport([
      sseResponse([frame('stream.open', 5, {}), frame('approval.pending', 6, {})]),
      sseResponse([frame('stream.open', 6, {})]),
    ]);
    const events = makeEvents(transport);
    const seen: string[] = [];
    events.subscribe(['approval.pending', 'stream.resync'], (e) => seen.push(e.type));
    await settle();
    await settle();

    expect(seen).toEqual(['approval.pending']);
  });

  it('announces a resync when it reconnects having never held a cursor', async () => {
    vi.useFakeTimers();
    const { transport } = streamTransport([
      // A fatal open: no body, so no cursor was ever learned.
      plainResponse(500),
      sseResponse([frame('stream.open', 9, {})]),
    ]);
    const events = makeEvents(transport);
    const seen: string[] = [];
    // `stream.resync` names no topic on its own, so pair it with a real one —
    // a resync-only subscriber cannot justify opening a connection.
    events.subscribe(['approval.pending', 'stream.resync'], (e) => seen.push(e.type));

    await vi.advanceTimersByTimeAsync(0);
    expect(events.status).toBe('down');
    await vi.advanceTimersByTimeAsync(2000);
    await vi.advanceTimersByTimeAsync(0);

    expect(seen).toEqual(['stream.resync']);
    expect(events.live).toBe(true);
  });

  it('honours Retry-After on a 429 rather than hammering a full cap', async () => {
    vi.useFakeTimers();
    const { transport, paths } = streamTransport([
      sseResponse([], 429, { 'retry-after': '30' }),
      sseResponse([frame('stream.open', 1, {})]),
    ]);
    const events = makeEvents(transport);
    events.subscribe(['approval.pending'], () => {});

    await vi.advanceTimersByTimeAsync(0);
    const afterFirst = paths.length;
    // Well past the 1s default backoff, but short of the server's 30s.
    await vi.advanceTimersByTimeAsync(5_000);
    expect(paths.length).toBe(afterFirst);

    await vi.advanceTimersByTimeAsync(26_000);
    expect(paths.length).toBeGreaterThan(afterFirst);
  });

  it('reports down and stays pollable when the server has no stream endpoint', async () => {
    vi.useFakeTimers();
    const { transport } = streamTransport([plainResponse(404)]);
    const events = makeEvents(transport);
    events.subscribe(['approval.pending'], () => {});
    await vi.advanceTimersByTimeAsync(0);

    expect(events.live).toBe(false);
    expect(events.status).toBe('down');
  });

  it('stops when the server speaks a newer protocol version', async () => {
    const { transport } = streamTransport([
      sseResponse([`event: stream.open\nid: 1\ndata: {"cursor":1,"v":99}\n\n`]),
    ]);
    const events = makeEvents(transport);
    events.subscribe(['approval.pending'], () => {});
    await settle();

    // Better no push channel than one whose framing we may misread; the
    // caller's poll fallback still works.
    expect(events.live).toBe(false);
  });

  it('keeps delivering to other subscribers when one throws', async () => {
    const { transport } = streamTransport([
      sseResponse([frame('approval.pending', 1, { approval_id: 'a1' })]),
    ]);
    const events = makeEvents(transport);
    const seen: string[] = [];
    events.subscribe(['approval.pending'], () => {
      throw new Error('bad handler');
    });
    events.subscribe(['approval.pending'], (e) => seen.push(e.type));
    await settle();

    expect(seen).toEqual(['approval.pending']);
  });
});
