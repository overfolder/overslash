import type { OverslashClient, RequestOptions } from '../client.js';
import type { Topic } from '../types/events.js';
import type { TransportResponse } from '../transport.js';

export interface OpenStreamOptions extends RequestOptions {
  /** Resume cursor. Sent as `Last-Event-ID`, exactly as `EventSource` would. */
  lastEventId?: string | number;
}

/**
 * The raw stream primitive: opens `GET /v1/events/stream` and hands back the
 * undrained response.
 *
 * Deliberately low-level — parsing, reconnection and cursor tracking live in
 * `@overslash/sdk/controllers` (`SseEvents`), so a caller that wants to drive
 * the stream itself is not forced through a state machine.
 */
export class EventsResource {
  constructor(private readonly client: OverslashClient) {}

  async open(topics: Topic[], opts: OpenStreamOptions = {}): Promise<TransportResponse> {
    const params = new URLSearchParams();
    if (topics.length) params.set('topics', topics.join(','));
    const qs = params.toString();

    return this.client.send('GET', `/v1/events/stream${qs ? `?${qs}` : ''}`, undefined, {
      stream: true,
      ...(opts.signal ? { signal: opts.signal } : {}),
      headers: {
        accept: 'text/event-stream',
        // Not sent by us on a first connect, so the server starts the client at
        // the org's high-water mark rather than replaying all of history.
        ...(opts.lastEventId === undefined
          ? {}
          : { 'last-event-id': String(opts.lastEventId) }),
      },
    });
  }
}
