/**
 * An SSE frame parser.
 *
 * Written by hand rather than using `EventSource` because two of the SDK's
 * three auth modes are bearer modes, `EventSource` cannot set an
 * `Authorization` header, and D45 deliberately refused a `?token=` query-param
 * mode (a credential in a query string lands in access logs, proxy logs and
 * `Referer`).
 *
 * Owning the parser also means owning the resume cursor, which is strictly
 * better: `EventSource` keeps its cursor internally, so a fatal error destroys
 * it and the reconnect starts blind.
 *
 * Implements the framing in the W3C spec as far as the server uses it: `event`,
 * `data`, `id`, comment lines, and `\n` / `\r\n` / `\r` line breaks.
 */

export interface SseFrame {
  /** Defaults to `message` per the spec; the gateway names every frame. */
  event: string;
  data: string;
  /** Present when the frame carried an `id:`. This is the resume cursor. */
  id?: string;
}

export class SseParser {
  private buffer = '';
  private event = '';
  private data: string[] = [];
  private id: string | undefined;

  /**
   * Feed a chunk; get back whatever frames completed.
   *
   * Chunk boundaries are arbitrary — a frame can arrive split across three
   * reads — so incomplete lines stay buffered.
   */
  push(chunk: string): SseFrame[] {
    this.buffer += chunk;
    const frames: SseFrame[] = [];

    // Split on any line terminator, keeping a trailing partial line buffered.
    // A trailing "\r" is held back too: it may yet turn out to be "\r\n".
    let searchFrom = 0;
    for (;;) {
      const match = /\r\n|\n|\r/.exec(this.buffer.slice(searchFrom));
      if (!match) break;
      const index = searchFrom + match.index;
      if (match[0] === '\r' && index + 1 === this.buffer.length) break;

      const line = this.buffer.slice(0, index);
      this.buffer = this.buffer.slice(index + match[0].length);
      searchFrom = 0;

      const frame = this.line(line);
      if (frame) frames.push(frame);
    }

    return frames;
  }

  /**
   * End of stream: resolve whatever was held back.
   *
   * A trailing lone `\r` is ambiguous mid-stream — it may yet turn out to be
   * `\r\n` — so `push` holds it. Once the body is closed it cannot, so it is a
   * terminator after all.
   */
  flush(): SseFrame[] {
    const frames: SseFrame[] = [];
    if (this.buffer) {
      const line = this.buffer.replace(/\r$/, '');
      this.buffer = '';
      const frame = this.line(line);
      if (frame) frames.push(frame);
    }
    // A body that ended without its final blank line still has a complete
    // frame's worth of fields buffered.
    const trailing = this.line('');
    if (trailing) frames.push(trailing);
    return frames;
  }

  private line(line: string): SseFrame | null {
    // Blank line dispatches the accumulated frame.
    if (line === '') {
      if (this.data.length === 0 && this.event === '') {
        // A stray blank line, or a comment-only block. Nothing to dispatch,
        // but per spec the id sticks for the next frame.
        return null;
      }
      const frame: SseFrame = {
        event: this.event || 'message',
        data: this.data.join('\n'),
        ...(this.id === undefined ? {} : { id: this.id }),
      };
      this.event = '';
      this.data = [];
      return frame;
    }

    // Comment — the gateway sends `: keep-alive` every 15s. Its only job is
    // proving the connection is alive, so it produces no frame.
    if (line.startsWith(':')) return null;

    const colon = line.indexOf(':');
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);

    switch (field) {
      case 'event':
        this.event = value;
        break;
      case 'data':
        this.data.push(value);
        break;
      case 'id':
        // The spec ignores an id containing NUL; the gateway sends a bigserial.
        if (!value.includes('\0')) this.id = value;
        break;
      case 'retry':
        // The gateway does not send this, and the SDK owns its own backoff.
        break;
      default:
        break;
    }
    return null;
  }
}

/**
 * Read a response body as a stream of SSE frames.
 *
 * Yields until the server closes — which it does every 30 seconds by design, so
 * the caller's reconnect path is the normal path, not the exceptional one.
 */
export async function* readSseStream(
  body: ReadableStream<Uint8Array>,
  signal?: AbortSignal,
): AsyncGenerator<SseFrame> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  const parser = new SseParser();

  const abort = () => void reader.cancel().catch(() => {});
  signal?.addEventListener('abort', abort, { once: true });

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      // `stream: true` so a multi-byte character split across chunks is not
      // decoded into replacement characters.
      for (const frame of parser.push(decoder.decode(value, { stream: true }))) {
        yield frame;
      }
    }
    for (const frame of parser.push(decoder.decode())) yield frame;
    for (const frame of parser.flush()) yield frame;
  } finally {
    signal?.removeEventListener('abort', abort);
    reader.releaseLock();
  }
}
