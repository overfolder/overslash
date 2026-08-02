import { describe, expect, it } from 'vitest';
import { SseParser, readSseStream } from '../src/controllers/sse-parse.js';

function feed(chunks: string[]) {
  const parser = new SseParser();
  return chunks.flatMap((c) => parser.push(c));
}

describe('SseParser', () => {
  it('parses the gateway framing: named event, id cursor, JSON data', () => {
    const frames = feed([
      'event: approval.created\nid: 4213\ndata: {"id":"e1","type":"approval.created"}\n\n',
    ]);

    expect(frames).toEqual([
      {
        event: 'approval.created',
        id: '4213',
        data: '{"id":"e1","type":"approval.created"}',
      },
    ]);
  });

  it('reassembles a frame split across arbitrary chunk boundaries', () => {
    // A network read boundary lands wherever it lands; the frame must survive.
    const frames = feed(['event: appro', 'val.res', 'olved\nid: 7\ndata: {"a":', '1}\n', '\n']);

    expect(frames).toHaveLength(1);
    expect(frames[0]).toEqual({ event: 'approval.resolved', id: '7', data: '{"a":1}' });
  });

  it('ignores keep-alive comments, which carry no frame', () => {
    const frames = feed([': keep-alive\n\n: keep-alive\n\n']);
    expect(frames).toEqual([]);
  });

  it('does not lose a frame that follows a keep-alive', () => {
    const frames = feed([': keep-alive\n\nevent: approval.pending\nid: 9\ndata: {}\n\n']);
    expect(frames).toHaveLength(1);
    expect(frames[0]?.event).toBe('approval.pending');
  });

  it('joins multi-line data with newlines, per spec', () => {
    const frames = feed(['event: x\ndata: line one\ndata: line two\n\n']);
    expect(frames[0]?.data).toBe('line one\nline two');
  });

  it('handles CRLF and bare CR terminators', () => {
    expect(feed(['event: a\r\ndata: 1\r\n\r\n'])[0]).toEqual({ event: 'a', data: '1' });
    expect(feed(['event: b\rdata: 2\r\rx'])[0]).toEqual({ event: 'b', data: '2' });
  });

  it('flushes a frame held back by an ambiguous trailing CR', () => {
    // Mid-stream a lone trailing "\r" may still turn out to be "\r\n", so it is
    // held. Once the body closes it cannot, and the frame must not be lost.
    const parser = new SseParser();
    expect(parser.push('event: b\rdata: 2\r\r')).toEqual([]);
    expect(parser.flush()).toEqual([{ event: 'b', data: '2' }]);
  });

  it('flushes a frame whose final blank line never arrived', () => {
    const parser = new SseParser();
    expect(parser.push('event: c\ndata: 3\n')).toEqual([]);
    expect(parser.flush()).toEqual([{ event: 'c', data: '3' }]);
  });

  it('does not split a CRLF that arrives across two chunks', () => {
    // Treating the trailing "\r" as a terminator would dispatch early and then
    // read the "\n" as a second blank line.
    const parser = new SseParser();
    expect(parser.push('event: a\ndata: 1\r')).toEqual([]);
    expect(parser.push('\n\r\n')).toEqual([{ event: 'a', data: '1' }]);
  });

  it('carries the last id forward when a later frame omits one', () => {
    // Per spec the id is sticky. The gateway stamps every frame, but a proxy
    // that drops one must not reset the cursor.
    const parser = new SseParser();
    parser.push('event: a\nid: 5\ndata: 1\n\n');
    const [second] = parser.push('event: b\ndata: 2\n\n');
    expect(second?.id).toBe('5');
  });

  it('defaults an unnamed event to `message`', () => {
    expect(feed(['data: bare\n\n'])[0]).toEqual({ event: 'message', data: 'bare' });
  });

  it('strips exactly one leading space after the colon', () => {
    expect(feed(['event: x\ndata:  two spaces\n\n'])[0]?.data).toBe(' two spaces');
  });

  it('tolerates a field with no colon at all', () => {
    const frames = feed(['event\ndata: 1\n\n']);
    expect(frames[0]).toEqual({ event: 'message', data: '1' });
  });
});

describe('readSseStream', () => {
  function streamOf(chunks: string[]): ReadableStream<Uint8Array> {
    const encoder = new TextEncoder();
    return new ReadableStream<Uint8Array>({
      start(controller) {
        for (const c of chunks) controller.enqueue(encoder.encode(c));
        controller.close();
      },
    });
  }

  it('yields frames until the server closes', async () => {
    const stream = streamOf([
      'event: stream.open\nid: 100\ndata: {"cursor":100,"v":1}\n\n',
      'event: approval.pending\nid: 101\ndata: {"id":"e","type":"approval.pending"}\n\n',
    ]);

    const seen: string[] = [];
    for await (const frame of readSseStream(stream)) seen.push(frame.event);

    expect(seen).toEqual(['stream.open', 'approval.pending']);
  });

  it('decodes a multi-byte character split across chunks', async () => {
    const encoder = new TextEncoder();
    const full = encoder.encode('event: x\ndata: café\n\n');
    const cut = 17; // lands inside the é
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(full.slice(0, cut));
        controller.enqueue(full.slice(cut));
        controller.close();
      },
    });

    const frames = [];
    for await (const frame of readSseStream(stream)) frames.push(frame);

    expect(frames[0]?.data).toBe('café');
  });

  it('stops when the caller aborts', async () => {
    const controller = new AbortController();
    const stream = streamOf(['event: a\ndata: 1\n\n', 'event: b\ndata: 2\n\n']);

    const seen: string[] = [];
    for await (const frame of readSseStream(stream, controller.signal)) {
      seen.push(frame.event);
      controller.abort();
    }

    expect(seen).toEqual(['a']);
  });
});
