/**
 * Transport — the single seam every request passes through.
 *
 * Two of the three auth modes build a bearer transport over `fetch`; the third
 * (`{ transport }`) is supplied wholesale by the host, which is what lets a
 * browser talk to Overslash without ever holding a credential, and what lets a
 * host with a "components never call fetch" rule keep it.
 */

export interface TransportRequest {
  method: string;
  /** Path and query only, e.g. `/v1/approvals?scope=assigned`. Never absolute. */
  path: string;
  headers: Record<string, string>;
  /** Pre-serialised body. Absent for GET/DELETE. */
  body?: string;
  signal?: AbortSignal;
  /**
   * True for the event stream. A proxying host must not buffer these: return
   * the response with its body stream intact.
   */
  stream?: boolean;
}

/**
 * A minimal response. `Response` satisfies this structurally, so a host proxy
 * can return whatever `fetch` gave it.
 */
export interface TransportResponse {
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
  /** Present for streaming responses. Null on platforms without streaming. */
  body?: ReadableStream<Uint8Array> | null;
}

export type Transport = (req: TransportRequest) => Promise<TransportResponse>;

export type FetchLike = (
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
    credentials?: 'omit' | 'same-origin' | 'include';
  },
) => Promise<TransportResponse>;

export interface BearerTransportOptions {
  baseUrl: string;
  /** Resolved per request, so a short-lived token can be re-minted. */
  authorization: () => Promise<string | undefined>;
  fetch: FetchLike;
}

/**
 * A transport that talks straight to the gateway with a bearer credential.
 *
 * `credentials: 'omit'` is deliberate: the session cookie is `SameSite=Lax` and
 * would not travel cross-site anyway, and sending credentials would force the
 * server's CORS layer to name an exact origin. Bearer-only keeps the widget
 * surface credential-less.
 */
export function createBearerTransport(opts: BearerTransportOptions): Transport {
  const base = opts.baseUrl.replace(/\/+$/, '');
  return async (req) => {
    const auth = await opts.authorization();
    const headers = { ...req.headers };
    if (auth) headers['authorization'] = auth;
    return opts.fetch(base + req.path, {
      method: req.method,
      headers,
      ...(req.body === undefined ? {} : { body: req.body }),
      ...(req.signal ? { signal: req.signal } : {}),
      credentials: 'omit',
    });
  };
}

/**
 * A transport for a host that proxies on its own origin, where the session
 * cookie is first-party and should be sent.
 */
export function createSameOriginTransport(opts: {
  basePath?: string;
  fetch: FetchLike;
}): Transport {
  const base = (opts.basePath ?? '').replace(/\/+$/, '');
  return async (req) =>
    opts.fetch(base + req.path, {
      method: req.method,
      headers: req.headers,
      ...(req.body === undefined ? {} : { body: req.body }),
      ...(req.signal ? { signal: req.signal } : {}),
      credentials: 'include',
    });
}
