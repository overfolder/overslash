/**
 * `OverslashClient` — the one object an integration holds.
 *
 * Three auth modes, and the mode decides whether the client ever touches a
 * credential:
 *
 * - `{ apiKey }`     server-side; the only mode that carries `X-Overslash-As`
 * - `{ token }`      browser; a short-lived widget token, re-minted on expiry
 * - `{ transport }`  browser; the host proxies and the SDK holds nothing
 */

import { toApiError } from './errors.js';
import {
  createBearerTransport,
  type FetchLike,
  type Transport,
  type TransportRequest,
  type TransportResponse,
} from './transport.js';
import { ApprovalsResource } from './resources/approvals.js';
import { ActionsResource } from './resources/actions.js';
import { SecretsResource } from './resources/secrets.js';
import { SecretRequestsResource } from './resources/secret-requests.js';
import { ConnectionsResource } from './resources/connections.js';
import { ServicesResource } from './resources/services.js';
import { EventsResource } from './resources/events.js';
import type { WhoamiResponse } from './types/identity.js';

/** A token, or a function that mints one. The function form survives expiry. */
export type TokenSource = string | (() => string | Promise<string>);

export type AuthConfig =
  | { apiKey: string }
  | { token: TokenSource }
  | { transport: Transport };

export interface OverslashClientOptions {
  /**
   * Gateway origin, e.g. `https://api.overslash.com`. Required for `apiKey`
   * and `token` modes; ignored in `transport` mode, where the host owns the URL.
   */
  baseUrl?: string;
  auth: AuthConfig;
  /**
   * `X-Overslash-As` — impersonate a user or an agent beneath one, by email,
   * UUID, or path (`alice@acme.com/support-agent`). Identities are provisioned
   * on first use.
   *
   * Only meaningful alongside an API key. A browser must never send this: a
   * widget token names its own identity in its claims, and an API key in a
   * browser is an org-wide credential leak. In `transport` mode the header is
   * still passed to the host's proxy, which is the trust boundary and should
   * validate or overwrite it.
   */
  as?: string;
  /** Injected for tests and for hosts that wrap `fetch`. Defaults to global. */
  fetch?: FetchLike;
  /** Appended to `X-Overslash-Client` for server-side attribution. */
  userAgent?: string;
}

export interface RequestOptions {
  signal?: AbortSignal;
}

const SDK_VERSION = '0.1.0';

export class OverslashClient {
  readonly approvals: ApprovalsResource;
  readonly actions: ActionsResource;
  readonly secrets: SecretsResource;
  readonly secretRequests: SecretRequestsResource;
  readonly connections: ConnectionsResource;
  readonly services: ServicesResource;
  readonly events: EventsResource;

  private readonly transport: Transport;
  private readonly impersonate?: string;
  private readonly clientLabel: string;
  /** Set only in `{ token }` mode, where a 401 is worth one silent retry. */
  private readonly refreshToken?: () => Promise<string>;

  constructor(options: OverslashClientOptions) {
    const { transport, refreshToken } = buildTransport(options);
    this.transport = transport;
    this.refreshToken = refreshToken;
    this.impersonate = options.as;
    this.clientLabel = options.userAgent
      ? `overslash-sdk/${SDK_VERSION} ${options.userAgent}`
      : `overslash-sdk/${SDK_VERSION}`;

    this.approvals = new ApprovalsResource(this);
    this.actions = new ActionsResource(this);
    this.secrets = new SecretsResource(this);
    this.secretRequests = new SecretRequestsResource(this);
    this.connections = new ConnectionsResource(this);
    this.services = new ServicesResource(this);
    this.events = new EventsResource(this);
  }

  /**
   * A client that acts as another identity. Cheap — it shares this client's
   * transport, so a per-request `as` costs nothing but an object.
   */
  as(identity: string): OverslashClient {
    const derived = Object.create(OverslashClient.prototype) as Mutable<OverslashClient>;
    Object.assign(derived, this, { impersonate: identity });
    // The resources close over their client, so they must be rebuilt to see
    // the new identity rather than the one they were constructed with.
    derived.approvals = new ApprovalsResource(derived as OverslashClient);
    derived.actions = new ActionsResource(derived as OverslashClient);
    derived.secrets = new SecretsResource(derived as OverslashClient);
    derived.secretRequests = new SecretRequestsResource(derived as OverslashClient);
    derived.connections = new ConnectionsResource(derived as OverslashClient);
    derived.services = new ServicesResource(derived as OverslashClient);
    derived.events = new EventsResource(derived as OverslashClient);
    return derived as OverslashClient;
  }

  /**
   * `GET /v1/whoami` — works on any identity-bound credential, unlike
   * `/auth/me`, which needs a session cookie. The SDK's connectivity check.
   */
  whoami(opts: RequestOptions = {}): Promise<WhoamiResponse> {
    return this.request<WhoamiResponse>('GET', '/v1/whoami', undefined, opts);
  }

  /** @internal */
  async request<T>(
    method: string,
    path: string,
    body?: unknown,
    opts: RequestOptions = {},
  ): Promise<T> {
    const res = await this.send(method, path, body, opts);

    if (res.status === 204) return undefined as T;

    const text = await res.text();
    const parsed = parseBody(text);

    if (res.status < 200 || res.status >= 300) throw toApiError(res.status, parsed);
    return parsed as T;
  }

  /**
   * @internal Raw send, used by `request` and by the stream (which must keep
   * the response body unread).
   */
  async send(
    method: string,
    path: string,
    body?: unknown,
    opts: RequestOptions & { stream?: boolean; headers?: Record<string, string> } = {},
  ): Promise<TransportResponse> {
    const req: TransportRequest = {
      method,
      path,
      headers: this.headers(opts.headers),
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      ...(opts.signal ? { signal: opts.signal } : {}),
      ...(opts.stream ? { stream: true } : {}),
    };

    let res = await this.transport(req);

    // One silent retry on a stale widget token. Only in `{ token }` mode, and
    // only for the gateway's *own* 401 — a service-auth envelope
    // (needs_authentication / reauth_required) means the target service needs
    // reconnecting, not that our credential expired.
    if (res.status === 401 && this.refreshToken) {
      const text = await res.text();
      const parsed = parseBody(text);
      if (!isServiceAuthEnvelope(parsed)) {
        await this.refreshToken();
        res = await this.transport(req);
      } else {
        return replayed(res, text);
      }
    }

    return res;
  }

  private headers(extra?: Record<string, string>): Record<string, string> {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      accept: 'application/json',
      'x-overslash-client': this.clientLabel,
      ...extra,
    };
    if (this.impersonate) headers['x-overslash-as'] = this.impersonate;
    return headers;
  }
}

type Mutable<T> = { -readonly [K in keyof T]: T[K] };

function buildTransport(options: OverslashClientOptions): {
  transport: Transport;
  refreshToken?: () => Promise<string>;
} {
  if ('transport' in options.auth) {
    return { transport: options.auth.transport };
  }

  const baseUrl = options.baseUrl;
  if (!baseUrl) {
    throw new Error('OverslashClient: `baseUrl` is required unless you supply a transport');
  }
  const fetchImpl = options.fetch ?? defaultFetch();

  if ('apiKey' in options.auth) {
    const key = options.auth.apiKey;
    return {
      transport: createBearerTransport({
        baseUrl,
        fetch: fetchImpl,
        authorization: async () => `Bearer ${key}`,
      }),
    };
  }

  const source = options.auth.token;
  let cached: string | undefined = typeof source === 'string' ? source : undefined;
  const mint = async (): Promise<string> => {
    if (typeof source === 'string') return source;
    cached = await source();
    return cached;
  };
  return {
    transport: createBearerTransport({
      baseUrl,
      fetch: fetchImpl,
      authorization: async () => `Bearer ${cached ?? (await mint())}`,
    }),
    // A string token cannot be refreshed; only re-invoke a supplied function.
    ...(typeof source === 'function' ? { refreshToken: mint } : {}),
  };
}

function defaultFetch(): FetchLike {
  const f = globalThis.fetch;
  if (!f) {
    throw new Error(
      'OverslashClient: no global fetch. Pass `fetch` explicitly (Node 18+ has it built in).',
    );
  }
  return ((input, init) => f(input, init as RequestInit)) as FetchLike;
}

/**
 * Read the body once, then try to parse it.
 *
 * Calling `.json()` and falling back to `.text()` blows up on an empty 404: the
 * stream is already consumed. The dashboard learned this the hard way.
 */
function parseBody(text: string): unknown {
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function isServiceAuthEnvelope(body: unknown): boolean {
  if (!body || typeof body !== 'object') return false;
  const code = (body as { error?: unknown }).error;
  return code === 'needs_authentication' || code === 'reauth_required';
}

/** Re-wrap a response whose body we already consumed while deciding to retry. */
function replayed(res: TransportResponse, text: string): TransportResponse {
  return {
    status: res.status,
    headers: res.headers,
    text: async () => text,
  };
}
