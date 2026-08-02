/**
 * `@overslash/sdk` — embed Overslash approvals, secret requests and OAuth
 * connects in your own product.
 *
 * ```ts
 * // Server-side, acting for one of your users:
 * const overslash = new OverslashClient({ baseUrl, auth: { apiKey: process.env.OVERSLASH_KEY! } });
 * const res = await overslash.as('alice@acme.com/assistant').actions.call({
 *   service: 'gmail', action: 'send_email', params,
 * });
 * if (res.status === 'pending_approval') { … }
 * ```
 *
 * See `@overslash/sdk/controllers` for the headless state machines and
 * `@overslash/sdk/elements` for the custom elements.
 */

export { OverslashClient } from './client.js';
export type {
  AuthConfig,
  OverslashClientOptions,
  RequestOptions,
  TokenSource,
} from './client.js';

export {
  createBearerTransport,
  createSameOriginTransport,
} from './transport.js';
export type {
  FetchLike,
  Transport,
  TransportRequest,
  TransportResponse,
} from './transport.js';

export {
  ApiError,
  AuthActionError,
  PopupBlockedError,
  StreamVersionError,
  WaitTimeoutError,
  pickApiError,
  toApiError,
} from './errors.js';
export type { AuthActionKind } from './errors.js';

export type { ListApprovalsQuery } from './resources/approvals.js';
export type { OpenStreamOptions } from './resources/events.js';

export * from './types/index.js';
