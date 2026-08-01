import type { OverslashClient, RequestOptions } from '../client.js';
import type {
  CreateSecretRequest,
  CreateSecretRequestResponse,
  ProvideMetadata,
  SubmitProvideResponse,
} from '../types/secrets.js';

/**
 * The secret-request handshake: an agent blocked on a missing credential asks
 * for one, and a human provides it through a single-use, token-signed URL.
 *
 * `create` is a server-side call (it needs write access). The two `provide`
 * calls are **public** — they authenticate with the request's own token, not
 * with the client's credential — which is what lets a widget render the form
 * inline instead of sending the user to the Overslash dashboard.
 */
export class SecretRequestsResource {
  constructor(private readonly client: OverslashClient) {}

  create(
    body: CreateSecretRequest,
    opts: RequestOptions = {},
  ): Promise<CreateSecretRequestResponse> {
    return this.client.request('POST', '/v1/secrets/requests', body, opts);
  }

  /**
   * Read the request's public metadata.
   *
   * Errors are meaningful and stable here: `410 already_fulfilled`, `410`
   * expired, `400 invalid_token`, `404`. `createProvideController` maps them to
   * states rather than making every caller re-derive the state machine.
   */
  getProvide(
    reqId: string,
    token: string,
    opts: RequestOptions = {},
  ): Promise<ProvideMetadata> {
    const qs = new URLSearchParams({ token }).toString();
    return this.client.request(
      'GET',
      `/public/secrets/provide/${encodeURIComponent(reqId)}?${qs}`,
      undefined,
      opts,
    );
  }

  /**
   * Submit the value. Single-use: a second submit is `410 already_fulfilled`.
   *
   * The value goes straight into the vault encrypted and is never returned by
   * any endpoint, including this one.
   */
  submitProvide(
    reqId: string,
    token: string,
    value: string,
    opts: RequestOptions = {},
  ): Promise<SubmitProvideResponse> {
    return this.client.request(
      'POST',
      `/public/secrets/provide/${encodeURIComponent(reqId)}`,
      { token, value },
      opts,
    );
  }
}
