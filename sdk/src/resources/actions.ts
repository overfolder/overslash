import type { OverslashClient, RequestOptions } from '../client.js';
import type { CallRequest, CallResponse } from '../types/actions.js';

export class ActionsResource {
  constructor(private readonly client: OverslashClient) {}

  /**
   * Invoke an action.
   *
   * Always sent with `?wrap=true`, which turns the gateway's own auth-401s into
   * a `200` discriminated union. So every expected outcome — executed, gated
   * behind an approval, denied, needs-connecting — is a **value** on the
   * returned union, and only transport failures, 5xx and permission denials
   * throw. An agent tool should not need a `try`/`catch` to discover that its
   * call needs a human.
   */
  call(req: CallRequest, opts: RequestOptions = {}): Promise<CallResponse> {
    return this.client.request('POST', '/v1/actions/call?wrap=true', req, opts);
  }

  /** Dry-run: validate params and permissions without executing. */
  validate(req: CallRequest, opts: RequestOptions = {}): Promise<unknown> {
    return this.client.request('POST', '/v1/actions/validate', req, opts);
  }
}
