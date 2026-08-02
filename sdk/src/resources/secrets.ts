import type { OverslashClient, RequestOptions } from '../client.js';
import type {
  PutSecretResponse,
  SecretNameRow,
  SecretSummary,
} from '../types/secrets.js';

export class SecretsResource {
  constructor(private readonly client: OverslashClient) {}

  /**
   * List secret slots.
   *
   * The shape depends on who is asking: a user-kind caller gets
   * `SecretSummary`; an agent bearer gets `SecretNameRow`, which says a slot
   * exists and when it last rotated, and nothing else.
   */
  list(opts: RequestOptions = {}): Promise<Array<SecretSummary | SecretNameRow>> {
    return this.client.request('GET', '/v1/secrets', undefined, opts);
  }

  /**
   * Write a value. Every write creates a new version; the latest is injected.
   *
   * `on_behalf_of` writes at the owner-user level so every agent under that
   * user shares the slot — the same reasoning as connections.
   */
  put(
    name: string,
    value: string,
    options: { onBehalfOf?: string } = {},
    opts: RequestOptions = {},
  ): Promise<PutSecretResponse> {
    const body: Record<string, unknown> = { value };
    if (options.onBehalfOf) body['on_behalf_of'] = options.onBehalfOf;
    return this.client.request('PUT', `/v1/secrets/${encodeURIComponent(name)}`, body, opts);
  }

  delete(name: string, opts: RequestOptions = {}): Promise<void> {
    return this.client.request('DELETE', `/v1/secrets/${encodeURIComponent(name)}`, undefined, opts);
  }
}
