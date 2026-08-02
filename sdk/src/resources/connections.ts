import type { OverslashClient, RequestOptions } from '../client.js';
import type {
  ConnectionDetail,
  ConnectionSummary,
  InitiateConnectionRequest,
  InitiateConnectionResponse,
  OAuthProviderInfo,
  UpgradeScopesResponse,
} from '../types/connections.js';

export class ConnectionsResource {
  constructor(private readonly client: OverslashClient) {}

  list(opts: RequestOptions = {}): Promise<ConnectionSummary[]> {
    return this.client.request('GET', '/v1/connections', undefined, opts);
  }

  get(id: string, opts: RequestOptions = {}): Promise<ConnectionDetail> {
    return this.client.request('GET', `/v1/connections/${encodeURIComponent(id)}`, undefined, opts);
  }

  /**
   * Start an OAuth flow.
   *
   * The returned `auth_url` is always the Overslash-gated
   * `/connect-authorize?id=…` — the raw provider authorize URL is never
   * surfaced, so a chat message carrying it cannot be forwarded into someone
   * else's account. That gate requires an Overslash session, which is why a
   * white-label org whose end users have none runs headless instead (D21).
   */
  initiate(
    req: InitiateConnectionRequest,
    opts: RequestOptions = {},
  ): Promise<InitiateConnectionResponse> {
    return this.client.request('POST', '/v1/connections', req, opts);
  }

  upgradeScopes(
    id: string,
    scopes: string[],
    opts: RequestOptions = {},
  ): Promise<UpgradeScopesResponse> {
    return this.client.request(
      'POST',
      `/v1/connections/${encodeURIComponent(id)}/upgrade_scopes`,
      { scopes },
      opts,
    );
  }

  delete(id: string, opts: RequestOptions = {}): Promise<void> {
    return this.client.request(
      'DELETE',
      `/v1/connections/${encodeURIComponent(id)}`,
      undefined,
      opts,
    );
  }

  setDefault(id: string, opts: RequestOptions = {}): Promise<{ is_default: boolean }> {
    return this.client.request(
      'POST',
      `/v1/connections/${encodeURIComponent(id)}/set_default`,
      {},
      opts,
    );
  }

  /** Preserve this connection when a service bound to it is deleted. */
  setKeep(id: string, keep: boolean, opts: RequestOptions = {}): Promise<{ keep: boolean }> {
    return this.client.request(
      'POST',
      `/v1/connections/${encodeURIComponent(id)}/keep`,
      { keep },
      opts,
    );
  }

  providers(opts: RequestOptions = {}): Promise<OAuthProviderInfo[]> {
    return this.client.request('GET', '/v1/oauth-providers', undefined, opts);
  }
}
