import type { OverslashClient, RequestOptions } from '../client.js';
import type { ServiceSummary } from '../types/identity.js';

export class ServicesResource {
  constructor(private readonly client: OverslashClient) {}

  list(opts: RequestOptions = {}): Promise<ServiceSummary[]> {
    return this.client.request('GET', '/v1/services', undefined, opts);
  }

  /** Discovery across the catalog and the caller's own instances. */
  search(query: string, opts: RequestOptions = {}): Promise<unknown> {
    const qs = new URLSearchParams({ q: query }).toString();
    return this.client.request('GET', `/v1/search?${qs}`, undefined, opts);
  }
}
