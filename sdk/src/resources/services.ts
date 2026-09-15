import type { OverslashClient, RequestOptions } from '../client.js';
import type { ServiceSummary } from '../types/identity.js';
import type { ServiceTestResponse } from '../types/services.js';

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

  /**
   * Run the instance's template-declared credential probe.
   *
   * Takes the instance **id**, never its name: name resolution is
   * caller-scoped, so an org admin probing someone else's instance would miss
   * it. Which action runs is the template's business, not the caller's — that
   * is the whole reason this is an endpoint rather than a documented call.
   *
   * `status: 'not_supported'` means the template declares no probe, which is
   * why callers check `test_action` on the instance before offering a button.
   */
  test(id: string, opts: RequestOptions = {}): Promise<ServiceTestResponse> {
    return this.client.request(
      'POST',
      `/v1/services/${encodeURIComponent(id)}/test`,
      undefined,
      opts,
    );
  }
}
