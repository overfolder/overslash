import type { OverslashClient, RequestOptions } from '../client.js';
import type { ServiceSummary } from '../types/identity.js';
import type { ServiceActivateResponse, ServiceTestResponse } from '../types/services.js';

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

  /**
   * Run the probe and, if it passes, make the instance callable.
   *
   * The promoting half of {@link test}, and a separate call on purpose:
   * `/test` is a diagnostic that an org admin may run against instances they
   * do not own, so promoting there would let an admin silently publish other
   * people's unverified drafts.
   *
   * Every outcome is a `200`, a red verdict included — "your credential does
   * not work" is the answer to the question, not a failure to answer it. Read
   * `status` for whether the service is live; do not infer it from the
   * verdict, which is absent entirely when `force` skipped the probe.
   *
   * `force: true` is "activate anyway": no probe runs, and the bypass is
   * recorded on the audit trail.
   *
   * Instance **id**, never the name — a service awaiting setup does not
   * resolve by name, which is the point of the status.
   */
  activate(
    id: string,
    { force, ...opts }: RequestOptions & { force?: boolean } = {},
  ): Promise<ServiceActivateResponse> {
    const qs = force ? '?force=true' : '';
    return this.client.request(
      'POST',
      `/v1/services/${encodeURIComponent(id)}/activate${qs}`,
      undefined,
      opts,
    );
  }
}
