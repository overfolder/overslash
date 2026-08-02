import type { OverslashClient, RequestOptions } from '../client.js';
import type {
  ApprovalResponse,
  ApprovalScope,
  ApprovalStatus,
  ExecutionSummary,
  ResolveApprovalRequest,
} from '../types/approvals.js';

export interface ListApprovalsQuery {
  /**
   * Defaults to `assigned` — the inbox.
   *
   * Omitting the scope entirely lists **org-wide**, because that endpoint has
   * no ACL gate. The SDK never does that implicitly; pass `scope: null` if you
   * genuinely want the org-wide listing and hold an admin credential.
   */
  scope?: ApprovalScope | null;
  status?: ApprovalStatus;
  /** Approvals requested *by* this identity, for a hierarchy view. */
  identityId?: string;
}

export class ApprovalsResource {
  constructor(private readonly client: OverslashClient) {}

  list(query: ListApprovalsQuery = {}, opts: RequestOptions = {}): Promise<ApprovalResponse[]> {
    const params = new URLSearchParams();
    const scope = query.scope === undefined ? 'assigned' : query.scope;
    if (scope) params.set('scope', scope);
    if (query.status) params.set('status', query.status);
    if (query.identityId) params.set('identity_id', query.identityId);
    const qs = params.toString();
    return this.client.request('GET', `/v1/approvals${qs ? `?${qs}` : ''}`, undefined, opts);
  }

  get(id: string, opts: RequestOptions = {}): Promise<ApprovalResponse> {
    return this.client.request('GET', `/v1/approvals/${encodeURIComponent(id)}`, undefined, opts);
  }

  /**
   * Allow, deny, remember, or hand up the chain.
   *
   * `allow` returns as soon as the verdict is recorded — the replay runs in a
   * spawned task — so the execution reaching a terminal state arrives
   * out-of-band, over the event stream or a later fetch. That asymmetry is why
   * `createApprovalController` exists.
   */
  resolve(
    id: string,
    body: ResolveApprovalRequest,
    opts: RequestOptions = {},
  ): Promise<ApprovalResponse> {
    return this.client.request('POST', `/v1/approvals/${encodeURIComponent(id)}/resolve`, body, opts);
  }

  /** Replay an allowed approval explicitly. Needed when `auto_call_on_approve` is off. */
  call(id: string, opts: RequestOptions = {}): Promise<ApprovalResponse> {
    return this.client.request('POST', `/v1/approvals/${encodeURIComponent(id)}/call`, {}, opts);
  }

  cancel(id: string, opts: RequestOptions = {}): Promise<ApprovalResponse> {
    return this.client.request('POST', `/v1/approvals/${encodeURIComponent(id)}/cancel`, {}, opts);
  }

  /**
   * Fetch the execution result. **Marks it read** (`output_read`), which is what
   * drives the "called but output unread" surfaces — so do not call this
   * speculatively from a list view.
   */
  execution(id: string, opts: RequestOptions = {}): Promise<ExecutionSummary> {
    return this.client.request(
      'GET',
      `/v1/approvals/${encodeURIComponent(id)}/execution`,
      undefined,
      opts,
    );
  }
}
