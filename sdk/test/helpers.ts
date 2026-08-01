import type { Transport, TransportRequest, TransportResponse } from '../src/transport.js';

export interface RecordedRequest extends TransportRequest {}

export interface StubResponse {
  status?: number;
  body?: unknown;
  /** Raw body, when you need to exercise the non-JSON path. */
  text?: string;
  headers?: Record<string, string>;
}

/**
 * A transport that answers from a queue and records what it was asked.
 *
 * This is also the documented testing recipe for consumers: the SDK never
 * reaches past its transport, so a host can stub either this or `global.fetch`
 * and see everything.
 */
export function mockTransport(responses: StubResponse[]): {
  transport: Transport;
  requests: RecordedRequest[];
} {
  const requests: RecordedRequest[] = [];
  const queue = [...responses];
  const transport: Transport = async (req) => {
    requests.push({ ...req });
    const next = queue.shift();
    if (!next) throw new Error(`mockTransport: no queued response for ${req.method} ${req.path}`);
    return stubResponse(next);
  };
  return { transport, requests };
}

export function stubResponse(stub: StubResponse): TransportResponse {
  const headers = new Map(
    Object.entries(stub.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
  );
  const text = stub.text ?? (stub.body === undefined ? '' : JSON.stringify(stub.body));
  return {
    status: stub.status ?? 200,
    headers: { get: (name: string) => headers.get(name.toLowerCase()) ?? null },
    text: async () => text,
  };
}

/** A minimal `ApprovalResponse` with only the fields a test cares about set. */
export function approvalFixture(
  overrides: Partial<import('../src/types/approvals.js').ApprovalResponse> = {},
): import('../src/types/approvals.js').ApprovalResponse {
  return {
    id: 'a1111111-1111-1111-1111-111111111111',
    identity_id: 'i1111111-1111-1111-1111-111111111111',
    requesting_identity_id: 'i1111111-1111-1111-1111-111111111111',
    current_resolver_identity_id: 'u1111111-1111-1111-1111-111111111111',
    identity_path: 'spiffe://acme/user/alice/agent/henry',
    identity_path_ids: [],
    action_summary: 'Send an email to jane@example.com',
    tags: [],
    permission_keys: ['email:send:recipient=jane@example.com'],
    derived_keys: [
      {
        service: 'email',
        action: 'send',
        arg: 'recipient=jane@example.com',
        label: 'recipient',
        value: 'jane@example.com',
      },
    ],
    suggested_tiers: [{ keys: ['email:send:*'], description: 'Any recipient' }],
    action_detail: null,
    action_detail_truncated: false,
    action_detail_size_bytes: 0,
    disclosed_fields: null,
    status: 'pending',
    token: 'tok',
    expires_at: new Date(Date.now() + 600_000).toISOString(),
    created_at: new Date().toISOString(),
    risk: 'med',
    ...overrides,
  };
}
