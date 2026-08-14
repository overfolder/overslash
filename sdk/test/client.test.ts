import { describe, expect, it, vi } from 'vitest';
import { OverslashClient } from '../src/client.js';
import { ApiError, AuthActionError } from '../src/errors.js';
import { approvalFixture, mockTransport, stubResponse } from './helpers.js';
import type { FetchLike } from '../src/transport.js';

describe('OverslashClient', () => {
  it('sends JSON, parses JSON, and labels itself', async () => {
    const approval = approvalFixture();
    const { transport, requests } = mockTransport([{ body: [approval] }]);
    const client = new OverslashClient({ auth: { transport } });

    const got = await client.approvals.list();

    expect(got).toEqual([approval]);
    expect(requests[0]?.method).toBe('GET');
    expect(requests[0]?.headers['x-overslash-client']).toMatch(/^overslash-sdk\//);
  });

  it('defaults the approval scope to `assigned` rather than listing org-wide', async () => {
    const { transport, requests } = mockTransport([{ body: [] }]);
    const client = new OverslashClient({ auth: { transport } });

    await client.approvals.list();

    expect(requests[0]?.path).toBe('/v1/approvals?scope=assigned');
  });

  it('lists org-wide only when the caller explicitly opts out of a scope', async () => {
    const { transport, requests } = mockTransport([{ body: [] }]);
    const client = new OverslashClient({ auth: { transport } });

    await client.approvals.list({ scope: null, status: 'pending' });

    expect(requests[0]?.path).toBe('/v1/approvals?status=pending');
  });

  it('always opts into ?wrap=true so gated calls come back as values', async () => {
    const { transport, requests } = mockTransport([
      { body: { status: 'pending_approval', approval_id: 'a1' } },
    ]);
    const client = new OverslashClient({ auth: { transport } });

    const res = await client.actions.call({ service: 'email', action: 'send' });

    expect(requests[0]?.path).toBe('/v1/actions/call?wrap=true');
    expect(res.status).toBe('pending_approval');
  });

  it('sets X-Overslash-As from `as()` without mutating the parent client', async () => {
    const { transport, requests } = mockTransport([{ body: [] }, { body: [] }]);
    const client = new OverslashClient({ auth: { transport } });

    await client.as('alice@acme.com/support-agent').approvals.list();
    await client.approvals.list();

    expect(requests[0]?.headers['x-overslash-as']).toBe('alice@acme.com/support-agent');
    expect(requests[1]?.headers['x-overslash-as']).toBeUndefined();
  });

  it('sends an ASCII display name literally, so a name with a % survives', async () => {
    const { transport, requests } = mockTransport([{ body: [] }, { body: [] }]);
    const client = new OverslashClient({ auth: { transport } });

    await client.as('alice@acme.com', 'Alice Smith').approvals.list();
    await client.as('bob@acme.com', '50% Club').approvals.list();

    expect(requests[0]?.headers['x-overslash-as-name']).toBe('Alice Smith');
    expect(requests[1]?.headers['x-overslash-as-name']).toBe('50% Club');
  });

  it('encodes a non-ASCII display name, which fetch could not send raw', async () => {
    const { transport, requests } = mockTransport([{ body: [] }]);
    const client = new OverslashClient({ auth: { transport } });

    await client.as('jose@acme.com', 'José Álvarez').approvals.list();

    expect(requests[0]?.headers['x-overslash-as-name']).toBe("UTF-8''Jos%C3%A9%20%C3%81lvarez");
  });

  it('omits the name header when no name is given, and never leaks it to the parent', async () => {
    const { transport, requests } = mockTransport([{ body: [] }, { body: [] }]);
    const client = new OverslashClient({ auth: { transport }, as: 'root@acme.com' });

    await client.as('alice@acme.com', 'Alice Smith').approvals.list();
    await client.approvals.list();

    expect(requests[1]?.headers['x-overslash-as']).toBe('root@acme.com');
    expect(requests[1]?.headers['x-overslash-as-name']).toBeUndefined();
  });

  it('returns undefined for 204 instead of trying to parse an empty body', async () => {
    const { transport } = mockTransport([{ status: 204 }]);
    const client = new OverslashClient({ auth: { transport } });

    await expect(client.connections.delete('c1')).resolves.toBeUndefined();
  });

  it('surfaces a non-JSON error body as text rather than throwing on parse', async () => {
    const { transport } = mockTransport([{ status: 502, text: 'upstream exploded' }]);
    const client = new OverslashClient({ auth: { transport } });

    const err = await client.whoami().catch((e) => e);

    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(502);
    expect(err.body).toBe('upstream exploded');
  });

  it('requires a baseUrl unless a transport is supplied', () => {
    expect(() => new OverslashClient({ auth: { apiKey: 'osk_x' } })).toThrow(/baseUrl/);
  });
});

describe('bearer mode', () => {
  function fetchStub(responses: Parameters<typeof stubResponse>[0][]) {
    const calls: Array<{ url: string; init: Record<string, unknown> }> = [];
    const queue = [...responses];
    const fetchImpl: FetchLike = async (url, init) => {
      calls.push({ url, init: (init ?? {}) as Record<string, unknown> });
      const next = queue.shift();
      if (!next) throw new Error('fetchStub: out of responses');
      return stubResponse(next);
    };
    return { fetchImpl, calls };
  }

  it('attaches the API key and never sends cookies', async () => {
    const { fetchImpl, calls } = fetchStub([{ body: { org_id: 'o1' } }]);
    const client = new OverslashClient({
      baseUrl: 'https://api.example.com/',
      auth: { apiKey: 'osk_secret' },
      fetch: fetchImpl,
    });

    await client.whoami();

    expect(calls[0]?.url).toBe('https://api.example.com/v1/whoami');
    expect((calls[0]?.init.headers as Record<string, string>).authorization).toBe(
      'Bearer osk_secret',
    );
    expect(calls[0]?.init.credentials).toBe('omit');
  });

  it('re-mints a widget token once on a gateway 401 and retries', async () => {
    const { fetchImpl, calls } = fetchStub([
      { status: 401, body: { error: 'token expired' } },
      { body: { org_id: 'o1' } },
    ]);
    const mint = vi.fn().mockResolvedValueOnce('t1').mockResolvedValueOnce('t2');
    const client = new OverslashClient({
      baseUrl: 'https://api.example.com',
      auth: { token: mint },
      fetch: fetchImpl,
    });

    await client.whoami();

    expect(mint).toHaveBeenCalledTimes(2);
    expect((calls[0]?.init.headers as Record<string, string>).authorization).toBe('Bearer t1');
    expect((calls[1]?.init.headers as Record<string, string>).authorization).toBe('Bearer t2');
  });

  it('does not re-mint on a service-auth 401 — the credential is fine, the service is not', async () => {
    const { fetchImpl } = fetchStub([
      {
        status: 401,
        body: { error: 'needs_authentication', provider: 'google', auth_url: 'https://gate' },
      },
    ]);
    const mint = vi.fn().mockResolvedValue('t1');
    const client = new OverslashClient({
      baseUrl: 'https://api.example.com',
      auth: { token: mint },
      fetch: fetchImpl,
    });

    const err = await client.whoami().catch((e) => e);

    expect(err).toBeInstanceOf(AuthActionError);
    expect(err.kind).toBe('needs_authentication');
    // Once to sign the original request, and not again.
    expect(mint).toHaveBeenCalledTimes(1);
  });

  it('does not retry when the token is a plain string it cannot refresh', async () => {
    const { fetchImpl, calls } = fetchStub([{ status: 401, body: { error: 'expired' } }]);
    const client = new OverslashClient({
      baseUrl: 'https://api.example.com',
      auth: { token: 'static' },
      fetch: fetchImpl,
    });

    await expect(client.whoami()).rejects.toBeInstanceOf(ApiError);
    expect(calls).toHaveLength(1);
  });
});
