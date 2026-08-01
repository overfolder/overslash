import { afterEach, describe, expect, it, vi } from 'vitest';
import { OverslashClient } from '../src/client.js';
import { createApprovalController, fromPendingCall } from '../src/controllers/approval.js';
import { createApprovalListController } from '../src/controllers/approval-list.js';
import { createProvideController } from '../src/controllers/provide.js';
import { createConnectController } from '../src/controllers/connect.js';
import { waitForApproval } from '../src/controllers/wait-for-approval.js';
import { WaitTimeoutError } from '../src/errors.js';
import type { EventsTransport } from '../src/controllers/events.js';
import type { EventEnvelope } from '../src/types/events.js';
import type { Transport } from '../src/transport.js';
import { approvalFixture, stubResponse, type StubResponse } from './helpers.js';

afterEach(() => vi.useRealTimers());

/** A transport that answers by (method, path) prefix, with a call log. */
function routed(routes: Array<[string, StubResponse | (() => StubResponse)]>) {
  const calls: string[] = [];
  const transport: Transport = async (req) => {
    const key = `${req.method} ${req.path}`;
    calls.push(key);
    for (const [prefix, stub] of routes) {
      if (key.startsWith(prefix)) {
        return stubResponse(typeof stub === 'function' ? stub() : stub);
      }
    }
    throw new Error(`routed: no stub for ${key}`);
  };
  return { transport, calls };
}

/** An `EventsTransport` a test can push events into. */
function fakeEvents(
  live = true,
): EventsTransport & { emit(event: EventEnvelope): void; subscriberCount(): number } {
  const subs = new Set<{ types: Set<string>; handler: (e: EventEnvelope) => void }>();
  return {
    live,
    status: live ? 'live' : 'down',
    subscribe(types, handler) {
      const sub = { types: new Set(types), handler: handler as (e: EventEnvelope) => void };
      subs.add(sub);
      return () => subs.delete(sub);
    },
    onStatusChange: () => () => {},
    close: () => {},
    emit(event) {
      for (const sub of subs) if (sub.types.has(event.type)) sub.handler(event);
    },
    subscriberCount: () => subs.size,
  };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

describe('createApprovalController', () => {
  it('adopts the server response optimistically on resolve', async () => {
    const seed = approvalFixture();
    const resolved = approvalFixture({ status: 'allowed' });
    const { transport } = routed([['POST /v1/approvals/', { body: resolved }]]);
    const client = new OverslashClient({ auth: { transport } });

    const ctrl = createApprovalController(client, { approval: seed });
    expect(ctrl.getState().isPending).toBe(true);

    await ctrl.resolve({ resolution: 'allow' });

    expect(ctrl.getState().approval?.status).toBe('allowed');
    expect(ctrl.getState().submitting).toBe(false);
    ctrl.dispose();
  });

  it('keeps a failed resolve visible without clobbering the approval', async () => {
    const { transport } = routed([
      ['POST /v1/approvals/', { status: 403, body: { error: 'not in your chain' } }],
    ]);
    const client = new OverslashClient({ auth: { transport } });
    const ctrl = createApprovalController(client, { approval: approvalFixture() });

    await ctrl.resolve({ resolution: 'allow' });

    expect(ctrl.getState().error).toBe('not in your chain');
    expect(ctrl.getState().approval?.status).toBe('pending');
    ctrl.clearError();
    expect(ctrl.getState().error).toBeNull();
    ctrl.dispose();
  });

  it('refetches when an event names its approval, and ignores other approvals', async () => {
    const { transport, calls } = routed([['GET /v1/approvals/', { body: approvalFixture() }]]);
    const client = new OverslashClient({ auth: { transport } });
    const events = fakeEvents();
    const approval = approvalFixture();
    const ctrl = createApprovalController(client, { approval, events });

    events.emit({ id: '1', type: 'approval.resolved', created_at: '', data: { approval_id: 'other' } });
    await flush();
    expect(calls).toHaveLength(0);

    events.emit({
      id: '2',
      type: 'approval.resolved',
      created_at: '',
      data: { approval_id: approval.id },
    });
    await flush();
    expect(calls).toEqual([`GET /v1/approvals/${approval.id}`]);
    ctrl.dispose();
  });

  it('refetches on stream.resync, which names no approval at all', async () => {
    const { transport, calls } = routed([['GET /v1/approvals/', { body: approvalFixture() }]]);
    const client = new OverslashClient({ auth: { transport } });
    const events = fakeEvents();
    const ctrl = createApprovalController(client, { approval: approvalFixture(), events });

    events.emit({ id: '', type: 'stream.resync', created_at: '', data: {} });
    await flush();

    expect(calls).toHaveLength(1);
    ctrl.dispose();
  });

  it('polls a non-terminal execution, and stops once it settles', async () => {
    vi.useFakeTimers();
    let current = approvalFixture({
      status: 'allowed',
      execution: {
        id: 'x1',
        status: 'executing',
        expires_at: '',
        created_at: '',
        output_read: false,
      },
    });
    const { transport, calls } = routed([['GET /v1/approvals/', () => ({ body: current })]]);
    const client = new OverslashClient({ auth: { transport } });
    // No events transport: this is the fallback path.
    const ctrl = createApprovalController(client, { approval: current });

    await vi.advanceTimersByTimeAsync(1600);
    expect(calls.length).toBeGreaterThanOrEqual(1);

    current = approvalFixture({
      status: 'allowed',
      execution: {
        id: 'x1',
        status: 'executed',
        expires_at: '',
        created_at: '',
        output_read: false,
      },
    });
    await vi.advanceTimersByTimeAsync(1600);
    const afterSettled = calls.length;

    await vi.advanceTimersByTimeAsync(5000);
    expect(calls.length).toBe(afterSettled);
    expect(ctrl.getState().executionTerminal).toBe(true);
    ctrl.dispose();
  });

  it('does not poll while the stream is live', async () => {
    vi.useFakeTimers();
    const approval = approvalFixture({
      status: 'allowed',
      execution: {
        id: 'x1',
        status: 'executing',
        expires_at: '',
        created_at: '',
        output_read: false,
      },
    });
    const { transport, calls } = routed([['GET /v1/approvals/', { body: approval }]]);
    const client = new OverslashClient({ auth: { transport } });
    const ctrl = createApprovalController(client, { approval, events: fakeEvents(true) });

    await vi.advanceTimersByTimeAsync(10_000);

    expect(calls).toHaveLength(0);
    ctrl.dispose();
  });

  it('gives up polling after the wall-clock deadline', async () => {
    vi.useFakeTimers();
    const approval = approvalFixture({
      status: 'allowed',
      execution: {
        id: 'x1',
        status: 'executing',
        expires_at: '',
        created_at: '',
        output_read: false,
      },
    });
    const { transport, calls } = routed([['GET /v1/approvals/', { body: approval }]]);
    const client = new OverslashClient({ auth: { transport } });
    const ctrl = createApprovalController(client, { approval });

    await vi.advanceTimersByTimeAsync(31_000);
    const atDeadline = calls.length;
    // It really did poll before giving up — otherwise this asserts nothing.
    expect(atDeadline).toBeGreaterThan(0);
    await vi.advanceTimersByTimeAsync(10_000);

    expect(calls.length).toBe(atDeadline);
    ctrl.dispose();
  });

  it('requires an approval or an id', () => {
    const { transport } = routed([]);
    const client = new OverslashClient({ auth: { transport } });
    expect(() => createApprovalController(client, {})).toThrow(/approval.*or.*id/);
  });
});

describe('fromPendingCall', () => {
  it('renders from the call result without inventing fields it does not have', () => {
    const approval = fromPendingCall({
      status: 'pending_approval',
      approval_id: 'a9',
      approval_url: 'https://x',
      action_description: 'Send an email',
      expires_at: '2026-01-01T00:00:00Z',
      relationship: 'self',
      suggested_tiers: [{ keys: ['email:send:*'], description: 'Any' }],
      risk: 'high',
      permission_keys: ['email:send:recipient=a@b.c'],
      action_detail_truncated: false,
      action_detail_size_bytes: 0,
    });

    expect(approval.id).toBe('a9');
    expect(approval.risk).toBe('high');
    expect(approval.status).toBe('pending');
    // Not carried by the call result — left empty rather than guessed.
    expect(approval.derived_keys).toEqual([]);
    expect(approval.identity_path).toBeNull();
  });
});

describe('createApprovalListController', () => {
  it('debounces a burst of events into one refetch', async () => {
    vi.useFakeTimers();
    const { transport, calls } = routed([['GET /v1/approvals', { body: [] }]]);
    const client = new OverslashClient({ auth: { transport } });
    const events = fakeEvents();
    const ctrl = createApprovalListController(client, { events, debounceMs: 100 });

    await vi.advanceTimersByTimeAsync(0);
    const afterInitial = calls.length;

    for (let i = 0; i < 3; i += 1) {
      events.emit({ id: `${i}`, type: 'approval.pending', created_at: '', data: {} });
    }
    await vi.advanceTimersByTimeAsync(200);

    expect(calls.length).toBe(afterInitial + 1);
    ctrl.dispose();
  });

  it('drops a resolved row and everything its rule cascaded over', async () => {
    const rows = [approvalFixture({ id: 'a1' }), approvalFixture({ id: 'a2' }), approvalFixture({ id: 'a3' })];
    const { transport } = routed([['GET /v1/approvals', { body: rows }]]);
    const client = new OverslashClient({ auth: { transport } });
    const ctrl = createApprovalListController(client, {});
    await flush();

    // Those sibling rows are gone server-side; leaving them invites a 404.
    ctrl.dropResolved(approvalFixture({ id: 'a1', cascaded_approval_ids: ['a3'] }));

    expect(ctrl.getState().approvals.map((a) => a.id)).toEqual(['a2']);
    ctrl.dispose();
  });
});

describe('createProvideController', () => {
  it('maps 410 already_fulfilled apart from 410 expired', async () => {
    const fulfilled = routed([
      ['GET /public/secrets/provide/', { status: 410, body: { error: 'already_fulfilled' } }],
    ]);
    const c1 = new OverslashClient({ auth: { transport: fulfilled.transport } });
    const ctrl1 = createProvideController(c1, { reqId: 'req_1', token: 't' });
    await flush();
    expect(ctrl1.getState().status).toBe('already_fulfilled');

    const expired = routed([
      ['GET /public/secrets/provide/', { status: 410, body: { error: 'expired' } }],
    ]);
    const c2 = new OverslashClient({ auth: { transport: expired.transport } });
    const ctrl2 = createProvideController(c2, { reqId: 'req_1', token: 't' });
    await flush();
    expect(ctrl2.getState().status).toBe('expired');

    ctrl1.dispose();
    ctrl2.dispose();
  });

  it('reports a missing token without calling the server', async () => {
    const { transport, calls } = routed([]);
    const client = new OverslashClient({ auth: { transport } });
    const ctrl = createProvideController(client, { reqId: 'req_1' });
    await flush();

    expect(ctrl.getState().status).toBe('missing_token');
    expect(calls).toHaveLength(0);
    ctrl.dispose();
  });

  it('flags a signed-provide request with no session, so the form can gate itself', async () => {
    const { transport } = routed([
      [
        'GET /public/secrets/provide/',
        {
          body: {
            id: 'req_1',
            secret_name: 'stripe_key',
            identity_label: 'henry',
            requested_by_label: 'henry',
            reason: null,
            expires_at: '',
            created_at: '',
            require_user_session: true,
            viewer: null,
          },
        },
      ],
    ]);
    const client = new OverslashClient({ auth: { transport } });
    const ctrl = createProvideController(client, { reqId: 'req_1', token: 't' });
    await flush();

    expect(ctrl.getState().status).toBe('ready');
    expect(ctrl.getState().needsSignIn).toBe(true);
    ctrl.dispose();
  });

  it('leaves the form usable after a recoverable submit failure', async () => {
    const { transport } = routed([
      ['GET /public/secrets/provide/', { body: metadata() }],
      ['POST /public/secrets/provide/', { status: 500, body: { error: 'boom' } }],
    ]);
    const client = new OverslashClient({ auth: { transport } });
    const ctrl = createProvideController(client, { reqId: 'req_1', token: 't' });
    await flush();

    expect(await ctrl.submit('sk_live_x')).toBe(false);
    expect(ctrl.getState().status).toBe('ready');
    expect(ctrl.getState().error).toBeTruthy();
    ctrl.dispose();
  });

  it('ends the form when someone else fills the request first', async () => {
    const { transport } = routed([
      ['GET /public/secrets/provide/', { body: metadata() }],
      ['POST /public/secrets/provide/', { status: 410, body: { error: 'already_fulfilled' } }],
    ]);
    const client = new OverslashClient({ auth: { transport } });
    const ctrl = createProvideController(client, { reqId: 'req_1', token: 't' });
    await flush();

    await ctrl.submit('sk_live_x');

    expect(ctrl.getState().status).toBe('already_fulfilled');
    ctrl.dispose();
  });

  function metadata() {
    return {
      id: 'req_1',
      secret_name: 'stripe_key',
      identity_label: 'henry',
      requested_by_label: 'henry',
      reason: null,
      expires_at: '',
      created_at: '',
      require_user_session: false,
      viewer: null,
    };
  }
});

describe('createConnectController', () => {
  const connection = {
    id: 'c-new',
    owner_identity_id: 'u1',
    provider_key: 'google',
    account_email: 'a@b.c',
    scopes: [],
    used_by_service_templates: [],
    is_default: false,
    keep: false,
    reauth_required: false,
    created_at: '',
  };

  it('reports a blocked popup as state, with the URL still available', async () => {
    // Not an exception: the host can render the URL as a link, which browsers
    // allow because clicking it is a user gesture.
    const { transport } = routed([
      ['GET /v1/connections', { body: [] }],
      ['POST /v1/connections', { body: { auth_url: 'https://gate', state: 's', provider: 'google', expires_at: '', flow_id: 'f' } }],
    ]);
    const client = new OverslashClient({ auth: { transport } });
    const ctrl = createConnectController(client, { provider: 'google', openWindow: () => null });

    await ctrl.start();

    expect(ctrl.getState().status).toBe('popup_blocked');
    expect(ctrl.getState().authUrl).toBe('https://gate');
    ctrl.dispose();
  });

  it('hands a headless org to the host rather than opening a URL it does not have', async () => {
    const { transport } = routed([
      ['GET /v1/connections', { body: [] }],
      [
        'POST /v1/connections',
        {
          status: 401,
          body: {
            error: 'needs_authentication',
            headless: true,
            provider: 'google',
            required_scopes: ['gmail.send'],
          },
        },
      ],
    ]);
    const client = new OverslashClient({ auth: { transport } });
    const seen: unknown[] = [];
    const ctrl = createConnectController(client, {
      provider: 'google',
      openWindow: () => ({ closed: false, close() {} }),
      onNeedsExternalAuth: (info) => seen.push(info),
    });

    await ctrl.start();

    expect(ctrl.getState().status).toBe('needs_external_auth');
    expect(seen).toEqual([{ provider: 'google', requiredScopes: ['gmail.send'] }]);
    ctrl.dispose();
  });

  it('ignores connection events that arrive before the flow starts', async () => {
    // The controller subscribes at construction, so an unrelated connection
    // event can land first. Acting on it timed the flow out before it began —
    // and, because `beforeIds` was still empty, could even have reported a
    // pre-existing connection as the one just made.
    const { transport } = routed([['GET /v1/connections', { body: [connection] }]]);
    const client = new OverslashClient({ auth: { transport } });
    const events = fakeEvents();
    const ctrl = createConnectController(client, {
      provider: 'google',
      events,
      openWindow: () => ({ closed: false, close() {} }),
    });

    events.emit({
      id: '1',
      type: 'connection.created',
      created_at: '',
      data: { connection_id: 'someone-elses' },
    });
    await flush();

    expect(ctrl.getState().status).toBe('idle');
    expect(ctrl.getState().connection).toBeNull();
    ctrl.dispose();
  });

  it('keeps its event subscription after a cancelled attempt, so a retry is still live', async () => {
    const { transport } = routed([
      ['GET /v1/connections', { body: [] }],
      ['POST /v1/connections', { body: { auth_url: 'https://gate', state: 's', provider: 'google', expires_at: '', flow_id: 'f' } }],
    ]);
    const client = new OverslashClient({ auth: { transport } });
    const events = fakeEvents();
    const ctrl = createConnectController(client, {
      provider: 'google',
      events,
      openWindow: () => ({ closed: false, close() {} }),
    });

    ctrl.cancel();
    await flush();

    expect(events.subscriberCount()).toBe(1);
    ctrl.dispose();
    expect(events.subscriberCount()).toBe(0);
  });

  it('resolves once a connection appears that was not there before', async () => {
    vi.useFakeTimers();
    let listed: unknown[] = [];
    const { transport } = routed([
      ['GET /v1/connections', () => ({ body: listed })],
      ['POST /v1/connections', { body: { auth_url: 'https://gate', state: 's', provider: 'google', expires_at: '', flow_id: 'f' } }],
    ]);
    const client = new OverslashClient({ auth: { transport } });
    const ctrl = createConnectController(client, {
      provider: 'google',
      openWindow: () => ({ closed: false, close() {} }),
    });

    const started = ctrl.start();
    await vi.advanceTimersByTimeAsync(0);
    listed = [connection];
    await vi.advanceTimersByTimeAsync(1600);

    await expect(started).resolves.toMatchObject({ id: 'c-new' });
    expect(ctrl.getState().status).toBe('connected');
    ctrl.dispose();
  });
});

describe('waitForApproval', () => {
  it('returns as soon as it is already settled, without waiting a tick', async () => {
    const settled = approvalFixture({
      status: 'allowed',
      execution: { id: 'x', status: 'executed', expires_at: '', created_at: '', output_read: false },
    });
    const { transport } = routed([['GET /v1/approvals/', { body: settled }]]);
    const client = new OverslashClient({ auth: { transport } });

    await expect(waitForApproval(client, settled.id)).resolves.toMatchObject({ status: 'allowed' });
  });

  it('returns on a denial rather than waiting for an execution that never comes', async () => {
    const denied = approvalFixture({ status: 'denied' });
    const { transport } = routed([['GET /v1/approvals/', { body: denied }]]);
    const client = new OverslashClient({ auth: { transport } });

    await expect(waitForApproval(client, denied.id)).resolves.toMatchObject({ status: 'denied' });
  });

  it('wakes on a stream event instead of waiting out the poll interval', async () => {
    vi.useFakeTimers();
    let current = approvalFixture();
    const { transport } = routed([['GET /v1/approvals/', () => ({ body: current })]]);
    const client = new OverslashClient({ auth: { transport } });
    const events = fakeEvents();

    const pending = waitForApproval(client, current.id, { events, pollIntervalMs: 60_000 });
    await vi.advanceTimersByTimeAsync(0);

    current = approvalFixture({
      status: 'allowed',
      execution: { id: 'x', status: 'executed', expires_at: '', created_at: '', output_read: false },
    });
    events.emit({
      id: '1',
      type: 'approval.executed',
      created_at: '',
      data: { approval_id: current.id },
    });
    // Far less than the poll interval it would otherwise have waited.
    await vi.advanceTimersByTimeAsync(10);

    await expect(pending).resolves.toMatchObject({ status: 'allowed' });
  });

  it('times out rather than hanging a tool call forever', async () => {
    vi.useFakeTimers();
    const { transport } = routed([['GET /v1/approvals/', { body: approvalFixture() }]]);
    const client = new OverslashClient({ auth: { transport } });

    const pending = waitForApproval(client, 'a1', { timeoutMs: 3000, pollIntervalMs: 500 });
    const assertion = expect(pending).rejects.toBeInstanceOf(WaitTimeoutError);
    await vi.advanceTimersByTimeAsync(4000);
    await assertion;
  });
});
