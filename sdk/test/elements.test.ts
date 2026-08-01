import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { OverslashClient } from '../src/client.js';
import { PollingEvents } from '../src/controllers/events.js';
import {
  configureOverslash,
  defineOverslashElements,
  resetOverslash,
} from '../src/elements/index.js';
import type { OverslashApprovalCard } from '../src/elements/approval-card.js';
import type { OverslashSecretPrompt } from '../src/elements/secret-prompt.js';
import type { Transport } from '../src/transport.js';
import { approvalFixture, stubResponse, type StubResponse } from './helpers.js';

beforeAll(() => defineOverslashElements());

afterEach(() => {
  document.body.innerHTML = '';
  resetOverslash();
});

function routed(routes: Array<[string, StubResponse | (() => StubResponse)]>) {
  const calls: string[] = [];
  const transport: Transport = async (req) => {
    calls.push(`${req.method} ${req.path}`);
    for (const [prefix, stub] of routes) {
      if (`${req.method} ${req.path}`.startsWith(prefix)) {
        return stubResponse(typeof stub === 'function' ? stub() : stub);
      }
    }
    throw new Error(`routed: no stub for ${req.method} ${req.path}`);
  };
  return { transport, calls };
}

function context(routes: Array<[string, StubResponse | (() => StubResponse)]>) {
  const { transport, calls } = routed(routes);
  const client = new OverslashClient({ auth: { transport } });
  // No stream in element tests: the poll fallback is the simpler path, and the
  // stream has its own suite.
  return { ctx: { client, events: new PollingEvents() }, calls };
}

const tick = () => new Promise((r) => setTimeout(r, 0));

describe('registration', () => {
  it('is idempotent, so a hot reload does not throw', () => {
    expect(() => defineOverslashElements()).not.toThrow();
    expect(customElements.get('overslash-approval-card')).toBeTruthy();
  });

  it('registers under a custom prefix, so two versions can coexist', () => {
    defineOverslashElements({ prefix: 'acme' });
    expect(customElements.get('acme-approval-card')).toBeTruthy();
  });
});

describe('<overslash-approval-card>', () => {
  it('renders a quiet placeholder rather than an error when unconfigured', async () => {
    const card = document.createElement('overslash-approval-card');
    document.body.appendChild(card);
    await tick();

    expect(card.shadowRoot?.textContent).toContain('No Overslash client configured');
  });

  it('renders the approval it is handed, without a round trip', async () => {
    const { ctx, calls } = context([]);
    const card = document.createElement('overslash-approval-card') as OverslashApprovalCard;
    card.context = ctx;
    card.approval = approvalFixture();
    document.body.appendChild(card);
    await tick();

    const html = card.shadowRoot?.textContent ?? '';
    expect(html).toContain('Send an email to jane@example.com');
    // The agent name, from the SPIFFE path.
    expect(html).toContain('henry');
    expect(calls).toHaveLength(0);
  });

  it('shows every permission key rather than a count', async () => {
    const { ctx } = context([]);
    const card = document.createElement('overslash-approval-card') as OverslashApprovalCard;
    card.context = ctx;
    card.approval = approvalFixture({
      permission_keys: ['email:send:recipient=a@x.com', 'email:send:recipient=b@x.com'],
    });
    document.body.appendChild(card);
    await tick();

    const keys = card.shadowRoot?.querySelectorAll('[part~="key"]');
    expect(keys).toHaveLength(2);
  });

  it('carries risk as a label, not only a colour', async () => {
    const { ctx } = context([]);
    const card = document.createElement('overslash-approval-card') as OverslashApprovalCard;
    card.context = ctx;
    card.approval = approvalFixture({ risk: 'high' });
    document.body.appendChild(card);
    await tick();

    expect(card.shadowRoot?.querySelector('[part~="risk-badge"]')?.textContent).toContain(
      'Destructive',
    );
  });

  it('resolves on click and reports what happened', async () => {
    const approval = approvalFixture();
    const { ctx, calls } = context([
      ['POST /v1/approvals/', { body: approvalFixture({ status: 'allowed' }) }],
    ]);
    const card = document.createElement('overslash-approval-card') as OverslashApprovalCard;
    card.context = ctx;
    card.approval = approval;
    document.body.appendChild(card);
    await tick();

    const events: CustomEvent[] = [];
    card.addEventListener('resolved', (e) => events.push(e as CustomEvent));

    card.shadowRoot?.querySelector<HTMLButtonElement>('[data-action="allow"]')?.click();
    await tick();
    await tick();

    expect(calls).toEqual([`POST /v1/approvals/${approval.id}/resolve`]);
    expect(events).toHaveLength(1);
    expect(events[0]?.detail.resolution).toBe('allow');
    expect(events[0]?.detail.message).toContain('Allowed once');
  });

  it('sends remember_keys only once a tier is chosen', async () => {
    const bodies: unknown[] = [];
    const transport: Transport = async (req) => {
      bodies.push(req.body ? JSON.parse(req.body) : undefined);
      return stubResponse({ body: approvalFixture({ status: 'allowed' }) });
    };
    const client = new OverslashClient({ auth: { transport } });
    const card = document.createElement('overslash-approval-card') as OverslashApprovalCard;
    card.context = { client, events: new PollingEvents() };
    card.approval = approvalFixture();
    document.body.appendChild(card);
    await tick();

    // Default is "just this once".
    card.shadowRoot?.querySelector<HTMLButtonElement>('[data-action="allow"]')?.click();
    await tick();
    expect(bodies[0]).toEqual({ resolution: 'allow' });

    // Choosing a tier switches the verb and carries its keys.
    card.approval = approvalFixture();
    await tick();
    card.shadowRoot?.querySelector<HTMLInputElement>('[data-action="tier-0"]')?.click();
    await tick();
    card.shadowRoot?.querySelector<HTMLButtonElement>('[data-action="allow"]')?.click();
    await tick();

    expect(bodies[1]).toEqual({
      resolution: 'allow_remember',
      remember_keys: ['email:send:*'],
    });
  });

  it('hides the controls when readonly', async () => {
    const { ctx } = context([]);
    const card = document.createElement('overslash-approval-card') as OverslashApprovalCard;
    card.context = ctx;
    card.approval = approvalFixture();
    card.setAttribute('readonly', '');
    document.body.appendChild(card);
    await tick();

    expect(card.shadowRoot?.querySelector('[data-action="allow"]')).toBeNull();
  });

  it('escapes a payload rather than letting it into the page as markup', async () => {
    const { ctx } = context([]);
    const card = document.createElement('overslash-approval-card') as OverslashApprovalCard;
    card.context = ctx;
    card.approval = approvalFixture({
      action_detail: JSON.stringify({ note: '<img src=x onerror=alert(1)>' }),
      action_detail_size_bytes: 42,
    });
    document.body.appendChild(card);
    await tick();

    // The literal text may appear — escaped — inside the <pre>. What must not
    // happen is it becoming an element: this payload came from an agent.
    expect(card.shadowRoot?.querySelector('img')).toBeNull();
    expect(card.shadowRoot?.querySelector('pre')?.innerHTML).toContain('&lt;img');
    expect(card.shadowRoot?.querySelector('pre')?.textContent).toContain('<img');
  });

  it('announces state changes in a live region', async () => {
    const { ctx } = context([]);
    const card = document.createElement('overslash-approval-card') as OverslashApprovalCard;
    card.context = ctx;
    card.approval = approvalFixture();
    document.body.appendChild(card);
    await tick();

    const live = card.shadowRoot?.querySelector('[aria-live="polite"]');
    expect(live?.textContent).toContain('Awaiting your decision');
  });

  it('takes copy overrides', async () => {
    const { ctx } = context([]);
    const card = document.createElement('overslash-approval-card') as OverslashApprovalCard;
    card.context = ctx;
    card.strings = { allow: 'Autoriser' };
    card.approval = approvalFixture();
    document.body.appendChild(card);
    await tick();

    expect(card.shadowRoot?.querySelector('[data-action="allow"]')?.textContent).toContain(
      'Autoriser',
    );
  });
});

describe('<overslash-approval-list>', () => {
  it('renders one card per approval and reports liveness', async () => {
    const { ctx } = context([['GET /v1/approvals', { body: [approvalFixture({ id: 'a1' }), approvalFixture({ id: 'a2' })] }]]);
    const list = document.createElement('overslash-approval-list');
    (list as unknown as { context: unknown }).context = ctx;
    document.body.appendChild(list);
    await tick();
    await tick();

    expect(list.shadowRoot?.querySelectorAll('overslash-approval-card')).toHaveLength(2);
    // No stream here, so the chip must not claim to be live.
    expect(list.shadowRoot?.querySelector('[part~="live"]')?.textContent).toContain('Auto-refresh');
  });

  it('renders an empty state that a host can slot into', async () => {
    const { ctx } = context([['GET /v1/approvals', { body: [] }]]);
    const list = document.createElement('overslash-approval-list');
    (list as unknown as { context: unknown }).context = ctx;
    document.body.appendChild(list);
    await tick();
    await tick();

    expect(list.shadowRoot?.querySelector('[part~="empty"]')).toBeTruthy();
    expect(list.shadowRoot?.querySelector('slot[name="empty"]')).toBeTruthy();
  });

  it('drops a resolved row without waiting for the refetch', async () => {
    const { ctx } = context([
      ['GET /v1/approvals', { body: [approvalFixture({ id: 'a1' }), approvalFixture({ id: 'a2' })] }],
      ['POST /v1/approvals/', { body: approvalFixture({ id: 'a1', status: 'allowed' }) }],
    ]);
    const list = document.createElement('overslash-approval-list');
    (list as unknown as { context: unknown }).context = ctx;
    document.body.appendChild(list);
    await tick();
    await tick();

    const first = list.shadowRoot?.querySelector<OverslashApprovalCard>('overslash-approval-card');
    first?.shadowRoot?.querySelector<HTMLButtonElement>('[data-action="allow"]')?.click();
    await tick();
    await tick();
    await tick();

    expect(list.shadowRoot?.querySelectorAll('overslash-approval-card')).toHaveLength(1);
  });
});

describe('<overslash-secret-prompt>', () => {
  const metadata = {
    id: 'req_1',
    secret_name: 'stripe_key',
    identity_label: 'henry',
    requested_by_label: 'henry',
    reason: 'To reconcile a refund',
    expires_at: '',
    created_at: '',
    require_user_session: false,
    viewer: null,
  };

  it('shows what is being asked for and why', async () => {
    const { ctx } = context([['GET /public/secrets/provide/', { body: metadata }]]);
    const prompt = document.createElement('overslash-secret-prompt') as OverslashSecretPrompt;
    prompt.context = ctx;
    prompt.setAttribute('req-id', 'req_1');
    prompt.setAttribute('token', 't');
    document.body.appendChild(prompt);
    await tick();
    await tick();

    const text = prompt.shadowRoot?.textContent ?? '';
    expect(text).toContain('stripe_key');
    expect(text).toContain('To reconcile a refund');
    expect(prompt.shadowRoot?.querySelector('input')?.type).toBe('password');
  });

  it('emits `submitted` without the value in it', async () => {
    const { ctx } = context([
      ['GET /public/secrets/provide/', { body: metadata }],
      ['POST /public/secrets/provide/', { body: { ok: true, name: 'stripe_key', version: 1 } }],
    ]);
    const prompt = document.createElement('overslash-secret-prompt') as OverslashSecretPrompt;
    prompt.context = ctx;
    prompt.setAttribute('req-id', 'req_1');
    prompt.setAttribute('token', 't');
    document.body.appendChild(prompt);
    await tick();
    await tick();

    const events: CustomEvent[] = [];
    prompt.addEventListener('submitted', (e) => events.push(e as CustomEvent));

    const input = prompt.shadowRoot?.querySelector('input');
    if (input) input.value = 'sk_live_supersecret';
    prompt.shadowRoot?.querySelector<HTMLButtonElement>('[data-action="submit"]')?.click();
    await tick();
    await tick();

    expect(events).toHaveLength(1);
    // The event bubbles through the host's whole DOM; the value must not.
    expect(JSON.stringify(events[0]?.detail)).not.toContain('supersecret');
    expect(prompt.shadowRoot?.textContent).toContain('Saved');
  });

  it('gates on sign-in when the org requires a signed provide', async () => {
    const { ctx } = context([
      ['GET /public/secrets/provide/', { body: { ...metadata, require_user_session: true } }],
    ]);
    const prompt = document.createElement('overslash-secret-prompt') as OverslashSecretPrompt;
    prompt.context = ctx;
    prompt.setAttribute('req-id', 'req_1');
    prompt.setAttribute('token', 't');
    document.body.appendChild(prompt);
    await tick();
    await tick();

    expect(prompt.shadowRoot?.querySelector('input')).toBeNull();
    expect(prompt.shadowRoot?.querySelector('slot[name="signin"]')).toBeTruthy();
  });
});

describe('<overslash-provider>', () => {
  it('supplies a context to descendants across the shadow boundary', async () => {
    const { ctx } = context([]);
    const provider = document.createElement('overslash-provider');
    (provider as unknown as { context: unknown }).context = ctx;
    const card = document.createElement('overslash-approval-card') as OverslashApprovalCard;
    provider.appendChild(card);
    document.body.appendChild(provider);
    card.approval = approvalFixture();
    await tick();

    expect(card.shadowRoot?.textContent).not.toContain('No Overslash client configured');
    expect(card.shadowRoot?.textContent).toContain('Send an email');
  });

  it('falls back to the global default when there is no provider', async () => {
    const { ctx } = context([]);
    configureOverslash(ctx);

    const card = document.createElement('overslash-approval-card') as OverslashApprovalCard;
    card.approval = approvalFixture();
    document.body.appendChild(card);
    await tick();

    expect(card.shadowRoot?.textContent).toContain('Send an email');
  });
});
