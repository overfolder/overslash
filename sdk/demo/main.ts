/**
 * Demo wiring.
 *
 * Two modes. With `?live=1` it talks to a real stack — sign in through
 * `/auth/dev/token` first — so the screenshots show what the elements actually
 * render against the API. Without it, a fixture, so the page is useful with no
 * backend at all.
 */

import { OverslashClient, createSameOriginTransport } from '../src/index.js';
import { SseEvents, PollingEvents } from '../src/controllers/index.js';
import { defineOverslashElements } from '../src/elements/index.js';
import type { OverslashApprovalCard } from '../src/elements/approval-card.js';
import type { OverslashContext } from '../src/elements/context.js';
import type { ApprovalResponse } from '../src/types/approvals.js';

defineOverslashElements();

const live = new URLSearchParams(location.search).has('live');

const client = new OverslashClient({
  // Same-origin through the Vite proxy, so the dev session cookie is first-party
  // — the arrangement the dashboard uses, and the one a host proxying on its own
  // domain would have.
  auth: { transport: createSameOriginTransport({ fetch: window.fetch.bind(window) }) },
});

const context: OverslashContext = {
  client,
  events: live ? new SseEvents(client) : new PollingEvents(),
};

const provider = document.getElementById('provider') as HTMLElement & {
  context: OverslashContext;
};
provider.context = context;

/** A representative approval: two recipients, a hero field, a real payload. */
const FIXTURE: ApprovalResponse = {
  id: '5f1c1f2e-0000-4000-8000-000000000001',
  identity_id: '5f1c1f2e-0000-4000-8000-000000000010',
  requesting_identity_id: '5f1c1f2e-0000-4000-8000-000000000010',
  current_resolver_identity_id: '5f1c1f2e-0000-4000-8000-000000000011',
  identity_path: 'spiffe://acme/user/alice/agent/support-bot',
  identity_path_ids: [],
  action_summary: 'Send a refund confirmation to two customers',
  tags: ['service:email', 'email:write'],
  permission_keys: [
    'email:send:recipient=jane@example.com',
    'email:send:recipient=sam@example.com',
  ],
  derived_keys: [
    {
      service: 'email',
      action: 'send',
      arg: 'recipient=jane@example.com',
      label: 'recipient',
      value: 'jane@example.com',
    },
    {
      service: 'email',
      action: 'send',
      arg: 'recipient=sam@example.com',
      label: 'recipient',
      value: 'sam@example.com',
    },
  ],
  suggested_tiers: [
    { keys: ['email:send:recipient=jane@example.com'], description: 'This recipient only' },
    { keys: ['email:send:*'], description: 'Any recipient' },
  ],
  action_detail: JSON.stringify(
    {
      to: ['jane@example.com', 'sam@example.com'],
      subject: 'Your refund has been processed',
      body: 'Hi — your refund of £42.00 is on its way and should arrive in 3–5 days.',
    },
    null,
    2,
  ),
  action_detail_truncated: false,
  action_detail_size_bytes: 214,
  disclosed_fields: [
    { label: 'Subject', value: 'Your refund has been processed', error: null, truncated: false, primary: true },
    { label: 'Recipients', value: 'jane@example.com, sam@example.com', error: null, truncated: false },
    { label: 'Attachments', value: null, error: null, truncated: false },
  ],
  status: 'pending',
  token: '',
  expires_at: new Date(Date.now() + 15 * 60_000).toISOString(),
  created_at: new Date().toISOString(),
  risk: 'med',
};

for (const [id, risk] of [
  ['card-default', 'med'],
  ['card-branded', 'low'],
  ['card-parted', 'high'],
  ['card-dark', 'med'],
] as const) {
  const card = document.getElementById(id) as OverslashApprovalCard;
  card.approval = { ...FIXTURE, risk };
}

if (!live) {
  // Without a backend the list and prompt have nothing to fetch; say so rather
  // than leaving two silent boxes.
  document.getElementById('list')?.setAttribute('hidden', '');
  document.getElementById('secret')?.setAttribute('hidden', '');
  for (const id of ['s-list', 's-secret']) {
    const note = document.createElement('p');
    note.className = 'note';
    note.textContent = 'Add ?live=1 with the e2e stack running to see this.';
    document.getElementById(id)?.appendChild(note);
  }
}

// Surfaced so the screenshot script can wait on a settled page, and so a human
// poking at the demo can see the events flowing.
for (const type of ['resolved', 'submitted', 'connected', 'error', 'needs-external-auth']) {
  document.addEventListener(type, (e) => {
    console.info(`[demo] ${type}`, (e as CustomEvent).detail);
  });
}
