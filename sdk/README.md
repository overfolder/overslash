# `@overslash/sdk`

Embed Overslash approvals, secret requests and OAuth connects in your own
product.

Zero runtime dependencies. Works in a browser, in Node ≥20, and through a proxy
on your own origin.

```bash
npm install @overslash/sdk
```

---

## Which half do you need?

Most integrations need both, and they are different jobs:

- **Server-side**, your backend calls actions as your users and reacts to
  webhooks. It holds the credential.
- **Browser-side**, your users see approval cards and credential prompts. It
  should hold as little as possible.

## Server-side

```ts
import { OverslashClient } from '@overslash/sdk';
import { waitForApproval } from '@overslash/sdk/node';

const overslash = new OverslashClient({
  baseUrl: 'https://api.overslash.com',
  auth: { apiKey: process.env.OVERSLASH_API_KEY! },
});

// Act as one of your users. Identities are provisioned on first use, so there
// is nothing to sync up front.
const asUser = overslash.as('alice@acme.com/support-agent');

const res = await asUser.actions.call({
  service: 'email',
  action: 'send',
  params: { to: 'jane@example.com', subject: 'Refund', body: '…' },
});

switch (res.status) {
  case 'called':
    return res.result;
  case 'pending_approval':
    // Everything an approval card renders is already here — no second fetch.
    showApprovalInYourUI(res);
    return waitForApproval(overslash, res.approval_id);
  case 'denied':
    return { error: res.reason };
  case 'needs_authentication':
  case 'reauth_required':
    return promptToConnect(res);
}
```

`actions.call` never throws for those outcomes — they are the API's normal
answers, not failures. Transport errors, 5xx and permission denials do throw.

### Blocking a tool call on a human

If your agent framework cannot pause mid-run, block inside the tool:

```ts
const res = await overslash.actions.call({ service, action, params });
if (res.status !== 'pending_approval') return res;

const final = await waitForApproval(overslash, res.approval_id, {
  timeoutMs: 120_000,
  events,           // optional; wakes on the event stream instead of polling
});

if (final.execution?.status === 'executed') {
  // Marks the output read, which is what clears "called but unread" surfaces.
  return overslash.approvals.execution(final.id);
}
```

### Webhooks

```ts
import { parseWebhookEvent, verifyWebhookSignature } from '@overslash/sdk/node';

app.post('/webhooks/overslash', express.raw({ type: '*/*' }), async (req, res) => {
  const ok = await verifyWebhookSignature({
    payload: req.body,                              // the RAW bytes
    signature: req.get('x-overslash-signature')!,
    secret: process.env.OVERSLASH_WEBHOOK_SECRET!,
  });
  if (!ok) return res.sendStatus(401);

  const event = parseWebhookEvent(req.body.toString('utf8'));
  // approval.created | approval.pending | approval.bubbled | approval.resolved
  // approval.executed | approval.execution_failed | approval.execution_cancelled
  // connection.* | secret_request.*
  res.sendStatus(204);
});
```

The signature is over the **raw body bytes**. Re-serialising a parsed body
changes the whitespace and the check fails — mount this route before any JSON
middleware.

## Browser-side

The SDK never needs a credential in the browser. Pick whichever fits:

### Proxy through your own backend (works today)

```ts
import { OverslashClient } from '@overslash/sdk';

const overslash = new OverslashClient({
  auth: {
    transport: (req) =>
      fetch(`/api/overslash${req.path}`, {
        method: req.method,
        headers: req.headers,
        body: req.body,
        signal: req.signal,
      }),
  },
});
```

Your backend attaches the API key and decides which identity the request acts
as. **Never take that identity from the browser** — it is exactly the thing the
proxy exists to decide.

### Short-lived widget tokens

```ts
const overslash = new OverslashClient({
  baseUrl: 'https://api.overslash.com',
  // A function, not a string: tokens are short-lived, and this is re-invoked
  // when one expires.
  auth: { token: () => fetch('/api/overslash/token').then((r) => r.json()).then((b) => b.token) },
});
```

Your backend mints the token for one identity. See
[docs/design/widget-sdk.md](../docs/design/widget-sdk.md).

## The UI

```ts
import { defineOverslashElements, configureOverslash } from '@overslash/sdk/elements';
import { SseEvents } from '@overslash/sdk/controllers';

defineOverslashElements();
configureOverslash({ client: overslash, events: new SseEvents(overslash) });
```

```html
<overslash-approval-list scope="actionable"></overslash-approval-list>
<overslash-approval-card approval-id="…"></overslash-approval-card>
<overslash-secret-prompt req-id="req_…" token="…"></overslash-secret-prompt>
<overslash-connect-button provider="google"></overslash-connect-button>
```

| Element | Events |
|---|---|
| `<overslash-approval-card>` | `resolved`, `error` |
| `<overslash-approval-list>` | `resolved`, `error` |
| `<overslash-secret-prompt>` | `submitted`, `error` |
| `<overslash-connect-button>` | `connected`, `needs-external-auth`, `error` |

Registration is explicit so the import is side-effect free (SSR-safe), and
`defineOverslashElements({ prefix: 'acme' })` lets two versions share a page.

### Theming

Elements render in an open shadow root and are themed entirely through custom
properties, which inherit through the boundary:

```css
.my-app {
  --overslash-accent: #6ce869;
  --overslash-accent-fg: #042503;
  --overslash-bg: #fffdf9;
  --overslash-fg: #2c2a26;
  --overslash-border: #e6ded6;
  --overslash-radius: 14px;
  --overslash-font-family: 'DM Sans', system-ui, sans-serif;
  --overslash-risk-high: #c0392b;
}
```

Full set: `--overslash-{font-family,font-mono,bg,bg-subtle,fg,fg-heading,muted,border,radius,spacing,accent,accent-fg,danger,warn,ok,risk-low,risk-med,risk-high,shadow}`.

Anything the tokens do not reach has a `part`:

```css
overslash-approval-card::part(card) { border-style: dashed; }
overslash-approval-card::part(button-allow) { border-radius: 999px; }
```

Copy is overridable per element:

```js
document.querySelector('overslash-approval-card').strings = { allow: 'Autoriser' };
```

## Framework use

The elements are standard custom elements; React 19, Svelte 5 and vanilla all
consume them directly. If you want your own markup, use the controllers — they
are the same ones the elements are built on.

```tsx
// React
import { useSyncExternalStore, useMemo, useEffect } from 'react';
import { createApprovalController } from '@overslash/sdk/controllers';

function Approval({ id }) {
  const ctrl = useMemo(() => createApprovalController(overslash, { id, events }), [id]);
  useEffect(() => () => ctrl.dispose(), [ctrl]);
  const { approval, submitting, error } = useSyncExternalStore(ctrl.subscribe, ctrl.getState);
  // …your markup
}
```

```svelte
<!-- Svelte -->
<script>
  import { readable } from 'svelte/store';
  import { createApprovalController } from '@overslash/sdk/controllers';

  const ctrl = createApprovalController(overslash, { id, events });
  const state = readable(ctrl.getState(), (set) => {
    const off = ctrl.subscribe(() => set(ctrl.getState()));
    return () => { off(); ctrl.dispose(); };
  });
</script>
```

## Realtime

`SseEvents` consumes `GET /v1/events/stream`: one connection per client,
multiplexed across subscribers, resuming from its own cursor. The server closes
every 30 seconds by design; that is not an error and the SDK does not report it
as one.

Where no stream is available — an older server, a proxy that breaks SSE — every
controller keeps a bounded poll running instead. Nothing extra to configure.

```ts
events.onStatusChange((status) => setLive(status === 'live'));
```

## Testing your integration

The SDK reaches the network only through its transport, so a stub sees
everything:

```ts
const overslash = new OverslashClient({
  auth: {
    transport: async (req) => ({
      status: 200,
      headers: { get: () => null },
      text: async () => JSON.stringify(fixture),
    }),
  },
});
```

Or inject `fetch` and stub `global.fetch` as usual.

## Development

```bash
npm install
npm test
npm run check
npm run build
npm run demo            # element playground on :5183

# Against a real stack:
make e2e-up             # from the repo root
OVERSLASH_E2E=1 npx vitest run test/integration
node demo/scripts/screenshot-sdk.mjs --live
```

Wire types are hand-written mirrors of the Rust DTOs, each naming its source. If
you change one of those DTOs, grep `Mirrors` in `sdk/src/types/` and in
`dashboard/src/lib/`.
