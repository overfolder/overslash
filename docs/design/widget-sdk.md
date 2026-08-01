# Widget SDK — `@overslash/sdk`

**Status:** Approved — implementation in progress
**Author:** Factory

## Motivation

Overslash's human-in-the-loop surfaces — an approval card, a secret request, an
OAuth connect button — exist in exactly one place: the dashboard. Every other
product that puts an agent in front of a user has to rebuild them.

Two of them already have, or are about to:

- **Overfolder** is the white-label case. It holds an org service key, calls
  every action with `X-Overslash-As: user@host.com/agent`, and surfaces
  approvals to end users who have no Overslash account and never see the
  Overslash domain. It has rebuilt the client twice in Rust
  (`agent-runner/src/overslash/client.rs` and `backend/src/services/overslash.rs`,
  ~50% duplicated), and its frontend never talks to Overslash at all: an
  approval reaches its webchat as a generic assistant message with buttons,
  routed through its own SSE stream, its own callback endpoint, and its own
  `action_requests` table. The one purpose-built component in that whole path
  is a secret input.
- **Soporti** is the single-agent case: one agent identity, staff users who
  approve its actions. It has no approval concept at all today, because its
  agent is read-only. The moment it gains a write tool it needs the entire
  surface, and its house rules (React 19, plain JS, no new dependencies, one
  `fetch` chokepoint, CSS custom properties, no component library) rule out most
  of what an SDK would naively ship.

Neither can use the dashboard's implementation, and both need the same four
things: a typed client, the state machines that make an approval card correct
(optimistic resolution, execution polling, cascade removal), a live channel, and
UI they can brand.

## What does not hold today

- **No JavaScript client of any kind.** No `packages/`, no `sdk/`, no published
  artifact. The dashboard's client is two hand-written modules
  (`lib/session.ts`, `lib/api.ts`) that assume same-origin cookies, and there is
  no OpenAPI description of the gateway API to generate one from.
- **The logic that makes an approval card correct is locked inside Svelte.**
  `lib/approvals/resolution.svelte.ts` is 219 lines of runes; `lib/approvals/format.ts`
  is 206 lines of pure functions that any consumer would want and no consumer
  can reach. `lib/oauth-connect.ts` holds the popup-and-poll dance.
- **Integrators reinvent the error model.** Overslash's auth-recovery envelopes
  (`reauth_required`, `needs_authentication`, `missing_scopes`, and their
  URL-less headless variants) are the load-bearing contract for "your agent
  needs the user to reconnect something", and Overfolder had to write ~120 lines
  of Rust to lift them into typed values.
- **A browser has no credential it can hold.** `osk_` keys are org-wide secrets;
  the `oss_session` cookie is `SameSite=Lax` and does not cross sites. The only
  browser-safe path today is a host-side proxy, which every integrator must
  build before writing a line of UI.

## Non-goals

- **Framework binding packages.** No `@overslash/react`, no `@overslash/svelte`.
  The headless controllers are framework-free and the components are custom
  elements, which is the only UI form all three target stacks consume natively.
- **Migrating the dashboard onto the SDK.** Deliberately deferred (see
  [Deferred](#deferred)); the types are shaped to allow it later.
- **Publishing automation.** v1 publishes manually.
- **Wrapping every endpoint.** The SDK covers the integration surface —
  approvals, actions, secrets, connections, events — not org administration,
  templates, or MCP.

## Package shape

One package, `@overslash/sdk`, at `sdk/` — a sibling of `dashboard/` with its
own npm root and no monorepo tooling. Subpath exports keep the layers separable:

| Subpath | Contents | Format |
|---|---|---|
| `.` | `OverslashClient`, resources, error model, wire types | ESM + CJS |
| `./controllers` | headless state machines, `Store`, `PollScheduler`, `EventsTransport` | ESM + CJS |
| `./elements` | custom elements + `defineOverslashElements()` | ESM |
| `./node` | webhook verification, server recipes | ESM + CJS |
| `./format` | pure display helpers | ESM + CJS |

One package rather than `core` + `ui` because the two halves version in lockstep
against one wire protocol, and subpath exports already give the tree-shaking
boundary that splitting would buy. Importing `@overslash/sdk` never pulls in the
element code.

**Zero runtime dependencies** is a hard constraint, not an aspiration: Soporti's
contributing rules forbid adding dependencies without asking, and an SDK that
arrives with a transitive tree is one that gets rejected on sight. Everything
here is reachable from `fetch`, `WebCrypto`, and the DOM.

## Auth and transport

The client takes one of three auth modes, and the mode determines whether it
ever holds a credential.

```ts
new OverslashClient({ baseUrl, auth: { apiKey: 'osk_…' } })            // server-side
new OverslashClient({ baseUrl, auth: { token: () => mintWidgetToken() } })  // browser, direct
new OverslashClient({ auth: { transport: myHostProxy } })              // browser, proxied
```

**`{ apiKey }`** is the server-side mode. It is also the mode that carries
`X-Overslash-As`: `client.as('alice@acme.com/support-agent')` returns a derived
client that sets the header on every request, which is SPEC §4's designated
integration surface for white-label backends and provisions identities on first
use.

**`{ transport }`** is the mode that works today from a browser with no backend
changes. The host supplies a function; the SDK hands it a
`{ method, path, headers, body }` and expects a response. The SDK never sees a
credential, the host attaches it server-side, and — critically for Soporti — the
SDK makes no `fetch` call of its own, so the repo's single-chokepoint rule
survives. A browser-supplied `as` must be validated or overwritten by the proxy;
the proxy is the trust boundary, and the docs say so in those words.

**`{ token }`** is the mode the widget-token work below unlocks: a short-lived,
narrowly-scoped bearer the browser may hold. Accepting a function rather than a
string is what makes expiry survivable — on a `401` the client re-invokes it
once and retries. That signature is stable whether or not the backend piece has
shipped, so nothing in the SDK changes when it does.

### Why `X-Overslash-As` never crosses the browser

It is only meaningful with an `osk_` key, and an `osk_` key in a browser is an
org-wide credential leak. A widget token names its identity in its own claims,
so the browser has nothing left to assert. The header is deliberately absent
from the API's CORS allow-list and should stay that way.

## Error model

`ApiError` carries `status` and the parsed body. The four auth-recovery
envelopes lift into `AuthActionError`, which is the shape an integrator actually
branches on:

| Wire | Status | `kind` | Carries |
|---|---|---|---|
| `needs_authentication` | 401 | `needs_authentication` | `provider`, `authUrl?`, `short?` |
| `reauth_required` | 401 | `reauth_required` | `provider`, `connectionId`, `accountEmail?` |
| `missing_scopes` | 403 | `missing_scopes` | `provider`, `requiredScopes`, `upgradeUrl?` |
| any of the above, headless org | — | as above | `headless: true`, **no URLs** |

`headless: true` is not an edge case to swallow — it is the white-label
contract (D21). The host runs its own OAuth dance and re-imports; the SDK's
connect controller surfaces it as a state and hands it to a host callback rather
than trying to open a window it has no URL for.

**Expected outcomes are values, not exceptions.** `actions.call` always sends
`?wrap=true`, which the gateway already supports (`routes/actions/mod.rs`) and
which turns its auth-401s into a `200` discriminated union. So a call returns
`{ status: 'called' | 'pending_approval' | 'denied' | 'needs_authentication' | 'reauth_required' }`
and the `pending_approval` arm carries everything an approval card needs —
`disclosed_fields`, `risk`, `permission_keys`, `suggested_tiers` — with no
second round trip. Transport failures, 5xx and permission denials still throw.
An agent tool that must branch on "did this need approval?" should never have to
write a `try`/`catch` to find out.

## Realtime

`GET /v1/events/stream` shipped in D45, and the SDK consumes it from v1. The
server's own framing comment names this client as the reason the wire contract
is versioned; `stream.open` carries `{ cursor, v: 1 }` so the SDK can refuse
framing it does not understand.

### A fetch-based parser, not `EventSource`

`EventSource` cannot set an `Authorization` header, and D45 deliberately
rejected a `?token=` query-param mode because a credential in a query string
lands in access logs, proxy logs and `Referer`. Two of the SDK's three auth
modes are bearer modes. So `SseEvents` parses the stream out of a `fetch`
response body: `ReadableStream` → UTF-8 decode → SSE line parsing. It works in
every browser that has streaming fetch, in Node ≥20, and through a host proxy in
transport mode.

Owning the parser also fixes the one lossy case the dashboard has to live with.
`EventSource` holds its resume cursor internally, so a fatal error destroys it
and the reconnect starts blind — which is why `stores/events.svelte.ts` has to
synthesise a `stream.resync` and make every subscriber refetch. The SDK keeps
the cursor itself, updated per frame exactly as the server's replay ordering
requires, so a reconnect after *any* failure resumes precisely. `resync` remains
only for the genuinely blind case: reconnecting having never received a cursor.

Otherwise the semantics are the dashboard's, because they are correct:

- The routine 30-second close is not an error. Reconnect immediately, do not
  report the connection down.
- A `connecting` grace window (~8s) before admitting `down`, so a connection
  that closes twice a minute does not flicker a status chip.
- Jittered backoff, 1s → 30s, on real failures. Honour `Retry-After` on `429`
  (the per-identity cap of 4 concurrent streams is a real ceiling for a page
  with several widgets, which is why the client opens **one** connection and
  multiplexes subscribers over it, with topics as the union of what they want).
- Events are notifications, not state. Every controller refetches the resource
  an event names. Payload fields are for routing.

`PollingEvents` implements the same `EventsTransport` interface with bounded
1.5-second polls, and is selected when the stream is unavailable — an older
server, a proxy that breaks SSE, a transport-mode host that does not forward
streaming responses. Polling ticks are skipped while the stream is live, which
is the same arrangement the dashboard settled on: an environment that breaks SSE
degrades to exactly the behaviour that shipped before it existed.

## Controllers

A controller is a state machine over a `Store`:

```ts
interface Store<T> {
  getState(): T;                     // stable reference until state changes
  subscribe(listener: () => void): () => void;
  dispose(): void;                   // stop timers, abort in-flight requests
}
```

That is precisely `useSyncExternalStore`'s contract, so React consumes it in one
line, and a Svelte `readable` wraps it in three. Shipping bindings would buy
nothing and cost two more packages to version.

| Controller | Ported from | Responsibility |
|---|---|---|
| `createApprovalController` | `lib/approvals/resolution.svelte.ts` | Optimistic `override`, derived execution states, refetch on `approval.resolved/executed/execution_failed/execution_cancelled/bubbled`, 30s×1.5s execution poll as fallback, `resolve`/`triggerCall`/`cancelExecution` |
| `createApprovalListController` | `routes/approvals/+page.svelte` | Subscribes `approval.pending` — the derived "is this waiting on me *now*" event — plus `created`/`bubbled`/`resolved`; debounced refetch; cascade removal via `cascaded_approval_ids` |
| `createProvideController` | `routes/secrets/provide/[req_id]/+page.ts` | The public provide state machine: `ready \| expired \| already_fulfilled \| invalid \| missing_token \| server_error`, plus submit states |
| `createSecretRequestController` | — | Mints via `POST /v1/secrets/requests`, exposes the URL to hand the user, watches `secret_request.fulfilled` |
| `createConnectController` | `lib/oauth-connect.ts` | Popup to the gated `auth_url`, completion via `connection.created/updated` with list-polling as fallback, `PopupBlockedError` as a *state*, `headless: true` → `needs_external_auth` + host callback |

`waitForApproval(client, id, { timeoutMs })` is the server-side counterpart: it
subscribes the stream when one is available and falls back to polling. It exists
because of a real constraint in the single-agent case — Soporti's run loop has
no pause/resume, so an approval must block inside the tool's `execute()` or not
happen at all. Blocking on a stream subscription is the difference between a
tool that waits 2 seconds and one that waits for the next poll tick.

`createApprovalController` can also be seeded from a `pending_approval` call
result (`fromPendingCall`), which is the whole point of returning that arm as a
value: the tool call that triggered the approval already carries what the card
renders.

## Web components

Four elements plus a provider:

| Element | Purpose |
|---|---|
| `<overslash-provider>` | Holds the client for a subtree; optional `token-endpoint` for widget tokens; exposes stream status |
| `<overslash-approval-card>` | One approval: risk, disclosed fields, permission keys, remember tiers, payload, actions, execution status |
| `<overslash-approval-list>` | The queue, stream-driven |
| `<overslash-secret-prompt>` | Inline secret provide form |
| `<overslash-connect-button>` | OAuth connect, popup flow |

A client reaches an element three ways, most specific winning: the `client`
property, a `<overslash-provider>` ancestor (resolved by a composed context
event), or a module-global `configureOverslash()`. Registration is explicit —
`defineOverslashElements({ prefix })` — so importing the module is side-effect
free, SSR does not break, and two versions on one page can coexist under
different tag names.

### Open shadow DOM, themed by custom properties and parts

The three target hosts carry three different global CSS regimes: Overfolder is
Tailwind v4 with hard-coded dark-mode hexes, Soporti is hand-written tokens plus
BEM with an explicit ban on hardcoded values, and a vanilla host is whatever it
is. Light-DOM markup would inherit all three and render differently in each.
Shadow DOM is the only way one stylesheet behaves the same everywhere.

The usual objection — "shadow DOM blocks host styling" — is answered rather than
dismissed. Custom properties inherit *through* the shadow boundary, so a
documented `--overslash-*` token set covers brand theming with no piercing at
all; and every structural node carries a `part`, so anything the tokens do not
reach is still reachable with `::part()`. A host that wants full markup control
is not stuck: that is what the headless controllers are for, and they are a
supported answer rather than a consolation.

Styles are injected as a constructable stylesheet shared across instances, with
a `<style>` clone as fallback. Copy is overridable per element via a `strings`
property merged over English defaults; structural copy uses named slots. No i18n
framework.

Accessibility is not optional in a component whose entire job is asking a human
to decide something: real `<button>`s, `aria-live="polite"` for execution
transitions, focus returned to the invoking control after resolution, and risk
communicated by label as well as colour.

## Types

Hand-written TypeScript mirroring the Rust DTOs, each carrying a
`/** Mirrors <rust path> */` header — the same discipline `dashboard/src/lib/session.ts`
and `types.ts` already follow, and for the same reason: there is no OpenAPI
description of the gateway API to generate from, and producing one means
annotating every route and DTO in `crates/overslash-api` with `utoipa` first.
That is a worthwhile project and an entirely separate one.

The SSE envelope and the webhook envelope are **one type**. D45 made them
byte-identical on purpose ("the same event payload regardless of transport"), so
`EventEnvelope` and the `EventType` union serve `parseWebhookEvent` in Node and
the stream parser in the browser. A consumer that already handles webhooks needs
no second parser, and the type system says so.

## Widget tokens (backend, follow-up)

The SDK ships without this and works via `{ transport }`. This is the design it
is shaped for; it lands as its own change.

**`POST /v1/widget-tokens`** — callable only by an API key (a session or MCP
caller is refused), with `X-Overslash-As` selecting the end-user identity
exactly as it does everywhere else, including provisioning on first use.
Returns a stateless HS256 JWT with `aud=widget`, TTL clamped to `[60, 3600]`
and defaulting to 900 seconds.

Claims: `sub` (the end-user identity), `org`, `key_id` (the minting key, so
revoking it kills every outstanding token), `impersonated_by` (the minting
key's identity), `caps`, `origins`.

There is deliberately **no refresh endpoint**. The host re-mints from its own
authenticated endpoint, because the host's session is the real authority on
whether that user is still logged in; a refresh endpoint would re-implement
that check worse.

**Capability restriction.** A widget token is not full identity powers. A static
`(method, path)` allowlist keyed on `caps` is enforced in the extractor,
fail-closed: `approvals` reaches the approval read/resolve/call/cancel routes
and the event stream, `secrets` reaches the public provide routes, `whoami` is
always on. Presented anywhere else — `PUT /v1/secrets/{name}`, `/v1/api-keys`,
`/mcp` — it fails at authentication. That allowlist *is* the XSS blast radius:
a stolen token can act on one identity's approvals for at most fifteen minutes,
and can read no secret, mint no key, and impersonate nobody.

**Listing is pinned.** `GET /v1/approvals` still has no ACL gate, and a widget
token must not inherit that: with one present, an absent `?scope` defaults to
`actionable` and anything outside `mine|assigned|actionable` is refused. The
event stream needs no equivalent work — its audience is frozen per event and
already narrower (D45).

**Resolution authority is unchanged.** No new ladder: `WriteAcl` plus
`classify_approval_relationship` decide, under the impersonated identity, and
self-approval remains impossible for a token with no MCP client binding — which
is correct, since an agent's own widget token must not approve the agent.

**CORS.** A dedicated `/widget/*` router subtree re-mounting the allowlisted
handlers, with `allow_credentials(false)` and permissive origins. Bearer-only
means the forbidden credentials+wildcard combination never arises, and
`cors_global` is untouched. Real origin restriction lives in the token's
`origins` claim and is checked at authentication, which is stronger than CORS —
CORS is a browser courtesy, a header check is not.

**Rate limiting** extends to `aud=widget` bearers. Today `extract_osk_prefix`
skips every non-`osk_` credential, which is defensible for MCP JWTs and
indefensible for one handed to a browser.

For the single-agent archetype, the mapping that makes all of this work is to
root the agent under the human who approves it: call actions as
`X-Overslash-As: staff@host.com/agent`, mint tokens as `staff@host.com`. The
staff member is then the agent's ancestor, so the existing downstream
relationship resolves, and audit attribution is per-human for free. The
alternative — one shared owner identity — collapses attribution and makes every
approver interchangeable.

## Test plan

- **Unit (vitest).** Stubbed `fetch` and a mock transport — which doubles as the
  documented testing recipe, since Soporti's rules require stubbing
  `global.fetch` rather than the service module. Error lifting against captured
  envelopes including headless variants; the `wrap=true` union; `as()`; the
  token-refresh retry.
- **SSE parser.** Scripted `ReadableStream`s: frames split across chunks,
  keep-alive comments, `stream.open`, per-frame cursor advance, resume after a
  mid-replay close, `resync` only when blind, `429` + `Retry-After`.
- **Controllers.** Fake timers for poll cadence and the wall-clock cap; optimistic
  override; cascade removal; provide-state mapping; popup timeout.
- **Elements.** vitest + happy-dom for shadow rendering, event dispatch, context
  resolution, strings merge.
- **Integration**, opt-in behind `OVERSLASH_E2E=1` against `make e2e-up`: a real
  action call → `pending_approval` → resolve → execution terminal, asserted to
  arrive **over the live stream**, mirroring `crates/overslash-api/tests/events_stream.rs`
  from the other side of the wire; plus a secret request minted, provided, and
  observed as `secret_request.fulfilled`.
- **Screenshots.** `sdk/demo/` is a Vite playground rendering every element in
  three theming modes. `sdk/demo/scripts/screenshot-sdk.mjs` follows the
  scenarios-library philosophy — boot the real stack, seed through the real API,
  capture what actually renders — rather than intercepting routes.
  `dashboard/scripts/screenshot-live-events.mjs` is the prior art.

## Deferred

- **Dashboard migration.** The dashboard keeps its own type mirrors,
  `format.ts` and `oauth-connect.ts` for now. Doing both at once would tie the
  SDK's first release to a dashboard-wide refactor. The SDK's type names and
  file grouping deliberately match so the swap is mechanical later — and the
  dashboard is the best possible dogfood for the element layer.
- **Publishing automation.** Manual `npm publish` for v1; wiring `sdk/` into
  release-please comes after the shape settles.
- **Generated types.** Blocked on the gateway having an OpenAPI description at
  all.
- **More elements.** `<overslash-connection-list>`, `<overslash-execution-result>`.
- **The `services` topic.** Nothing to subscribe to yet (D45's own deferred list).
