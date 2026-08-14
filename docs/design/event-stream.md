# Real-time event stream — `GET /v1/events/stream`

**Status:** Implemented
**Author:** Factory

## Motivation

SPEC.md §10 has listed SSE as one of three async delivery transports since the
first draft, alongside polling and webhooks, with the promise that "the same
event payload is delivered regardless of transport". Only two of the three
existed. Callers that wanted to know something happened either configured a
webhook — which needs a public HTTPS endpoint, and so is unavailable to a
browser, a laptop agent, or an embedded widget — or polled.

The dashboard shows what polling costs. Resolving an approval returns
immediately while the auto-call runs in a spawned task, so `resolution.svelte.ts`
polled `/v1/approvals/{id}` every 1.5 seconds for up to 30 to watch the
execution finish. The notification bell polled every 30 seconds. The approvals
queue did not poll at all: it mutated its list in place after *your* actions and
silently went stale on everyone else's, while rendering a decorative "live" chip
that was connected to nothing.

The widget SDK v1, designed separately, ships poll-based and specifies
auto-detecting this stream as its push upgrade. That makes the wire contract a
compatibility surface from day one, which is why it is versioned.

## What did not hold before this change

- **No push channel of any kind.** The only SSE in the codebase was the MCP
  elicitation response, and it waits on a 500 ms database poll loop
  (`services/mcp_session.rs`). No pub/sub, no broadcast, nothing to subscribe to.
- **No replayable event log.** `webhook_deliveries` rows are per-subscription:
  an org with no webhook configured produced no rows at all, and the rows carry
  no record of who was permitted to see the event. `Last-Event-ID` resume had
  nothing to resume from.
- **Emission was scattered.** Eight call sites each hand-rolled
  `tokio::spawn { webhook_dispatcher::dispatch(...) }` with a string literal
  event name. Nothing forced two transports to agree, because there was only one.
- **`secret_request.*` events did not exist.** The handshake that blocks an
  agent on a missing credential emitted audit rows only — the one party who
  needed to know when the secret arrived had no way to find out except polling.

## Design

### Wire contract (v1)

```
GET /v1/events/stream?topics=approvals,connections,secrets,activity
Authorization: Bearer <osk_… | mcp jwt>      (or the oss_session cookie)
Last-Event-ID: <cursor>                      (sent automatically by EventSource)

: keep-alive                                 every 15s

event: stream.open
id: 4210
data: {"cursor": 4210, "v": 1}

event: approval.created
id: 4213
data: {"id":"<uuid>","type":"approval.created","created_at":"…","data":{…}}
```

The `data:` field is the webhook envelope verbatim, so a client that already
handles webhooks needs no second parser. The SSE `id:` is the resume cursor and
the `event:` field is the type, so a browser can `addEventListener` per type
without inspecting bodies.

`stream.open` carries the protocol version and the cursor a fresh subscriber
should resume from — without it, a client with no history would have to either
replay everything or guess. Unknown topics are a 400 that names the offender: a
typo that silently delivered nothing would be indistinguishable from a quiet
system.

### The 30-second ceiling

Every connection is closed by the server after 30 seconds
(`EVENTS_STREAM_MAX_CONNECTION_SECS`). This is deliberate, and it is the reason
resume is trustworthy: the reconnect path runs twice a minute in production
rather than being exercised for the first time during an incident. It also keeps
idle connections cheap and stops any proxy in the path from being the thing that
decides the timeout.

### Events table and fan-out

```sql
CREATE TABLE events (
    id BIGSERIAL PRIMARY KEY,   -- the resume cursor
    event_id UUID …,            -- stable uuid for the envelope
    org_id UUID …, type TEXT, topic TEXT, payload JSONB,
    audience UUID[] …,          -- who may see it, frozen at emit time
    created_at TIMESTAMPTZ …
);
```

`id` is a bigserial rather than the uuid primary key used elsewhere because it
*is* the cursor: `Last-Event-ID` needs a total order the client can echo back and
the server can turn into `WHERE id > $cursor`.

An `AFTER INSERT` trigger calls `pg_notify('overslash_events', NEW.id::text)`.
Each replica runs a `PgListener` task that receives the cursor, fetches the row,
and republishes it on a process-local `tokio::sync::broadcast`. Only the id
travels over NOTIFY, so the 8 KB payload ceiling is irrelevant and no event data
lands in `pg_stat_activity`. The trigger rather than a `pg_notify` bolted onto
the INSERT makes notification an invariant of the table instead of a convention
every writer must remember.

**Writers never publish to the bus directly**, not even for a subscriber on the
same replica that produced the event. That costs one database round trip and
buys a single delivery path: one ordering, one dedupe rule, and no divergence
between the single-replica case under test and the multi-replica case deployed.

Retention is 7 days, swept hourly. The log only has to outlive a reconnect
window; the rest is forensic slack.

### The approval taxonomy

Three moments in an approval's life need a decision from someone new, and they
are three separate events because they answer different questions:

| Event | Question it answers | Audit row |
|---|---|---|
| `approval.created` | Was an approval raised? | yes |
| `approval.bubbled` | Did it move between resolvers? | yes |
| `approval.pending` | Is something waiting on *me* right now? | **no** |

`approval.pending` is **derived**. It fires immediately after `created`, and
again after every `bubbled` — user-initiated or from the auto-bubble sweep — so
a caller that only wants an inbox subscribes to one type instead of
reconstructing "is this mine now?" from two different event shapes. It carries
`current_resolver_identity_id`, `can_be_handled_by` and a `reason` of `created`
or `bubbled`.

It deliberately has **no audit-log counterpart**. The audit log records facts;
`pending` restates one that `created` and `bubbled` already recorded, and a row
per gated agent call would be pure volume on the hottest path in the system.
The two surfaces have different jobs, and a derived convenience event belongs
only on the notification one.

Ordering matters here, which is why [`emit_all`] exists: a derived signal must
never reach a subscriber before the fact it derives from. Two separate `emit`
calls could not promise that — each spawns its own task, so the inserts would
race and the cursors could come out reversed. `emit_all` appends the whole
sequence in order within one task, and only then delivers the webhooks (a
webhook call can take ten seconds against an endpoint we do not control;
interleaving would let a third party delay the second event on the stream).

`approval.bubbled` spans **both** resolvers in its audience — the one losing
the item needs to know as much as the one gaining it, and after a hand-up the
previous resolver may no longer sit on the new resolver's chain.

Every way an approval can *end* is one event, `approval.resolved`, distinguished
by `status`: `allowed` and `denied` from a human verdict, `allowed` again from
the cascade, and `expired` from the background sweep. A second type would buy a
subscriber nothing — anything watching for "how did my request end" is already
watching `approval.resolved` — and would cost every existing consumer a new case
to handle. Expiry sets `resolved_by: "system"` and carries no `execution`,
because nothing ran.

The expiry sweep is cross-org and bulk, so returning rows to emit from is where
it could have stopped being bounded. Three things keep it in hand: the
`RETURNING` projection is a narrow `ExpiredApproval` (the audience pair, the
summary and the tags — never the jsonb columns, one of which is the whole
replayable request body), the statement takes a `LIMIT`, and the tick drains a
capped number of batches before yielding, logging when it hits that ceiling. A
larger backlog costs a subscriber nothing but a minute: the approvals were
already past `expires_at` and unusable.

The `LIMIT` lives inside a **`MATERIALIZED` CTE**, and that detail is worth
knowing before anyone rewrites the statement. The obvious spelling —
`WHERE id IN (SELECT ... LIMIT n FOR UPDATE SKIP LOCKED)` — makes the bound a
property of the *plan*: add any further qual to the outer table and the planner
may pick a nested-loop semi-join with the subquery on the inner side, rescanning
and re-`LIMIT`ing it per outer row, which updates and returns more rows than
asked for. That was observed, not theorised. A `MATERIALIZED` CTE is an explicit
optimization fence evaluated exactly once, so the bound holds regardless of
statistics.

### The `activity` topic

`action.called` and `action.completed` bracket every call through
`POST /v1/actions/call`. They exist for the Live Map, and they are the first
events on the gateway's **hottest path** — one durable `events` row each, per
call, where every other event here is emitted once per operator action. So
emission is gated on `OVERSLASH_LIVE_MAP` (`config.live_map_enabled`), which is
set on dev and in `scripts/e2e-up.sh` and never in production, and reported to
clients as `live_map` on `GET /v1/version`.

The **topic string stays valid either way**. A client asking for `activity` on a
deployment with the flag off gets silence, not a 400 — a subscription that
succeeds or fails depending on an env var would be a worse contract than one
that is simply quiet.

Both are emitted from `routes/actions/mod.rs::call_action`, the wrapper that
already brackets the request for metrics, rather than from the four terminal
sites inside `call_action_impl`. That wrapper owns the outcome taxonomy —
including the `UpstreamErrored` marker that tells an upstream's 500 riding
behind an outer 200 apart from Overslash's own failure — and `action.completed`
reports exactly it (`called | denied | rejected | failed | upstream_error`)
alongside `duration_ms`.

The pair is **not ordered**. The two events bracket the upstream call, so
[`emit_all`] cannot span them and each `emit` spawns its own task; the inserts
race and `completed` can carry the lower cursor. That is why they share a
`call_id` minted in the wrapper rather than being paired by arrival order, and
why the dashboard treats a `completed` for an unknown `call_id` as a packet
already on its return leg instead of dropping the call.

### Visibility

`audience` is the access-control decision, resolved once by the code path that
emits the event and frozen into the row. That path already holds the approval
row and the identity chains, so it costs at most one extra query instead of one
per subscriber — and an event is a historical fact, so re-deriving visibility at
read time would let tomorrow's re-parenting change who could see what happened
today.

The rules mirror the corresponding read endpoints:

| Event | Audience | Why |
|---|---|---|
| `approval.*` | `chain(requester) ∪ chain(current_resolver)` | Requester covers `?scope=mine`; resolver covers `?scope=assigned`; the resolver's *ancestors* are exactly `?scope=actionable`, since an identity can act iff the resolver is itself or a descendant. The requester's ancestors come along so a parent keeps seeing its sub-agents' traffic. |
| `connection.*` | `chain(owner) ∪ {actor}` | **Not** the owner's descendants. Sub-agents *use* an owner-level connection via `on_behalf_of` but cannot list or manage it, and an event stream must never be wider than the read model it reflects. |
| `secret_request.*` | `chain(requested_by) ∪ chain(target)` | The requesting agent is the one blocked on the secret. The target's chain covers the owner-user whose vault slot is written. Whoever pastes the value is anonymous and gains nothing by doing so. |
| `action.*` | `chain(actor)` | The Live Map's feed. A parent keeps seeing what its sub-agents call; a sibling chain sees nothing. Org admins bypass the array, which is what makes one stream an org-wide operator view and a personal one for everyone else. Discloses no more than `GET /v1/audit` already shows the same caller. |

Delivery applies one predicate, in two places:

```
event.org_id == subscriber.org_id
  AND event.topic ∈ subscribed_topics
  AND (subscriber.is_org_admin OR subscriber.identity_id ∈ event.audience)
```

On the **replay** path it runs in SQL, so rows the caller may not see are never
fetched. On the **live** path the listener publishes every row to the local bus
and each connection filters in memory. Org admins bypass the audience array
because they can already read every resource in the org over REST; the stream
would be an odd place to be stricter.

The stream requires an identity-bound credential. An org-level key with no
identity has no audience membership to evaluate, so it gets a 403 rather than
something org-wide.

**This is deliberately narrower than `GET /v1/approvals`,** which today has no
ACL gate — any identity in an org can list every pending approval in it. That is
a known gap; the stream does not inherit it. A sibling agent connected to the
stream receives nothing about another chain's approvals, and there is an
integration test asserting exactly that.

### Auth

The existing `AuthContext` extractor already accepts all three credential
kinds — the `oss_session` cookie, `osk_` API keys, and MCP JWTs — so the route
needed no new auth code.

There is deliberately **no `?token=` query-param mode**, even though
`EventSource` cannot set headers. A credential in a query string lands in access
logs, proxy logs, and `Referer` headers. It is unnecessary here: the dashboard
reaches the API through same-origin proxies (the Vite dev proxy, the
`vercel.json` rewrites), so a plain `EventSource` on a relative path carries the
session cookie automatically. Note the corollary — pointing an `EventSource`
directly at `api.overslash.com` from `app.overslash.com` would *not* carry it,
because the cookie is `SameSite=Lax`. The stream must stay on the relative,
proxied path.

A future short-lived widget token (`aud=widget`) slots into `AuthContext`
alongside the existing audiences without touching this route.

### Backpressure and caps

A subscriber that falls behind the broadcast channel gets `Lagged`, and the
handler ends the connection. That *is* the repair: the client reconnects with its
cursor and the backlog is served durably from Postgres rather than from an
in-memory catch-up buffer that would have to be invented and bounded.

Concurrent streams are capped per identity (4) and per org (64), enforced with
an RAII permit so a client disconnect releases the slot. Refusal is a 429 with
`Retry-After`, because the caller is not malformed — it is early, and a slot
frees within one connection lifetime. The counters are per-replica: a global cap
would need a round trip on every connect to enforce a limit whose only job is
bounding one process's memory.

## Emission

`services::events::emit` is the single seam. It appends to the log (which
notifies) *and* hands the identical payload to the webhook dispatcher, so
SPEC §10's "same payload regardless of transport" is structural rather than
aspirational. All eight former `dispatch()` sites now call it, and three new
secret-request sites were added. The nine event-name string literals became an
`EventType` enum whose `as_str()` feeds both transports and the audit log.

Emission stays fire-and-forget: an observer failing must not fail the request
that was observed. The two transports are independent — a failed log append
still attempts webhook delivery, and vice versa.

**Secret-request payloads exclude the provide token and URL.** That URL is a
bearer capability: anyone holding it can fulfil the request. Webhook
subscriptions are org-wide, so including it would hand every operator who can
configure a hook the ability to satisfy any secret request in the org. There is a
test asserting the payload carries no `token`, `url`, or `short_url`.

## Dashboard

One `EventSource` for the whole app, in `stores/events.svelte.ts`, exposing a
callback registry (`onEvent`) and reactive connection state. Consumers refetch
the resource an event names rather than trusting payloads as state.

Polling is kept as the fallback rather than deleted. The bell's 30-second
interval stays armed but skips its tick while the stream is live; the
resolution controller's 1.5-second poll does the same. If the stream is
unavailable — an old server, a proxy that breaks SSE, a network that hates
long-lived connections — behaviour degrades to exactly what shipped before.

The routine 30-second close is invisible: native `EventSource` reconnects and
replays `Last-Event-ID`. The lossy case is the browser giving up entirely (a
fatal status), because the cursor dies with the `EventSource`. The store then
reconnects with jittered backoff and, on the next open, dispatches a synthetic
`stream.resync` that tells subscribers to refetch. That is the only situation
where the client cannot trust its own state, and it is handled in one place.

The approvals queue now reconciles on any approval event with a 300 ms debounced
refetch of both lists, so an approval raised by an agent — or resolved in another
tab, by a colleague, or by the expiry sweep — appears or disappears without a
navigation. Expiry needed no client change to land there: the refetch reads
`scope=assigned`, which is `status = 'pending'` only, so an expired approval
leaves the queue on the strength of the event alone. The "live" chip is finally
connected to the connection state it always implied, and shows a muted
"auto-refresh" when the stream is down.

## Test plan

`crates/overslash-api/tests/events_stream.rs` — the first wire-level SSE
consumer in the suite (the MCP puppet's parser ignores `id:` and `event:`, which
this contract is built on, so the tests carry their own field-aware parser).
Covered: the open frame and its cursor; the deadline actually closing the
connection; live delivery through NOTIFY → listener → bus; replay after
reconnect and no redelivery when resuming from the last cursor; audience scoping
(a sibling agent in the same org receives nothing, an org admin receives
everything); topic filtering and a 400 for an unknown topic; the per-identity
connection cap returning 429; webhook/stream payload parity read from the
delivery row; the token-leak assertion; and 401 without credentials.

`crates/overslash-api/tests/approval_expiry_events.rs` covers the expiry sweep's
half of the contract: the `approval.resolved` payload and its
`status: "expired"`, delivery to a live subscriber and to a webhook subscriber,
the audience being the requester and resolver chains and nothing wider, the
`LIMIT` bounding one statement, the drain loop crossing batches and stopping at
its per-tick ceiling with the remainder left for the next one, two orgs swept
together staying apart, a live approval surviving, a second sweep re-emitting
nothing, and the audit row. The SSE reader those tests share with
`events_stream.rs` lives in `tests/common/sse.rs`.

Unit tests cover the delivery predicate in isolation (org mismatch, audience
membership, admin bypass, topic filter), `Last-Event-ID` parsing, topic parsing,
and the connection-cap accounting including the rollback when the org slot is
taken but the identity cap then rejects.

## Deferred

- **The `services` topic.** SPEC.md §7 implies service-lifecycle notifications
  (`pending_credentials → active`), but no `service.*` event exists on any
  transport yet. It slots in as one more `EventType` variant.
- **MCP elicitation still polls.** Its 500 ms `await_completion` loop predates
  the bus and could now wait on it instead.
- **The dashboard subscribes only to `approvals`.** Connection and secret events
  are emitted and streamable, but nothing in the UI reacts to them yet.
