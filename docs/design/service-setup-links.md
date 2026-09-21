---
title: Service setup links and the credential probe
status: Approved — implemented
related:
  - docs/design/agent-mcp-bootstrap-story.md
  - docs/design/agent-credential-provisioning.md
  - docs/design/agent-self-management.md
  - services/overslash.yaml
---

# Service setup links and the credential probe

Standing up a secret-backed service used to take three disconnected moves and
end with nobody knowing whether it worked. This is the shape that joins them
up, and the reasoning behind each seam. The binding choices are recorded as
`D83` in [DECISIONS.md](../../DECISIONS.md); this document is the longer
form — what the flow looks like end to end, what was rejected, and what is
deliberately still missing.

---

## The gap

Three surfaces, all of which stopped short.

**The agent.** D79 gave a first-level agent the four `_own` anchors and gave
`overslash_search` an `auth.setup` chain naming the calls that make a row
callable. For a secret-backed template that chain was `create_service`, then
`request_secret`. The agent made two calls and handed its user a URL onto
`/secrets/provide/{req_id}` — a page whose headline is a vault key name. From
the human's seat: *paste a value for `resend_key`*. It does not say what
Resend is, that an agent asked, or what happens next.

**The dashboard.** `/services/new` binds a credential *name* through
`SecretNamePicker`, whose own hint text read "create it on the Secrets page".
The wizard could not take a value, so the shortest path from "I have an API
key" to "the service works" went through two pages in the wrong order.

**Both.** Nothing ever exercised the credential. A key pasted with a trailing
newline, a key for the wrong account, a key that was revoked last week — all
land identically, and surface as a 401 on the agent's first real call, which
may be minutes or days later and is attributed to the action rather than to
the setup.

OAuth was the one path already joined up: `kernel_create_service` auto-starts
the dance and returns `connect.auth_url` for the caller to hand over. Even
there, nothing verified the result.

---

## The flow

```
agent                          Overslash                         human
  │                                │                               │
  ├─ create_service(resend) ──────▶│                               │
  │                                ├─ instance (credential-less)   │
  │                                ├─ mint setup link per slot     │
  │◀── { id, setup: {setup_url} } ─┤                               │
  │                                │                               │
  ├─ "open this to finish setup" ──────────────────────────────────▶
  │                                │                               │
  │                                │◀── GET /services/setup/req_… ─┤
  │                                ├── service + slot metadata ───▶│
  │                                │◀── POST {token, value} ───────┤
  │                                ├─ vault write                  │
  │                                ├─ bind credentials[token]      │
  │◀── event: secret_request.fulfilled                             │
  │      { service_id, service_status: "pending_setup" }           │
  │                                │◀ POST /v1/services/{id}/activate
  │                                ├─ probe → ok                   │ (signed in)
  │                                ├─ pending_setup → active       │
  │                                ├─ { status: "active", 214ms }─▶│
  │◀── event: service.activated                                    │
```

The instance is **not callable** until that last step. `create_service` returns
it `status: "pending_setup"` — it resolves by name nowhere and appears in no
search result, because nothing has yet checked that its credential works.

One agent call, one URL, one page. The OAuth path is the same diagram with
`connect.auth_url` in place of `setup.setup_url` and the provider's consent
screen in place of the setup page — which is the point: the two are twins.

---

## Seams

### `x-overslash-test` — the template names its own probe

```yaml
paths:
  /domains:
    get:
      operationId: list_domains
      risk: read
      test: true                  # or: test: { params: { limit: 1 } }
```

The alternative was an info-level pointer (`info.test: { action, params }`).
The operation-level marker won because it lives next to the `risk:` it is
constrained by, reuses `OPERATION_ALIASES`, and cannot dangle — there is no
operationId to go stale.

`false` switches a probe off without deleting the line, which is why the
boolean is unwrapped in `openapi::extract::parse_test` rather than by a
`Deserialize` impl (which cannot express absence).

Two validation rules are **errors**, not lints, because the probe fires
unattended the moment a credential lands:

| Rule | Why |
|---|---|
| at most one per template | A second candidate is not a richer template, it is an unanswerable question about which one the Test button means. |
| `risk: read` | A write-risk probe is an action nobody chose to run. |

A third rule — `test.params` must name real params and cover every required
one — exempts params that declare a `default`. `apply_defaults` runs before
the required check on both `/call` and `/validate`, so demanding a probe
restate Gmail's `userId: me` would make the template say the same thing twice
and drift the moment the default changed.

Declared on 20 of the 24 shipped templates. The four without one are each
deliberate:

| template | why not |
|---|---|
| `deepwiki` | every tool needs a repo name, and it authenticates with nothing — no credential for a probe to prove |
| `overslash` | `runtime: platform`; a platform action answers from this process against no upstream credential, which is why `Ext::Test` is not read at `Pos::PlatformAction` |
| `github_legacy_oauth`, `test_email` | `x-overslash-hidden` fixtures, not agent-facing |

### The setup link — mirroring auto-connect

`kernel_create_service`'s auto-connect block has a twin beside it. Same shape,
deliberately: best-effort (a mint failure logs and omits the bundle rather
than rolling back the instance), opt-out by a `skip_*` flag, surfaced as a
sibling field on the same response.

The three mint paths — `POST /v1/secrets/requests`, the MCP
`request_secret` kernel, and this auto-mint — now share one
`services::service_setup::mint`. They previously rebuilt the JWT-and-row
handshake by hand, which is how their TTLs came to differ.

### Why `secret_requests` grew two columns

[agent-credential-provisioning.md](agent-credential-provisioning.md) proposes
generalizing `secret_requests` into `credential_requests` with a kind
discriminator, to hold OAuth-client collection alongside secrets. That is
still the right destination and this is not it.

The OAuth half of *service setup* is already carried end to end by
`oauth_flows` + `service_instances.connection_id`. A `credential_requests`
table today would have exactly one kind in it, and the migration to add the
second kind would be the same work either way. So: two nullable columns, and a
check constraint (`(service_instance_id IS NULL) = (credential_key IS NULL)`)
that keeps the shape honest — a slot key with no instance names nothing, and
an instance with no slot key leaves fulfilment with no binding to make.

### Validate at mint, trust at fulfilment

Minting runs as a caller holding `manage_services_own`, with the template
resolved. It checks the instance is reachable in the org and resolves the slot
key — inferring it when the template declares exactly one (every shipped
template), refusing with both names when it declares several.

Fulfilment runs from a public route carrying a signed capability token and *no
identity*. It binds the slot the row names through a narrow
`OrgScope::bind_credential_slot` rather than re-entering `kernel_update_service`
and its permission checks, because re-entering would mean inventing an identity
to satisfy a check that has already happened.

The bind is a single `jsonb_set`, not a read-modify-write of the whole
credentials map: two links outstanding on one instance (a two-slot template,
or two browser tabs) must not erase each other.

### The probe is not a bypass

The obvious shape — `POST /public/services/setup/{id}/test`, running as the
instance owner with approvals skipped — is rejected. It would be a new,
permanently-open path to executing an action as someone else, justified only
by the caller holding a link.

Instead the probe goes through `call_action_impl` unchanged, and the setup page
offers it only to a visitor holding an `oss_session` for the org. This costs
nothing in the case the feature exists for: a fresh instance's Myself auto-grant
carries `auto_approve_level = 'read'`, and validation forces the probe to
`risk: read`, so the owner's own probe auto-approves.

`pending_approval` is therefore a real verdict, rendered as one.

### Draft until verified

D83 shipped the probe as a *diagnostic* and left the verdict advisory: the
instance was committed before anyone asked whether its key worked, and the
wizard's way out said "Continue anyway". A key with a trailing newline and a key
for the wrong account landed exactly where a good one did. The verdict now gates
the instance instead of merely describing it — the binding choices are `D86`
in [DECISIONS.md](../../DECISIONS.md).

Three things make it cheap. `status` already had a CHECK constraint to widen.
Every name-resolution query already filters `status = 'active'`, and
`overslash_search` already skips non-active rows, so a fourth value is excluded
from the call path and from discovery with no new predicate. And the probe
reaches a gated instance anyway, because it addresses the call by `service_id`
and *that* branch of `resolve_instance_for_call` is any-status. The feature is
mostly two lookups that already disagreed being allowed to mean something.

`pending_setup` is a status of its own rather than a reuse of `draft`, because
`draft` is a state a person parks an instance in on purpose and the sweeper
below has to be able to tell the two apart. The separation is enforced at the
API: `pending_setup` is absent from the status allow-list `PATCH /status` and
`update_service` validate against, so it is a valid *source* status and never a
valid target. Every row in it was therefore put there by a setup flow, which is
what lets the purge key on age alone.

The gate defaults on **exactly where a probe runner exists** — restating the
auto-mint's condition rather than approximating it. The reason is a constraint
worth stating plainly: an agent cannot probe the instance it just created.
`require_owner_or_admin` resolves to `caller_may_manage_owned`, which admits the
owner, an *ancestor* of the owner, or an admin — and an agent is deliberately
not an ancestor of its own owner-user. Gating a flow with no human in it
produces an instance nobody can release, which the sweeper collects a day later.

| create | gated? | why |
|---|---|---|
| a setup link is minted | yes | a human lands on a page we control, with a session, and their browser runs the probe |
| credentials already bound | no | no link, no page, no probe runner — and the agent cannot lift it itself |
| `skip_credentials: true` | no | the caller said it would wire this up |
| org-level (no owner) | no | `mint` needs an identity to store the secret under, so no link exists |
| OAuth | no | the dance ends in a server-side callback with no caller to probe as |
| no `x-overslash-test` | no | nothing to wait for |

`verify: true` forces it for a caller that probes on its own — the dashboard
wizard, which checks even on the path where the user named an existing vault
secret and no link was minted. On a probeless template it is a `400` rather than
a quiet `active`: answering "fine, it's live" to a caller that asked for
verification is how a dashboard comes to report a service checked that nothing
ever checked.

### Why `activate` and `test` are two endpoints

`POST /v1/services/{id}/activate` runs the same probe and, on a green verdict,
promotes. It is not folded into `/test` because `/test` is a diagnostic the
service detail page runs against live instances, and `require_owner_or_admin`
admits an org **admin** to instances they do not own — so promote-on-green there
would mean an admin sweeping the org's services silently published other
people's unverified drafts.

Nor is promotion the client's to declare. Routing it through `PATCH /status`
after a verdict the client claims to have seen would make the gate advisory,
since any caller can assert a verdict it never obtained. "Activate anyway" is
`activate?force=true`, which runs no probe either — so nothing is saved by going
around it, and going around it would skip the `service.activated` event an agent
may be blocked on. `PATCH /status` stays reachable as an override and now writes
the audit row it never had, flagging `bypassed_verification` on the one
transition worth finding later.

Every outcome is a `200`. A red verdict is the answer to the question, not a
failure to answer it, and a 4xx would make the dashboard render an error where a
verdict and a retry belong. `not_supported` promotes: a template can lose its
`x-overslash-test` after an instance was gated on it, and refusing forever over
a probe that no longer exists is worse than recording which verdict let it
through.

### Sign-in is now mandatory on a setup link

`mint` raises `require_user_session` to true whenever the request names a
service, whatever the org's `allow_unsigned_secret_provide` says.
One-directional — it can only tighten — and keyed on
`service_instance_id.is_some()`, which is the check constraint's own definition
of a setup request.

This reads as a policy change and is closer to the page declining a submission
it cannot complete. Fulfilment is what triggers the probe; the probe runs
through `call_action_impl`; `call_action_impl` needs an identity to evaluate a
chain against. An anonymous fulfilment can therefore never yield a verdict, so
it would leave the instance accepted-but-never-live until the sweeper deleted
it, with nobody told why. A bare secret request, whose only outcome is a stored
value, still honours the org setting.

The consequence is reported rather than hidden: the person finishing a link is
frequently not the instance's owner, the probe runs as *them*, and the Myself
auto-grant belongs to the owner — so they get `denied` and the instance stays
gated. Promotion staying behind owner-or-admin therefore costs nothing that was
ever obtainable, and the page names the person who has to finish rather than
announcing "saved" over a service that is quietly dead.

### What the sweeper takes, and what it leaves

`service_setup_draft_purge` deletes `pending_setup` rows older than
`MAX_LINK_TTL_SECS + sweep_grace_secs`, derived rather than configured. The
deadline is the **longest** link a caller could mint, not the auto-mint's
one-hour default: `POST /v1/secrets/requests` takes a `ttl_seconds` clamped to
that ceiling, and the instance must outlive every link that could still fulfil
it — the `secret_requests` rows cascade with it, so sweeping early would delete
a live URL out from under someone mid-paste.

Measured from `created_at`. `bind_credential_slot` bumps `updated_at`, so
someone pasting a third wrong key would push the deadline out indefinitely and
the sweep would never bound the table. `PATCH /status` → `draft` parks an
instance off the clock, which is the escape hatch for a setup that genuinely
needs longer.

It leaves the vault secret. `mint_bundle` stores under the *template's*
`default_secret_name`, so two Resend instances owned by one user share
`resend_key` — deleting it could pull the credential out from under a different,
live service. D85 refuses to *mint* into that collision unforced, which narrows
the window without closing it: a `force: true` create shares the name on
purpose, and rows predating D85 already do. `DELETE /v1/services/{name}` leaves
secrets alone for the same reason, and a sweeper that destroyed more than the
manual delete would be the inconsistency. No audit row and no event either, matching every other sweep: an
audit row records somebody's act, and a sweeper is nobody.

### Reopening a gated instance

No new endpoints. `PUT /v1/secrets/{name}` rewrites the value directly for the
owner, and `PUT /v1/services/{id}/manage` edits config, URL and name —
`kernel_update_service` has no status predicate, so it works on a gated instance
untouched. The wizard's failure step is an inline panel over those two, not a
rewind to its configure step, whose submit *creates*.

Handing the correction back to *someone else* is the third way, and it meets
[D85](../../DECISIONS.md) head on. `validate_binding` and `resolve_slot_key`
never required a slot to be *un*bound, so a second link at the same slot is
mintable — but by the time there is a wrong key to fix, that slot's vault name
is occupied, and a link aimed at an occupied name is exactly what D85 refuses
with `secret_name_conflict`. That is the right answer rather than a collision
between the two features: reopening a credential to correct it **is** a
rotation, which is the case D85 reserves `force: true` for, and the forced mint
reports what it supersedes. The alternative — exempting a re-mint at a slot the
same instance already owns — would carve a hole in D85 precisely where the value
being replaced is most likely to be one somebody is using.

### The verdict carries no body

"Do these credentials work" is the whole question. Piping an arbitrary upstream
response through a button anyone with instance access can press would make a
new disclosure surface out of a diagnostic.

What it does carry: the upstream status, wall-clock latency, the call's
`action_description`, and a truncated upstream error — enough to tell a wrong
key from a service that is merely down. A transport failure reaching the
upstream reports `failed` rather than a gateway `502`, because `502` tells the
operator *Overslash* is broken when what happened is that their service could
not be reached.

### One write path, two pages

`/services/setup/{req_id}` renders the service and submits to the existing
`/public/secrets/provide/{req_id}`. A second POST endpoint would have put the
credential-binding step in two places, which is how they drift. The setup page
is a framing of the same handshake, not a second protocol; a request with no
`service_instance_id` 404s on the setup route and keeps the older page.

Both pages must be listed in **two** places in the dashboard: `+layout.ts`
decides whether a page needs a session, `+layout.svelte` whether it wears the
app shell. Missing either is how `/oauth/consent` ended up chrome-less but
session-gated.

---

## Known limits

- **One slot per page.** A template with two unbound per-instance slots gets
  two links, handed over in sequence; the page names the outstanding siblings
  but cannot link to them, because each link is a separate capability. No
  shipped template declares two, which is why this is a documented limit rather
  than a feature.
- **The setup page has no OAuth face.** For an OAuth template the human clicks
  `connect.auth_url` and the provider's own screens take over; there is nothing
  for a setup page to add, and `/connect-authorize` fail-fasts on session
  mismatch by design. The Test button for OAuth lives on the authenticated
  surfaces — the create wizard (which *is* the "Connect & create" screen) and
  the service detail page's credentials tab, which is what makes a reconnect
  verifiable.
- **No deny.** `/secrets/provide`'s Deny button is still local-only
  (`TODO(secret-request-deny)`), and the setup page does not add one. A request
  the human refuses stays pending until it expires.
- **No `activate` over MCP.** `probe::run` needs `AuthContext`,
  `CallerTransport` and `ClientIp`; a `PlatformCallContext` carries none of
  them, so exposing activation as a platform action would mean synthesising an
  identity and re-entering the call path from inside a call. An agent's path is
  to hand over `setup.setup_url` and wait for `service.activated`, or poll
  `get_service` with `include_inactive: true`. This is only a limit at all
  because the agent could not usefully probe anyway — it is not an ancestor of
  its own owner-user, so `require_owner_or_admin` refuses it.
- **The purge does not clean up connections.** A gated instance got there via an
  unbound *secret* slot, so a bound connection is incidental; and
  `fire_connection_deleted` wants an actor for its audit row and event, which a
  sweeper has not got. Identity-owned connections are reusable, so the cost is a
  row rather than a leak.
- **The 24h window is fixed, from `created_at`.** A setup that legitimately
  needs longer is parked with `PATCH /status` → `draft`, which takes it off the
  clock. Renewing on `updated_at` instead would mean a third wrong key pushed
  the deadline out forever and the sweep never bounded the table.
