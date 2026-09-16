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
  │                                │◀── POST /v1/services/{id}/test┤ (signed in)
  │                                ├── { status: "ok", 214ms } ───▶│
  │◀── event: secret_request.fulfilled                             │
  │      { service_id, remaining_slots: [] }                       │
```

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
offers the Test button only to a visitor holding an `oss_session` for the org.
This costs nothing in the case the feature exists for: a fresh instance's
Myself auto-grant carries `auto_approve_level = 'read'`, and validation forces
the probe to `risk: read`, so the owner's own probe auto-approves. An anonymous
link recipient sees "Sign in to test" rather than a button that quietly
elevates.

`pending_approval` is therefore a real verdict, rendered as one.

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
