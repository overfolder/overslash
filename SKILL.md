---
name: overslash
description: Overslash is a multi-tenant actions and authentication gateway for AI agents on app.overslash.com. USE WHEN you need to call external services on behalf of a user, manage OAuth connections, resolve approvals, or run service actions.
---

# Installing the CLI

```bash
git clone https://github.com/overfolder/overslash
cd overslash
make install        # builds dashboard + binary, installs to ~/.local/bin
```

Make sure `~/.local/bin` is in your PATH. Then confirm:

```bash
overslash --version
```

Self-host the gateway with `overslash web` (starts on `http://localhost:7171`).  
To use the managed cloud instead, see the enrollment sections below.

---

# Enrolling with app.overslash.com

Point your MCP client at `https://app.overslash.com/mcp`.

## MCP clients that speak OAuth (Claude Code, Cursor, Windsurf)

Add the server — nothing else:

```json
{ "url": "https://app.overslash.com/mcp" }
```

On first use a browser window opens, the user signs in and picks an agent
identity, and the client stores tokens automatically. Subsequent runs skip
that step entirely.

## MCP clients that only take a static Bearer header (e.g. OpenClaw)

```bash
overslash mcp login --server https://app.overslash.com
```

This opens a browser, signs in, and writes `~/.config/overslash/mcp.json`.

Configure the client to use the stdio shim — it auto-refreshes tokens:

```json
{ "command": "overslash", "args": ["mcp"] }
```

## Organizations with their own subdomain

If your organization has a slug (`acme`), point the client at its subdomain
instead — every agent enrolled through it is guaranteed to land in that org,
signed in through that org's IdP:

```json
{ "url": "https://acme.app.overslash.com/mcp" }
```

Discovery, sign-in, and tool calls all stay on that host. `https://acme.api.overslash.com/mcp`
is an equivalent endpoint that reaches the API directly, bypassing the edge
proxy; prefer the `app` host unless you have a reason not to, since it is the
one the browser sign-in flow is built around.

## After enrollment

You have four MCP tools:

| Tool | Purpose |
|---|---|
| `overslash_search` | Discover services and actions available to you |
| `overslash_read` | Call a read-class action — the server rejects writes/deletes routed through it. Prefer this over `overslash_call` for read-only operations: clients can skip the confirmation prompt because the tool is annotated `readOnlyHint: true`. |
| `overslash_call` | Call any action (read, write, or delete), resume a pending approval, or invoke a platform action |
| `overslash_auth` | `whoami` · `service_status` |

See `SPEC.md` for the full API reference.

## Bootstrapping a service from a template

When `overslash_search` returns a useful **template** but no live `service`,
you can instantiate it yourself — no dashboard click needed (provided your
identity holds `overslash:manage_services_own:*`).

**Step 1 — discover.**

```
overslash_search { "query": "calendar" }
```

If `services: []` and `templates: [{ key: "google_calendar", … }]`, continue.

**Step 2 — create the service instance.**

```
overslash_call {
  "service": "overslash",
  "action": "create_service",
  "params": { "template_key": "google_calendar", "name": "google-calendar" }
}
```

The platform kernel auto-grants the new instance to your owner-user's
Myself group (admin + `auto_approve_reads`), so siblings of yours under the
same user pick it up immediately. The response carries
`credentials_status`:

| Value | Meaning | Next step |
|---|---|---|
| `needs_authentication` | OAuth template with no connection bound, **or** a secret-based / MCP-bearer template with no secret set | OAuth → step 3; secret-based → [Providing a secret](#providing-a-secret-non-oauth-services) |
| `ok` | secret/connection inferred from existing user state | skip to step 5 |
| `partially_degraded` | a connection is bound but does not cover every action's scopes — uncovered actions return `403 missing_scopes` | click the upgrade `auth_url` returned in that 403 |
| `needs_reconnect` | a connection is bound but covers none of the scope-bearing actions | re-run consent (step 3) |

> `needs_authentication` means *no credential is bound yet* — it does **not**
> tell you whether the underlying OAuth **client** even exists. If the org has
> no OAuth client for the provider, you only find that out at step 3. See
> [When the OAuth client itself is missing](#when-the-oauth-client-itself-is-missing).

**Step 3 — start OAuth.**

```
overslash_call {
  "service": "overslash",
  "action": "create_connection",
  "params": { "service_id": "<id from step 2>", "provider": "google" }
}
```

Returns `{ auth_url, state }`. Surface `auth_url` to the user verbatim:
*"Click here to authorize Google Calendar."* Overslash binds the resulting
token to the service on its OAuth callback. If instead this returns a `400`
about *"no OAuth client credentials configured"*, the org has no OAuth client —
see [When the OAuth client itself is missing](#when-the-oauth-client-itself-is-missing).

**Step 4 — confirm ready.**

```
overslash_read {
  "service": "overslash",
  "action": "get_service",
  "params": { "name": "google-calendar" }
}
```

Wait until `credentials_status == "ok"` (poll a few seconds — the OAuth
callback flips it). The user has clicked through.

**Step 5 — call the service.** Use `overslash_read` for `risk: read` actions
(no confirmation prompt) and `overslash_call` for everything else; both go
through the standard approval flow described below.

## Configuring a new service (no template exists yet)

If `overslash_search` returns **neither** a live `service` **nor** a `template`
for the API you need, author the template yourself, then instantiate it as in
the section above. Requires your identity to hold `overslash:manage_templates_own:*`.

A service is an **OpenAPI 3.1 YAML** document plus a few `x-overslash-*` vendor
extensions that tell the gateway how to gate and authenticate each action (the
unprefixed aliases shown here are also accepted):

```yaml
openapi: 3.1.0
info:
  title: Acme
  key: acme                      # unique template key, ^[a-z][a-z0-9_-]*$
  category: Productivity
servers:
  - url: https://api.acme.com    # calls are bounded to this host
components:
  securitySchemes:
    # Secret-based — Overslash injects a vault secret:
    token:
      type: apiKey
      in: header
      name: Authorization
      # How to build the header value from the secrets below. Absent means
      # "inject the one secret verbatim". Slots are named literally so the
      # gateway knows which secrets to decrypt.
      x-overslash-template:
        lang: jq
        expr: '"Bearer " + .token'
      default_secret_name: acme_key
    # …or OAuth style instead:
    # oauth:
    #   type: oauth2
    #   provider: acme            # credential-cascade resolver key
    #   flows: { authorizationCode: { authorizationUrl: …, tokenUrl: …, scopes: {…} } }
paths:
  /v1/messages:
    post:
      operationId: send_message
      summary: "Send a message to {channel}"   # templated into approval prompts
      risk: write                               # read | write | delete — gates approval/auto-approve
      scope_param: channel                      # binds the permission/approval scope
      # A list scopes several params at once, and `param:label` files them
      # under one namespace — services/email.yaml scopes every recipient with
      #   scope_param: [to:recipient, cc:recipient, bcc:recipient]
      # so each address mints `email:send:recipient=<addr>` and a bcc is gated
      # like a to. Keys dedupe, so an address on two headers is one approval.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [channel, text]
              properties:
                channel: { type: string }
                text:    { type: string }
```

**Create it (atomic).** Validates strictly and goes live immediately, or returns
`validation_failed` with the errors to fix:

```
overslash_call {
  "service": "overslash",
  "action": "create_template",
  "params": { "openapi": "<the full YAML above>", "user_level": true }
}
```

Then follow **Bootstrapping a service from a template** above — `create_service`
with `template_key: "acme"`, bind a connection/secret, and call it.

**Messy or third-party spec?** Use `import_template` instead — it persists a
**draft** even when validation warns, so you can refine it:

```
overslash_call {
  "service": "overslash",
  "action": "import_template",
  "params": { "openapi": "<spec>", "include_operations": ["send_message"], "key": "acme" }
}
```

Editing and **promoting** a draft to active is REST-only today (no MCP action):
`PUT /v1/templates/drafts/{id}` then `POST /v1/templates/drafts/{id}/promote`
(both `Authorization: Bearer …`). See `SPEC.md` for the full `x-overslash-*`
extension table (`risk`, `scope_param` — including its list and `param:label`
forms, `resolve`, `provider`, `default_secret_name`).

## When credentials are missing

`needs_authentication` and `ok` cover the happy path. Two other conditions need
different handling — and in both, **provisioning the actual secret material is a
human step you can only hand off, never perform yourself**: secret/credential
*values* are never returned to an agent (bearer-token reads return names +
metadata only; reveal is dashboard-session-only).

### When the OAuth client itself is missing

`needs_authentication` says "no user consent yet". A different failure is "there
is no OAuth client at all" — no managed client, no org-level OAuth credentials,
and no bring-your-own-client (BYOC). When that's the case, `create_connection`
(step 3) returns a `400`:

```json
{ "error": "bad_request",
  "message": "no OAuth client credentials configured for provider 'google'. Configure org-level OAuth App Credentials in Org Settings, or create a BYOC credential via POST /v1/byoc-credentials" }
```

You **cannot** fix this yourself — registering an OAuth client requires a
`client_id` / `client_secret` an agent must not hold. Surface the message to the
user and point them at the setup guide:
[Linking Google services](https://www.overslash.com/docs/guide/how-to/link-google-services.md)
(managed-client vs BYOC, Google Cloud Console steps, troubleshooting table).
A related `400 "pinned BYOC credential '<id>' not found"` means the connection's
BYOC client was deleted — tell the user to create a new connection.

### Providing a secret (non-OAuth services)

For secret-based services — an API key, a bearer token, an HMAC secret, or a
`user:password` pair — there is **no `auth_url`**. When
the required secret is absent, calling the action returns a `400`:

```json
{ "error": "credential_missing",
  "secret_name": "RESEND_API_KEY",
  "service": "resend",
  "hint_url": "https://app.overslash.com/secrets?name=RESEND_API_KEY" }
```

Mint a one-time provisioning link with the `request_secret` platform action and
surface it to the user — they paste the value on the page; **you never see it**:

```
overslash_call {
  "service": "overslash",
  "action": "request_secret",
  "params": { "secret_name": "RESEND_API_KEY", "purpose": "Send transactional email" }
}
```

Returns `{ request_id, provide_url, short_url, expires_at }`. Show `short_url`
(the oversla.sh link, present when the shortener is configured) or `provide_url`
verbatim. This is the secret-bag analogue of `create_connection`'s `auth_url`.
Once the user submits the value, retry the action. (The link's TTL is fixed at
1h over MCP; use the REST endpoint `POST /v1/secrets/requests` if you need to
override `ttl_seconds`.)

## Handling pending approvals

When `overslash_call` hits a permission gap it does not execute — it returns:

```json
{
  "status": "pending_approval",
  "approval_id": "abc-123",
  "approval_url": "https://app.overslash.com/approvals/abc-123",
  "expires_at": "…"
}
```

**Step 1 — show the user `approval_url`** so they can allow or deny in the dashboard.

**Step 2 — poll your inbox** until the approval turns into something you can act on:

```
overslash_call { "service": "overslash", "action": "get_events" }
```

It returns an array of events. The two that concern you here:

| `type` | What it means | What to do |
|---|---|---|
| `ready_to_call` | Approved, waiting for you to dispatch it (15-minute TTL) | `overslash_call { "approval_id": "abc-123" }` |
| `result_unread` | Already ran on your behalf — the output is waiting | `get_result` (Step 3) |

Which one you get depends on your identity's `auto_call_on_approve` setting. It
is **on by default**, meaning the gateway runs the action for you the moment it
is approved and you collect the output afterwards.

An empty array means nothing has changed yet — sleep briefly and poll again.
The approval itself expires, so this is not an infinite wait.

**Step 3 — collect the result.**

```
overslash_call { "service": "overslash", "action": "get_result",
                 "params": { "approval_id": "abc-123" } }
```

This returns the execution's `status`, `result`, `error`, and
`http_status_code`. Reaching for `overslash_call { "approval_id": … }` instead
will not work — that answers 409 once the action has already run.

Use `get_result` even if you already glimpsed the body elsewhere (`list_pending`
nests it too): it is the only call that marks the output as read, and an unread
result keeps reappearing in `get_events`.

**Never re-submit the original parameters once an approval exists** — that
creates a second approval instead of resuming the first.

Shell-capable harnesses can use the CLI instead of polling in-protocol (see
[Installing the CLI](#installing-the-cli) above):

```bash
overslash inbox                  # same event array, as JSON on stdout
overslash get-result abc-123     # exit 0 = executed, 1 = failed/pending, 2 = error
overslash watch abc-123          # block until resolved; --timeout 15m --poll 3s
```

## Your inbox

`get_events` is the one call that answers "is anything waiting on me?" — worth
running at session start to pick up work that survived an interrupted session.
A third event type appears when you have descendants:

| `type` | Meaning |
|---|---|
| `approval_needed` | A sub-agent below you is blocked and **you** can unblock it — resolve with `overslash_approve`. These are always someone else's request (`relationship: "downstream"`); your own parked requests never appear here |
| `ready_to_call` | Your approved action is waiting to be dispatched |
| `result_unread` | Your action already ran and you have not read the output |

Events carry `approval_id`, `action_summary`, `risk`, `relationship`, and the
execution's lifecycle — but never the result body. Use `get_result` for that.

The rest of the pending-execution surface, on the built-in `overslash` platform
service:

| Action | Effect |
|---|---|
| `get_events` | Everything waiting on you (above) |
| `get_result` | Fetch one execution's outcome — `params: { "approval_id": "…" }` |
| `list_pending` | Your approved actions still needing attention (dispatch or unread output) |
| `call_pending` | Dispatches one — `params: { "approval_id": "…" }` |
| `cancel_pending` | Discards one — `params: { "approval_id": "…" }` |

```
overslash_call { "service": "overslash", "action": "get_events" }
```
