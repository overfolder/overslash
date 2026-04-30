---
title: Agent self-bootstraps a new OAuth service via MCP only
status: Draft — partially implemented
related:
  - docs/design/agent-self-management.md
  - docs/design/user-stories.md
  - services/overslash.yaml
---

# Agent self-bootstraps a new OAuth service via MCP only

A concrete end-to-end narrative for an agent that, **without ever touching the dashboard**, takes a raw OpenAPI document, turns it into a working OAuth-backed Overslash service, and starts calling actions on it. This story exercises the platform metaservice (`service="overslash"`) end-to-end and pins down what is shipped today vs what still needs implementation.

It is the post-cleanup, post-bridge counterpart to Story 1 of [user-stories.md](user-stories.md), which uses the older `overslash_auth(action="create_service_from_template", …)` shape that has since been removed from the MCP surface.

---

## Actors

- **Mira** — individual user with an Overslash account at `https://mira.overslash.dev`. Has already enrolled an agent named `mira-assistant`.
- **mira-assistant** — an MCP-only agent (e.g. Claude Code wired to the Overslash MCP). Holds an Overslash bearer. Has no dashboard access.
- **Overslash** — `mira.overslash.dev`.
- **Eventbrite** — third-party SaaS Mira wants to integrate. Publishes an OpenAPI 3.1 document at a public URL and supports OAuth 2.1.

**Goal:** Mira tells `mira-assistant`: *"go set up Eventbrite for me — here's their OpenAPI doc — and pull tomorrow's events."* The agent produces a working service from scratch and a usable URL for Mira to click once. Nothing else.

---

## Happy path (5 steps, all over MCP)

### Step 1 — Create a service template from raw OpenAPI

The agent fetches the Eventbrite OpenAPI YAML (out-of-band — `mira-assistant` already has an HTTP fetch tool) and submits it to the Overslash metaservice:

```jsonc
overslash_call(
  service = "overslash",
  action  = "create_template",
  params  = {
    "openapi": "<raw YAML string>",
    "user_level": true        // template lives under Mira's user scope, not org-wide
  }
)
```

Overslash parses the document, applies the `x-overslash-*` normalizer, infers the OAuth provider from `securitySchemes`, and persists the template under Mira's identity. Returns:

```jsonc
{ "key": "eventbrite-mira", "tier": "user", "auth": { "type": "oauth", "provider": "eventbrite" } }
```

If the OpenAPI doc is invalid, this is the *only* point where a write is rejected — the call returns structured validation errors and nothing is persisted.

### Step 2 — Create a service from the template (no credentials yet)

The agent instantiates the template:

```jsonc
overslash_call(
  service = "overslash",
  action  = "create_service",
  params  = {
    "template_key": "eventbrite-mira",
    "name": "eventbrite",
    "status": "draft"          // explicitly not active until OAuth completes
  }
)
```

Returns a service detail row whose derived `credentials_status` is `needs_authentication` (no `connection_id`, OAuth required by template). This is **the "needs_authentication" state** the question asks about — it is not a stored enum value but a derived field computed at read time from the bound connection's state (`crates/overslash-api/src/routes/services.rs:573-577`).

The auto-add-to-Myself behavior at `services.rs:558-568` runs here: the service is granted to Mira's *Myself* group with `admin` access and `auto_approve_reads = true`, on-demand creating the group if missing. **Step 4 in the question is therefore satisfied as a side effect of Step 2 — there is no separate call.**

### Step 3 — Start OAuth and hand the URL to Mira

```jsonc
overslash_call(
  service = "overslash",
  action  = "create_connection",
  params  = {
    "service_id": "<id from step 2>",
    "provider":   "eventbrite"
  }
)
```

Returns:

```jsonc
{ "connection_id": "...", "auth_url": "https://eventbrite.com/oauth/authorize?...", "state": "..." }
```

The agent prints `auth_url` to Mira: *"click this once to authorize Eventbrite."*

#### Is this vulnerable to the Obsidian "MCP meets OAuth" pitfalls?

[Reference: *When MCP Meets OAuth: Common Pitfalls Leading to One-Click Account Takeover*, Obsidian Security.] The Overslash OAuth implementation is examined per-pitfall in `crates/overslash-api/src/routes/oauth.rs`:

| Pitfall | Verdict | Where |
|---|---|---|
| Shared client_id (confused-deputy) | **Mitigated.** Per-registration `client_id` via RFC 7591 DCR; no consent caching across clients. | `oauth.rs:81, 112` |
| Missing consent layer | **Mitigated.** Mandatory consent screen with server-issued `request_id`, 60s TTL, in-memory store. | `oauth.rs:46, 321-334` |
| State / session mis-binding | **Mitigated.** `state` round-tripped *and* tied to `session_claims.sub/org` at consent time; token issued to the consenting identity. | `oauth.rs:189, 263-288, 328, 940` |
| Open redirect on `redirect_uri` | **Mitigated.** DCR validates URIs at registration; authorize endpoint matches against the registered set. | `oauth.rs:93-100, 250-260` |
| PKCE missing or downgraded | **Mitigated.** S256 mandatory at authorize, `code_verifier` required at token exchange. | `oauth.rs:205-210, 1014-1021` |
| Refresh-token replay | **Mitigated.** Single-use rotation; replay revokes the entire chain. | `oauth.rs:1087-1099` |
| Cookie scope / SameSite | **Worth tightening.** Session cookie attributes are not explicitly `SameSite=Strict` on the IdP redirect path. Track separately; not in scope for this story. | `oauth.rs:276-286` |

**Net:** the agent handing `auth_url` to Mira is safe under the Obsidian threat model. The URL is bound to Mira's session (consent screen requires her to be logged in), to the registered redirect URI, and to a PKCE challenge the agent does not control. An attacker who intercepts the URL cannot complete the flow without Mira's session.

The piece worth flagging for follow-up is unrelated to step 3 itself — the cookie hardening — and applies whether the URL is delivered via MCP, dashboard, or platform.

### Step 4 — Mira clicks; service flips to active

Mira authorizes in her browser. Overslash's OAuth callback writes the encrypted token, links the connection to the service, and the derived `credentials_status` becomes `ok`. The agent polls:

```jsonc
overslash_auth(action = "service_status", params = { "service": "eventbrite" })
```

…and sees `{ "status": "active", "credentials_status": "ok" }`.

The auto-grant from step 2 is already in place, so no additional group/permission work is required. The agent can call actions immediately.

### Step 5 — Use the service

```jsonc
overslash_call(
  service = "eventbrite",
  action  = "list_events",
  params  = { "from": "tomorrow" }
)
```

The first call may return `{ "status": "pending_approval", "approval_id": "..." }` if no permission key matches yet — Mira clicks the approval URL, picks **Allow & Remember** at her preferred specificity tier, and subsequent reads auto-approve under the Myself-group `auto_approve_reads` flag (set in step 2).

---

## Surfaces touched

- **MCP only**, three tools: `overslash_call` (steps 1, 2, 3, 5), `overslash_auth` (step 4 polling), and the standalone approval/consent pages Mira clicks in the browser.
- **Zero dashboard pages** in the agent path. Mira touches two URLs: the OAuth consent screen (third-party + Overslash consent) and one approval page.

---

## What works today vs what is missing

### Shipped

- **Step 4 (auto-add to Myself).** Verified at `crates/overslash-api/src/routes/services.rs:558-568`. Runs on every service creation, including ones that would arrive via the bridge below. No new code needed.
- **Step 5 (`overslash_call` execution).** Shipped end-to-end at `crates/overslash-api/src/routes/mcp.rs:413-430` (and forwarded to `/v1/actions/call`).
- **OAuth security posture for step 3.** All the Obsidian pitfalls above are already mitigated server-side. Whatever calls the OAuth start endpoint inherits these protections — including a future MCP bridge.
- **Approval replay.** `list_pending` / `call_pending` / `cancel_pending` already bridged at `crates/overslash-api/src/routes/mcp.rs:792-841`.

### Missing implementations / PRs

The whole story collapses into one structural gap: the metaservice OpenAPI declares `manage_templates`, `manage_services`, `manage_connections` but the MCP dispatcher's `match action { … other => Err(…) }` at `crates/overslash-api/src/routes/mcp.rs:838-840` rejects everything except the three approval-replay actions. The work to land this story is a small, well-bounded sequence of PRs.

#### PR 1 — Bridge `manage_templates` actions in the metaservice dispatcher

- **File:** `crates/overslash-api/src/routes/mcp.rs`, function `dispatch_overslash_platform`.
- **Add arms** for `create_template`, `import_template`, `list_templates`, `get_template`, `delete_template`. Each forwards to the existing REST handler (`crates/overslash-api/src/routes/templates.rs:1219` for `import_template`, `templates.rs:695` for `create_template`).
- **Permission:** caller must hold `manage_templates` (already declared per-action in `services/overslash.yaml:80-99`). Reuse the existing extractor — no re-auth, no scope elevation.
- **Tests:** integration test under `crates/overslash-api/tests/` that posts a real OpenAPI YAML through MCP and asserts the resulting template row.
- **Risk surface:** template authoring is `risk: write` per the YAML. Should land as `manage_templates_own` per [agent-self-management.md §1](agent-self-management.md) — an agent can author its own templates but cannot publish them org-wide.

#### PR 2 — Bridge `manage_services` actions

- **File:** same dispatcher.
- **Add arms** for `create_service`, `update_service`, `list_services`. Forward to `services.rs:344` (`create_service`).
- **Behavior:** because `services.rs:558-568` already auto-grants to Myself, no extra wiring needed for step 4 of the story.
- **Tests:** integration test that creates a service via MCP, asserts the Myself grant exists, asserts `credentials_status == "needs_authentication"`.

#### PR 3 — Bridge `manage_connections` actions

- **File:** same dispatcher.
- **Add arm** for `create_connection`. Forward to `crates/overslash-api/src/routes/connections.rs:59-144`.
- **Returns:** the existing `{ auth_url, state, provider }` structure. No new shape to design.
- **Permission:** `manage_connections` (`services/overslash.yaml:36-38`).
- **Tests:** integration test that walks template → service → connection → asserts a usable `auth_url`. The OAuth callback path itself (the security-critical half) is unchanged and already covered.

#### PR 4 — Structured `needs_authentication` error from `overslash_call`

Independent of the bridge but tightly coupled to the agent UX. Today, calling an action on a service whose connection isn't ready returns a string-wrapped 400 ("secret not found"). The agent has no way to distinguish *"the service is misconfigured"* from *"I just need to start OAuth."*

- **File:** `crates/overslash-api/src/routes/mcp.rs::dispatch_call` (around line 784) plus the upstream `forward` helper.
- **Shape:** extend the result envelope to carry typed errors:
  - `{ "error": "needs_authentication", "service": "...", "service_id": "...", "hint": "call overslash.create_connection" }`
  - `{ "error": "reauth_required", "connection_id": "...", "auth_url": "..." }` (already partially structured in `oauth.rs`)
  - `{ "error": "missing_scopes", "connection_id": "...", "missing": [...], "upgrade_url": "..." }`
- **Tests:** add cases to the existing MCP integration tests that exercise each error type.
- **Spec link:** [agent-self-management.md §5](agent-self-management.md).

#### PR 5 — Permission grants for new agent-bootstrap scopes

The `_own` vs `_share`/`_publish` split from [agent-self-management.md §1](agent-self-management.md) needs to land at the permission-rule level so an agent can be granted `manage_services_own` without inheriting `manage_services_share`. This is a one-time schema/permission-key change in the dashboard + REST layer.

- **Files:** permission key parsing (likely under `crates/overslash-core/src/permissions/`), template normalization, default permission seeds.
- **Tests:** unit tests on permission resolution; one integration test asserting an agent with only `_own` cannot call `_share` actions.

#### PR 6 — Documentation update

- **File:** [user-stories.md](user-stories.md).
- **Change:** rewrite Story 1 step 6 to use the new `overslash_call(service="overslash", action="create_service")` shape instead of the removed `overslash_auth(action="create_service_from_template", …)`. Today Story 1 is documenting an MCP shape that doesn't exist anymore.

#### Sequencing

PR 1 and PR 2 are independent and can land in either order. PR 3 depends on PR 2 (you create a connection *for* a service). PR 4 is independent and can land first or last; landing it first improves the diagnostic story while the bridge is being built. PR 5 should land before PR 1 reaches production permission defaults but can be developed in parallel. PR 6 follows whichever of PR 1–3 lands first.

---

## Out of scope for this story

- Cross-org service creation. Everything assumed within Mira's single org.
- Template *publishing* (org-wide / global). The bridge intentionally exposes `_own` only; promoting a template to global stays a dashboard act.
- Self-approval of the first call in step 5. If the agent's identity is `inherit_permissions`-linked to Mira, the first read may auto-approve through her group ceiling; otherwise Mira clicks once. Either way the answer is downstream of [agent-self-management.md §2](agent-self-management.md), not this story.
