# Overslash — Specification

A standalone, multi-tenant **identity and authentication gateway** for AI agents. Overslash handles everything between "an agent wants to call an external API" and "the API call runs with the right credentials."

Overslash is **purely an auth and identity layer**. It does not orchestrate agents, manage compute, track which nodes are connected, schedule work, or know anything about the runtime environment agents live in. It answers one question: "is this identity allowed to do this action with these credentials?" — and if yes, calls the authenticated HTTP request.

It owns: identity hierarchy, secret management, OAuth flows, permission rules, human approval workflows, action calls, service registry, and audit trail.

The name: it slashes through doors and auth for the user.

---

## 1. Problem Statement

AI agents that interact with external services (GitHub, Gmail, Stripe, Slack, etc.) face a common set of problems that every agent platform rebuilds from scratch:

1. **Secret management** — agents need API keys and tokens, but shouldn't hold them in context
2. **OAuth flows** — connecting to services requires redirect flows, token storage, and refresh logic
3. **Permission gating** — destructive actions (sending emails, creating PRs, charging cards) need human approval
4. **Audit trail** — organizations need to know what their agents did, when, and with whose authority
5. **Identity hierarchy** — agents spawn sub-agents, which spawn more sub-agents. Who approved what?

Every agent platform (Overfolder, OpenClaw, custom harnesses) solves these independently, badly. The auth code is coupled to the agent loop. Permissions are prompt-based ("please ask before sending"). Secrets leak into conversation context.

Overslash extracts all of this into a single service with a clean REST API that any agent platform can call.

---

## 2. Goals and Non-Goals

### Goals

1. Standalone service — not embedded in any agent framework
2. Multi-tenant — organizations with isolated identities, secrets, and audit
3. Hierarchical identities — users own agents, agents spawn sub-agents, permissions flow up
4. Versioned secret vault — encrypted, never returned via API, with version history
5. OAuth engine — system credentials and BYOC (Bring Your Own Client) per identity (User or Agent)
6. Permission chains — every level in the identity hierarchy must authorize an action
7. Human approval workflows — with expiry, "Allow & Remember" with TTL, approval URLs for any channel
8. Universal HTTP execution — any REST API, with or without a service definition
9. Service registry — YAML-defined services (global + org-extensible) with human-readable action descriptions
10. Audit everything — every action, approval, secret access, connection change
11. Three integration surfaces over one backend — REST API, CLI (`overslash`), and MCP server, so any HTTP client, shell-capable agent, or MCP-aware editor can use Overslash without rebuilding the same plumbing
12. Meta tools — minimal tool interface for LLM agents (`overslash_search`, `overslash_call`, `overslash_auth`, `overslash_approve`) available across REST, CLI, and MCP surfaces
13. Web UI — for org admins and users to manage everything visually, served by Vercel in cloud mode and embedded same-origin in self-hosted mode (`overslash web`)
14. Single-binary self-hosting — `overslash` ships everything (API, dashboard, MCP server) so an org can run the entire product from one executable

### Non-Goals

1. **Being an agent framework or LLM router** — Overslash doesn't know about LLMs, prompts, or agent loops
2. **Orchestrating agents** — Overslash does not schedule, dispatch, or coordinate agent work. It has no concept of tasks, queues, or workflows.
3. **Managing compute or infrastructure** — no awareness of nodes, containers, runtimes, or where agents run. Overslash doesn't know or care what machine an agent lives on.
4. **Tracking agent connectivity** — Overslash does not monitor which agents are online, healthy, or reachable. It authenticates requests when they arrive.
5. **Executing code or managing VMs** — Overslash calls HTTP requests, not arbitrary programs
6. **Channel-specific UIs** (Telegram bots, WhatsApp) — callers build their own; Overslash provides approval URLs
7. **Being a general-purpose API gateway** — no rate limiting of upstream APIs, no caching, no transformation

---

## 3. Architecture

### Components

| Component | Tech | Purpose |
|-----------|------|---------|
| **Backend** | Rust / Axum | REST API, OAuth engine, permission resolver, action executor, audit logger |
| **Web UI** | SvelteKit | Web UI for org admins and users |
| **PostgreSQL** | — | All persistent state |
| **Encryption** | AES-256-GCM | Secret storage (key via env var or KMS) |
| **Valkey** (optional) | Redis-compatible | Webhook delivery queue, approval notification pub/sub, rate-limit counters. Valkey is preferred over Redis (see DECISIONS.md D4); Redis remains drop-in compatible. |

### How It Fits

```
Any Caller (agent platform, CI, human, script)
  │
  │  Authorization: Bearer ovs_acme_agent-henry_...
  │
  ▼
┌─────────────────────────────────┐
│          Overslash               │
│                                  │
│  Identity → Permission Chain     │
│  Secret Vault → Auth Injection   │
│  OAuth Engine → Token Refresh    │
│  Service Registry → Action Build │
│  Approval Workflow → Gate/Allow  │
│  Audit Trail → Log Everything    │
└──────────────┬──────────────────┘
               │
               ▼
         External Service
    (GitHub, Google, Stripe, ...)
```

### Integration Surfaces

Overslash exposes three peer surfaces over the same backend. The REST API is canonical; the CLI and MCP server are thin wrappers that hold credentials locally and call the REST API on the user's or agent's behalf.

| Surface | Audience | Transport | Credentials held | Distribution |
|---|---|---|---|---|
| **REST API** | Platforms, CI, custom integrations, agents capable of HTTP | HTTPS / JSON | Caller's choice (per-request `Authorization: Bearer ...`) | Hosted at the org's Overslash domain |
| **CLI (`overslash`)** | Developers, shell-capable agents, ops/admin scripting | Local process invocation, REST under the hood | One identity at a time, from `~/.config/overslash/` or env | Single static binary |
| **MCP server** | LLM agents inside MCP-aware editors (Claude Code, Cursor, Windsurf, ...) | **Primary**: MCP Streamable HTTP at `POST /mcp` (same Axum process as the REST API) with OAuth 2.1 (browser flow). **Compat**: stdio shim `overslash mcp` for editors whose MCP transport is stdio-only — proxies frames to `POST /mcp`. | None — the MCP client (or stdio shim) holds them. Default: an OAuth-issued user access token. Advanced: a static `osk_…` agent API key. | The HTTP transport ships in `overslash serve` / `overslash web`. The optional stdio shim is a subcommand of the same binary (`overslash mcp`). |

The MCP server reuses Overslash's existing IdP login flow as an OAuth 2.1 Authorization Server. A standards-compliant MCP client (Claude Code, Cursor, Windsurf, …) discovers the AS via `WWW-Authenticate` on a 401 from `/mcp`, fetches `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource`, dynamically registers itself ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)), opens a browser for the consent step, and uses the resulting access token on every subsequent JSON-RPC call. Editors that only speak stdio MCP point at `overslash mcp` (the compat shim), which holds a single token in `~/.config/overslash/mcp.json` and proxies every JSON-RPC frame to `POST /mcp` over Bearer. The shim is a pipe — no business logic, no dual credentials.

The session established by OAuth is an **agent identity** owned by the signed-in user, not the user itself: `/oauth/authorize` pauses at an in-app **consent step** where the user creates or picks the agent the MCP client will act as, and the `(user, client_id) → agent` binding is stored so repeat logins skip the prompt. Layer 2 applies (see §4 *MCP OAuth Enrollment*). Static `osk_…` agent keys remain available for non-interactive callers (CI, headless deployments). Approvals surface via the standard webhook / SSE / approval-URL path (§10 *Async Event Delivery*). Full design in [docs/design/mcp-oauth-transport.md](docs/design/mcp-oauth-transport.md). White-label platforms (e.g., Overfolder) bypass the MCP server entirely and call the REST API directly with their own UX.

### Distribution and Binary Layout

Overslash ships as a single executable, `overslash`, with subcommands:

| Command | Purpose |
|---|---|
| `overslash help` | Standard clap-generated help, including per-subcommand `--help` |
| `overslash serve` | Start the REST API only. Cloud-mode default. The dashboard is served separately (Vercel + SSR) and proxies API traffic back. |
| `overslash web` | Start the REST API *and* serve the SvelteKit dashboard same-origin from the same Axum process. Self-hosted mode. The dashboard is built with `@sveltejs/adapter-static` and embedded into the binary at compile time, so a single binary is the entire product. |
| `overslash mcp` | Stdio-to-HTTP shim for MCP clients that don't yet speak Streamable HTTP. Reads `~/.config/overslash/mcp.json` (server URL + bearer token) and proxies every JSON-RPC frame to `POST <server>/mcp`. No business logic — the actual MCP server lives in `overslash serve` / `overslash web`. See §10 for tool details. |
| `overslash mcp login` | Mint a token for the stdio shim by running the standard OAuth Authorization Code + PKCE flow against the configured server (opens a browser, captures the callback on `127.0.0.1`, writes `~/.config/overslash/mcp.json`). Replaces the old paste-tokens helper. |

MCP clients that speak Streamable HTTP (Claude Code, Cursor, Windsurf, …) point at the server URL directly and handle OAuth themselves via the AS endpoints:

```json
{
  "mcpServers": {
    "overslash": {
      "type": "http",
      "url": "https://<your-overslash>/mcp"
    }
  }
}
```

On first connection the client hits `POST /mcp`, receives `401 + WWW-Authenticate`, follows the AS metadata, dynamically registers, opens a browser for the consent step, and proceeds — no pre-shared secrets or prior CLI step required. See [docs/design/mcp-oauth-transport.md](docs/design/mcp-oauth-transport.md).

Editors that only speak stdio MCP use the `overslash mcp` compat shim instead:

```json
{
  "mcpServers": {
    "overslash": {
      "command": "overslash",
      "args": ["mcp"]
    }
  }
}
```

The stdio shim requires `overslash mcp login` once (runs the same OAuth flow interactively) and then proxies every JSON-RPC frame to `POST /mcp`. Both shapes terminate at the same handler and produce the same `(user → agent) → MCP token` binding server-side.

`serve` and `web` share the same `create_app` router and config — `web` only adds a static-file fallback and same-origin defaults. The `mcp` shim carries no Postgres or Axum dependency; it is a tiny stdio↔HTTP pipe.

### Multi-Org Deployment Model

- **Cloud** serves orgs off a single wildcard origin `app.overslash.com`. `*.app.overslash.com` resolves to the same instance; subdomain middleware maps the `Host` header to an `org_id`. `app.overslash.com` (the root) hosts Overslash-level login and the `/account` page; `<slug>.app.overslash.com` hosts an individual corp org.
- **Self-hosted** runs the same binary and code path. Two env flags scope it down:
  - `ALLOW_ORG_CREATION=false` — disables `POST /v1/orgs` and the dashboard's "Create org" CTAs. Existing orgs keep working.
  - `SINGLE_ORG_MODE=<slug>` — disables subdomain middleware; every request is scoped to the named org, the root-domain login lands directly in that org with no personal-org auto-creation, and the org switcher is hidden.

Self-hosted operators who want the "old" single-org experience set `SINGLE_ORG_MODE=<their-org-slug>`. Self-hosted operators who want full multi-org (e.g., an internal PaaS) leave both flags unset. See [docs/design/multi_org_auth.md](docs/design/multi_org_auth.md).

---

## 4. Identity Hierarchy

### User Authentication

Users authenticate to Overslash via external Identity Providers (IdPs). Overslash is a **Relying Party (RP)** — it does not store passwords or manage user credentials directly.

**Protocol: OpenID Connect (OIDC)** — the authentication layer built on OAuth 2.0. OIDC provides identity (who the user is) via ID tokens, while OAuth alone only handles authorization. Overslash uses the **Authorization Code Flow with PKCE** for all web-based logins.

**Supported IdP types:**
- **Social providers** — Google, GitHub (pre-configured, just needs client ID/secret)
- **Corporate SSO** — any OIDC-compliant IdP (Okta, Azure AD, Auth0, Keycloak, etc.) configured via the IdP's issuer URL. Overslash uses **OpenID Connect Discovery** (`.well-known/openid-configuration`) to auto-discover endpoints — org-admins only need to provide the issuer URL, client ID, and client secret.
- **SAML 2.0** — supported for enterprise environments that require it (many corporate IdPs only offer SAML). Overslash acts as a SAML Service Provider (SP). However, OIDC is preferred where both are available — SAML is XML-heavy, harder to debug, and less suited to SPAs.
- **Dev login** — a debug-only login method (enabled via env var, disabled in production) for local development without an external IdP.

**Configuration sources:** IdPs can be configured via environment variables or in-database settings. Env vars take precedence — an IdP set via env var cannot be disabled or modified from the dashboard (shown as read-only with an "env" badge). This includes dev login: if `DEV_LOGIN=true` is set, it's active regardless of DB settings. In-database IdPs are managed by org-admins in the Org Dashboard settings.

**IdP credential resolution.** Each IdP config stores its own `client_id` and `client_secret`. However, when org-level OAuth App Credentials exist for the same provider (§7), the IdP config defaults to those — the `[+ Add Provider]` flow pre-populates the fields from `OAUTH_{PROVIDER}_CLIENT_ID` / `SECRET` org secrets. The org-admin can accept the defaults (sharing one OAuth app for both login and API access) or override with dedicated credentials (e.g., a separate GCP project for login with a narrower consent screen). IdP configs that use the org defaults stay in sync — updating the org OAuth App Credential updates the IdP automatically. IdP configs with overrides are independent.

**Per-org IdP configuration:** Each org configures its own IdPs. An org can enable multiple IdPs simultaneously (e.g., Google for convenience + corporate Okta for SSO).

**User provisioning.** Overslash separates "the human" (`users` table) from "the actor in an org" (existing `identities` table linked via `user_id`). A `users` row is either **Overslash-backed** (bound to a root-level IdP in `overslash_idp_provider`/`overslash_idp_subject`, owns a personal org) or **org-only** (bound only through `identities` in corp orgs). Lookups at login are always by `(provider, subject)`; email is informational and is never used to merge users across IdPs or grant memberships.

**How humans end up in orgs.**

- *Personal org* — auto-created the first time a human signs in at the root domain via an Overslash-level IdP. Exactly one member, always the owner. Personal orgs cannot configure per-org IdPs and have no subdomain.
- *Corp org, as creator* — an Overslash-backed user creates a corp org via `POST /v1/orgs`; they receive a regular `admin` membership + an admin `identities` row in the new org. An org may stay on the Overslash-level IdP indefinitely (creator is its sole admin) or later configure its own IdP to onboard more humans. The creator's Overslash-level login continues to reach the org in either case — they're just an admin, no special flag.
- *Corp org, as member* — sign in through the org's own IdP on `<slug>.app.overslash.com`. Auto-provisioning is gated by `org_idp_configs.allowed_email_domains` (empty list = trust the IdP entirely). There are no invites; membership crossing trust domains (e.g., a Google-backed user into Acme without the creator path) is not supported.

**No cross-IdP account linking.** A human who uses Google for personal and Okta for Acme has two distinct `users` rows. This is intentional: Google and Okta are different trust domains and the system treats them as such. See [docs/design/multi_org_auth.md](docs/design/multi_org_auth.md).

### Hierarchy

```
Org (acme)
  └── User (alice)                     depth=0
       └── Agent (henry)               depth=1, parent=alice
            ├── SubAgent (researcher)   depth=2, parent=henry
            └── SubAgent (emailer)      depth=2, parent=henry
```

- **Users** auto-provisioned on first IdP login — at the root domain for personal orgs, at the org subdomain for corp org members, or via `POST /v1/orgs` for corp org creators (who become regular admins)
- **Agents** created by users
- **Sub-agents** created by agents — no user intervention needed
- **UI equivalence**: the UI does not distinguish between Agents and Sub-agents — they are all presented as "Agents" in the tree. The `sub_agent` kind remains an API/backend distinction (for idle cleanup and depth tracking), but the UI treats them identically. The only difference visible to users is who the parent is.
- Each identity has API keys for authenticating with Overslash
- Sub-agents are garbage-collected by **idle timeout** (ephemeral workers): if a sub-agent has not made an authenticated request for longer than the org's `subagent_idle_timeout_secs`, it is **archived** in two phases — first its API keys are auto-revoked and pending approvals expired (`archived_at` set), then after `subagent_archive_retention_days` the row is hard-deleted. Archived identities return `403 identity_archived` from the gateway with a `restorable_until` timestamp, and `POST /v1/identities/{id}/restore` un-archives within the retention window and resurrects the auto-revoked API keys (manually-revoked keys stay revoked). Parents never archive while a live sub-agent child exists, so active subtrees outlive idle parents. Org admins configure both knobs in `[4h, 60d]` and `[1d, 60d]` ranges respectively. Users and agents are never auto-archived.

### Agent Enrollment

Enrollment is **MCP OAuth 2.1** (MCP spec 2025-06-18 — RFC 8414 + RFC 7591 + PKCE). There is one path: an MCP client (Claude Code, Cursor, Windsurf, an `overslash mcp login` CLI run for editors that only take a static Bearer header, …) connects to `/mcp`, discovers the Authorization Server at `/.well-known/oauth-authorization-server`, registers itself via `POST /oauth/register`, and drives the user through a browser-hosted Authorization Code + PKCE flow at `/oauth/authorize`. A short instruction page for agents lives at `/SKILL.md` (served by the API, see the repo-root `SKILL.md`).

**Consent.** After the user signs in at `/oauth/authorize`, the server pauses the authorize request and redirects the browser to the dashboard at `/oauth/consent?request_id=…`. The dashboard renders the enrollment card (design-system styled) and calls a small JSON API (`GET /v1/oauth/consent/{request_id}`, `POST /v1/oauth/consent/{request_id}/finish`). In **new** mode the user picks a parent (defaults to themselves), toggles `inherit_permissions` (off by default — users opt in rather than out), and optionally attaches the agent to groups (search-and-create, with `everyone` implicit and never shown). In **reauth** mode — recognised when a DCR re-registration produces a new `client_id` but the previously-enrolled `client_name` + `software_id` still match an unrevoked binding for the same user — the card skips the form and simply rebinds the new `client_id` to the existing agent, preserving that agent's rules and groups.

**Binding.** On submission, the server persists a `(user_identity_id, client_id) → agent_identity_id` row and the dashboard follows the returned `redirect_uri` back to the MCP client with an auth code bound to the agent. Subsequent authorizations from the same `(user, client_id)` reuse the binding and skip the prompt. The issued access token's `sub` is the agent; `/mcp` refuses any token whose `sub` points at a user-kind identity so a pre-binding or CSRF-stolen token can't slip through. The consent screen is hosted inline in the OAuth flow — there is no separate "consent URL" sent out-of-band.

**Headless / long-lived credentials.** Static `osk_…` API keys minted via `POST /v1/api-keys` remain the credential for non-interactive callers (CI, batch jobs) — see §Authentication. Device-flow OAuth for headless clients is a future add.

### Identity Reconfiguration

After enrollment, an identity's configuration remains mutable:

- **Parent**: an identity can be reparented to a different position in the hierarchy (within the user's subtree)
- **`inherit_permissions`**: can be enabled or disabled at any time
- **Remembered approvals**: can be viewed and revoked per identity

### `inherit_permissions`

A live pointer (not a copy). When set on an identity, it dynamically has whatever permissions its parent has — current AND future. Parent gains a rule tomorrow, child gains it too.

---

## 5. Permission System

### Unified Permission Key Format

All permissions in Overslash use a single key format:

```
{service}:{action}:{arg}
```

This format covers every level of abstraction — from registry-defined actions to raw HTTP:

| Key | Meaning |
|-----|---------|
| `github:create_pull_request:overfolder/*` | Registry action, scoped to repos |
| `github:*:*` | Any action on GitHub |
| `github:POST:/repos/*/pulls` | Specific HTTP verb + path against GitHub |
| `github:ANY:*` | Any HTTP request against GitHub |
| `http:POST:api.example.com` | Raw HTTP to a specific host |
| `http:ANY:*` | Unrestricted HTTP proxy |
| `secret:gh_token:api.github.com` | Inject a specific secret toward a specific host |

**Special action values:**
- **HTTP verbs** (`GET`, `POST`, `PUT`, `DELETE`, etc.) — allow specific HTTP methods against the service
- **`ANY`** — allow any HTTP method
- **`*`** — wildcard matching any action (note: `{service}:*:*` currently permits both registry actions and raw HTTP verbs against the service; in the future, groups may introduce finer-grained controls to limit `{service}:ANY` or direct HTTP access even when `{service}:*:*` is granted)

**Pseudo-services:**
- **`http`** — raw HTTP access with no service abstraction. The arg is the target host. Most orgs won't grant this — it turns Overslash into a general HTTP proxy.
- **`secret`** — secret injection gating. The action is the secret name, the arg is the target host. Required alongside `http` keys when secrets are injected. Prevents a secret approved for one host from being exfiltrated to another.

### Two-Layer Model

Permissions are enforced in two layers:

**Layer 1: Groups (coarse-grained ceiling, org-admin managed)**

Groups define which services are available and at what access level. They constrain users, and agents inherit their owner-user's group ceiling. A request that exceeds the group ceiling is denied outright — no approval can override it. Groups also control **service visibility**: if a user isn't in any group granting access to a service, that service is hidden from service listings and the API Explorer.

Group grants reference **org-level service instances** directly (via FK), paired with a structured **access level**:

Group examples:
- "Engineering": github (write), slack (write), stripe (read)
- "Admin": github (admin), slack (admin), stripe (admin), + raw HTTP access
- "Read-only": github (read), slack (read)

Access levels map to the `Risk` enum:
- **read** — non-mutating actions only (`risk: read`, or GET/HEAD/OPTIONS for raw HTTP)
- **write** — read + mutating actions (`risk: write`, + POST/PUT/PATCH)
- **admin** — full access including destructive actions (`risk: delete`, + DELETE)

Raw HTTP access (Mode A) is gated by a separate `allow_raw_http` boolean on the group — it is not a service instance.

User-owned service instances bypass the group ceiling for the creator (they own the instance), but their agents still need permission keys via approvals.

When a user has no group assignments, no ceiling is enforced (permissive). Orgs opt into enforcement by creating groups and assigning users.

**Auto-approve reads:** Each service grant in a group can optionally enable `auto_approve_reads`. When set, non-mutating requests (actions where `risk: read`, or GET/HEAD/OPTIONS for raw HTTP) from agents automatically create permission keys without requiring user approval. Mutating requests (`risk: write` or `delete`) still go through normal approval flow. This is configured per-service per-group — org-admins decide which services have sensitive read operations (financial data, PII) vs ones where reads are safe (listing PRs, checking calendar events).

**Layer 2: Permission keys (fine-grained, user-managed, agent-specific)**

Within the group ceiling, agents require specific permission keys for each action. Keys are created when a user clicks "Allow & Remember" on an approval — they are never written by hand. Permission keys build up organically as agents are used and users approve their actions. Users acting through the dashboard or API Explorer are gated by groups only — they are their own approvers.

### Resolution Flow

1. Agent makes a request → system derives permission keys from the request
2. **Group check**: is the service + access level within the owner-user's group grants? If not → **deny** (not approvable)
3. **Permission key check**: are all derived keys covered by existing rules for this identity? If yes → **auto-approve**
4. If not → **create approval request** → user decides → "Allow & Remember" stores keys with optional TTL

### Hierarchical Resolution

When a sub-agent calls an action, every level in the ancestor chain must authorize:

1. Check sub-agent → has matching key or `inherit_permissions`? Pass, continue up.
2. Check agent → has matching key? Pass, continue up.
3. Check user → within group ceiling? Pass. All levels authorized → **call**.
4. First level without a matching key and without `inherit_permissions` → **gap**. Create an approval (see below).

### Approval Bubbling

When a gap is found, an approval is created. The approval is **always linked to the requesting identity** (`identity_id` = the agent that triggered the action) — for audit, display, and so the requester sees the same approval whether resolved by an agent or a user.

The approval has a **current resolver**: the closest ancestor that can act on it. The resolver search walks upward from the requester:

- An ancestor can resolve only if the requested permission is within its **own boundary** (parent cannot grant a child more than itself has — same/narrower keys, same/shorter TTL).
- Identities with `inherit_permissions=true` are skipped — they don't own permissions, they borrow.
- The user is always the final resolver of last resort (constrained only by the group ceiling).

The current resolver receives the approval (via webhook or polling) and chooses one of:

- **Approve (Allow Once)** — the approval transitions to `allowed` and an `executions` row (`status='pending'`, 15-minute lifetime) is created. The requesting agent (via `POST /v1/approvals/{id}/call`) or the resolver (via the dashboard's "Execute Now" button calling the same endpoint) can then trigger the replay. If neither fires within 15 minutes, the pending execution expires and no action runs. The resolver may also `POST /v1/approvals/{id}/cancel` to invalidate the pending execution; on Allow Once this is terminal for the agent — it must request a fresh approval to try again.
- **Approve & Remember** — as above, and on **successful `/call`** a permission rule is stored (see "Rule placement" below). Cancel, expire, or replay failure ⇒ no rule is persisted; the reviewer can retry after addressing the underlying cause.
- **Bubble up** — defer to the next ancestor that can resolve, or the user if none.
- **Reject** — denied. No execution row is created; the stored `action_detail` remains for audit.

**Rule placement on Approve & Remember**: the new permission rule is added to the **closest non-`inherit_permissions` ancestor of the requester** (inclusive of the requester). Identities with `inherit_permissions=true` are skipped because their permissions are dynamic — putting a rule there would be silently overridden by parent walks. This is the requester's "permission-owning" identity.

**Why this arrangement is expected to be common.** Real-world agent deployments tend to converge on a multi-level hierarchy:

- **A single powerful "main" agent per user.** Users want one always-on agent (a Chief of Staff, an executive assistant, an ops manager) with broad authority across the services they own. It's the day-to-day driver and the entry point for delegation.
- **Specialist sub-agents with minimum-privilege boundaries.** The main agent spawns long-lived specialists (Marketing, Finance, Engineering, Support) that each own a slice of the business. These intentionally do **not** inherit the parent's full power — they get only the services they need. This keeps a compromised or misbehaving specialist from reaching beyond its lane.
- **Ephemeral task-scoped sub-sub-agents.** Specialists in turn spin up short-lived workers (a Researcher, a Reviewer, a Drafter) for individual tasks. These typically do use `inherit_permissions=true` because they're temporary and their privileges should track the parent's exactly — there's no lasting identity to grant rules to anyway.

The result is a User → Main → Specialist → Worker shape with `inherit_permissions=true` only at the leaves. The bubbling model is designed for exactly this: most approvals get handled by the specialist or the main agent (which already has the relevant authority), and the user is only pulled in when something genuinely crosses a privilege boundary.

**Example.** Chain: `User:alice → Agent:ChiefOfStaff → Agent:Marketing → Agent:Researcher (inherit_permissions=true)`.

- alice's group grants `service-a`, `service-b`, `service-c` (full).
- ChiefOfStaff has rules for `service-a:*` and `service-b:*`.
- Marketing has rules for `service-a:*`.
- Researcher inherits from Marketing.

Researcher calls `service-b:action`:
1. The approval is filed against Researcher (`identity_id = researcher`).
2. Researcher is skipped (inherits). Marketing can't resolve (no `service-b`). ChiefOfStaff has `service-b` → **initial resolver = ChiefOfStaff**.
3. Chief picks Approve & Remember → rule is created on **Marketing** (Researcher's closest non-inherit ancestor), not on Researcher.
4. Next time Researcher does the same action, it auto-passes via Marketing's new rule.

If Chief instead bubbles up → resolver = User. If Researcher had called `service-c:action`, the resolver search would have skipped Marketing (no `service-c`) and ChiefOfStaff (no `service-c`) and gone directly to alice.

**Auto-bubble timeout.** If an approval sits with its current resolver longer than `approval_auto_bubble_secs` (per-org setting, default 300s = 5 minutes), it automatically bubbles to the next ancestor. Setting this to `0` makes every approval go straight to the user (skip agent resolvers entirely). This prevents requests from getting stuck on an absent or unresponsive agent resolver.

### Visibility Scoping

`GET /v1/approvals` accepts an optional `?scope=` filter so callers can ask three different questions about the same pending-approvals set without round-tripping the whole list:

- **`?scope=mine`** — approvals the **caller has requested** (`identity_id = caller`). Useful for an agent polling "what am I waiting on?" or for a user to see things they themselves submitted via the dashboard.
- **`?scope=assigned`** — approvals where **the caller is the current resolver right now** (`current_resolver_identity_id = caller`). This is the strict "inbox" view: only approvals that are sitting on this exact identity, not on a descendant. Excludes anything the caller requested themselves (the self-resolve ban — see "Trust Model and Approval Resolution" below — would block resolution anyway).
- **`?scope=actionable`** — approvals the caller **could act on**: the caller is the current resolver, **or** any descendant of the caller is the current resolver. An ancestor can always step in for a descendant, so this surfaces everything in the caller's subtree. Also excludes self-requested approvals.
- **No `scope`** — legacy org-wide listing of all pending approvals. Preserved for back-compat with admin tooling.

`mine`, `assigned`, and `actionable` all require an identity-bound credential (the caller has to be a real identity to ask "is this mine?").

The three scopes layer naturally for a dashboard inbox: `assigned` is the bell-badge count, `actionable` is the broader queue an org admin or main agent can drain on behalf of subordinates, and `mine` is the "outbox" of things the caller is waiting on.

### Trust Model and Approval Resolution

The core trust assumption: **agents are not trusted to approve their own actions.** Overslash exists precisely because prompt-based permission ("please ask before sending") is not real security. The approval system enforces this:

**Who can resolve an approval:**
- **Users** — via the Overslash dashboard (logged in) or via the platform's UX calling the resolve API with the user's credentials
- **Ancestor agents** — an agent can approve for its sub-agents, but **only** if the permission being granted is already within the agent's own boundary (same or narrower keys, same or shorter TTL). A parent cannot grant a child more than it has itself.
- **The requesting agent itself** — **never**. An agent cannot resolve its own approval requests.

**How approvals flow through the platform:**

1. Agent calls `overslash_call` via the platform → gets `{ "status": "pending_approval", "approval_id": "apr_abc123" }`.
2. The agent cannot resolve this. The platform receives the approval event (via webhook or polling on the user's behalf).
3. The platform surfaces the approval to the user in its own UX (Telegram buttons, Slack message, CLI prompt, etc.) including the `suggested_tiers` and `description` from the approval payload.
4. The user makes a decision. The platform calls `POST /v1/approvals/{id}/resolve` using the **user's** Overslash credentials — not the agent's API key. Resolve **does not run the action**; on `allow`/`allow_remember` it moves the approval to `allowed` and creates a pending `executions` row.
5. Replay is then triggered explicitly by one of:
   - **Agent** — `POST /v1/approvals/{id}/call` (sync; returns the replayed result).
   - **User** — "Call Now" in the dashboard, which calls the same endpoint.
   An atomic `pending → executing` transition plus a unique index on `(approval_id)` guarantees at-most-one replay even under user+agent races.
6. Pending executions expire after **15 minutes**. The resolver may also `POST /v1/approvals/{id}/call`.

The agent observes the outcome by polling `GET /v1/approvals/{id}` (the nested `execution` object transitions with the row) or by listening for the `approval.executed` / `approval.execution_failed` / `approval.execution_cancelled` webhooks. A dedicated `GET /v1/approvals/{id}/execution` endpoint returns the execution summary directly.

**There is no self-authenticating approval URL.** Approval resolution always requires credentials of an identity with authority over the requesting identity. This prevents an agent from obtaining and resolving its own approval link.

**Overslash-hosted approval page:** Overslash provides a deep-link URL for each approval: `https://acme.overslash.dev/approvals/apr_abc123`. This page requires login — if the logged-in user has authority to resolve the approval, they see the full approval details and specificity picker. If not logged in, they hit the login page and get redirected back. Platforms can include this URL when surfacing approvals to users as a zero-integration-effort path — the platform doesn't need to build its own approval UI. The platform decides whether to link to Overslash's page or handle resolution in its own UX.

(The secret request page at `/secrets/provide/req_...?token=jwt` uses a signed URL because providing a secret doesn't grant the agent authority — the agent still needs a separate approval to use it.)

### Pending Approval Limits

Each agent identity can have **at most 3 pending approvals** at any time. When a new approval request is created and 3 already exist, the oldest pending request is automatically dropped (denied with reason "superseded"). This prevents stale approvals from accumulating when agents are actively working.

### Notification Delay

Approval and secret requests are **not notified immediately**. Only requests that remain unresolved for **more than 1 minute** trigger notifications (bell badge, email, webhook). This prevents flash notifications for requests that agents or ancestor identities resolve quickly on their own. Notifications auto-dismiss when the underlying request is resolved.

### Remembered Approvals

"Allow & Remember" on an approval creates permission key rules with optional TTL. These rules auto-approve matching future requests. Permission rules and remembered approvals are the same concept — "permission rules" is the storage format, "remembered approvals" is the user-facing term. Users can view and revoke them per identity via the dashboard.

The rule is stored **only after a successful `POST /v1/approvals/{id}/call`** — a cancelled, expired, or failed replay leaves no rule behind. This prevents a reviewer from being silently committed to auto-approving an action they never saw succeed.

### Replay Semantics

Approval and action execution are decoupled into two stages. `POST /v1/approvals/{id}/resolve` records a decision (and, on `allow`/`allow_remember`, creates a pending `executions` row with a 15-minute lifetime); the action itself only runs when something explicitly calls `POST /v1/approvals/{id}/call`.

- **Stored payload.** At approval creation, Overslash serialises the resolved `ActionRequest` plus the original caller's `filter` and `prefer_stream` flags into `approvals.action_detail`. Secret values are never stored — only `SecretRef` (name + injection metadata), resolved fresh at replay time. A rotated secret is used in its current form.
- **At-most-once.** `executions.approval_id` is uniquely indexed and the `pending → executing` transition is an atomic SQL UPDATE guarded by `status='pending' AND expires_at > now()`. User and agent can race `/execute`; exactly one wins, the other receives 409. Any terminal state (executed / failed / cancelled / expired) is sticky.
- **Identity & audit.** Replay always uses the **requester's** identity for audit and rate limiting, regardless of whether the agent or the resolver pressed the button. The `audit_logs` row for `action.executed` carries `detail.replayed_from_approval` and `detail.execution_id`; a separate `approval.executed` entry records the button press.
- **Streaming.** Originally-streaming requests are replayed as buffered requests (bounded by `MAX_RESPONSE_BODY_BYTES`) — there is no agent connection to stream to. The stored result flags `streamed_originally: true` so callers can tell.
- **Timeouts & orphans.** The `/call` handler bounds the upstream call with `EXECUTION_REPLAY_TIMEOUT_SECS` (default 30). If the API crashes while `status='executing'`, a sweeper transitions the row to `failed` with `error='orphaned'` after the timeout plus a minute of slack.
- **Ceilings.** The group-ceiling check is not re-run at `/call` — the resolver's allow is authoritative, and the ceiling was enforced at approval creation.

### User Identities Skip Layer 2

Permission keys (Layer 2) are an **agent-only** concept. When a request is authenticated as a **user identity** — not an agent — only Layer 1 (group ceiling) applies. There is no approval flow, no permission key resolution, no "Allow & Remember" prompt: the user is their own approver, and any action within their group ceiling is called immediately.

This rule is transport-agnostic. It holds for the dashboard, the API Explorer, an MCP session logged in as a user, a CLI calling the REST API directly with user credentials, or any other surface. **What matters is the identity type on the credential, not the channel.**

A practical consequence: an MCP session established via the default OAuth flow is a *user* session, not an agent session. If a customer wants MCP usage gated by per-action approvals, they configure the MCP client (or the `overslash mcp` stdio shim) to authenticate with an `osk_…` agent API key directly, bypassing OAuth — at which point Layer 2 kicks in. In that mode, approvals surface via the standard webhook / SSE / approval-URL path (§10 *Async Event Delivery*); they are not resolved in-band by the same session that triggered them, because an agent cannot approve its own request.

### Platform-Managed Notifications

When a platform (Overfolder, OpenClaw, etc.) is mediating between Overslash and a user — surfacing approvals, secret requests, and OAuth handoffs in its own UX — Overslash's built-in notification machinery (bell badge, email, 1-minute delayed webhook) becomes redundant and can produce duplicate prompts.

Each identity (or each org) can set `notifications.managed_by_platform = true`. When set:

- The 1-minute delayed notification webhook is **suppressed** for that identity's approvals and secret requests
- The bell badge and email notifications are **suppressed**
- The platform is responsible for surfacing pending events via its own webhook subscription, polling, or SSE stream (§10 *Async event delivery*)

This is a per-identity flag (so a single org can have both platform-mediated agents and direct-use agents) but typically set at agent-creation time by the platform's enrollment flow.

### Specificity Tiers

When an approval is created, Overslash derives the most specific permission keys from the request and generates broader alternatives by progressively replacing segments with `*`. These are returned as structured data in the approval payload — no human-readable labels, so platforms can render them in any language or UI format.

```json
{
  "id": "apr_abc123",
  "status": "pending",
  "identity": "spiffe://acme/user/alice/agent/henry",
  "derived_keys": [
    { "key": "github:create_pull_request:overfolder/backend",
      "service": "github", "action": "create_pull_request", "arg": "overfolder/backend" }
  ],
  "suggested_tiers": [
    { "keys": ["github:create_pull_request:overfolder/backend"],
      "description": "Create pull request on overfolder/backend" },
    { "keys": ["github:create_pull_request:*"],
      "description": "Create pull request on any repo" },
    { "keys": ["github:*:*"],
      "description": "Any GitHub action" }
  ]
}
```

Each tier includes a `description` — an English human-readable label generated by Overslash from the service registry and key structure. Platforms can display it as-is, use it as fallback, or ignore it and build their own labels from the structured `derived_keys` parts for i18n.

For multi-key requests (e.g., `http` service with secret injection), keys within each tier broaden together as coherent sets — not as independent per-key choices. This keeps tiers to 2-4 options regardless of how many keys the request derives:

```json
{
  "derived_keys": [
    { "key": "http:POST:api.example.com", "service": "http", "action": "POST", "arg": "api.example.com" },
    { "key": "secret:api_key:api.example.com", "service": "secret", "action": "api_key", "arg": "api.example.com" }
  ],
  "suggested_tiers": [
    { "keys": ["http:POST:api.example.com", "secret:api_key:api.example.com"],
      "description": "POST to api.example.com with api_key" },
    { "keys": ["http:ANY:api.example.com", "secret:api_key:api.example.com"],
      "description": "Any request to api.example.com with api_key" }
  ]
}
```

The resolve endpoint accepts keys directly:

```json
POST /v1/approvals/{id}/resolve
{
  "resolution": "allow_remember",
  "remember_keys": ["github:create_pull_request:*"],
  "ttl": "24h"
}
```

`resolution` can be `allow` (one-time, no keys stored), `allow_remember` (stores keys), or `deny`. `remember_keys` can be a suggested tier verbatim or a custom set — Overslash validates that the keys don't exceed the group ceiling.

**Design principles:**

- **Overslash generates tiers; platforms render them.** Each tier includes an English `description` that platforms can display as-is or use as fallback. The structured parts (`service`, `action`, `arg`) in `derived_keys` give platforms everything they need to build labels in other languages.
- **Suggested tiers are convenience, not a constraint.** Platforms with 2 buttons can just use "Allow" + "Allow & Remember" (most specific tier). Platforms with more room can show multiple tiers. Overslash's own dashboard renders the full picker.
- **2-4 tiers max.** Multi-key actions compose within tiers to avoid combinatorial explosion.

### Org-Level ACL

Within an org, access control determines which users can see and manage which resources. An ACL (Access Control List) or role-based system governs:

- Which users can view/manage specific services, connections, and secrets
- Which users can create and manage agents
- Which users can resolve approvals for other users' agents
- Org-admin vs member vs read-only roles

This is distinct from the permission key system (which gates action execution). ACL controls who can administer Overslash itself within an org.

---

## 6. Secrets

### Versioned

Every write creates a new version. Latest is always used for injection. Earlier versions can be restored (creates a new version pointing to the old value). Version history records who created each version and when, enabling audit and confident rollback.

### Scoping

Secrets belong to the identity that created them. When agents set up integrations, they use `on_behalf_of` to create secrets at the owner-user level — so all agents under that user share them.

### Access Model

Secret values are encrypted at rest. Access to values depends on the actor:

| Actor | Own secrets | Child identity secrets | Other user secrets |
|-------|-----------|----------------------|------------------|
| **User** (dashboard) | read/write | read/write | — |
| **Agent** (API) | — | — | — |
| **Org admin** (User with `is_org_admin = true`) | read/write | read/write | read/write (all org) |

> **Org admin** is an attribute on a User identity, not a separate principal. There is no standalone "org" identity that can authenticate or hold API keys — every authenticated caller is a User or an Agent. Agents earn admin authority the same way they earn any other permission: by being placed in a group with `admin` access on the **`overslash`** meta service (a system-managed `service_instance` that represents Overslash itself within each org). The `is_org_admin` flag is the fast path for Users and is kept in sync with membership of the system **Admins** group.

- **Users** can view and manage secret values for all secrets in their subtree (their own + their agents' secrets) via the dashboard.
- **Agents** have **no read access to the secret vault via API key** — not even names or version numbers. Secret values are only injected at action execution time, gated by the permission chain. Listing and inspection of secrets is dashboard-only (JWT session auth), so the secret namespace is never exposed to a compromised agent token. Agents that need to confirm a rotation must rely on the audit trail or on a successful action execution.
- **Org admins** can view and manage all secrets across the org. This follows the standard model for org-managed credential stores (same as 1Password Teams, AWS Secrets Manager, etc.) and is required for compliance, debugging, and offboarding scenarios.

---

## 7. OAuth Engine

Overslash handles OAuth flows (authorization URL generation, code exchange, token storage, automatic refresh) for services that use OAuth authentication. The OAuth engine is internal machinery — not a user-facing concept. Users interact with **services** (§9), which encapsulate their credentials.

OAuth client credentials resolve via a three-tier cascade. At execution time, the OAuth engine walks the cascade top-to-bottom and uses the first match:

1. **User-level BYOC** — the user provides their own OAuth app credentials for a provider, stored as versioned secrets in the user's vault with well-known names: `OAUTH_{PROVIDER}_CLIENT_ID` and `OAUTH_{PROVIDER}_CLIENT_SECRET` (e.g., `OAUTH_GOOGLE_CLIENT_ID`). This lets power users or contractors use their own GCP/GitHub/etc. project without touching org config.

2. **Org-level** — org-admins configure OAuth app credentials for a provider at the org level, stored as org-level secrets with the same well-known naming convention. All users in the org inherit these credentials for services that use the provider. This is the recommended path for Google Workspace customers (see below).

3. **Overslash system credentials** — managed by instance operators via environment variables, used as defaults for all orgs. Covers consumer accounts and low-stakes scopes where a shared Overslash-verified app is acceptable.

If no credentials are found at any level, the connect flow shows an error explaining that no OAuth app is configured for this provider.

When a user creates a service from a template that uses OAuth, the connect flow walks them through the OAuth redirect. The resulting token is stored encrypted and bound to that service instance.

**Provider-level credentials, not service-level.** OAuth client credentials are scoped to the *provider* (e.g., `google`), not to individual services. Google Calendar, Google Drive, and Gmail all reference `provider: google` in their templates — they all share the same OAuth app credentials. Scopes differ per service, but the OAuth client is the same. This means an org that configures org-level Google credentials gets Calendar, Drive, and Gmail working with one setup.

**IdP and service credential reuse.** When an org configures Google as an IdP for login (§3) and also uses Google-based services (Calendar, Drive, Gmail), the same org-level secrets can serve both purposes. The IdP config (§3 `org_idp_configs`) and the OAuth engine both resolve to the same `OAUTH_GOOGLE_CLIENT_ID` / `OAUTH_GOOGLE_CLIENT_SECRET` org secrets. Org-admins configure Google credentials once — in Org Settings — and both login and service connections use them. This is intentional: a single GCP project with the right scopes covers both OIDC login and API access.

**System credentials and verification.** Overslash system credentials are subject to the upstream IdP's app-verification process. For Google in particular, sensitive scopes (Calendar, basic Gmail/Drive) require Google brand verification, and restricted scopes (full Gmail/Drive) require an annual CASA assessment by an authorized lab. This is expensive, slow, and recurs yearly. For Google Workspace customers, **prefer per-org credentials** — each Workspace admin creates their own GCP project, marks its OAuth consent screen as Internal, and provides client ID + secret to Overslash via Org Settings. Internal-tier clients require no Google verification regardless of scope. System credentials remain available as a default for low-stakes scopes and consumer accounts, but Workspace orgs should be onboarded via org-level credentials. (See [docs/design/google-workspace-oauth.md](docs/design/google-workspace-oauth.md) for the full analysis.)

---

## 8. Action Execution

### `POST /v1/actions/call`

All action execution goes through a single endpoint. The caller specifies a service instance and action — the level of abstraction is determined by what they choose:

**Service + defined action** — the caller names a service instance and a template-defined action (e.g., `github` + `create_pull_request`). Overslash builds the HTTP request from the template definition. Auth auto-resolved from the service's credentials. Derives key: `github:create_pull_request:{resource}`.

**Service + HTTP verb** — the caller names a service instance and an HTTP method + path (e.g., `github` + `POST /repos/X/pulls`). Auth is auto-injected from the service's credentials. For agents that know the API but want Overslash to handle auth. Derives key: `github:POST:/repos/X/pulls`.

**`http` pseudo-service** — the caller uses the `http` pseudo-service with a full URL, method, headers, body, and secret injection metadata. This is the lowest-level path — agents construct the full request. Requires `http` in the user's group. Derives keys: `http:POST:api.github.com` + `secret:gh_token:api.github.com`.

These are a spectrum of abstraction over the same execution pipeline and permission key format (`{service}:{action}:{arg}`).

### Gating

Every request derives permission keys. Resolution follows the two-layer model (§5):

1. Group ceiling check (service + access level)
2. Permission key check (all derived keys must be covered)
3. If uncovered → approval request → user decides → "Allow & Remember" stores keys

### Approval URLs

When `call_action` returns `pending_approval`, the response includes a user-facing URL the agent surfaces to its owner (e.g., "please approve here: `https://<dashboard>/approvals/<id>`"). The URL points at the dashboard deep-link page (`/approvals/{id}`), which renders as a modal overlay on top of `/agents` after login. The host portion is resolved from the deployment-level **`DASHBOARD_URL`** envvar (served by `overslash serve`; `overslash web` uses the same-origin dashboard host) — **never** from the API's own `Host` header and never hardcoded. Agent-facing responses must not leak internal API hostnames or placeholder domains (`overslash.example`, `api.*`) to downstream LLM output. Self-hosted deployments set the envvar; cloud deployments pick it up from the Cloud Run/Vercel config.

### Secret Injection (`http` service only)

When using the `http` pseudo-service, the caller specifies how each secret should be injected per-call (as header, query param, or cookie). This generates `secret:{name}:{host}` permission keys alongside the `http:{METHOD}:{host}` key. Both must be covered for auto-approval.

For service-based requests, auth is resolved automatically from the service instance's credentials — no manual secret injection needed.

### Human-Readable Descriptions

For registry-known services, action descriptions support **string interpolation** with `{param_name}` placeholders that resolve to the actual arguments at execution time:

```yaml
create_pull_request:
  description: "Create pull request '{title}' on {repo}"
  # → "Create pull request 'Fix bug' on overfolder/app"

list_pull_requests:
  description: "List pull requests on {repo}[ with state {state}]"
  # → "List pull requests on overfolder/app with state open"  (both provided)
  # → "List pull requests on overfolder/app"                   (state omitted)
```

**Optional params** use **conditional segments**: `[text with {optional_param}]` — the bracketed segment is included only when all its placeholders are present. This avoids dangling "with state" fragments when optional params are omitted.

These descriptions appear in: approval requests (what the agent wants to do), audit log entries, specificity tier descriptions, and the API Explorer response panel.

---

## 9. Service Templates and Services

Two distinct concepts:

- **Service Template** — an OpenAPI 3.1 definition describing an API: base URL, auth config, operations. No credentials. A blueprint.
- **Service** — a named instance of a template, bound to specific credentials. `work-calendar` is a Google Calendar template instantiated with alice@acme.com's OAuth token.

### Service Templates

Templates live in a three-tier registry:

| Tier | Managed by | Visible to | Mutable |
|------|-----------|------------|---------|
| **Global** | Overslash (shipped OpenAPI YAML) | Everyone | Read-only for orgs |
| **Org** | Org-admins | Org members | Full CRUD |
| **User** | Users (if org allows) | Creator + their agents | Full CRUD |

**Global**: OpenAPI 3.1 YAML files shipped with Overslash under `services/`. Common APIs (Eventbrite, GitHub, Gmail, Google Calendar, Google Drive, Slack, Stripe, Resend, X). Read-only for orgs. Org-admins can hide unused global templates from their org.

**Org**: Org-admins create templates for the org's internal or niche APIs. Visible to all org members (templates are blueprints — visibility doesn't grant access, creating a service instance does).

**User**: Users create personal templates for APIs only they use. Gated by org setting (`allow_user_templates`). Private by default. Users can **propose sharing** a template to org level — org-admin reviews and approves or denies.

**Org-admin visibility**: Org-admins can see all templates in the org (global + org + user-created) in a read-only list for security/compliance — they need to know what external APIs their users are connecting to.

### Template Definition

Templates are authored as OpenAPI 3.1 documents. Five AI-gateway-specific fields that OpenAPI cannot express natively live under the `x-overslash-*` vendor-extension namespace: `risk`, `scope_param`, `resolve`, `provider`, `default_secret_name`. For authoring ergonomics, the same keys may also be written without the prefix (just `risk:`, `scope_param:`, etc.) — the backend normalizes aliases to their canonical `x-overslash-*` form on load and before persist. Ambiguous documents (both forms present on the same object) are rejected with a stable `ambiguous_alias` error.

```yaml
openapi: 3.1.0
info:
  title: Google Calendar
  key: google_calendar              # alias for x-overslash-key
servers:
  - url: https://www.googleapis.com
components:
  securitySchemes:
    oauth:
      type: oauth2
      provider: google              # alias for x-overslash-provider
      flows:
        authorizationCode:
          authorizationUrl: https://accounts.google.com/o/oauth2/v2/auth
          tokenUrl: https://oauth2.googleapis.com/token
          scopes:
            https://www.googleapis.com/auth/calendar: ""
paths:
  /calendar/v3/calendars/{calendarId}/events:
    parameters:
      - name: calendarId
        in: path
        required: true
        description: "Calendar identifier (use 'primary' for the main calendar)"
        schema:
          type: string
          default: primary
        resolve:                    # alias for x-overslash-resolve
          get: /calendar/v3/calendars/{calendarId}
          pick: summary
    post:
      operationId: create_event
      summary: "Create event '{summary}' on calendar {calendarId}"
      risk: write                   # alias for x-overslash-risk
      scope_param: calendarId       # alias for x-overslash-scope_param
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [summary, start, end]
              properties:
                summary: {type: string, description: Title of the event}
                start: {type: object, description: "Start time object"}
                end: {type: object, description: "End time object"}
```

**Key gateway-specific fields:**
- **`x-overslash-risk` / `risk:`** — enum: `read`, `write`, `delete`. Defaults to a value inferred from the HTTP method (GET/HEAD/OPTIONS → read, DELETE → delete, else write). Influences auto-approve-reads behavior.
- **`x-overslash-scope_param` / `scope_param:`** — which parameter provides the `{arg}` segment in permission keys. Without it, the arg is `*`.
- **`x-overslash-resolve` / `resolve:`** — on a parameter, fetch a human-readable name for an opaque ID. Runs a follow-up GET against the service and extracts a field. Used in agent-facing descriptions.
- **`x-overslash-provider` / `provider:`** — on an `oauth2` security scheme, the symbolic OAuth provider name (`google`, `slack`, `github`, ...). Decoupled from OAuth URLs so the gateway can resolve credentials independently.
- **`x-overslash-default_secret_name` / `default_secret_name:`** — on an `apiKey` or `http` security scheme, the canonical secret name for auto-wiring. Templates are expected to declare **either** an OAuth scheme **or** an apiKey/http scheme with this field — OAuth templates don't fall back to an API key secret.
- **Platform-namespace actions** — `x-overslash-platform_actions` (alias `platform_actions:`) at the top level declares permission anchors with no HTTP binding (e.g. the `overslash` meta service's admin actions).

### OAuth Scopes

Service-level `scopes:` under the `oauth` auth block is the **superset** of scopes the service can request. What's actually granted by the provider is stored on the connection — the OAuth token response returns the accepted `scope` value, which is persisted in `connections.scopes` and is the ground truth for what the access token can do.

**Per-action scopes (planned).** A single connection doesn't always need every scope the service knows about — Gmail's `list_messages` only needs `gmail.readonly`, while `send_message` needs `gmail.send`. The planned model:

```yaml
auth:
  - type: oauth
    provider: google
    scopes:
      - https://www.googleapis.com/auth/gmail.readonly
      - https://www.googleapis.com/auth/gmail.send
      - https://www.googleapis.com/auth/gmail.modify
actions:
  list_messages:
    required_scopes: [https://www.googleapis.com/auth/gmail.readonly]
    # …
  send_message:
    required_scopes: [https://www.googleapis.com/auth/gmail.send]
    # …
```

At connect time, the caller picks which scopes to request from the service's superset (e.g., "read-only" vs "full"). At execution time, Overslash checks `connections.scopes ⊇ action.required_scopes` before dispatching; on mismatch it fails fast with an upgrade hint (`"reconnect with X scope"`) instead of letting the provider 403. This enables minimal-privilege connections and progressive reconnection when an agent reaches an action it isn't scoped for. `required_scopes` defaults to the service-level set when omitted (current behavior).

**Scope catalogs from upstream.** Scopes are hand-declared in YAML today. For large providers (Google, GitHub, Stripe) they can be codegen'd from Google Discovery documents or OpenAPI 3.x `security` annotations at build time — the YAML stays the runtime source of truth, the tool just keeps us honest as upstream APIs evolve.

### Secret-Token Templates

Templates whose `auth.type` is `api_key` (or any other secret-token variant) declare two extra fields to make the secret-provide flow usable:

```yaml
key: linear
display_name: Linear
hosts: [api.linear.app]
auth:
  - type: api_key
    instructions: "Paste your Linear personal API key. Find it at https://linear.app/settings/api"
    injection: { as: header, header_name: Authorization, prefix: "Bearer " }
    verify:
      method: GET
      path: /viewer
      expect_status: 200
```

- **`instructions`** — a short human-facing string telling the user *where to get the secret* and *what kind of secret it is*. Rendered verbatim on the `/secrets/provide/...` page above the input field, and returned in the `create_service_from_template` response so the agent can mention it when surfacing the URL. Without this, users staring at a "paste secret here" page have no idea what's expected. **Required for secret-token templates.**

- **`verify`** — an optional pre-flight HTTP probe fired immediately after the user submits the secret, before flipping the service to `active`. If the probe succeeds, the service goes `active`. If it fails (401, 403, network error), the service stays in `pending_credentials`, the error is shown on the same secret-provide page, and the user can paste a new value without restarting the flow (the row's JWT is re-issued in place). The annoying failure mode for secret services is "user typo'd the key, agent doesn't find out until hours later" — `verify` closes that gap. Opt-in per template because some upstream APIs charge for every request or rate-limit auth checks aggressively; for most APIs a `GET /viewer`-style probe is free and fast.

**Multi-secret templates** (e.g., AWS access key ID + secret access key) declare multiple slots under the auth block; the secret-provide page renders one input per slot and submission is atomic.

### Services (Instances)

A service is created by instantiating a template with a name and credentials:

```
Template: Google Calendar
  ↓
Service: "google-calendar"          (OAuth token for alice@acme.com — org default)
Service: "google-calendar"          (OAuth token for alice@gmail.com — user, shadows org)
Service: "client-calendar"          (OAuth token for alice@bigclient.org — user, different name)
```

**Service ownership:**
- **Org services** — created by org-admins, assigned to groups. All users in those groups can use them. Example: `github` (org's GitHub OAuth app, per-user tokens).
- **User services** — created by users, private to the creator and their agents. Example: `my-scraper`.

**Naming and resolution:**

Service names default to the template key in lowercase (e.g., template "GitHub" → service `github`). Names are scoped: org services and user services can share the same name.

Resolution uses **user-shadows-org**: when a user has a service with the same name as an org service, the user's instance takes precedence. To explicitly reference the org instance, use qualified syntax: `org/github`.

- `github` → user's `github` if exists, else org's `github`
- `org/github` → explicitly the org's instance

This lets users override org defaults with their own credentials (e.g., personal GitHub account instead of org's) simply by creating a service with the same name.

**Qualified vs unqualified names by context:**

| Context | Format | Example | Why |
|---------|--------|---------|-----|
| Permission keys | unqualified | `github:create_pull_request:*` | Follows resolution, no pinning to a specific scope |
| Group grants | FK to service instance | github (write) | Direct reference to org-level service + access level |
| Audit log | fully qualified | `org/github:create_pull_request:overfolder/app` | Forensic record — must show exactly which instance and credentials were used |
| Approval display | scope-qualified | `user/github` or `org/github` | User needs to know which credentials the agent will use (`user/` is sufficient — the user knows who they are) |
| API requests | unqualified (default) | `github` | Resolution applies; `org/github` available to bypass shadow |

**Permission keys** use the unqualified name and follow the same resolution:
- `github:create_pull_request:overfolder/*` — resolves through the user's `github` if it shadows, else the org's
- `google-calendar:list_events:*`

**Groups grant access to org services (instances)**:
- Engineering group gets: github (write), slack (write)
- Service discovery is group-gated: `GET /v1/services` returns org-level services only if the calling user (or agent's owner-user) belongs to a group that grants access to that service.
- User-owned services are always visible to their creator and bypass the group ceiling, but their agents still need permission keys via approvals.

**Service lifecycle:** see *Service Lifecycle States* below.

### Service Lifecycle States

A service instance moves through a small state machine. The same machine applies whether credentials come via OAuth, secret token, or no credentials at all (shared/free APIs).

| State | Meaning | Visible in `overslash_search`? | Cleanup |
|---|---|---|---|
| **`pending_credentials`** | Created, awaiting OAuth callback or secret submission via the credential flow URL | **No** — would pollute the catalog and let other agents try to use it | TTL: **15 minutes**, then deleted |
| **`active`** | Ready to use; credentials stored and (optionally) verified | Yes | — |
| **`error`** | OAuth denied, scopes insufficient, secret rejected, or credential verification failed in a non-recoverable way | **No** | TTL: **24 hours** for forensic visibility, then deleted |
| **`archived`** | Soft-deleted, hidden from discovery; audit log + remembered approvals preserved | No | Manual restore or hard-delete by owner |

There is intentionally **no `Draft` state**. A service is either configured-and-active or it is not. To test an active service before exposing it to agents, set the per-service flag `exposed_to_agents: false` — `overslash_search` filters it out for agent identities but the API Explorer can still call against it as the owner-user.

**`pending_credentials` is a single state with a `flow_kind: "oauth" | "secret"` discriminator** on the row. The lifecycle code has one path; only the credential-redemption surfaces (OAuth callback handler vs `/secrets/provide/...` page) differ.

**Pending visibility:** the owner-user sees pending services in the dashboard with a "Connecting…" badge and a "Cancel" button (manual delete before TTL). The creating agent sees its own pending services via `overslash_auth(action="status")`. No other identity in the org sees them.

**Executing against a pending service** returns `service_not_ready`, distinct from `not_authorized`. Agents should poll `status` (or subscribe via SSE) instead of retry-spamming `call`.

**Retrying a failed credential flow:** `overslash_auth(action="retry_credentials", service=...)` works on rows in `pending_credentials` (extends TTL, mints a fresh URL, invalidates the previous one) or `error` (flips back to `pending_credentials`, mints a fresh URL). The service ID and name are preserved across retries — the dashboard's "Connecting…" view stays continuous.

**Concurrent flows on one row:** the OAuth `state` value or secret JWT is single-use. `retry_credentials` purges the previous one before minting a fresh one, preventing replay races where two browser tabs could finish a flow.

**OAuth scope downgrade:** if the user grants only a subset of requested scopes, Overslash records the *actually granted* scopes on the service and flips to `active`. `overslash_search` returns the service's `actions` list filtered to the granted scopes — the agent sees a smaller surface than the template advertises and can decide what to do.

**Name conflicts at create time:** if the owner already has a service (active *or* pending) with the requested name, `create_service_from_template` returns `409 conflict` with the existing service ID. No auto-suffixing — the agent loses track of names. The agent can pick a different name or call `retry_credentials` against the existing pending row.

### Creating a Service

1. Pick a template (from global/org/user templates)
2. Name the service instance — defaults to the template key (e.g., `google-calendar`). Rename to create additional instances (e.g., `personal-calendar`).
3. OAuth client override (optional) — for templates that use OAuth, the user can optionally provide their own OAuth app credentials (client ID + client secret). If provided, these are stored as secrets `OAUTH_{PROVIDER}_CLIENT_ID` / `OAUTH_{PROVIDER}_CLIENT_SECRET` in the user's vault and used instead of org or system credentials for this user's connections to this provider. If omitted, the cascade (§7) resolves credentials normally.
4. Connect credentials — OAuth flow, API key input, or shared credential (for org services)
5. Optionally assign to groups (org-admin only)

For org services with OAuth (per-user tokens): the org-admin configures the org's OAuth app credentials as org-level secrets (`OAUTH_{PROVIDER}_CLIENT_ID` / `SECRET`, configured in Org Settings → OAuth App Credentials). Users in the assigned groups see the service and complete their individual OAuth flow using the org's app credentials. The service is shared, but each user has their own token.

### Programmatic Service Creation (Agent-Led)

The dashboard flow above has an exact REST counterpart: agents can instantiate templates without any human dashboard interaction. This is the path used by the meta tool `overslash_auth(action="create_service_from_template", ...)` (§10).

Authority rules:
- An **agent** can create services on behalf of its owner-user via `on_behalf_of` (§6 *Scoping*) — the resulting service is owned by the user, shared across all agents in that subtree.
- An agent **cannot** create org-level services. Only org-admins (acting as users) can.
- The calling identity must have the template visible to it (§9 *Tier visibility*).

The creation call returns one of:
- **OAuth-based template** → an OAuth start URL the user must visit. The service is created in a pending state pending the OAuth callback.
- **Secret-based template** (API key, bearer token) → a signed secret-provide URL the user must visit. The service is created in a pending state pending secret provisioning. (See §11 *Standalone Pages*.)
- **Shared/no-credential template** → the service is created `Active` immediately.

Once the user has supplied credentials at the returned URL, the service flips to `Active` and the agent learns about it via polling, SSE (§10 *Async event delivery*), or webhook. From the agent's perspective, the entire onboarding of a new integration is: search → auth.create → surface URL to user → poll for active → call. **No dashboard required.**

### OpenAPI Import

Upload an OpenAPI 3.x spec (file or URL) → Overslash parses it and stores a **draft template** with actions and parameter schemas. Available at both org and user tier. Because the template format is already an OpenAPI 3.1 superset, import is a mapping/augment pass rather than a translation: fetch → parse YAML/JSON → dereference local `$ref`s → synthesize missing `operationId`s → apply overrides (`key`, `display_name`) → optionally filter to the selected operations → normalize aliases to canonical `x-overslash-*` form → lenient compile.

**Drafts are DB-backed** (a `service_templates` row with `status='draft'`), not client-side state. This is the only way the flow works for agents invoking the REST API / MCP without a browser session: import in one call, promote in another. Dashboard users get the same benefit — half-finished imports survive browser reloads.

**Endpoints:**

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/v1/templates/import` | Create a draft from a source. Accepts `draft_id` to replace an existing draft's source without re-creating the row. |
| `GET`  | `/v1/templates/drafts` | List caller-visible drafts (org drafts for admins, user drafts for their owner). |
| `GET`  | `/v1/templates/drafts/{id}` | Fetch draft detail for review/edit. |
| `PUT`  | `/v1/templates/drafts/{id}` | Replace the draft's YAML (manual edits). Re-runs the lenient validator. |
| `POST` | `/v1/templates/drafts/{id}/promote` | Run the strict validator; on success flip `status='active'`. Fails closed with `TemplateValidationFailed` if the draft still has errors. |
| `DELETE` | `/v1/templates/drafts/{id}` | Discard. |

Drafts are **invisible** to `GET /v1/templates`, `overslash_search`, the runtime registry, and service-instance creation — they cannot be instantiated until promoted. The unique-key index on `service_templates` is scoped to `WHERE status='active'` so a draft can coexist with the template it plans to replace.

**Request shape:**

```json
{
  "source": { "type": "url",  "url":  "https://example.com/openapi.yaml" }
         | { "type": "body", "body": "...", "content_type": "application/yaml" },
  "include_operations": ["list_widgets", "create_widget"],  // optional; default = all
  "key":          "my-widgets",        // optional override of info.x-overslash-key
  "display_name": "My Widgets",         // optional override of info.title
  "user_level":   false,
  "draft_id":     null                  // pass to update an existing draft in place
}
```

**Response shape** (shared by import, get-draft, put-draft):

```json
{
  "id": "<uuid>",
  "tier": "org" | "user",
  "openapi": "<canonical YAML string>",
  "preview": { "key": "...", "display_name": "...", "hosts": [...], "auth": [...], "actions": [...] },
  "validation": { "valid": false, "errors": [...], "warnings": [...] },
  "import_warnings": [
    { "code": "derived_key",           "message": "...", "path": "info.x-overslash-key" },
    { "code": "derived_operation_id",  "message": "...", "path": "paths./widgets.post.operationId" },
    { "code": "openapi_3_0_source",    "message": "...", "path": "openapi" },
    { "code": "unresolved_external_ref","message": "...", "path": "..." },
    { "code": "http_insecure",         "message": "...", "path": "source.url" }
  ],
  "operations": [
    { "operation_id": "list_widgets", "method": "get", "path": "/widgets",
      "summary": "...", "included": true, "synthesized_id": false }
  ]
}
```

`preview` may be `null` when the source didn't compile cleanly; `validation.errors` explains why. The draft still persists so the user can fix it in the editor and re-save.

**URL-fetch policy** (for `source.type == "url"`):
- Accept `https://` silently; `http://` is accepted with an `http_insecure` warning (rendered as a dashboard banner).
- DNS-resolve the host up-front and reject if *any* resolved address is loopback, private (rfc1918, fc00::/7), link-local (169.254/16, fe80::/10), multicast, unspecified, broadcast, documentation, carrier-grade NAT (100.64/10), or IPv4-mapped private v6. Sidesteps basic DNS-rebinding.
- Manual redirect handling, max 3 hops, each hop re-validated.
- 10-second connect + read timeout; 512 KiB body cap (same as `POST /v1/templates/validate`).

**Partial import / selection:** `include_operations` takes `operationId`s (or the synthesized `{method}_{path-slug}` id for operations missing one). The response always enumerates *every* operation from the source with an `included` flag — the dashboard renders a checkbox tree so users refine selection without re-parsing the source. Unchecking an operation and re-submitting with the new `include_operations` (+ the same `draft_id`) rewrites the draft's YAML.

**OpenAPI 3.0 inputs** are accepted with a warning but not translated — schema objects using JSON-Schema-draft-04 semantics may fail the strict validator at promote time. Users fix those inline before promoting.

### Template Validation

The template YAML is parsed and validated by a pure-Rust linter in `overslash-core::template_validation`. The same linter is used by:
- **Backend**: `POST /v1/templates/validate` — accepts raw YAML in the request body, always returns HTTP 200 with a `ValidationReport`. YAML parse errors and duplicate mapping keys are themselves reported as validation issues rather than transport-level 4xx responses, so the dashboard editor can render diagnostics inline on every keystroke.
- **CRUD hook**: `POST /v1/templates` and `PUT /v1/templates/{id}/manage` run the same validator over the JSON-encoded `auth` / `actions` fields before writing to the database. A rejected save returns `400` with a `{"error": "validation_failed", "report": {…}}` body matching the validate-endpoint shape.
- **Registry loader**: shipped `services/*.yaml` files are validated at startup; a broken template is logged loudly and skipped (CI also runs a smoke test asserting every shipped template validates clean).
- **Dashboard**: calls the validate endpoint for linting. The linter core has no YAML, DB, or I/O dependencies — a WASM feature gate (`overslash-core/yaml`) is already in place so the module can be compiled to WASM for instant client-side validation once the dashboard wires it up.

**Response shape** (same for the endpoint and the CRUD error body under `report`):

```json
{
  "valid": false,
  "errors": [
    { "code": "unknown_scope_param", "message": "...", "path": "actions.list_events.scope_param" }
  ],
  "warnings": [
    { "code": "risk_method_mismatch", "message": "...", "path": "actions.list_events.risk" }
  ]
}
```

**Rules** (errors unless marked *warning*):

| Code | What it catches |
|---|---|
| `missing_field` | required field (`key`, `display_name`, `description`, `resolver.pick`, path on HTTP actions) is empty |
| `invalid_key` | service `key` does not match `^[a-z][a-z0-9_-]*$` |
| `invalid_action_key` | action key does not match `^[a-z][a-z0-9_]*$` |
| `invalid_host` | host is empty, contains scheme, path, or whitespace |
| `unknown_auth_type` | `auth[i].type` is not `oauth` or `api_key` (also surfaces as a `schema_error` on JSON input) |
| `incomplete_token_injection` | `token_injection.as="header"` without `header_name`, or `"query"` without `query_param` |
| `invalid_token_injection` | `token_injection.as` is not `"header"` or `"query"` |
| `invalid_http_method` | action `method` is not one of GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS |
| `invalid_path_syntax` | action `path` does not start with `/` or has an unclosed `{` placeholder |
| `unknown_path_param` | `{param}` in `path` does not reference a defined param |
| `path_param_not_required` | `{param}` in `path` references a param not marked `required: true` |
| `invalid_param_type` | `params.<name>.type` is not one of `string`, `number`, `integer`, `boolean`, `array`, `object` |
| `invalid_enum_values` | `enum` is empty, or `default` is set but not a member of `enum` |
| `unbalanced_brackets` | description has an unbalanced or nested `[` (segments are flat only) |
| `invalid_description_syntax` | description has an unclosed `{` placeholder |
| `unknown_description_param` | `{param}` in description does not reference a defined param |
| `unknown_resolver_param` | `{param}` in `resolve.get` does not reference a defined param on the same action |
| `unknown_scope_param` | `scope_param` does not reference a defined param |
| `invalid_response_type` | `response_type` is set to something other than `"json"` or `"binary"` |
| `duplicate_action_key` | the `actions:` mapping in YAML defines the same key twice |
| `yaml_parse` | YAML source could not be parsed (wrapped serde_yaml error) |
| `schema_error` | JSON input (CRUD path) for `auth` or `actions` is structurally malformed |
| `risk_method_mismatch` *(warning)* | read-only HTTP method (GET/HEAD/OPTIONS) is annotated with `risk: write` or `risk: delete` |

**Grammar notes.** `[optional segment]` in descriptions is **flat only** — nested `[` inside `[...]` is rejected. A `{param}` placeholder inside a description or `[...]` segment must reference a param defined on the same action. The runtime interpolator in `overslash-core::description` uses the same shared grammar primitives (`overslash-core::description_grammar`) as the linter, so "runtime accepts it but linter doesn't" drift is not possible.

**Platform namespace templates.** Services with empty `hosts` and actions that omit `method`/`path` (e.g. shipped `services/overslash.yaml`) are explicitly supported. An action with an empty `method` is treated as a non-HTTP permission anchor and the HTTP-specific rules are skipped for it — `description` and `scope_param` are still validated.

**Request body size.** `POST /v1/templates/validate` caps the body at 512 KiB. Larger payloads return `400 Bad Request` without running the validator.

---

## 10. Meta Tools for LLM Agents

A small tool set that lets any LLM agent use Overslash. These are the underlying tools surfaced by both the CLI (`overslash` subcommands) and the MCP server (the `POST /mcp` HTTP transport, optionally fronted by the `overslash mcp` stdio shim — see §3 *Integration Surfaces*); REST callers invoke the same operations directly. All four are surface-agnostic; the credential column reflects what kind of identity the call is meaningful from.

| Tool | Purpose | Credential | Surfaces |
|------|---------|------------|----------|
| `overslash_search` | Discover services and actions. Returns schemas + auth status. | agent (or user) | REST, CLI, MCP |
| `overslash_call` | Call any action (all three modes). Returns result or `pending_approval`. Called with `{approval_id}` to resume a previously-approved action and receive the replay result — see §5 *Replay Semantics*. | agent (or user) | REST, CLI, MCP |
| `overslash_auth` | Check/initiate auth, store/request secrets, create sub-identities, instantiate templates. | agent (or user) | REST, CLI, MCP |
| `overslash_approve` | Resolve a pending approval (one-time, "Allow & Remember", bubble, or reject). See §5 *Approval Bubbling*. | **user** (an agent cannot approve its own requests) | REST, CLI, MCP |

When the MCP session is OAuth-authenticated as a user (the default), Layer 2 is skipped entirely, so `overslash_call` returns results directly without ever producing a `pending_approval` for `overslash_approve` to resolve. The tool exists for the inverse direction — a user surface (dashboard, CLI, or an MCP session in user mode) resolving approvals raised by an *agent* identity elsewhere in the org. Platforms that wrap the agent surface handle approval plumbing themselves (webhook/polling/SSE → their own user UX → REST `POST /v1/approvals/{id}/resolve`).

### `overslash_search`

Discovery returns a structured payload with two distinct kinds of hits:

```json
{
  "services": [
    { "name": "google-calendar", "scope": "user", "status": "active",
      "template_key": "google-calendar",
      "auth": { "type": "oauth", "provider": "google", "connected": true },
      "actions": [ { "key": "list_events", "risk": "read", "params": { ... } }, ... ] }
  ],
  "templates": [
    { "key": "linear", "tier": "global", "display_name": "Linear",
      "auth": { "type": "api_key" },
      "actions_summary": ["list_issues", "create_issue", ...],
      "instantiable": true }
  ]
}
```

- **`services`** — service instances the calling identity can already use (gated by Layer 1 group ceiling and tier visibility).
- **`templates`** — blueprints visible to the caller that have **no** corresponding instance yet, with `instantiable: true` if the caller has authority to create one (typically via `on_behalf_of` for an agent's owner-user). Templates are filtered by tier visibility (global / org / user with `allow_user_templates`).

Search is **cheap and idempotent** by design. Agents are expected to re-query rather than maintain client-side state. There is no subscribe API for service catalog changes — re-call search after any state-changing operation (e.g., after `create_service_from_template` returns active).

### `overslash_auth`

Sub-actions, by category:

| Category | Action | Purpose |
|---|---|---|
| **Service instantiation** | `create_service_from_template` | Create a service instance from a template. Params: `template`, `name`, `scope` (`user`/`org`), `on_behalf_of?`. Returns OAuth start URL, secret-provide URL, or `active` immediately. |
| | `status` | Poll a pending service. Params: `service`. Returns the service's lifecycle state (`pending_credentials`, `active`, `error`, `archived`) along with `flow_kind` and `flow_url` when pending. See §9 *Service Lifecycle States*. |
| | `retry_credentials` | Re-issue a fresh credential flow URL for a `pending_credentials` or `error` service. Invalidates any previous URL on the same row. |
| **Secret management** | `list_secrets` | List secret names + version metadata visible to caller (never values). |
| | `request_secret` | Request a new secret value from a user. Returns a signed `/secrets/provide/req_...` URL. |
| | `rotate_secret` | Rotate a secret on an `active` service. Params: `service`, `slot`. Returns a signed `/secrets/provide/...` URL for the user to paste a new value. The service stays `active` throughout — rotation is a `secret_version++` operation, never a state change (§6, §9). |
| **Sub-identities** | `create_subagent` | Create a sub-agent under the calling agent. Params: `name`, `inherit_permissions?`, `ttl?`. Returns API key once. |
| **Auth introspection** | `whoami` | Return the calling identity's SPIFFE path, depth, owner-user, group memberships. |

### Async Event Delivery

Many flows are asynchronous from the agent's perspective: OAuth callback, secret provisioning, approval resolution. Overslash supports **three transports** for the same underlying events. Callers pick whichever fits their environment:

| Transport | Best for | Mechanism |
|---|---|---|
| **Polling** | Simple agents, no infra | Re-call the relevant `GET` endpoint (`/v1/services/{id}`, `/v1/approvals/{id}`). Idempotent. |
| **SSE** | Agents that can hold an HTTP connection | `GET /v1/events/stream?topics=...` opens a Server-Sent Events stream. Connection has a fixed **30-second timeout** — clients reconnect with `Last-Event-ID` to resume. The 30s ceiling keeps idle connections cheap, plays nicely with proxies, and forces clients to handle reconnection cleanly. Topics are scoped to the authenticated identity (e.g., `approvals`, `services`). |
| **Webhooks** | Platform integrations with their own infra | Configure a webhook endpoint per identity or per org; Overslash POSTs events with HMAC signature. |

The same event payload is delivered regardless of transport. Agents may use any combination — e.g., SSE for liveness during a foreground task, webhooks for background events, polling as a fallback.

When `notifications.managed_by_platform` is set (§5), Overslash's user-facing notifications (bell, email, 1-minute delayed webhook) are suppressed — but the event-stream transports above still fire normally, because the platform is the consumer.

---

## 11. Web UI

Web UI for non-API interactions. Built with SvelteKit + TypeScript.

**Two delivery modes.** In **cloud mode** the dashboard is hosted on Vercel with full SvelteKit (SSR allowed) and proxies API/auth/health/public/SKILL.md paths back to the API origin via `vercel.json` rewrites. In **self-hosted mode** the operator runs `overslash web`, which boots the same Axum app *and* serves the dashboard same-origin from embedded static assets (built with `@sveltejs/adapter-static`, embedded into the binary at compile time behind the `embed-dashboard` Cargo feature). Same-origin removes the cross-origin cookie and CORS complexity that Vercel rewrites paper over in cloud mode — the same router serves `/v1/*`, `/auth/*`, `/health/*`, `/public/*`, `/SKILL.md`, and falls back to the SPA for everything else (with `index.html` for unknown paths to support client-side routing). Cloud and self-hosted ship from the same codebase; the only difference is which Cargo feature is enabled and which subcommand is invoked.

### Core Views

- **Agents** (default landing view) — tree view of the identity hierarchy rooted at the logged-in user. The user node is immutable (cannot be deleted, renamed, or reparented). Agent creation does not offer a Kind selector — all created identities are agents, and parentage determines hierarchy position. Inline management: create, edit, delete agents.
- **User profile** — authenticated user info, API keys, settings
- **Services** — browse templates, create/manage service instances, connect credentials
- **Developer connection tool (API Explorer)** — interactive API explorer for connected services. Select a service, pick a defined action or make a custom request, fill in parameters, and call. Similar to Swagger UI or Postman but integrated with Overslash auth. Available actions adapt to the user's group grants (defined actions, HTTP verbs, or raw HTTP). Always calls as the logged-in user's own identity — no agent impersonation. Actions are logged in the audit trail under the user. Can be hidden via org setting.
- **Audit log** — searchable, filterable log of all actions, approvals, and secret accesses. Filterable by identity, service, time range, event type.

### Org-Admin Views

Templates (browse/create/import), Services (org-level instances, group assignment), Webhooks, Settings.

### User Views

My Services (instances + credentials), My Secrets (names + versions), Approvals (pending, one-click resolve with expiry picker), My Agents (permission management).

### Standalone Pages

Overslash provides built-in standalone pages for common user interactions. These serve two purposes: (1) direct use by unplatformed agents (e.g., agents connecting to Overslash without a platform intermediary), and (2) a zero-effort integration path for platforms that don't want to build their own UI for these flows.

Platforms can always build fully white-label equivalents using the same REST API these pages consume. The API exposes all the data needed: approval details with suggested tiers, secret request metadata, OAuth consent payloads. The built-in pages are a convenience, not a requirement.

- **Approval resolution** (`/approvals/apr_...`) — requires login. Shows approval details and specificity picker. See §5 Trust Model.
- **Secret request** (`/secrets/provide/req_...?token=jwt`) — no login required *by default* for the user landing on the page (signed URL). Secure input field for secret provisioning. Safe because providing a secret doesn't grant the agent authority. **One page, two contexts:** this URL is used both for (a) mid-execution secret requests when an agent calls `overslash_auth.request_secret` and (b) initial bootstrap of a secret-based service when an agent calls `create_service_from_template` against an API-key template (§9 *Programmatic Service Creation*). Both contexts share the same security properties — the signed token scopes the page to a single secret slot on a single identity.

  **The API calls that generate these URLs always require an authenticated identity** — typically an enrolled agent acting `on_behalf_of` its owner-user, or a user acting through the dashboard. There is no path for an unenrolled or anonymous caller to issue a secret-provide URL. The "no login" property describes only the user-facing redemption step, not the issuance step.

  #### User Signed Mode

  The signed URL is anonymous by default — the JWT in the URL is the sole capability gate. Two strictly additive enhancements raise the bar for orgs that need a named human on every secret provision:

  1. **Opportunistic session binding.** If the visitor's browser already holds a valid `oss_session` cookie for the same org as the request, the page captures that identity on the `secret_versions.provisioned_by_user_id` column and on the audit-log `detail` JSON (`user_signed: true`, `provisioned_by_user_id: <uuid>`). The visitor does not have to log in — but if they're already logged in, we record *who* they were. The signed URL remains the capability gate; the session is purely an identity attestation. When both are present, the session is the primary identity for the audit row (`identity_id` on the audit entry is the session user, not the target identity).

  2. **Required user session (org setting).** Org admins can set `allow_unsigned_secret_provide = false` via `PATCH /v1/orgs/{id}/secret-request-settings`. New secret requests minted while the toggle is off are stamped `require_user_session = true` at mint time and **must** be redeemed by a visitor with a same-org session — anonymous submission is rejected with `401 user_session_required`. The toggle is forward-only: outstanding URLs minted before the flip continue to honor the policy they were issued under, so flipping the toggle never breaks in-flight requests.

  **Cross-tenant sessions are ignored** (treated as anonymous). A session in org A cannot be used to provision a secret in org B, regardless of token validity — the standalone page silently drops the cookie in that case.
- **OAuth consent** (`/oauth/consent?request_id=...`) — requires login. MCP-client enrollment approval with name editing, parent placement, and `inherit_permissions`/group toggles. See §4 *Agent Enrollment*.
- **SKILL.md** (`/SKILL.md`) — unauthenticated. Agent-facing enrollment instructions, served from the repo-root `SKILL.md` file.

---

## 12. Audit Trail

Every action execution, approval resolution, secret access, and connection change is logged with the full identity chain. Queryable by identity, service, time range, and event type.

---

## 12a. Configurable Detail Disclosure

For approvals and audit rows to be useful for human review, resolvers need to know *what* an action is about to do — not just that an HTTP request is pending. Templates can declare two opt-in extensions on any HTTP action to control how a resolved request is surfaced:

- **`x-overslash-disclose`** — a labeled list of jq filters. Each filter runs at approval-create time (and again at call-success audit-write time) against a structured projection of the resolved request. Results land on `approvals.disclosed_fields` and on `audit_log.detail.disclosed`, rendered in the dashboard as a prominent "Summary" block *above* the raw-payload disclosure.
- **`x-overslash-redact`** — a list of dotted paths into the same projection. Matched values are replaced with the sentinel `"[REDACTED]"` **before** the projection is persisted as `approvals.action_detail`. Redaction defends the raw-payload blob from leaking template-declared sensitive fields; it does *not* affect disclosure extraction (which runs first).

### jq input shape

Each disclose filter runs against this projection of the resolved request:

```json
{
  "method": "POST",
  "url": "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
  "params": { "userId": "me" },
  "body": { "raw": "VG86IGFsaWNlQGV4YW1wbGUuY29tCg..." }
}
```

- `body` is parsed as JSON when the outbound request's `Content-Type` is a JSON media type (`application/json`, `application/*+json`); otherwise it's carried as the raw string.
- `params` is the post-resolution parameter map — every arg the agent passed, regardless of whether it was bound to the URL path, the query string, or the body.

### Declaration

```yaml
paths:
  /gmail/v1/users/{userId}/messages/send:
    post:
      operationId: send_message
      disclose:
        - label: To
          filter: '.body.raw | gsub("-"; "+") | gsub("_"; "/") | @base64d | capture("(?im)^To:\\s*(?<v>[^\\r\\n]+)").v'
        - label: Subject
          filter: '.body.raw | gsub("-"; "+") | gsub("_"; "/") | @base64d | capture("(?im)^Subject:\\s*(?<v>[^\\r\\n]+)").v'
        - label: Body
          filter: '.body.raw | gsub("-"; "+") | gsub("_"; "/") | @base64d | split("\r\n\r\n")[1:] | join("\r\n\r\n")'
          max_chars: 2000
      redact:
        - body.raw
```

Unprefixed `disclose:` / `redact:` aliases normalize to `x-overslash-disclose` / `x-overslash-redact` like the other operation-level extensions. jq syntax is validated at template register / promote time; a malformed filter rejects the template with a `disclose_invalid_jq` issue.

### Wire shape of a disclosed field

```json
{ "label": "To", "value": "alice@example.com", "error": null, "truncated": false }
```

`error` carries a per-filter runtime error (jq type mismatch, missing field, etc.) — one filter's failure never poisons the rest of the summary. `truncated` is set when the value hit the per-field `max_chars` clamp or the 10 KB hard ceiling.

### Sandbox guarantees

All of an action's filters run in one `spawn_blocking` task with these limits:

- **Per-filter timeout** — `filter_timeout_ms` (same setting that gates response filters).
- **Batch timeout** — `n × filter_timeout_ms`, capped at an absolute **30 s** wall-clock ceiling. Scales linearly with field count so legitimate multi-field templates aren't silently degraded, while the absolute ceiling defends against pathological templates.
- **Output values cap** — 10 000 per filter (matches `response_filter`). Disclosure expects exactly one; excess values set `truncated: true` on the field and take the first.
- **Per-value size cap** — 10 KB, applied on top of `max_chars`.
- **Projection size cap** — 1 MB (safety ceiling, one order of magnitude above the `action_detail` product limit).

### Trust boundary

Templates are authored by org ops (three-tier registry: global / org / user). A template author who chooses not to redact a sensitive path takes responsibility for that call — redaction is declarative, not heuristic. The `disclose` jq engine can read redacted-target paths (extraction runs on the un-redacted projection); if an author surfaces a token via a filter, they're doing so deliberately.

---

## 13. Rate Limiting

Overslash enforces per-identity rate limiting to prevent abuse, runaway agents, and resource exhaustion. This is **not** upstream API rate limiting (which remains a non-goal per §2) — it limits requests *to Overslash itself*.

### Two-Tier Model

Every authenticated request checks **two counters**, both must pass:

1. **User bucket** — keyed on the owning User. All agents and sub-agents under a User share this budget. Prevents malicious or forking agents from circumventing limits by spawning sub-identities.
2. **Identity cap** (optional) — keyed on the specific identity (agent/sub-agent). A tighter ceiling that prevents a single misconfigured agent from consuming the entire User budget.

### Configuration Resolution

The User bucket limit is resolved in priority order:
1. Per-user override (scope `user`)
2. Group default — most permissive across the user's groups (scope `group`)
3. Org-wide default (scope `org`)
4. System fallback (`DEFAULT_RATE_LIMIT` env var, default 1000 req/min)

Identity caps are per-identity only — no inheritance.

Configured by org admins via `PUT /GET /DELETE /v1/rate-limits`.

### Behavior

- **Algorithm**: Fixed window counter.
- **Headers** on all responses: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` (reflecting the User bucket).
- **429 Too Many Requests** with `Retry-After` header and JSON body when exceeded.
- **Storage**: Redis/Valkey if available (distributed, accurate across instances); in-memory `DashMap` fallback (single-instance, no external dependency).
- **Fail-open**: If Redis becomes unavailable at runtime, requests are allowed through (logged as warning).
- **Health endpoint** (`/health`) is exempt from rate limiting.

---

## 14. Open-Source Plan

Overslash will be released as open source (Apache 2.0 or similar). It has no platform-specific logic. The global service registry is community-maintained via PRs.

Callers (like Overfolder) build their own channel-specific integrations (Telegram approval buttons, etc.) on top of Overslash's REST API and approval URLs.
