# Overslash — Specification

A standalone, multi-tenant **identity and authentication gateway** for AI agents. Overslash handles everything between "an agent wants to call an external API" and "the API call executes with the right credentials."

Overslash is **purely an auth and identity layer**. It does not orchestrate agents, manage compute, track which nodes are connected, schedule work, or know anything about the runtime environment agents live in. It answers one question: "is this identity allowed to do this action with these credentials?" — and if yes, executes the authenticated HTTP request.

It owns: identity hierarchy, secret management, OAuth flows, permission rules, human approval workflows, action execution, service registry, and audit trail.

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
5. OAuth engine — system credentials, org credentials, and BYOC (Bring Your Own Client) per identity
6. Permission chains — every level in the identity hierarchy must authorize an action
7. Human approval workflows — with expiry, "Allow & Remember" with TTL, approval URLs for any channel
8. Universal HTTP execution — any REST API, with or without a service definition
9. Service registry — YAML-defined services (global + org-extensible) with human-readable action descriptions
10. Audit everything — every action, approval, secret access, connection change
11. Simple REST API — any HTTP client can use Overslash
12. 3 meta tools — minimal tool interface for LLM agents (search, execute, auth)
13. Dashboard — web UI for org admins and users to manage everything visually

### Non-Goals

1. **Being an agent framework or LLM router** — Overslash doesn't know about LLMs, prompts, or agent loops
2. **Orchestrating agents** — Overslash does not schedule, dispatch, or coordinate agent work. It has no concept of tasks, queues, or workflows.
3. **Managing compute or infrastructure** — no awareness of nodes, containers, runtimes, or where agents run. Overslash doesn't know or care what machine an agent lives on.
4. **Tracking agent connectivity** — Overslash does not monitor which agents are online, healthy, or reachable. It authenticates requests when they arrive.
5. **Executing code or managing VMs** — Overslash executes HTTP requests, not arbitrary programs
6. **Channel-specific UIs** (Telegram bots, WhatsApp) — callers build their own; Overslash provides approval URLs
7. **Being a general-purpose API gateway** — no rate limiting of upstream APIs, no caching, no transformation

---

## 3. Architecture

### Components

| Component | Tech | Purpose |
|-----------|------|---------|
| **Backend** | Rust / Axum | REST API, OAuth engine, permission resolver, action executor, audit logger |
| **Dashboard** | SvelteKit | Web UI for org admins and users |
| **PostgreSQL** | — | All persistent state |
| **Encryption** | AES-256-GCM | Secret storage (key via env var or KMS) |
| **Redis** (optional) | — | Webhook delivery queue, approval notification pub/sub |

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

**Per-org IdP configuration:** Each org configures its own IdPs. An org can enable multiple IdPs simultaneously (e.g., Google for convenience + corporate Okta for SSO).

**User provisioning:** On first login via an IdP, Overslash creates the user identity in the org (matched by email domain or explicit org assignment). Subsequent logins update the user's profile (name, avatar) from the IdP's claims.

### Hierarchy

```
Org (acme)
  └── User (alice)                     depth=0
       └── Agent (henry)               depth=1, parent=alice
            ├── SubAgent (researcher)   depth=2, parent=henry
            └── SubAgent (emailer)      depth=2, parent=henry
```

- **Users** created by org-admins (or auto-provisioned on first IdP login)
- **Agents** created by users
- **Sub-agents** created by agents — no user intervention needed
- Each identity has API keys for authenticating with Overslash
- Sub-agents can have a **TTL** for auto-cleanup (ephemeral workers)

### Agent Enrollment

Two enrollment flows connect agents to the identity hierarchy:

**User-initiated enrollment**: A user creates the agent identity in the dashboard or via API, providing a name, parent placement, and optional `inherit_permissions` flag. Overslash returns a single-use enrollment token. The user pastes the enrollment snippet (containing the Overslash URL, token, and a link to `overslash.dev/enrollment/SKILL.md`) into the agent's conversation. The agent exchanges the single-use token for a permanent API key. Simple, controlled — the user decides when and where the agent exists.

The enrollment token has a **fixed 15-minute TTL**. The agent identity appears in the hierarchy immediately in a **pending enrollment** state (inactive until token exchange). If the token expires unused, the pending identity is cleaned up automatically.

**Agent-initiated enrollment**: The agent discovers Overslash (e.g., via `overslash.dev/SKILL.md` → `overslash.dev/enrollment/SKILL.md` or environment hints) and requests an enrollment token, proposing a name and optional metadata about itself. This token only grants the ability to generate a consent URL. The agent presents this URL to a user (in chat, email, etc.). The authenticated user visits the consent URL, where they can:

- **Edit the agent's proposed name** (pre-filled but fully editable)
- **Choose placement** in the hierarchy (defaults to directly under the approving user)
- **Review default settings** (inherit_permissions, etc.)

The consent URL is scoped to the org. Any authenticated user in the org with agent-creation permissions can approve — not just one specific user. After approval, the agent's token is exchanged for a permanent API key server-side. The agent, polling or via webhook, picks up the key.

Note: `inherit_permissions` is not offered during agent-initiated enrollment — the user configures this after enrollment if desired.

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

Groups define which services are available and at what access level. They constrain users, and agents inherit their owner-user's group ceiling. A request that exceeds the group ceiling is denied outright — no approval can override it.

Group examples:
- "Engineering": `github:ANY:*`, `slack:*:*`, `stripe:*:*`
- "Admin": adds `http:ANY:*`, `secret:*:*`
- "Read-only": `github:GET:*`, `slack:GET:*`

Three tiers of trust emerge naturally:
1. **`{service}:*:*`** — any action on a known service. Safest (in the future, groups may distinguish registry-only access from raw HTTP verb access for finer control).
2. **`{service}:ANY:*`** — arbitrary API calls against known services. Mid trust.
3. **`http:ANY:*`** — full HTTP proxy with secret injection. Highest trust.

**Auto-approve reads:** Each service grant in a group can optionally enable `auto_approve_reads`. When set, non-mutating requests (actions where `risk: read`, or GET/HEAD/OPTIONS for raw HTTP) from agents automatically create permission keys without requiring user approval. Mutating requests (`risk: write` or `delete`) still go through normal approval flow. This is configured per-service per-group — org-admins decide which services have sensitive read operations (financial data, PII) vs ones where reads are safe (listing PRs, checking calendar events).

**Layer 2: Permission keys (fine-grained, user-managed, agent-specific)**

Within the group ceiling, agents require specific permission keys for each action. Keys are created when a user clicks "Allow & Remember" on an approval — they are never written by hand. Permission keys build up organically as agents are used and users approve their actions. Users acting through the dashboard or API Explorer are gated by groups only — they are their own approvers.

### Resolution Flow

1. Agent makes a request → system derives permission keys from the request
2. **Group check**: is the service + access level within the owner-user's group grants? If not → **deny** (not approvable)
3. **Permission key check**: are all derived keys covered by existing rules for this identity? If yes → **auto-approve**
4. If not → **create approval request** → user decides → "Allow & Remember" stores keys with optional TTL

### Hierarchical Resolution

When a sub-agent executes an action, every level in the ancestor chain must authorize:

1. Check sub-agent → has matching key or `inherit_permissions`? Pass, continue up.
2. Check agent → has matching key? Pass, continue up.
3. Check user → within group ceiling? Pass. All levels authorized → **execute**.
4. First level without a matching key and without `inherit_permissions` → **gap**. Create approval at that level.

### Approval Bubbling

The approval is created at the gap level. That level's ancestors can resolve it. This means agents approve for their sub-agents without pestering the user.

### Trust Model and Approval Resolution

The core trust assumption: **agents are not trusted to approve their own actions.** Overslash exists precisely because prompt-based permission ("please ask before sending") is not real security. The approval system enforces this:

**Who can resolve an approval:**
- **Users** — via the Overslash dashboard (logged in) or via the platform's UX calling the resolve API with the user's credentials
- **Ancestor agents** — an agent can approve for its sub-agents, but **only** if the permission being granted is already within the agent's own boundary (same or narrower keys, same or shorter TTL). A parent cannot grant a child more than it has itself.
- **The requesting agent itself** — **never**. An agent cannot resolve its own approval requests.

**How approvals flow through the platform:**

1. Agent calls `overslash_execute` via the platform → gets `{ "status": "pending_approval", "approval_id": "apr_abc123" }`
2. The agent cannot resolve this. The platform receives the approval event (via webhook or polling on the user's behalf).
3. The platform surfaces the approval to the user in its own UX (Telegram buttons, Slack message, CLI prompt, etc.) including the `suggested_tiers` and `description` from the approval payload.
4. The user makes a decision. The platform calls `POST /v1/approvals/{id}/resolve` using the **user's** Overslash credentials — not the agent's API key.
5. The agent's pending request completes (via polling or webhook to the platform).

**There is no self-authenticating approval URL.** Approval resolution always requires credentials of an identity with authority over the requesting identity. This prevents an agent from obtaining and resolving its own approval link.

**Overslash-hosted approval page:** Overslash provides a deep-link URL for each approval: `https://acme.overslash.dev/approvals/apr_abc123`. This page requires login — if the logged-in user has authority to resolve the approval, they see the full approval details and specificity picker. If not logged in, they hit the login page and get redirected back. Platforms can include this URL when surfacing approvals to users as a zero-integration-effort path — the platform doesn't need to build its own approval UI. The platform decides whether to link to Overslash's page or handle resolution in its own UX.

(The secret request page at `/secrets/provide/req_...?token=jwt` uses a signed URL because providing a secret doesn't grant the agent authority — the agent still needs a separate approval to use it.)

### Remembered Approvals

"Allow & Remember" on an approval creates permission key rules with optional TTL. These rules auto-approve matching future requests. Users can view and revoke remembered approvals per identity via the dashboard.

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
| **Agent** (API) | list names only | list names only | — |
| **Org admin** (dashboard) | read/write | read/write | read/write (all org) |

- **Users** can view and manage secret values for all secrets in their subtree (their own + their agents' secrets) via the dashboard.
- **Agents** can list secret names, version numbers, and timestamps (created, last used) but never read values via API. Secret values are only injected at action execution time. Version numbers and timestamps give agents enough signal to detect rotations and confirm writes without exposing values.
- **Org admins** can view and manage all secrets across the org. This follows the standard model for org-managed credential stores (same as 1Password Teams, AWS Secrets Manager, etc.) and is required for compliance, debugging, and offboarding scenarios.

---

## 7. OAuth Engine

Overslash handles OAuth flows (authorization URL generation, code exchange, token storage, automatic refresh) for services that use OAuth authentication. The OAuth engine is internal machinery — not a user-facing concept. Users interact with **services** (§9), which encapsulate their credentials.

OAuth client credentials can come from three sources:

1. **Service-level** — credentials configured on the service instance itself
2. **Overslash system credentials** — managed by Overslash operators, used as defaults for global templates

When a user creates a service from a template that uses OAuth, the connect flow walks them through the OAuth redirect. The resulting token is stored encrypted and bound to that service instance.

---

## 8. Action Execution

### `POST /v1/actions/execute`

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

- **Service Template** — a YAML definition describing an API: base URL, auth config, actions. No credentials. A blueprint.
- **Service** — a named instance of a template, bound to specific credentials. `work-calendar` is a Google Calendar template instantiated with alice@acme.com's OAuth token.

### Service Templates

Templates live in a three-tier registry:

| Tier | Managed by | Visible to | Mutable |
|------|-----------|------------|---------|
| **Global** | Overslash (shipped YAML) | Everyone | Read-only for orgs |
| **Org** | Org-admins | Org members | Full CRUD |
| **User** | Users (if org allows) | Creator + their agents | Full CRUD |

**Global**: YAML files shipped with Overslash. Common APIs (Eventbrite, GitHub, Google Calendar, Stripe, Slack, Resend, X, etc.). Read-only for orgs. Org-admins can hide unused global templates from their org.

**Org**: Org-admins create templates for the org's internal or niche APIs. Visible to all org members (templates are blueprints — visibility doesn't grant access, creating a service instance does).

**User**: Users create personal templates for APIs only they use. Gated by org setting (`allow_user_templates`). Private by default. Users can **propose sharing** a template to org level — org-admin reviews and approves or denies.

**Org-admin visibility**: Org-admins can see all templates in the org (global + org + user-created) in a read-only list for security/compliance — they need to know what external APIs their users are connecting to.

### Template Definition

```yaml
key: google-calendar
display_name: Google Calendar
description: "Google Calendar API"
hosts: [www.googleapis.com/calendar]
auth:
  - type: oauth
    provider: google
    scopes: [https://www.googleapis.com/auth/calendar]
    token_injection: { as: header, header_name: Authorization, prefix: "Bearer " }
actions:
  create_event:
    method: POST
    path: /calendars/{calendar_id}/events
    description: "Create event '{summary}'[ on {calendar_id}]"
    risk: write
    scope_param: calendar_id
    params:
      calendar_id: { type: string, required: true, default: primary }
      summary: { type: string, required: true }
      start: { type: string, required: true, description: "ISO 8601 datetime" }
      end: { type: string, required: true, description: "ISO 8601 datetime" }
  list_events:
    method: GET
    path: /calendars/{calendar_id}/events
    description: "List events[ on {calendar_id}]"
    risk: read
    scope_param: calendar_id
    params:
      calendar_id: { type: string, required: true, default: primary }
      time_min: { type: string, description: "ISO 8601 datetime" }
      time_max: { type: string, description: "ISO 8601 datetime" }
```

**Key fields:**
- **`scope_param`** — which parameter provides the `{arg}` segment in permission keys. Without `scope_param`, the arg is `*`.
- **`risk`** — enum: `read`, `write`, `delete`. Defaults to `read` when omitted. Informational for the UI and influences auto-approve-reads behavior (`read` → non-mutating, `write`/`delete` → mutating).

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
| Group grants | unqualified | `github:ANY:*` | Same |
| Audit log | fully qualified | `org/github:create_pull_request:overfolder/app` | Forensic record — must show exactly which instance and credentials were used |
| Approval display | scope-qualified | `user/github` or `org/github` | User needs to know which credentials the agent will use (`user/` is sufficient — the user knows who they are) |
| API requests | unqualified (default) | `github` | Resolution applies; `org/github` available to bypass shadow |

**Permission keys** use the unqualified name and follow the same resolution:
- `github:create_pull_request:overfolder/*` — resolves through the user's `github` if it shadows, else the org's
- `google-calendar:list_events:*`

**Groups grant access to org services (instances)**:
- Engineering group gets: `github:ANY:*`, `slack:*:*`
- User services bypass the group ceiling for the creator (they own the instance), but their agents still need permission keys via approvals.

**Service lifecycle:** **Draft** → **Active** → **Archived**. Draft services can be tested in the API Explorer but not used by agents. Archived services are hidden from discovery but not deleted — existing remembered approvals are preserved.

### Creating a Service

1. Pick a template (from global/org/user templates)
2. Name the service instance — defaults to the template key (e.g., `google-calendar`). Rename to create additional instances (e.g., `personal-calendar`).
3. Connect credentials — OAuth flow, API key input, or shared credential (for org services)
4. Optionally assign to groups (org-admin only)

For org services with OAuth (per-user tokens): the org-admin creates the service with the org's OAuth app credentials. Users in the assigned groups see the service and complete their individual OAuth flow to get their own token. The service is shared, but each user has their own credential.

### OpenAPI Import

Upload an OpenAPI 3.x spec (file or URL) → Overslash parses it and generates a **template** with actions and parameter schemas. Available at both org and user tier. The import is a starting point — the user reviews and edits the generated template before saving. Partial import supported: pick which endpoints become actions, skip the rest.

### Template Validation

The template YAML is parsed and validated by a Rust parser (`overslash-core`). The same parser is used by:
- **Backend**: `POST /v1/templates/validate` — accepts YAML, returns structured errors and warnings
- **Dashboard**: calls the validate endpoint for linting. Future: ship the parser as WASM for instant client-side validation without a round-trip.

Validation checks: required fields, valid auth types, valid HTTP methods, path template syntax (`{param}` matches defined params), parameter type consistency, duplicate action keys, etc.

---

## 10. Meta Tools for LLM Agents

Three tools that let any LLM agent use Overslash:

| Tool | Purpose |
|------|---------|
| `overslash_search` | Discover services and actions. Returns schemas + auth status. |
| `overslash_execute` | Execute any action (all three modes). Returns result or pending approval. |
| `overslash_auth` | Check/initiate auth, store/request secrets, create sub-identities. |

The agent platform wraps these 3 tools and handles plumbing (receiving approval events via webhook/polling, surfacing them to the user, and calling the resolve API with user credentials).

---

## 11. Dashboard

Web UI for non-API interactions. Built with SvelteKit + TypeScript.

### Core Views

- **User profile** — authenticated user info, API keys, settings
- **Org/User/Agent hierarchy** — tree view of the identity hierarchy, with inline management (create, edit, delete, enrollment tokens)
- **Services** — browse templates, create/manage service instances, connect credentials
- **Developer connection tool (API Explorer)** — interactive API explorer for connected services. Select a service, pick a defined action or make a custom request, fill in parameters, and execute. Similar to Swagger UI or Postman but integrated with Overslash auth. Available actions adapt to the user's group grants (defined actions, HTTP verbs, or raw HTTP). Always executes as the logged-in user's own identity — no agent impersonation. Actions are logged in the audit trail under the user. Can be hidden via org setting.
- **Audit log** — searchable, filterable log of all actions, approvals, and secret accesses. Filterable by identity, service, time range, event type.

### Org-Admin Views

Templates (browse/create/import), Services (org-level instances, group assignment), Webhooks, Settings.

### User Views

My Services (instances + credentials), My Secrets (names + versions), Approvals (pending, one-click resolve with expiry picker), My Agents (permission management).

### Standalone Pages

Overslash provides built-in standalone pages for common user interactions. These serve two purposes: (1) direct use by unplatformed agents (e.g., agents connecting to Overslash without a platform intermediary), and (2) a zero-effort integration path for platforms that don't want to build their own UI for these flows.

Platforms can always build fully white-label equivalents using the same REST API these pages consume. The API exposes all the data needed: approval details with suggested tiers, secret request metadata, enrollment consent payloads. The built-in pages are a convenience, not a requirement.

- **Approval resolution** (`/approvals/apr_...`) — requires login. Shows approval details and specificity picker. See §5 Trust Model.
- **Secret request** (`/secrets/provide/req_...?token=jwt`) — no login required (signed URL). Secure input field for secret provisioning. Safe because providing a secret doesn't grant the agent authority.
- **Enrollment consent** (`/enroll/consent/...`) — requires login. Agent-initiated enrollment approval with name editing and parent placement.

---

## 12. Audit Trail

Every action execution, approval resolution, secret access, and connection change is logged with the full identity chain. Queryable by identity, service, time range, and event type.

---

## 13. Open-Source Plan

Overslash will be released as open source (Apache 2.0 or similar). It has no platform-specific logic. The global service registry is community-maintained via PRs.

Callers (like Overfolder) build their own channel-specific integrations (Telegram approval buttons, etc.) on top of Overslash's REST API and approval URLs.
