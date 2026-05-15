# Overslash — Decoupled Actions & Auth Gateway

**Status**: Not Implemented
**Date**: 2026-03-23
**Related**: `curl-gate.md`, `gated-actions.md`, `byoc-oauth.md`, `nango-integration.md`, `gated-connectors-approvals.md`
**Supersedes**: Parts of `curl-gate.md` (secret injection, HTTP execution), `gated-actions.md` (approval lifecycle, permission rules), `byoc-oauth.md` (BYOC credential management), `nango-integration.md` (OAuth token management — Nango no longer under consideration)

## Overview

Overslash is a standalone, multi-tenant actions and authentication gateway. It handles everything between "an agent wants to call an external API" and "the API call executes with the right credentials." It owns: identity hierarchy, secret management, OAuth flows, permission rules, human approval workflows, action execution, service registry, and audit trail.

Extracted from Overfolder's agent-runner so that it can be used by any organization running AI agents — not just Overfolder. The name: it slashes through doors and auth for the user.

**What Overslash is**: A gated, authenticated action execution layer that any caller (agent, human, CI pipeline) can use via REST.

**What Overslash is not**: An agent framework, an LLM router, or a tool registry. It doesn't know about LLMs. It receives HTTP requests and executes them with auth and approval.

## Motivation

The current Overfolder agent-runner bundles action execution, secret management, OAuth, and approval workflows into ~5,000+ lines of tightly coupled Rust. This creates problems:

1. **Adding new integrations requires Rust code changes** — each OAuth provider or connector is a new module
2. **Permission logic is embedded in the agent loop** — can't be reused by other callers
3. **Secret management is tied to Overfolder's DB schema** — not portable
4. **BYOC OAuth adds complexity** at every layer (backend routes, agent-runner, frontend)
5. **No multi-tenant isolation** — permission rules and secrets are per-user but not per-organization

Overslash extracts all of this into a single service with a clean REST API. Overfolder's agent-runner becomes a thin client that calls Overslash instead of managing auth and approvals internally.

## Architecture

```
Any Caller (Overfolder agent-runner, CI, human, other agent platform)
  │
  │  POST /v1/actions/call
  │  Authorization: Bearer ovs_acme_agent-henry_k8x9...
  │
  ▼
┌──────────────────────────────────────────────────────────────────┐
│                          Overslash                               │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │  Identity    │  │  Permission  │  │  Service Registry      │  │
│  │  Hierarchy   │  │  Chain       │  │  (YAML + DB)           │  │
│  │             │  │              │  │                        │  │
│  │  User       │  │  SubAgent    │  │  github.yaml           │  │
│  │   └─Agent   │  │   ↑ Agent   │  │  stripe.yaml           │  │
│  │     └─Sub   │  │   ↑ User    │  │  custom-crm (org-def)  │  │
│  └─────────────┘  └──────────────┘  └────────────────────────┘  │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │  Secret     │  │  OAuth       │  │  Action Executor       │  │
│  │  Vault      │  │  Engine      │  │                        │  │
│  │  (versioned)│  │  (BYOC +     │  │  Raw HTTP / Service    │  │
│  │             │  │   system)    │  │  + Action / Connection │  │
│  └─────────────┘  └──────────────┘  └────────────────────────┘  │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐                              │
│  │  Approval   │  │  Audit       │                              │
│  │  Workflow   │  │  Trail       │                              │
│  └─────────────┘  └──────────────┘                              │
└──────────────────────────────────────────────────────────────────┘
  │                    │
  │ Webhook:           │ HTTP with injected auth:
  │ approval.created   │ POST api.github.com/...
  ▼                    ▼
Caller / User         External Service
```

### Deployment

Overslash ships as two components:

1. **Backend** (Rust/Axum) — the REST API, OAuth engine, permission resolver, action executor, audit logger. Single binary, single Docker image.
2. **Dashboard** (SvelteKit or similar) — web UI for org admins and users to manage identities, view/resolve approvals, browse audit trail, configure services, manage secrets and connections. Served as a static SPA or SSR app.

Infrastructure requirements:

- **PostgreSQL** — identities, secrets, permissions, approvals, audit, org-level service definitions
- **Encryption key** — AES-256-GCM for secret storage (env var or KMS)
- **Optional: Redis** — for webhook delivery queue and approval notification pub/sub

Overslash is **not** embedded in agent-runner. Agent-runner calls Overslash over HTTP. This means Overslash can serve multiple agent platforms simultaneously.

### Dashboard

The dashboard serves both org-admins and individual users/agents-via-their-owners. It is the primary UI for non-API interactions with Overslash.

#### Org-Admin Views

| View | Purpose |
|------|---------|
| **Identities** | Create/manage users, agents. View identity hierarchy tree. Issue/revoke API keys. |
| **Services** | Browse global registry, register org-specific services, import OpenAPI specs. |
| **Audit** | Searchable audit log across all identities. Filter by identity, service, time range, event type. |
| **Connections** | Org-level OAuth credentials (shared across identities). BYOC credential management. |
| **Webhooks** | Register/manage webhook endpoints. View delivery history. |
| **Permissions** | View/create/delete rules for any identity. Bulk rule management. |
| **Settings** | Org name, billing, max sub-identity depth, default policies. |

#### User Views

| View | Purpose |
|------|---------|
| **My Connections** | Active OAuth connections. Connect new services. Revoke access. |
| **My Secrets** | Secret inventory (names + versions, never values). Restore old versions. |
| **Approvals** | Pending approvals (own + agents'). One-click Allow/Deny/Allow & Remember with expiry picker. |
| **My Agents** | Agents owned by this user. View their sub-identity trees. Manage agent permissions. |
| **My Audit** | Personal audit trail. |
| **Permissions** | Own rules + rules for owned agents. |

#### Approval Resolution Page

A standalone page (no login required — signed token in URL) for resolving a single approval:

```
https://overslash.dev/approve/apr_...?token=signed_jwt
```

Shows: action description, executing identity, risk level, detail. Buttons: Allow, Deny, Allow & Remember (with duration picker). This is the page linked from Telegram messages, emails, or push notifications.

#### Secret Request Page

Similarly standalone for `request_secret`:

```
https://overslash.dev/secrets/provide/req_...?token=signed_jwt
```

Shows: which agent requested it, description of what's needed. Single secure input field. Value encrypted on submit, never displayed again.

### Multi-Tenancy

Each organization gets isolated:
- Identities (users, agents, sub-agents)
- Secrets and connections
- Permission rules
- Audit trail
- Org-level service definitions (extending the global registry)

Organizations cannot see each other's data. The global service registry (GitHub, Google, Stripe, etc.) is shared read-only across all orgs.

---

## Identity Hierarchy

### Model

```
Org (acme)
  └── User (alice)                     depth=0, type=user
       └── Agent (henry)               depth=1, type=agent, parent=alice
            ├── SubAgent (researcher)   depth=2, type=subagent, parent=henry
            └── SubAgent (emailer)      depth=2, type=subagent, parent=henry
                 └── SubSub (formatter) depth=3, type=subagent, parent=emailer
```

- **Users** are created by org-admins
- **Agents** are created by users (parent = creating user)
- **Sub-agents** are created by agents (parent = creating agent) — no user/admin intervention needed

Each identity gets API keys. The API key encodes org + identity, used for all Overslash requests.

### Identity Properties

| Field | Type | Purpose |
|-------|------|---------|
| `id` | UUID | Internal identifier |
| `org_id` | UUID | Organization |
| `parent_id` | UUID? | Parent identity (null for users) |
| `owner_id` | UUID | Root user of the chain |
| `type` | enum | `user`, `agent`, `subagent` |
| `name` | string | Display name |
| `depth` | int | 0=user, 1=agent, 2+=subagent |
| `inherit_permissions` | bool | Dynamically inherit parent's permissions |
| `can_create_sub` | bool | Whether this identity can create sub-identities |
| `max_sub_depth` | int | How deep the chain can go (org-configurable, default 5) |
| `ttl` | duration? | Auto-destroy after duration (for ephemeral subagents) |

### Sub-Identity Lifecycle

Agents create ephemeral sub-identities for delegated work:

```
POST /v1/sub-identities
{
  "name": "researcher",
  "inherit_permissions": true,
  "ttl": "2h"
}
→ { "id": "idt_...", "api_key": "ovs_acme_researcher_..." }
```

The agent passes the API key to the sub-agent process. The sub-agent uses it for all Overslash calls. When TTL expires, the sub-identity and its API keys are destroyed. Secrets and connections created by sub-agents are promoted to the owner user (not destroyed).

---

## Permission System

### Hierarchical Permission Resolution

When a sub-agent executes an action, the permission check walks the entire ancestor chain. Every level must authorize.

```
resolve_action(executing_identity, action):
    chain = [subagent, agent, user]   // ancestor chain, bottom to top

    for level in chain:
        if level has explicit permission rule covering the action:
            PASS — continue to next level
        else if level.inherit_permissions == true:
            PASS — dynamically inherits parent's grants, continue
        else:
            GAP — stop here, create approval request at this level
            the approval can be handled by this level or any ancestor
            return PENDING_APPROVAL

    all levels passed → ALLOWED
```

### `inherit_permissions`

A live pointer, not a copy. When set on an identity:
- The identity dynamically has whatever permissions its parent has
- If the parent gains a new rule tomorrow, the child gains it too
- If the parent loses a rule, the child loses it
- Avoids copying hundreds of rules when spawning sub-agents

### Permission Rules

```sql
CREATE TABLE permissions (
    id UUID PRIMARY KEY,
    identity_id UUID NOT NULL REFERENCES identities(id),
    service TEXT,                  -- null = all services
    scope TEXT NOT NULL,           -- "POST:/repos/*/pulls", "*", "read:*"
    description TEXT,
    created_by UUID REFERENCES identities(id),
    created_via TEXT,              -- 'manual' | 'allow_remember:apr_...'
    expires_at TIMESTAMPTZ,       -- null = permanent
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Approval Bubbling

When a gap is found at a level, the approval request is created targeting that level. **Who can handle it:**

- The gap level itself: NO (can't approve your own actions)
- The parent of the gap level: YES
- Any ancestor above: YES

This achieves the goal: **agents approve for their sub-agents without pestering the user.**

| Scenario | Gap at | Handled by | User involved? |
|----------|--------|------------|----------------|
| SubAgent lacks rule, Agent has it | SubAgent | Agent | No |
| SubAgent inherits, Agent lacks rule | Agent | User | Yes |
| SubAgent lacks rule, Agent lacks rule | SubAgent | Agent or User | Agent can handle it |

### Approval Resolution

```
POST /v1/approvals/:id/resolve
{
  "decision": "allow",                    // one-time allow
  "decision": "deny",                     // reject
  "decision": "allow_remember",           // create persistent rule
    "grant_to": "idt_henry",             // which level gets the rule
    "expires_in": "30d"                   // optional expiry
}
```

When `allow_remember` is used, the rule is created at the `grant_to` level. If a sub-agent has `inherit_permissions: true` from that level, it's covered automatically for future actions.

### Approval Visibility

```
GET /v1/approvals?scope=actionable     # Approvals I can resolve (descendants' gaps)
GET /v1/approvals?scope=mine           # Approvals where I'm the executing identity
GET /v1/approvals?scope=all            # Both
```

---

## Secrets

### Versioned Secret Storage

Every `PUT` creates a new version. Latest is always used for injection. Earlier versions can be restored.

```sql
CREATE TABLE secrets (
    id UUID PRIMARY KEY,
    identity_id UUID NOT NULL REFERENCES identities(id),
    name TEXT NOT NULL,
    current_version INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(identity_id, name)
);

CREATE TABLE secret_versions (
    id UUID PRIMARY KEY,
    secret_id UUID NOT NULL REFERENCES secrets(id),
    version INTEGER NOT NULL,
    encrypted_value BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by UUID REFERENCES identities(id),
    UNIQUE(secret_id, version)
);
```

- `PUT /v1/secrets/:name` — creates new version, returns version number
- `GET /v1/secrets` — list secrets (name, current_version, created_at — never values)
- `GET /v1/secrets/:name` — metadata + version history
- `POST /v1/secrets/:name/restore` — `{ version: 2 }` creates version N+1 with version 2's value
- `DELETE /v1/secrets/:name` — soft-delete (versions preserved, org-admin can hard-delete)

### Secret Scoping

Secrets are scoped to the identity that created them. However, when an agent sets up an integration on behalf of a user, the secret is created at the **user level** (the agent's owner), not the agent level. This way all agents under the same user share the connection.

The `on_behalf_of` field enables this:

```
PUT /v1/secrets/stripe_key
{
  "value": "sk_live_...",
  "on_behalf_of": "idt_alice"    // agent henry stores it for user alice
}
```

Agents can only use `on_behalf_of` pointing to their owner user. Overslash validates the chain.

---

## Connections (OAuth)

### Flow

```
POST /v1/connections
{
  "provider": "google",
  "scopes": ["calendar.events", "gmail.send"],
  "on_behalf_of": "idt_alice",            // agent creates for owner user
  "byoc_credentials": {                    // optional BYOC
    "client_id": "...",
    "client_secret": "..."
  }
}
→ {
    "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
    "connection_id": "conn_...",
    "message": "Ask the user to open this URL to connect Google"
  }
```

The agent presents the `auth_url` to the user via their chat channel (Telegram, web, etc.). The user clicks, completes OAuth, and the connection is stored in Overslash at the user level.

### Auth Resolution (credential fallback chain)

```
1. Identity has BYOC credentials for this provider? → use them
2. Org has shared OAuth credentials for this provider? → use them
3. Overslash has system credentials for this provider? → use them
4. No credentials available → return error with setup instructions
```

### Connection Ownership

Connections created via `on_behalf_of` belong to the user. All agents and sub-agents under that user can use the connection. This matches reality: it's the user's Google account, not the agent's.

```
GET /v1/connections                    # List connections (own + inherited from owner)
DELETE /v1/connections/:id             # Revoke (only the owner-user or org-admin)
```

---

## Service Registry

### Two-Tier: Global + Org

**Global registry**: Maintained by Overslash creators. YAML files shipped with the service. Covers common APIs (GitHub, Google, Stripe, Slack, Notion, etc.). Read-only for all orgs.

**Org registry**: Org-admins and users can register additional services for their own APIs or niche services.

### Service Definition Format

```yaml
# services/github.yaml (global registry)
key: github
display_name: GitHub
hosts:
  - api.github.com
auth:
  - type: oauth
    provider: github
    token_injection:
      as: header
      header_name: Authorization
      prefix: "Bearer "
  - type: api_key
    default_secret_name: github_token
    injection:
      as: header
      header_name: Authorization
      prefix: "Bearer "
actions:
  create_pull_request:
    method: POST
    path: /repos/{repo}/pulls
    description: "Create a pull request"
    risk: write
    params:
      repo: { type: string, required: true, description: "owner/repo" }
      title: { type: string, required: true }
      head: { type: string, required: true }
      base: { type: string, required: true }
      body: { type: string }
  list_repos:
    method: GET
    path: /user/repos
    description: "List repositories for the authenticated user"
    risk: read
    params:
      sort: { type: string, enum: [created, updated, pushed, full_name] }
      per_page: { type: integer, default: 30 }
```

### Ad-Hoc APIs (Unknown to Registry)

When an agent encounters an API not in the registry, it uses **raw HTTP mode** (Mode A) — no service registration needed. The agent constructs the full HTTP request and specifies secret injection directly.

For repeated use of the same ad-hoc API, the agent (acting `on_behalf_of` the user) can register a lightweight service definition:

```
POST /v1/services
{
  "key": "my-crm",
  "display_name": "Acme CRM",
  "hosts": ["api.acme-crm.com"],
  "auth": [{
    "type": "api_key",
    "default_secret_name": "acme_crm_key",
    "injection": { "as": "header", "header_name": "X-API-Key" }
  }],
  "actions": {}
}
```

This is an org-level registration. Future requests to `api.acme-crm.com` get human-readable descriptions and auto-resolve auth.

### OpenAPI Import

```
POST /v1/services/import
{
  "format": "openapi",
  "spec_url": "https://api.acme-crm.com/openapi.json",
  "auth": { "type": "api_key", "injection": { "as": "header", "header_name": "X-API-Key" } }
}
```

Overslash parses the OpenAPI spec, generates a service definition with actions, params, and descriptions. Stored as an org-level service.

---

## Agent Integration Setup Flow

Agents must be able to set up new integrations autonomously, creating connections and secrets at the user level so all agents under that user benefit.

### Path 1: API Key Integration

```
User: "Check my Stripe dashboard for recent charges"

Agent:
  1. overslash_search("stripe charges")
     → { service: "stripe", action: "list_charges", auth_status: "not_connected" }

  2. overslash_auth({ action: "request_secret",
       secret_name: "stripe_key",
       description: "Stripe API key (found in Dashboard → Developers → API Keys)",
       on_behalf_of: owner_user })
     → { status: "requested", message: "Asked the user to provide 'stripe_key'" }

  -- User receives a prompt (via Telegram/web) with a secure input field --
  -- User submits the key → encrypted → stored at user level in Overslash --

  3. overslash_call({ service: "stripe", action: "list_charges", params: { limit: 10 } })
     → { status: "called", result: { ... } }
```

The key never enters the LLM context. The `request_secret` flow shows the user a secure input (Overslash hosts a simple web page, or the caller's platform renders an inline input card).

### Path 2: OAuth Integration

```
User: "What's on my calendar today?"

Agent:
  1. overslash_search("calendar events today")
     → { service: "google-calendar", action: "list_events", auth_status: "not_connected" }

  2. overslash_auth({ action: "connect",
       service: "google-calendar",
       scopes: ["calendar.events"],
       on_behalf_of: owner_user })
     → { auth_url: "https://accounts.google.com/...", connection_id: "conn_..." }

  3. Agent presents the auth_url to the user in chat:
     "I need access to your Google Calendar. Please click this link to connect: [Connect Google Calendar]"

  -- User clicks, completes OAuth consent, callback stores token in Overslash --
  -- Overslash sends webhook: connection.completed --

  4. overslash_call({ service: "google-calendar", action: "list_events",
       params: { date: "2026-03-23" } })
     → { status: "called", result: { ... } }
```

### Path 3: Unknown API (Ad-Hoc)

```
User: "Post this update to our internal dashboard at api.acme-internal.com"

Agent:
  1. overslash_search("acme internal dashboard")
     → { results: [] }   // not in registry

  2. overslash_auth({ action: "request_secret",
       secret_name: "acme_dashboard_key",
       description: "API key for the internal dashboard",
       on_behalf_of: owner_user })

  -- User provides key --

  3. overslash_call({
       raw_http: {
         method: "POST",
         url: "https://api.acme-internal.com/v1/updates",
         headers: { "Content-Type": "application/json" },
         body: "{\"message\": \"Q1 results are in\"}"
       },
       secrets: [{ name: "acme_dashboard_key", inject_as: "header",
                   header_name: "Authorization", prefix: "Bearer " }]
     })
     → pending approval (first time, has secrets) → user approves
     → { status: "called", result: { status_code: 201, body: ... } }
```

No service registration needed. If the agent uses this API repeatedly, it can register it as a service for better UX (human-readable descriptions, auto-resolve auth).

---

## Action Execution

### `POST /v1/actions/call`

The single most important endpoint. Three modes:

### Mode A: Raw HTTP

Agent knows the exact request. Like curl gate.

```json
{
  "raw_http": {
    "method": "POST",
    "url": "https://api.github.com/repos/acme/app/pulls",
    "headers": { "Content-Type": "application/json" },
    "body": "{\"title\":\"Fix bug\",\"head\":\"fix\",\"base\":\"main\"}"
  },
  "secrets": [
    { "name": "gh_token", "inject_as": "header",
      "header_name": "Authorization", "prefix": "Bearer " }
  ]
}
```

### Mode B: Connection-Based

Use a specific OAuth connection. Token auto-injected.

```json
{
  "raw_http": {
    "method": "GET",
    "url": "https://www.googleapis.com/calendar/v3/calendars/primary/events"
  },
  "connection": "conn_abc123"
}
```

### Mode C: Service + Action

Registry-resolved. Overslash builds the HTTP request from the service definition.

```json
{
  "service": "github",
  "action": "create_pull_request",
  "params": {
    "repo": "acme/app",
    "title": "Fix bug",
    "head": "fix",
    "base": "main"
  },
  "auth": "auto"
}
```

**Auth resolution for Mode C** (when `auth` is `"auto"` or omitted):

1. Active OAuth connection for this service's provider → use it
2. Multiple connections → use the one tagged `default: true`, or most recently created
3. Secret matching the service's `default_secret_name` → inject per service's auth spec
4. No auth found → return error: `{ "error": "no_auth", "service": "github", "setup_hint": "..." }`

Mode C also supports explicit auth override:
```json
"auth": { "secret": "gh_token" }
"auth": { "connection": "conn_abc123" }
```

### Response

```json
// Immediate execution (auto-approved or no gate)
{
  "status": "called",
  "result": { "status_code": 201, "headers": {...}, "body": "..." },
  "audit_id": "aud_...",
  "action_description": "Create pull request 'Fix bug' on acme/app"
}

// Requires human approval
{
  "status": "pending_approval",
  "approval_id": "apr_...",
  "approval_url": "https://overslash.dev/approve/apr_...",
  "gap_identity": "henry/researcher",
  "can_be_handled_by": ["idt_henry", "idt_alice"],
  "action_description": "Create pull request 'Fix bug' on acme/app",
  "expires_at": "2026-03-23T12:00:00Z"
}
```

### Gating Logic

```
action arrives with secrets or connection referenced
  │
  ├─ No secrets AND no connection AND no service auth
  │   └─ Unauthenticated request → call directly (no gate)
  │
  └─ Auth involved (secrets, connection, or service auth)
      │
      ├─ Walk permission chain (subagent → agent → user)
      │   ├─ All levels pass → auto-approve → inject auth → call
      │   └─ Gap found → create approval → return pending_approval
      │
      └─ On approval resolution:
          ├─ allow → inject auth → call → return result via webhook
          ├─ allow_remember → create permission rule + call
          └─ deny → notify caller
```

### Human-Readable Action Descriptions

When the service is in the registry, Overslash generates descriptions from action metadata:

| Raw Request | Generated Description |
|---|---|
| `POST api.github.com/repos/acme/app/pulls` | "Create pull request on acme/app" |
| `GET api.stripe.com/v1/charges?limit=10` | "List recent charges (Stripe)" |
| `DELETE api.github.com/repos/acme/app/branches/old` | "Delete branch 'old' on acme/app" |

For unknown APIs (Mode A with no service match), Overslash shows the raw HTTP: `"POST https://api.acme-internal.com/v1/updates"`.

---

## Meta Tools for Agent LLMs

Three tools that let any LLM agent use Overslash without knowing the full API.

### `overslash_search`

Discover services and actions. Always call first.

```json
{
  "name": "overslash_search",
  "description": "Search for external services and actions you can call. Returns matching services with parameter schemas and auth status.",
  "input_schema": {
    "properties": {
      "query": { "type": "string", "description": "What you want to do, e.g. 'create a github pull request'" }
    },
    "required": ["query"]
  }
}
```

Returns services, actions, param schemas, and `auth_status` ("connected" / "needs_setup") so the agent knows whether to set up auth first.

### `overslash_call`

Call any action. Covers all three modes.

```json
{
  "name": "overslash_call",
  "description": "Call an action on an external service. Supports three modes: service+action (preferred), raw HTTP, or connection-based.",
  "input_schema": {
    "properties": {
      "service": { "type": "string", "description": "Service key from search results" },
      "action": { "type": "string", "description": "Action key from search results" },
      "params": { "type": "object", "description": "Action parameters" },
      "auth": { "description": "Optional auth override. Omit for auto-resolve." },
      "raw_http": {
        "type": "object",
        "description": "Alternative: raw HTTP request when no service/action match exists.",
        "properties": {
          "method": { "type": "string" },
          "url": { "type": "string" },
          "headers": { "type": "object" },
          "body": { "type": "string" }
        }
      },
      "secrets": {
        "type": "array",
        "description": "Secrets to inject (for raw_http mode).",
        "items": {
          "properties": {
            "name": { "type": "string" },
            "inject_as": { "type": "string", "enum": ["header", "query", "cookie"] },
            "header_name": { "type": "string" },
            "prefix": { "type": "string" }
          }
        }
      }
    }
  }
}
```

### `overslash_auth`

Manage auth: check status, connect OAuth, store/request secrets, create sub-identities.

```json
{
  "name": "overslash_auth",
  "description": "Manage authentication for external services. Check connection status, initiate OAuth, store or request secrets, create sub-identities.",
  "input_schema": {
    "properties": {
      "action": {
        "type": "string",
        "enum": ["check", "connect", "store_secret", "request_secret", "list_secrets", "create_sub"],
        "description": "What to do"
      },
      "service": { "type": "string", "description": "Service key (for check/connect)" },
      "scopes": { "type": "array", "items": { "type": "string" }, "description": "OAuth scopes (for connect)" },
      "secret_name": { "type": "string", "description": "For store/request secret" },
      "secret_value": { "type": "string", "description": "For store_secret only" },
      "secret_description": { "type": "string", "description": "For request_secret — shown to the human" },
      "on_behalf_of": { "type": "string", "description": "Create secret/connection at owner user level" },
      "sub_name": { "type": "string", "description": "For create_sub" },
      "inherit_permissions": { "type": "boolean", "description": "For create_sub" },
      "ttl": { "type": "string", "description": "For create_sub, e.g. '2h'" }
    },
    "required": ["action"]
  }
}
```

### Why 3 Tools

| Count | Problem |
|-------|---------|
| 1 | Too many fields, LLM confusion about valid combinations |
| 2 | Auth management crammed into execute, messy |
| **3** | **Clean separation: discover → authenticate → act** |
| 5+ | Unnecessary overhead; approval checking is an execute response, permission management shouldn't be agent-accessible |

The agent harness (Overfolder or any other) wraps these 3 tools and handles plumbing: webhook registration, approval injection into the agent loop, polling.

---

## Full REST API

### Authentication

Every request carries an API key identifying org + identity:

```
Authorization: Bearer ovs_acme_agent-henry_k8x9...
```

### Access Levels

Three access levels: **org-admin**, **user**, **agent**.

#### Org-Admin Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/v1/identities` | Create users and agents |
| GET | `/v1/identities` | List all identities in org |
| GET | `/v1/identities/:id` | Get identity details |
| DELETE | `/v1/identities/:id` | Remove identity |
| POST | `/v1/identities/:id/api-keys` | Issue API key for any identity |
| DELETE | `/v1/identities/:id/api-keys/:kid` | Revoke API key |
| POST | `/v1/services` | Register org-specific service |
| PUT | `/v1/services/:key` | Update org service definition |
| DELETE | `/v1/services/:key` | Remove org service |
| POST | `/v1/services/import` | Import from OpenAPI spec |
| GET | `/v1/audit` | Query ALL audit (any identity) |
| POST | `/v1/org/connections` | Org-level OAuth credentials |
| POST | `/v1/webhooks` | Register org-level webhooks |
| GET | `/v1/permissions` (any identity) | View/manage any identity's permissions |
| POST | `/v1/permissions` (any identity) | Create rules for any identity |
| DELETE | `/v1/secrets/:name/hard` | Permanently destroy secret versions |

#### User Endpoints (scoped to self)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| PUT | `/v1/secrets/:name` | Manage own secrets |
| GET | `/v1/secrets` | List own secrets |
| GET | `/v1/secrets/:name` | Secret metadata + version history |
| POST | `/v1/secrets/:name/restore` | Restore version |
| DELETE | `/v1/secrets/:name` | Soft-delete |
| POST | `/v1/connections` | Initiate OAuth |
| GET | `/v1/connections` | List own connections |
| DELETE | `/v1/connections/:id` | Revoke connection |
| POST | `/v1/actions/call` | Execute as self |
| GET | `/v1/approvals` | Own + descendant approvals |
| POST | `/v1/approvals/:id/resolve` | Resolve own or descendant approvals |
| DELETE | `/v1/approvals/:id` | Cancel pending |
| GET | `/v1/permissions` | View own rules |
| POST | `/v1/permissions` | Create own rules |
| DELETE | `/v1/permissions/:id` | Delete own rules |
| POST | `/v1/permissions` (for agent) | Create rules for owned agents |
| GET | `/v1/services` | Browse registry (read-only) |
| GET | `/v1/services/:key` | Service detail |
| GET | `/v1/services/:key/actions` | List actions |
| GET | `/v1/audit` | Own audit trail |

#### Agent Endpoints (most restricted)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/v1/actions/call` | Execute as self |
| GET | `/v1/secrets` | List own secret names (never values) |
| PUT | `/v1/secrets/:name` | Store a secret (`on_behalf_of` owner for integrations) |
| POST | `/v1/secrets/:name/request` | Ask owner-user to provide a secret |
| GET | `/v1/connections` | List own + inherited connections |
| POST | `/v1/connections` | Initiate OAuth (`on_behalf_of` owner) |
| GET | `/v1/approvals?scope=actionable` | Descendant approvals agent can handle |
| GET | `/v1/approvals?scope=mine` | Own pending approvals |
| POST | `/v1/approvals/:id/resolve` | Resolve descendant approvals |
| DELETE | `/v1/approvals/:id` | Cancel own pending |
| GET | `/v1/services` | Browse registry |
| GET | `/v1/services/:key/actions` | Discover actions |
| GET | `/v1/audit` | Own audit trail |
| POST | `/v1/sub-identities` | Create sub-identity |
| GET | `/v1/sub-identities` | List own sub-identities |
| DELETE | `/v1/sub-identities/:id` | Destroy sub-identity |

**Key restriction**: Agents CANNOT create or modify their own permission rules. Only their owner-user or org-admin can grant permissions. This prevents an agent from auto-approving its own destructive actions.

### Webhooks

```
POST /v1/webhooks
{
  "url": "https://agent-runner.overfolder.com/hooks/overslash",
  "events": ["approval.created", "approval.resolved", "connection.completed", "secret.provided"]
}
```

---

## Audit Trail

Every action execution, approval resolution, secret access, and connection change is logged.

```
GET /v1/audit?identity=idt_...&service=github&from=2026-03-01&to=2026-03-23
```

Audit entry:
```json
{
  "id": "aud_...",
  "identity_id": "idt_henry",
  "identity_chain": ["idt_researcher", "idt_henry", "idt_alice"],
  "action": "execute",
  "service": "github",
  "method": "POST",
  "url": "api.github.com/repos/acme/app/pulls",
  "status_code": 201,
  "permission_resolution": "auto_approved",
  "approval_id": null,
  "timestamp": "2026-03-23T11:30:00Z"
}
```

---

## Database Schema (Core Tables)

```sql
-- Organizations
CREATE TABLE orgs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Identity hierarchy
CREATE TABLE identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id),
    parent_id UUID REFERENCES identities(id),
    owner_id UUID REFERENCES identities(id),
    type TEXT NOT NULL CHECK (type IN ('user', 'agent', 'subagent')),
    name TEXT NOT NULL,
    depth INTEGER NOT NULL DEFAULT 0,
    inherit_permissions BOOLEAN NOT NULL DEFAULT false,
    can_create_sub BOOLEAN NOT NULL DEFAULT true,
    max_sub_depth INTEGER NOT NULL DEFAULT 5,
    ttl INTERVAL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by UUID REFERENCES identities(id)
);

-- API keys
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL UNIQUE,   -- bcrypt hash of the key
    key_prefix TEXT NOT NULL,        -- first 8 chars for identification
    name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

-- Versioned secrets
CREATE TABLE secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL REFERENCES identities(id),
    name TEXT NOT NULL,
    current_version INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(identity_id, name)
);

CREATE TABLE secret_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id UUID NOT NULL REFERENCES secrets(id),
    version INTEGER NOT NULL,
    encrypted_value BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by UUID REFERENCES identities(id),
    UNIQUE(secret_id, version)
);

-- OAuth connections
CREATE TABLE connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL REFERENCES identities(id),
    provider TEXT NOT NULL,          -- 'google', 'github', 'spotify'
    service_key TEXT,                -- 'google-calendar', 'gmail' (nullable = provider-wide)
    encrypted_access_token BYTEA NOT NULL,
    encrypted_refresh_token BYTEA,
    token_expires_at TIMESTAMPTZ,
    scopes TEXT[],
    account_email TEXT,
    byoc_credential_id UUID,         -- references org or identity BYOC credentials
    is_default BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Permission rules
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL REFERENCES identities(id),
    service TEXT,                     -- null = all services
    scope TEXT NOT NULL,
    description TEXT,
    created_by UUID REFERENCES identities(id),
    created_via TEXT,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Approval requests
CREATE TABLE approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id),
    executing_identity_id UUID NOT NULL REFERENCES identities(id),
    gap_identity_id UUID NOT NULL REFERENCES identities(id),
    short_id INTEGER NOT NULL,       -- per-identity sequential
    action_summary TEXT NOT NULL,
    action_detail TEXT,
    action_input JSONB NOT NULL,     -- full request for replay
    permission_keys TEXT[],
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'cancelled', 'executed')),
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES identities(id),
    decision TEXT,                    -- 'allow', 'deny', 'allow_remember'
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Org-level service definitions (extends global YAML registry)
CREATE TABLE org_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id),
    key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    definition JSONB NOT NULL,       -- full service definition
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by UUID REFERENCES identities(id),
    UNIQUE(org_id, key)
);

-- Audit trail
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id),
    identity_id UUID NOT NULL,
    identity_chain UUID[] NOT NULL,   -- full ancestor chain
    event_type TEXT NOT NULL,         -- 'action.executed', 'approval.resolved', 'secret.accessed', ...
    service TEXT,
    method TEXT,
    url TEXT,
    status_code INTEGER,
    permission_resolution TEXT,       -- 'auto_approved', 'approved:apr_...', 'unauthenticated'
    approval_id UUID,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_org_time ON audit_log(org_id, created_at DESC);
CREATE INDEX idx_audit_identity ON audit_log(identity_id, created_at DESC);
```

---

## What This Replaces in Overfolder

| Current Overfolder Code | Replaced By |
|------------------------|-------------|
| `agent-runner/src/tools/secrets.rs` | Overslash secrets API |
| `agent-runner/src/tools/curl.rs` (secret injection, gating) | Overslash `actions/call` |
| `agent-runner/src/tools/connectors/permissions.rs` | Overslash permissions + approvals |
| `agent-runner/src/tools/connectors/oauth.rs` | Overslash connections API |
| `backend/src/routes/integration.rs` (OAuth flows) | Overslash OAuth engine |
| `backend/src/routes/byog.rs` (BYOC credentials) | Overslash BYOC in connections |
| `connector_approvals` / `action_requests` tables | Overslash approvals table |
| `action_permission_rules` table | Overslash permissions table |
| `user_secrets` table | Overslash secrets + secret_versions |
| `oauth_tokens` table | Overslash connections |

**What stays in agent-runner**: The agentic loop, context building, tool execution dispatch (calling Overslash), VM delegation, memory management, model routing.

**Nango decision**: Overslash subsumes what Nango would have provided. Nango is no longer under consideration — Overslash owns OAuth flows, token refresh, and the proxy pattern natively.

---

## Open-Source Boundary

Overslash can be released as a standalone open-source project (Apache 2.0 or similar). It has no Overfolder-specific logic.

### Open Source (Overslash)

- Backend: REST API server (Rust/Axum)
- Dashboard: org admin + user web UI (SvelteKit)
- Identity hierarchy and API key management
- Secret vault with versioning
- OAuth engine with BYOC support
- Permission chain resolution
- Approval workflow (API + standalone approval/secret-request pages)
- Action executor (raw HTTP, service+action)
- Service registry (YAML loader + DB)
- Audit trail
- Global service definitions (github.yaml, google.yaml, stripe.yaml, ...)

### Overfolder-Specific (Private)

- Telegram approval inline keyboards (sends Overslash approval URL via Telegram buttons)
- Agent-runner Overslash client integration
- Overfolder-specific webhook handlers
- Overfolder frontend integrations page (embeds/links to Overslash dashboard)

---

## Implementation Plan

### Phase 1: Core Service (MVP)

1. Overslash backend scaffold (Rust/Axum, single binary)
2. Orgs + identities + API keys
3. Secret vault with versioning
4. `POST /v1/actions/call` (Mode A: raw HTTP only)
5. Permission rules + basic gating (flat, no hierarchy yet)
6. Approval workflow (API-only)
7. Audit trail
8. Dashboard: minimal — identity management, approval resolution page, secret request page
9. Overfolder agent-runner integration (replace secrets.rs + curl.rs)

### Phase 2: OAuth + Registry

1. OAuth engine (system credentials, token refresh)
2. BYOC credential support
3. Connections API
4. Global service registry (YAML definitions for top 20 services)
5. Mode C (service + action) execution
6. OpenAPI import
7. Human-readable action descriptions
8. Dashboard: connections page, service browser, secret management, audit viewer

### Phase 3: Hierarchy

1. Identity hierarchy (parent/child, depth tracking)
2. `inherit_permissions` dynamic resolution
3. Sub-identity CRUD for agents
4. Approval bubbling (gap detection, ancestor chain handling)
5. TTL-based sub-identity cleanup
6. Webhook notifications for approval chain
7. Dashboard: identity hierarchy tree view, agent permission management

### Phase 4: Polish

1. Meta tools (overslash_search, overslash_call, overslash_auth)
2. Rate limiting per identity
3. Org billing / usage metering
4. Dashboard: org settings, webhook management, bulk permission operations
5. Service definition contribution workflow (PRs to global registry)

---

## Open Questions

- **Execution isolation**: Should Overslash execute HTTP requests directly, or delegate to a sandbox (like Overfolder's VMs)? Direct is simpler. Sandbox prevents response exfiltration but adds latency and complexity.
- **Secret request UX**: Overslash needs a minimal web UI for `request_secret` (a page where the user submits a value). Is this built into Overslash, or does the caller provide the UI?
- **Connection sharing across agents**: Currently connections at the user level are visible to all agents under that user. Should there be a way to restrict a connection to specific agents?
- **Global registry governance**: How are PRs to the global service registry reviewed? Who decides which services get added?
- **Overslash hosting for Overfolder**: Does Overfolder run its own Overslash instance, or use a managed Overslash service? Initially self-hosted alongside agent-runner.
