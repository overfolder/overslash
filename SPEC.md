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

```
Org (acme)
  └── User (alice)                     depth=0
       └── Agent (henry)               depth=1, parent=alice
            ├── SubAgent (researcher)   depth=2, parent=henry
            └── SubAgent (emailer)      depth=2, parent=henry
```

- **Users** created by org-admins
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
| `github:create_pull_request:overfolder/*` | Defined registry action, scoped to repos |
| `github:defined:*` | Any registry-defined action on GitHub |
| `github:POST:/repos/*/pulls` | Specific HTTP verb + path against GitHub |
| `github:ANY:*` | Any HTTP request against GitHub |
| `http:POST:api.example.com` | Raw HTTP to a specific host |
| `http:ANY:*` | Unrestricted HTTP proxy |
| `secret:gh_token:api.github.com` | Inject a specific secret toward a specific host |

**Special action values:**
- **HTTP verbs** (`GET`, `POST`, `PUT`, `DELETE`, etc.) — allow specific HTTP methods against the service
- **`ANY`** — allow any HTTP method
- **`defined`** — allow only actions defined in the service registry (no raw HTTP verbs)

**Pseudo-services:**
- **`http`** — raw HTTP access with no service abstraction. The arg is the target host. Most orgs won't grant this — it turns Overslash into a general HTTP proxy.
- **`secret`** — secret injection gating. The action is the secret name, the arg is the target host. Required alongside `http` keys when secrets are injected. Prevents a secret approved for one host from being exfiltrated to another.

### Two-Layer Model

Permissions are enforced in two layers:

**Layer 1: Groups (coarse-grained ceiling, org-admin managed)**

Groups define which services are available and at what access level. They constrain users, and agents inherit their owner-user's group ceiling. A request that exceeds the group ceiling is denied outright — no approval can override it.

Group examples:
- "Engineering": `github:ANY:*`, `slack:defined:*`, `stripe:defined:*`
- "Admin": adds `http:ANY:*`, `secret:*:*`
- "Read-only": `github:GET:*`, `slack:GET:*`

Three tiers of trust emerge naturally:
1. **`{service}:defined:*`** — locked to predefined registry actions. Safest.
2. **`{service}:ANY:*`** — arbitrary API calls against known services. Mid trust.
3. **`http:ANY:*`** — full HTTP proxy with secret injection. Highest trust.

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
    { "keys": ["github:create_pull_request:overfolder/backend"] },
    { "keys": ["github:create_pull_request:*"] },
    { "keys": ["github:defined:*"] }
  ]
}
```

For multi-key requests (e.g., `http` service with secret injection), keys within each tier broaden together as coherent sets — not as independent per-key choices. This keeps tiers to 2-4 options regardless of how many keys the request derives:

```json
{
  "derived_keys": [
    { "key": "http:POST:api.example.com", "service": "http", "action": "POST", "arg": "api.example.com" },
    { "key": "secret:api_key:api.example.com", "service": "secret", "action": "api_key", "arg": "api.example.com" }
  ],
  "suggested_tiers": [
    { "keys": ["http:POST:api.example.com", "secret:api_key:api.example.com"] },
    { "keys": ["http:ANY:api.example.com", "secret:api_key:api.example.com"] }
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

- **Overslash generates tiers; platforms render them.** The structured parts (`service`, `action`, `arg`) give platforms everything they need to build labels in any language. Overslash is not a translation service.
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

## 7. Connections (OAuth)

OAuth connections support three credential sources (fallback chain):

1. **Identity BYOC** — the identity's own OAuth client credentials
2. **Org credentials** — shared across the org
3. **Overslash system credentials** — managed by Overslash operators

Connections are created at the user level (even when initiated by an agent). All agents under that user inherit access.

---

## 8. Action Execution

### `POST /v1/actions/execute`

All action execution goes through a single endpoint. The caller specifies a service and action — the level of abstraction is determined by what they choose, not by separate API "modes":

**Service + defined action** — the caller names a service and a registry-defined action (e.g., `github` + `create_pull_request`). Overslash builds the HTTP request from the service definition. Auth auto-resolved from connections/secrets. This is the simplest and safest path — agents don't need to know URLs or HTTP methods. Derives key: `github:create_pull_request:{resource}`.

**Service + HTTP verb** — the caller names a service/connection and an HTTP method + path (e.g., `github` + `POST /repos/X/pulls`). Auth is auto-injected from the connection. For agents that know the API but want Overslash to handle auth. Derives key: `github:POST:/repos/X/pulls`.

**`http` service** — the caller uses the `http` pseudo-service with a full URL, method, headers, body, and secret injection metadata. This is the lowest-level path — agents construct the full request. Requires `http` in the user's group. Derives keys: `http:POST:api.github.com` + `secret:gh_token:api.github.com`.

These are not separate API modes — they are a spectrum of abstraction over the same execution pipeline and permission key format (`{service}:{action}:{arg}`).

### Gating

Every request derives permission keys. Resolution follows the two-layer model (§5):

1. Group ceiling check (service + access level)
2. Permission key check (all derived keys must be covered)
3. If uncovered → approval request → user decides → "Allow & Remember" stores keys

### Secret Injection (`http` service only)

When using the `http` pseudo-service, the caller specifies how each secret should be injected per-call (as header, query param, or cookie). This generates `secret:{name}:{host}` permission keys alongside the `http:{METHOD}:{host}` key. Both must be covered for auto-approval.

For service-based requests, auth is resolved automatically from connections — no manual secret injection needed.

### Human-Readable Descriptions

For registry-known services, Overslash generates descriptions from action metadata: "Create pull request 'Fix bug' on acme/app" instead of "POST api.github.com/repos/acme/app/pulls".

---

## 9. Service Registry

### Two-Tier

**Global**: YAML files shipped with Overslash. Common APIs (Eventbrite, GitHub, Google Calendar, Stripe, Slack, Resend, X, etc.). Read-only for orgs.

**Org**: Org-admins register additional services for their own or niche APIs. OpenAPI import supported.

### Service Definition

```yaml
key: github
display_name: GitHub
hosts: [api.github.com]
auth:
  - type: oauth
    provider: github
    token_injection: { as: header, header_name: Authorization, prefix: "Bearer " }
  - type: api_key
    default_secret_name: github_token
    injection: { as: header, header_name: Authorization, prefix: "Bearer " }
actions:
  create_pull_request:
    method: POST
    path: /repos/{repo}/pulls
    description: "Create a pull request"
    risk: write
    params:
      repo: { type: string, required: true }
      title: { type: string, required: true }
      head: { type: string, required: true }
      base: { type: string, required: true }
```

---

## 10. Meta Tools for LLM Agents

Three tools that let any LLM agent use Overslash:

| Tool | Purpose |
|------|---------|
| `overslash_search` | Discover services and actions. Returns schemas + auth status. |
| `overslash_execute` | Execute any action (all three modes). Returns result or pending approval. |
| `overslash_auth` | Check/initiate auth, store/request secrets, create sub-identities. |

The agent harness wraps these 3 tools and handles plumbing (webhooks, approval injection into agent loop).

---

## 11. Dashboard

Web UI for non-API interactions. Built with SvelteKit + TypeScript.

### Core Views

- **User profile** — authenticated user info, API keys, settings
- **Org/User/Agent hierarchy** — tree view of the identity hierarchy, with inline management (create, edit, delete, enrollment tokens)
- **Connected services** — which services have active connections, their status, and quick actions (reconnect, revoke)
- **Developer connection tool (API Explorer)** — interactive API explorer for connected services. Select a service, pick a defined action or make a custom request, fill in parameters, and execute. Similar to Swagger UI or Postman but integrated with Overslash auth. Available actions adapt to the user's group grants (defined actions, HTTP verbs, or raw HTTP). Always executes as the logged-in user's own identity — no agent impersonation. Actions are logged in the audit trail under the user. Can be hidden via org setting.
- **Audit log** — searchable, filterable log of all actions, approvals, and secret accesses. Filterable by identity, service, time range, event type.

### Org-Admin Views

Services (browse/register/import), Connections (org-level OAuth), Webhooks, Permissions, Settings.

### User Views

My Connections, My Secrets (names + versions), Approvals (pending, one-click resolve with expiry picker), My Agents (permission management).

### Standalone Pages (no login required, signed URL)

- **Approval resolution**: `https://overslash.dev/approve/apr_...?token=jwt` — Allow/Deny/Remember
- **Secret request**: `https://overslash.dev/secrets/provide/req_...?token=jwt` — secure input field

---

## 12. Audit Trail

Every action execution, approval resolution, secret access, and connection change is logged with the full identity chain. Queryable by identity, service, time range, and event type.

---

## 13. Open-Source Plan

Overslash will be released as open source (Apache 2.0 or similar). It has no platform-specific logic. The global service registry is community-maintained via PRs.

Callers (like Overfolder) build their own channel-specific integrations (Telegram approval buttons, etc.) on top of Overslash's REST API and approval URLs.
