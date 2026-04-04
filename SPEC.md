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

**User-initiated enrollment**: A user creates the agent identity in the dashboard or via API, providing a name, parent placement, optional permission groups, and optional `inherit_permissions` flag. Overslash returns a single-use enrollment token. The user pastes the enrollment snippet (containing the Overslash URL, token, and a link to `overslash.dev/enrollment/SKILL.md`) into the agent's conversation. The agent exchanges the single-use token for a permanent API key. Simple, controlled — the user decides when and where the agent exists.

The enrollment token has a **fixed 15-minute TTL**. The agent identity appears in the hierarchy immediately in a **pending enrollment** state (inactive until token exchange). If the token expires unused, the pending identity is cleaned up automatically.

**Agent-initiated enrollment**: The agent discovers Overslash (e.g., via `overslash.dev/SKILL.md` → `overslash.dev/enrollment/SKILL.md` or environment hints) and requests an enrollment token, proposing a name and optional metadata about itself. This token only grants the ability to generate a consent URL. The agent presents this URL to a user (in chat, email, etc.). The authenticated user visits the consent URL, where they can:

- **Edit the agent's proposed name** (pre-filled but fully editable)
- **Choose placement** in the hierarchy (defaults to directly under the approving user)
- **Assign permission groups**

The consent URL is scoped to the org. Any authenticated user in the org with agent-creation permissions can approve — not just one specific user. After approval, the agent's token is exchanged for a permanent API key server-side. The agent, polling or via webhook, picks up the key.

Note: `inherit_permissions` is not offered during agent-initiated enrollment — the user configures this after enrollment if desired.

### Identity Reconfiguration

After enrollment, an identity's configuration remains mutable:

- **Parent**: an identity can be reparented to a different position in the hierarchy (within the user's subtree)
- **Permission groups**: can be added or removed at any time
- **`inherit_permissions`**: can be enabled or disabled at any time

### `inherit_permissions`

A live pointer (not a copy). When set on an identity, it dynamically has whatever permissions its parent has — current AND future. Parent gains a rule tomorrow, child gains it too.

---

## 5. Permission System

### Hierarchical Resolution

When a sub-agent executes an action, every level in the ancestor chain must authorize:

1. Check sub-agent → has rule or `inherit_permissions`? Pass, continue up.
2. Check agent → has rule? Pass, continue up.
3. Check user → has rule? Pass. All levels authorized → **execute**.
4. First level without a rule and without `inherit_permissions` → **gap**. Create approval at that level.

### Approval Bubbling

The approval is created at the gap level. That level's ancestors can resolve it. This means agents approve for their sub-agents without pestering the user.

### Org-Level ACL

Within an org, access control determines which users can see and manage which resources. An ACL (Access Control List) or role-based system governs:

- Which users can view/manage specific services, connections, and secrets
- Which users can create and manage agents
- Which users can resolve approvals for other users' agents
- Org-admin vs member vs read-only roles

This is distinct from the per-identity permission rules (which gate action execution). ACL controls who can administer Overslash itself within an org.

### Permission Rules

Rules have optional expiry. "Allow & Remember" on an approval creates a persistent rule at the level the approver chooses, with optional TTL.

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

Three modes:

**Mode A: Raw HTTP** — agent knows the exact request, specifies secret injection.

**Mode B: Connection-based** — use a specific OAuth connection, token auto-injected.

**Mode C: Service + Action** — registry-resolved. Overslash builds the HTTP request from the service definition. Auth auto-resolved from connections/secrets.

### Gating

- No auth involved → execute directly (no gate)
- Auth involved → walk permission chain → all pass → execute; gap found → create approval

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
- **Developer connection tool (API Explorer)** — interactive API explorer for connected services. Select a service and action from the registry, fill in parameters, and execute via Mode B/C. Similar to Swagger UI or Postman but integrated with Overslash auth. Always executes as the logged-in user's own identity — no agent impersonation. Actions are logged in the audit trail under the user. Can be hidden via org setting.
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
