# Overslash

A standalone, multi-tenant actions and authentication gateway for AI agents. Overslash handles everything between "an agent wants to call an external API" and "the API call executes with the right credentials."

It owns: identity hierarchy, secret management, OAuth flows, permission rules, human approval workflows, action execution, service registry, and audit trail.

The name: it slashes through doors and auth for the user.

Overslash is **purely an auth and identity layer**. It does not orchestrate agents, manage compute, or track connectivity. The UI reflects this: it shows identities, permissions, credentials, approvals, and audit — never agent runtime state, task queues, or infrastructure. Status indicators (active/idle/errored) are derived from recent audit events (last action timestamp and result), not from a live connection to the agent.

This document describes the web UI

## Logo

The Overslash logo is:
the word Overslash replacing the l with an slash "Overs/ash"
This stash can have animated color, and it can open and close as transition, turning into dos slashes and then growing as a portal

## Login

Unlogged users go into a blank page with a centered login form:

This login form has:
+ The Overslash logo
+ Login in with Google, Github using horizontal buttons with button and text(these buttons can be disabled or not present if the corresponding IDP is not configured)
+ Login in with ......, same, for custom corporate IDP, Okta, ...
+ On dev(and if enabled via envvar) a "Dev Login" is a different orangish color and with a developer/console icon. This is a debug login

UNauth users go here, and on auth, they go back to the page they were trying to access previously, or /dashboard if no such page or a loop would form

## Page Structure

All the following pages have this structure
There is a collapsable navigation menu on the left bar on desktop, when expanded shows labels and icons, when contracted only icons. On mobile this bar can be shown and hidden using swipes.

Nav items: Dashboard, Services, API Explorer, Audit Log. Org Dashboard appears under an "ADMIN" label for org-admins.

**Profile is NOT a nav item.** Instead, the logged-in user's avatar and name appear at the bottom of the sidebar (desktop) or top-right (mobile). Clicking opens the User Profile view.

## User Dashboard view

The default view post-login, unless the user was already trying to go to another route.

### Layout: Two-panel

Left panel: **Agent tree**. Right panel: **Detail view** for the selected node.

The tree stays clean — each row shows: name, status indicator, and pending approval badge count if any. Selecting a node populates the detail panel.

### Agent tree (left panel)

```
User
|
|- ● Agent 1
|- ⚠ Agent 2              [2 pending]
|- [-] Agent 3
|   |
|   |- Subagent 1 [Last active: ..., Created: ....]
|   \- Subagent 2
\- [-] SwarmAgent (12)
    |- Subagent 1
    |- Subagent 10
    \- [see more]
```

- Status indicators by state: active, idle, errored (color-coded)
- Pending approval count shown as a badge — highest-signal element, something is blocked waiting for the user
- Agents with many sub-agents collapse, showing the count. Expand to see children, with `[see more]` pagination for large groups. (TBD: collapse individual agents vs entire subtrees)
- Some IDs are agent-created, others human-created — allow filtering by origin

### Detail panel (right panel)

When a node is selected, show:

- **Agent name / ID**
- **Status**: active / idle / errored
- **Last action**: service + action name, timestamp, success/fail
- **Pending approvals**: list of pending approval requests — this is the primary actionable element
- **Links**: `[View executions]` `[View permissions]`

### Live updates

The dashboard supports **streaming updates** from the backend (SSE or WebSocket) to reflect agent activity in real time — status changes, new sub-agents, new approvals, completed actions all update the tree and detail panel live.

When streaming is off or unavailable, show a **refresh button** and optionally an **auto-refresh toggle** (polling fallback).

## User Profile view

Accessible from the nav or a user avatar/menu in the top bar. Shows the authenticated user's own identity and credentials within Overslash.

### Identity

- **Name**, **email**, **avatar** (from IDP)
- **Identity path**: displayed as `acme / user / alice` — each segment is a clickable link (org → org dashboard, user → this profile). *(Design note: segments mirror the SPIFFE ID path structure.)*
- **Org**: which org the user belongs to, and their role (admin, member, read-only)
- **Login method**: which IDP was used (Google, GitHub, corporate SSO, dev login)
- **Created / Last login** timestamps

### API Keys

The user's personal API keys for calling the Overslash REST API directly (not via the dashboard).

- **List of active keys**: name/label, prefix (first 8 chars), created date, last used date
- **Create new key**: name/label input → key shown once on creation, never again. Copy button + warning.
- **Revoke key**: per-key revoke with confirmation

Keys are scoped to the user identity. Agent keys are managed separately in the agent detail panel.

### Enrollment Tokens

Tokens for enrolling new agents under this user (user-initiated enrollment flow).

- **Generate token**: creates a single-use enrollment token, shown once. Copy button.
- **Active tokens**: list of unused tokens with creation date and expiry. Revoke button per token.

### Settings

- **Default approval TTL**: when this user approves an action with "Allow & Remember", the default TTL pre-filled in the expiry picker (e.g., 1h, 24h, 7d)
- **Notification preferences**: how to receive approval requests — email, webhook URL, or dashboard-only

## Org Dashboard view (org-admins only)

Accessible to org-admin users. Shows an overview of the org's users.

### User list

A table/list of all users in the org, showing:

- **Name**
- **Email**
- **Groups/roles** (admin, member, read-only, custom groups)
- **Status** (active, invited, disabled)
- **Agent count**
- **Last active**

Supports search and filtering by group/role/status.

### User detail (click-through)

Clicking a user navigates to their dashboard — this reuses the **User Dashboard view** component, rendered in the context of the selected user. The org-admin sees exactly what that user would see (agent tree, detail panel, live updates), with read access to their agents, approvals, and activity.

### Groups

A section/tab within the Org Dashboard for managing user groups.

- **Groups list**: name, member count, shared services count
- **Group detail**: member list (add/remove users), list of services shared with this group
- **"Everyone"** group is always present, cannot be deleted, all users are implicit members

## Services view

A single view in the nav for discovering, connecting, managing, and sharing services. "Connected Services" is a filter preset within this view, not a separate page.

### Service list

Shows all services visible to the user, regardless of source:

```
Service            Source          Status            Actions
──────────────────────────────────────────────────────────────
GitHub             Overslash       ● Connected       [Manage] [Share]
Google Calendar    Org             ● Connected       [Manage]
Stripe             Org             ○ Available       [Connect]
Slack              Overslash       ○ Available       [Connect]
Internal CRM       Org (custom)    ○ Available       [Connect]
My Scraper API     You (custom)    ● Connected       [Manage] [Share]
```

**Source**: where the service definition comes from.
- **Overslash** — global registry (shipped YAML)
- **Org** — org-provided (org-defined template or org-shared connection)
- **You** — user-defined custom service

**Status**:
- **Connected** — active connection for this user
- **Available** — definition exists, not yet connected
- **Shared (groups)** — user has shared this to org groups

**Filtering**: by source, by status (the "Connected Services" shortcut), by category (dev tools, comms, payments, etc.)

### Connect flow

Triggered by `[Connect]` on an available service. The flow depends on the service source:

**Org-provided services**:
- *Shared credentials* (e.g., org Stripe account): one-click activate, no auth needed
- *Per-user OAuth with org client* (e.g., Google Calendar — org provides the OAuth app, each user needs their own token): click Connect → OAuth redirect → done

**Templated services** (Overslash global registry or org-defined):
- *OAuth*: shows requested scopes → Connect → OAuth redirect → callback → connected
- *API key*: form to paste the key → stored as a versioned secret → connected
- *Both available*: user picks which auth method

**Custom services** (via `[+ Add Custom Service]` button):
1. Name + Base URL
2. Auth method: None / API Key / OAuth (client ID, secret, auth URL, token URL, scopes)
3. Test connection (optional)
4. Save as template toggle — makes it reusable by the user

### Manage

`[Manage]` on a connected service: reconnect, revoke, view connection health, see which agents use it.

### Share

`[Share]` (visible to users with org permissions): promote the service to org level, pick which groups can see/use it. Unshare pulls it back to user-only.

## Audit Log view

A dedicated nav item. Filterable, searchable event stream — newest first, paginated.

### Event row

Each row shows enough to scan without clicking:

```
Timestamp            Identity (SPIFFE)                                    Event              Service        Result
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
2m ago               spiffe://acme/user/alice/agent/henry/sa/researcher   Action executed    GitHub         ✓ 200
5m ago               spiffe://acme/user/alice/agent/henry                 Approval resolved  —              Allowed (24h)
12m ago              spiffe://acme/user/alice/agent/henry/sa/emailer      Action executed    Gmail          ✗ 403
15m ago              spiffe://acme/user/alice                             Secret accessed    Stripe         ✓ injected
18m ago              spiffe://acme/user/alice/agent/henry                 Connection changed Google         ✓ reconnected
1h ago               spiffe://acme/user/alice/agent/henry/sa/researcher   Approval created   Slack          ⏳ pending
```

- **Timestamp** — relative for recent, absolute for older. Hover shows full UTC + local.
- **Identity** — SPIFFE ID of the identity that triggered the event. The full path encodes the hierarchy.
- **Event type** — action executed, approval created/resolved, secret accessed, connection changed, identity created/deleted, permission changed
- **Service** — which external service was involved (blank for identity/permission events)
- **Result** — success/fail/pending, with status code for executions

### Filters

A filter bar above the list, all combinable:

- **Identity** — pick any node in the hierarchy, optionally include descendants
- **Event type** — multi-select checkboxes
- **Service** — dropdown from known services
- **Result** — success / failure / pending
- **Time range** — presets (last hour, today, 7 days, 30 days) + custom range picker

Filters update the URL so they're shareable/bookmarkable.

### Event detail (expand or side panel)

Clicking a row expands or opens a side panel with:

- **Request**: method, URL, parameters (for action executions)
- **Human-readable description**: "Created pull request 'Fix bug' on acme/app" (for registry-known services)
- **Permission chain resolution**: which levels passed, where the gap was (if approval was needed)
- **Approval info**: who approved, when, with what TTL, the approval URL used
- **Secret references**: which secrets were injected (names only, never values)
- **Response**: status code, timing, truncated response body (configurable)

Identities, approvals, and services referenced in the detail are **clickable links** to their respective views in the dashboard.

### Refresh

A **refresh button** that reloads the current page of results. The button has a **side dropdown** to enable auto-refresh at a chosen interval: 5s, 15s, 1m, 5m, 30m. When auto-refresh is active, the button shows the selected interval and a visual indicator.

### Export

A **CSV export** button that downloads the currently filtered result set.

## API Explorer view

An interactive tool for testing and debugging service connections through Overslash. Simpler than Postman — the goal is verifying that auth works and seeing what comes back, not building collections or scripting.

Can be **hidden from users via an org setting** (e.g., orgs that don't want users making ad-hoc API calls). When hidden, the nav item is not shown.

### Execution modes

The explorer maps directly to Overslash's three execution modes, presented as tabs:

**Mode C — Service + Action** (default, simplest):
- Pick a service from a dropdown (only connected services)
- Pick an action from the service registry (dropdown, with human-readable descriptions)
- Auto-generated form: the registry defines the action's parameters, so the explorer renders input fields for each one (text, dropdown, checkbox as appropriate)
- Hit **Execute** → shows result

This is the beginner-friendly mode. No URLs, no headers, no HTTP knowledge required.

**Mode B — Connection-based**:
- Pick a connection from a dropdown
- Enter a path (e.g., `/repos/acme/app/pulls`)
- Pick HTTP method (GET/POST/PUT/PATCH/DELETE)
- Optional: request body (JSON editor), query parameters (key-value pairs)
- Auth is injected automatically from the selected connection
- Hit **Execute** → shows result

For users who know the API but want Overslash to handle auth.

### Response panel

All modes share the same response display:

- **Status code** (color-coded: 2xx green, 4xx yellow, 5xx red)
- **Response time**
- **Headers** (collapsible)
- **Body** (syntax-highlighted JSON, with raw/pretty toggle)
- **Permission chain**: which identity was used, whether an approval was needed/resolved

### Identity

The API Explorer always executes as the **logged-in user's own identity**. There is no "execute as" selector — no impersonation of agents or sub-agents. All actions taken through the explorer are logged in the audit trail under the user's identity.

