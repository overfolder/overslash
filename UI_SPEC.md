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

## Global UX Conventions

**Appearance**: light and dark modes, toggled in user settings. No custom theming.

**Routing**: SPA with History mode URLs. Most views have deep-linkable URLs — selected agent, selected service, audit log filters, etc. Sharing a URL lands the recipient on the same view (after login if needed).

**Copy pattern**: click-to-copy button (clipboard icon) next to copyable values (API keys, permission keys, enrollment tokens, URLs). Toast confirmation: "Copied to clipboard."

**Time display**: all timestamps shown as relative by default ("2m ago", "1h ago"), with full UTC ISO-8601 on hover. User settings allow preference: relative, absolute (local timezone), or absolute (UTC).

**Toasts**: success/error feedback appears as a toast notification (bottom-right, auto-dismiss after 5s for success, sticky for errors). Used after: approve/deny, provide secret, revoke key, create agent, archive service, etc.

**Empty states**: views with no data show greyed-out text: "No agents found", "No services found", etc. For agents, service templates, and services, the empty state includes a button to create the first one (e.g., `[+ Create your first agent]`).

**Confirmation dialogs**: destructive actions get a modal confirmation. The modal follows a consistent pattern: title ("Delete agent?"), consequence description, two buttons — `[Cancel]` and the destructive action in red.

Confirmation required:
- **Delete agent** — "Delete agent:henry? This will also delete 3 sub-agents and revoke all their API keys."
- **Revoke API key** — "Revoke key ovs_a1b2...? This cannot be undone."
- **Archive/delete service** — "Archive my-scraper? Agents using this service will lose access."
- **Delete template** — "Delete template? X services are based on this template." (block if active services exist)
- **Disable IdP** — "Disable Google login? 12 users use this provider."
- **Remove webhook** — "Remove webhook? Pending deliveries will be lost."

No confirmation needed (immediate + toast feedback):
- Approve/deny approval (already intentional with specificity picker)
- Provide/deny secret request
- Revoke remembered approval (low-risk, re-approvable)
- Toggle `inherit_permissions`
- Edit agent name, service name

## Design System

Visual foundation for all Overslash UI. Modern SaaS minimal aesthetic — clean, neutral, one accent color. Designed for a developer/admin audience.

### Colors

**Neutral palette** (backgrounds, text, borders):

| Token | Usage |
|-------|-------|
| Neutral/50 | Page background (light) |
| Neutral/100 | Card hover, subtle backgrounds |
| Neutral/200 | Borders, dividers, input strokes |
| Neutral/300 | Disabled icons, placeholder shapes |
| Neutral/400 | Placeholder text, secondary icons |
| Neutral/500 | Secondary text, labels |
| Neutral/600 | Nav text (inactive), form labels |
| Neutral/700 | Body text, primary readable content |
| Neutral/800 | — |
| Neutral/900 | Headings, high-emphasis text, code editor background |

**Primary palette** (indigo — actions, active states, links):

| Token | Usage |
|-------|-------|
| Primary/50 | Active nav item background, selected row highlight |
| Primary/100 | Hover states on primary backgrounds |
| Primary/500 | Primary buttons, active indicators, links |
| Primary/600 | Primary button hover |
| Primary/700 | Primary button pressed |

**Dark mode mapping** — in dark mode, the neutral scale inverts. Backgrounds become dark, text becomes light. Primary and semantic colors remain the same hue but adjust lightness for contrast:

| Light token | Dark mode value | Notes |
|-------------|----------------|-------|
| Neutral/50 (page bg) | #111213 | Dark page background |
| Neutral/100 | #1a1b1e | Card hover, subtle backgrounds |
| Neutral/200 (borders) | #2a2b2f | Borders, dividers — subtle on dark |
| Neutral/300 | #3a3b40 | Disabled icons |
| Neutral/400 | #6b6d73 | Placeholder text (unchanged) |
| Neutral/500 | #8b8d92 | Secondary text (slightly lighter) |
| Neutral/600 | #b0b2b8 | Nav text, form labels |
| Neutral/700 | #d4d5d9 | Body text |
| Neutral/900 (headings) | #f0f1f2 | High-emphasis text |
| White (card bg) | #1a1b1e | Card/panel backgrounds |
| Primary/50 (highlights) | rgba(99,90,217,0.15) | Active state backgrounds |
| Code editor bg | #0d0e10 | Slightly darker than page bg |

Primary and semantic colors (indigo, green, yellow, red, orange) keep their mid-range values — they already have sufficient contrast on dark backgrounds. Badge backgrounds use the same 12% opacity approach, which works naturally on dark surfaces.

**Semantic colors**:

| Token | Usage |
|-------|-------|
| Success/500 | Active status, connected, 2xx results, valid indicators |
| Warning/500 | Pending status, needs-setup, write-risk badges, reconnecting bar |
| Error/500 | Error status, 4xx/5xx results, deny/delete/revoke actions, offline bar |
| Orange/500 | Dev login button, `env` badge |

### Typography

Font: **Inter** for all UI text. **Roboto Mono** for code, permission keys, SPIFFE paths, and YAML.

| Style | Size / Weight | Usage |
|-------|---------------|-------|
| Heading/H1 | 28px Bold | Page titles (rare — mainly Design System page) |
| Heading/H2 | 22px Semi Bold | Section headings |
| Heading/H3 | 18px Semi Bold | Card titles, sidebar logo |
| Body/Large | 16px Regular | Page titles in top bar, section labels |
| Body/Default | 14px Regular | Standard body text, table cells, form values |
| Body/Medium | 14px Medium | Emphasized body text, button labels, nav items |
| Body/Small | 12px Regular | Timestamps, footnotes, validation messages |
| Label/Default | 13px Medium | Form labels, info row labels, filter chips |
| Label/Small | 11px Medium | Badge text, admin section label |
| Code/Default | 13px Roboto Mono Regular | Permission keys, SPIFFE paths, API paths |

### Buttons

**Primary**: Indigo background, white text. Main actions (Save, Create, Allow & Remember, Provide, Approve & Enroll, Execute).

**Secondary**: White background, neutral-700 text, neutral-200 border. Secondary actions (Cancel, Allow Once, filter chips).

**Danger**: Error-red background, white text. Destructive primary actions (used sparingly — most destructive actions use text-only danger style).

**Danger text**: White background, error-red text, neutral-200 border. Deny, Revoke, Delete links.

**Ghost**: White background, primary text, no border. Tertiary actions (links styled as buttons).

**Small buttons**: Same variants at reduced padding (6px vertical, 12px horizontal, 12px font). Used in approval cards, table row actions.

### Badges

Rounded pill shape (border-radius 12px), small padding (4px vertical, 10px horizontal), 12px medium text.

**Status badges** (semi-transparent background at 12% opacity):
- `Active` — success green
- `Idle` — neutral-200 solid background, neutral-500 text
- `Error` — error red
- `Pending` — warning yellow

**Origin badges** (solid neutral-100 background):
- `user-created`, `self-enrolled` — neutral-500 text

**Access level badges** (semi-transparent):
- `read` — success green
- `write` — warning yellow
- `admin` — error red

**Special badges**:
- `env` — solid orange background, white text. Indicates config from environment variable (read-only).

**HTTP method badges** (used in Template Editor, API Explorer):
- `GET` — success green solid background, white bold text
- `POST` — warning yellow solid background, white bold text
- `PUT`, `PATCH`, `DELETE` — same pattern with appropriate semantic color

### Status Indicators

Small filled circles (8px diameter) used in the agent tree and detail headers:
- **Active** (success green): recent successful action
- **Idle** (neutral-400): no recent activity
- **Error** (error red): recent failed action
- **Connected** (success green): service connection status
- **Needs setup** (warning yellow): service awaiting credential setup

### Form Controls

**Text input**: White background, neutral-200 border, 8px corner radius, 10px vertical / 14px horizontal padding. Placeholder text in neutral-400.

**Password input**: Same as text input with masked characters. "Show" toggle link (primary color) on the right side.

**Dropdown**: Same as text input with "▾" indicator on the right side. Dropdown menus have white background, neutral-200 border, 8px corner radius, drop shadow, with items that highlight in primary-50 on hover/selection.

**Toggle**: 40x22px pill shape. On = primary fill with white knob right. Off = neutral-300 fill with white knob left.

**Checkbox**: 18x18px rounded square (4px radius). Checked = primary fill with white "✓". Unchecked = white fill with neutral-300 border.

**Radio buttons**: 16px circle. Selected = primary fill with 6px white inner circle. Unselected = white fill with neutral-300 border.

### Refresh Control

A split button used in the Audit Log (and reusable elsewhere). Two parts joined with no gap:

- **Left**: refresh icon (↻), triggers immediate refresh on click
- **Right**: dropdown arrow (▾), opens interval picker

The two halves share a continuous border — left half has rounded left corners, right half has rounded right corners, joined seamlessly.

**States**:

- **Default (idle)**: White background, neutral-200 border, neutral-600 icon. Click left half to refresh once. Click right half to open interval picker.
- **Auto-refresh active**: Primary-50 background, primary border, primary icon. The icon is followed by the selected interval label (e.g., "15s"). Below the button, a thin progress bar (3px tall) shows the cycle position — neutral-200 track with primary fill that animates from 0% to 100% over the interval, then resets on each refresh.
- **Dropdown open**: Shows a dropdown menu below with interval options: Off, 5s, 15s, 1m, 5m, 30m. Active interval has primary-50 highlight and a "✓" checkmark.

### Toasts

Bottom-right positioned, auto-dismiss after 5s for success, sticky for errors.

White background with drop shadow. Left edge has a small semantic-colored dot (8px circle). Close button ("✕") on the right.

- **Success toast**: success-green dot. "Secret stored successfully."
- **Error toast**: error-red dot. "Failed to revoke API key." Sticky until dismissed.

### Cards

**Section card**: White background, neutral-200 border, 12px corner radius, 24px padding. Used for grouped content (Identity, API Keys, Secrets, Settings sections in User Profile; Groups detail in Org Dashboard).

**Approval card**: Neutral-50 (BG) background, neutral-200 border, 10px corner radius, 16px padding. Contains: action description (medium weight), permission key (monospace, neutral-400), timestamp, and action buttons row.

**Standalone page card**: White background, 16px corner radius, 32-40px padding, drop shadow (rgba(0,0,0,0.08), y:4, blur:24). Centered on a neutral-50 page background. Used for Secret Request, Approval, Enrollment consent pages.

### Tables

Used throughout for lists of users, services, secrets, audit events, etc.

**Header row**: Neutral-50 background, 8px corner radius, semi-bold 12px text in neutral-400. Acts as column labels.

**Data rows**: White background, neutral-100 bottom border (1px), regular 13px text in neutral-700. Consistent column widths defined per table.

**Table card**: Entire table wrapped in a white card with neutral-200 border and 12px corner radius. Header row sits at the top inside the card.

### Connection Status Bars

Thin full-width bars at the top of the page for connectivity state. Semi-transparent semantic background (15% opacity), medium 12px text.

- **Reconnecting**: Warning yellow. "Reconnecting..."
- **Connected**: Success green. "Connected" (auto-dismiss after 3s)
- **Offline**: Error red. "No connection." Persistent until reconnected.

### Navigation

**Sidebar** (desktop): collapsible, two states.

**Expanded** (240px): neutral-50 background, neutral-200 right border. Contains:
- Logo ("Overs/ash") at top (bold 18px)
- Nav items with 18px icon placeholder + label. Active item: primary-50 background, primary text, semi-bold. Inactive: neutral-600 text, medium weight.
- "ADMIN" section label (11px semi-bold, neutral-400, letter-spaced) separates admin-only items.
- User avatar (32px circle) + name at the bottom.
- Collapse button (chevron «) at the bottom or top-right of the sidebar.

**Collapsed** (64px): same background and border. Contains:
- Logo collapses to "/" (the slash character, bold 18px) — the iconic part of "Overs/ash".
- Nav items show icons only (18px, centered), no labels. Active item still has primary-50 rounded background. Tooltip on hover shows the label.
- "ADMIN" label hidden. Admin nav items still show as icon-only.
- User avatar only (no name), centered.
- Expand button (chevron ») to restore.

**Top bar**: 56px tall, white background, neutral-200 bottom border. Page title on left (semi-bold 16px). Notification bell + badge on right.

**Notification badge**: Error-red circle (16px) overlapping the bell icon, with white bold count text.

## Mobile Layout

Breakpoint: 768px. Below = mobile layout, above = desktop.

**Navigation**: sidebar becomes a hamburger menu (top-left) that slides in as an overlay. Swipe-right from left edge also opens it. Notification bell stays in the top bar — tapping opens a full-screen notification list (not a dropdown).

**Stacked navigation with back gesture**: mobile shows one panel at a time.

- **Dashboard**: default view is the agent tree (full width). Tapping an agent pushes the detail panel as a full-screen view with a `[← Back]` header.
- **Services**: service list → service detail/editor is a full-screen push.
- **Audit log**: event list → event detail is a full-screen push.
- **Template Editor**: only the Visual tab is practical on mobile. YAML tab is available but shows a "best on desktop" hint — code editing on a phone is painful.
- **Approval resolution**: specificity picker renders as a vertical radio list (works well on mobile as-is).

## Loading States

**Skeleton screens, not spinners.** On initial page load, show skeleton placeholders matching the layout shape — grey rectangles for text, circles for avatars, rounded boxes for badges.

- **Agent tree**: 4-5 skeleton rows with grey bars for names and circles for status indicators
- **Detail panel**: grey blocks for name, status, approvals section
- **Service list / audit log**: skeleton table rows matching column layout
- **SSE/WebSocket reconnection**: thin colored bar at the top of the page — yellow "Reconnecting..." → green "Connected" (auto-dismiss after 3s). Existing data stays visible.
- **Action in progress** (approve, save, provide secret): the action button shows a small inline spinner and is disabled. No full-page loading state.

## Error States

**Inline errors + toasts for transient failures.**

- **Page load errors** (can't fetch agents, services, etc.): error card in place of content — "Failed to load agents" with `[Retry]` button. Grey icon, not alarming.
- **Action errors** (approve failed, save failed, etc.): sticky red-tinted toast with the error message. Form/button resets to pre-action state so the user can retry.
- **Auth errors** (session expired, 401): redirect to login with toast "Session expired, please log in again." After login, redirect back.
- **Permission errors** (403): show the view structure with a centered "You don't have access to this resource" message. Nav stays visible.
- **Network offline**: persistent thin red bar at top "No connection." Existing data stays visible. Actions are disabled with tooltip "Offline."

## Page Structure

All the following pages have this structure.
There is a collapsable navigation menu on the left bar on desktop, when expanded shows labels and icons, when contracted only icons. On mobile this bar can be shown and hidden using swipes.

Nav items: Dashboard, Services, API Explorer, Audit Log. Org Dashboard appears under an "ADMIN" label for org-admins.

**Profile is NOT a nav item.** Instead, the logged-in user's avatar and name appear at the bottom of the sidebar (desktop) or top-right (mobile). Clicking opens the User Profile view.

**Notifications are NOT a nav item.** A notification bell icon sits in the top bar (right side, next to the user avatar). It shows a badge count of unresolved items (pending approvals + secret requests). Clicking opens a dropdown panel listing recent notifications grouped by type — each item links to the relevant approval or secret request. Notifications also appear inline as badges on each agent node in the Dashboard agent tree (see below). There is no separate notifications page.

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
- Pending approval count + pending secret request count shown as badges — highest-signal elements, something is blocked waiting for the user
- Agents with many sub-agents collapse, showing the count. Expand to see children, with `[see more]` pagination for large groups. (TBD: collapse individual agents vs entire subtrees)
- Some IDs are agent-created, others human-created — allow filtering by origin

### Detail panel (right panel)

When a node is selected, show:

- **Agent name / ID**
- **Status**: active / idle / errored
- **Last action**: service + action name, timestamp, success/fail
- **Pending approvals**: list of pending approval requests with inline resolution (see Approval Resolution below) — this is the primary actionable element
- **Pending secret requests**: list of secrets the agent is waiting for — each with `[Provide]` (opens value input inline) and `[Deny]`. See also the standalone secret request page.
- **Active permission rules**: summary count of remembered approval rules for this identity, with `[View rules]` link
- **Links**: `[View executions]` `[View permissions]`

### Approval resolution

When a user resolves an approval (from the detail panel, notification dropdown, or standalone approval page), three options are presented:

- **Allow** — one-time approval, no keys stored
- **Allow & Remember** — opens the specificity picker (see below)
- **Deny**

#### Specificity picker (Allow & Remember)

The dashboard reads `suggested_tiers` from the approval API. Each tier includes a `description` (English label generated by Overslash) which the dashboard displays directly. The permission key string is shown as secondary text.

```
Allow & Remember — choose scope:

  ○ Create pull request on overfolder/backend
    github:create_pull_request:overfolder/backend

  ○ Create pull request on any repo
    github:create_pull_request:*

  ○ Any GitHub action
    github:*:*

  Expires: [24h ▾]                         [Confirm]
```

Agent platforms that need i18n can build their own labels from the structured key parts (`service`, `action`, `arg`) in `derived_keys`.

For `http` service approvals, tiers compose the paired keys:

```
  ○ POST to api.example.com with api_key
    http:POST:api.example.com + secret:api_key:api.example.com

  ○ Any request to api.example.com with api_key
    http:ANY:api.example.com + secret:api_key:api.example.com
```

Overslash also hosts a deep-link approval page at `/approvals/apr_...` (requires login) so platforms can link users directly without building their own approval UI. The page shows the same approval details and specificity picker. The platform decides whether to link here or handle resolution in its own UX.

### Live updates

The dashboard supports **streaming updates** from the backend (SSE or WebSocket) to reflect agent activity in real time — status changes, new sub-agents, new approvals, completed actions all update the tree and detail panel live.

When streaming is off or unavailable, show a **refresh button** and optionally an **auto-refresh toggle** (polling fallback).

### Inline identity management

The agent tree supports creating, editing, and deleting agents directly.

#### Tree actions

- **`[+ New Agent]` button** at the top of the tree panel — starts the user-initiated enrollment flow
- **Kebab menu (⋮)** on each agent node — options: Rename, Move (reparent), Delete

#### User-initiated enrollment

`[+ New Agent]` opens an inline form or modal:

- **Agent name** (required)
- **Parent** — defaults to the user, dropdown/tree-picker to choose another position in the user's subtree
- **`inherit_permissions`** — checkbox (if checked, agent inherits parent's current + future rules)
- **TTL** — optional, for ephemeral agents

On submit, shows a **one-time enrollment snippet** designed to be pasted into the agent's conversation:

```
┌─ Enrollment Instructions ───────────────────────┐
│                                                  │
│  Agent "henry" created. Paste this into your     │
│  agent's conversation:                           │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │ # Overslash enrollment                     │  │
│  │ OVERSLASH_URL=https://acme.overslash.dev   │  │
│  │ OVERSLASH_ENROLLMENT_TOKEN=oet_a1b2c3...   │  │
│  │                                            │  │
│  │ For integration details, see:              │  │
│  │ https://overslash.dev/enrollment/SKILL.md  │  │
│  └────────────────────────────────────────────┘  │
│                                    [Copy] [Done] │
│                                                  │
│  ⚠ This token is shown once. The agent          │
│  exchanges it for a permanent API key.           │
└──────────────────────────────────────────────────┘
```

The enrollment token has a **fixed 15-minute TTL**. The agent appears in the tree immediately in a **pending enrollment** state (greyed out / dashed outline) until the agent exchanges the token. If the token expires unused, the pending identity is cleaned up.

#### Agent-initiated enrollment (consent page)

When an agent discovers Overslash and requests enrollment, it generates a consent URL to send to a user. The consent page is a standalone page requiring login (not part of the dashboard nav).

The user sees:

- **Proposed name** — pre-filled by the agent, fully editable by the user
- **Requested by** — agent metadata (IP, timestamp)
- **Placement tree** — shows where the agent will land in the hierarchy. Defaults to directly under the approving user. A `[Change parent]` control opens a mini tree picker showing only positions the user is authorized to place agents (their subtree):

```
┌─ Select parent ─────────────┐
│  ○ alice (you)              │
│  ○ agent-henry              │
│    ○ sa-researcher          │
│  ● agent-builder  ← selected│
└─────────────────────────────┘
```

- **No `inherit_permissions` option** — the user configures this after enrollment if desired

Actions: `[Approve & Enroll]` and `[Deny]`.

After approval, shows a success message. The agent picks up its API key via polling or webhook.

#### Detail panel — agent management

When an agent is selected in the tree, the detail panel includes management controls:

- **Name** — click to edit inline
- **Origin** — badge showing "user-created" or "self-enrolled"
- **Parent** — displayed with a `[Move]` action to reparent (opens tree picker)
- **Permission rules** — read-only list of active permission keys for this identity (see Permission Rules below)
- **`inherit_permissions`** — toggle, configurable at any time
- **API Keys** — list with prefix, created/last-used dates, `[Revoke]` per key, `[+ New Key]`
- **Remembered approvals** — list of "Allow & Remember" rules active for this identity (see Remembered Approvals below)
- **Actions** — `[View executions]` `[Delete agent]`

Delete shows a confirmation dialog warning about child identities that will be deleted.

#### Permission rules

Permission rules are expressed as **permission keys** — structured strings in the format `{service}:{action}:{arg}` that encode what an identity is auto-approved to do. Keys are never written by hand — they are created when a user clicks "Allow & Remember" on an approval request. They build up organically as agents are used.

The permission rules section in the detail panel shows a read-only view:

```
Permission Rules for agent:henry

Key                                                Source          Expires
───────────────────────────────────────────────────────────────────────────
github:create_pull_request:overfolder/*    remembered      2026-04-08
github:GET:*                               remembered      never
slack:send_message:#engineering            remembered      2026-04-15
stripe:*:*                           inherited       —
```

- **Key** — the permission key string (`{service}:{action}:{arg}`)
- **Source** — `remembered` (from "Allow & Remember" approval) or `inherited` (from parent via `inherit_permissions`)
- **Expires** — TTL from the approval, "never" if no expiry, or "—" for inherited rules
- Inherited rules link to the parent identity. Remembered rules link to the approval event that created them.

ALL permission keys for a request must be covered for auto-approval. A single missing key triggers the approval flow.

#### Remembered approvals

When a user clicks "Allow & Remember" on an approval, the system stores permission key rules that auto-approve matching future requests. These rules are scoped to the identity that triggered the original request. This is the only way permission keys are created — users never write them by hand.

The remembered approvals section shows:

```
Remembered Approvals for agent:henry

Permission Keys                                          Approved By    Approved At         Expires
────────────────────────────────────────────────────────────────────────────────────────────────────
github:create_pull_request:overfolder/*          alice          2026-04-01 10:30    2026-04-08
http:POST:api.example.com                                alice          2026-03-28 14:00    never
  + secret:api_key:api.example.com

                                                                              [Revoke] per rule
```

- Rules are grouped by the approval event — each "Allow & Remember" produces a set of permission keys that were approved together
- **Approved by** — which user approved
- **Approved at** — timestamp
- **Expires** — TTL from the approval, or "never" if no expiry was set
- **`[Revoke]`** — removes the remembered approval, requiring re-approval for matching requests

This view is also accessible from the User Profile (showing all remembered approvals across the user's subtree) and from the Org Dashboard for org-admins.

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

### Secrets

Manages secrets in the user's subtree (their own + their agents' secrets). Org admins see all org secrets (see Org Dashboard).

#### Secret list

```
Secret Name          Service       Owner          Versions    Last Used
────────────────────────────────────────────────────────────────────────────
github_token         GitHub        alice (you)    3           2m ago
stripe_api_key       Stripe        alice (you)    1           1h ago
openai_key           —             agent:henry    2           5m ago
```

- **Name** — the secret identifier used for injection
- **Service** — associated service, if any (blank for generic secrets)
- **Owner** — which identity in the subtree owns this secret
- **Versions** — count, clickable to expand version history
- **Last used** — last time any version was injected during action execution

#### Value reveal

Secret values are shown via a **click-to-reveal** pattern. The value is masked by default; clicking a reveal button shows it inline. This is the dashboard-only privilege — agents never receive values via API.

#### Version history (expand row or side panel)

```
Secret: github_token

Version   Created              Created By        Status
───────────────────────────────────────────────────────────
v3        2026-04-01 10:30     agent:henry       ● current
v2        2026-03-20 14:15     user:alice         ○ previous
v1        2026-03-10 09:00     user:alice         ○ previous

                                   [Reveal v2] [Restore v2]
                                   [Reveal v1] [Restore v1]
```

- **Created by** — which identity wrote this version (shows `on_behalf_of` provenance)
- **Reveal** — click-to-reveal for any version, enabling comparison before rollback
- **Restore** — creates a new version (v4) pointing to the old value. Does not delete anything.

#### Actions

- **`[+ New Secret]`** — name + value input + optional service association. Value shown in a password-type field during creation.
- **`[Update Value]`** — creates a new version. Password-type input.
- **`[Delete]`** — removes the secret entirely (all versions). Confirmation dialog warns which agents/services reference it.

#### Pending secret requests

When an agent requests a secret that doesn't exist (via the API), a banner appears at the top of the secrets section:

```
⚠ Pending secret requests:
  agent:henry requests "openai_api_key" — [Provide] [Deny]
```

`[Provide]` opens the value input (creates the secret). `[Deny]` dismisses the request. This is the inline version of the standalone secret request page (`/secrets/provide/req_...?token=jwt`).

### Remembered Approvals

A view of all "Allow & Remember" rules across the user's subtree (their own identity + all agents and sub-agents). This is the primary place to audit and manage what has been auto-approved.

```
Remembered Approvals

Identity                    Permission Keys                                          Approved At         Expires        Actions
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
agent:henry                 github:create_pull_request:overfolder/*          2026-04-01 10:30    2026-04-08     [Revoke]
agent:henry                 http:POST:api.example.com                                2026-03-28 14:00    never          [Revoke]
                              + secret:api_key:api.example.com
agent:builder/sa:coder      github:GET:*                                     2026-03-25 09:00    2026-04-25     [Revoke]
```

- **Filtering**: by identity (pick from agent tree), by service/host, by expiry status (active, expired, never-expiring)
- **Bulk revoke**: not supported — each rule is individually revocable to maintain granularity
- Expired rules are greyed out and shown in a separate "Expired" section, auto-hidden after 30 days

### Enrollment Tokens

Enrollment tokens are generated via the `[+ New Agent]` flow in the Dashboard agent tree (see **Inline identity management**). This section shows a read-only list of the user's active (unused) tokens with creation date and expiry. Revoke button per token.

### Settings

User-level preferences. Changes take effect immediately.

**Appearance:**
- **Theme**: Light / Dark / System (follows OS preference)

**Time display:**
- **Format**: Relative ("2m ago") / Absolute local / Absolute UTC
- **Timezone**: auto-detected from browser, overridable

**Approvals:**
- **Default approval TTL**: pre-filled expiry when clicking "Allow & Remember" (1h, 24h, 7d, 30d, never)

**Notifications:**
- **Notification preferences**: how to receive approval requests and secret requests — email, webhook URL, or dashboard-only

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

A section/tab within the Org Dashboard for managing user groups. Groups define the coarse-grained permission ceiling — which services and access levels are available to members.

- **Groups list**: name, member count, service grant count
- **Group detail**:
  - **Members**: list with add/remove
  - **Service grants**: permission key patterns that define the ceiling for this group. Managed by org-admins.

```
Group: Engineering

Service Grants
──────────────────────────────────────────────────────────────────
github:ANY:*             Full GitHub API access            Auto-approve reads: ✓
slack:*:*          Slack — any action                 Auto-approve reads: ✓
stripe:*:*         Stripe — any action                Auto-approve reads: ✗
google-calendar:ANY:*    Google Calendar API access         Auto-approve reads: ✓
```

Grants use the `{service}:{action}:{arg}` format. Org-admins pick from known services and choose the access tier (`*` for all actions, `ANY` for raw HTTP verbs, specific verbs, or specific actions). The UI presents this as dropdowns — not as raw key strings to type.

**Auto-approve reads** toggle per service grant: when enabled, agents' non-mutating requests automatically create permission keys without user approval. Disabled by default for sensitive services (financial, PII).

- **"Everyone"** group is always present, cannot be deleted, all users are implicit members

### Settings

A section within the Org Dashboard. Single scrollable view with four sections as cards.

#### Identity Providers

Configure how users authenticate to this org.

```
Identity Providers

Provider          Type        Status      Users     Actions
──────────────────────────────────────────────────────────────
Google            OIDC        ● Active    12        [Edit] [Disable]
Okta (SSO)        OIDC        ● Active    3         [Edit] [Disable]
Dev Login         Debug       ● Active    —         env (read-only)

                                          [+ Add Provider]
```

`[+ Add Provider]` flow:
- **Type**: Google / GitHub / OIDC (custom)
- **Google/GitHub**: client ID + client secret (endpoints are well-known)
- **Custom OIDC**: issuer URL (auto-discovers via `.well-known/openid-configuration`) + client ID + client secret
- **Dev Login**: toggle on/off. Warning badge when enabled in production.

Providers configured via environment variables are shown with an "env" badge and are read-only — they cannot be edited or disabled from the dashboard. Env vars take precedence over in-database settings.

Per-provider settings:
- **Auto-create users**: create user identity on first login (matched by email domain)
- **Allowed email domains**: restrict which domains can log in (e.g., `acme.com`)
- **Default group**: which group new users join on first login

SAML 2.0: future concern. "SAML" appears greyed out in the type dropdown with a "coming soon" tooltip.

#### Webhooks

Configure endpoints that receive events from Overslash. Platforms use these to surface approvals in their own UX.

```
Webhooks

Endpoint                                  Events              Status      Actions
──────────────────────────────────────────────────────────────────────────────────
https://platform.acme.com/overslash       All                 ● Active    [Edit] [Test] [Logs]
https://slack-bot.internal/hooks          approval.*          ● Active    [Edit] [Test] [Logs]

                                                              [+ Add Webhook]
```

`[+ Add Webhook]`:
- **URL**: the endpoint
- **Events**: multi-select — `approval.created`, `approval.resolved`, `action.executed`, `service.connected`, `identity.created`, etc. Or "All".
- **Secret**: auto-generated HMAC secret for signature verification. Shown once, copyable.
- **Headers**: optional custom headers (e.g., auth token for the receiving endpoint)

`[Test]` sends a test event, shows the response inline.

`[Logs]` opens the delivery log for this webhook:

```
Delivery Log

Event                    Sent At              Status    Response    Actions
──────────────────────────────────────────────────────────────────────────
approval.created         2m ago               ✓ 200     12ms        [View]
approval.resolved        5m ago               ✓ 200     8ms         [View]
action.executed          12m ago              ✗ 500     timeout     [View] [Retry]
```

- `[View]` shows request/response details for the delivery
- `[Retry]` re-sends the event
- Auto-retry: 3 attempts with exponential backoff (10s, 1m, 10m). After 3 failures → "Degraded" (orange). After 24h of continuous failures → "Failed" (red). Never auto-disabled — org-admin manually disables or fixes.

#### Features

Org-level feature flags.

```
Features

Allow user-created templates        [✓]    Users can create personal service templates
Allow user-created services         [✓]    Users can create personal service instances
Show API Explorer                   [✓]    API Explorer visible in nav for all users
Default approval TTL                [24h ▾] Pre-filled expiry for "Allow & Remember"
```

Each with a toggle or dropdown. Settings configured via environment variables are shown as read-only with an "env" badge.

#### Org Info

- **Org name** — editable
- **Org slug** — used in URLs on Overslash Cloud (`acme.overslash.dev`), editable with warning about URL changes. Not shown on self-hosted instances.
- **Created** — timestamp
- **Plan / billing** — placeholder for future

## Services view

A single nav item covering both **service templates** (API blueprints) and **services** (named instances with credentials). Two sub-views via tabs at the top: **My Services** (default) and **Template Catalog**.

### My Services

Shows the user's service instances — both org-provided and user-created:

```
My Services

Name                 Template            Owner     Status          Actions
──────────────────────────────────────────────────────────────────────────────
github               GitHub              Org       ● Connected     [Manage]
google-calendar      Google Calendar     Org       ● Connected     [Manage]
google-calendar      Google Calendar     You       ● Connected     [Manage]  ← shadows org
stripe               Stripe              Org       ○ Needs setup   [Connect]
my-scraper           My Scraper API      You       ● Connected     [Edit] [Manage]
```

When a user service shadows an org service with the same name, it's indicated in the list. The user's instance takes precedence for execution and permission key resolution. To use the org instance explicitly, agents can reference `org/google-calendar`.

- **Name** — the service instance name (used in permission keys and by agents)
- **Template** — which template this instance is based on
- **Owner** — `Org` (assigned via group) or `You` (user-created)
- **Status**: Connected, Needs setup (org service where user hasn't completed OAuth), Draft, Archived

**Filtering**: by owner (Org / You), by status

`[+ New Service]` button — opens the service creation flow (see below). Only visible if the org allows user-created services.

### Template Catalog

Browse available templates to create new service instances from:

```
Template Catalog

Template            Source          Actions   Category
──────────────────────────────────────────────────────────────
GitHub              Overslash       12        Dev Tools         [View] [Create Service]
Google Calendar     Overslash       8         Productivity      [View] [Create Service]
Stripe              Overslash       15        Payments          [View] [Create Service]
Internal CRM        Org             3         Custom            [View] [Create Service]
My Scraper API      You             2         Custom            [View] [Edit] [Share]
```

- **Source**: Overslash (global, read-only), Org (org-admin managed), You (user-created)
- **`[View]`** — opens the Template Editor in read-only mode
- **`[Create Service]`** — starts the service creation flow with this template pre-selected
- **`[Edit]`** — opens the Template Editor (only for user/org templates)
- **`[Share]`** — proposes sharing a user template to org level

`[+ New Template]` button — opens the template creation flow. Only visible if the org allows user-created templates.

### Create service flow

1. **Pick a template** — dropdown or pre-selected from catalog
2. **Name the instance** — defaults to the template key (e.g., `google-calendar`). The user can rename to create multiple instances (e.g., `google-calendar`, `personal-calendar`). This name is used in permission keys and by agents.
3. **Connect credentials** — depends on the template's auth config:
   - *OAuth*: shows requested scopes → Connect → OAuth redirect → callback → done
   - *API key*: form to paste the key → stored as a versioned secret → done
   - *Both available*: user picks which auth method
   - *Org service with shared credential*: one-click, no auth needed
   - *Org service with per-user OAuth*: OAuth redirect using the org's app
4. **Status**: starts as Active (or Draft if the user wants to test first)

### Manage service

`[Manage]` on a service instance shows:

- **Connection status** — connected, expired (needs re-auth), error
- **Credential type** — OAuth (which account), API key, shared
- **Template** — link to view the template definition
- **Usage** — which agents used this service, last execution, execution count
- **Actions**: `[Reconnect]` `[Revoke]` `[Archive]`

### Create template

`[+ New Template]` — two creation paths:

**Manual creation:**
1. **Template identity**: key, display name, base URL, description
2. **Auth config**: None / API Key (injection config) / OAuth (provider, scopes, token injection) / Both
3. **Actions**: optional — add defined actions now or later (see Template Editor)
4. Save as Draft or Active

**OpenAPI import:**
1. Upload an OpenAPI 3.x spec file or paste a URL
2. Overslash parses the spec and generates a preview: template + actions + parameter schemas
3. User reviews — pick which endpoints become actions, edit names/descriptions, skip the rest
4. Save as Draft or Active

Both paths open the **Template Editor** for final review.

### Template Editor

The editing view for user-defined and org-defined templates. Two tabs:

#### Visual tab

A form-based editor for the template definition:

**Template section:**
- Key, display name, description, base URL
- Auth config: method picker + relevant fields (OAuth URLs/scopes, API key injection config)

**Actions section:**
- List of defined actions with name, method badge, path, mutating badge (read/write)
- `[+ New Action]` button opens an inline form:
  - Name, HTTP method (dropdown), path template (with `{param}` placeholder syntax)
  - Description template — supports `{param}` interpolation and `[conditional segments]`. Typing `{` triggers autocomplete from the action's defined params. Placeholders render as highlighted chips. Invalid placeholders (referencing non-existent params) show as validation warnings. Example: `Create pull request '{title}' on {repo}`
  - Mutating toggle — optional, defaults to inferred from HTTP method (GET/HEAD/OPTIONS → read, else → write)
  - Scope param: which parameter drives the permission key arg (dropdown from defined params)
  - Parameters: add/remove rows — name, type (string / number / boolean / enum), required toggle, description, enum values if applicable
- Click any action to expand and edit inline
- Drag to reorder, delete with confirmation

#### YAML tab

A code editor showing the full template definition as YAML:

```
┌─ Template Editor: My Scraper API ─────────────────────────────┐
│  [Visual]  [YAML]                                             │
│                                                               │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ key: my-scraper-api                                      │ │
│  │ display_name: My Scraper API                             │ │
│  │ description: "Personal web scraping service"             │ │
│  │ hosts: [scraper.myserver.com]                            │ │
│  │ auth:                                                    │ │
│  │   - type: api_key                                        │ │
│  │     injection: { as: header, header_name: X-API-Key }    │ │
│  │ actions:                                                 │ │
│  │   scrape_page:                                           │ │
│  │     method: POST                                         │ │
│  │     path: /scrape                                        │ │
│  │     description: "Scrape a web page"                     │ │
│  │     # mutating: true (inferred from POST)                │ │
│  │     params:                                              │ │
│  │       url: { type: string, required: true }              │ │
│  │       format: { type: string, enum: [html, text, md] }   │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                               │
│  ┌─ Validation ─────────────────────────────────────────────┐ │
│  │ ✓ Valid                                                  │ │
│  │ ⚠ Action "scrape_page" has no scope_param — permission   │ │
│  │   keys will use wildcard arg (*)                         │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                               │
│                                         [Test] [Save] [Delete] │
└───────────────────────────────────────────────────────────────┘
```

- YAML is directly editable — changes sync to the Visual tab on switch (and vice versa)
- **Validation panel** below the editor shows errors and warnings from the backend validate endpoint (`POST /v1/templates/validate`). Validation runs on every edit (debounced). Errors block saving, warnings are informational.
- Future: ship the Rust YAML parser as WASM for instant client-side validation without a round-trip. V1 uses the backend validate endpoint.

#### View-only mode

For global (Overslash-shipped) templates, the editor opens in read-only mode. Both Visual and YAML tabs are viewable but not editable. This lets users inspect the template — what actions are available, what parameters they take, how auth is configured.

### Share template

`[Share to Org]` on a user-created template: proposes sharing to org level. The template definition is shared (blueprint only, no credentials). Org-admin reviews and approves (making it available for org service creation) or denies.

### Org-admin: Services management

Org-admins see additional capabilities:

**Org services:**
- Create org-level service instances from any template, assign to groups
- For OAuth templates: configure the org's OAuth app credentials (client ID/secret). Users in assigned groups complete their own OAuth flow using the org's app.
- For API key templates: optionally provide a shared credential, or let each user provide their own.

**Org templates:**
- Create/edit org-level templates (same Template Editor)
- Hide/show global templates for the org

**Pending share proposals:**
- A badge/section showing user templates proposed for org sharing
- Org-admin reviews the definition (opens in read-only Template Editor) → `[Approve]` or `[Deny]`

**User services visibility:**
- Read-only list of all user-created services across the org: name, template, base URL, owner. For compliance/audit — org-admins need to know what external APIs their users are connecting to. No edit access to user services.

**Usage stats:**
- Per service: execution count, which users/agents use it, last activity

## Audit Log view

A dedicated nav item. Filterable, searchable event stream — newest first, paginated.

### Infinite Scroll

The audit log uses **infinite scroll** over a paginated API (cursor-based). No page numbers or "Load more" button — new events load automatically as the user scrolls near the bottom.

**Scroll trigger**: when the viewport is within 200px of the last loaded row, the next page is fetched.

**States**:

- **Loading more**: 3 skeleton rows appear below the last loaded row, with a centered "Loading more..." label and small spinner. Existing data stays visible and interactive above.
- **End of list**: a centered "No more events" label in neutral-400, with subtle top padding. Marks the end — no more skeleton loading.
- **Load error**: replaces skeleton rows with "Failed to load more events" text and a `[Retry]` button. The user can retry or scroll up to existing data. Does not lose loaded events.
- **Initial load**: full skeleton screen (4-5 skeleton rows matching the table layout) before any data is available.

**Filter changes**: when filters are updated, the list resets — clears all loaded data, shows the initial skeleton, and fetches page 1 with the new filters. The scroll position resets to top.

**Auto-refresh interaction**: when auto-refresh fires, new events are **prepended** to the top of the list. If the user has scrolled down, a floating pill appears at the top: "↑ 3 new events" — clicking it scrolls to top. If the user is already at the top, new rows animate in with a brief highlight.

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

Uses the **Refresh Control** (see Design System). The refresh icon button reloads the current page of results. The adjoined dropdown enables auto-refresh at a chosen interval. When auto-refresh is active, a progress bar below the button visualizes the cycle countdown.

### Export

A **CSV export** button that downloads the currently filtered result set.

## API Explorer view

An interactive tool for testing and debugging service connections through Overslash. Simpler than Postman — the goal is verifying that auth works and seeing what comes back, not building collections or scripting.

Can be **hidden from users via an org setting** (e.g., orgs that don't want users making ad-hoc API calls). When hidden, the nav item is not shown.

### Unified flow

The explorer uses a single flow — no separate tabs or modes. The level of abstraction is determined by what the user selects:

1. **Pick a service** — dropdown showing the user's service instances (connected ones prioritized). If the user's group grants `http`, "Raw HTTP" appears as an option at the bottom.

2. **Pick an action** — adapts to the selected service and the user's group grants:
   - **Defined actions** listed first with human-readable descriptions and mutating badges (e.g., `create_pull_request — Create a pull request [write]`)
   - **"Custom Request"** appears at the bottom if the user's group grants HTTP verb access for this service (e.g., `github:ANY:*` or `github:POST:*`). Opens method + path + body inputs, with auth auto-injected from the connection.
   - For **"Raw HTTP"** service: always shows method + full URL + headers + body + secret selector (pick from user's secrets, specify injection method per secret)

3. **Fill parameters** — auto-generated form for defined actions (text, number, enum dropdowns from the registry schema). Method + path + JSON body editor for custom requests. Full URL + secret injection config for raw HTTP.

4. **Execute** → response panel

The explorer naturally adapts to what the user is allowed to do. A user with `github:*:*` sees all GitHub actions. A user with `github:ANY:*` also sees "Custom Request". A user without `http` in any group never sees the raw HTTP option.

### Response panel

- **Status code** (color-coded: 2xx green, 4xx yellow, 5xx red)
- **Response time**
- **Headers** (collapsible)
- **Body** (syntax-highlighted JSON, with raw/pretty toggle)
- **Permission keys derived**: shows which `{service}:{action}:{arg}` keys were checked for this request

### Identity

The API Explorer always executes as the **logged-in user's own identity**. There is no "execute as" selector — no impersonation of agents or sub-agents. All actions taken through the explorer are logged in the audit trail under the user's identity.

## Standalone Pages

Standalone pages have a minimal layout: Overslash logo at top, no sidebar, no nav. They handle expired and already-resolved states gracefully.

### Secret Request Page (`/secrets/provide/req_...?token=jwt`)

No login required — the JWT in the URL authenticates the request. Safe because providing a secret doesn't grant the agent any authority (the agent still needs a separate approval to use it).

```
┌─────────────────────────────────────────────────────┐
│  Overs/ash                                          │
│                                                     │
│  Secret Request                                     │
│                                                     │
│  agent:henry needs a secret:                        │
│                                                     │
│  Name: openai_api_key                               │
│  Description: "OpenAI API key with GPT-4 access"    │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │ ••••••••••••••••••••••                        │  │
│  │                                    [👁 Show]  │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  [Provide]  [Deny]                                  │
│                                                     │
│  Requested 3m ago · Expires in 12m                  │
└─────────────────────────────────────────────────────┘
```

- **Password-type input** — value hidden by default, toggle to reveal for verification before submitting
- **Provide** — encrypts and stores the secret. Shows confirmation: "Secret 'openai_api_key' stored. The agent has been notified."
- **Deny** — dismisses the request. Shows: "Request denied. The agent has been notified."
- **Expired** — "This request has expired." No form shown.
- **Already provided** — "This secret has already been provided."

Secret requests also appear in the dashboard: as notification bell items, as badges on the agent tree, and as inline `[Provide]` / `[Deny]` actions in the agent detail panel. The standalone page is for resolving from outside the dashboard (e.g., a link in Telegram or email).

### Approval Deep-Link Page (`/approvals/apr_...`)

Login required. If not logged in → redirect to login → redirect back. If logged in but without authority to resolve → show approval details read-only with: "You don't have permission to resolve this approval."

```
┌─────────────────────────────────────────────────────┐
│  Overs/ash                              alice ▾     │
│                                                     │
│  Approval Request                                   │
│                                                     │
│  agent:henry wants to:                              │
│  Create pull request "Fix bug" on overfolder/app    │
│  via: user/github                                   │
│                                                     │
│  POST /repos/overfolder/app/pulls                   │
│  Body: {"title":"Fix bug","head":"fix","base":"main"}│
│                                                     │
│  ┌─ Allow & Remember ────────────────────────────┐  │
│  │  ○ Create pull request on overfolder/app      │  │
│  │  ○ Create pull request on any repo            │  │
│  │  ○ Any GitHub action                          │  │
│  │                                               │  │
│  │  Expires: [24h ▾]                             │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  [Allow Once]  [Allow & Remember]  [Deny]           │
│                                                     │
│  Requested 2m ago · Expires in 14m                  │
│                                                     │
│  [← Go to Dashboard]                               │
└─────────────────────────────────────────────────────┘
```

- Shows human-readable description + raw request details + resolved service instance (qualified: `user/github` or `org/github`)
- Full specificity picker for "Allow & Remember" — reads `suggested_tiers` and `description` from the approval API (same as dashboard)
- After resolution → confirmation + link to dashboard
- **Already resolved** — "This approval was allowed by alice 3m ago." (or denied)
- `[← Go to Dashboard]` for navigation to the full UI
- Platforms can link users here as a zero-integration-effort path to resolve approvals

### Agent Enrollment Consent Page (`/enroll/consent/...`)

Login required. An agent generated a consent URL and sent it to a user. Any authenticated user in the org with agent-creation permissions can approve — not scoped to a specific user.

```
┌─────────────────────────────────────────────────────┐
│  Overs/ash                              alice ▾     │
│                                                     │
│  Agent Enrollment Request                           │
│                                                     │
│  An agent is requesting to join your org:           │
│                                                     │
│  Proposed name: [research-bot        ]  (editable)  │
│  Requested by: 203.0.113.42 · 5m ago               │
│                                                     │
│  Parent placement:                                  │
│  ┌─ Select parent ─────────────────────┐            │
│  │  ● alice (you)                      │            │
│  │  ○ agent-henry                      │            │
│  │    ○ sa-researcher                  │            │
│  │  ○ agent-builder                    │            │
│  └─────────────────────────────────────┘            │
│                                                     │
│  ☐ inherit_permissions                              │
│                                                     │
│  [Approve & Enroll]  [Deny]                         │
│                                                     │
│  This token expires in 10m                          │
└─────────────────────────────────────────────────────┘
```

- **Proposed name** — pre-filled by the agent, fully editable
- **Requested by** — agent metadata (IP, timestamp). The agent has no identity yet.
- **Parent placement** — mini tree picker showing only the approving user's subtree. Defaults to directly under the user.
- **`inherit_permissions`** — checkbox, off by default
- **No permission keys** — keys build up organically through approvals after enrollment
- **Approve & Enroll** — creates the identity, agent picks up API key via polling/webhook. Shows: "Agent 'research-bot' enrolled under alice. The agent has been notified."
- **Deny** — rejects enrollment, token invalidated
- **Token expired** — "This enrollment request has expired."
- **Already enrolled** — "This agent has already been enrolled."

