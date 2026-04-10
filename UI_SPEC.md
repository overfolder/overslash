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

UNauth users go here, and on auth, they go back to the page they were trying to access previously, or /agents if no such page or a loop would form

## Global UX Conventions

**Appearance**: light and dark modes, toggled in user settings. No custom theming.

**Routing**: SPA with History mode URLs. Most views have deep-linkable URLs — selected agent, selected service, audit log filters, etc. Sharing a URL lands the recipient on the same view (after login if needed).

**Copy pattern**: click-to-copy button (clipboard icon) next to copyable values (API keys, permission keys, enrollment tokens, URLs). Toast confirmation: "Copied to clipboard."

**Time display**: all timestamps shown as relative by default ("2m ago", "1h ago"), with full UTC ISO-8601 on hover. User settings allow preference: relative, absolute (local timezone), or absolute (UTC).

**Toasts**: success/error feedback appears as a toast notification (bottom-right, auto-dismiss after 5s for success, sticky for errors). Used after: approve/deny, provide secret, revoke key, create agent, archive service, etc.

**Empty states**: views with no data show greyed-out text: "No agents found", "No services found", etc. For agents, service templates, and services, the empty state includes a button to create the first one (e.g., `[+ Create your first agent]`).

**Confirmation dialogs**: destructive actions get a modal confirmation. All destructive confirmations MUST use the application's styled modal component — never `window.confirm()` or browser-native dialogs. The modal follows a consistent pattern: title ("Delete agent?"), consequence description, two buttons — `[Cancel]` and the destructive action in red.

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

Primary and semantic colors (indigo, green, yellow, red, orange) keep their mid-range values — they already have sufficient contrast on dark backgrounds. Badge/pill backgrounds must use **18-20% opacity** in dark mode (not the 12% used in light mode) to ensure sufficient visibility. This applies to all status badges, access level pills (`read`, `write`, `admin`), source pills (`inherited`, `remembered`), and origin badges. Hover accent states (e.g., Primary/100 on interactive elements) must also be adjusted for dark backgrounds. All badge text in dark mode must meet WCAG AA contrast ratio (4.5:1 for small text, 3:1 for large text).

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

### Search Bar

A unified search component used across Services, Template Catalog, Audit Log, and Org Users/Groups views. Combines free-text search with structured filters.

**Behavior:**
- **Free text**: typing plain text matches against any visible field (name, template, owner, identity, etc.)
- **Structured expressions**: `key operator value` syntax. Operators: `=` (exact), `~` (contains), `!=` (not equal). Multiple expressions are joined by AND.
- **Parsed expressions** render as **removable pill chips** inside the input field. Each chip shows `key = value` with an "✕" to remove. Free text remains as editable text after the chips.

```
/-------------------------------------------------------------------------------------\
| [owner = Org][name ~ "fish"] blah blah                                              |
\-------------------------------------------------------------------------------------/
```

**Available keys** vary by context:
- **Services**: `owner`, `name`, `template`, `status`
- **Template Catalog**: `source`, `name`, `category`
- **Audit Log**: `identity`, `event`, `service`, `result`, `time`
- **Org Users**: `name`, `email`, `group`, `role`, `status`

**Autocomplete**: After typing 3+ characters that match a known key prefix, a dropdown appears below the input suggesting matching keys (e.g., typing "own" suggests `owner =`). Debounced at 200ms to avoid interrupting normal typing. Selecting a key suggestion inserts the key + operator and positions the cursor for value entry. **Values are also autocompleted** when possible — e.g., after `owner =`, the dropdown shows known values ("Org", "You", specific user names). Selecting a value **creates the pill** immediately. Recent searches appear below suggestions.

**Visual**: White background, neutral-200 border, 8px corner radius. Pill chips have primary-50 background, primary text, small "✕".

### Split Button

A button with two halves joined seamlessly — left side is the default action, right side is a dropdown to choose an alternative. Used for **Allow & Remember** (approval resolution) and **Refresh Control**.

**Structure**: left half has rounded left corners, right half (▾) has rounded right corners. No gap between them — they share a continuous border.

**Approval variant**: Left = "Allow & Remember" (applies most specific tier). Right dropdown = specificity picker showing all tiers with radio selection + expiry dropdown.

### Notifications Dropdown

Opens when clicking the notification bell in the top bar. Not a page — a floating dropdown panel anchored below the bell.

**Content**: Lists pending approvals and secret requests, **grouped by agent**. Each item shows the agent name, request description, and timestamp. Clicking an item navigates to the agent detail panel (or standalone approval/secret page).

**Rules**:
- Requests younger than 1 minute are **not shown** — only notify after 1 minute if still unresolved. This prevents flash notifications for requests that agents resolve quickly on their own.
- Items **auto-dismiss** when the underlying approval or secret request is resolved.
- Badge count on the bell reflects only items older than 1 minute and still unresolved.

**Layout**: Max height ~400px with scroll. "No pending notifications" empty state. Each item has the agent's status dot, agent name, description, and relative timestamp.

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

- **Agents**: default view is the agent tree (full width). Tapping an agent pushes the detail panel as a full-screen view with a `[← Back]` header.
- **Services**: service list → service detail/editor is a full-screen push. API Explorer is full-screen.
- **Secrets**: secret list → secret detail is a full-screen push. Version reveal modal works as-is.
- **Audit log**: event list → event detail is a full-screen push.
- **Template Editor**: only the Visual tab is practical on mobile. YAML tab shows a "best on desktop" hint.
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

Nav items: **Agents**, **Services**, **Secrets**, **Audit Log**. API Explorer is a sub-view within Services, not a top-level nav item. Template Editor is accessed from Services, not a nav item.

Under an "ADMIN" label (org-admins only): **Users**, **Groups**.

At the bottom of the sidebar: **Settings** (gear icon) — opens user settings. For org-admins, a second settings link or sub-menu provides org settings.

**Profile is NOT a nav item.** The logged-in user's avatar and name appear at the bottom of the sidebar (desktop) or top-right (mobile). Clicking opens the User Profile view.

**Notifications bell** sits in the top bar (right side). Badge count shows unresolved items older than 1 minute. Clicking opens the **Notifications Dropdown** (see Design System) — pending approvals and secret requests grouped by agent. Items auto-dismiss when resolved. There is no separate notifications page. Notifications also appear inline as badges on each agent node in the Agents view tree.

**Live indicator**: a small dot next to the notification bell shows the SSE/WebSocket connection status — green when connected, yellow when reconnecting, hidden when using polling fallback.

## Agents view

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
|   |- Agent 3a [Last active: ..., Created: ....]
|   \- Agent 3b
\- [-] SwarmAgent (12)
    |- Agent sw-1
    |- Agent sw-10
    \- [see more]
```

- Status indicators by state: active, idle, errored (color-coded)
- Pending approval count + pending secret request count shown as badges — highest-signal elements, something is blocked waiting for the user
- Agents with many sub-agents collapse, showing the count. Expand to see children, with `[see more]` pagination for large groups. (TBD: collapse individual agents vs entire subtrees)
- Some IDs are agent-created, others human-created — allow filtering by origin

### Detail panel (right panel)

When an agent node is selected, the detail panel shows:

- **Agent name** — click to edit inline
- **Origin** — badge: "user-created" or "self-enrolled"
- **Status**: active / idle / errored (badge)
- **Parent** — displayed with `[Move]` action to reparent (opens tree picker)
- **`inherit_permissions`** — toggle, configurable at any time

**User (root) node**: when the root User node is selected, the detail panel shows user info in **read-only** mode. Name is not editable inline. The `[Move]`, `[Delete]`, and origin badge are not shown. The `inherit_permissions` toggle is not applicable. The only action available is `[+ Add Agent]` to create a child agent. This is the logged-in user — it cannot be deleted, renamed, or reparented.

#### Recent Activity

Shows the last ~5 actions (service + action name, timestamp, success/fail result). A "View all →" link opens the Audit Log with the identity filter pre-set to this agent.

#### Pending Approvals

List of pending approval requests with inline resolution (see Approval Resolution below). **Maximum 3 pending approvals per agent** — when a new approval request arrives and 3 already exist, the oldest pending request is automatically dropped (denied with reason "superseded"). This prevents stale approvals from accumulating.

#### Pending Secret Requests

List of secrets the agent is waiting for — each with `[Provide]` (opens value input inline) and `[Deny]`. These also appear as notifications in the bell dropdown. See also the standalone secret request page.

#### Permission Rules

Permission rules are **remembered approvals** — permission keys created when a user clicks "Allow & Remember" on an approval. They build up organically as agents are used and are never written by hand. Each rule auto-approves matching future requests.

```
Permission Rules for agent:henry

Key                                       Source       Approved By   Expires      Actions
────────────────────────────────────────────────────────────────────────────────────────────
github:create_pull_request:overfolder/*   remembered   alice         2026-04-08   [Revoke]
github:GET:*                              remembered   alice         never        [Revoke]
slack:send_message:#engineering           remembered   alice         2026-04-15   [Revoke]
stripe:*:*                                inherited    —             —            —
```

- **Key** — the permission key string (`{service}:{action}:{arg}`)
- **Source** — `remembered` (from "Allow & Remember") or `inherited` (from parent via `inherit_permissions`)
- **Approved By** — which user approved (blank for inherited)
- **Expires** — TTL, "never", or "—" for inherited
- **`[Revoke]`** — removes the rule, requiring re-approval. Not available for inherited rules.
- Inherited rules link to the parent identity. Remembered rules link to the approval event.

ALL permission keys for a request must be covered for auto-approval. A single missing key triggers the approval flow.

#### Actions

- **`[+ Add Agent]`** — opens the same enrollment flow as `[+ New Agent]` but with parent pre-set to this agent
- **`[Delete Agent]`** — solid Danger button. Confirmation dialog warns about child identities and their API keys being deleted.

### Approval resolution

When a user resolves an approval (from the detail panel, notification dropdown, or standalone approval page), two actions are presented:

- **Allow & Remember** — a **split button** (see Design System). Left side applies the most specific tier (safest default). Right dropdown (▾) opens the specificity picker to choose a broader scope.
- **Deny**

#### Specificity picker (split button dropdown)

The dropdown reads `suggested_tiers` from the approval API. Each tier includes a `description` (English label generated by Overslash). The permission key string is shown as secondary text.

```
┌─────────────────────────────────────────────────┐
│  ○ Create pull request on overfolder/backend    │
│    github:create_pull_request:overfolder/backend│
│                                                 │
│  ○ Create pull request on any repo              │
│    github:create_pull_request:*                 │
│                                                 │
│  ○ Any GitHub action                            │
│    github:*:*                                   │
│                                                 │
│  Expires: [24h ▾]                               │
└─────────────────────────────────────────────────┘
```

The most specific tier is pre-selected. Selecting a tier and clicking "Allow & Remember" (or just clicking the left side of the split button) stores permission keys at that scope.

For `http` service approvals, tiers compose paired keys:

```
  ○ POST to api.example.com with api_key
    http:POST:api.example.com + secret:api_key:api.example.com

  ○ Any request to api.example.com with api_key
    http:ANY:api.example.com + secret:api_key:api.example.com
```

Overslash also hosts a deep-link approval page at `/approvals/apr_...` (requires login) with the full specificity picker. The standalone page always shows the expanded picker (not the split button pattern), since users arriving via link need full context.

Agent platforms that need i18n can build their own labels from the structured key parts (`service`, `action`, `arg`) in `derived_keys`.

### Live updates

The dashboard supports **streaming updates** from the backend (SSE or WebSocket) to reflect agent activity in real time — status changes, new sub-agents, new approvals, completed actions all update the tree and detail panel live.

A **live indicator dot** next to the notification bell in the top bar shows the connection status (see Design System — Navigation). When streaming is off or unavailable, the dashboard falls back to polling with the Refresh Control.

### Inline identity management

The agent tree supports creating, editing, and deleting agents directly.

#### Tree actions

- **`[+ New Agent]` button** at the top of the tree panel — starts the user-initiated enrollment flow for a root-level agent
- **Hover actions** on each agent node — two icons appear on the right side of the row on hover:
  - **`+` icon** — add an agent under this agent (opens enrollment flow with parent pre-set)
  - **`⋮` kebab menu** — options: Rename, Move (reparent), Delete

#### User-initiated enrollment

`[+ New Agent]` opens an inline form or modal:

- **Agent name** (required)
- **Parent** — defaults to the user, dropdown/tree-picker to choose another position in the user's subtree
- **TTL** — optional, for ephemeral agents

The creation flow does NOT include a Kind/type selector. All created identities are agents — parentage determines hierarchy position.

`inherit_permissions` is not offered during enrollment — the user configures this after enrollment in the agent detail panel if desired.

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
- **Placement tree** — reuses the agent tree pattern. Shows the user and their first-level agents by default (collapsed). Clicking an agent **selects it as parent AND expands its sub-agents**, allowing deeper placement. The tree is collapsible and only shows the user's subtree.

```
┌─ Select parent ─────────────┐
│  ● alice (you)              │
│  ○ agent-henry              │ ← click to select + expand
│  ○ agent-builder            │
└─────────────────────────────┘
```

After clicking agent-henry:

```
┌─ Select parent ─────────────┐
│  ○ alice (you)              │
│  ● agent-henry   ← selected│
│    ○ sa-researcher          │
│    ○ sa-emailer             │
│  ○ agent-builder            │
└─────────────────────────────┘
```

- **No `inherit_permissions` option** — always false for agent-initiated enrollment per spec

Actions: `[Approve & Enroll]` and `[Deny]`.

After approval, shows a success message. The agent picks up its API key via polling or webhook.


## User Profile view

Accessible by clicking the user's avatar/name at the bottom of the sidebar. Shows the authenticated user's identity and preferences. Not a nav item — it's a profile overlay or view.

### Identity

- **Name**, **email**, **avatar** (from IDP)
- **Identity path**: displayed as `acme / user / alice` — each segment is a clickable link (org → org dashboard, user → this profile). *(Design note: segments mirror the SPIFFE ID path structure.)*
- **Org**: which org the user belongs to, and their role (admin, member, read-only)
- **Login method**: which IDP was used (Google, GitHub, corporate SSO, dev login)
- **Created / Last login** timestamps

Users authenticate to Overslash via OAuth/OIDC only — there are no user API keys for dashboard access.

### Enrollment Tokens

Enrollment tokens are generated via the `[+ New Agent]` flow in the Agents view tree (see **Inline identity management**). This section shows a read-only list of the user's active (unused) tokens with creation date and expiry. Revoke button per token.

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

Accessible to org-admin users. **Users** and **Groups** appear as separate nav links under the "ADMIN" section in the sidebar. Settings is accessible from the org's gear icon at the bottom of the sidebar.

### User list

Uses the **Search Bar** (see Design System) with keys: `name`, `email`, `group`, `role`, `status`.

A table/list of all users in the org, showing:

- **Name**
- **Email**
- **Groups/roles** (admin, member, read-only, custom groups)
- **Status** (active, invited, disabled)
- **Agent count**
- **Last active**

Search and filtering via the Search Bar above the table.

### User detail (click-through)

Clicking a user navigates to their agents view — this reuses the **Agents view** component, rendered in the context of the selected user. The org-admin sees exactly what that user would see (agent tree, detail panel, live updates), with read access to their agents, approvals, and activity.

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

**Dev User access**: Dev Users (logged in via Dev Login) have org-admin privileges in development mode. The Org Settings view must be accessible to Dev Users.

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

## Secrets view

A dedicated nav item. Manages secrets owned by the user and their agents. Users see only secrets in their own subtree. Org admins see all secrets across the org.

Pending secret requests do NOT appear here — they are surfaced in the agent detail panel and as notifications.

### Secret list

Uses the **Search Bar** (see Design System). Filterable by name, owner.

```
Secret Name          Owner          Versions    Last Used
────────────────────────────────────────────────────────────────
github_token         alice (you)    3           2m ago
stripe_api_key       alice (you)    1           1h ago
openai_key           agent:henry    2           5m ago
```

- **Name** — the secret identifier used for injection
- **Owner** — which identity in the subtree owns this secret
- **Versions** — count
- **Last used** — last time any version was injected during action execution

`[+ New Secret]` button — name + value input. Value in a password-type field during creation.

### Secret detail

Clicking a secret row opens the detail view:

- **Secret name**
- **Owner** — which identity owns this secret
- **Last used** timestamp
- **Used by** — list of services (and agents, if direct) that reference this secret. Each row links to the service detail. Empty state: "No services use this secret yet."
- **`[Update Value]`** — creates a new version. Password-type input.
- **`[Delete]`** — removes the secret entirely (all versions). Confirmation dialog warns which agents/services reference it.

#### Version list

```
Version   Created              Created By        Status
───────────────────────────────────────────────────────────
v3        2026-04-01 10:30     agent:henry       ● current
v2        2026-03-20 14:15     user:alice         ○ previous
v1        2026-03-10 09:00     user:alice         ○ previous
```

- **Created by** — which identity wrote this version (shows `on_behalf_of` provenance)
- **Restore** — creates a new version (v4) pointing to the old value. Does not delete anything.

#### Secret version modal

Clicking a version row (or `[Reveal]` button) opens a modal showing:

- Version number, created timestamp, created by
- **Secret value** — masked by default. A `[Reveal]` button shows the value inline (click-to-reveal pattern). This is the **only way** to view secret values in the dashboard — agents never receive values via API.
- `[Copy]` button to copy the revealed value
- `[Restore this version]` if not the current version

This modal is the dashboard-only privilege for viewing secret values.

## Services view

A single nav item covering both **service templates** (API blueprints) and **services** (named instances with credentials). Two sub-views via tabs at the top: **My Services** (default) and **Template Catalog**.

### My Services

Uses the **Search Bar** (see Design System) with keys: `name`, `template`, `owner`, `status`.

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

Uses the **Search Bar** (see Design System) with keys: `source`, `name`, `category`.

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
1. **Input**: upload an OpenAPI 3.x spec file (JSON/YAML) or paste a URL. A loading spinner shows while parsing.
2. **Parse preview**: Overslash parses the spec and shows a structured preview — template identity (key, name, base URL inferred from `servers`), auth config (inferred from `securitySchemes`), and a list of all endpoints grouped by tag.
3. **Endpoint picker**: each endpoint shows as a row with checkbox, HTTP method badge, path, and inferred description. User picks which endpoints become actions, can edit generated names/descriptions, and skip the rest. "Select all" / "Deselect all" toggles at the top.
4. **Parameter mapping**: for selected endpoints, parameter schemas are extracted from path params, query params, and request body. User can edit types, mark required/optional, and set `scope_param`.
5. **Review**: opens the **Template Editor** (Visual tab) with all generated content pre-filled. User makes final edits before saving as Draft or Active.

### Template Editor

The editing view for user-defined and org-defined templates. Two tabs.

**Header**: shows breadcrumb (`← Services / Template Editor:`) followed by the template display name and an optional **status pill** next to it indicating the template's lifecycle state:
- **`Draft`** (warning yellow) — work in progress, not yet published. Templates start in Draft when imported from OpenAPI or created from scratch. Drafts are only visible to the author and cannot be used to create services.
- **`Active`** (success green) — published and usable. (No pill is shown for Active to keep the header uncluttered, OR an Active pill is shown for explicitness — implementation choice.)
- **`Archived`** (muted gray) — retired template, hidden from catalogs but still referenced by historical services.

The pill is omitted if the template has no special status. Changing status happens via the kebab menu in the header (`Publish`, `Unpublish`, `Archive`).

Two tabs:

#### Visual tab

A form-based editor for the template definition:

**Template section:**
- Key, display name, description, base URL
- **Auth config**: method picker (`API Key` / `OAuth 2.0` / `Bearer Token` / `Basic Auth` / `None`) + relevant fields per method:
  - **API Key**: header/query name, injection location (`header` / `query`), and a **Secret picker** for the key value (see below).
  - **OAuth 2.0**: authorize URL, token URL, scopes (multi-input), and **Secret pickers** for `client_id` and `client_secret`.
  - **Bearer Token**: **Secret picker** for the token.
  - **Basic Auth**: username field + **Secret picker** for the password.
  
  **Secret picker** — a searchable dropdown listing the secrets the current user owns (filtered to user-level secrets, plus org-level secrets if the user is an org admin). The dropdown shows: secret name (mono), owner identity, last-used timestamp. Typing in the dropdown filters the list by name (debounced 200ms). A `[+ New Secret]` action at the bottom of the dropdown opens the New Secret modal inline; on save, the newly-created secret is auto-selected. Selected secrets render as a chip with the secret name and a `✕` to clear. The picker stores a reference to the secret (not its value) — the value is injected at execution time, never embedded in the template.

**Actions section:**
- List of defined actions with name, method badge, path, mutating badge (read/write)
- `[+ New Action]` button opens the **New Action modal** (see below)
- Click any action to open the same modal in **edit mode** prefilled with that action's values
- Drag to reorder, delete with confirmation

##### New / Edit Action modal

A centered modal (~640px wide, scroll if content exceeds viewport) that captures all fields for an action in one place. Same component used for both create and edit (the title and primary button label switch between *New Action* / *Edit Action* and *Create* / *Save*).

**Modal layout:**

1. **Header** — title (`New Action` or `Edit Action: <name>`), close `✕` button.
2. **Identity row** — two fields side by side:
   - **Name** (`text`, required) — snake_case identifier used in permission keys and SDK calls. Validation: lowercase, digits, underscores, starts with letter. Inline error if invalid.
   - **HTTP Method** (`dropdown`, required) — `GET / POST / PUT / PATCH / DELETE / HEAD / OPTIONS`. Each option shows the method's badge color.
3. **Path template** (`text`, required) — full-width, monospace input. Supports `{param}` placeholder syntax. Typing `{` triggers autocomplete from currently-defined params. Inline placeholder chips render in primary color. Invalid placeholders (param not defined) underlined with a warning. Example: `/repos/{owner}/{repo}/issues`.
4. **Description template** (`textarea`, required) — full-width, 2 rows tall. Supports `{param}` interpolation and `[conditional segments]`. Typing `{` triggers param autocomplete; typing `[` starts a conditional segment. Placeholders render as highlighted chips inside the textarea preview. Live preview line below shows the rendered example using placeholder values. Example: `Create pull request "{title}" on {owner}/{repo}` → preview: `Create pull request "Fix bug" on overfolder/app`.
5. **Mutating toggle** — checkbox + label `Mutating (write) action`. Default value is inferred from the HTTP method (GET/HEAD/OPTIONS → unchecked/read, others → checked/write). Manual override allowed; an info icon explains what mutating means (controls approval-by-default behavior).
6. **Scope param** (`dropdown`) — which defined parameter drives the permission key arg. Options are populated from the params table below. `None` is allowed (key uses `*` wildcard). Helper text: *"The selected param's value becomes the resource arg in the permission key, e.g. for `slack.chat.post_message:#general` the scope param is `channel`."*
7. **Parameters table** — full-width editable table with columns:
   - **Name** (text, required) — param identifier
   - **Type** (dropdown) — `string` / `number` / `boolean` / `enum` / `object`
   - **Required** (checkbox)
   - **Description** (text)
   - **Enum values** (only when type = `enum`) — comma-separated; renders as removable chips
   - Trailing **`✕`** button to delete the row
   
   Below the table: `[+ Add parameter]` ghost button.
8. **Footer** — full-width row with `[Cancel]` (ghost, left) and `[Create]` / `[Save]` (primary, right). For edit mode also a `[Delete action]` button on the far left in danger style with a confirmation popover.

**Validation:** the primary button is disabled until all required fields are valid. Errors render inline beneath each field. The modal locks scroll on the page behind it (overlay backdrop dimmed at 50% opacity).

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
- **`[Test]`** — opens the API Explorer (see below) pre-loaded with a draft service instance of this template. If no service instance exists yet, creates a temporary draft instance and prompts the user for credentials. This lets template authors verify actions, parameters, and auth config work against the real API before publishing.
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
- **Identity** — full SPIFFE-style hierarchical path of the identity that triggered the event, with the `spiffe://` scheme stripped (e.g. `acme/user/alice/agent/henry/agent/researcher`). 
  
  > **Note on segment conventions:** SPIFFE itself only defines the URI shape (`spiffe://<trust-domain>/<path>`); the segment names are application-defined. Overslash uses `<org>/user/<username>/agent/<agentname>` and recurses with `agent/<name>` for sub-agents at any depth, so the hierarchy scales to arbitrary nesting (`agent/a/agent/b/agent/c/...`) without inventing new prefixes.
  
  The path is grouped into **logical link units**, each navigating to the corresponding detail view:
  - `acme` — org segment (links to Org page)
  - `user/alice` — user link unit (type + name together, links to that User Profile page)
  - `agent/henry` — agent link unit (type + name together, links to that agent's Agents view detail panel)
  - `agent/researcher` — sub-agent link unit at the next nesting level (recursively the same `agent/<name>` pattern, links to that sub-agent's Agents view detail panel)
  
  The forward-slash separators between link units stay muted (non-clickable). Hover on a link unit underlines the whole `type/name` pair.
- **Event type** — action executed, approval created/resolved, secret accessed, connection changed, identity created/deleted, permission changed
- **Service** — which external service was involved (blank for identity/permission events)
- **Result** — success/fail/pending, with status code for executions

### Search & Filters

Uses the **Search Bar** (see Design System) with keys: `identity`, `event`, `service`, `result`, `time`.

Examples:
- `[identity ~ henry][event = action.executed]` — all actions by henry
- `[service = GitHub][result = failure]` — failed GitHub calls
- `[time > 2026-04-01]` — events after a specific date

Time range presets (last hour, today, 7 days, 30 days) are available as quick-select buttons next to the search bar for convenience.

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

### API Explorer

A sub-view within Services (accessed via a tab or button, not a top-level nav item). An interactive tool for testing and debugging service connections through Overslash. Simpler than Postman — the goal is verifying that auth works and seeing what comes back.

Can be **hidden from users via an org setting** (e.g., orgs that don't want users making ad-hoc API calls). When hidden, the tab is not shown.

#### Unified flow

The explorer uses a single flow. The level of abstraction is determined by what the user selects:

1. **Pick a service** — dropdown showing the user's service instances (connected ones prioritized). If the user's group grants `http`, "Raw HTTP" appears as an option at the bottom.

2. **Pick an action** — adapts to the selected service and the user's group grants:
   - **Defined actions** listed first with human-readable descriptions and mutating badges (e.g., `create_pull_request — Create a pull request [write]`)
   - **"Custom Request"** appears at the bottom if the user's group grants HTTP verb access for this service. Opens method + path + body inputs, with auth auto-injected.
   - For **"Raw HTTP"** service: shows method + full URL + headers + body + secret selector (pick from user's secrets, specify injection method per secret)

3. **Fill parameters** — auto-generated form for defined actions (text, number, enum dropdowns from the registry schema). Method + path + JSON body editor for custom requests. Full URL + secret injection config for raw HTTP.

4. **Execute** → response panel

#### Raw HTTP example

When "Raw HTTP" is selected as the service:

```
Service: Raw HTTP
Method:  [POST ▾]
URL:     [https://api.example.com/v1/data               ]
Headers: [Content-Type: application/json                 ]
Body:    [{"query": "test", "limit": 10}                 ]

Secrets:
  [api_key ▾]  inject as [Header ▾]  name [Authorization ▾]  prefix [Bearer ]
```

This generates permission keys `http:POST:api.example.com` + `secret:api_key:api.example.com`.

#### Response panel

- **Status code** (color-coded: 2xx green, 4xx yellow, 5xx red)
- **Response time**
- **Headers** (collapsible)
- **Body** (syntax-highlighted JSON, with raw/pretty toggle)
- **Permission keys derived**: shows which `{service}:{action}:{arg}` keys were checked

#### Identity

The API Explorer always executes as the **logged-in user's own identity**. No agent impersonation. All actions are logged in the audit trail under the user's identity.

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
│  [← Go to Agents]                                  │
└─────────────────────────────────────────────────────┘
```

- Shows human-readable description + raw request details + resolved service instance (qualified: `user/github` or `org/github`)
- **Agent (identity)** — rendered as a SPIFFE-style hierarchical path (`acme/user/alice/agent/henry/...`), with the same link-unit treatment as the audit log Identity column (see §"Audit Log"). Backed by `identity_path` on the approval API response. The bare `identity_id` UUID is never shown to end users.
- Full specificity picker for "Allow & Remember" — reads `suggested_tiers` and `description` from the approval API (same as Agents view)
- After resolution → confirmation + link to Agents view
- **Already resolved** — "This approval was allowed by alice 3m ago." (or denied)
- `[← Go to Agents]` for navigation to the full UI
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
│  │  ○ agent-henry              ▸       │            │
│  │  ○ agent-builder             ▸       │            │
│  └─────────────────────────────────────┘            │
│                                                     │
│  [Approve & Enroll]  [Deny]                         │
│                                                     │
│  This token expires in 10m                          │
└─────────────────────────────────────────────────────┘
```

- **Proposed name** — pre-filled by the agent, fully editable
- **Requested by** — agent metadata (IP, timestamp). The agent has no identity yet.
- **Parent placement** — collapsible tree picker reusing the agent tree pattern. Only the user and first-level agents are shown by default. Clicking an agent selects it as parent AND expands its sub-agents for deeper placement. Chevron (▸) indicates expandable nodes.
- **No `inherit_permissions`** — always false for agent-initiated enrollment per spec
- **No permission keys** — keys build up organically through approvals after enrollment
- **Approve & Enroll** — creates the identity, agent picks up API key via polling/webhook. Shows: "Agent 'research-bot' enrolled under alice. The agent has been notified."
- **Deny** — rejects enrollment, token invalidated
- **Token expired** — "This enrollment request has expired."
- **Already enrolled** — "This agent has already been enrolled."

