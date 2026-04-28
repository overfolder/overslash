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

### Root vs. corp-org subdomain login (multi-org)

The same `/login` page renders differently depending on the host the browser hit. The backend's `/auth/providers` response carries a `scope` field that drives the UI.

- **Root apex (`app.overslash.com`)** — `scope: "root"`. Lists only Overslash-level IdPs (env-var Google / GitHub / Dev Login). A user who signs in here gets their personal org on first login.
- **Corp subdomain (`<slug>.app.overslash.com`)** — `scope: "org"`. Lists only that org's IdPs from `org_idp_configs`. Env-level IdPs are NOT shown — a corp-subdomain login must go through the corp's IdP. This is the trust-domain boundary.
- **Corp subdomain with no IdP configured yet** — `scope: "org"` with an empty providers list. The page shows an explanatory empty state: "This organization has no sign-in configured yet. Ask the org admin to add an Identity Provider on their Org Settings page." The admin (= org creator) reaches the org via `/auth/switch-org` from the root dashboard, not via this login page.

### Org creator = regular admin, no "breakglass" framing

When a user creates a corp org via `POST /v1/orgs`, they receive a normal `admin` membership and an admin `identities` row. There is no special "bootstrap" or "breakglass" labeling anywhere in the UI — the creator is simply the org's admin. Their Overslash-level login continues to reach the org regardless of whether the org configures a custom IdP later.

An org may stay on Overslash-level auth indefinitely (only the creator is a member), or later enable one or more IdPs in **Org Settings → Identity Providers**. After an IdP is enabled, additional humans sign in via the corp IdP on the subdomain; the creator's Overslash-level login keeps working via their existing admin membership.

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
- **Org switcher** (sidebar footer, above the Settings link): shows the current org's name. When the user belongs to more than one org, clicking it opens a dropdown grouped by **Personal** / **Orgs** with the current entry highlighted. Selecting an entry posts to `/auth/switch-org { org_id }` and the browser hard-reloads onto the returned URL (root apex for personal orgs, `<slug>.app.overslash.com` for corp orgs). The current org's role (admin / member) is implicit — no per-row badges; every row is just an org name.
- User avatar (32px circle) + name at the bottom.
- Collapse button (chevron «) at the bottom or top-right of the sidebar.

**Collapsed** (64px): same background and border. Contains:
- Logo collapses to "/" (the slash character, bold 18px) — the iconic part of "Overs/ash".
- Nav items show icons only (18px, centered), no labels. Active item still has primary-50 rounded background. Tooltip on hover shows the label.
- "ADMIN" label hidden. Admin nav items still show as icon-only.
- Org switcher collapses to the first letter of the current org's slug in a single cell; clicking still opens the dropdown (which anchors to the right of the sidebar so it's readable).
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
- **Template Editor**: the OpenAPI YAML editor is desktop-first. On mobile the CodeMirror pane is still usable but reduced (smaller gutter, no validation panel when space is tight).
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

`inherit_permissions` defaults to **false** for new agents. The create form includes an opt-in checkbox labeled "Inherits Permissions — inherit parent's current and future rules" (unchecked by default). The user can also toggle this later in the agent detail panel.

For enrollment-created agents, `inherit_permissions` is not offered — it stays false, configurable after enrollment in the detail panel.

On submit, shows a **one-time enrollment snippet** designed to be pasted into the agent's conversation:

```
┌─ Enrollment Instructions ────────────────────────┐
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
│  ⚠ This token is shown once. The agent           │
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
│  ● agent-henry   ← selected │
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
github:ANY:*             Full GitHub API access             Auto-approve reads: ✓
slack:*:*                Slack — any action                 Auto-approve reads: ✓
stripe:*:*               Stripe — any action                Auto-approve reads: ✗
google-calendar:ANY:*    Google Calendar API access         Auto-approve reads: ✓
```

Grants use the `{service}:{action}:{arg}` format. Org-admins pick from known services and choose the access tier (`*` for all actions, `ANY` for raw HTTP verbs, specific verbs, or specific actions). The UI presents this as dropdowns — not as raw key strings to type.

**Auto-approve reads** toggle per service grant: when enabled, agents' non-mutating requests automatically create permission keys without user approval. Disabled by default for sensitive services (financial, PII).

- **"Everyone"** group is always present, cannot be deleted, all users are implicit members

### Settings

A section within the Org Dashboard. Single scrollable view with sections as cards. Subsections below are documented in intended order; some (notably *Features*) are not yet implemented in the dashboard.

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
- **Google/GitHub**: client ID + client secret (endpoints are well-known). If org-level OAuth App Credentials exist for this provider (see below), the fields are pre-populated with those values and a note reads "Using org OAuth credentials". The admin can accept the defaults (credentials stay linked — updating the org OAuth App Credential updates the IdP) or clear and provide dedicated credentials (IdP becomes independent).
- **Custom OIDC**: issuer URL (auto-discovers via `.well-known/openid-configuration`) + client ID + client secret
- **Dev Login**: toggle on/off. Warning badge when enabled in production.

Providers configured via environment variables are shown with an "env" badge and are read-only — they cannot be edited or disabled from the dashboard. Env vars take precedence over in-database settings.

Per-provider settings:
- **Auto-create users**: create user identity on first login (matched by email domain)
- **Allowed email domains**: restrict which domains can log in (e.g., `acme.com`)
- **Default group**: which group new users join on first login

SAML 2.0: future concern. "SAML" appears greyed out in the type dropdown with a "coming soon" tooltip.

#### OAuth App Credentials

Below the Identity Providers table, an **OAuth App Credentials** section manages org-level OAuth client credentials shared across IdP login and service connections.

```
OAuth App Credentials

Provider          Client ID               Configured    Actions
────────────────────────────────────────────────────────────────
Google            7293...apps.google…      ● Secrets     [Edit] [Remove]
GitHub            Iv1.a8b2c3...            ● Secrets     [Edit] [Remove]

                                                         [+ Add Provider Credentials]
```

`[+ Add Provider Credentials]` flow:
- **Provider**: dropdown of known OAuth providers (Google, GitHub, Slack, etc.)
- **Client ID**: text input — stored as org secret `OAUTH_{PROVIDER}_CLIENT_ID`
- **Client Secret**: password input — stored as org secret `OAUTH_{PROVIDER}_CLIENT_SECRET`
- On save, creates (or updates) two org-level secrets with the well-known names.

Credentials configured via environment variables show an "env" badge and are read-only (same pattern as IdP env overrides).

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

Allow user-created templates        [✓]     Users can create personal service templates
Allow user-created services         [✓]     Users can create personal service instances
Show API Explorer                   [✓]     API Explorer visible in nav for all users
Default approval TTL                [24h ▾] Pre-filled expiry for "Allow & Remember"
```

Each with a toggle or dropdown. Settings configured via environment variables are shown as read-only with an "env" badge.

#### Secret requests

Controls how users can fulfill standalone secret-request URLs (`/secrets/provide/req_…`).

```
Secret requests

Allow unsigned secret provisioning                                  [● On]
When on, recipients can submit a secret via the signed URL without
logging in — the capability comes entirely from the URL token. When
off, every newly-issued URL will require the recipient to be signed
in to Overslash before submitting. Existing outstanding URLs are
unaffected — the toggle is forward-only.
```

- **Pill toggle** (rounded, filled when on, outlined when off) backed by `PATCH /v1/orgs/{id}/secret-request-settings`.
- **Default: on.** Existing orgs keep their current open behavior across the upgrade.
- **Forward-only semantics.** Flipping the toggle off stamps `secret_requests.require_user_session = true` on new rows only; URLs minted before the flip keep working as they were issued.
- Cross-tenant sessions are ignored — a session for org B cannot be used to provision a secret in org A, regardless of token validity.

See SPEC §11 *Standalone Pages → User Signed Mode* for the full policy spec and the flow through the provide page.

#### Org Info

- **Org name** — editable
- **Org slug** — used in URLs on Overslash Cloud (`acme.overslash.dev`), editable with warning about URL changes. Not shown on self-hosted instances.
- **Created** — timestamp
- **Plan / billing** — placeholder for future

## Secrets view

A dedicated nav item at `/secrets`. Manages secrets owned by the user and their agents. Users see only secrets in their own subtree. Org admins see all secrets across the org.

Pending secret requests do NOT appear here — they are surfaced in the agent detail panel and as notifications.

### Secret list (`/secrets`)

Uses the **Search Bar** (see Design System). Filterable by name, owner.

```
Secret Name          Owner          Versions    Updated
────────────────────────────────────────────────────────────────
github_token         alice (you)    3           2m ago
stripe_api_key       alice (you)    1           1h ago
openai_key           agent:henry    2           5m ago
```

- **Name** — the secret identifier used for injection
- **Owner** — which identity in the subtree owns this secret. Resolved as the `created_by` of **version 1** — the original creator owns the slot, even if later versions were written by other agents under that user.
- **Versions** — count (equal to `current_version` since versions are dense and 1-indexed)
- **Updated** — `updated_at` timestamp of the most recent write (new version, restore). *Last used* (most recent injection at action time) is intentionally omitted — there is no per-secret access log; agents proving rotation should rely on the audit trail.

`[+ New Secret]` button opens an inline dialog: **Name** + **Value** (password-type) inputs. Submission calls `PUT /v1/secrets/{name}` with the typed value, then navigates to the new secret's detail page.

### Secret detail (`/secrets/{name}`)

Clicking a secret row navigates to the full-screen detail page (push, not modal — versions and used-by lists need room):

- **Secret name** — page title
- **Owner** — identity that owns this secret (see *Owner* above)
- **Created / Updated** — timestamps
- **Used by** — list of service instances whose `secret_name` matches this secret. Each row links to `/services/{name}`. Empty state: "No services use this secret yet."
- **`[Update value]`** — opens a small dialog with a password-type input. Submission creates a new version (`PUT /v1/secrets/{name}`).
- **`[Delete]`** — soft-deletes the secret entirely (all versions). Confirmation dialog warns which services reference it.

#### Version list

```
Version   Created              Created By        Status
───────────────────────────────────────────────────────────
v3        2026-04-01 10:30     agent:henry        ● current
v2        2026-03-20 14:15     user:alice         ○ previous
v1        2026-03-10 09:00     user:alice         ○ previous
```

- **Created by** — which identity wrote this version (shows `on_behalf_of` provenance)
- **Restore** — creates a new version (v4) pointing to the old value. Does not delete anything.

#### Secret version modal

Clicking a version row (or `[Reveal]` button) opens a modal showing:

- Version number, created timestamp, created by
- **Secret value** — masked by default. A `[Reveal]` button calls `POST /v1/secrets/{name}/versions/{version}/reveal` and shows the value inline (click-to-reveal pattern). The reveal is audit-logged as `secret.revealed`. This is the **only way** to view secret values in the dashboard — agents never receive values via API.
- `[Copy]` button to copy the revealed value
- `[Restore this version]` if not the current version — calls `POST /v1/secrets/{name}/versions/{version}/restore`, which creates a new version pointing to the old value. Audit-logged as `secret.restored`.

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

Two buttons in the catalog header:
- `[Import OpenAPI]` — always visible, opens the OpenAPI import wizard (see below). Non-admins can still import, but org-level drafts require admin and user-level drafts require `allow_user_templates`.
- `[+ New Template]` — opens the blank template editor. Only visible if the org allows user-created templates (admin) or to admins for org-level templates.

If the caller has any open drafts, a **Drafts** card renders above this table; see *Template Catalog — Drafts section* below.

### Create service flow

1. **Pick a template** — dropdown or pre-selected from catalog
2. **Name the instance** — defaults to the template key (e.g., `google-calendar`). The user can rename to create multiple instances (e.g., `google-calendar`, `personal-calendar`). This name is used in permission keys and by agents.
3. **Connect credentials** — depends on the template's auth config:
   - *OAuth*: shows requested scopes and a `[Connect]` button that starts the OAuth redirect. Below the connect button, a collapsible **"Use your own OAuth app"** section (collapsed by default). When expanded, shows two text inputs: **Client ID** and **Client Secret** (password-masked with show/hide toggle). If the user fills these in and clicks `[Connect]`, Overslash creates two secrets in the user's vault — `OAUTH_{PROVIDER}_CLIENT_ID` and `OAUTH_{PROVIDER}_CLIENT_SECRET` — and uses them for the OAuth redirect instead of org/system credentials. A help link explains why a user might want this (e.g., "Use credentials from your own GCP project"). If org-level or system credentials are not configured for this provider, the collapsible section starts **expanded** and the fields are required — there's nothing to fall back to.
   - *Org service with per-user OAuth*: OAuth redirect using the org's app credentials (resolved from org-level secrets). No BYOC option — the org controls the app.
   - *API key*: form to paste the key → stored as a versioned secret → done
   - *Both available*: user picks which auth method
   - *Org service with shared credential*: one-click, no auth needed
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

`[Import OpenAPI]` button (next to `[+ New Template]` at the top of the Template Catalog) opens a two-page flow: a lightweight **source wizard** creates a draft, then the **Draft Editor** handles review, selection, and promotion.

**Source wizard** (`/services/templates/import`):

A single page with three cards:

1. *Source* — tabs for **Fetch URL** and **Paste or upload**.
   - URL tab: single text field. HTTPS is encouraged; an HTTP URL shows an amber banner (`⚠ Plain HTTP URLs are fetched over an unencrypted connection`). Private and loopback addresses are blocked server-side — the error surfaces inline.
   - Paste tab: a file picker (`.yaml` / `.yml` / `.json`, 512 KiB cap) plus a monospace textarea. Picking a file populates the textarea; the user can then edit inline before submitting.
2. *Metadata (optional)* — two inputs: **Template key** (leave blank to derive from `info.title`) and **Display name**. These are the only structured fields at this stage; everything else is edited in the draft editor.
3. *Tier* — Org-level (admin only) vs User-level (requires the org setting). Mirrors the New-Template flow.

`[Import & Review]` submits `POST /v1/templates/import`. On success the wizard navigates directly to the draft editor. On validation failure (e.g. the source didn't parse as YAML or JSON) the error banner at the top renders the first few `report.errors`.

Because drafts are DB-backed, the agent-led flow is the same endpoint with no UI: `POST /v1/templates/import → POST /v1/templates/drafts/{id}/promote`.

**Draft Editor** (`/services/templates/drafts/{id}`):

Page header: breadcrumb back to Services, the draft's display name (falls back to the key), a tier badge, and a yellow `draft` pill. Layout is a vertical stack of cards:

1. *Import notes* (only when non-empty) — yellow-tinted card listing `ImportWarning`s: `derived_key`, `derived_operation_id`, `openapi_3_0_source`, `unresolved_external_ref`, `circular_ref`, `http_insecure`. Each entry shows `code`, message, and path in monospace.
2. *Validation errors* (only when `validation.valid === false`) — red-tinted card listing unresolved issues with their `code` + `path`. Editing the YAML below or toggling operations usually clears these; promotion is blocked until the list is empty.
3. *Operations* — one row per operation returned by the server, grouped by path. Each row has a checkbox, color-coded HTTP method badge, path, operationId (with `(auto-named)` marker for synthesized ids), and summary. Toggling any checkbox re-submits `POST /v1/templates/import` with the same `draft_id` and the new `include_operations` — the backend rewrites the draft's canonical YAML so selection and manual edits stay in sync. While the request is in flight all checkboxes are disabled.
4. *YAML* — reuses `TemplateEditorYaml` (CodeMirror, live `POST /v1/templates/validate` on keystroke). Drafts share the *same* editor with the New Template flow; the only differences live in the action footer.
5. *Actions footer* — `[Discard draft]` on the left (danger style, opens a confirmation dialog), `[Save draft]` and `[Save & promote]` on the right. Save-draft is disabled when the YAML matches the last-known server copy. Save-and-promote auto-saves any pending edits first, then calls `POST /v1/templates/drafts/{id}/promote`; on success the user lands on the (now active) template detail page. If promotion fails validation the error banner renders the backend report and the draft stays put.

**Template Catalog — Drafts section** (above the active templates list, rendered only when the user has any):

A light card titled `Drafts (N)` with one row per draft. Each row shows display name + tier badge + key + operation count, plus an `N issues` badge (red) when `validation.valid === false`. Row actions: `[Resume]` (navigates to the draft editor) and `[Discard]` (confirmation dialog). Drafts stay local to their owner (user tier) or to org-admins (org tier); they never show up in the main active-templates table or in agent-facing catalogs.

**Behavioral notes:**
- Unlike the old multi-step wizard, parameter mapping is done *inline in the YAML editor* rather than via a dedicated screen. The validation card makes unknown-scope-param / missing-resolver errors visible, and the YAML editor is where they're fixed.
- Promotion is gated on the *strict* validator, not the lenient one used for drafts: a draft that persists with issues cannot be promoted until those issues are gone.
- Users can iterate freely: import → tweak selection → edit YAML → save draft → come back later → promote. The draft `id` is the durable handle across browser sessions and API callers.

### Template Editor

The editing view for user-defined and org-defined templates. Two tabs.

**Header**: shows breadcrumb (`← Services / Template Editor:`) followed by the template display name and an optional **status pill** next to it indicating the template's lifecycle state:
- **`Draft`** (warning yellow) — work in progress, not yet published. Templates start in Draft when imported from OpenAPI or created from scratch. Drafts are only visible to the author and cannot be used to create services.
- **`Active`** (success green) — published and usable. (No pill is shown for Active to keep the header uncluttered, OR an Active pill is shown for explicitness — implementation choice.)
- **`Archived`** (muted gray) — retired template, hidden from catalogs but still referenced by historical services.

The pill is omitted if the template has no special status. Changing status happens via the kebab menu in the header (`Publish`, `Unpublish`, `Archive`).

#### OpenAPI YAML editor

A single CodeMirror pane showing the full template definition as OpenAPI 3.1 with `x-overslash-*` extensions. There is no separate visual tab — templates are edited as raw YAML, which is the canonical format stored in the database.

```
┌─ Template Editor: My Scraper API ─────────────────────────────┐
│                                                               │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ openapi: 3.1.0                                           │ │
│  │ info:                                                    │ │
│  │   title: My Scraper API                                  │ │
│  │   description: "Personal web scraping service"           │ │
│  │   key: my-scraper-api                                    │ │
│  │ servers:                                                 │ │
│  │   - url: https://scraper.myserver.com                    │ │
│  │ components:                                              │ │
│  │   securitySchemes:                                       │ │
│  │     token:                                               │ │
│  │       type: apiKey                                       │ │
│  │       in: header                                         │ │
│  │       name: X-API-Key                                    │ │
│  │       default_secret_name: scraper_key                   │ │
│  │ paths:                                                   │ │
│  │   /scrape:                                               │ │
│  │     post:                                                │ │
│  │       operationId: scrape_page                           │ │
│  │       summary: Scrape a web page                         │ │
│  │       requestBody:                                       │ │
│  │         content:                                         │ │
│  │           application/json:                              │ │
│  │             schema:                                      │ │
│  │               properties:                                │ │
│  │                 url: {type: string}                      │ │
│  │                 format: {type: string,                   │ │
│  │                          enum: [html, text, md]}         │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                               │
│  ┌─ Validation ─────────────────────────────────────────────┐ │
│  │ ✓ Valid                                                  │ │
│  │ ⚠ Action "scrape_page" has no scope_param — permission   │ │
│  │   keys will use wildcard arg (*)                         │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                               │
│                                                [Save] [Delete]│
└───────────────────────────────────────────────────────────────┘
```

**Aliases**: for ergonomic authoring, the `x-overslash-*` extensions may be written without their prefix — `risk:`, `scope_param:`, `resolve:`, `provider:`, `default_secret_name:`, `category:`, `key:`, and top-level `platform_actions:` all canonicalize to their `x-overslash-*` form on save. Ambiguous documents (both forms on the same object) are rejected inline with `ambiguous_alias` and a line-precise dot-path pointing to the offending key.

**Validation panel** below the editor shows errors and warnings from the backend validate endpoint (`POST /v1/templates/validate`). Validation runs on every edit (debounced ~400ms). Errors block saving, warnings are informational. Stable machine-readable codes (`openapi_parse_error`, `ambiguous_alias`, `duplicate_operation_id`, `unknown_scope_param`, `invalid_risk`, `unknown_path_param`, `missing_field`, …) let the panel render structured messages with path hints.

**Editor behavior**:
- YAML syntax highlighting via `@codemirror/lang-yaml`. Minimal CodeMirror footprint (line numbers, history, bracket matching, default keymaps — no autocompletion, search, or fold gutter) so the lazy-loaded chunk stays small.
- Dark mode follows the dashboard theme (`oneDark` when the document has `data-theme="dark"`).
- Client-side YAML-syntax parse catches malformed YAML immediately; structured semantics go to the backend.
- Future: ship the Rust OpenAPI parser as WASM for instant client-side validation of `x-overslash-*` semantics without a round-trip.

#### View-only mode

For global (Overslash-shipped) templates, the editor opens in read-only mode. The YAML source is still displayed verbatim so users can inspect the template — what operations are available, what parameters they take, how auth is configured.

### Share template

`[Share to Org]` on a user-created template: proposes sharing to org level. The template definition is shared (blueprint only, no credentials). Org-admin reviews and approves (making it available for org service creation) or denies.

### Org-admin: Services management

Org-admins see additional capabilities:

**Org services:**
- Create org-level service instances from any template, assign to groups
- For OAuth templates: the org's OAuth app credentials are resolved from org-level secrets (`OAUTH_{PROVIDER}_CLIENT_ID` / `SECRET`, configured in Org Settings → OAuth App Credentials). If no org credentials exist for the template's provider, the create flow prompts the admin to configure them first (link to Org Settings). Users in assigned groups complete their own OAuth flow using the org's app.
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

A sub-view within Services (accessed via the third tab, alongside `Instances` and `Template Catalog`). An interactive tool for testing and debugging service connections through Overslash. Simpler than Postman — the goal is verifying that auth works and seeing what comes back.

Rows in the `Instances` table carry an **"⌘ Try it"** button that deep-links to the explorer tab with that service pre-selected (`/services?tab=api-explorer&service=<name>`).

Can be **hidden from users via an org setting** (e.g., orgs that don't want users making ad-hoc API calls). When hidden, the tab is not shown. *(Toggle not yet wired — tracked as a follow-up.)*

#### Two modes

A pill toggle at the top of the tab switches between two execution modes:

1. **Service + Action** — pick one of your service instances, then pick a defined action. Parameters render as an auto-generated form (text, number, enum dropdowns, JSON textarea for object/array params). Execute hits `POST /v1/actions/call` as Mode C.

2. **Raw HTTP** — method dropdown + full URL input, free-form headers and body textareas. Execute hits `POST /v1/actions/call` as Mode A. Headers support `{{SECRET_NAME}}` template substitution:

   ```
   Method:  [POST ▾]
   URL:     https://api.example.com/v1/data
   Headers: Content-Type: application/json
            Authorization: Bearer {{MY_TOKEN}}
   Body:    {"query": "test", "limit": 10}
   ```

   Each header whose value contains a single `{{NAME}}` token is rewritten on submit into a `SecretRef` (`inject_as: "header"`, prefix = any text before the token) and the backend injects the decrypted secret at execute time. Body template substitution is not supported yet — `{{…}}` in the body is sent literally, with a visible warning.

#### Response panel

Renders to the right of (or below, on narrow viewports) the request card:

- **Status code** chip (color-coded: 2xx green, 4xx yellow, 5xx red)
- **Response time** in milliseconds
- **Body** (syntax-highlighted JSON)
- For `pending_approval`: an info card with a link to the approval detail page.
- For `denied`: an error card with the reason.

#### Identity

The API Explorer always executes as the **logged-in user's own identity**. No agent impersonation. All actions are logged in the audit trail under the user's identity.

## Account view (`/account`)

A top-level page scoped to the human, not any one org — always reachable from the sidebar footer's user avatar. Uses the app shell (sidebar, top bar) like the rest of the dashboard.

**Profile card**:
- Display name, email (last value the IdP returned, informational)
- `User ID` (a UUID, in a monospaced chip) so the user can reference their own account when filing support

**Organizations card**:
- List of the user's memberships, one per row
- Each row shows the org name, the role (`admin` / `member`), and a `personal` tag for the user's own personal org
- Per-row actions:
  - **Current** (disabled) / **Switch** — same `/auth/switch-org` flow as the sidebar switcher
  - **Leave** — `DELETE /v1/account/memberships/{org_id}`. Confirms before the request. Refused server-side for personal orgs and for the last admin of a non-personal org (dashboard surfaces the error verbatim).

There is no "breakglass" / "bootstrap" tag in this view. The org creator shows up the same as any other admin — a row with `admin`. Their Overslash-level login route is implicit in the fact that the row exists.

**Create org** CTA (top-right of the Organizations card): visible only when `ALLOW_ORG_CREATION=true` on the server. Clicking opens a slim modal (name + slug); on success the browser hard-reloads onto the new org's subdomain (the server returns `redirect_to`) where the creator lands as the sole admin.

## Standalone Pages

Standalone pages have a minimal layout: Overslash logo at top, no sidebar, no nav. They handle expired and already-resolved states gracefully.

### Secret Request Page (`/secrets/provide/req_...?token=jwt`)

No login required *by default* — the JWT in the URL authenticates the request. Safe because providing a secret doesn't grant the agent any authority (the agent still needs a separate approval to use it). Orgs that need a named human on every submission can turn on **User Signed Mode** (see below) via the org settings page.

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
│  ┌─ ✓ Signed in as jane@acme.com ──────────────┐   │ ← viewer banner
│  │ Your name will be recorded on the audit     │   │ (shown only when
│  │ trail for this submission.                  │   │ the visitor has a
│  └─────────────────────────────────────────────┘   │ same-org session)
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
- **Viewer banner** (green, above the input) — shown when the visitor's browser already has a valid `oss_session` cookie for the request's org. Identifies the human whose name will be recorded as `provisioned_by_user_id` on the resulting `secret_versions` row. The visitor did not have to log in — they already were.
- **Sign-in gate** (yellow warning, replaces the input) — shown in the same `ready` page state when the request was minted under the stricter *require user session* mode but the visitor has no session. The page still renders the request metadata (name, requester, reason) so the visitor understands what they're being asked for, but the input is replaced with a "Sign in to continue" link. A POST attempt without a session would be rejected server-side with `401 user_session_required` anyway — the gate is purely a UX optimization to avoid wasting the visitor's time.

#### User Signed Mode (two strictly additive layers)

1. **Opportunistic session binding** — always on. If the visitor is already signed in to the same org as the request (detected via the `oss_session` cookie, sent because the public page uses `credentials: 'same-origin'`), the backend stamps `secret_versions.provisioned_by_user_id` and attributes the `secret_request.fulfilled` audit row to that human instead of the target identity. The URL JWT is still the capability gate; the session is a pure identity attestation layered on top. Cross-tenant sessions are silently ignored.

2. **Required user session** — opt-in via the org settings toggle *Allow unsigned secret provisioning* (default: on). When off, every newly-minted secret-request URL is stamped `require_user_session = true` at mint time; the public page renders the sign-in gate for anyone without a matching session, and the backend rejects anonymous submission with `401 user_session_required`. The toggle is forward-only — outstanding URLs minted before the flip keep the policy they were issued under, so flipping the toggle never breaks in-flight links.

Secret requests also appear in the dashboard: as notification bell items, as badges on the agent tree, and as inline `[Provide]` / `[Deny]` actions in the agent detail panel. The standalone page is for resolving from outside the dashboard (e.g., a link in Telegram or email).

### Approval Deep-Link Page (`/approvals/apr_...`)

Login required. If not logged in → redirect to login → redirect back. If logged in but without authority to resolve → show approval details read-only with: "You don't have permission to resolve this approval."

```
┌───────────────────────────────────────────────────────┐
│  Overs/ash                              alice ▾       │
│                                                       │
│  Approval Request                                     │
│                                                       │
│  agent:henry wants to:                                │
│  Create pull request "Fix bug" on overfolder/app      │
│  via: user/github                                     │
│                                                       │
│  POST /repos/overfolder/app/pulls                     │
│  Body: {"title":"Fix bug","head":"fix","base":"main"} │
│                                                       │
│  ┌─ Allow & Remember ────────────────────────────┐    │
│  │  ○ Create pull request on overfolder/app      │    │
│  │  ○ Create pull request on any repo            │    │
│  │  ○ Any GitHub action                          │    │
│  │                                               │    │
│  │  Expires: [24h ▾]                             │    │
│  └───────────────────────────────────────────────┘    │
│                                                       │
│  [Allow Once]  [Allow & Remember]  [Deny]             │
│                                                       │
│  Requested 2m ago · Expires in 14m                    │
│                                                       │
│  [← Go to Agents]                                     │
└───────────────────────────────────────────────────────┘
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
│  Requested by: 203.0.113.42 · 5m ago                │
│                                                     │
│  Parent placement:                                  │
│  ┌─ Select parent ─────────────────────┐            │
│  │  ● alice (you)                      │            │
│  │  ○ agent-henry              ▸       │            │
│  │  ○ agent-builder            ▸       │            │
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

### MCP OAuth Consent Page (`/oauth/consent?request_id=...`)

Session required. Reached from `GET /oauth/authorize` on first connection from a new MCP client (e.g. Claude Code hitting `POST /mcp` without a token). This is where the user enrolls the agent the MCP client will act as.

```
┌─────────────────────────────────────────────────────┐
│  Overs/ash                                          │
│                                                     │
│  Authorize MCP client                               │
│  Signed in as alice@acme.com                        │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │  Claude Code is requesting access on your     │  │
│  │  behalf.                                      │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  Overslash connects this MCP client through a       │
│  scoped agent identity owned by your user — not     │
│  your user directly. The client's actions are       │
│  auditable separately, approvals route correctly,   │
│  and you can revoke the agent without touching      │
│  your own account.                                  │
│                                                     │
│  ┌─ Create a new agent ─────────────────────────┐   │
│  │  ● Create a new agent named                  │   │
│  │    [Claude Code                         ]    │   │
│  └──────────────────────────────────────────────┘   │
│                                                     │
│  ┌─ Use an existing agent ──────────────────────┐   │
│  │  ○ Select one you already own                │   │
│  │    ┌──────────────────────────────────┐      │   │
│  │    │ research-bot                   ▾ │      │   │
│  │    └──────────────────────────────────┘      │   │
│  └──────────────────────────────────────────────┘   │
│                                                     │
│  [ Authorize ]                                      │
└─────────────────────────────────────────────────────┘
```

- **Signed in as …** — the human user's email from the active dashboard session. If the session expired between `/oauth/authorize` and landing on this page, show a short error page pointing the user back to their MCP client to restart.
- **Client card** — shows the DCR-registered `client_name` from `oauth_mcp_clients`. Falls back to "(unnamed client)" if the MCP client didn't advertise one.
- **Explainer paragraph** — load-bearing copy. This is what makes Overslash different from a plain OAuth app: users are not granting the client *their own* rights, they're creating a scoped agent. The sentence stays visible; do not collapse behind a "learn more" link.
- **Create new agent** — default mode. Suggested name is `client_name` (falling back to "MCP Client"). Editable text input, max 120 chars. No trimming of empty → server replaces blank with a safe default.
- **Use existing agent** — `<select>` populated from the user's un-archived `kind = agent` identities (children via `owner_id`). When the user has no agents yet, the whole fieldset is disabled and the radio isn't selectable.
- **Authorize button** — `POST /oauth/consent/finish` with `request_id`, `mode` (`new` | `existing`), and either `name` or `agent_id`. On success, 303 → the MCP client's `redirect_uri?code=…&state=…`.
- **Errors** — rendered as a minimal server-side error page. Cases: session expired, `request_id` expired or unknown, session user ≠ authorize user, agent ownership mismatch. No dashboard chrome — this is a standalone auth surface.
- **Repeat visits are automatic** — once the binding is stored, subsequent `/oauth/authorize` calls for the same `(user, client_id)` skip this page entirely. There's no separate "I want to re-pick the agent" UI here (v1); to change the binding, use the dashboard MCP Clients admin (follow-up) or delete the binding row.

This page is intentionally hosted by the API server (not SvelteKit), so the Authorization Server remains self-contained in modes where the dashboard isn't served (`overslash serve` cloud mode). Markup lives in `crates/overslash-api/src/routes/oauth_consent.html` and is rendered via simple `{{placeholder}}` substitution — no template engine.

