# Overslash User Stories

Concrete end-to-end narratives showing how different actors interact with Overslash. These stories ground the abstract spec (§§4–11) in real flows and clarify which surfaces (REST API, dashboard standalone pages, MCP, platform-mediated UX) each actor touches.

Each story names: the **actors**, the **happy path**, the **Overslash surfaces** involved, and the **spec sections** exercised.

---

## Story 1 — OpenClaw user enrolls an agent and connects Google Calendar

**Actors**
- **Alice** — individual user with an Overslash cloud account (`alice` under org `personal`).
- **OpenClaw agent** — a coding/assistant agent running locally on Alice's machine, with no prior knowledge of Overslash.
- **Overslash cloud** — `https://personal.overslash.dev`.

**Goal:** Alice wants her OpenClaw agent to be able to read and create events on her Google Calendar, without ever handing it her Google credentials or her Overslash API key.

### Happy path

1. **Discovery.** Alice tells OpenClaw: *"connect yourself to my Overslash at personal.overslash.dev"*. OpenClaw fetches `https://overslash.dev/SKILL.md`, follows the link to `https://overslash.dev/enrollment/SKILL.md`, and learns the agent-initiated enrollment protocol (§4 *Agent Enrollment*).
2. **Agent-initiated enrollment.** OpenClaw calls the enrollment endpoint on `personal.overslash.dev`, proposing a name (`openclaw`) and metadata about itself. Overslash returns a single-use enrollment token + a consent URL: `https://personal.overslash.dev/enroll/consent/...`.
3. **Consent.** OpenClaw prints the consent URL in the chat. Alice clicks it, logs into Overslash via her configured IdP (Google OIDC, §4 *User Authentication*), and lands on the enrollment consent page (§11 *Standalone Pages*). She:
   - Edits the proposed name from `openclaw` to `openclaw-laptop`.
   - Accepts the default placement (directly under `alice`).
   - Leaves `inherit_permissions` off.
   - Clicks **Approve**.
4. **Key exchange.** OpenClaw, polling the enrollment endpoint, picks up its permanent API key (`ovs_personal_openclaw-laptop_...`) and stores it locally. The agent identity is now `spiffe://personal/user/alice/agent/openclaw-laptop`.
5. **Agent-led discovery (no instance yet).** Alice asks OpenClaw: *"what's on my calendar tomorrow?"* OpenClaw doesn't know if a calendar service is connected — so it calls `overslash_search(query="calendar")` (§10). Overslash returns a structured payload distinguishing two kinds of hits:
   ```json
   {
     "services": [],                                  // no instances Alice has connected yet
     "templates": [
       { "key": "google-calendar", "tier": "global",
         "display_name": "Google Calendar",
         "auth": { "type": "oauth", "provider": "google" },
         "actions_summary": ["list_events", "create_event", ...],
         "instantiable": true }
     ]
   }
   ```
   The agent now knows: there is no live calendar service for Alice, but there is a global template it can instantiate. No human-driven dashboard tour needed.
6. **Agent-led service creation.** OpenClaw calls `overslash_auth(action="create_service_from_template", template="google-calendar", name="google-calendar", on_behalf_of="alice")`. Because the template uses OAuth and no token exists yet, Overslash creates the service in `pending_oauth` state and returns an OAuth start URL bound to Overslash's system Google client (§7). OpenClaw prints the URL in chat: *"To connect your Google Calendar I need you to authorize this link."*
7. **OAuth consent.** Alice clicks, signs into Google, grants the calendar scope, and lands on Overslash's OAuth callback. The token is encrypted and bound to Alice's new `google-calendar` service instance (§6, §9). Overslash flips the service to `active`. OpenClaw, polling `overslash_auth(action="status", service="google-calendar")` (or via webhook), sees the transition.
8. **Re-discovery and execute.** OpenClaw re-runs `overslash_search(query="calendar")` — now `services` contains the live instance with full action schemas, and OpenClaw calls `overslash_execute(service="google-calendar", action="list_events")`.
9. **Approval.** No matching permission key exists for `openclaw-laptop`. Overslash returns `{ status: "pending_approval", approval_id: "apr_..." }` with `suggested_tiers` (§5 *Specificity Tiers*). Because there is no platform mediating, OpenClaw surfaces the Overslash-hosted approval URL (`https://personal.overslash.dev/approvals/apr_...`) directly to Alice.
10. **Resolution.** Alice opens the URL, is already logged in, and picks the broadest sensible tier: `google-calendar:list_events:*` with **Allow & Remember** + 30-day TTL. Resolution succeeds (§5 *Trust Model*) — Alice has authority over her own agent.
11. **Execution.** OpenClaw's pending request resumes; Overslash injects the OAuth token from the `google-calendar` service, executes the GET, returns the event list. Audit records: identity `spiffe://personal/user/alice/agent/openclaw-laptop`, service `user/google-calendar`, action `list_events`, key `google-calendar:list_events:*` (§12).
12. **Subsequent reads.** All later `list_events` calls auto-approve via the stored permission key. A future `create_event` call will trigger a fresh approval (different key, `risk: write`).

The key shift: **Alice never opens the Overslash dashboard.** Service connection, OAuth handoff, and permission grants are all driven by the agent through the meta tools, with Alice only clicking the two URLs she has authority over (the OAuth consent and the approval page).

### Surfaces touched
- Public marketing site (`overslash.dev/SKILL.md`, `enrollment/SKILL.md`).
- REST API: enrollment endpoints, all 3 meta tools (`overslash_search`, `overslash_execute`, `overslash_auth`).
- OAuth: Google consent screen (system OAuth client).
- Standalone pages: `/enroll/consent/...`, `/approvals/apr_...` (§11). **No dashboard usage.**

### Spec coverage
§4 (agent-initiated enrollment, IdP login), §5 (approval, specificity tiers, trust model), §7 (OAuth engine, system credentials), §9 (templates → service instances), §10 (meta tools), §11 (standalone pages), §12 (audit).

### Notes / open questions
- Without a platform, the only notification channel for the approval is OpenClaw printing the URL into the chat. The 1-minute notification delay (§5) means Alice won't get an email/bell ping unless she ignores it for over a minute — fine for a synchronous "ask + click" loop.

---

## Story 2 — Corporate employee installs the Overslash MCP in Claude Code

**Actors**
- **Bob** — software engineer at ACME, member of the `acme` org in Overslash, in the `Engineering` group.
- **Claude Code** — local CLI with MCP support.
- **Overslash MCP server** — Overslash's first-party MCP server (see [mcp-integration.md](mcp-integration.md)).
- **ACME org-admin** — has already pre-configured org services: `github` (org GitHub OAuth app), `slack` (write), `jira` (write), and a corporate Okta IdP.

**Goal:** Bob wants to use ACME's pre-approved set of services (GitHub, Slack, Jira) from inside Claude Code, with org-level audit and group-level ceilings enforced.

### Happy path

1. **Install.** Bob runs the Overslash MCP install command (e.g., `claude mcp add overslash …`) pointing at `https://acme.overslash.dev`. The MCP server registers `overslash_search`, `overslash_execute`, `overslash_auth` as tools in Claude Code (§10).
2. **Authentication.** On first use, the MCP server initiates a device-code / browser login flow against `acme.overslash.dev`. Bob's browser opens, he authenticates via ACME's corporate Okta SSO (§4), and the MCP server stores the resulting Overslash credentials locally. Bob is now acting as `spiffe://acme/user/bob` — **not** as an agent. Claude Code is treated as a UI front-end for Bob himself, governed by his group membership (§5 Layer 1).
3. **Discovery.** Bob asks Claude Code: *"list open PRs assigned to me in the backend repo"*. Claude Code calls `overslash_search` → MCP forwards to Overslash → Overslash returns only services Bob's group grants visibility to (§9 *Service discovery is group-gated*): `github`, `slack`, `jira`, plus the global read-only specs Engineering has access to.
4. **Execution.** Claude Code calls `overslash_execute` with `service=github`, `action=list_pull_requests`, `repo=acme/backend`, `assignee=bob`. Because Bob is acting as himself (not as an agent), the **two-layer model collapses to Layer 1 only**: the request must be within the Engineering group ceiling (§5). `github` (write) covers `list_pull_requests` (`risk: read`), so it passes immediately — **no approval needed, ever, for actions within Bob's own group ceiling**.
5. **Audit.** The audit log records the action under identity `spiffe://acme/user/bob`, service `org/github` (fully qualified, §9 *Qualified vs unqualified names by context*), with the resolved underlying GitHub user being Bob's per-user OAuth token under the org's GitHub OAuth app.
6. **Mutating action.** Bob asks: *"comment on PR #1234 saying 'lgtm'"*. Claude Code calls `overslash_execute` with `service=github`, `action=create_issue_comment`. `risk: write`, still within Engineering's `github (write)` grant → executes, audited.
7. **Out-of-bounds action.** Bob asks: *"delete the staging branch"*. Action is `risk: delete`. Engineering only has `github (write)`, not `admin`. Overslash returns a hard **deny** with `not_approvable: true` — no approval flow, the group ceiling cannot be lifted by anyone except an org-admin reassigning Bob's group (§5 *Layer 1*). Claude Code surfaces the deny to Bob with the reason.
8. **Discovering a personal service via templates.** Bob asks: *"track my personal Linear tickets too"*. Linear is not in ACME's org services. Claude Code calls `overslash_search(query="linear")`. Because `allow_user_templates` is enabled for Engineering, Overslash returns:
   ```json
   {
     "services": [],
     "templates": [
       { "key": "linear", "tier": "global", "instantiable": true,
         "auth": { "type": "api_key", "header": "Authorization" } }
     ]
   }
   ```
   Claude Code calls `overslash_auth(action="create_service_from_template", template="linear", name="my-linear", scope="user")`. Linear uses an API key, not OAuth, so Overslash creates the service in `pending_secret` state and returns a **secret request URL** (`/secrets/provide/req_...?token=jwt`, §11). Bob pastes his Linear API key once into that signed page; the service flips to `active`. Subsequent `overslash_execute` calls work — and because this is a *user-owned* service, it bypasses the group ceiling for Bob himself (§5, §9).

### Surfaces touched
- MCP server (Overslash's first-party MCP, see [mcp-integration.md](mcp-integration.md)).
- REST API: meta tools, login.
- IdP: corporate Okta via OIDC discovery (§4).
- (Optional) Dashboard: Bob can visit `acme.overslash.dev` to see his group memberships and audit history of his own actions.

### Spec coverage
§4 (corporate SSO via OIDC), §5 (Layer 1 group ceiling, no Layer 2 for users acting as themselves), §9 (org services, qualified naming, group-gated discovery), §10 (meta tools), §12 (audit under user identity).

### Notes / open questions
- This story relies on the trust assertion that **users acting through MCP are users, not agents**. The MCP login establishes a user session, not an agent identity. This must be made explicit in the MCP design doc — otherwise an attacker who compromised Bob's laptop could elevate from "Bob's MCP session" to "Bob creating an agent".
- If ACME's org-admin enables stricter MCP policies (e.g., "MCP sessions are treated as agents and need permission keys"), Bob's flow degrades into the approval loop from Story 1. This is a per-org policy decision, not specified yet.

---

## Story 3 — Overfolder user connects Google Calendar via Telegram

**Actors**
- **Carol** — end user of the Overfolder consumer agent platform, primarily interacting via Telegram.
- **Overfolder platform** — multi-tenant agent platform that uses Overslash as its auth/identity backend. Carol's identity in Overslash is `spiffe://overfolder/user/carol/agent/carols-assistant`.
- **Carol's assistant agent** — long-running agent on Overfolder, already enrolled into Overslash by the platform during Carol's signup.
- **Overslash** — running as `overslash.overfolder.com` (Overfolder's tenant), invisible to Carol.

**Goal:** Carol wants her assistant to manage her calendar. Carol never sees the word "Overslash" — every interaction is mediated by Overfolder, surfaced through Telegram.

### Happy path

1. **Request.** In Telegram, Carol tells her assistant: *"hey, can you start managing my Google Calendar?"*
2. **Service discovery.** The assistant calls `overslash_search(query="calendar")`. Overslash returns `services: []` (none connected for Carol yet) and `templates: [{ key: "google-calendar", tier: "global", auth: { type: "oauth", provider: "google" }, instantiable: true }]`. The assistant doesn't have to ask Carol *which* calendar service to use — there is exactly one global template that matches. It calls `overslash_auth(action="create_service_from_template", template="google-calendar", name="google-calendar", on_behalf_of="carol")` (§4, §6 *Scoping*) so all of Carol's future agents share the same instance.
3. **OAuth handoff.** Overslash needs Carol's consent to mint the OAuth token and bind it to a new `google-calendar` service. Overslash returns an OAuth start URL. The assistant cannot click this — it has no browser. It returns the URL to **Overfolder**, not directly to Carol.
4. **Platform-mediated UX.** Overfolder receives the OAuth URL through its event channel (webhook from Overslash). Overfolder's Telegram integration formats a Telegram message: *"Your assistant wants to connect to Google Calendar. [Connect Google Calendar]"* with the URL behind the button. Carol taps it.
5. **Google OAuth.** Carol completes Google's consent screen in her browser. Google redirects to Overslash's callback. Overslash creates the `google-calendar` service instance owned by `carol`, stores the encrypted token (§6, §7), and fires a webhook back to Overfolder: *"service instance ready"*.
6. **Continuation.** Overfolder sends Carol a Telegram message: *"Connected. What would you like me to do?"* Carol replies: *"add lunch with Dave tomorrow at 1pm"*.
7. **Action attempt.** The assistant calls `overslash_execute` with `service=google-calendar`, `action=create_event`, `summary="Lunch with Dave"`, `start=...`, `end=...`. Overslash derives keys: `google-calendar:create_event:primary` (`risk: write`). No matching permission key for `carols-assistant` → Overslash returns `{ status: "pending_approval", approval_id, suggested_tiers, description }`.
8. **Approval surfacing.** Overfolder receives the approval event via webhook. Its Telegram integration renders inline buttons:
   - **Allow once** — `resolution: allow`
   - **Allow this calendar** — `remember_keys: ["google-calendar:create_event:primary"]`, TTL `7d`
   - **Allow any calendar** — `remember_keys: ["google-calendar:create_event:*"]`, TTL `30d`
   - **Deny**

   The button labels come from the `description` field (§5 *Specificity Tiers*) or from Overfolder's own i18n layer using the structured `derived_keys`. Crucially, Carol never sees an Overslash URL. **No Overslash login is involved**, because Overfolder is calling `POST /v1/approvals/{id}/resolve` using **Carol's** Overslash credentials (which Overfolder holds on her behalf, established during signup), not the assistant's API key (§5 *Trust Model*).
9. **Resolution.** Carol taps **Allow this calendar**. Overfolder calls the resolve endpoint with Carol's credentials. Overslash stores the key for `carols-assistant`, completes the original `create_event` execution, and returns the result through the assistant's pending request. The assistant replies in Telegram: *"Added lunch with Dave for tomorrow 1–2pm."*
10. **Subsequent calls.** Future `create_event` on `primary` auto-approve for 7 days. The audit log records every step under `spiffe://overfolder/user/carol/agent/carols-assistant`, with no Overfolder-side coupling — if Carol churns to a different platform, her audit, services, and remembered approvals stay in Overslash.

### Surfaces touched
- Overfolder's Telegram bot (entirely Overfolder-side).
- Overfolder backend ↔ Overslash REST API (search, execute, auth, resolve).
- Overslash webhooks → Overfolder (approval events, OAuth-completion events).
- **Zero** Overslash dashboard or standalone-page exposure to Carol. No Overslash URL is ever shown.

### Spec coverage
§4 (platform-managed user provisioning), §5 (approval flow, trust model — platform resolves with **user's** credentials, not agent's; specificity tiers rendered by platform), §6 (`on_behalf_of` for shared secrets across user's agents), §7 (OAuth engine), §9 (template → user-owned service instance), §10 (meta tools), §12 (audit under platform-namespaced identity).

### Notes / open questions
- This story is the strongest validation of the **"no platform-specific logic in Overslash"** rule (CLAUDE.md rule 4). Telegram never appears in any Overslash code path — Overfolder owns the bot, the buttons, the i18n, and the URL hiding.
- It also exercises the trust model edge case: Overfolder holds Carol's Overslash credentials. This means Overfolder is part of Carol's TCB. This is fine — Carol already trusts Overfolder with her chats — but should be explicit in the platform-integration docs.
- The 1-minute notification delay (§5) interacts oddly with chat UX: if Carol takes >1 minute to tap a button, Overslash will fire a notification webhook *in addition to* the original one Overfolder is already showing. Overfolder must dedupe (or Overslash should expose a "platform-managed, suppress notifications" hint per agent).

---

## Cross-story observations

| Aspect | Story 1 (OpenClaw direct) | Story 2 (Corporate MCP) | Story 3 (Overfolder/Telegram) |
|---|---|---|---|
| User identity origin | Personal IdP (Google OIDC) | Corporate IdP (Okta OIDC) | Platform-managed, opaque to user |
| Platform layer | None | Claude Code MCP (thin) | Overfolder (thick) |
| Approval surfacing | Overslash standalone page | N/A (user acts as themselves) | Telegram inline buttons |
| Who calls resolve API | Alice via her own browser session | N/A | Overfolder, with Carol's stored creds |
| Permission layer used | Layer 2 (per-agent keys) | Layer 1 only (group ceiling) | Layer 2 (per-agent keys) |
| Notification needs | Synchronous, none | None | Webhook-driven, must dedupe |
| Audit identity | `spiffe://personal/user/alice/agent/openclaw-laptop` | `spiffe://acme/user/bob` (no agent) | `spiffe://overfolder/user/carol/agent/carols-assistant` |

These three stories together cover the full matrix of (user-managed vs corp-managed) × (no platform / thin platform / thick platform) and exercise every standalone page, every meta tool, both permission layers, and every approval-resolution path described in §5.
