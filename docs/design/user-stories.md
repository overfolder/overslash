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

## Story 4 — Sub-agents, TTL workers, and approval bubbling

**Actors**
- **Diego** — solo researcher with a `personal` org account.
- **`research-bot`** — Diego's long-lived research agent at `spiffe://personal/user/diego/agent/research-bot`. Already has permission keys for `arxiv:*:*`, `google-search:search:*`, and `slack:post_message:#research`.
- **Three ephemeral worker sub-agents** — `worker-1`, `worker-2`, `worker-3`, spawned by `research-bot` for a single fan-out job.

**Goal:** A literature-review job is large enough that `research-bot` wants to fan it out across three parallel workers. The story exercises sub-agent creation, TTL cleanup, `inherit_permissions` as a live pointer, approval bubbling to the gap level, ancestor-agent-resolves-for-descendant, the 3-pending approval cap, and how the hierarchy lets agents cooperate without pestering the user for every action.

### Happy path

1. **Job kickoff.** Diego asks `research-bot`: *"do a lit review on graph neural networks for protein folding, use as many sources as you can, summarize each."* `research-bot` decides to fan out.
2. **Sub-agent creation.** `research-bot` calls `overslash_auth(action="create_subagent", name="worker-1", inherit_permissions=true, ttl="1h")` three times, getting back three permanent-but-ephemeral API keys. The new identities appear in the hierarchy at depth=2:
   ```
   personal
     └── diego                              depth=0
          └── research-bot                  depth=1
               ├── worker-1   ttl=1h        depth=2  inherit_permissions=true
               ├── worker-2   ttl=1h        depth=2  inherit_permissions=true
               └── worker-3   ttl=1h        depth=2  inherit_permissions=true
   ```
   Because `inherit_permissions=true` is a **live pointer** (§4), each worker dynamically has whatever permission keys `research-bot` has — current and future. No keys are copied.
3. **Parallel fan-out.** `research-bot` dispatches three subtasks to the workers in parallel.
4. **Auto-approved action via inheritance.** `worker-1` calls `overslash_execute(service="arxiv", action="list_papers", query="GNN protein folding")`. Hierarchical resolution (§5):
   - `worker-1`: no own keys, `inherit_permissions=true` → check parent
   - `research-bot`: has `arxiv:*:*` → covers `arxiv:list_papers:*` → pass
   - `diego`: within group ceiling (Diego has no groups configured → permissive) → pass
   
   Auto-approved. Audit logs the action under `spiffe://personal/user/diego/agent/research-bot/worker-1`, with the resolution chain recorded.
5. **Gap at the parent boundary, bubbling to the user.** `worker-2` calls `overslash_execute(service="google-scholar", action="search", query="...")`. Resolution:
   - `worker-2`: no own keys, inherit → check parent
   - `research-bot`: has `google-search:search:*` but **not** `google-scholar:search:*` (different service) → gap at this level
   
   The approval is created **at `research-bot`**, not at `worker-2`, because that's the first level where a key could resolve it (§5 *Approval Bubbling*). `research-bot` cannot resolve approvals for keys it does not already hold itself (§5 *Trust Model*: "A parent cannot grant a child more than it has itself") — and it doesn't have any `google-scholar` access. So the approval bubbles further: it surfaces to **Diego**, the first identity with authority to grant a brand-new key.
6. **3-pending cap kicks in.** While step 5 is in flight, `worker-3` discovers a paper PDF on a new domain and tries to fetch metadata via a different unfamiliar service. That's the third unresolved approval bubbled to `research-bot` in this job. But `research-bot` had a stale pending approval from a previous job two days ago (Diego never resolved it). Adding `worker-3`'s request would put `research-bot` at 4 pending — over the cap (§5 *Pending Approval Limits*). Overslash auto-drops the oldest one, marks it `superseded`, and creates the new one. The audit log records both events.
7. **Diego resolves the user-level approval.** Diego sees the bubbled approval from step 5 in his dashboard (or via whatever notification channel he uses). He picks the broadest sensible tier: `google-scholar:search:*`, **Allow & Remember**, 7-day TTL. The key is stored on **`research-bot`** (the gap level), not on `worker-2` directly. Because workers `inherit_permissions`, all three workers immediately gain `google-scholar:search:*` access through the live pointer. The pending request from `worker-2` resumes and executes.
8. **Ancestor agent resolves for descendant — within boundary.** Later, `worker-1` wants to post a status update to Slack: `slack:post_message:#research`. Resolution:
   - `worker-1`: no own keys, inherit → check parent
   - `research-bot`: has `slack:post_message:#research` exactly → covers → pass
   
   This resolves entirely through inheritance; no approval ever needed to be created. **But suppose `worker-1` wanted to post to `#general` instead.** Then `research-bot` doesn't have that exact key. The approval would be created at `research-bot`. *In principle* `research-bot` could resolve it programmatically (because `slack:post_message:*` is a broader version of what `research-bot` has, the parent could grant the narrower `#general` key to its descendant — wait, no: `research-bot` has `:#research`, which is **not** a superset of `:#general`. So research-bot cannot grant this; it bubbles to Diego.
   
   The cleaner case is: `research-bot` has `slack:post_message:*`, and a worker wants `slack:post_message:#general`. The worker's request creates an approval at the worker level (the gap), which `research-bot` **can** resolve programmatically because the requested key is a strict subset of one it already holds. Spec §5 trust model permits this: *"an agent can approve for its sub-agents, but only if the permission being granted is already within the agent's own boundary."* The mechanism: `research-bot` calls `overslash_auth(action="resolve_descendant_approval", approval_id, resolution="allow_remember", remember_keys=["slack:post_message:#general"], ttl="1h")`. Overslash validates that the requested keys are a subset of `research-bot`'s own boundary, validates the TTL is no longer than `research-bot`'s own TTL on the source key, and resolves. Diego is never paged.
9. **TTL cleanup.** One hour after spawn, all three workers expire. Their identities are deleted from the active hierarchy. Audit entries remain forever, identified by the SPIFFE path; the workers cannot be reanimated or impersonated.
10. **Disabling inheritance for a future run.** Diego decides next session's workers should not inherit — he wants tighter control. He toggles `inherit_permissions: false` in the dashboard for the next batch of workers `research-bot` spawns. Now the next workers will need their own explicit keys for everything. (The toggle is on the worker template / spawn defaults Diego configures, not retroactively on already-spawned workers.)

### Surfaces touched
- Meta tools: `create_subagent`, `execute`, `resolve_descendant_approval`.
- Dashboard: identity hierarchy tree, pending approvals view (showing the bubbled approval at `research-bot` level with the descendant chain).
- Audit log: per-sub-agent SPIFFE paths, resolution chains for hierarchical resolution.

### Spec coverage
§4 (sub-agents at depth=2, TTL, `inherit_permissions` live pointer), §5 (hierarchical resolution, approval bubbling to gap level, ancestor-resolves-for-descendant trust rule, pending approval cap with `superseded` reason), §10 (`create_subagent`, plus the exposed gap below).

### Notes / open questions
- **SPEC gap exposed.** §10 lists `overslash_auth` actions but doesn't currently include a way for an ancestor agent to resolve a descendant's approval programmatically. Step 8 invents `resolve_descendant_approval`. The trust rule from §5 ("ancestors can resolve within own boundary") is well-specified but the mechanism is not. Worth adding to §10's `overslash_auth` action table.
- The TTL on the resolved key (step 8) should be capped by the source key's remaining TTL on the parent — otherwise a parent could grant a child a longer-lived key than it has itself, by extending TTL forward. Worth clarifying in §5.
- The `superseded` drop in step 6 has a UX wrinkle: if the dropped approval was important to Diego, he gets no signal that it was dropped (it just disappears). Maybe Overslash should fire a notification on supersession, or expose dropped approvals in the audit log with a clear reason. Currently §5 says the cap exists but doesn't specify visibility of drops.

---

## Story 5 — ACME's org-admin sets up Overslash from scratch

**Actors**
- **Erin** — IT admin at ACME, signing up for Overslash on day 1.
- **ACME** — mid-size company with ~80 engineers, runs Okta SSO, has its own GCP project, has an internal `inventory-api` documented with an OpenAPI 3.x spec.
- **Frank** — an ACME engineer who joins Overslash mid-story as the first end user.

**Goal:** Stand up the ACME org so Engineering can start using Overslash productively, without paying the CASA tax for Google scopes (BYOC), without exposing every global template, and with the org's internal `inventory-api` available as a first-class service.

### Happy path

1. **Org provisioning.** Erin signs up at `acme.overslash.com`. Overslash creates the `acme` org and makes Erin the first org-admin. She sees an empty dashboard with onboarding hints.
2. **IdP configuration.** Erin opens **Settings → Identity Providers → Add IdP → Okta**. She pastes ACME's Okta issuer URL (`https://acme.okta.com`). Overslash hits `.well-known/openid-configuration`, autodiscovers all endpoints (§4 *OIDC Discovery*). Erin pastes the client ID + secret she generated in Okta, saves. She tests with her own login by signing out and signing back in via Okta — round-trip works.
3. **Group creation.** Erin opens **Settings → Groups** and creates three groups:
   - **Engineering**: grants `github (write, auto_approve_reads=true)`, `slack (write)`, `jira (write)`. The `auto_approve_reads` flag (§5) means agents in this group auto-approve any non-mutating GitHub/Slack/Jira actions without prompting users — large UX win for read-heavy agent workflows.
   - **Admin**: grants `github (admin)`, `slack (admin)`, `jira (admin)`, plus `allow_raw_http: true`. Reserved for Erin and a couple of senior engineers.
   - **Read-only**: grants `github (read)`, `slack (read)`, `jira (read)`. For the security team and contractors.
4. **Org GitHub service via BYOC.** Erin doesn't want to wait for CASA on Overslash's system Google credentials, and for GitHub specifically, she wants ACME's *own* GitHub OAuth app so PRs and audit trails attribute to ACME's brand. She:
   - Goes to her ACME GCP project (a separate one from Overslash), creates an OAuth client for GitHub (web application type)... actually GitHub doesn't use GCP. She creates a GitHub OAuth App at `github.com/settings/developers`, copies client ID + secret.
   - In Overslash: **Templates → Global → GitHub → Use as Org Service**. Names the instance `github`. Picks "Use custom OAuth client" instead of system credentials, pastes the GitHub OAuth App credentials. Assigns to Engineering and Admin groups.
   - Each Engineering user, on first use, completes a per-user OAuth flow against ACME's own GitHub OAuth app — they end up with personal tokens but bound to the ACME app, which means ACME's GitHub admins control the app and can revoke it organization-wide.
5. **Google Workspace BYOC for Calendar.** Erin repeats the pattern for Google Calendar, but using a real GCP project this time. She creates a GCP project under ACME's Workspace org, enables the Calendar API, creates an OAuth client (web application), sets the **OAuth consent screen to Internal** — this restricts the app to acme.com users and **skips Google's verification entirely** regardless of scopes (see [google-workspace-oauth.md](google-workspace-oauth.md) — TBD). She pastes the GCP client ID + secret into Overslash's `google-calendar` template. Engineering and Admin groups get access. No CASA, no annual review, ACME admins retain full control.
6. **OpenAPI import for `inventory-api`.** ACME's internal `inventory-api` runs at `inventory.acme.internal` and is documented with a 12-endpoint OpenAPI 3.x spec. Erin opens **Templates → Import OpenAPI**, uploads the spec file. Overslash's `overslash-core` parser walks the spec and shows the discovered endpoints with checkboxes. Erin:
   - Selects 8 of the 12 endpoints (skips the deprecated and admin-only ones)
   - Reviews each: marks GETs as `risk: read`, POSTs as `risk: write`, DELETEs as `risk: delete`
   - Sets `scope_param: warehouse_id` on the warehouse-scoped actions so permission keys end up like `acme-inventory:list_items:warehouse-NYC` instead of `:*`
   - Names the resulting template `acme-inventory`, saves at the **org tier** (visible to all ACME users, mutable by org-admins)
   - Creates a service instance from it, configures the bearer token via `/secrets/provide`, assigns to Engineering. The verify probe (`GET /healthz`) succeeds, service flips to `active`.
7. **Hide unused globals.** Erin opens **Templates → Global** and hides Eventbrite, Stripe, Resend, and Linear from her org. They no longer appear in user dashboards, the API Explorer, or `overslash_search` results for any ACME identity. (Templates are still in the underlying registry; she can re-enable them later.)
8. **Allow user templates.** Erin enables `allow_user_templates` in **Settings → Org Policies**. Some advanced engineers will want to import their own personal OpenAPI specs for niche internal tools or test fixtures. ACME's policy is "user templates are private to the user and their agents; sharing to org level requires Erin's review."
9. **First end user joins.** Erin shares `acme.overslash.com` with the Engineering team. Frank logs in: he's redirected to Okta, authenticates with his ACME credentials, and lands back on Overslash. Auto-provisioning (§4) creates `spiffe://acme/user/frank`. Erin had pre-mapped Okta groups → Overslash groups (or assigned manually), so Frank lands in Engineering automatically. He sees his profile with the services Engineering has access to: `github`, `slack`, `jira`, `google-calendar`, `acme-inventory`.
10. **User-initiated agent enrollment.** Frank wants to enroll his Claude Code CLI as an agent. Goes to **My Agents → New Agent**, names it `claude-code-laptop`, leaves `inherit_permissions=false`. Overslash returns an enrollment snippet: a URL, a single-use token, and a link to `overslash.dev/enrollment/SKILL.md`. Frank copy-pastes the snippet into Claude Code. Claude Code reads the SKILL, exchanges the token for a permanent API key (15-min TTL on the token, §4). The agent is live.
11. **API Explorer test.** Frank opens **API Explorer**, picks the `github` service, picks the `list_repositories` action, hits Run. The action executes as `spiffe://acme/user/frank` — the API Explorer never impersonates agents (§11). Layer 1 group check passes (Engineering has github write), no Layer 2 because Frank is acting as himself (§5 *User Identities Skip Layer 2*). Audit log records the call under Frank's user identity, with `via: api_explorer`.
12. **Service shadowing vignette.** Frank also has a personal GitHub account he uses for open-source contributions. He creates a *user-owned* service from the GitHub template, also named `github`, with his personal OAuth token. No conflict — user services and org services have separate name scopes (§9). Now when Frank's `claude-code-laptop` agent calls `service=github`, resolution returns the **user's** instance (user-shadows-org). To explicitly hit the org instance, the agent uses `service=org/github`. This lets Frank toggle between work and personal GitHub by adjusting the agent's prompt rather than reconfiguring services.

### Surfaces touched
- Dashboard org-admin views: Settings (IdP, Org Policies), Groups, Templates (Global + Org + Import), Services (org-level instances + group assignment).
- Dashboard user views: My Profile, My Services, My Agents, API Explorer.
- OpenAPI parser (`overslash-core`).
- OAuth callbacks against ACME's own GitHub OAuth App and ACME's own internal-tier Google OAuth client.
- IdP discovery against `acme.okta.com/.well-known/openid-configuration`.
- Standalone page: enrollment snippet handed to Claude Code.

### Spec coverage
§4 (OIDC discovery, IdP config via dashboard, user auto-provisioning, user-initiated enrollment), §5 (groups with `auto_approve_reads`, `allow_raw_http`, no Layer 2 for users), §7 (service-level OAuth credentials a.k.a. BYOC, the path that sidesteps CASA for Workspace), §9 (org-tier templates, OpenAPI import + endpoint selection + risk tagging + scope_param, hiding global templates, `allow_user_templates`, service shadowing user-over-org, secret-token service with verify probe), §11 (org-admin Settings/Groups/Templates/Services views, API Explorer, hierarchy tree).

### Notes / open questions
- **SPEC gap.** §4 mentions Okta group → Overslash group sync only implicitly. Step 9 assumes pre-mapping; in reality Erin would need to manually assign Frank to a group on first login unless we build an Okta-claims → Overslash-group mapping in §4. Worth deciding whether this is in scope or a "manual assignment for v1."
- The OpenAPI import flow in step 6 is described in §9 but the *endpoint selection UX* (checkboxes, risk-tagging, scope_param assignment) is not specified in detail. Worth a §9 sub-section or a separate design doc.
- BYOC for Google Workspace (step 5) depends on the [google-workspace-oauth.md](google-workspace-oauth.md) doc being written — it's referenced from §7 but doesn't exist yet. Story 5 is the canonical use case for it.

---

## Story 6 — The `http` escape hatch

**Actors**
- **Hank** — power user at TinyCo (5-person startup, single-org Overslash deployment), member of a `PowerUser` group with `allow_raw_http: true`.
- **`automation-bot`** — Hank's general-purpose automation agent.
- **TinyCo's internal project tracker** — a private API at `internal.tinyco.com` that nobody has bothered to template because it's only used by 2 people and changes weekly.

**Goal:** Hank's agent needs to call an obscure internal API that has no template. The story exercises the `http` pseudo-service (Mode A), `secret:host` permission keys, multi-key tier composition in approvals, and the `allow_raw_http` group flag — and positions raw HTTP as a deliberate escape hatch, not a default.

### Happy path

1. **Request.** Hank tells `automation-bot`: *"create a row in the project tracker at internal.tinyco.com/api/projects with name='Q2 launch', owner=hank, status=planning."*
2. **Discovery turns up nothing.** `automation-bot` calls `overslash_search(query="project tracker")` — no template hits, no service. It tries `overslash_search(query="tinyco")` — still nothing. The agent recognizes there's no first-class integration and falls back to the raw HTTP path.
3. **Secret check.** `automation-bot` calls `overslash_auth(action="list_secrets")` and finds `tinyco_api_token` already stored on Hank's identity (Hank pasted it weeks ago via `/secrets/provide` for an earlier task). The agent has the metadata: secret name, version 1, last used 12 days ago. It does **not** see the value.
4. **Raw HTTP execute.** `automation-bot` calls `overslash_execute` with the `http` pseudo-service:
   ```json
   {
     "service": "http",
     "method": "POST",
     "url": "https://internal.tinyco.com/api/projects",
     "headers": { "Content-Type": "application/json" },
     "body": { "name": "Q2 launch", "owner": "hank", "status": "planning" },
     "secret_injection": [
       { "secret": "tinyco_api_token",
         "as": "header", "header_name": "Authorization", "prefix": "Bearer " }
     ]
   }
   ```
5. **Key derivation.** Overslash derives **two** permission keys from this single request (§8 *Secret Injection*):
   - `http:POST:internal.tinyco.com` — the raw HTTP key
   - `secret:tinyco_api_token:internal.tinyco.com` — the secret-injection key, scoped to this specific host so a token approved for one host cannot be exfiltrated to another (§5 *Pseudo-services*)
   
   Both keys must be covered for the request to execute.
6. **Layer 1 check.** Hank is in `PowerUser`, which has `allow_raw_http: true`. The raw HTTP path is permitted. (If Hank had been in Engineering instead, the request would be hard-denied at this layer regardless of any approval — `allow_raw_http` is a separate gate, not a service grant.)
7. **Layer 2 check + approval.** Neither key exists for `automation-bot`. Overslash creates an approval with **multi-key tier composition** (§5 *Specificity Tiers*) — keys broaden together as coherent sets, not independently:
   ```json
   {
     "id": "apr_...",
     "derived_keys": [
       { "key": "http:POST:internal.tinyco.com",
         "service": "http", "action": "POST", "arg": "internal.tinyco.com" },
       { "key": "secret:tinyco_api_token:internal.tinyco.com",
         "service": "secret", "action": "tinyco_api_token", "arg": "internal.tinyco.com" }
     ],
     "suggested_tiers": [
       { "keys": ["http:POST:internal.tinyco.com",
                  "secret:tinyco_api_token:internal.tinyco.com"],
         "description": "POST to internal.tinyco.com with tinyco_api_token" },
       { "keys": ["http:ANY:internal.tinyco.com",
                  "secret:tinyco_api_token:internal.tinyco.com"],
         "description": "Any request to internal.tinyco.com with tinyco_api_token" }
     ]
   }
   ```
   Notice there are only **2 tiers**, not 4 — multi-key requests compose within tiers to avoid combinatorial explosion (§5 design principle: "2-4 tiers max").
8. **Resolution.** Hank picks the most specific tier (POST + that secret + that host) with a 7-day TTL. Both keys are stored together as a coherent rule on `automation-bot`. Approval resolves, request executes.
9. **Execution.** Overslash builds the outbound request, injects the encrypted secret as `Authorization: Bearer ...`, fires the POST to `internal.tinyco.com`, returns the response body to the agent. The agent reports success to Hank: *"Created row 'Q2 launch'."*
10. **Audit forensics.** Audit log records the action with the qualified `http` pseudo-service, both derived keys, the host, the secret slot used, the request method/URL (but **not** body or response — those are too sensitive to log indiscriminately by default), and the resolution chain.

### Surfaces touched
- Meta tools: `overslash_search`, `overslash_auth.list_secrets`, `overslash_execute` with the `http` pseudo-service.
- Approval UI: rendering the multi-key tier composition (whatever surface Hank uses — dashboard, MCP, etc.).
- Audit: forensic record of raw HTTP usage.

### Spec coverage
§5 (`allow_raw_http` group flag, multi-key tier composition, `secret:` pseudo-service for host-scoped secret injection), §8 (`http` pseudo-service, secret injection metadata, derives keys from request).

### Notes / open questions
- **Position raw HTTP as deliberate, not default.** Most orgs should leave `allow_raw_http: false`. Spec §5 already says: *"Most orgs won't grant this — it turns Overslash into a general HTTP proxy."* The story should reinforce this — it's the right primitive for the rare case where templating isn't worth the effort (one-off tools, rapidly-changing internal APIs, exploration phase). For anything used more than a couple times, **make it a template** so you get human-readable descriptions, parameter validation, scoped permission keys, and discoverability via `overslash_search`. The escape hatch is a feature; using it routinely is a smell.
- **Vignette: contrast with MegaCorp.** A friend of Hank's at MegaCorp asks why MegaCorp's Engineering group doesn't have `allow_raw_http`. Answer: MegaCorp's security team disabled it because it bypasses the entire template review process — every external API at MegaCorp must go through a security review before becoming a template. That's the right default for a regulated environment. TinyCo gets to use the escape hatch because they're 5 people who all trust each other and need to move fast.
- **Audit body redaction policy** is mentioned in step 10 ("not body or response") but isn't actually specified in §12. Worth pinning down — the default should probably be metadata-only with an opt-in `audit.log_payloads: true` per service for high-sensitivity services where you want full forensics.

---

## Story 7 — Failure recovery and secret rotation

**Actors**
- **Bob** — same Bob from Story 2, ACME engineer using Linear via the user-owned `my-linear` service.
- **`automation-bot`** — Bob's automation agent (different from Story 2's MCP-as-himself flow; this one is an enrolled agent).
- **Sara** — ACME's security officer, org-admin, makes a brief appearance for the compliance vignette.

**Goal:** Story 2 ended with Bob's Linear service active on the happy path. This story takes the unhappy paths: a typo'd secret rejected by `verify`, retry on the same row, and later a leaked secret that needs rotation. Plus a brief org-admin compliance check at the end.

### Happy path

1. **Recap and create.** `automation-bot` calls `overslash_auth(action="create_service_from_template", template="linear", name="my-linear", scope="user")`. Overslash creates the row in `pending_credentials`, mints a `/secrets/provide/req_...?token=jwt` URL, and returns it along with the template's `instructions` field (§9 *Secret-Token Templates*): *"Paste your Linear personal API key. Find it at https://linear.app/settings/api"*. The agent surfaces the URL and instructions verbatim to Bob.
2. **Typo.** Bob clicks the URL, lands on the secret-provide page, and pastes his Linear API key — but he transposes two characters at the end. He hits Submit.
3. **Verify probe fails.** Overslash runs the template's `verify` probe (`GET https://api.linear.app/viewer` with `Authorization: Bearer <pasted-key>`). Linear returns `401 Unauthorized`. Overslash:
   - **Does not** flip the service to `active`
   - **Does not** flip it to `error` either — the failure is recoverable
   - Keeps the row in `pending_credentials`
   - Re-issues a fresh JWT for the same row (the previous one is now consumed and invalidated, §9 *Concurrent flows on one row*)
   - Re-renders the secret-provide page with an error banner: *"Linear rejected that key (401 Unauthorized). Double-check it at https://linear.app/settings/api and try again."* and a fresh empty input field.
4. **Retry on the same row.** Bob squints at his clipboard, realizes the typo, pastes the correct key, hits Submit. Verify probe runs against the new value, gets `200 OK`. Overslash encrypts and stores the secret as version 1, flips the service to `active`. The page redirects to a "Connected" confirmation. The agent learns about the transition via SSE.
5. **Use.** `automation-bot` proceeds with `linear:create_issue` and friends. Permission keys auto-approve from a previous Allow & Remember. Days pass.
6. **The leak.** Bob accidentally commits a `.env` file containing the Linear API key to a public GitHub repo. He realizes within 5 minutes (his pre-commit hook should have caught it but didn't — separate problem). He needs to rotate immediately.
7. **Rotation.** Bob opens the dashboard → **My Services → my-linear → Rotate Secret**. The dashboard calls `overslash_auth(action="rotate_secret", service="my-linear", slot="api_key")` on Bob's behalf. Overslash mints a fresh `/secrets/provide/...` URL (this is the same page used at bootstrap and for mid-flight requests — one page, three contexts now: bootstrap, mid-flight request, rotation). The dashboard opens the URL in a new tab.
8. **In-flight call survives.** Meanwhile, `automation-bot` is in the middle of a `linear:create_issue` call using **version 1** of the secret. That call is already past the secret-injection step — it's holding the old token in memory and the request is in flight against Linear. It completes successfully against the old (still valid) key. Linear hasn't been told yet that the key is compromised.
9. **Revoke upstream + paste new key.** Bob switches to Linear's web UI, revokes the leaked key, and generates a new one with the same scopes. He pastes the new key into the secret-provide page in the other tab. Verify probe runs against the new key — succeeds. Overslash creates **version 2** of the secret. The service stays `active` throughout the rotation — `pending_credentials` is for *initial* connection, not rotation (§9 lifecycle).
10. **Subsequent calls use latest.** The next `linear:create_issue` from `automation-bot` automatically picks up version 2 (latest, §6). The agent sees no change. The audit log records: *"secret `my-linear/api_key` rotated by user `bob` at T+0:42:13, version 2 created."*
11. **Rollback gone wrong, then forward fix.** A week later, a routine `linear:list_projects` call starts failing with `403 Forbidden`. Bob investigates and discovers the new (version 2) key was minted with narrower scopes than the original — he forgot to tick a box in Linear's UI. His instinct is to **restore version 1**, but version 1 is the leaked key (and revoked upstream anyway). Instead, he generates a third Linear key with the correct wider scopes, opens **Rotate Secret** again, pastes it. Version 3 is created. Audit log shows the full version history: who created each version, when, which calls used which version, and the time intervals between rotations. Bob can confidently see that version 1 has been unused for >7 days at this point (no risk of stragglers).
12. **Org-admin compliance vignette.** Sara (security officer, org-admin) does her monthly secret review. She opens **Org Settings → Secrets → All Org Secrets**. This view is org-admin-only and shows every secret across every user identity in ACME (§6 *Access Model*). For each secret she sees: name, owning identity, current version number, last-used timestamp, last-rotated timestamp. She does **not** see plaintext values — they remain encrypted at rest, and the API never returns them (§6). She spots:
    - `my-linear/api_key` belonging to `bob`, recently rotated twice — flags it for a quick chat with Bob (turns out: legit, the leak was caught immediately)
    - A secret on a former employee's identity, last used 6 months ago — Sara archives the identity (which cascades to its secrets and services)
    - A secret with no `last_used` at all — created 3 months ago, never used — likely a forgotten setup attempt; Sara DMs the owner.

### Surfaces touched
- `/secrets/provide/...` page (initial bootstrap, retry after verify failure, rotation — three contexts, one page).
- Dashboard: My Services → Rotate Secret (user view), Org Settings → All Org Secrets (org-admin view).
- Meta tools: `create_service_from_template`, `rotate_secret`.
- Verify probe against upstream Linear API.
- Audit log with secret-version history.

### Spec coverage
§6 (versioning, rotation, restore semantics, org-admin compliance access without plaintext exposure, last-used timestamps), §9 (`verify` pre-flight probe earning its keep, retry on same row without restarting flow, secret-provide page serves bootstrap + mid-flight + rotation), §12 (audit log secret-version history).

### Notes / open questions
- **In-flight rotation safety.** Step 8 assumes the in-flight call uses version 1 because secret resolution happens at the start of execution, not throughout. Worth pinning down in §6: "secret version is resolved once per outbound HTTP call, at the moment of injection. A rotation mid-call does not affect calls already past injection."
- **Rotation does not re-enter `pending_credentials`.** Worth stating explicitly in §9 — currently the lifecycle subsection talks about initial flows but doesn't address rotation. The clean rule: rotation is a `secret_version++` operation on an `active` service, never a state change.
- **Version restore policy.** Step 11 sidesteps restore (version 1 was leaked). But §6 mentions restore as a feature: "Earlier versions can be restored (creates a new version pointing to the old value)." Restoring should be guarded by a confirm dialog warning about leaked-secret scenarios — the dashboard should make it hard to footgun yourself by restoring a known-bad version.

---

## Story 8 — Security incident investigation

**Actors**
- **Sara** — ACME's security officer and org-admin (returning from Story 7).
- **Greg** — a former ACME employee whose offboarding was incomplete two weeks ago. His user identity is still active.
- **`data-export-bot`** — an agent Greg created months ago, with three sub-agent workers `exporter-1/2/3`.
- **PagerDuty** — fires an alert based on a webhook from Overslash's anomaly detection (or a downstream tool watching the audit log).

**Goal:** A security incident triggered by stale credentials. Sara needs to investigate via the audit log, contain via the identity hierarchy, revoke the source of the over-permission, and produce forensics for legal. The story exercises §11 dashboard views, §12 audit, §5 hierarchical disable + remembered approval revocation, and surfaces several SPEC gaps about offboarding cascades.

### Happy path

1. **The page.** PagerDuty fires: *"`data-export-bot` made 47 GitHub API requests in the last 5 minutes — anomalous."* Sara opens Overslash's dashboard at `acme.overslash.com`.
2. **Audit log search.** Sara navigates to **Audit Log**, filters by `identity prefix = spiffe://acme/user/greg/`, time range `last 1 hour`, event type `action_executed`. 47 entries appear: a flood of `github:list_pull_requests:*` and `github:get_pull_request_files:*` calls across many ACME repos, distributed across `data-export-bot`, `data-export-bot/exporter-1`, `exporter-2`, and `exporter-3`. She sorts by repo: the bot is iterating *every* private repo in the `acme` org and pulling diffs.
3. **Hierarchy tree view.** Sara opens **Identities → Tree View**. She sees:
   ```
   acme
     └── greg                       (user, last login: 14 days ago)
          └── data-export-bot       (agent)
               ├── exporter-1       (sub-agent, inherit_permissions=true)
               ├── exporter-2       (sub-agent, inherit_permissions=true)
               └── exporter-3       (sub-agent, inherit_permissions=true)
   ```
   Greg's user is still active despite his offboarding two weeks ago — the offboarding ticket got stuck in HR's queue. Sara takes a screenshot for the postmortem and immediately moves to containment.
4. **Containment via cascade disable.** Sara right-clicks Greg's user node → **Disable Identity (cascade)**. Overslash flips Greg's user to `disabled`, and the cascade disables `data-export-bot` and all three sub-agents immediately. Any in-flight requests fail with `identity_disabled`. New requests bearing those API keys are rejected at the auth middleware before reaching any business logic. The 47-call flood stops within seconds.
5. **Investigation: how did it get this much access?** Sara opens `data-export-bot` → **Remembered Approvals**. She sees:
   - `github:*:*` — approved by `greg`, no TTL, created 3 months ago. **Way too broad.**
   - `slack:post_message:*` — approved by `greg`, no TTL, created 2 months ago.
   - A handful of more reasonable scoped keys.
   
   The `github:*:*` rule was technically within Greg's group ceiling at the time — Engineering had `github (admin)` then, and Greg approved a broad rule because he was setting up an export tool and didn't want to be prompted again. **The upstream policy gap** is twofold: (a) Engineering had GitHub admin instead of write, and (b) Greg's approval had no TTL.
6. **Revocation.** Sara revokes the `github:*:*` rule and the `slack:post_message:*` rule from `data-export-bot`. The bot is already disabled, but she revokes the keys anyway for cleanliness — if Greg's user is ever re-enabled (unlikely now, but possible if the offboarding ticket gets moved instead of completed), the bot won't auto-approve those actions again on its own.
7. **Lock down inheritance.** Sara also flips `inherit_permissions: false` on each of the three sub-agents. Even in the unlikely scenario that they're re-enabled, they should no longer dynamically inherit from the parent — they would need explicit keys for everything.
8. **User-owned service archive.** Greg's user owned a personal `github` service instance (with his personal GitHub OAuth token, separate from ACME's org GitHub service — service shadowing from Story 5, step 12). This bypassed the org group ceiling for Greg's identity. Sara archives the service (§9 lifecycle: `active → archived`), which preserves audit and remembered approvals for forensics but makes it unusable. She also notes that this is a structural risk: **user-owned services can shadow org services and bypass ceilings**, which is a feature for normal users but a footgun for offboarding. She files a TODO to require org-admin review on user services that shadow org services.
9. **Audit export.** Sara exports the relevant audit log entries — last 30 days under `spiffe://acme/user/greg/`, including IPs (per [audit-log.md](audit-log.md) — the IP capture work shipped). The export is JSON, signed, includes the resolution chains for each action so legal can see exactly which identity at which depth approved what. She hands it off to legal and HR.
10. **Postmortem actions.** Sara files a list of follow-ups, none of which Overslash auto-fixes:
    - **Tighten Engineering group**: drop from `github (admin)` to `github (write)`. Audit which existing remembered approvals would now exceed the new ceiling and flag them for review (Overslash *should* offer this; it currently doesn't — gap).
    - **Require TTL on remembered approvals** (org policy). Overslash supports TTLs but doesn't enforce them as a policy. Worth adding an org setting `require_remembered_approval_ttl: true` with a default max TTL.
    - **Wire up offboarding cascade**. Currently Overslash has no integration with HR/IdP offboarding — Greg's Okta account being deactivated did not propagate to Overslash. Sara files a request: when an IdP reports a user as deactivated (via SCIM, or on next login attempt failure with `user_disabled` from the IdP), cascade-disable in Overslash. This is a real SPEC gap.
    - **User-owned services shadowing org services**: require org-admin review or at least flag in audit.
    - **Anomaly detection rules**: tune the PagerDuty alert thresholds — 47 calls in 5 minutes was caught, but a slower exfiltration over hours would not have been.
    
    Whole investigation took 8 minutes from page to containment, 30 minutes including the postmortem write-up. The audit + hierarchy + revocation surfaces did their job; the gaps are about *prevention*, not *response*.

### Surfaces touched
- Dashboard: Audit Log (search, filter, export), Identities (tree view, cascade disable), agent detail page (Remembered Approvals + revocation), service archive.
- Audit log API with IP capture (per [audit-log.md](audit-log.md)).
- Auth middleware: rejecting disabled identities at the boundary.

### Spec coverage
§5 (remembered approvals revocation, hierarchical disable cascade, ancestor-controls-descendant trust model in reverse), §9 (service archive lifecycle, service shadowing risk), §11 (dashboard org-admin views: audit, identity tree, remembered approvals, agent detail), §12 (audit log search/filter/export, IP capture, resolution chain in audit entries).

### Notes / open questions
- **SPEC gap: cascade disable.** §4 mentions disabling identities but doesn't specify cascade semantics. The story assumes "disable user → cascade to all descendants instantly." Worth pinning down in §4: cascade is mandatory, not optional, because partial-disable produces unsafe states.
- **SPEC gap: IdP-driven offboarding.** §4 covers user *provisioning* on first IdP login but not *deprovisioning*. Real-world: SCIM is the standard. Worth a §4 sub-section on offboarding (SCIM `DELETE /Users/{id}`, or detecting `user_disabled` on login attempt). Without this, every Overslash deployment will eventually have a Greg.
- **SPEC gap: required TTL on remembered approvals.** §5 makes TTL optional. Story 8 argues for an org policy `require_remembered_approval_ttl` that forces a max TTL. Default off for backward compatibility but easy to opt into.
- **SPEC gap: user-owned service shadowing audit.** §9 documents shadowing as a feature without flagging the offboarding risk. Worth adding a note + a dashboard surface that lists "user-owned services that shadow org services" so security can review them.
- **SPEC gap: anomaly detection.** Not in scope for Overslash itself (Overslash is an auth gateway, not a SIEM), but the audit log export format should be designed for easy ingestion by downstream tools (Splunk, Datadog, etc.). Worth a note in §12.
- **SPEC gap: post-revocation impact analysis.** Step 10 mentions: "audit which existing remembered approvals would now exceed the new ceiling." This is a useful tool that doesn't exist yet — when an org-admin tightens a group ceiling, Overslash should report which existing keys are now out-of-policy (and either auto-revoke them or flag them for review). Add to the §5 / §11 wishlist.

---

## Cross-story observations

### The original 3 stories (1–3): integration patterns

| Aspect | Story 1 (OpenClaw direct) | Story 2 (Corporate MCP) | Story 3 (Overfolder/Telegram) |
|---|---|---|---|
| User identity origin | Personal IdP (Google OIDC) | Corporate IdP (Okta OIDC) | Platform-managed, opaque to user |
| Platform layer | None | Claude Code MCP (thin) | Overfolder (thick) |
| Approval surfacing | Overslash standalone page | N/A (user acts as themselves) | Telegram inline buttons |
| Who calls resolve API | Alice via her own browser session | N/A | Overfolder, with Carol's stored creds |
| Permission layer used | Layer 2 (per-agent keys) | Layer 1 only (group ceiling) | Layer 2 (per-agent keys) |
| Notification needs | Synchronous, none | None | Webhook-driven, must dedupe |
| Audit identity | `spiffe://personal/user/alice/agent/openclaw-laptop` | `spiffe://acme/user/bob` (no agent) | `spiffe://overfolder/user/carol/agent/carols-assistant` |

These three cover the (user-managed vs corp-managed) × (no platform / thin platform / thick platform) matrix and exercise every standalone page, every meta tool, both permission layers, and every approval-resolution path described in §5.

### The new 5 stories (4–8): depth, lifecycle, escape hatches, failure, forensics

| Story | Primary axis | What it forces SPEC to specify |
|---|---|---|
| **4** Sub-agents | Hierarchy depth (depth=2), inherit_permissions live pointer, approval bubbling, ancestor-resolves-for-descendant | `resolve_descendant_approval` action on `overslash_auth`; TTL inheritance bound on resolved keys; visibility of `superseded` approval drops |
| **5** Org-admin onboarding | Day-1 dashboard flows, OpenAPI import, BYOC OAuth, hiding globals, user-initiated enrollment | OpenAPI import endpoint-selection UX; Okta group → Overslash group sync (or explicit "manual for v1"); google-workspace-oauth.md doc |
| **6** Raw HTTP escape hatch | `http` pseudo-service, secret:host keys, multi-key tier composition, `allow_raw_http` group flag | Audit body redaction policy; positioning of escape hatch as deliberate, not default |
| **7** Failure recovery + secret rotation | `verify` probe failure + retry on same row; secret rotation on active service; in-flight call safety; org-admin compliance access | "Rotation never re-enters `pending_credentials`"; secret-version resolved once per call; restore-version footgun guard |
| **8** Security incident | Audit log search/export, hierarchy cascade disable, remembered approval revocation, service archive, IdP-driven offboarding | Cascade disable semantics; SCIM/IdP-driven offboarding; required-TTL org policy; post-revocation impact analysis; user-owned shadowing audit surface |

### Spec feature coverage matrix

Beyond the matrix above, this is which SPEC concepts each story exercises (✅ = exercised in detail, ◐ = mentioned in passing, blank = not touched):

| Concept | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| User → Agent (depth=1) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Sub-agents (depth=2+) |  |  |  | ✅ |  |  |  | ✅ |
| `inherit_permissions` live pointer |  |  |  | ✅ |  |  |  | ◐ |
| Sub-agent TTL |  |  |  | ✅ |  |  |  |  |
| User-initiated enrollment |  |  |  |  | ✅ |  |  |  |
| Agent-initiated enrollment | ✅ |  | ◐ |  |  |  |  |  |
| OIDC IdP login (social) | ✅ |  |  |  |  |  |  |  |
| OIDC IdP login (corporate) |  | ✅ |  |  | ✅ |  |  |  |
| Layer 1 group ceiling |  | ✅ |  |  | ✅ | ✅ |  | ✅ |
| Layer 2 permission keys | ✅ |  | ✅ | ✅ |  | ✅ | ◐ | ✅ |
| `auto_approve_reads` |  |  |  |  | ✅ |  |  |  |
| `allow_raw_http` |  |  |  |  | ◐ | ✅ |  |  |
| Approval bubbling to gap |  |  |  | ✅ |  |  |  |  |
| Ancestor-resolves-for-descendant |  |  |  | ✅ |  |  |  |  |
| 3-pending cap (`superseded`) |  |  |  | ✅ |  |  |  |  |
| Specificity tiers (single key) | ✅ |  | ✅ |  |  |  |  |  |
| Multi-key tier composition |  |  |  |  |  | ✅ |  |  |
| Hard deny (`not_approvable`) |  | ✅ |  |  |  |  |  |  |
| Notification suppression |  |  | ✅ |  |  |  |  |  |
| Remembered approvals (Allow & Remember) | ✅ |  | ✅ |  |  | ✅ |  | ✅ |
| Remembered approval revocation |  |  |  |  |  |  |  | ✅ |
| Versioned secrets |  |  |  |  |  |  | ✅ |  |
| Secret rotation on active service |  |  |  |  |  |  | ✅ |  |
| Org-admin compliance access to secrets |  |  |  |  |  |  | ✅ |  |
| `on_behalf_of` |  |  | ✅ |  |  |  |  |  |
| OAuth: system credentials | ✅ |  | ✅ |  |  |  |  |  |
| OAuth: BYOC service-level credentials |  |  |  |  | ✅ |  |  |  |
| Service + defined action (Mode C) | ✅ | ✅ | ✅ | ✅ | ✅ |  | ✅ |  |
| Service + HTTP verb (Mode B) |  |  |  |  |  |  |  |  |
| `http` pseudo-service (Mode A) |  |  |  |  |  | ✅ |  |  |
| Secret injection via `http` |  |  |  |  |  | ✅ |  |  |
| Global templates | ✅ |  | ✅ |  | ✅ |  |  |  |
| Org templates |  | ✅ |  |  | ✅ |  |  |  |
| User templates |  |  |  |  | ◐ |  |  |  |
| OpenAPI import |  |  |  |  | ✅ |  |  |  |
| Hiding global templates |  |  |  |  | ✅ |  |  |  |
| Service shadowing (user/org) |  |  |  |  | ✅ |  |  | ◐ |
| Secret-token template `instructions` |  | ✅ |  |  |  |  | ✅ |  |
| Secret-token template `verify` |  | ◐ |  |  | ◐ |  | ✅ |  |
| Pending → active (OAuth flow) | ✅ |  | ✅ |  | ✅ |  |  |  |
| Pending → active (secret flow) |  | ✅ |  |  | ✅ |  | ✅ |  |
| Pending → error → retry |  |  |  |  |  |  | ✅ |  |
| Service archive |  |  |  |  |  |  |  | ✅ |
| Async event delivery: polling | ✅ |  |  | ◐ |  |  |  |  |
| Async event delivery: SSE |  |  |  | ◐ |  |  | ◐ |  |
| Async event delivery: webhook |  |  | ✅ |  |  |  |  | ◐ |
| `overslash_search` (services + templates) | ✅ | ✅ | ✅ | ◐ |  | ✅ |  |  |
| `overslash_execute` (any mode) | ✅ | ✅ | ✅ | ✅ |  | ✅ | ✅ |  |
| `overslash_auth.create_service_from_template` | ✅ | ✅ | ✅ |  |  |  | ✅ |  |
| `overslash_auth.create_subagent` |  |  |  | ✅ |  |  |  |  |
| `overslash_auth.list_secrets` |  |  |  |  |  | ✅ |  |  |
| `overslash_auth.rotate_secret` |  |  |  |  |  |  | ✅ |  |
| `overslash_auth.retry_credentials` |  |  |  |  |  |  | ✅ |  |
| `overslash_auth.resolve_descendant_approval` |  |  |  | ✅ |  |  |  |  |
| Standalone: enrollment consent | ✅ |  |  |  | ◐ |  |  |  |
| Standalone: approval page | ✅ |  |  |  |  |  |  |  |
| Standalone: secret-provide (bootstrap) |  | ✅ |  |  | ◐ |  | ✅ |  |
| Standalone: secret-provide (rotation) |  |  |  |  |  |  | ✅ |  |
| Dashboard: org-admin Settings/Groups/Templates |  |  |  |  | ✅ |  | ◐ | ◐ |
| Dashboard: API Explorer |  |  |  |  | ✅ |  |  |  |
| Dashboard: identity tree view |  |  |  | ◐ |  |  |  | ✅ |
| Dashboard: audit search/filter/export |  |  |  |  |  |  |  | ✅ |
| Dashboard: remembered approvals view |  |  |  |  |  |  |  | ✅ |
| Cascade disable identity |  |  |  |  |  |  |  | ✅ |
| Audit log: resolution chains | ◐ |  | ◐ | ✅ |  |  |  | ✅ |
| Audit log: IP capture |  |  |  |  |  |  |  | ✅ |

**Concepts still uncovered after all 8 stories:**
- **Service + HTTP verb (Mode B middle ground)** — the spectrum between defined actions and raw HTTP. Probably belongs as a vignette in Story 6 or as a tiny Story 9. Low priority.
- **SAML enterprise IdP**, **dev login**, **multi-IdP simultaneous on one org** — niche. Worth a one-paragraph "variants" appendix rather than a full story.
- **Identity reparenting** — mentioned in §4 but not exercised. Probably fits as a vignette in Story 5 or 8.
- **Domain-wide delegation** for Google service accounts — covered in the google-workspace-oauth.md research but no story uses it. Fold into the BYOC vignette in Story 5 or write a §7 sub-doc.
- **Rate limiting (§13)** — operational concern, deliberately skipped.
- **User template proposing/sharing to org level** — mentioned in §9 but not exercised. Minor.
- **Allow once (vs Allow & Remember)** — minor variant; not a story driver.

These gaps are all minor or operational. The 8 stories together exercise every load-bearing SPEC concept.
