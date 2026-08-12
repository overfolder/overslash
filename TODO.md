# Overslash — TODO

Roadmap to public launch. Phases 1–4 are shipped (see [STATUS.md](STATUS.md)); what remains is the commercial + trust surface around the product engine, plus the dashboard residuals that still ship visibly broken or missing.

Three blocks, in priority order:

1. **Launch Blockers** — must ship before opening the public signup funnel.
2. **Launch +1** — polish within the first weeks of GA.
3. **Backlog** — post-launch, not gating.

A PR can ladder up to a block by tagging its first line `[launch]`, `[launch+1]`, or `[backlog]`. When everything in §1 is checked, we cut GA.

---

## 1. Launch Blockers

### 1.1 Transactional email

No mailer exists today. Billing has no receipts and new accounts get no welcome / verification touch. Approvals and secret-requests are explicitly **not** email-driven — email is the wrong channel for real-time decisions (latency, deliverability, off-device), and the dashboard + webhook + `oversla.sh` link is the path of record.

- [x] Pick a provider and wire it (likely Resend — we already template a service for it). Config: `EMAIL_PROVIDER`, `EMAIL_FROM`, `EMAIL_REPLY_TO`; secret via the existing vault.
- [x] Templated emails — store templates in `crates/overslash-core/templates/email/` with `{var}` interpolation matching the audit-description style.
- [x] **Billing**: receipt on `invoice.payment_succeeded`; dunning on `invoice.payment_failed`; subscription canceled / trial ending.
- [x] **Welcome / first login** for both root signups and corp-org JIT provisioning.
- [x] **Webhook DLQ digest** → daily digest to org admins listing webhook endpoints with terminal failures.
- [x] Per-user unsubscribe state for non-transactional (welcome) emails only — billing emails are exempt by policy.
- [ ] (Optional, post-MVP) User-level opt-in email for newly remembered permissions — informational only, not a control surface.

### 1.2 Onboarding & trust domains

D12 keeps trust domains clean. Corp-org admins still need a way to onboard the *first* teammate before that teammate has logged in via the org's IdP. Slug squatting is intentionally **not** mitigated pre-launch — paid org creation is the natural gate; we'll deal with squatters reactively if any appear.

- [x] **Corp-org invite path** — email-gated against the org's `org_idp_configs.allowed_email_domains`. Invite resolves on first IdP login (binds the new identity to the invite's role). Does **not** bypass the IdP; only pre-authorizes the email.
- [x] Audit events on creator-admin add (`POST /v1/orgs`) and removal (`DELETE /v1/account/memberships/{org_id}` when the leaver is the original creator).
- [x] Login page on a corp subdomain renders a clear empty state when no IdP is configured + a "you've been invited, please log in via X" state when the visitor's email matches a pending invite.

### 1.3 Human-facing documentation site

`SKILL.md` covers agents. Humans (the people swiping the credit card) have nothing past `www.overslash.com`. The single biggest sales blocker after email.

- [-] Docs site at `docs.overslash.com` (or `/docs` on the marketing site). MDX or VitePress; ship as static.
- [ ] Concepts: identity hierarchy, permissions/approvals, secrets, services, groups, rate limits.
- [ ] Quickstart: 10-minute "first authed call" against Resend or GitHub.
- [ ] Per-template setup guides for the 9 shipped services (Eventbrite, GitHub, Gmail, Google Calendar, Google Drive, Resend, Slack, Stripe, X).
- [ ] REST API reference auto-generated from the routes (consider serving `/openapi.json` from the API and rendering with Scalar/Redoc).
- [ ] MCP setup guide (Claude Desktop, Cursor, Claude Code) — fold in `dashboard/src/routes/docs/claude-code/` content.
- [ ] Self-hosting guide (`overslash web`, OpenTofu module, single-org mode).

### 1.4 Operational readiness

Monitoring is deployed; paging and recovery procedures are not yet exercised.

- [x] Bind `pagerduty_integration_key` in `infra/env/prod.tfvars` (or a Slack channel via a custom notification channel) so P0 alerts actually page someone.
- [x] Public status page (Better Stack / Statuspage / Instatus) wired to the existing P0 uptime check + a manual override.
- [x] **Master-key rotation runbook** — documented procedure to rotate the AES-256-GCM master key with zero downtime (dual-key read, re-encrypt loop, drop old key). Run the drill end-to-end on dev.
- [ ] **Postgres PITR restore drill** — document and execute a full restore-to-new-instance against the dev DB; record RTO/RPO observed.
- [ ] On-call runbook: how to roll back a Cloud Run revision, how to disable a webhook target, how to revoke a leaked API key, how to suspend an org.

### 1.5 Legal / compliance

- [ ] (later) `security.txt` at `https://www.overslash.com/.well-known/security.txt` + vuln disclosure policy page.
- [ ] (later) DPA template + signing flow (DocuSign / PandaDoc / countersigned PDF). Procurement asks for this on every B2B deal.
- [x] Subprocessor list page on the marketing site (Cloud Run, Cloud SQL, Stripe, Cloudflare, Resend, configured IdPs). On www.overslash.com/privacy
- [ ] (later) **GDPR request handling** — document the manual process for data-export and hard-delete requests (intake → DPO ack → manual SQL → audit row). Automated endpoints are a post-launch backlog item; volume expected to be near zero at GA.

---

## 2. Launch +1 (first weeks after GA)

### 2.1 Dashboard residuals

- [ ] **IdP config edit UI** on `/org` — backend `PUT /v1/org-idp-configs/{id}` already supports it (TECH_DEBT.md §3).
- [ ] **Notification bell** dropdown in the top bar (review card `504a7`). Dashboard-side sibling of the agent inbox — the same "what's waiting on me?" question the `overslash` `get_events` action answers; reuse `services::inbox` classification rather than inventing a second one.
- [ ] **Archived sub-agents** — list + restore button on `/agents`, plus per-org cleanup config form (`subagent_idle_timeout_secs`, `subagent_archive_retention_days`).
- [ ] **Per-agent permission management** — rules, scopes, "Allow & Remember" review/edit on the agent detail page.
- [ ] **`/account` profile editing** — name + avatar editable.
- [ ] **Org webhook management UI** — list, create, rotate signing secret, disable.
- [ ] **Toggle Switch** component (`ToggleSwitch.svelte`) adopted everywhere replacing checkboxes (review card `2e268`).
- [ ] **OAuth Connections UX** (review card `c2575`): stop creating phantom Identity Provider + UUID connection when an admin adds a Google OAuth Client ID; reuse connections across services sharing the same provider; show provider email instead of UUIDs; support incremental scopes auth.
- [ ] **Services view fixes** (review card `73d90`): show username/email for service owners, fix `/users/{name}` 404, correct the `overslash` meta-service "Needs Setup" copy, group pills as a column, services connectable to groups from the detail view.

### 2.2 Templates & coverage

- [ ] Ship 11 more service templates to hit top 20 (priority order: Notion, Linear, Jira, Asana, HubSpot, Salesforce, Airtable, Discord, PagerDuty, Zendesk, Intercom).
- [ ] Complete the OpenAPI **bulk import** UX at `/services/templates/import` — currently scaffolded; needs overlay-default suggestions and a diff preview before save.
- [ ] **User-to-org template sharing** — propose / approve / deny flow (review card `7e5ee`).
- [ ] **Hard pins on `instance_defaults`** — a layer default is a *preset* an instance may override (D36, D38). Add an opt-in "not instance-changeable" flag so an org layer can mandate a value: the instance form renders it read-only and `instance_config::validate_config` rejects a key the layer has hard-pinned. Deferred deliberately — the preset is the useful case for per-instance values like a mailbox username, and a ceiling only matters once a layer wants to mandate an org-wide constant.

### 2.3 API surface gaps

- [ ] **Approval visibility scoping** — `GET /v1/approvals?scope=actionable` vs `?scope=mine` (Phase 3 carry-over).
- [ ] **Webhook payload**: include `gap_identity` and `can_be_handled_by` on approval events (Phase 3 carry-over).
- [ ] **Live Map follow-ups** (D57, dev-gated behind `OVERSLASH_LIVE_MAP`):
  - Structural agent→service edges from permission rules. Today they only
    appear once traffic reveals them, because `GET /v1/permissions` is
    per-identity and deriving them up front would cost one request per agent.
  - Node icons. Deferred because identities and services carry no icon field —
    the map renders monograms. Revisit when they do.
  - Resolve an approval from the map. The amber state is real (it comes off
    `approval.pending`); the design's click-a-packet Allow/Deny popover was
    dropped rather than built against a half-modelled in-flight approval.
  - The force layout's repulsion pass is O(n²) over every structural node,
    every frame — inherited from the design prototype. Fine for a few hundred
    nodes, and the reason the map is dev-gated is not this, but it is the first
    thing to fix if it ever ships wider. A spatial grid is the usual answer.
  - Decide whether `activity` can ever be on by default. It is the only topic
    whose volume scales with the gateway's hot path — one durable `events` row
    per call — so ungating it means answering that first.
- [ ] **MCP Login Flow Fixes** (review card `877cb`) — assignment/consent page served from dashboard, default `inherit_permissions=true` for new MCP agents, reuse the existing agent on reauth, hide revoked MCP clients from the UI after 3s.

---

## 3. Backlog (post-launch)

- Global service registry community contribution workflow (PR-based, with the validator endpoint as CI).
- Multi-region / data residency (EU instance separate from US).
- SOC 2 prep — separate workstream; controls audit, evidence collection, vendor (Vanta / Drata).
- Bulk permission operations on the Org Settings view.
- Light mode + theme toggle on the dashboard.
- More e2e: MCP approval-bubbling and elicitation full-chain (puppet + scaffold specs in; deterministic gap-trigger pending — likely via a seeded service template + a no-permissions sub-agent).
- Increase integration coverage across all API routes; unit tests for permission resolution; OAuth refresh + BYOC fallback edge cases.
- **Priority-aware compact truncation.** `compact_response::shrink_to_budget` applies uniform limits across the whole JSON tree, so a payload that ships column descriptors alongside rows (Metabase, BigQuery, Snowflake, most tabular APIs) spends the 8 KB budget on metadata before the truncator reaches the rows — a 254-row Metabase result renders as 10 rows plus `…+244 more items`. Make it priority-aware: detect the principal collection by shape, drop sibling metadata before it, and add a depth lever so nested descriptor subtrees (`cols[i].fingerprint`) collapse while their scalar leaves (`cols[i].name`) survive. Heuristic rather than a template `x-overslash-*` extension: the motivating traffic arrives over Mode A (`service: "http"`), which has no template action to annotate. D57 (advertised paging params, a reachable `filter`) and D61 (a cropped result now carries a URL to its own full bytes) both made this less urgent, but neither made it wrong.
- **Gated async** (D62, the largest gap in the first cut). `execution: "async"` on a call that hits the permission chain is accepted and then forgotten: the approval carries no async intent, so approving it runs the call synchronously, still bounded by the request cap. This is the shape that most wants async — a slow query that needed a human's approval. The design is settled and `approvals.execution_mode` already ships reserved for it: stamp it from `req.is_async()` in `permission_gate`, have `POST /v1/approvals/{id}/call` enqueue and return 202 instead of running inline, and have `spawn_auto_call` enqueue rather than call `execute_claimed_approval`. Needs a `create_approval` signature change through repo + scope, and the `async_call_gated.rs` tests that were planned and never written.
- **Template async markers.** Let an action declare that it runs async by default (`x-overslash-async-default`), resolved at template-resolution time rather than mid-flight, and surfaced in the MCP tool schema and `/v1/search` so a caller sees it before calling. This is the answerable half of D56's objection to auto-promotion: the response shape stays a function of the request plus the *published* contract. Worth its own decision record, since it revisits D56.
- **Hybrid mode** (`execution: "hybrid"`), speculative. Always wait up to N, then always return 202. Uniform, so callers know both shapes are possible for every hybrid call — unlike mid-flight auto-promotion, which makes the shape depend on how the upstream felt that second. Still needs an answer to the re-dial problem: the in-flight upstream request cannot be handed to a leased row without either sending it twice or degrading to a detached task with weaker guarantees. Do not build without solving that.
- **Do not auto-promote a long-running sync call to async.** Considered and rejected: promotion either re-dials the upstream (duplicate side effects, and there are no idempotency keys) or spawns a detached task (no lease, dies on scale-in — a second async path with strictly weaker guarantees than the first). It also makes the response shape depend on runtime behaviour rather than on the request plus the published contract. The cheap fix for the underlying need is to have the 504 name `execution: "async"` in its hint.
- Async execution follow-ups (D62): (a) `execution` on the `overslash_read` MCP tool — the canonical async case, a slow analytics query, is read-class, but that tool has its own required-args schema and body-builder so it needs a second forwarder plus tests; (b) binary async results — currently a 400, because `http_caller::call` runs bodies through `from_utf8_lossy` before they reach the row; the real fix is the worker writing to object storage with the row keeping `{result_url, mime, size_bytes}`, which needs a bucket + IAM in Terraform; (c) `NOTIFY`-driven wake-up so a queued job starts immediately instead of within one 2s tick — the `LISTEN` bridge already exists in `services::events::bus`; (d) `orgs.max_async_call_timeout_ms`, if an org ever complains that the sync ceiling they set to bound connection-holding also bounds their background jobs.

---

## Done

Through 2026-05. Highlights below; full detail in [STATUS.md](STATUS.md).

- **Phases 1–4 backend**: orgs, identities, secrets (versioned + encrypted), permission rules, approvals (with bubbling), webhooks, audit, API keys.
- **OAuth + Service Registry**: native OAuth engine with three-tier BYOC, 9 OpenAPI 3.1 templates, three-tier template registry, template validation endpoint, per-service scopes, `on_behalf_of`.
- **Mode A/B collapse** (SPEC §8): single Service + HTTP verb execution surface; typed `reauth_required` envelopes; dry-run `/v1/actions/validate`; stable webhook envelope.
- **Identity hierarchy**: parent/child + `inherit_permissions` live pointer; approval bubbling; sub-agent idle archive + retention (backend).
- **Groups (Layer 1 ceiling)**: read/write/admin grants, `auto_approve_level` (a second ceiling on the same ladder), raw HTTP as the `http` singleton.
- **Rate limiting**: two-tier (User bucket + identity caps), Redis/Valkey or in-memory, standard headers + 429.
- **Multi-provider OIDC** + per-org IdP configs + GitHub social login + email-domain provisioning.
- **Multi-org auth**: subdomain routing on `*.app|api.overslash.com`, switch-org, account memberships, corp-org creation with creator-admin.
- **MCP**: Streamable HTTP + OAuth 2.1 AS endpoints, `overslash mcp login` CLI, annotated tools split into `overslash_search` / `_read` / `_call` / `_auth`, metaservice bridge for self-management actions, typed error envelopes.
- **Stripe billing**: checkout-creates-org, customer portal, geo-priced EUR/USD, automatic tax, `free_unlimited` tier, full Stripe fake + Playwright Checkout e2e.
- **Monitoring**: 5 GCP dashboards (overview / api-use / actions-and-oauth / cloudsql-use / business) + P0/P1/P2 alerts + uptime + OTel sidecar + JSON logs.
- **Dashboard**: Agents tree, Services + templates, Secrets list + detail with reveal/restore, Audit Log with CSV export, Approval queue redesign, Members, Account, Billing flows, OAuth consent, API Explorer with Try-it, per-agent MCP Connection card, responsive shell.
- **Real-stack e2e**: scenarios library, MCP puppet client (Rust + REST + TS), OAuth fake AS, Auth0/Okta IdP fakes, Mode-C e2e against connected GitHub.
- **CLI**: single `overslash` binary with `serve` / `web` / `mcp` / `mcp login` subcommands.
