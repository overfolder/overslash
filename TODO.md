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

No mailer exists today. Approvals fan out only via webhook + dashboard; secret-request links must be hand-copied; billing has no receipts. This is the single biggest non-technical-buyer gap.

- [ ] Pick a provider and wire it (likely Resend — we already template a service for it). Config: `EMAIL_PROVIDER`, `EMAIL_FROM`, `EMAIL_REPLY_TO`; secret via the existing vault.
- [ ] Templated emails — store templates in `crates/overslash-core/templates/email/` with `{var}` interpolation matching the audit-description style.
- [ ] **Approval.created** → email the current resolver with the approval card + `oversla.sh` link. Re-fire on bubble.
- [ ] **Approval.resolved** → email the original requester's owner-user with outcome + auto-call result.
- [ ] **Secret request minted** → email the target (when known) with the signed-URL link.
- [ ] **Billing**: receipt on `invoice.payment_succeeded`; dunning on `invoice.payment_failed`; subscription canceled / trial ending.
- [ ] **Welcome / first login** for both root signups and corp-org JIT provisioning.
- [ ] **Webhook DLQ digest** → daily digest to org admins listing webhook endpoints with terminal failures.
- [ ] Audit row per send (`email.sent` / `email.failed`) so deliverability is debuggable.
- [ ] Per-user unsubscribe state for non-transactional (welcome) emails only — transactional emails are exempt by policy.

### 1.2 Onboarding & trust domains

D12 keeps trust domains clean. Corp-org admins still need a way to onboard the *first* teammate before that teammate has logged in via the org's IdP, and the org-creation endpoint is still trivially squat-able.

- [ ] **Corp-org invite path** — email-gated against the org's `org_idp_configs.allowed_email_domains`. Invite resolves on first IdP login (binds the new identity to the invite's role). Does **not** bypass the IdP; only pre-authorizes the email.
- [ ] **Slug squatting mitigation** on `POST /v1/orgs` — domain verification (DNS TXT) for corp slugs, or admin approval queue. Personal orgs unaffected.
- [ ] Audit events on creator-admin add (`POST /v1/orgs`) and removal (`DELETE /v1/account/memberships/{org_id}` when the leaver is the original creator).
- [ ] Login page on a corp subdomain renders a clear empty state when no IdP is configured + a "you've been invited, please log in via X" state when the visitor's email matches a pending invite.

### 1.3 Human-facing documentation site

`SKILL.md` covers agents. Humans (the people swiping the credit card) have nothing past `www.overslash.com`. The single biggest sales blocker after email.

- [ ] Docs site at `docs.overslash.com` (or `/docs` on the marketing site). MDX or VitePress; ship as static.
- [ ] Concepts: identity hierarchy, permissions/approvals, secrets, services, groups, rate limits.
- [ ] Quickstart: 10-minute "first authed call" against Resend or GitHub.
- [ ] Per-template setup guides for the 9 shipped services (Eventbrite, GitHub, Gmail, Google Calendar, Google Drive, Resend, Slack, Stripe, X).
- [ ] REST API reference auto-generated from the routes (consider serving `/openapi.json` from the API and rendering with Scalar/Redoc).
- [ ] MCP setup guide (Claude Desktop, Cursor, Claude Code) — fold in `dashboard/src/routes/docs/claude-code/` content.
- [ ] Self-hosting guide (`overslash web`, OpenTofu module, single-org mode).

### 1.4 Operational readiness

Monitoring is deployed; paging and recovery procedures are not yet exercised.

- [ ] Bind `pagerduty_integration_key` in `infra/env/prod.tfvars` (or a Slack channel via a custom notification channel) so P0 alerts actually page someone.
- [ ] Public status page (Better Stack / Statuspage / Instatus) wired to the existing P0 uptime check + a manual override.
- [ ] **Master-key rotation runbook** — documented procedure to rotate the AES-256-GCM master key with zero downtime (dual-key read, re-encrypt loop, drop old key). Run the drill end-to-end on dev.
- [ ] **Postgres PITR restore drill** — document and execute a full restore-to-new-instance against the dev DB; record RTO/RPO observed.
- [ ] On-call runbook: how to roll back a Cloud Run revision, how to disable a webhook target, how to revoke a leaked API key, how to suspend an org.

### 1.5 Legal / compliance

- [ ] `security.txt` at `https://www.overslash.com/.well-known/security.txt` + vuln disclosure policy page.
- [ ] DPA template + signing flow (DocuSign / PandaDoc / countersigned PDF). Procurement asks for this on every B2B deal.
- [ ] Subprocessor list page on the marketing site (Cloud Run, Cloud SQL, Stripe, Cloudflare, Resend, configured IdPs).
- [ ] **GDPR data export** — org-scoped dump endpoint (`POST /v1/orgs/{id}/data-export` → presigned URL with identities, secrets metadata only, audit log, approvals, services). Audit-logged.
- [ ] **GDPR hard-delete** — full erasure pipeline for an org or a user (cascades through identities, secrets, audit). Soft-delete with a 30-day grace, then hard purge.

### 1.6 Critical dashboard fixes

A short list — most dashboard work is in §2 polish. These three are visibly broken today.

- [ ] Inline "Allow Once" on `/agents` (review card `20ae2`) — current flow forces a round-trip to `/approvals/{id}`.
- [ ] Canonical `OVERSLASH_DASHBOARD_URL` env threaded through approval URLs (currently emits `overslash.example` in webhooks).
- [ ] Fix "Requested Invalid Date" rendering on Pending Approvals (review card `2e268`).

---

## 2. Launch +1 (first weeks after GA)

### 2.1 Dashboard residuals

- [ ] **IdP config edit UI** on `/org` — backend `PUT /v1/org-idp-configs/{id}` already supports it (TECH_DEBT.md §3).
- [ ] **Notification bell** dropdown in the top bar (review card `504a7`).
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

### 2.3 API surface gaps

- [ ] **Approval visibility scoping** — `GET /v1/approvals?scope=actionable` vs `?scope=mine` (Phase 3 carry-over).
- [ ] **Webhook payload**: include `gap_identity` and `can_be_handled_by` on approval events (Phase 3 carry-over).
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

---

## Done

Through 2026-05. Highlights below; full detail in [STATUS.md](STATUS.md).

- **Phases 1–4 backend**: orgs, identities, secrets (versioned + encrypted), permission rules, approvals (with bubbling), webhooks, audit, API keys.
- **OAuth + Service Registry**: native OAuth engine with three-tier BYOC, 9 OpenAPI 3.1 templates, three-tier template registry, template validation endpoint, per-service scopes, `on_behalf_of`.
- **Mode A/B collapse** (SPEC §8): single Service + HTTP verb execution surface; typed `reauth_required` envelopes; dry-run `/v1/actions/validate`; stable webhook envelope.
- **Identity hierarchy**: parent/child + `inherit_permissions` live pointer; approval bubbling; sub-agent idle archive + retention (backend).
- **Groups (Layer 1 ceiling)**: read/write/admin grants, `auto_approve_reads`, raw HTTP as the `http` singleton.
- **Rate limiting**: two-tier (User bucket + identity caps), Redis/Valkey or in-memory, standard headers + 429.
- **Multi-provider OIDC** + per-org IdP configs + GitHub social login + email-domain provisioning.
- **Multi-org auth**: subdomain routing on `*.app|api.overslash.com`, switch-org, account memberships, corp-org creation with creator-admin.
- **MCP**: Streamable HTTP + OAuth 2.1 AS endpoints, `overslash mcp login` CLI, annotated tools split into `overslash_search` / `_read` / `_call` / `_auth`, metaservice bridge for self-management actions, typed error envelopes.
- **Stripe billing**: checkout-creates-org, customer portal, geo-priced EUR/USD, automatic tax, `free_unlimited` tier, full Stripe fake + Playwright Checkout e2e.
- **Monitoring**: 5 GCP dashboards (overview / api-use / actions-and-oauth / cloudsql-use / business) + P0/P1/P2 alerts + uptime + OTel sidecar + JSON logs.
- **Dashboard**: Agents tree, Services + templates, Secrets list + detail with reveal/restore, Audit Log with CSV export, Approval queue redesign, Members, Account, Billing flows, OAuth consent, API Explorer with Try-it, per-agent MCP Connection card, responsive shell.
- **Real-stack e2e**: scenarios library, MCP puppet client (Rust + REST + TS), OAuth fake AS, Auth0/Okta IdP fakes, Mode-C e2e against connected GitHub.
- **CLI**: single `overslash` binary with `serve` / `web` / `mcp` / `mcp login` subcommands.
