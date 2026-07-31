# Overslash — Status

**Current state**: Phases 1–4 backend complete. Stripe billing live, monitoring stack deployed, dashboard mature (audit log, members, approval queue, billing flows all shipped). Mode A/B collapsed into a single Service + HTTP verb surface (SPEC §8). Public launch is gated on transactional email, human-facing docs, and the legal/compliance surface — see [TODO.md](TODO.md).

---

## Agent Tooling

- **PR mergeability Stop hook** (`.claude/hooks/pr-mergeability-gate.sh`, wired in `.claude/settings.json`): blocks Claude Code task agents from ending their turn until the current branch's PR satisfies all three mergeability gates — CI green (waits up to 10 min for pending checks via `gh pr checks --watch`), no unresolved review conversations (GraphQL `reviewThreads.isResolved`), and no merge conflicts (`mergeStateStatus != CONFLICTING`). When all gates pass, the hook arms `gh pr merge --auto --squash` so the PR enters the `dev` merge queue automatically. Capped at **N=5** block attempts per turn (tracked via `stop_hook_active` + a per-session counter under `$TMPDIR/overslash-pr-gate/`); after the 5th block the hook surfaces the failing gate(s) on stderr and allows the stop so a human can take over rather than looping forever. If there is no PR for the current branch, the hook is a no-op. The 'behind base' state is intentionally NOT gated — the merge queue handles up-to-dateness.
- **Merge queue on `dev`** (repo ruleset id `14770759`, `.github` settings): PRs target `dev` and are merged via GitHub's merge queue (squash, ALLGREEN grouping, required check `ci-ok`). The queue rebases each candidate against latest `dev` and merges when green, removing the agent's responsibility for keeping branches up-to-date with base. `dev` flows into `master` via merge commits (no squash) so feature history is preserved on `master`; the `master` ruleset (id `14707284`) enforces `merge`-commit-only.

## What Exists

- [SPEC.md](SPEC.md) — Full product specification
- [TODO.md](TODO.md) — Phased implementation roadmap
- [DECISIONS.md](DECISIONS.md) — Settled architectural decisions
- [TECH_DEBT.md](TECH_DEBT.md) — Known workarounds
- [docs/design/INDEX.md](docs/design/INDEX.md) — Design documents

## What's Built

### Phase 1 — Core Service (MVP) ✅

- Rust/Axum backend with Cargo workspace (`crates/overslash-api`, `crates/overslash-core`)
- PostgreSQL schema with sqlx migrations
- Full CRUD: orgs, identities, secrets (versioned + encrypted), API keys
- `POST /v1/actions/call` �� raw HTTP with secret injection (`http` pseudo-service)
- Permission rules (flat per-identity)
- Approval workflow (create, resolve with allow/deny/allow_remember, expiry loop)
- Audit trail (all actions, approvals, secret access)
- Webhook delivery (approval.created, approval.resolved)
- 8+ integration tests

### Phase 2 — OAuth + Service Registry (in progress)

- OAuth engine (authorization URL, code exchange, token storage, auto-refresh)
- BYOC credential resolution with fallback chain (identity → org → system)
- Three-tier OAuth credential cascade (SPEC §7): user BYOC → org-level secrets (`OAUTH_{PROVIDER}_CLIENT_ID/SECRET`) → system env vars. Org-level tier is managed via Org Settings → OAuth App Credentials (`PUT/GET/DELETE /v1/org-oauth-credentials/{provider}`). IdP configs (`org_idp_configs`) default to the same org secrets (migration 032 makes `encrypted_client_id/secret` nullable; login resolves from the org secrets when NULL), so rotating org credentials propagates to linked IdPs automatically.
- Connections API (initiate, list, revoke)
- OAuth connections bind to the **owner identity** on import/connect (DECISIONS D23) — `kernel_create_connection`/`kernel_import_connection` resolve the calling identity to its ceiling user (agent→`owner_id`) by default, so connections stop accreting on agents and every agent under a user shares one (storage complement to the D22 read path). `upgrade_scopes` accepts the caller's ceiling owner. Migration `086_connection_owner_identity` re-points existing agent-level rows to their owner, owner-wins-deduping against an existing owner connection for the same `(provider, account_email)`.
- White-label token vault (`POST /v1/connections/import`, migration `082_connection_token_vault`) — partners that own their OAuth run the dance themselves and import the resulting tokens; overslash stores/refreshes/injects them and issues no `redirect_uri`. The import **requires** a `byoc_credential_id` (null → 400); overslash self-refreshes hard-pinned to that client, never the env/org cascade. Auth-recovery for white-label end users is driven by a per-org `headless` flag (migration `084_orgs_headless`, admin-only `GET`/`PATCH /v1/orgs/{id}/headless`): for a headless org, `reauth_required`/`needs_authentication`/`missing_scopes` return **URL-less** envelopes (`headless: true`, no `auth_url`/`short`/`upgrade_url`, no flow row) so the integration re-runs its own dance and re-imports. The `connections.integration_managed` flag is **removed** (migration `085_drop_connection_integration_managed`) — it conflated refreshability with flow-ownership; the no-client import mode and the `connection.refresh_required` webhook are gone. Replaces and removes the per-request `redirect_uri` override + allow-list (#388/#392), the per-org `oauth_redirect_url` + `use_org_redirect` switch (#398), `POST /v1/oauth/exchange`, the `include_raw`/raw-authorize-URL surface, and `oauth_connection_flows.redirect_uri`. See [docs/design/white-label-token-vault.md](docs/design/white-label-token-vault.md).
- Global service template registry — OpenAPI 3.1 loader with `x-overslash-*` alias normalization, search API, and parse-don't-validate pipeline (PR #118)
- 10 service templates shipped as OpenAPI 3.1: Eventbrite, GitHub, Gmail, Google Calendar, Google Drive, Google Tasks, Resend, Slack, Stripe, X (plus the `overslash` platform namespace)
- `outlook` service — Microsoft Graph mail (Gmail-equivalent): profile, messages (search/read/send/move/delete), drafts (create/send), and mail folders, over `provider: microsoft` (already seeded). Structured `sendMail` JSON gives clean approval disclosure without base64 decoding
- OAuth for external MCP-runtime services — `x-overslash-mcp.auth: {kind: oauth, provider: …}` resolves the caller's owner connection (D22) into the outbound MCP bearer via the standard `oauth_providers`/`connections` machinery (shipped for HubSpot + Slack). `services/slack.yaml` wraps Slack's official MCP server (`mcp.slack.com/mcp`) and decorates the tools that benefit — `send_message` (write) with `disclose` + channel scope, ID-scoped reads with `scope_param` (DECISIONS D24). `template_oauth_provider` + `McpDetail.provider` extended so oauth MCP services auto-connect, validate pinned connections, and surface a dashboard connect affordance.
- Template/service instance split — templates (OpenAPI 3.1 blueprints with `x-overslash-*` extensions) + service instances (named, with credentials and lifecycle)
- Three-tier template registry — global (read-only, shipped OpenAPI) + org (CRUD by org admins) + user (CRUD, gated by `user_template_policy`) (PR #100)
- **Layered service templates** — every org/user template row is a **layer** (`extends`/`delta`, migration 097). A standalone layer holds a full OpenAPI doc; a **derived** layer holds a delta over a live base, resolved by the **fold** `apply(delta, resolve(extends))`. Masks (allowlist/denylist, risk clamp-up, additive disclose, relabel, hidden) are monotonic so containment is structural; extensions add actions/hosts only (no auth, no rebinding). `extends` is a live pointer (curation tracks upstream); discovery/instantiation/execution all read the effective surface. Pure fold in `overslash-core::service_layer`, shared walker in `services::template_resolve`, dashboard layer editor at `/services/templates/layer`. `allow_user_templates` → `user_template_policy` enum (`none`/`restrictive`(reserved)/`full`). (DECISIONS D29)
- Template validation endpoints — `POST /v1/templates/validate` (PR #108, struct-level OpenAPI lint, WASM-reusable) + `POST /v1/templates/validate-delta` (derived-layer delta lint against its resolved base)
- User-level services always visible to owner and their agents (PR #130)
- Per-service OAuth scopes declared end-to-end on templates and propagated through the authorization URL (PR #127)
- Service+action execution (registry-resolved, auth auto-resolved)
- Service + HTTP verb execution (SPEC §8) — instance + caller-supplied `method` + (`path`|`url`); auth from instance binding, host bounded by `svc.hosts`. Permission keys derive as `{service}:{METHOD}:{path}`.
- `connection: <uuid>` action calls removed (DECISIONS D14) — closes the host-binding gap; free-form authed calls go through Service + HTTP verb.
- `scope_param` on service actions — permission keys use specific args from action params. Accepts a list with per-entry scope labels (`[to:recipient, cc:recipient, bcc:recipient]`), deriving `{service}:{action}:{label}={value}` keys; value-only rules still match any label (DECISIONS D40).
- `on_behalf_of` for agent-initiated operations (PR #90) — agents create secrets and connections at the owner-user level so sibling agents share them
- Description interpolation — `{param}` substitution and `[optional segments]` in action descriptions
- Human-readable audit descriptions — interpolated descriptions for the action shape, `METHOD host/path` for the `http` pseudo-service, `identity_name` resolved in audit responses
- Suggested tiers + derived_keys on approval payloads (2-4 broadening levels)
- Approval resolution API aligned with spec (`resolution` + `remember_keys` + `ttl`)
- X.com OAuth with PKCE support
- Eventbrite OAuth provider support
- E2E tests against real providers: Eventbrite (OAuth), GitHub (PR #113), Google Calendar (PR #111), Google Drive (PR #107), Gmail (PR #115), Resend (token), X.com (OAuth+PKCE, PR #114), Outlook/Microsoft Graph (OAuth; mock e2e in CI + `#[ignore]` live test)
- sqlx compile-time query checking enforced across all repos
- **SQL content policy (D42/D43)** — `services/metabase.yaml` (API-key auth; `run_query`/`export_query` at `risk: dynamic`) + a Postgres-exact classifier (`pg_query`/libpg_query behind the default-off `sql_policy` feature; release builds and the e2e stack enable it, the Windows binary fails closed). `x-overslash-sql-field` nominates the SQL param and its body path (string params nest, object params are descended into); read-only SELECTs run as read-class per referenced table (`table={label}/{relation}` keys), everything else elevates to write and bubbles approval on the **mutation targets** (`table_mut={label}/{relation}` + mutation-shaped all-tables sentinel — a remembered read grant never authorizes writes, and "read anything, write only scratch" is expressible); `column=`/`column_star=` deny screening overrides even the `auto_approve_reads` bypass. Verified against a live Metabase + Pagila (`make metabase-e2e`).

### Phase 2.5 — Dashboard (in progress)

- SvelteKit dashboard scaffolded (`/dashboard/`) with TypeScript, Tailwind CSS, adapter-static
- Agents view redesigned per Figma (PR #105) — identity hierarchy tree with user node as immutable root, inline agent management
- Templates dashboard UI (PR #112) — global / org / user template list with Template Editor entry point and provider dropdown (PR #124)
- Services view — create from template, connect credentials, browse instances (Create Service surfaces user-level BYOC via `has_user_byoc_credential`, PR #131)
- Standalone Provide Secret page (PR #89) with User Signed Mode for attributed secret provisioning (PR #109)
- Developer Connection Tool — interactive API explorer with unified execution flow
  - Service/action selector with method and risk badges
  - Auto-generated parameter forms from action schemas (text, number, enum dropdowns)
  - Supports defined actions, custom HTTP requests, and raw HTTP (`http` pseudo-service)
  - Response panel with JSON syntax highlighting, headers table, request inspector
  - API key management with localStorage persistence
- 2026-04-10 review corrections applied — doc-level (PR #96) and dashboard-level (PR #99)
- Build/quality — zero-warning vite builds enforced (PR #125); Inter + Roboto Mono self-hosted via `@fontsource-variable` (PR #129)
- **Secrets dashboard view** — `/secrets` list (filtered by subtree per SPEC §6 — non-admins see only their own subtree, admins see the whole org) and `/secrets/{name}` detail (versions table, used-by, reveal modal, update-value, restore-version). Backend: `GET /v1/secrets` + `GET /v1/secrets/{name}` extended with `owner_identity_id` (now stored as an explicit column on `secrets`, set on first insert, preserved across versions via COALESCE), `created_at`/`updated_at`, `versions[]`, `used_by[]`. New endpoints `POST /v1/secrets/{name}/versions/{v}/reveal` (audit-logged as `secret.revealed`) and `.../restore` (audit-logged as `secret.restored`). Reveal / restore / detail stay session-only. `GET /v1/secrets` (list) accepts bearer auth and returns a narrow `{name, version_count, last_rotated_at}` shape to agent/sub-agent callers — values never leave the vault.
- **Audit Log dashboard view** (`/audit`, PR #238) — full-text + filter search over the audit trail with identity path, ref + UUID search, deep-linkable rows, and CSV export.
- **Approval queue redesign** — distilled approval card + queue UI (PR #250), auto-call-on-approve made universal with result piped to the webhook (PRs #239, #257), select-requesting-agent on deep-link with auto-call feedback (PR #245), shortened approval URLs via `oversla.sh` (PR #249).
- **Members page** (`/members`) — org membership listing + admin actions for the multi-org world.
- **API Explorer** — component library + interactive page; surfaced from service-instance views via a "Try it" button (PR #247).
- **Per-agent MCP Connection card** (PR #204, fixed in #211) — DCR / OAuth consent / disable / revoke surfaced inline on `/agents/{id}`; URL-driven `/agents/<id>` rationalization (PR #214).
- **Org service keys** mintable from Org Settings (PR #221).
- **Template catalog UX pass** (PR #237) + secret-name autocomplete with vault picker (PR #236) + `/services/templates/import` route scaffolded for OpenAPI bulk import.
- **Responsive shell** for tablet + mobile (PR #240); favicon (PR #241); `/docs/claude-code/` quickstart route.
- **Preview-deployment OAuth handoff** (PRs #242, #248) — server-side auth-state instead of cookies so Vercel preview URLs can complete OAuth.

### Phase 3 — Identity Hierarchy + Hierarchical Permissions

- Parent/child identity relationships with `parent_id`, `depth`, `owner_id` columns
- `IdentityKind` expanded: `user`, `agent`, `sub_agent`
- Hierarchy validation: users have no parent, agents require user parent, sub_agents require agent/sub_agent parent
- `inherit_permissions` dynamic resolution: when set, identity inherits parent's permission rules at query time (live pointer, not copy); chain walks upward through continuous `inherit_permissions=true` ancestors
- Ancestor chain query (recursive CTE) and children listing endpoints
- MCP OAuth 2.1 agent enrollment — `/oauth/authorize` pauses and routes through `/oauth/consent` (new-mode creates an agent under the signed-in user; reauth-mode rebinds a re-registered DCR `client_id` to the existing agent). Bespoke `/v1/enrollment-tokens` and `/v1/enroll*` flows retired — migration 042 drops `enrollment_tokens` + `pending_enrollments`.
- MCP enrollment org-scoping (D26, migration 095, design `mcp-enrollment-org-scoping.md`) — on a corp subdomain (`<slug>.api.overslash.com`) the enrolled agent's org is derived from the subdomain, not the session: a mismatched warm session is re-authed through the org IdP, the fast-path binding lookup is org-scoped (`mcp_client_agent_bindings` UNIQUE now includes `org_id`), and DCR clients are org-stamped (`oauth_mcp_clients.org_id`, NULL at root) so a client can't be replayed on another org's subdomain and the Org Settings → MCP Clients list/revoke is scoped to the admin's org. Root apex stays the multi-org hub (enrollment follows the session org, corp or personal — unchanged).
- Agent-facing `SKILL.md` at repo root, served at `/SKILL.md` by the API (cloud Vercel rewrite + self-hosted Axum route), documents the OAuth path + the `overslash mcp login` workaround for MCP clients without native OAuth support (e.g. OpenClaw).
- Standalone "Provide Secret" page (`/secrets/provide/req_{id}?token=jwt`): JWT-scoped, single-use, no-login secret submission. `secret_requests` table (migration 027), `POST /v1/secrets/requests` (mint), public `GET`/`POST /public/secrets/provide/{req_id}` (verify + submit), SvelteKit standalone route.
- **User Signed Mode** for the Provide Secret page (migration 031): opportunistic session binding (if the visitor's `oss_session` cookie is present and matches the request's org, their identity is recorded on `secret_versions.provisioned_by_user_id` and the `secret_request.fulfilled` audit row is attributed to them instead of the target identity), plus an org toggle `allow_unsigned_secret_provide` (**on by default** — defaults to true so existing orgs keep current behavior) exposed via new `GET/PATCH /v1/orgs/{id}/secret-request-settings`. When the toggle is flipped off, newly-minted requests carry `secret_requests.require_user_session = true` at mint time and reject anonymous submission with `401 user_session_required`. The toggle is forward-only — outstanding URLs keep the policy they were issued under. Cross-tenant sessions are silently ignored. Dashboard: org settings page exposes the toggle; the provide page switches to `credentials: 'same-origin'` and renders a "Signed in as …" banner or a "Sign in to continue" gate as appropriate.
- `GET /v1/identities/{id}/children`, `GET /v1/identities/{id}/chain`
- Sub-agent idle cleanup with two-phase archive — `last_active_at` touched per request, background loop (60s) archives idle sub-agents (revoking API keys with `revoked_reason='identity_archived'` and expiring pending approvals), then purges archived rows past the retention window. Parents wait for live children before archiving or purging. `POST /v1/identities/{id}/restore` un-archives within the window and resurrects auto-revoked API keys; manually-revoked keys are untouched. Archived identities return `403 identity_archived` from the auth middleware. Idle timeout (`subagent_idle_timeout_secs`, 4h–60d) and retention (`subagent_archive_retention_days`, 1d–60d) are configured per-org via `PATCH /v1/orgs/{id}/subagent-cleanup-config`.
- Hierarchical permission chain walk (SPEC §5): `call_action` walks the requester→user chain; each non-user level must authorize via own rules or `inherit_permissions`
- Approval bubbling: approval `identity_id` stays the requester; `current_resolver_identity_id` tracks who must act now; explicit `bubble_up` resolution and per-org `approval_auto_bubble_secs` background sweep advance the resolver up the chain
- Resolver authorization: only the current resolver, an ancestor of it, or an org-admin (no-identity) key can resolve a pending approval
- "Allow & Remember" rule placement targets the requester's closest non-`inherit_permissions` ancestor (inclusive), not the requester itself when it just borrows permissions

### Phase 4 — Groups (Layer 1 Permission Ceiling)

- `groups`, `group_grants`, `identity_groups` tables (migration 020)
- Group grants reference org-level service instances with structured access levels (`read`/`write`/`admin`)
- Raw HTTP is the synthetic `http` service instance (one system-managed singleton per org) — group access uses the standard grant mechanism with read/write/admin levels mapping to verb risk
- `auto_approve_reads` per-grant — auto-creates permission keys for non-mutating agent requests
- Full CRUD API: `POST/GET/PUT/DELETE /v1/groups`, grants, and member management
- Group ceiling check in action execution (Layer 1, before permission key check)
- Users gated by groups only — they are their own approvers (skip Layer 2)
- User-owned service instances bypass ceiling for the creator
- Service visibility filtered by group membership (`GET /v1/services`)
- Approval resolution validates `remember_keys` against group ceiling
- Backward compatible: no groups assigned = no ceiling enforced (permissive)

### Multi-Provider OIDC Authentication

- Generic OIDC provider support — `/auth/login/{provider_key}` and `/auth/callback/{provider_key}` replacing Google-specific routes
- OIDC Discovery — auto-discover IdP endpoints from `.well-known/openid-configuration` with SSRF protection
- GitHub social login — GitHub userinfo + email API integration
- Per-org IdP configuration — `org_idp_configs` table (CRUD API at `/v1/org-idp-configs`)
- Env var vs DB precedence — env vars (`GOOGLE_AUTH_CLIENT_ID`, `GITHUB_AUTH_CLIENT_ID`) take precedence over DB config
- Multiple IdPs per org simultaneously
- User provisioning by email domain matching (configurable per IdP config)
- Profile update on subsequent logins (name, avatar synced from IdP claims)
- Available providers endpoint — `GET /auth/providers?org=<slug>` for login page
- Backward-compatible Google login routes preserved

### Phase 4 — Rate Limiting

- Two-tier rate limiting: User bucket (shared by all agents) + optional per-identity caps
- Rate limit configuration API: `PUT/GET/DELETE /v1/rate-limits` with scopes: `org`, `group`, `user`, `identity_cap`
- Resolution chain: per-user override → group default (most permissive) → org default → system fallback
- Standard headers on all responses: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- 429 Too Many Requests with `Retry-After` header when exceeded
- Dual storage backend: Redis/Valkey (distributed) or in-memory DashMap (single-instance fallback)
- Fail-open on Redis errors; health endpoint exempt from rate limiting
- Fixed window counter algorithm with configurable window size

### Org Slug Subdomains (`<org>.app|api.overslash.com`)

- **Dual subdomain surface**: `*.app.overslash.com` (browser dashboard via Vercel wildcard) and `*.api.overslash.com` (programmatic / MCP / OAuth-AS via Cloud Run + GCLB). MCP clients hit `<slug>.api.overslash.com/mcp` directly, browsers hit `<slug>.app.overslash.com` and call the API cross-origin. The subdomain middleware accepts either suffix and dispatches the same way; `.well-known/oauth-authorization-server` and the MCP `WWW-Authenticate` challenge return per-subdomain issuer URLs so RFC 8414 discovery works on every org subdomain.
- **GCLB stack** (`infra/modules/api-lb/`): one global IP + wildcard managed cert (`api.overslash.com` + `*.api.overslash.com`) + serverless NEG → Cloud Run. URL map is a single catch-all — `subdomain_middleware` does the per-org dispatch in-process. Replaces the old `google_cloud_run_domain_mapping` (single-domain only). Toggled via `enable_api_lb=true` in tfvars.
- **Per-org default IdP** (migration 049, `org_idp_configs.is_default` + partial unique index): each org designates one enabled IdP as the default. `/oauth/authorize` on a corp subdomain bounces unauthenticated callers straight through the default; with no default but multiple IdPs, redirects to `/login` for the picker. Surfaced via `is_default` on `/auth/providers` and the create/update payload.
- **Strict trust-domain isolation on corp subdomains** (DECISIONS.md D12): `resolve_auth_credentials` no longer falls through to env-var creds when an org is in scope — only `org_idp_configs` for that org grant admission. Env-var-managed Overslash login keeps working at the root apex for personal-org sign-up / org-creator bootstrap.
- **Return-host preservation** across the apex-bound OAuth callback: when login originates on `<slug>.app.overslash.com` but the OAuth provider's pre-registered redirect_uri lands at the API apex, the callback reads `oss_auth_org` + `app_host_suffix` to build an absolute redirect back to the original subdomain so users don't get stranded on the apex.
- **`X-Forwarded-Host` trust**: subdomain middleware reads XFH first, falls back to `Host`. GCLB forwards Host unchanged but XFH support keeps Vercel rewrites and any future proxy chain working with one code path.
- **Wildcard CORS**: `DASHBOARD_ORIGIN` accepts `https://*.app.overslash.com` syntax (single-DNS-label predicate match — `evil.attacker.app.overslash.com` doesn't squeak through).
- **Dashboard**: org settings IdP card adds a "Default" column and "Set default" / "Unset default" actions. Login page on a corp subdomain auto-redirects when a single default IdP is set, preserving the `next=` query param so MCP-driven OAuth bounces resume cleanly.
- **Vercel**: `dashboard/vercel.json` adds wildcard host matchers for `*.app.overslash.com` (and `*.app.dev.overslash.com`), forwarding REST/auth paths to `api.overslash.com`. `/.well-known/*` and `/mcp` on `app.*` redirect to the matching `api.*` so programmatic clients always land on the canonical issuer.
- New env vars: `API_HOST_SUFFIX` (alongside the existing `APP_HOST_SUFFIX`); `SESSION_COOKIE_DOMAIN` typically `.app.overslash.com` for cross-subdomain cookie sharing.

### Multi-Org Auth

- Data model (`users`, `user_org_memberships`, `orgs.is_personal`, `identities.user_id`) live (migration 040). Design: [docs/design/multi_org_auth.md](docs/design/multi_org_auth.md). Trust-domain rule codified in DECISIONS.md D12.
- Session JWT carries `user_id` alongside `sub` (identity) + `org`. Legacy tokens without `user_id` keep working until they expire; extractors resolve the human via `identities.user_id` as a fallback.
- **Subdomain middleware** parses `Host` → `RequestOrgContext::{Root, Org}` and attaches it to request extensions. `SessionAuth` / `AuthContext` enforce `jwt.org == subdomain.org` and return 401 `org_mismatch` otherwise — the dashboard routes that through `/auth/switch-org`. `SINGLE_ORG_MODE=<slug>` bypasses the middleware for self-hosted single-org operators.
- **Login flow rewire** — root-login provisions an Overslash-backed user + personal org on first sign-in; org-subdomain login provisions an org-only user via one of two admission paths picked by the org admin: (a) the legacy domain-whitelist gate (`org_idp_configs.allowed_email_domains`, non-match → 403 `not_permitted_by_org_idp`), or (b) the invite-gated path (migration 066, `orgs.allow_overslash_managed_signin = true` — default for new corp orgs) where every sign-in must match a pending `org_invites` row regardless of IdP, non-match → 403 `not_invited`. No cross-IdP account linking — each IdP is its own trust domain.
- **Corp-org creation** — `POST /v1/orgs` creates the org + an admin `identities` row + a regular `admin` membership for the caller (when the session carries a `user_id`). The creator's Overslash-level login keeps working against the org indefinitely, whether or not the org later configures its own IdP. Gated by `ALLOW_ORG_CREATION` (returns 403 `org_creation_disabled` when disabled).
- **Account surface** — `POST /auth/switch-org`, `GET /v1/account/memberships`, `DELETE /v1/account/memberships/{org_id}` (personal-org + last-admin guards). `/auth/me/identity` now returns `user_id`, `personal_org_id`, `memberships[]`.
- **Session cookie** honors a configurable `Domain` (`SESSION_COOKIE_DOMAIN`, typically `.app.overslash.com`) so the same `oss_session` is shared across subdomains.
- **Dashboard** — `OrgSwitcher` in the sidebar footer (grouped Personal / Orgs, no per-row badges), `/account` page with leave-membership action, login page renders a corp-org empty state when no IdP is configured, `/org` hides IdP + OAuth-credential cards on personal orgs and shows a "configure an IdP" warning banner on corp orgs without one enabled.
- Migration 041 drops the pre-040 `identities.email` global UNIQUE, keeping a plain lookup index. Multi-org requires the same human's email to appear on multiple identity rows; the `(org_id, user_id)` partial UNIQUE from 040 continues to prevent double-admission per human per org.

### Billing (Stripe)

- Cloud billing surface — `/v1/billing/{config,geo,checkout,portal}`, `/v1/orgs/{id}/subscription`, signed `POST /v1/webhooks/stripe`. Checkout creates the Stripe customer + subscription, provisions the org on `checkout.session.completed`, then routes the session to the new org via `redirect_for_org` (PRs #213, #197).
- Geo-aware pricing — `/v1/billing/geo` reads `CF-IPCountry` (falls back to `X-Country-Code` / USD) and returns EUR for EU member states.
- Stripe customer portal — `POST /v1/billing/portal` returns a hosted self-service link; surfaced from `/billing/portal`.
- Automatic tax wired (`customer_update=auto`) for cross-border compliance.
- `free_unlimited` org tier + instance-admin self-service create (PR #217) for design partners + self-hosted accounts.
- E2E coverage — `crates/overslash-fakes/src/stripe.rs` ships a full Stripe fake driven by a Playwright Checkout flow (PR #231); `tests/billing.rs` + `tests/free_unlimited.rs` exercise the REST surface.
- Dashboard — `/billing/new-team` (Checkout entry), `/billing/portal`, `/billing/success`, `CreateOrgModal` deferring to checkout when `cloud_billing=true`.

### Monitoring & Observability

- OpenTofu module `infra/modules/monitoring/` (PRs #200, #205, #207, #272) deploys 5 GCP dashboards — `overview`, `api-use`, `actions-and-oauth`, `cloudsql-use`, `business` — plus P0/P1/P2 alert policies: API down, API 5xx > 1%, API P99 > 5s, Cloud SQL CPU/disk, background-task staleness, OAuth refresh failure ratio, webhook terminal failure ratio, plus uptime checks.
- OTel sidecar exports metrics into GMP (instance-label collision fixed in #272).
- Notification channels: email channel auto-provisioned when `alert_email` is set (`infra/env/dev.tfvars` already wired); PagerDuty channel auto-provisioned when `pagerduty_integration_key` is set. **Slack / PagerDuty integration keys are not yet bound** (see Launch Blockers in TODO.md).
- Public status page at <https://status.overslash.com> (Better Stack) with independent HTTPS uptime checks for `api.overslash.com` and `app.overslash.com`. Runbook: [`docs/runbooks/status-page.md`](docs/runbooks/status-page.md).
- JSON-format logs with `message`/`span`/`textPayload` surfaced through `make logs` (PR #198).

### Actions surface — unified

- Mode A (raw HTTP under a synthetic instance) collapsed into the `http` service singleton (PR #265, DECISIONS D15).
- Mode B (`connection: <uuid>` calls) killed; replaced by SPEC §8 Service + HTTP verb (PR #261, DECISIONS D14). Single `CallRequest` shape across all execution paths.
- Typed `reauth_required` + `needs_authentication` error envelopes (PR #259); structured 400 + dry-run `POST /v1/actions/validate` (PR #256); MCP tools/call surfaces the same typed envelopes (PR #263).
- Stable webhook envelope with routing headers (PR #258); connection lifecycle events emit webhooks (PR #260).

### MCP — additional surface (beyond the OAuth transport already documented)

- Tools annotated for client UX and `overslash_call` split into `overslash_read` (read-class fast-path, prompt-skip) + `overslash_call` (general) (PR #235).
- Metaservice bridge: service-instance kernels (PR #244), template-authoring (PR #246), `create_connection` (PR #253), `request_secret` kernel with signed-provide handshake (PR #252), capability-gated connection settings on OAuth consent (PR #215).
- Fan-out search per instance, actionable template-vs-instance errors (PR #243); nested OAuth for upstream MCP servers (PR #220); MCP Inspector CORS (PR #232).

### Not Yet Built

**Launch blockers** — tracked in [TODO.md](TODO.md):

- Transactional email subsystem (billing receipts + welcome + webhook DLQ digest; approvals and secret-requests stay in dashboard/webhook only).
- Corp-org invite flow (D12-compatible) and corp-subdomain login empty-state.
- Human-facing documentation site (concepts + REST reference + per-template quickstarts).
- DPA, security.txt, vulnerability disclosure policy, subprocessor list.
- Documented manual GDPR request process (export + hard-delete handled by hand at launch; automation deferred).
- Master-key rotation runbook + tested rotation; Postgres PITR restore drill.
- PagerDuty (or Slack) integration key bound to `infra/modules/monitoring/`.

**Dashboard residuals** (carry-overs from review cards `504a7` / `20ae2` / `2e268`):

- IdP config **edit** UI (backend `PUT /v1/org-idp-configs/{id}` already supports it — see TECH_DEBT.md §3).
- Notification bell dropdown in the top bar.
- Archived sub-agent list + restore button + per-org cleanup config form (backend shipped).
- Per-agent permission management UI (rules, scopes, "Allow & Remember" review/edit).
- Canonical `OVERSLASH_DASHBOARD_URL` env wired into approval URLs.
- Toggle Switch design-system component (`ToggleSwitch.svelte` lives but not adopted everywhere).
- `/account` profile editing (name + avatar).
- Org webhook management UI.

**Backend / API**:

- Approval visibility scoping (`?scope=actionable` vs `?scope=mine`).
- Webhook payload: include `gap_identity` and `can_be_handled_by` on approval events.
- User-to-org template sharing (propose / approve / deny; card `7e5ee`).
- OpenAPI bulk import UX completion (`/services/templates/import` route scaffolded; polish + overlay defaults pending).
- Ship 11 more service templates to hit the top-20 target (currently 9 + `overslash` namespace).
- Audit events on creator-admin add/remove on `POST /v1/orgs` and `DELETE /v1/account/memberships/{org_id}`.

### CLI + MCP — Surface Restructure (OAuth transport)

- Single binary `overslash` replaces the old `overslash-api` bin (crates: `overslash-cli`, `overslash-mcp`).
- Subcommands: `serve` (REST API only, cloud mode), `web` (REST + embedded SvelteKit dashboard, self-hosted), `mcp` (stdio↔HTTP shim), `mcp login` (OAuth 2.1 onboarding).
- **MCP over Streamable HTTP + OAuth 2.1** — `POST /mcp` on the API, gated by `Authorization: Bearer`. Two single-credential modes: user JWT (aud=mcp, minted via `/oauth/authorize` → `/oauth/token`) or static `osk_…` agent key. Dual-credential model is gone. Full design in [docs/design/mcp-oauth-transport.md](docs/design/mcp-oauth-transport.md).
- Authorization Server endpoints live in `overslash-api`:
  - `GET /.well-known/oauth-authorization-server` (RFC 8414) and `GET /.well-known/oauth-protected-resource` (RFC 9728).
  - `POST /oauth/register` (RFC 7591 DCR, public clients / PKCE only), `GET /oauth/authorize` (OAuth 2.1 §4.1 + PKCE, bounces through IdP login via `?next=`), `POST /oauth/token` (authorization_code + refresh_token grants with single-use rotation + replay detection), `POST /oauth/revoke` (RFC 7009).
  - Registered clients are visible + revocable in Org Settings → MCP Clients.
- `overslash mcp` is a thin stdio↔HTTP pipe: reads `~/.config/overslash/mcp.json` (`{ server_url, token, refresh_token?, client_id? }`), forwards stdin frames to `POST /mcp`, auto-refreshes on 401 once when a refresh_token is present.
- `overslash mcp login` runs the standard OAuth Authorization Code + PKCE flow against `/oauth/authorize` (browser + 127.0.0.1 one-shot listener), persists the resulting token, prints the editor config snippet.
- Four tools exposed by `POST /mcp`, each carrying MCP 2025-06-18 annotation hints (`readOnlyHint`/`destructiveHint`/`idempotentHint`/`openWorldHint`) so clients can present `overslash_search`/`overslash_read`/`overslash_auth` without a confirmation prompt and surface `overslash_call` as destructive:
  - `overslash_search` → `GET /v1/search` — unified service/action discovery (§10) with keyword + Jaro-Winkler fuzzy + optional local pgvector embeddings (`bge-small-en-v1.5`). Hybrid ranker; results fan out one row per configured instance with the callable name in top-level `service`, the underlying `template` for traceability, and hoisted `account_email`/`secret_name`. Env kill-switch `OVERSLASH_EMBEDDINGS=off` + boot-time pgvector preflight — falls back to keyword+fuzzy transparently on vanilla Postgres.
  - `overslash_read` → `POST /v1/actions/call` with `require_risk=read` — read-only fast-path. Same `service`/`action`/`params` shape as `overslash_call`'s fresh-call mode; the action handler rejects with HTTP 400 when the resolved action's risk is not `Read`. No `approval_id` field (resume is by definition write/destructive). `overslash` meta-service: only the read-class actions (`list_pending`, `get_result`, `get_events`, `list_services`, `get_service`, `list_templates`, `get_template`) are reachable through this tool.
  - `overslash_call` → `POST /v1/actions/call` — full surface (read/write/delete) plus approval resume via `approval_id`.
- **Real-time event stream** — `GET /v1/events/stream?topics=approvals,connections,secrets` (SSE, D45, [docs/design/event-stream.md](docs/design/event-stream.md)). Fixed 30s connection ceiling with `Last-Event-ID` resume per SPEC §10. Backed by a durable `events` table (`BIGSERIAL id` = the resume cursor) fanned out cross-replica by an `AFTER INSERT` `pg_notify` of the id alone + a per-replica `PgListener` → `tokio::broadcast`; no Redis. Events carry a frozen `audience uuid[]` mirroring `mine`/`assigned`/`actionable`, so the stream is identity-scoped rather than org-broadcast (deliberately narrower than `GET /v1/approvals`, which still has no ACL gate). Auth is the existing `AuthContext` (session cookie, `osk_` key, or MCP JWT); identity-bound credentials only, no query-param token. A single `services::events::emit` seam feeds the stream *and* webhooks so payloads cannot drift — it replaced all 8 `webhook_dispatcher::dispatch` call sites — and adds `secret_request.created`/`.fulfilled` (token/URL excluded from the payload). Per-replica caps: 4 streams/identity, 64/org, refused 429 + `Retry-After`. Dashboard consumes it via one shared `EventSource` (`stores/events.svelte.ts`): the approvals queue, detail view and notification bell update live, with their previous polling retained as fallback and the queue's "live" chip finally wired to real connection state. Not yet emitted: approval *expiry* (bulk cross-org sweep — see TECH_DEBT.md) and any `service.*` event.
- **Agent inbox** — the `overslash` meta-service carries `get_events` (poll for anything waiting on this identity: `approval_needed` / `ready_to_call` / `result_unread`) and `get_result` (fetch one execution's outcome via `GET /v1/approvals/{id}/execution`). Closes the hole where an action auto-executed under `auto_call_on_approve` was invisible to its requester: `/call` answers 409 once the execution is terminal, and `list_pending` used to drop terminal rows. `list_pending` now also retains terminal-but-unread executions. Read-tracking is server-side (`executions.result_viewed_at`), so `get_result` doubles as the acknowledgement and the event self-clears. Same feed on the CLI: `overslash inbox` and `overslash get-result <approval_id>`; classification is shared via `services::inbox`. `GET /mcp` remains a 405 — MCP itself has no push channel — but the transport-agnostic one now exists: `GET /v1/events/stream` (SSE, D45).
  - `overslash_auth` → dispatched per-action: `whoami` and `service_status`. The self-management actions (`list_secrets`/`request_secret`/`create_subagent`/`create_service_from_template`) have been intentionally pulled from the MCP surface — they live in the dashboard until `docs/design/agent-self-management.md` lands.
- `overslash web` + `embed-dashboard` Cargo feature embeds `dashboard/build/` (built with `@sveltejs/adapter-static`) via `rust-embed`. Cloud Vercel build path unchanged.
- Infra image still tagged `overslash-api:*` to keep Artifact Registry stable; only the in-container entrypoint changed (`overslash serve`).
- **MCP puppet client** (`crates/overslash-mcp-puppet`) — generic Streamable-HTTP MCP client with full SSE handling, used as the puppet for e2e flows. Ships as: a Rust library, a REST server (binary `overslash-mcp-puppet`) that the harness boots alongside the API, and a thin TS wrapper in `dashboard/tests/scenarios/mcp-puppet.mjs`. Per-call elicitation answers (FIFO queue) plus a suspend/resume API for inspect-then-answer tests. Replaces the slim fetch-based driver under `dashboard/tests/e2e/fixtures/`. Verified by 9 unit + integration tests against an in-test mock server, plus three Playwright specs (`mcp-capabilities`, `mcp-approval-bubbling`, `mcp-elicitation`).

## What's Deployed

- **Marketing site**: `www.overslash.com` — landing page with Terms and Privacy Policy.
- **Cloud infra**: dev environment provisioned via `infra/env/dev.tfvars` (Cloud Run + Cloud SQL + GCLB wildcard cert on `*.api.overslash.com` + monitoring module + Stripe webhook endpoint). Prod tfvars exists; GA cutover gated on Launch Blockers.
- **Local dev**: Docker Compose (Postgres on port 55432); worktree isolation via `make local`.

## Infrastructure

- **Repository**: `overfolder/overslash` (private, will be open-sourced)
- **Default branch**: `master`
- **CI**: GitHub Actions with coverage reporting, real OAuth provider tests
- **PR flow**: feature branches → `dev` → `master`
- **IaC**: OpenTofu under `/infra` — deploys to GCP Cloud Run with Cloud SQL, Artifact Registry, Secret Manager, Cloud Build, and optional Memorystore/DNS
- **Mailbox Gateway**: shared [overfwd](https://github.com/overspiral/overfwd) deployment on Cloud Run (`infra/modules/cloud-run-overfwd/`, `enable_overfwd`) serving `mailbox.overslash.com` / `mailbox.dev.overslash.com` — the `servers[0]` of `services/email.yaml`. Digest-pinned third-party image via the Artifact Registry Docker Hub mirror; requires a bearer key that the API supplies for every org through the platform-credential rung, so no org stores it (D39). Runbook: [docs/runbooks/mailbox-gateway.md](docs/runbooks/mailbox-gateway.md)
- **Docker**: Multi-stage Dockerfile (Rust build → Debian slim runtime), `docker-compose.prod.yml` for local prod-like testing
- **Environments**: `dev` (overslash-dev) and `prod` (overslash) via `infra/env/*.tfvars`
- **Deployment**: `make tofu-plan ENV=dev && make tofu-apply ENV=dev`
