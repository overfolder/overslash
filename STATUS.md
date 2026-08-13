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
- Account hints on the authorize URL (migration `106_oauth_login_hint_param`) — a reconnect returns the user to the account the connection already belongs to instead of whichever provider session the browser happens to hold. `kernel_create_connection_for_identity` derives the hint from the connection's `account_email` whenever `upgrade_connection_id` is set, so every reconnect path inherits it (`POST /v1/connections/{id}/upgrade_scopes`, the dashboard Reconnect button, and the action handler's `reauth_required`/`missing_scopes` minters). Fresh flows accept an explicit `login_hint` on `POST /v1/connections`, MCP `overslash.create_connection`, and as an override on `upgrade_scopes`. The parameter *name* is per-provider (`oauth_providers.login_hint_param`, exposed on `GET /v1/oauth-providers/{key}`): `login_hint` for Google/Microsoft and OIDC-discovered custom providers, `login` for GitHub (the synthetic `{login}@users.noreply.github.com` label is unwrapped back to the username first), NULL — and therefore dropped, never sent — for LinkedIn/HubSpot/Slack/Notion/Spotify/X/Eventbrite, none of which take a per-user hint.
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
- **SQL content policy (D42/D43)** — `services/metabase.yaml` (API-key auth; `run_query`/`export_query` at `risk: dynamic`) + a Postgres-exact classifier (`pg_query`/libpg_query behind the default-off `sql_policy` feature; release builds and the e2e stack enable it, the Windows binary fails closed). `x-overslash-sql-field` nominates the SQL param and its body path (string params nest, object params are descended into); read-only SELECTs run as read-class per referenced table (`table={label}/{relation}` keys), everything else elevates to write and bubbles approval on the **mutation targets** (`table_mut={label}/{relation}` + mutation-shaped all-tables sentinel — a remembered read grant never authorizes writes, and "read anything, write only scratch" is expressible); `column=`/`column_star=` deny screening overrides even the `auto_approve_level` bypass. Verified against a live Metabase + Pagila (`make metabase-e2e`).

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
- **Service icons** (D63) — templates carry `info.icon`, implicit from the template key whenever Overslash ships an asset by that name, so 18 of the shipped templates declare nothing and still render a mark. Built-in assets are generated from `simple-icons` into `assets/service-icons/` by `make service-icons`, baked into the API binary, and served unauthenticated at `GET /icons/{key}.svg` with an ETag. Templates may instead declare an `https://` URL; nothing else reaches a browser. Surfaces as an absolute `icon_url` on the template and service-instance responses, rendered by `ServiceIcon.svelte` over the existing letter tile. Slack, LinkedIn, Eventbrite and Outlook ship no mark yet (each absent from simple-icons) and keep their monograms. Four glyphs are authored by us rather than sourced — `email`, `deepwiki`, `overslash` and `http` — the last a globe, since Mode A is not a vendor and the mark stands for "any URL you supply".
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
- `auto_approve_level` per-grant (`none`/`read`/`write`/`admin`, D53) — a second ceiling on the same ladder, bounded by `access_level`: calls at or below the level skip Layer 2 entirely. Defaults to `none` on a new grant, `read` on the auto-created Myself grant. Deny rules still bind on auto-approved mutations.
- Full CRUD API: `POST/GET/PUT/DELETE /v1/groups`, grants, and member management. `GET /v1/groups` reports `is_member` for the calling identity (resolved through their ceiling user)
- Org-level service creation (`user_level: false`) requires a non-empty `groups` array on `POST /v1/services`, and at least one named group must be one the creator belongs to — an org-level instance has no Myself group, so without a grant nothing can reach it. The dashboard's `/services/new` form surfaces the picker and blocks submit until it's satisfied
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
- **One sign-in resolver** (`crates/overslash-api/src/services/org_signin.rs`): a single answer to "which providers can this org sign in with, on whose OAuth app", read by `/auth/providers`, `/oauth/authorize`, `/v1/org-idp-configs` and `resolve_auth_credentials`. An `org_idp_configs` row claims its provider key — disabled means that provider is off for the org, not that Overslash's app takes over — and the Overslash-managed providers fill the unclaimed keys when `allow_overslash_managed_signin` is on. Before this, each handler re-derived the rule and they disagreed: `/oauth/authorize` had never learned about managed sign-in and returned 503 `login_required` for orgs that used it instead of a dedicated IdP.
- **Per-org default IdP** (migration 049, `org_idp_configs.is_default` + partial unique index): each org designates one enabled IdP as the default. `/oauth/authorize` on a corp subdomain bounces unauthenticated callers straight through it; with no default it goes straight to a lone provider, or to `/login` for the picker when there are several. Surfaced via `is_default` on `/auth/providers` and the create/update payload.
- **Corp-subdomain login bounces target the app host**: anything that *starts* a login for an org (the `/oauth/authorize` IdP bounce) redirects to `https://<slug>.<app-apex>/…`, not a host-relative path. The `oss_auth_*` cookies carry `Domain=SESSION_COOKIE_DOMAIN` (`.app.<apex>`), so a login kicked off on `<slug>.api.<apex>` — the host the AS metadata advertises as `authorization_endpoint` — would have its cookies rejected by the browser and die at the callback. Deployments with no `APP_HOST_SUFFIX` keep the relative path.
- **Trust-domain isolation on corp subdomains** (DECISIONS.md D12 + its 2026-05 amendment): an org's own `org_idp_configs` rows are the default path; the Overslash-managed providers are available only where the org opted in via `allow_overslash_managed_signin`, and admission stays a separate gate (pending invite identity, or `managed_signin_allowed_domains`). Env-var-managed Overslash login keeps working at the root apex for personal-org sign-up / org-creator bootstrap.
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
- **Account surface** — `POST /auth/switch-org`, `GET /v1/account/memberships`, `DELETE /v1/account/memberships/{org_id}` (personal-org + last-admin guards). `/auth/me/identity` now returns `user_id`, `personal_org_id`, `memberships[]`, `invitations[]`.
- **Invitee-side invitations** (D52) — `GET /v1/account/invitations`, `POST /v1/account/invitations/{id}/accept`, `POST /v1/account/invitations/{id}/decline`. Keyed on the caller's IdP-verified `users.email`, so it lists invitations from orgs they haven't joined; accept links the pending identity + creates the membership in place (refused with `org_requires_idp_signin` for orgs running their own IdP), decline archives it as `invite_declined`. Surfaced as a **Pending invitations** section at the bottom of the dashboard sidebar, above the org switcher.
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
- Re-fetchable call results (DECISIONS D62): a `verbose: false` render that truncates stores the full `ActionResult` (encrypted, `call_results` table, migration 111) and stamps `_full_result.download_url` into the same envelope as the cropped body. Redeemed through the existing `GET /v1/downloads/{token}`, which now branches on `call_result_id` to serve stored bytes instead of replaying upstream. `CALL_RESULT_MAX_BYTES` (1 MB, `0` disables); shares `DOWNLOAD_TOKEN_TTL_SECS`. Side effect: `deliver: "url"` now effectively works for OAuth-authenticated services on the re-fetch path, since a result-backed token dials nothing. Complements D57, which mints a token for the *same request* when the transport cap trips and no body ever existed; this one serves *stored bytes* and dials nothing. Truncation itself is unchanged — priority-aware compaction is in TODO.md §3.
- Layered call timeouts (DECISIONS D56): `timeout_ms` per call, `x-overslash-timeout_ms` per action, `x-overslash-default_timeout_ms` per service, `call_timeout_ms` / `max_call_timeout_ms` per org, `CALL_TIMEOUT_MS` / `CALL_TIMEOUT_MAX_MS` per deployment. 504 carries `timeout_source`. The previously-unbounded inline path is now bounded; streaming bounds time-to-first-byte and guards the transfer with a per-chunk idle timeout. `CALL_TIMEOUT_MS` is pinned to 110000 in Cloud Run for the rollout, to be removed once audit percentiles confirm nothing legitimate lives above 30s.
- List-heavy actions have a middle gear (DECISIONS D61). `GET /v1/search` action rows now carry `params` — the action's caller-supplied contract (name/type/required/description/enum/default), required-first then alphabetical, `instance-config` params excluded — so a declared paging parameter is discoverable instead of folklore. `filter` is declared on the `overslash_call` / `overslash_read` MCP tool schemas and forwarded (bare jq string lifted into `{lang, expr}`), and now actually applies on the MCP-runtime and platform-runtime forks, which previously accepted it and silently ignored it. A `response_too_large` 502 carries a pre-minted `download_url` + `expires_at` for the same request (best-effort: OAuth-injected services and inline raw-HTTP credentials still get the plain 502), and the compact truncation hint leads with narrowing rather than `verbose=true`. `services/metabase.yaml` gains `limit`/`offset`/`archived` on `search`, the real `f` enum + `model_id` on `list_cards`, and new `popular_items` / `recents` actions; `export_query` now declares a `responses:` block so it compiles to a binary response type instead of being buffered against the size cap.
- Async (non-blocking) action calls (DECISIONS D62), behind `ASYNC_EXECUTION_ENABLED` (default off): `execution: "sync" | "async"` on `POST /v1/actions/call`, a 202 `accepted` envelope carrying `execution_id`, and a claim-and-lease worker that runs the call off the request path. Executions become a resource of their own (`GET /v1/executions`, `GET /v1/executions/{id}`, `POST /v1/executions/{id}/cancel`), with a new `executions` event topic, a dashboard list + detail page, MCP `get_execution` / `cancel_execution`, and `overslash get-execution`. This is what the D56 over-ceiling 400 now points at. Gated calls are covered too (DECISIONS D66): the request's mode is stamped on `approvals.execution_mode`, and triggering the approved replay — manually or via `auto_call_on_approve` — queues it for the worker and answers 202 instead of dialling inline, with the synchronous claim excluded by an `AND request IS NULL` predicate so the two triggers can never both reach the upstream. Async is bounded by `ASYNC_CALL_TIMEOUT_MAX_MS` (default 900000) rather than the 110000 sync ceiling, because that number exists to sit under a proxy's request cap and no proxy is counting an async call.
- `execution: "hybrid"` (DECISIONS D68), same flag: the call runs off the connection from the first byte, and the connection waits on it for `HYBRID_HANDOFF_MS` (default 5s, per-call `handoff_after_ms`). Beat it and the caller gets the ordinary `called` envelope — now carrying `execution_id` — and miss it and the caller gets the same `accepted` envelope async returns. The row is inserted **already claimed** before anything is dialled, so it is durable either way and no worker can take it; a hybrid row whose replica dies is failed as `hybrid_instance_lost`, never requeued, because the upstream already received the request. `HYBRID_MAX_INFLIGHT` (default 32) caps concurrent hybrid jobs per replica, and over it a call degrades onto the ordinary async queue with the same envelope. `origin` distinguishes `hybrid` from `async_call`. A gated hybrid call is queued exactly as a gated async one is.
- Execution results are no longer readable org-wide. `GET /v1/approvals/{id}/execution` checked only org scope, so any identity-bound credential in the org could read any execution's upstream body; `GET /v1/approvals/{id}` and the approvals list embedded the same body. All four paths now go through `services::execution_access` (admin, or the requester, or write access plus ancestry over the requester or the resolver), and a viewer outside that set gets `result_redacted: true` instead of the payload.

- Display-param resolvers are cached (DECISIONS D64). An `x-overslash-resolve` answer — display string *and* the `scope`-derived canonical value — is reused for a bounded window instead of costing an authenticated round trip on every `/v1/actions/call`. Valkey-backed when `REDIS_URL` is set, process-local `DashMap` otherwise; every operation is bounded at `RESOLVE_CACHE_TIMEOUT_MS` and fails open to a live resolve. The lookup runs before credentials are assembled, so a full hit skips the vault decrypt on HTTP and `build_client` (vault reads + blocking DNS) on MCP. TTL is `cache_ttl:` per resolver, else `RESOLVE_CACHE_TTL_SECS` (300s), clamped by `RESOLVE_CACHE_SCOPE_TTL_MAX_SECS` when the resolver canonicalizes a permission key; failures cached separately for 30s. Values are keyring-encrypted, and the key carries a credential fingerprint so gmail's `userId: me` cannot serve one user's address to another. `services/gmail.yaml` pins `cache_ttl: 3600` on the 19 `me → profile` resolvers.

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
- **Real-time event stream** — `GET /v1/events/stream?topics=approvals,connections,secrets` (SSE, D45, [docs/design/event-stream.md](docs/design/event-stream.md)). Fixed 30s connection ceiling with `Last-Event-ID` resume per SPEC §10. Backed by a durable `events` table (`BIGSERIAL id` = the resume cursor) fanned out cross-replica by an `AFTER INSERT` `pg_notify` of the id alone + a per-replica `PgListener` → `tokio::broadcast`; no Redis. Events carry a frozen `audience uuid[]` mirroring `mine`/`assigned`/`actionable`, so the stream is identity-scoped rather than org-broadcast (deliberately narrower than `GET /v1/approvals`, which still has no ACL gate). Auth is the existing `AuthContext` (session cookie, `osk_` key, or MCP JWT); identity-bound credentials only, no query-param token. Approvals carry three "needs a decision" events — `approval.created`, `approval.bubbled` (user or auto-bubble sweep) and the derived `approval.pending` (fires after both; the inbox signal, stream+webhooks only, no audit row) — and one terminal event, `approval.resolved`, whose `status` distinguishes a human verdict (`allowed`/`denied`), a cascade, and the background expiry sweep (`expired`, `resolved_by: "system"`, plus an `approval.expired` audit row). A single `services::events::emit` seam feeds the stream *and* webhooks so payloads cannot drift — it replaced all 8 `webhook_dispatcher::dispatch` call sites — and adds `secret_request.created`/`.fulfilled` (token/URL excluded from the payload). Per-replica caps: 4 streams/identity, 64/org, refused 429 + `Retry-After`. Dashboard consumes it via one shared `EventSource` (`stores/events.svelte.ts`): the approvals queue, detail view and notification bell update live, with their previous polling retained as fallback and the queue's "live" chip finally wired to real connection state. The expiry sweep returns rows rather than a count so it can emit per approval; it stays bounded by a `MATERIALIZED`-CTE `LIMIT` per statement and a capped number of batches per 60s tick. Not yet emitted: any `service.*` event.
- **Live Map** — `/map` in the dashboard: a radial force-directed graph of the org's fleet (users at the centre, agents and subagents orbiting, services on an outer ring) with packets animating along the edges as calls happen. **Dev-gated** behind `OVERSLASH_LIVE_MAP` (D57), reported to the dashboard as `live_map` on `GET /v1/version`, which is what gates the nav item. Fed by a fourth stream topic, `activity`, carrying `action.called` / `action.completed` — the first events on the action call path, emitted from the `call_action` metrics wrapper so the outcome taxonomy (`called | denied | rejected | failed | upstream_error`) is stated once. Audience is `chain(actor)`, so an admin sees the whole org and a member sees their own chain, with no second ACL. Structure comes from `GET /v1/identities` + `GET /v1/services`; agent→service edges are activity-derived (there is no bulk permissions endpoint) and expire after five idle minutes. Approvals show as an amber node state off `approval.pending`/`.resolved`; resolving from the map is not wired. User nodes draw their IdP avatar and service nodes draw their catalog mark (D63) off the `icon_url` already on `GET /v1/services`; a service whose template resolves none keeps its monogram, and agents have neither so they always do. Ball images are inert to pointer input (`draggable="false"`, `pointer-events: none`) — a node is a drag handle, and without that the browser's native image drag wins the gesture and you drag a ghost of the picture instead of the node.
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
