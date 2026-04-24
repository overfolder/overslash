# Overslash — Status

**Current state**: Phase 2 in progress. Core backend fully functional with OAuth, service registry, and unified action execution.

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
- `POST /v1/actions/execute` �� raw HTTP with secret injection (`http` pseudo-service)
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
- Global service template registry — OpenAPI 3.1 loader with `x-overslash-*` alias normalization, search API, and parse-don't-validate pipeline (PR #118)
- 9 service templates shipped as OpenAPI 3.1: Eventbrite, GitHub, Gmail, Google Calendar, Google Drive, Resend, Slack, Stripe, X (plus the `overslash` platform namespace)
- Template/service instance split — templates (OpenAPI 3.1 blueprints with `x-overslash-*` extensions) + service instances (named, with credentials and lifecycle)
- Three-tier template registry — global (read-only, shipped OpenAPI) + org (CRUD by org admins) + user (CRUD, gated by `allow_user_templates`) (PR #100)
- Template validation endpoint `POST /v1/templates/validate` (PR #108) — struct-level OpenAPI lint reusable client-side via WASM feature gate
- User-level services always visible to owner and their agents (PR #130)
- Per-service OAuth scopes declared end-to-end on templates and propagated through the authorization URL (PR #127)
- Service+action execution (registry-resolved, auth auto-resolved)
- `scope_param` on service actions — permission keys use specific args from action params
- `on_behalf_of` for agent-initiated operations (PR #90) — agents create secrets and connections at the owner-user level so sibling agents share them
- Description interpolation — `{param}` substitution and `[optional segments]` in action descriptions
- Human-readable audit descriptions — interpolated descriptions for Mode C, `METHOD host/path` for Mode A, `identity_name` resolved in audit responses
- Suggested tiers + derived_keys on approval payloads (2-4 broadening levels)
- Approval resolution API aligned with spec (`resolution` + `remember_keys` + `ttl`)
- X.com OAuth with PKCE support
- Eventbrite OAuth provider support
- E2E tests against real providers: Eventbrite (OAuth), GitHub (PR #113), Google Calendar (PR #111), Google Drive (PR #107), Gmail (PR #115), Resend (token), X.com (OAuth+PKCE, PR #114)
- sqlx compile-time query checking enforced across all repos

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

### Phase 3 — Identity Hierarchy + Hierarchical Permissions

- Parent/child identity relationships with `parent_id`, `depth`, `owner_id` columns
- `IdentityKind` expanded: `user`, `agent`, `sub_agent`
- Hierarchy validation: users have no parent, agents require user parent, sub_agents require agent/sub_agent parent
- `inherit_permissions` dynamic resolution: when set, identity inherits parent's permission rules at query time (live pointer, not copy); chain walks upward through continuous `inherit_permissions=true` ancestors
- Ancestor chain query (recursive CTE) and children listing endpoints
- MCP OAuth 2.1 agent enrollment — `/oauth/authorize` pauses and routes through `/oauth/consent` (new-mode creates an agent under the signed-in user; reauth-mode rebinds a re-registered DCR `client_id` to the existing agent). Bespoke `/v1/enrollment-tokens` and `/v1/enroll*` flows retired — migration 040 drops `enrollment_tokens` + `pending_enrollments`.
- Agent-facing `SKILL.md` at repo root, served at `/SKILL.md` by the API (cloud Vercel rewrite + self-hosted Axum route), documents the OAuth path + the `overslash mcp login` workaround for MCP clients without native OAuth support (e.g. OpenClaw).
- Standalone "Provide Secret" page (`/secrets/provide/req_{id}?token=jwt`): JWT-scoped, single-use, no-login secret submission. `secret_requests` table (migration 027), `POST /v1/secrets/requests` (mint), public `GET`/`POST /public/secrets/provide/{req_id}` (verify + submit), SvelteKit standalone route.
- **User Signed Mode** for the Provide Secret page (migration 031): opportunistic session binding (if the visitor's `oss_session` cookie is present and matches the request's org, their identity is recorded on `secret_versions.provisioned_by_user_id` and the `secret_request.fulfilled` audit row is attributed to them instead of the target identity), plus an org toggle `allow_unsigned_secret_provide` (**on by default** — defaults to true so existing orgs keep current behavior) exposed via new `GET/PATCH /v1/orgs/{id}/secret-request-settings`. When the toggle is flipped off, newly-minted requests carry `secret_requests.require_user_session = true` at mint time and reject anonymous submission with `401 user_session_required`. The toggle is forward-only — outstanding URLs keep the policy they were issued under. Cross-tenant sessions are silently ignored. Dashboard: org settings page exposes the toggle; the provide page switches to `credentials: 'same-origin'` and renders a "Signed in as …" banner or a "Sign in to continue" gate as appropriate.
- `GET /v1/identities/{id}/children`, `GET /v1/identities/{id}/chain`
- Sub-agent idle cleanup with two-phase archive — `last_active_at` touched per request, background loop (60s) archives idle sub-agents (revoking API keys with `revoked_reason='identity_archived'` and expiring pending approvals), then purges archived rows past the retention window. Parents wait for live children before archiving or purging. `POST /v1/identities/{id}/restore` un-archives within the window and resurrects auto-revoked API keys; manually-revoked keys are untouched. Archived identities return `403 identity_archived` from the auth middleware. Idle timeout (`subagent_idle_timeout_secs`, 4h–60d) and retention (`subagent_archive_retention_days`, 1d–60d) are configured per-org via `PATCH /v1/orgs/{id}/subagent-cleanup-config`.
- Hierarchical permission chain walk (SPEC §5): `execute_action` walks the requester→user chain; each non-user level must authorize via own rules or `inherit_permissions`
- Approval bubbling: approval `identity_id` stays the requester; `current_resolver_identity_id` tracks who must act now; explicit `bubble_up` resolution and per-org `approval_auto_bubble_secs` background sweep advance the resolver up the chain
- Resolver authorization: only the current resolver, an ancestor of it, or an org-admin (no-identity) key can resolve a pending approval
- "Allow & Remember" rule placement targets the requester's closest non-`inherit_permissions` ancestor (inclusive), not the requester itself when it just borrows permissions

### Phase 4 — Groups (Layer 1 Permission Ceiling)

- `groups`, `group_grants`, `identity_groups` tables (migration 020)
- Group grants reference org-level service instances with structured access levels (`read`/`write`/`admin`)
- `allow_raw_http` per-group for Mode A raw HTTP access
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

### Not Yet Built

- Dashboard gaps (tracked in TODO.md §Review Corrections 2026-04-20):
  - Audit Log view (backend audit trail is complete; UI missing — card `504a7`)
  - IdP config **edit** UI (create/delete/toggle ship; backend `PUT /v1/org-idp-configs/{id}` already supports full updates — see TECH_DEBT.md §3)
  - API Explorer accessibility from main nav (card `504a7`)
  - Notification bell dropdown (card `504a7`)
  - Approval resolver as modal/dropdown instead of standalone page (card `20ae2`, design pending)
  - Toggle Switch design-system component adopted everywhere (card `2e268`, in progress)
  - Inline "Allow Once" on /agents and canonical `OVERSLASH_DASHBOARD_URL` in approval URLs (card `20ae2`)
- OpenAPI bulk import UX (endpoint in Review, card `7187f`)
- User-to-org template sharing (propose / approve / deny; in Review, card `7e5ee`)
- Phase 3: approval visibility scoping (`?scope=actionable` vs `?scope=mine`), webhook `gap_identity` + `can_be_handled_by`
- Phase 3: archived sub-agent list + restore button + cleanup config form in the Agents view (backend shipped)
- Phase 4: Meta tools (`overslash_search`/`_execute`/`_auth` in Review, card `30b36`), org billing / usage metering, documentation site

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
- Four tools exposed by `POST /mcp`:
  - `overslash_search` → `GET /v1/search` — unified service/action discovery (§10) with keyword + Jaro-Winkler fuzzy + optional local pgvector embeddings (`bge-small-en-v1.5`). Hybrid ranker; `auth.instances[]` lists every connected instance with `owner_email`. Env kill-switch `OVERSLASH_EMBEDDINGS=off` + boot-time pgvector preflight — falls back to keyword+fuzzy transparently on vanilla Postgres.
  - `overslash_execute` → `POST /v1/actions/execute`
  - `overslash_auth` → dispatched per-action: `whoami`/`list_secrets`/`request_secret`/`create_subagent`/`create_service_from_template`/`service_status`. `rotate_secret` and a few others from SPEC §10 not yet wired (return `invalid_params` with a clear message).
  - `overslash_approve` → `POST /v1/approvals/{id}/resolve` — no longer "MCP only"; usable from any user-mode surface.
- `overslash web` + `embed-dashboard` Cargo feature embeds `dashboard/build/` (built with `@sveltejs/adapter-static`) via `rust-embed`. Cloud Vercel build path unchanged.
- Infra image still tagged `overslash-api:*` to keep Artifact Registry stable; only the in-container entrypoint changed (`overslash serve`).

## What's Deployed

Nothing yet. Running locally via Docker Compose (Postgres on port 55432).

## Infrastructure

- **Repository**: `overfolder/overslash` (private, will be open-sourced)
- **Default branch**: `master`
- **CI**: GitHub Actions with coverage reporting, real OAuth provider tests
- **PR flow**: feature branches → `dev` → `master`
- **IaC**: OpenTofu under `/infra` — deploys to GCP Cloud Run with Cloud SQL, Artifact Registry, Secret Manager, Cloud Build, and optional Memorystore/DNS
- **Docker**: Multi-stage Dockerfile (Rust build → Debian slim runtime), `docker-compose.prod.yml` for local prod-like testing
- **Environments**: `dev` (overslash-dev) and `prod` (overslash) via `infra/env/*.tfvars`
- **Deployment**: `make tofu-plan ENV=dev && make tofu-apply ENV=dev`
