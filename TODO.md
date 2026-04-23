# Overslash — TODO

Phased roadmap. Each phase is usable independently.

---

## Spec–Code Misalignments

All resolved via PRs #29–#40 — see Done section for detail.

### Dashboard (dashboard/ vs UI_SPEC.md)

Existing dashboard code predates the unified permission model and template/service split.

**High priority:**
- [ ] Types: remove Mode A/B/C execution variants, unify into single `ExecuteRequest` with service + action
- [x] Types: `risk` is now a `Risk` enum (`read|write|delete`) — aligned with spec
- [ ] Types: add template/service instance split (`ServiceTemplate` + `ServiceInstance`)
- [ ] Types: add permission key types (`{service}:{action}:{arg}`)
- [ ] Types: remove `approval_url` from `ExecuteResponse` (no self-auth approval URLs)
- [ ] Login: extract from profile page to standalone `/login` page with logo, multi-IdP buttons (uses `GET /auth/providers`), redirect-back-after-auth
- [ ] IdP config: **edit** UI for existing configs — create/delete/toggle shipped; dashboard lacks a form to update client_id/secret or flip `use_org_credentials` (backend `PUT /v1/org-idp-configs/{id}` already supports it — see TECH_DEBT.md §3)
- [ ] Stores: remove `executionMode` (A/B/C), `connections` store; update to unified model

**Medium priority:**
- [ ] Layout: add nav items (Agents, Services, Secrets, Audit Log; ADMIN: Users, Groups)
- [ ] Layout: collapsible sidebar (labels+icons expanded, icons-only collapsed)
- [ ] Layout: notification bell in top bar with badge count
- [ ] Layout: profile avatar at bottom of sidebar (not a nav item)
- [ ] Logo: change from `//` to `Overs/ash` per spec
- [ ] API client: split `GET /v1/services` into templates + instances endpoints
- [ ] API client: remove `GET /v1/connections` (connections absorbed into services)

**Low priority:**
- [ ] Profile: expand with API keys, secrets, remembered approvals, enrollment tokens, settings sections
- [ ] CSS: add light mode + theme toggle (currently dark-only)

### Review Corrections (2026-04-10)

- [ ] Rename: "Dashboard" nav item and view to "Agents" — make it the default landing view
- [ ] Rename: all UI references from "Identities" to "Agents"
- [ ] Agents view: User node is tree root, immutable (no delete/rename/move). No adding User identities.
- [ ] Create agent: remove Kind dropdown. Only agent creation allowed; parent determines hierarchy position.
- [ ] Dark mode: increase contrast for accent hover states and badge/pill backgrounds (e.g., "inherit" pill). Target WCAG AA (4.5:1) for all badge text in dark mode.
- [ ] Delete confirmation: replace all `window.confirm()` / browser-native dialogs with styled modal component per UI_SPEC.
- [ ] Org Settings: fix "Cannot load org settings. Admin access required" for Dev Users. Dev Login users must have org-admin access in development mode.
- [x] Docker: cache Rust toolchain layer in dev Dockerfile to avoid re-downloading rustup components on every `make dev` run. (PRs #97, #98)
- [ ] (Backlog) Template Editor: build and make accessible from Services view
- [ ] (Backlog) API Explorer: ensure accessible and functional for testing the overslash meta-service

### Review Corrections (2026-04-20)

Consolidated backlog cards from [docs/review/2026-04-20.md](docs/review/2026-04-20.md). Each card groups related review items and has a corresponding entry on the Kanban board.

- [ ] **Approval System UX Overhaul** (card `20ae2`) — canonical `OVERSLASH_DASHBOARD_URL` envvar threaded through approval URLs (currently points at `overslash.example`), inline "Allow Once" on /agents, modal/dropdown resolver with expiry and granularity pickers, hide "Bubble Up" when the current user is already the resolver
- [ ] **Missing Dashboard Views: Audit Log + API Explorer + Notification Dropdown** (card `504a7`) — Audit Log view, API Explorer accessibility from main nav, Notification bell dropdown of notifications
- [ ] **Services View & Data Display Fixes** (card `73d90`) — show username/email not UUID for service owners, fix `/users/{name}` 404, correct the `overslash` meta-service "Needs Setup" copy, group pills as a column on service list, add `category` field to all templates, services connectable to groups from the detail view
- [ ] **OAuth Connections & Provider UX Fixes** (card `c2575`) — stop creating phantom Identity Provider + UUID connection when admin adds a Google OAuth Client ID, reuse connections across services sharing the same provider, show provider email / identity instead of UUIDs, support incremental scopes auth
- [ ] **MCP Login Flow Fixes** (card `877cb`) — assignment/consent page served from dashboard (not api), default `inherit_permissions = true` for new MCP agents, reuse the existing agent on reauthentication, hide revoked MCP clients from the UI after 3s
- [~] **UI Component Polish: Toggle Switches + Date Formatting** (card `2e268`, in progress) — design-system Toggle Switch component adopted everywhere (starting with "Inherits Permissions"), fix "Requested Invalid Date" rendering on Pending Approvals
- [x] Multi-org login design for Cloud Overslash — design doc landed at `docs/design/multi_org_auth.md`; implementation tracked below
- [ ] **Multi-org implementation** — PRs 1–5 per `docs/design/multi_org_auth.md`: data model + backfill, JWT + `/auth/switch-org` + account routes, subdomain middleware + self-hosted flags (`ALLOW_ORG_CREATION`, `SINGLE_ORG_MODE`), login-flow rewiring with corp-org bootstrap admin, dashboard org switcher + `/account` page
- [ ] Corp-org slug squatting mitigation — domain verification or admin approval on `POST /v1/orgs` (follow-up to multi-org rollout)
- [ ] Audit events for bootstrap-admin add/remove — emit on `POST /v1/orgs` and on `DELETE /v1/account/memberships/{org_id}` when the removed row had `is_bootstrap=true`
- [ ] `/account` profile editing — name + avatar editable once the `users` table exists (follow-up to multi-org PR 1)

---

## Phase 1: Core Service (MVP) ✅

- [x] Project scaffold (Rust/Axum, Cargo workspace, Docker)
- [x] PostgreSQL schema + migrations (sqlx)
- [x] Orgs CRUD
- [x] Identities CRUD (users + agents, flat — no hierarchy yet)
- [x] API key issuance + authentication middleware
- [x] Secret vault with versioning (PUT, GET metadata, restore, soft-delete)
- [x] `POST /v1/actions/execute` — raw HTTP with secret injection (`http` pseudo-service)
- [x] Permission rules (flat per-identity, no chain yet)
- [x] Approval workflow — create, resolve (allow/deny/allow_remember), expire
- [x] Secret request page (standalone signed-URL web page — safe because providing a secret doesn't grant agent authority). Follow-ups: backend `deny` endpoint + audit event; wire `overslash_auth.request_secret` and `create_service_from_template` to mint requests.
- [x] Audit trail (log every action, approval, secret access)
- [x] Agents view: minimal — superseded by Phase 2.5 Agents redesign per Figma (PR #105)
- [x] Webhook delivery (approval.created, approval.resolved)

## Phase 2: OAuth + Service Registry (in progress)

- [x] OAuth engine (authorization URL, code exchange, token storage, auto-refresh)
- [x] BYOC credential support (identity, org, system fallback chain)
- [x] Connections API (initiate, list, revoke) — to be refactored into service instances
- [x] `on_behalf_of` for agent-initiated service creation at user level (PR #90)
- [x] Global service template registry — OpenAPI 3.1 loader for shipped definitions
- [ ] Ship top 20 service templates — 9 shipped: Eventbrite, GitHub, Gmail, Google Calendar, Google Drive, Resend, Slack, Stripe, X (plus the `overslash` platform namespace)
- [x] Template/service split — templates (OpenAPI blueprints) + services (named instances with credentials) (PR #31)
- [x] Three-tier template registry — global (OpenAPI, read-only) + org (DB, CRUD) + user (DB, CRUD, gated by org setting) (PR #100)
- [x] Service instances — create from template, bind credentials, assign to groups (PR #31)
- [x] Template validation endpoint (`POST /v1/templates/validate`) — OpenAPI 3.1 parse + alias normalization + struct-level lint in `overslash-core::template_validation`. WASM feature gate in place for client-side reuse.
- [x] OpenAPI-native template format — OpenAPI 3.1 with `x-overslash-*` vendor extensions (risk, scope_param, resolve, provider, default_secret_name, category, key, platform_actions) and unprefixed aliases that canonicalize on save.
- [ ] Bulk OpenAPI import UX — upload/paste a vendor's public spec and auto-generate a template with sensible `x-overslash-*` overlay defaults.
- [ ] User-to-org template sharing (propose, approve/deny)
- [x] Service + action execution (registry-resolved, auth auto-resolve)
- [x] Human-readable action descriptions from registry metadata (description interpolation, PR #35)

## Phase 2.5: Dashboard + Enrollment

### Dashboard (SvelteKit + TypeScript)

- [x] Scaffold SvelteKit project with TypeScript, auth, API client, and user profile view
- [ ] Agents view (default landing) — tree visualization with inline identity management
- [ ] Services view — template catalog, service instances, create/manage/connect
- [x] Developer connection tool — interactive API explorer (execute via Mode A/B/C, like Swagger UI for Overslash)
- [ ] Audit log view — searchable, filterable log with identity/service/time/event filters

### Agent Enrollment

- [ ] User-to-Agent enrollment flow — user pre-creates agent identity, gets single-use token, agent exchanges for API key
- [ ] Agent-initiated enrollment flow + `SKILL.md` — agent discovers Overslash, gets enrollment token, generates consent URL for user approval

## Phase 3: Identity Hierarchy + Permissions

- [x] Parent/child identity relationships (depth tracking, owner_id)
- [x] `inherit_permissions` — dynamic resolution (live pointer, not copy)
- [x] Sub-identity CRUD for agents (via `POST /v1/identities` with `kind: sub_agent` and `parent_id`)
- [x] Sub-agent idle cleanup with two-phase archive (backend) — idle archive, retention purge, restore endpoint, per-org config
- [ ] Agents view: archived sub-agent list with restore button, org sub-agent cleanup config form (`subagent_idle_timeout_secs`, `subagent_archive_retention_days`), `archived_at`/`last_active_at` columns in identity tree
- [x] Permission chain walk (ancestor chain, gap detection)
- [x] Approval bubbling (current_resolver tracking, explicit bubble_up, auto-bubble timer, rule placement on closest non-inherit ancestor)
- [ ] Approval visibility scoping (`?scope=actionable` vs `?scope=mine`)
- [ ] Webhook: include `gap_identity` and `can_be_handled_by` in approval events
- [x] Org-level ACL — role-based access control via group membership on the `overslash` meta service, plus an `is_org_admin` fast-path on User identities. Naked org-level identities/API keys removed (migration 028).
- [x] Agents view: identity hierarchy tree view (PR #105)
- [ ] Agents view: per-agent permission management UI (rules, scopes, "Allow & Remember" review/edit)

## Phase 4: Polish + Meta Tools

- [ ] Meta tool definitions (overslash_search, overslash_execute, overslash_auth)
- [x] Semantic search for service/action discovery — `GET /v1/search` with keyword + fuzzy + local pgvector embeddings (PR pending)
- [x] Rate limiting per identity — two-tier model (User bucket + identity caps), Redis/Valkey or in-memory
- [ ] Org billing / usage metering
- [x] Human-readable audit descriptions — interpolated descriptions for Mode C, method+URL for Mode A, identity name resolution in audit responses
- [ ] Org settings view: org settings, webhook management, bulk permission operations
- [ ] Global service registry contribution workflow (community PRs)
- [ ] Documentation site

## Ongoing: Testing Coverage

- [ ] Increase integration test coverage across all API routes
- [ ] Add unit tests for core permission resolution logic
- [ ] Add tests for edge cases in OAuth token refresh and BYOC fallback
- [ ] Dashboard component tests
- [ ] E2E tests for enrollment flows

---

## Done

- Phase 1 core backend (all API routes, permissions, approvals, audit, webhooks, expiry loop)
- Phase 2 OAuth engine with BYOC credential resolution (identity → org → system fallback)
- Service+action execution (registry-resolved with automatic auth)
- Service registry: 9 OpenAPI 3.1 templates shipped — Eventbrite, GitHub, Gmail, Google Calendar, Google Drive, Resend, Slack, Stripe, X — plus the `overslash` platform namespace. Original YAML format migrated to OpenAPI 3.1 with `x-overslash-*` vendor extensions (PR #128) and refactored with parse-don't-validate (PR #118).
- E2E integration tests: Eventbrite, GitHub (PR #113), Google Calendar (PRs #111, #98), Google Drive (PR #107), Gmail (PR #115), Resend, X.com (OAuth+PKCE, PR #114)
- CI pipeline with coverage reporting, sharded tests (PRs #116, #119), skip-coverage on draft PRs
- All spec–code misalignments resolved (PRs #29–#40): risk enum, identity hierarchy, template/instance split, approval resolve fields, scope_param, description interpolation, suggested tiers, category removed from spec
- sqlx compile-time query checking enforced across all repos (PR #39)
- Multi-provider OIDC authentication: generic provider routes, OIDC Discovery, GitHub social login, per-org IdP config, env var precedence, email domain matching, profile sync
- `on_behalf_of` for agent-initiated operations (PR #90) — agents create secrets/connections at owner-user level so siblings share them
- Three-tier OAuth credential cascade (SPEC §7): user BYOC + org-level OAuth App Credentials + system env (PRs #117, #122, #124, #131), with shared resolution for IdP configs
- Per-service OAuth scopes declared end-to-end (PR #127)
- User-level services visible to owner and their agents (PR #130)
- Three-tier template registry — global / org / user with `allow_user_templates` gate (PR #100)
- Template validation endpoint `POST /v1/templates/validate` (PR #108)
- Sub-agent idle cleanup with two-phase archive + restore endpoint + per-org config
- Phase 3: Groups (Layer 1 ceiling, `auto_approve_reads`, `allow_raw_http`), org-level ACL via groups on the `overslash` meta-service + `is_org_admin` fast-path
- Phase 4: Two-tier rate limiting (User bucket + identity caps), Redis/Valkey or in-memory, standard headers + 429
- CLI + MCP surface restructure: single `overslash` binary with `serve` / `web` / `mcp` / `mcp login` subcommands (PR #121); MCP over Streamable HTTP + OAuth 2.1 AS endpoints (PR #123); user-BYOC in Create Service + Template Editor provider dropdown (PR #124)
- Standalone Provide Secret page (PR #89) + User Signed Mode (PR #109, migration 031)
- Templates dashboard UI (PR #112), Agents view redesign per Figma (PR #105), self-hosted Inter/Roboto Mono (PR #129), zero-warning vite builds enforced (PR #125)
- 2026-04-10 review corrections applied (doc: PR #96, dashboard: PR #99, Docker Rust toolchain cache: PRs #97, #98)
- Code quality: CTE cycle protection (PR #38), identity_response From impl (PR #37), org ownership check helper
