# Overslash — TODO

Phased roadmap. Each phase is usable independently.

---

## Spec–Code Misalignments

Things already implemented that diverge from SPEC.md. Resolve each by updating the spec or the code.

- [x] **Approval resolve field name**: resolved — `decision` renamed to `resolution`, `remember_keys` + `ttl` added to resolve endpoint (PR #30)
- [x] **No suggested_tiers in approvals**: resolved — `derived_keys` + `suggested_tiers` with broadening levels implemented (PR #40)
- [x] **risk vs mutating**: resolved — spec updated to use `risk: read|write|delete` enum matching code; `Risk` is now a proper Rust enum (PR #29)
- [x] **No scope_param**: resolved — `scope_param` implemented on service actions, permission keys now use specific args (PR #34)
- [x] **No category on templates**: resolved — removed from spec; not needed (PR #33)
- [x] **No description interpolation**: resolved — `{param}` substitution and `[optional segments]` implemented (PR #35)
- [x] **Template/instance split**: resolved — templates (YAML blueprints) + service instances (named, with credentials) implemented (PR #31)
- [x] **Identity depth**: resolved — parent/child hierarchy with depth tracking, `sub_agent` kind, enrollment assigns parent (PR #32)

### Dashboard (dashboard/ vs UI_SPEC.md)

Existing dashboard code predates the unified permission model and template/service split.

**High priority:**
- [ ] Types: remove Mode A/B/C execution variants, unify into single `ExecuteRequest` with service + action
- [x] Types: `risk` is now a `Risk` enum (`read|write|delete`) — aligned with spec
- [ ] Types: add template/service instance split (`ServiceTemplate` + `ServiceInstance`)
- [ ] Types: add permission key types (`{service}:{action}:{arg}`)
- [ ] Types: remove `approval_url` from `ExecuteResponse` (no self-auth approval URLs)
- [ ] Login: extract from profile page to standalone `/login` page with logo, multi-IdP buttons (uses `GET /auth/providers`), redirect-back-after-auth
- [ ] IdP config: admin settings page for managing org IdP configs (uses `/v1/org-idp-configs` CRUD API)
- [ ] Stores: remove `executionMode` (A/B/C), `connections` store; update to unified model

**Medium priority:**
- [ ] Layout: add nav items (Dashboard, Services, API Explorer, Audit Log, Org Dashboard)
- [ ] Layout: collapsible sidebar (labels+icons expanded, icons-only collapsed)
- [ ] Layout: notification bell in top bar with badge count
- [ ] Layout: profile avatar at bottom of sidebar (not a nav item)
- [ ] Logo: change from `//` to `Overs/ash` per spec
- [ ] API client: split `GET /v1/services` into templates + instances endpoints
- [ ] API client: remove `GET /v1/connections` (connections absorbed into services)

**Low priority:**
- [ ] Profile: expand with API keys, secrets, remembered approvals, enrollment tokens, settings sections
- [ ] CSS: add light mode + theme toggle (currently dark-only)

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
- [ ] Secret request page (standalone signed-URL web page — safe because providing a secret doesn't grant agent authority)
- [x] Audit trail (log every action, approval, secret access)
- [ ] Dashboard: minimal — identity list, inline approval resolution, secret request
- [x] Webhook delivery (approval.created, approval.resolved)

## Phase 2: OAuth + Service Registry (in progress)

- [x] OAuth engine (authorization URL, code exchange, token storage, auto-refresh)
- [x] BYOC credential support (identity, org, system fallback chain)
- [x] Connections API (initiate, list, revoke) — to be refactored into service instances
- [ ] `on_behalf_of` for agent-initiated service creation at user level
- [x] Global service template registry — YAML loader for shipped definitions
- [ ] Ship top 20 service templates — 7 shipped: Eventbrite, GitHub, Google Calendar, Resend, Slack, Stripe, X
- [x] Template/service split — templates (YAML blueprints) + services (named instances with credentials) (PR #31)
- [ ] Three-tier template registry — global (YAML, read-only) + org (DB, CRUD) + user (DB, CRUD, gated by org setting)
- [x] Service instances — create from template, bind credentials, assign to groups (PR #31)
- [ ] Template validation endpoint (`POST /v1/templates/validate`)
- [ ] OpenAPI import (`POST /v1/templates/import`) — parse OpenAPI 3.x, generate template + actions
- [ ] User-to-org template sharing (propose, approve/deny)
- [x] Service + action execution (registry-resolved, auth auto-resolve)
- [x] Human-readable action descriptions from registry metadata (description interpolation, PR #35)

## Phase 2.5: Dashboard + Enrollment

### Dashboard (SvelteKit + TypeScript)

- [ ] Scaffold SvelteKit project with TypeScript, auth, API client, and user profile view
- [ ] Org/User/Agent hierarchy view — tree visualization with inline identity management
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
- [ ] Dashboard: archived sub-agent list with restore button, org sub-agent cleanup config form (`subagent_idle_timeout_secs`, `subagent_archive_retention_days`), `archived_at`/`last_active_at` columns in identity tree
- [x] Permission chain walk (ancestor chain, gap detection)
- [x] Approval bubbling (current_resolver tracking, explicit bubble_up, auto-bubble timer, rule placement on closest non-inherit ancestor)
- [ ] Approval visibility scoping (`?scope=actionable` vs `?scope=mine`)
- [ ] Webhook: include `gap_identity` and `can_be_handled_by` in approval events
- [ ] Org-level ACL — role-based access control for who can manage resources within an org
- [ ] Dashboard: identity hierarchy tree view, agent permission management

## Phase 4: Polish + Meta Tools

- [ ] Meta tool definitions (overslash_search, overslash_execute, overslash_auth)
- [ ] Semantic search for service/action discovery
- [x] Rate limiting per identity — two-tier model (User bucket + identity caps), Redis/Valkey or in-memory
- [ ] Org billing / usage metering
- [x] Human-readable audit descriptions — interpolated descriptions for Mode C, method+URL for Mode A, identity name resolution in audit responses
- [ ] Dashboard: org settings, webhook management, bulk permission operations
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
- Service registry with 7 YAML definitions (Eventbrite, GitHub, Google Calendar, Resend, Slack, Stripe, X)
- E2E integration tests: Eventbrite (OAuth), Google Calendar (OAuth), Resend (token-based), X.com (OAuth+PKCE)
- CI pipeline with coverage reporting and real OAuth provider tests
- All spec–code misalignments resolved (PRs #29–#40): risk enum, identity hierarchy, template/instance split, approval resolve fields, scope_param, description interpolation, suggested tiers, category removed from spec
- sqlx compile-time query checking enforced across all repos (PR #39)
- Multi-provider OIDC authentication: generic provider routes, OIDC Discovery, GitHub social login, per-org IdP config, env var precedence, email domain matching, profile sync
- Code quality: CTE cycle protection (PR #38), identity_response From impl (PR #37), org ownership check helper
