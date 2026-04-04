# Overslash — TODO

Phased roadmap. Each phase is usable independently.

---

## Spec–Code Misalignments

Things already implemented that diverge from SPEC.md. Resolve each by updating the spec or the code.

- [ ] **Approval resolve field name**: spec says `resolution` + `remember_keys` + `ttl`; code uses `decision` only — no key selection or TTL at resolve time
- [ ] **No suggested_tiers in approvals**: spec returns structured `derived_keys` + `suggested_tiers` (2-4 broadening levels); code only has flat `permission_keys: Vec<String>`
- [x] **risk vs mutating**: resolved — spec updated to use `risk: read|write|delete` enum matching code; `Risk` is now a proper Rust enum
- [ ] **No scope_param**: spec defines `scope_param` on actions to fill `{arg}` in permission keys; code doesn't implement it — all service-action keys have `*` as arg
- [ ] **No category on templates**: spec defines `category` for UI grouping; code and YAMLs don't have it
- [ ] **No description interpolation**: spec supports `{param}` substitution and `[optional segments]` in action descriptions; code treats descriptions as static strings
- [ ] **Template/instance split**: spec separates templates (blueprints) from services (named instances with lifecycle); code has definitions + connections with no instance layer
- [ ] **Identity depth**: spec has User/Agent/SubAgent with parent_id and depth; code has flat `kind IN ('user','agent')` — enrollment creates orphaned agents

### Dashboard (dashboard/ vs UI_SPEC.md)

Existing dashboard code predates the unified permission model and template/service split.

**High priority:**
- [ ] Types: remove Mode A/B/C execution variants, unify into single `ExecuteRequest` with service + action
- [x] Types: `risk` is now a `Risk` enum (`read|write|delete`) — aligned with spec
- [ ] Types: add template/service instance split (`ServiceTemplate` + `ServiceInstance`)
- [ ] Types: add permission key types (`{service}:{action}:{arg}`)
- [ ] Types: remove `approval_url` from `ExecuteResponse` (no self-auth approval URLs)
- [ ] Login: extract from profile page to standalone `/login` page with logo, multi-IDP buttons, redirect-back-after-auth
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
- [ ] Template/service split — templates (YAML blueprints) + services (named instances with credentials)
- [ ] Three-tier template registry — global (YAML, read-only) + org (DB, CRUD) + user (DB, CRUD, gated by org setting)
- [ ] Service instances — create from template, bind credentials, assign to groups
- [ ] Template validation endpoint (`POST /v1/templates/validate`)
- [ ] OpenAPI import (`POST /v1/templates/import`) — parse OpenAPI 3.x, generate template + actions
- [ ] User-to-org template sharing (propose, approve/deny)
- [x] Service + action execution (registry-resolved, auth auto-resolve)
- [ ] Human-readable action descriptions from registry metadata

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

- [ ] Parent/child identity relationships (depth tracking, owner_id)
- [ ] `inherit_permissions` — dynamic resolution (live pointer, not copy)
- [ ] Sub-identity CRUD for agents (`POST /v1/sub-identities`)
- [ ] TTL-based sub-identity auto-cleanup
- [ ] Permission chain walk (ancestor chain, gap detection)
- [ ] Approval bubbling (gap level targeting, ancestor handling)
- [ ] Approval visibility scoping (`?scope=actionable` vs `?scope=mine`)
- [ ] Webhook: include `gap_identity` and `can_be_handled_by` in approval events
- [ ] Org-level ACL — role-based access control for who can manage resources within an org
- [ ] Dashboard: identity hierarchy tree view, agent permission management

## Phase 4: Polish + Meta Tools

- [ ] Meta tool definitions (overslash_search, overslash_execute, overslash_auth)
- [ ] Semantic search for service/action discovery
- [ ] Rate limiting per identity
- [ ] Org billing / usage metering
- [ ] Human-readable audit descriptions for Mode C (resolve IDs to names via response parsing)
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
