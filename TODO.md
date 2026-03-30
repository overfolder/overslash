# Overslash — TODO

Phased roadmap. Each phase is usable independently.

---

## Phase 1: Core Service (MVP) ✅

- [x] Project scaffold (Rust/Axum, Cargo workspace, Docker)
- [x] PostgreSQL schema + migrations (sqlx)
- [x] Orgs CRUD
- [x] Identities CRUD (users + agents, flat — no hierarchy yet)
- [x] API key issuance + authentication middleware
- [x] Secret vault with versioning (PUT, GET metadata, restore, soft-delete)
- [x] `POST /v1/actions/execute` — Mode A (raw HTTP with secret injection)
- [x] Permission rules (flat per-identity, no chain yet)
- [x] Approval workflow — create, resolve (allow/deny/allow_remember), expire
- [ ] Approval resolution page (standalone signed-URL web page)
- [ ] Secret request page (standalone signed-URL web page)
- [x] Audit trail (log every action, approval, secret access)
- [ ] Dashboard: minimal — identity list, approval resolution, secret request
- [x] Webhook delivery (approval.created, approval.resolved)

## Phase 2: OAuth + Service Registry (in progress)

- [x] OAuth engine (authorization URL, code exchange, token storage, auto-refresh)
- [x] BYOC credential support (identity, org, system fallback chain)
- [x] Connections API (initiate, list, revoke)
- [ ] `on_behalf_of` for agent-initiated connections at user level
- [x] Global service registry — YAML loader for shipped definitions
- [ ] Ship top 20 service definitions — 7 shipped: Eventbrite, GitHub, Google Calendar, Resend, Slack, Stripe, X
- [ ] Org service registry — DB-backed, CRUD endpoints
- [ ] OpenAPI spec import (`POST /v1/services/import`)
- [x] Mode C execution (service + action, registry-resolved, auth auto-resolve)
- [ ] Human-readable action descriptions from registry metadata

## Phase 2.5: Dashboard + Enrollment

### Dashboard (SvelteKit + TypeScript)

- [ ] Scaffold SvelteKit project with TypeScript, auth, API client, and user profile view
- [ ] Org/User/Agent hierarchy view — tree visualization with inline identity management
- [ ] Connected services view — service connection status, reconnect/revoke actions
- [ ] Developer connection tool — interactive API explorer (execute via Mode A/B/C, like Swagger UI for Overslash)
- [ ] Audit log view — searchable, filterable log with identity/service/time/event filters

### Agent Enrollment

- [ ] User-to-Agent enrollment flow — user pre-creates agent identity, gets single-use token, agent exchanges for API key
- [ ] Agent-initiated enrollment flow + `SKILL.md` — agent discovers Overslash, gets enrollment token, generates consent URL for user approval

## Phase 3: Identity Hierarchy + Permissions

> Design doc: [docs/design/permission-chain-implementation.md](docs/design/permission-chain-implementation.md)

### 3.1 Schema & Types
- [ ] Migration 015: add `parent_id`, `owner_id`, `depth`, `inherit_permissions`, `can_create_sub`, `max_sub_depth`, `ttl` to identities; expand kind CHECK to include `subagent`
- [ ] Migration 015: add `gap_identity_id`, `can_be_handled_by`, `grant_to` to approvals
- [ ] Migration 015: add `expires_at` to permission_rules
- [ ] Rust types: add `SubAgent` to `IdentityKind` enum
- [ ] Rust types: add hierarchy fields to `Identity` and `IdentityRow`
- [ ] Rust types: add gap/grant fields to `Approval` and `ApprovalRow`
- [ ] Update all existing SQL SELECT lists in identity and approval repos

### 3.2 Identity Hierarchy Repo
- [ ] `get_ancestor_chain()` — recursive CTE walking parent_id to root
- [ ] `is_ancestor_of()` — verify ancestry relationship
- [ ] `create_sub_identity()` — compute depth/owner_id, validate max_sub_depth
- [ ] `list_children()` — direct children of an identity
- [ ] `cleanup_expired_sub_identities()` — delete identities past TTL
- [ ] `list_by_identities()` — batch-load permission rules for a set of identity IDs with expiry filter
- [ ] Background task: TTL cleanup loop (alongside existing approval expiry)

### 3.3 Chain Walk Algorithm
- [ ] `resolve_chain()` in `permissions.rs` — walk ancestor chain bottom-to-top, detect gaps
- [ ] `ChainWalkResult`, `PermissionGap` types
- [ ] Handle `inherit_permissions` as live pointer (skip level, parent's rules cover)
- [ ] Deny at any level short-circuits entire chain
- [ ] Expired permission rules filtered out
- [ ] Unit tests: flat identity regression, 2-level allow, 2-level gap, 3-level middle gap, deny override, multiple gaps, cascading inherit, expired rules

### 3.4 Identity CRUD API
- [ ] Extend `POST /v1/identities` to accept `parent_id`, `inherit_permissions`, `can_create_sub`, `max_sub_depth`, `ttl`
- [ ] Validate: parent exists in same org, depth constraints, kind matches depth
- [ ] Extend `GET /v1/identities` response with hierarchy fields
- [ ] Dashboard: identity hierarchy tree view with parent/child visualization + inline management

### 3.5 Action Execution Integration
- [ ] In `execute_action`: detect hierarchical identity (`parent_id IS NOT NULL`), load ancestor chain, batch-load rules, call `resolve_chain()`
- [ ] Flat identity path unchanged (backwards-compatible)
- [ ] Create one approval per gap with `gap_identity_id` and `can_be_handled_by`
- [ ] Extend `pending_approval` response with `gaps` array
- [ ] Integration tests: subagent gap detection, multi-gap, legacy flat identity unchanged

### 3.6 Approval Resolution & Scoping
- [ ] `GET /v1/approvals?scope=actionable|mine|all` — scope filtering with `can_be_handled_by` array
- [ ] Resolve authorization: verify resolver is in `can_be_handled_by`, forbid self-approval (403)
- [ ] `allow_remember` with `grant_to` parameter — create rule on target identity
- [ ] `allow_remember` with `expires_in` parameter — set `expires_at` on created rule
- [ ] Dashboard: approval list with actionable/mine tabs, resolve UI with grant_to picker and expires_in picker
- [ ] Integration tests: self-approval forbidden, ancestor resolves, scope filtering, grant_to, expires_in

### 3.7 Webhook Payload Updates
- [ ] `approval.created` event: include `gap_identity`, `gap_identity_id`, `can_be_handled_by`, `identity_id`, `expires_at`
- [ ] `approval.resolved` event: include `gap_identity_id`, `resolved_by`, `grant_to`
- [ ] Integration test: verify webhook payloads contain new fields

### 3.8 Org-Level ACL
- [ ] Role-based access control for who can manage resources within an org (admin/member/read-only)
- [ ] Dashboard: org settings for role management

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
- Mode C execution (service+action registry-resolved with automatic auth)
- Service registry with 7 YAML definitions (Eventbrite, GitHub, Google Calendar, Resend, Slack, Stripe, X)
- E2E integration tests: Eventbrite (OAuth), Google Calendar (OAuth), Resend (token-based), X.com (OAuth+PKCE)
- CI pipeline with coverage reporting and real OAuth provider tests
