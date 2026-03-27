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
- [ ] Ship top 20 service definitions — 6 shipped: GitHub, Google Calendar, Resend, Slack, Stripe, X
- [ ] Org service registry — DB-backed, CRUD endpoints
- [ ] OpenAPI spec import (`POST /v1/services/import`)
- [x] Mode C execution (service + action, registry-resolved, auth auto-resolve)
- [ ] Human-readable action descriptions from registry metadata
- [ ] Dashboard: connections, service browser, secret management, audit viewer

## Phase 3: Identity Hierarchy

- [ ] Parent/child identity relationships (depth tracking, owner_id)
- [ ] `inherit_permissions` — dynamic resolution (live pointer, not copy)
- [ ] Sub-identity CRUD for agents (`POST /v1/sub-identities`)
- [ ] TTL-based sub-identity auto-cleanup
- [ ] Permission chain walk (ancestor chain, gap detection)
- [ ] Approval bubbling (gap level targeting, ancestor handling)
- [ ] Approval visibility scoping (`?scope=actionable` vs `?scope=mine`)
- [ ] Webhook: include `gap_identity` and `can_be_handled_by` in approval events
- [ ] Dashboard: identity hierarchy tree view, agent permission management

## Phase 4: Polish + Meta Tools

- [ ] Meta tool definitions (overslash_search, overslash_execute, overslash_auth)
- [ ] Semantic search for service/action discovery
- [ ] Rate limiting per identity
- [ ] Org billing / usage metering
- [ ] Dashboard: org settings, webhook management, bulk permission operations
- [ ] Global service registry contribution workflow (community PRs)
- [ ] Documentation site

---

## Done

- Phase 1 core backend (all API routes, permissions, approvals, audit, webhooks, expiry loop)
- Phase 2 OAuth engine with BYOC credential resolution (identity → org → system fallback)
- Mode C execution (service+action registry-resolved with automatic auth)
- Service registry with 6 YAML definitions (GitHub, Google Calendar, Resend, Slack, Stripe, X)
- E2E integration tests: Resend (token-based), Google Calendar (OAuth), X.com (OAuth+PKCE)
- CI pipeline with coverage reporting and real OAuth provider tests
