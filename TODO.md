# Overslash — TODO

Phased roadmap. Each phase is usable independently.

---

## Phase 1: Core Service (MVP)

- [ ] Project scaffold (Rust/Axum, Cargo workspace, Docker)
- [ ] PostgreSQL schema + migrations (sqlx or refinery)
- [ ] Orgs CRUD
- [ ] Identities CRUD (users + agents, flat — no hierarchy yet)
- [ ] API key issuance + authentication middleware
- [ ] Secret vault with versioning (PUT, GET metadata, restore, soft-delete)
- [ ] `POST /v1/actions/execute` — Mode A (raw HTTP with secret injection)
- [ ] Permission rules (flat per-identity, no chain yet)
- [ ] Approval workflow — create, resolve (allow/deny/allow_remember), expire
- [ ] Approval resolution page (standalone signed-URL web page)
- [ ] Secret request page (standalone signed-URL web page)
- [ ] Audit trail (log every action, approval, secret access)
- [ ] Dashboard: minimal — identity list, approval resolution, secret request
- [ ] Webhook delivery (approval.created, approval.resolved)

## Phase 2: OAuth + Service Registry

- [ ] OAuth engine (authorization URL, code exchange, token storage, auto-refresh)
- [ ] BYOC credential support (identity, org, system fallback chain)
- [ ] Connections API (initiate, list, revoke)
- [ ] `on_behalf_of` for agent-initiated connections at user level
- [ ] Global service registry — YAML loader for shipped definitions
- [ ] Ship top 20 service definitions (GitHub, Google Calendar, Gmail, Stripe, Slack, Notion, etc.)
- [ ] Org service registry — DB-backed, CRUD endpoints
- [ ] OpenAPI spec import (`POST /v1/services/import`)
- [ ] Mode C execution (service + action, registry-resolved, auth auto-resolve)
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

(Nothing yet.)
