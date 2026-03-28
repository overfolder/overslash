# Overslash — Status

**Current state**: Phase 2 in progress. Core backend fully functional with OAuth, service registry, and 3 execution modes.

---

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
- `POST /v1/actions/execute` — Mode A (raw HTTP with secret injection)
- Permission rules (flat per-identity)
- Approval workflow (create, resolve with allow/deny/allow_remember, expiry loop)
- Audit trail (all actions, approvals, secret access)
- Webhook delivery (approval.created, approval.resolved)
- 8+ integration tests

### Phase 2 — OAuth + Service Registry (in progress)

- OAuth engine (authorization URL, code exchange, token storage, auto-refresh)
- BYOC credential resolution with fallback chain (identity → org → system)
- Connections API (initiate, list, revoke)
- Global service registry — YAML loader with search API
- 7 service definitions shipped: Eventbrite, GitHub, Google Calendar, Resend, Slack, Stripe, X
- Mode B execution (connection-based, token auto-injected)
- Mode C execution (service+action, registry-resolved, auth auto-resolved)
- X.com OAuth with PKCE support
- Eventbrite OAuth provider support
- E2E tests against real providers: Eventbrite (OAuth), Google Calendar (OAuth), Resend (token), X.com (OAuth+PKCE)

### Not Yet Built

- Standalone approval resolution page (signed-URL)
- Standalone secret request page (signed-URL)
- `on_behalf_of` for agent-initiated connections
- Org service registry (DB-backed CRUD)
- OpenAPI spec import
- Human-readable action descriptions
- Dashboard (SvelteKit)
- Phase 3: Identity hierarchy (parent/child, inherit_permissions, approval bubbling)
- Phase 4: Meta tools, semantic search, rate limiting, billing

## What's Deployed

Nothing yet. Running locally via Docker Compose (Postgres on port 55432).

## Infrastructure

- **Repository**: `overfolder/overslash` (private, will be open-sourced)
- **Default branch**: `master`
- **CI**: GitHub Actions with coverage reporting, real OAuth provider tests
- **PR flow**: feature branches → `dev` → `master`
