# Overslash — Status

**Current state**: Phase 2 in progress. Core backend fully functional with OAuth, service registry, and unified action execution.

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
- `POST /v1/actions/execute` �� raw HTTP with secret injection (`http` pseudo-service)
- Permission rules (flat per-identity)
- Approval workflow (create, resolve with allow/deny/allow_remember, expiry loop)
- Audit trail (all actions, approvals, secret access)
- Webhook delivery (approval.created, approval.resolved)
- 8+ integration tests

### Phase 2 — OAuth + Service Registry (in progress)

- OAuth engine (authorization URL, code exchange, token storage, auto-refresh)
- BYOC credential resolution with fallback chain (identity → org → system)
- Connections API (initiate, list, revoke)
- Global service template registry — YAML loader with search API
- 7 service templates shipped: Eventbrite, GitHub, Google Calendar, Resend, Slack, Stripe, X
- Connection-based execution (service + HTTP verb, token auto-injected)
- Service+action execution (registry-resolved, auth auto-resolved)
- X.com OAuth with PKCE support
- Eventbrite OAuth provider support
- E2E tests against real providers: Eventbrite (OAuth), Google Calendar (OAuth), Resend (token), X.com (OAuth+PKCE)

### Phase 2.5 — Dashboard (in progress)

- SvelteKit dashboard scaffolded (`/dashboard/`) with TypeScript, Tailwind CSS, adapter-static
- Developer Connection Tool — interactive API explorer with unified execution flow
  - Service/action selector with method and risk badges
  - Auto-generated parameter forms from action schemas (text, number, enum dropdowns)
  - Supports defined actions, custom HTTP requests, and raw HTTP (`http` pseudo-service)
  - Response panel with JSON syntax highlighting, headers table, request inspector
  - API key management with localStorage persistence

### Phase 3 — Identity Hierarchy (foundations)

- Parent/child identity relationships with `parent_id`, `depth`, `owner_id` columns
- `IdentityKind` expanded: `user`, `agent`, `sub_agent`
- Hierarchy validation: users have no parent, agents require user parent, sub_agents require agent/sub_agent parent
- `inherit_permissions` boolean stored (resolution logic not yet implemented)
- Ancestor chain query (recursive CTE) and children listing endpoints
- Enrollment approval auto-assigns parent to approving user
- `GET /v1/identities/{id}/children`, `GET /v1/identities/{id}/chain`

### Not Yet Built

- Dashboard: scaffold auth, user profile, org/agent hierarchy view, connected services, audit log
- Standalone approval resolution page (signed-URL)
- Standalone secret request page (signed-URL)
- `on_behalf_of` for agent-initiated connections
- Org service registry (DB-backed CRUD)
- OpenAPI spec import
- Human-readable action descriptions
- Phase 3: Identity hierarchy — permission chain walk, approval bubbling (parent/child + depth tracking done)
- Phase 4: Meta tools, semantic search, rate limiting, billing

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
