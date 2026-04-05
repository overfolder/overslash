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
- Template/service instance split — templates (YAML blueprints) + service instances (named, with credentials and lifecycle)
- Service+action execution (registry-resolved, auth auto-resolved)
- `scope_param` on service actions — permission keys use specific args from action params
- Description interpolation — `{param}` substitution and `[optional segments]` in action descriptions
- Human-readable audit descriptions — interpolated descriptions for Mode C, `METHOD host/path` for Mode A, `identity_name` resolved in audit responses
- Suggested tiers + derived_keys on approval payloads (2-4 broadening levels)
- Approval resolution API aligned with spec (`resolution` + `remember_keys` + `ttl`)
- X.com OAuth with PKCE support
- Eventbrite OAuth provider support
- E2E tests against real providers: Eventbrite (OAuth), Google Calendar (OAuth), Resend (token), X.com (OAuth+PKCE)
- sqlx compile-time query checking enforced across all repos

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

### Dashboard (SvelteKit)

- Auth-gated admin sidebar with 5 management sections (visible to `kind=user` identities only)
- **Templates management** — browse, search, create, edit, delete org templates; global templates shown read-only
- **Services management** — CRUD for service instances, inline status changes (draft/active/archived)
- **Groups management** — master-detail UI with member assignment and service grant management (access level + auto-approve reads)
- **Webhooks management** — CRUD for webhook subscriptions + expandable delivery history with color-coded status codes
- **Settings** — org name/slug editing, `allow_user_templates` policy toggle, IdP config management (env/db sources with badges), member list
- Backend: `GET/PUT /v1/orgs/me` for org settings, `GET /v1/webhooks/{id}/deliveries` for delivery log, migration 022 (`allow_user_templates`)
- Reusable components: DataTable, Modal, EmptyState, StatusBadge; shared admin CSS
- Playwright screenshot script for CI proof-of-work

### Not Yet Built

- Dashboard: org/agent hierarchy view, connected services, audit log viewer
- Dashboard: standalone pages (approval resolution, secret request, enrollment consent)
- `on_behalf_of` for agent-initiated connections
- Template validation endpoint + OpenAPI import
- Org-level ACL (role-based access control for who can manage groups, services, etc.)
- Phase 3: `inherit_permissions` resolution, permission chain walk, approval bubbling (parent/child + depth tracking done)
- Phase 4: Meta tools, semantic search, rate limiting, billing, documentation site

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
