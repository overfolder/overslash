# Overslash

Overslash is a standalone, multi-tenant actions and authentication gateway for AI agents. It handles secret management, OAuth, permission chains, human approvals, and authenticated HTTP execution via a REST API.

## Navigation

| When you need to... | Read this |
|---------------------|-----------|
| Understand the full product | [SPEC.md](SPEC.md) |
| Know what's deployed | [STATUS.md](STATUS.md) |
| Check settled decisions | [DECISIONS.md](DECISIONS.md) |
| Find what to work on | [TODO.md](TODO.md) |
| Understand a known workaround | [TECH_DEBT.md](TECH_DEBT.md) |
| Find a design doc | [docs/design/INDEX.md](docs/design/INDEX.md) |

## Tech Stack

- **Backend**: Rust + Axum
- **Database**: PostgreSQL (sqlx or refinery for migrations)
- **Dashboard**: SvelteKit
- **Encryption**: AES-256-GCM for secrets
- **Optional**: Redis for webhooks and pub/sub

## Git Conventions

- **Default branch**: `master`
- **PR target**: `dev` — PRs go to `dev`, then `dev` merges to `master` for releases

## Key Concepts

- **Identity hierarchy**: User → Agent → SubAgent. Permissions checked at every level.
- **`inherit_permissions`**: Live pointer — child dynamically has parent's current + future rules.
- **Three execution modes**: Raw HTTP (Mode A), Connection-based (Mode B), Service+Action (Mode C).
- **Approval bubbling**: Gap in permission chain → approval created at gap level → ancestors can resolve.
- **Versioned secrets**: Every write creates a new version. Latest used for injection. Old versions restorable.
- **Service registry**: Global YAML (shipped) + org DB (custom). Provides human-readable action descriptions.
- **`on_behalf_of`**: Agents create secrets/connections at owner-user level so all agents share them.

## Rules

1. **SPEC.md is the target. STATUS.md is reality.** Never confuse aspiration with current state.
2. **Parse, don't validate.** Config and API inputs are parsed into typed structs at the boundary.
3. **Secrets never leave the vault.** Encrypted at rest, injected at execution time, never returned via API.
4. **No platform-specific logic.** Overslash is a generic gateway. Telegram buttons, Slack bots, etc. are caller-side concerns.
