# Overslash

**A standalone, multi-tenant actions and authentication gateway for AI agents.**

Overslash sits between your AI agents and the outside world. It handles the
parts that every agent platform ends up reinventing badly:

- 🔐 **Secret management** — encrypted vault, versioned, never returned via API
- 🔑 **OAuth flows** — connect once, reuse across agents
- 🧬 **Permission chains** — User → Agent → SubAgent, with live inheritance
- 🙋 **Human approvals** — gaps in the permission chain bubble up to a human
- 🌐 **Authenticated HTTP execution** — agents call services without ever
  touching the credentials themselves

You point your agent at Overslash, declare what services and scopes it needs,
and Overslash takes care of authentication, authorization, approval, and
execution.

> ## ⚠️ Pre-release software
>
> Overslash is under active development and **not yet ready for production
> use**. APIs, schemas, and behaviors will change without notice. Self-host at
> your own risk, and expect breakage. We do not yet provide upgrade guarantees,
> security advisories, or stability commitments.
>
> If you want to follow along, kick the tires, or give feedback — welcome!
> If you need a stable production gateway today — wait for the first tagged
> release.

---

## What's in the box

- **Backend** — Rust + Axum REST API (`crates/overslash-api`), single `overslash` binary (`crates/overslash-cli`) with `serve` / `web` / `mcp` subcommands, MCP stdio server (`crates/overslash-mcp`)
- **Database** — PostgreSQL with versioned secrets and audit trail
- **Dashboard** — SvelteKit web UI for managing users, agents, secrets,
  connections, and approvals
- **Service registry** — YAML descriptions of third-party APIs
  (`services/*.yaml`), so actions are human-readable
- **Three execution modes** — raw HTTP, connection-based, and high-level
  service+action calls

For the full product vision, see [SPEC.md](SPEC.md). For what's actually
implemented today, see [STATUS.md](STATUS.md).

## Running locally

### Prerequisites

- Rust (toolchain pinned in `rust-toolchain.toml`)
- Docker or Podman (with `docker compose` / `podman-compose`)
- Node.js + npm (for the dashboard)
- `make`

### Quick start

```bash
# 1. Start Postgres (and write .env.local if you're in a worktree)
make local

# 2. Run database migrations
make migrate

# 3. Run the full dev stack (Postgres + API + dashboard, hot-reload)
make dev
```

That's it. The API and dashboard will be available on their default local
ports (see `docker/docker-compose.dev.yml`).

### Useful targets

| Command | What it does |
|---|---|
| `make local` | Start only Postgres |
| `make dev` | Start everything (Postgres + API + dashboard) |
| `make dev-api` | Start Postgres + API only |
| `make dev-dashboard` | Run the SvelteKit dev server (no container) |
| `make migrate` | Apply database migrations |
| `make test` | Run the Rust test suite |
| `make check` / `make fmt` / `make clippy` | Lint and formatting |
| `make down` | Stop dev services |

### Running tests

```bash
make test
```

Integration tests need Postgres running (`make local` first). When running the
full suite directly with `cargo test`, pass `--test-threads=4` to avoid
exhausting the Postgres connection pool.

### Worktree isolation

If you work on Overslash from multiple git worktrees in parallel, `make local`
auto-detects the worktree and spins up an isolated Postgres on a unique port.
No manual config required. Tear down a worktree's containers with
`make worktree-clean`.

## Connect an MCP client

Overslash ships an MCP Authorization Server at `POST /mcp` and `/oauth/*`. Any
MCP client that speaks the Streamable-HTTP transport — Claude Code, Cursor,
Windsurf, etc. — connects directly. On first use, the client opens a browser
for the OAuth flow; you sign in, pick or name an **agent** for that client to
act as, and it's done. The client is now bound to a scoped agent identity owned
by your user, not to your user directly — so its actions are auditable
separately, Layer 2 approvals route correctly, and you can revoke the agent
without touching your own account.

### Claude Code (one command)

```bash
claude mcp add --transport http overslash https://<your-overslash>/mcp
```

Run any Overslash tool (`overslash_search`, `overslash_auth whoami`, …) and
Claude Code handles the OAuth dance. For local dev, the URL is
`http://localhost:3000/mcp`.

### Manual `.mcp.json`

Works with Claude Code and any other editor that consumes the MCP standard
config format (Cursor, Windsurf, etc. with their equivalent file names):

```json
{
  "mcpServers": {
    "overslash": {
      "type": "streamable-http",
      "url": "https://<your-overslash>/mcp"
    }
  }
}
```

### `npx` (if your client supports it)

Some MCP clients accept an `npx`-style launcher. The ecosystem's canonical
launcher for adding an HTTP MCP server is still settling — check your client's
docs for the current incantation. If yours doesn't advertise one, stick to the
two options above; no Overslash-specific `npx` package is published.

### Stdio fallback

For editors that don't speak Streamable-HTTP MCP yet, the `overslash mcp`
subcommand is a 1:1 stdio↔HTTP pipe. Run `overslash mcp login` once to mint a
token, then point the editor's MCP config at the `overslash` binary. Details
in [`docs/design/mcp-oauth-transport.md`](docs/design/mcp-oauth-transport.md).

### What the consent screen is asking

When the browser opens during first-time setup, Overslash asks whether to
**create a new agent** for this client or **reuse an existing one**. That
agent — not your user — is what the MCP client authenticates as on every
subsequent call. You can rename, revoke, or scope it from the dashboard at
any time, and repeat logins from the same client skip the consent screen by
reusing the bound agent.

## Repository layout

```
crates/          Rust workspace (overslash-core, overslash-db, overslash-api, overslash-mcp, overslash-cli)
dashboard/       SvelteKit web UI
services/        Service registry YAML definitions (MIT licensed)
docs/            Design docs and architecture notes
docker/          Local dev compose files
infra/           OpenTofu/Terraform for cloud infra
SPEC.md          Product specification (the target)
STATUS.md        What's actually deployed (reality)
DECISIONS.md     Settled architectural decisions
TODO.md          Active work
```

For deeper navigation, see [CLAUDE.md](CLAUDE.md).

## Licensing

Overslash is **source-available**, not strictly open-source.

- The core (everything in this repo by default) is licensed under the
  **Elastic License 2.0** — free to use, self-host, modify, and use
  commercially, **except** you may not offer Overslash as a hosted/managed
  service to third parties.
- The service registry YAMLs in `services/` are licensed under **MIT**.
- SDKs and client libraries will be released under a more permissive license
  (TBD).

See [LICENSING.md](LICENSING.md) for the full explanation, or
[LICENSE](LICENSE) and [services/LICENSE](services/LICENSE) for the legal text.

For commercial licensing (e.g. if you want to offer a managed Overslash
service), contact Overspiral S.L.

---

Copyright © 2026 Overspiral S.L. — built in 🇪🇸.
