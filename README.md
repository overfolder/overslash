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
implemented today, see [STATUS.md](STATUS.md). Live production health is at
[status.overslash.com](https://status.overslash.com).

## Running locally

The fastest way to try Overslash is to grab a prebuilt binary, point it at
a Postgres instance, and start it. No clone, no Rust toolchain, no `make`.

### 1. Download a binary

Grab the latest release for your platform from
[github.com/overfolder/overslash/releases](https://github.com/overfolder/overslash/releases):

- `overslash-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` — Linux x86_64
- `overslash-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz` — Linux arm64
- `overslash-vX.Y.Z-aarch64-apple-darwin.tar.gz` — macOS Apple Silicon
- `overslash-vX.Y.Z-x86_64-pc-windows-msvc.zip` — Windows x86_64

Each release also publishes a `SHA256SUMS.txt` — verify with:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

Extract the archive — you get a single `overslash` binary with the dashboard
embedded.

### 2. Start Postgres

Any Postgres 14+ instance works. A throwaway one in Docker:

```bash
docker run -d --name overslash-pg \
  -e POSTGRES_PASSWORD=overslash -e POSTGRES_DB=overslash \
  -p 5432:5432 postgres:17
```

### 3. Start `overslash web`

Set the three required env vars and run the binary. The API auto-applies
migrations on first start.

```bash
export DATABASE_URL=postgres://postgres:overslash@localhost:5432/overslash
export SECRETS_ENCRYPTION_KEY=$(openssl rand -base64 32)
export SIGNING_KEY=$(openssl rand -base64 32)
./overslash web
```

Dashboard at <http://localhost:3000>. Stop with `Ctrl+C`; the binary leaves
no state outside Postgres.

> This path is enough to try Overslash. For development — hot-reload, tests,
> writing migrations — see
> [Running locally from source](#running-locally-from-source).

## Running locally from source

### Prerequisites

- Rust (toolchain pinned in `rust-toolchain.toml`)
- Docker or Podman (with `docker compose` / `podman-compose`)
- Node.js + npm (for the dashboard)
- `make`

### Quick start

```bash
# Run the full dev stack (Postgres + API + dashboard, hot-reload). Creates the
# shared `overfolder-shared` podman network, writes .env.local in worktrees, and
# the API auto-runs database migrations on startup. `make dev` is an alias.
make local

# Just need Postgres (e.g. to run the test suite)?
make local-db
```

That's it. The API and dashboard will be available on their default local
ports (see `docker/docker-compose.dev.yml`).

> **Working on migrations or SQL queries?** A few Makefile targets
> (`make new-migration`, `make sqlx-prepare`, `make check-sqlx`) need the
> `sqlx-cli` Rust binary:
>
> ```bash
> cargo install sqlx-cli --no-default-features --features postgres --locked
> ```
>
> You don't need it just to run Overslash — the API auto-runs migrations on
> startup.

### Useful targets

| Command | What it does |
|---|---|
| `make local` | Start everything (Postgres + API + dashboard); creates the shared `overfolder-shared` network |
| `make dev` | Alias of `make local` |
| `make local-db` | Start only Postgres |
| `make dev-api` | Start Postgres + API only |
| `make dev-dashboard` | Run the SvelteKit dev server (no container) |
| `make migrate` | Apply database migrations (rarely needed — the API auto-migrates on boot) |
| `make test` | Run the Rust test suite |
| `make check` / `make fmt` / `make clippy` | Lint and formatting |
| `make local-down` / `make down` | Stop dev services |

### Running tests

```bash
make test
```

Integration tests need Postgres running (`make local-db` first). When running the
full suite directly with `cargo test`, pass `--test-threads=4` to avoid
exhausting the Postgres connection pool.

### Worktree isolation

If you work on Overslash from multiple git worktrees in parallel, `make local`
(and `make local-db`) auto-detects the worktree and spins up an isolated
Postgres on a unique port.
No manual config required. Tear down a worktree's containers with
`make worktree-clean`.

## Cutting a release

Releases are published from GitHub Actions. To cut one, tag and push:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The [release workflow](.github/workflows/release.yml) builds binaries for
linux-x64, linux-arm64, macos-arm64, and windows-x64, generates
`SHA256SUMS.txt`, and publishes them to
[github.com/overfolder/overslash/releases](https://github.com/overfolder/overslash/releases).

For a dry-run, trigger the workflow manually with a `-test` suffix on the
version (e.g. `v0.1.0-test`) — it builds and uploads artifacts to the run
but does not publish a release.

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
      "type": "http",
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
