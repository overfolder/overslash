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

Set the three required env vars (see [Configuration](#configuration)) and run
the binary. The API auto-applies migrations on first start.

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

## Configuration

Overslash is configured entirely through the environment. `.env.example` is the
full annotated catalogue; this table is the part you need to start.

**An empty value means unset.** `SIGNING_KEY=""` is treated exactly as
`SIGNING_KEY` never having been exported — the API reports it as missing and
refuses to boot, rather than signing tokens with an empty key. This matters
because deployment substrates hand empty strings to processes routinely: a
Compose file's `${FOO:-}` renders as `""` when `FOO` is unset, and a Secret
Manager version can hold an empty payload. Values are trimmed, so a secret that
picked up a trailing newline from a shell pipeline still works.

### Required

The API exits at startup, naming everything that is missing, if any of these is
unset or empty.

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Postgres connection string. Migrations are applied on first start. |
| `SECRETS_ENCRYPTION_KEY` | AES-256-GCM key for the secret vault. 32 bytes. |
| `SIGNING_KEY` | Signs sessions, approval links and download/upload tokens. |

### Required in context

Only checked when the feature they belong to is switched on. Turning the
feature on without them is a startup failure, not a silent degradation.

| Variable | Required when |
|---|---|
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | `CLOUD_BILLING` is on |
| `EMAIL_API_KEY`, `EMAIL_FROM` | `EMAIL_PROVIDER` is set |

### Common optional

| Variable | Default | Purpose |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address. |
| `PORT` | `3000` | Bind port. |
| `PUBLIC_URL` | derived from `HOST`/`PORT` | The origin advertised in redirect URIs and links. Set it behind a reverse proxy. |
| `DASHBOARD_ORIGIN` | `*localhost*` | Comma-separated CORS origins. Set explicit origins in production. |
| `REDIS_URL` | unset | Valkey/Redis for rate-limit counters and the resolver cache. Unset means process-local, which is correct for a single replica. |
| `GOOGLE_AUTH_CLIENT_ID`, `GOOGLE_AUTH_CLIENT_SECRET` | unset | Google sign-in. Both halves or neither. An IdP configured here takes precedence over one configured in the dashboard. |
| `GITHUB_AUTH_CLIENT_ID`, `GITHUB_AUTH_CLIENT_SECRET` | unset | GitHub sign-in, same rules. |
| `DEV_AUTH` | off | Enables `/auth/dev/token`, a passwordless local login. **Leave off in production.** |
| `LOG_FORMAT` | text | Set to `json` for structured logs. |

### Flags

Every boolean above reads the same way: `true`, `1`, `yes` or `on` turn it on;
`false`, `0`, `no` or `off` turn it off; case does not matter. Unset, empty, or
a value that is none of those falls back to the documented default and logs a
warning naming the variable — so `DEV_AUTH=0` disables dev login rather than
enabling it on the strength of the variable merely existing.

Operator-only variables that widen egress (`OVERSLASH_SSRF_ALLOWED_CIDRS` and
the metadata override) are deliberately left out of this table; they are
documented in
[docs/compliance/casa/gap-assessment.md](docs/compliance/casa/gap-assessment.md),
which depends on their being environment-only and unset on the hosted
deployment.

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
claude mcp add --transport http --scope user overslash https://<your-overslash>/mcp
```

`--scope user` registers the server once for your whole machine rather than for
a single project; drop it to scope the server to the current project instead.
This is the command the dashboard's Agents view renders, with your org's URL
already filled in.

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

### `npx` (clients that only speak stdio)

For a client that takes an `npx`-style launcher but not Streamable-HTTP, the
community's generic stdio↔HTTP bridge works:

```bash
npx -y mcp-remote https://<your-overslash>/mcp
```

`mcp-remote` is a third-party package, not ours — no Overslash-specific `npx`
package is published. If your client speaks HTTP, prefer the two options above;
if it ships its own launcher, prefer that. The dashboard's Agents view renders
this command too, with your org's URL already filled in.

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
