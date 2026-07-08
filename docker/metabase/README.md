# Local Metabase + Metabase MCP

A throwaway local Metabase instance for exploring the [Metabase MCP server]
(`@jerichosequitin/metabase-mcp`) — used to understand its tool surface and
design a good Overslash **service spec** for Metabase.

- **One shared instance** on the host (`http://localhost:3033`).
- **Claude MCP config is registered at user scope**, so it works in the base
  repo *and every `.cline/worktrees/<id>/overslash` worktree* automatically.
- App metadata is stored in a dedicated Postgres (`metabase-db`); the Overslash
  dev database is never touched. Metabase ships a **Sample Database** so the MCP
  has queryable data immediately.

## Setup (one time)

```bash
cd ~/code/overfolder/overslash
./docker/metabase/bootstrap.sh       # up + wait + create admin + mint API key
./docker/metabase/register-mcp.sh    # wire Claude Code (user scope)
```

Then restart Claude Code (or open a new session) in any worktree. The
`metabase` MCP server appears in every project.

- Metabase UI: http://localhost:3033 — `admin@overslash.local` / `Overslash123!`
- Credentials + API key: `docker/metabase/.env.metabase` (gitignored)

Both scripts are idempotent: re-running `bootstrap.sh` reuses a still-valid key,
and `register-mcp.sh` replaces the prior registration (use it to rotate).

## Config knobs

Environment overrides for `bootstrap.sh`:

| Var | Default | Meaning |
|-----|---------|---------|
| `METABASE_URL` | `http://localhost:3033` | instance URL |
| `MB_ADMIN_EMAIL` | `admin@overslash.local` | admin user |
| `MB_ADMIN_PASSWORD` | `Overslash123!` | admin password |
| `MB_KEY_NAME` | `overslash-mcp` | API key label |

For `register-mcp.sh`:

| Var | Default | Meaning |
|-----|---------|---------|
| `METABASE_READ_ONLY_MODE` | `true` | `false` lets the MCP run write SQL |
| `MCP_NAME` | `metabase` | MCP server name in Claude |

## Lifecycle

```bash
# stop (keeps data)
podman-compose -f docker/metabase/docker-compose.yml down
# start again
podman-compose -f docker/metabase/docker-compose.yml up -d
# wipe everything (drops the volume)
podman-compose -f docker/metabase/docker-compose.yml down -v
# remove the Claude registration
claude mcp remove -s user metabase
```

## The MCP server

`@jerichosequitin/metabase-mcp` — runs via `npx -y`, authenticates with a
Metabase API key, defaults to **read-only** (SELECT only). Tools cover
databases, tables/fields, cards (questions), dashboards, collections, and
native/SQL query execution — a useful reference surface when writing the
Overslash service spec. Upstream: https://github.com/jerichosequitin/metabase-mcp
