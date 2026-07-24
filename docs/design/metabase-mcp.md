# Metabase MCP — reference & service-spec notes

**Status:** Draft — reference (input for a future `services/metabase.yaml`)

Notes from installing and exercising the [Metabase MCP server]
(`@jerichosequitin/metabase-mcp`) against a local Metabase, to inform an
Overslash Metabase **service spec**. The local setup that produced these notes
lives in [`docker/metabase/`](../../docker/metabase/README.md) (one shared
instance on `http://localhost:3033`, Claude MCP registered at user scope so it
reaches the base repo and every worktree).

## The MCP at a glance

- **Transport:** stdio, launched via `npx -y @jerichosequitin/metabase-mcp`.
- **Auth:** a Metabase **API key** sent as the `x-api-key` header (env
  `METABASE_API_KEY`). Email+password is also supported but the key is the
  clean path.
- **Shape:** a thin, *generic* wrapper over the Metabase REST API
  (`/api/database`, `/api/dataset`, `/api/card`, `/api/search`, …) — six
  meta-tools, not per-resource operations.

| Tool | Purpose | Class |
|------|---------|-------|
| `search` | Native search over cards/dashboards/tables/collections/etc. (optionally inside SQL bodies) | read |
| `list` | Bulk overview of one model type (`cards`/`dashboards`/`tables`/`databases`/`collections`), paginated + cached | read |
| `retrieve` | Full detail for ≤50 IDs of one model (incl. `field`, table schemas) | read |
| `execute` | **Run raw SQL** (SQL mode) *or* run a saved card (card mode); ≤500 rows | read **and write** |
| `export` | Like `execute` but ≤1M rows → writes a CSV/JSON/XLSX to `~/Downloads/Metabase` | read (+ local file write) |
| `clear_cache` | Flush the MCP's internal response cache | local |

## Raw SQL

Yes. `execute` (SQL mode) runs any valid SQL against a `database_id`, with
`{{template variables}}` bound via `native_parameters`; `export` does the same
for large pulls. Verified live against the H2 Sample Database:

- `SELECT category, COUNT(*), AVG(price) FROM products GROUP BY category` → rows
  returned.
- `DROP TABLE …` with `METABASE_READ_ONLY_MODE=true` → rejected.

**Caveat that matters for the spec:** the read-only guard is enforced
**client-side in the MCP** — it regex-matches the SQL string and rejects
anything that isn't a SELECT. Metabase itself is *not* enforcing it. A caller
talking to Metabase directly, or a statement that dodges the regex, is not
bound by it. The real boundary is Metabase's own **connection / native-query
permissions** (a read-only DB user or a restricted permission group).

## Fit with Overslash

Good on the mechanics; the tool *shape* tells us how to model it.

**Fits cleanly**
- **Auth → secret injection.** A static API key in a header is exactly
  Overslash Mode C. One `x-api-key` secret.
- **Read/discovery actions** (`search`, `list`, `retrieve`, SELECT-only
  `execute`) are naturally **low risk-class** — the kind `overslash_read` can
  invoke without a confirmation prompt.

**Friction / design decisions**
- **Don't wrap this MCP; wrap the REST API it calls.** An Overslash service
  spec is per-operation (OpenAPI 3.1 + `x-overslash-*`). Split the six
  meta-tools into discrete, individually risk-classed actions:
  - `list_databases`, `get_database_schema`, `list_cards`, `run_card`,
    `run_query` (native SELECT) → **low / medium** risk.
  - arbitrary native SQL (write-capable `execute`) → **high** risk →
    permission-scoped + human-approval bubbling.
- **Don't port the client-side read-only regex.** Model the boundary the
  Overslash way: risk class + approval on the write action, backed by a
  **read-only Metabase key/group** as the actual enforcement. Belt (risk
  class) and suspenders (Metabase perms).
- **`export` writes to local disk** — undesirable in a gateway. A service-spec
  `export` action should return the payload (or a URL), not touch a filesystem.

## Next step

Draft `services/metabase.yaml`: API-key auth (`x-api-key`), the read actions
above as low-risk, and native SQL gated behind approval — using the discrete
REST endpoints rather than the MCP's six meta-tools.
