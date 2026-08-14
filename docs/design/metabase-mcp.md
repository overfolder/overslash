# Metabase MCP — reference & service-spec notes

**Status:** Shipped — `services/metabase.yaml` and the full SQL policy (all
D42 tiers) landed together; the annotation surface shipped in the amended
shape settled in **DECISIONS.md D43** (`x-overslash-sql-field` merges the
field nomination with the body path; `risk: dynamic`; `column_star` deny
keys). This doc remains the background reference. The gated live-stack suite
is `make metabase-e2e` (docker/metabase + Pagila).

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

## SQL policy: parser choice & enforcement scope (D42)

The question beyond "gate the write action behind approval" is whether Overslash
should **parse the SQL** to enforce read/write and per-table/column rules. The
operator's priorities: care a lot about **read-vs-write, table names, column
names**; care little about the rest; **Postgres first**. Settled shape (D42):

### Pluggable via two field annotations (not a Metabase-specific code path)

Policy attaches to **fields**, so any SQL-bearing tool (Metabase `execute`,
HubSpot `query_crm_data`, Shopify ShopifyQL) opts in identically. Both are
ordinary `x-overslash-*` vendor annotations (normalized via `openapi/alias.rs`) —
**not** a synthetic OpenAPI type: 3.1 has no `sql` type and we don't invent one.

- `x-overslash-sql: true` on the string param carrying the query → turns on
  parse-and-classify for the call.
- `x-overslash-sql-database: <jq expr>` → a **jq expression over the call params**
  (one field `.database_id`, or a composition `.project + "/" + .dataset`) whose
  result keys into per-instance config (`x-overslash-instance-config` /
  `x-overslash-config`, D38): `{ "5": { dialect: "postgres", label: "reveni-prod" } }`.
  Resolves the **dialect** to parse with + a human **DB label** for audit. Reuses
  the jq engine already behind `x-overslash-disclose`/`-transform` (D27).
  Unresolved → default `postgres`, fail-closed.

### Parser: `pg_query` (libpg_query), not `sqlparser-rs`

Use the **`pg_query` crate** (Rust bindings over `libpg_query` — Postgres's own C
parser, as used by pganalyze). It parses anything Postgres accepts *identically*
and exposes `.tables()`, column refs, and statement types directly; the
dialect-approximation fragility that dogs a pure-Rust parser (`sqlparser-rs`'s
`PostgreSqlDialect`) — and its weakness on the read/write traps — is the reason to
prefer it, since correctness on read/write + table/column is the entire point.
Cost: a **C-toolchain build dependency + larger binary**, so gate it behind a
**`sql_policy` Cargo feature, off by default** (the default build and CI jobs that
don't compile the feature stay unaffected). Dialect is resolved per DB field, not
pinned per action, so a second backend (`sqlparser-rs` for best-effort dialects)
can be added later without touching the rule surface.

### What parsing guarantees — asymmetric, stated honestly

- **Read vs write — enforceable.** Classify from the parse tree, fail-closed:
  `SELECT`/`WITH`-only → read; DML/DDL/`TRUNCATE`/`COPY`, **multi-statement**,
  **writable CTE** (`WITH t AS (DELETE … RETURNING …) …`), `DO`/`CALL`, or
  unparseable → write. Elevates the action's otherwise-static `Risk` so writes
  route to the existing approval bubbling. This is where parsing beats both the
  MCP's regex and a read-only key *for approval routing*.
- **Table names — enforceable.** `.tables()` lists referenced relations → one
  derived permission key per table, DB-label-scoped, reusing the `scope_param` key
  shape (`metabase:execute:table=reveni-prod/public.orders`) and the existing glob
  rule engine — no new grammar. Caveats: unqualified names depend on `search_path`
  (require schema-qualified rules); a **view** is gated as its own name.
- **Column names — fail-closed detection only.** Parsing yields *referenced*
  identifiers, not *resolved* columns. **`SELECT *` surfaces `*` as a literal
  column name** (and `t.*` as `*` under `t`), so a deny-`*` rule fails closed and
  **forces explicit enumeration**, after which listed columns bite. But views/CTEs
  hide base-table columns from any parser, so **true column masking (PII) pushes
  down to Metabase data-sandboxing / column DB grants** — never claimed as an
  Overslash-side guarantee.

**Net:** read/write + table rules enforce in Overslash; column masking is the
DB's job. Keep the read-only Metabase key as the backstop regardless (belt +
suspenders). Wiring point: `crates/overslash-api/src/routes/actions/call.rs`, where
full `req.params` is already in memory before the ceiling/chain walk.

### Function calls — enforceable, added after the fact (D69)

The list above shipped with one hole written down as a non-guarantee:
"volatile functions inside a SELECT classify read — function-level policy is
out of scope, DB grants own it." Delegating to DB grants reads fine and does
not hold, because the gateway is precisely the layer an org reaches for when
it *cannot* re-grant the upstream — the Metabase service account is shared,
and `risk: dynamic` promises Overslash will tell read from write on its
behalf. Under the D42 rule `SELECT pg_read_file('/etc/passwd')`,
`SELECT dblink_exec('…','DELETE FROM t')` and
`SELECT query_to_xml('DELETE FROM t', …)` were all reads that auto-approved
and executed; the last two are arbitrary write execution through a statement
the classifier had just certified.

D69 closes it by making the function set part of the verdict, **fail-closed**:
a `SELECT` stays read only while every function it invokes is on a safe list,
and a miss both elevates to write and drops `tables_exhaustive`, because a UDF
body or a `dblink` host reaches relations the `FROM` clause never named.

The list is generated, not curated: every `pg_catalog` function Postgres marks
IMMUTABLE or STABLE, since Postgres's own contract is that those cannot modify
the database. That single rule excludes `nextval`, `set_config`,
`pg_read_file`, `lo_import` and `pg_terminate_backend` without naming any of
them, and it scales to a namespace `CREATE FUNCTION` extends at runtime — the
reason a denylist was rejected. Two subtractions and one addition are made by
hand and each says why in the source: the relation-slurping XML functions
(STABLE, but they read a relation named at runtime) and `txid_current`
(STABLE, but it assigns an xid) come out; `pg_sleep` and its
volatile-but-harmless siblings go in. Per-database `safe_functions` in the
`sql_databases` config is the escape hatch for PostGIS, `unaccent` and
in-house UDFs.

The subtle half is the **enumeration**, not the list. `pg_query`'s `nodes()`
iterator is a hand-written per-variant field list and skips seven positions —
aggregate `FILTER`, `LIMIT`/`OFFSET`, `VALUES` rows, `DISTINCT ON`, window
frame `ORDER BY`, `agg_order`, array subscripts — which for D42's table
enumeration is imprecision and for a screen is a bypass. The walk re-roots at
each dropped field for precision, and is then *checked* against a count of
`FuncCall` nodes taken from prost's derived `Debug` rendering of the tree, so
a call the walk could not reach fails the statement closed instead of passing
as a read. Operators remain unscreened — an `A_Expr` names an operator, not a
function, and resolving one to its implementing function needs a catalog the
classifier does not have.

## Outcome (2026-07-24)

Everything above shipped in one change rather than the audit-first sequence —
see **D43** for the deltas discovered during implementation:

- `services/metabase.yaml`: 5 read actions + `run_query`/`export_query` at
  `risk: dynamic`, disclose capturing the raw SQL, `x-api-key` secret scheme,
  `sql_databases` config var.
- `x-overslash-sql` + body nesting merged into **`x-overslash-sql-field:
  <dotted-path>`** (string params are placed at the path; object params are
  descended into — Metabase's export endpoint takes the dataset query as one
  nested object, which is what forced extraction mode).
- Classifier in `overslash_core::sql_policy` behind the default-off
  `sql_policy` feature (release builds enable it; Windows stays fail-closed).
- Per-table keys split by context — reads mint `table={label}/{relation}`,
  mutation targets mint `table_mut={label}/{relation}` (+ mutation-shaped
  sentinel), so a remembered read grant never authorizes writes and
  asymmetric policies are expressible; `column=`/`column_star=` deny screen,
  ladder `**` rungs, deny-sweep under the `auto_approve_level` bypass.
- Verified against a live Metabase + Pagila (views, partitioned `payment`,
  CSV export): `make metabase-up` / `make metabase-e2e`.
