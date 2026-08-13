#!/usr/bin/env bash
#
# Regenerate crates/overslash-core/src/sql_policy/catalog_functions.rs — the
# D69 list of `pg_catalog` functions a SELECT may call and still classify read.
#
# Usage: ./scripts/gen-sql-safe-functions.sh
# Requires: podman or docker. Nothing else; the container is throwaway.
#
# Why the catalog is the authority: Postgres's own contract is that an
# IMMUTABLE or STABLE function "cannot modify the database" (see the CREATE
# FUNCTION docs). So volatility, not our taste, decides the bulk of the list —
# and it draws the line exactly where we want it, keeping `nextval`,
# `pg_read_file`, `lo_import`, `set_config` and `pg_terminate_backend` out
# without us naming a single one of them.
#
# Two things volatility does *not* catch, so they are subtracted by hand below:
#
#   1. The relation-slurping XML functions are STABLE (they only read) but they
#      take a table/schema/database *by name at runtime*, so they read
#      relations the parse tree never mentions. That would silently break the
#      table-enumeration guarantee D42/D43 promise, which is a harder promise
#      than read-vs-write. `query_to_xml`/`cursor_to_xml` are already volatile.
#   2. `txid_current` / `pg_current_xact_id` are STABLE but assign a real
#      transaction id when the transaction does not have one — an irreversible
#      bump of a global counter. The `_if_assigned` and `_snapshot` variants
#      only observe, so they stay.
#
# Run against the Postgres major that libpg_query 6 vendors (17), so the list
# and the parser agree on what exists.

set -euo pipefail

PG_IMAGE="docker.io/library/postgres:17-alpine"
CONTAINER="overslash-gen-sql-safe-functions"
OUT="crates/overslash-core/src/sql_policy/catalog_functions.rs"

# Subtracted from the volatility query — see the header. Kept as a SQL list so
# the generated file is exactly what the query returned.
EXCLUDED="
  'table_to_xml', 'table_to_xmlschema', 'table_to_xml_and_xmlschema',
  'schema_to_xml', 'schema_to_xmlschema', 'schema_to_xml_and_xmlschema',
  'database_to_xml', 'database_to_xmlschema', 'database_to_xml_and_xmlschema',
  'txid_current', 'pg_current_xact_id'
"

RUNTIME=$(command -v podman || command -v docker) || {
    echo "need podman or docker" >&2
    exit 1
}

cleanup() { "$RUNTIME" rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

cleanup
"$RUNTIME" run --rm -d --name "$CONTAINER" -e POSTGRES_PASSWORD=gen "$PG_IMAGE" >/dev/null

for _ in $(seq 1 60); do
    "$RUNTIME" exec "$CONTAINER" pg_isready -U postgres >/dev/null 2>&1 && break
    sleep 1
done

psql() { "$RUNTIME" exec "$CONTAINER" psql -U postgres -tAc "$1"; }

version=$(psql "SELECT current_setting('server_version')")

# prokind: f=function, a=aggregate, w=window. Procedures ('p') are excluded —
# they are only reachable through CALL, which already classifies write.
names=$(psql "
    SELECT DISTINCT p.proname
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'pg_catalog'
      AND p.provolatile IN ('i', 's')
      AND p.prokind IN ('f', 'a', 'w')
      AND p.proname NOT IN ($EXCLUDED)
    ORDER BY 1
")

count=$(printf '%s\n' "$names" | grep -c . || true)

{
    cat <<HEADER
//! GENERATED — do not edit. Run \`./scripts/gen-sql-safe-functions.sh\`.
//!
//! Every \`pg_catalog\` function, aggregate and window function that Postgres
//! $version marks IMMUTABLE or STABLE, minus the by-hand subtractions the
//! generator documents (relation-slurping XML functions, xid assignment).
//! Postgres guarantees non-volatile functions cannot modify the database, so
//! calling one from a SELECT keeps the statement a read.
//!
//! Sorted by Postgres's \`ORDER BY\`, which is C-collation here (ASCII), so
//! [\`CATALOG_SAFE\`] is safe to binary-search with Rust's byte ordering. The
//! test in the parent module pins that.

/// $count names, sorted.
#[rustfmt::skip]
pub(super) static CATALOG_SAFE: &[&str] = &[
HEADER

    # Pack ~4 per line rather than one-per-line: crates/*/src/*.rs is capped at
    # 1000 lines by scripts/check-line-counts.sh.
    printf '%s\n' "$names" | grep . | sed 's/.*/"&",/' | fmt -w 68 | sed 's/^/    /'

    echo '];'
} >"$OUT"

echo "wrote $OUT — $count names from Postgres $version ($(wc -l <"$OUT") lines)"
