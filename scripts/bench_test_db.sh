#!/usr/bin/env bash
# Benchmark: sqlx migrate (current) vs CREATE DATABASE ... TEMPLATE (proposed)
#
# Usage: ./scripts/bench_test_db.sh [ITERATIONS]
# Requires: psql, sqlx-cli, running Postgres

set -euo pipefail

ITERATIONS="${1:-10}"
DB_URL="${DATABASE_URL:-postgres://overslash:overslash@localhost:55432/overslash}"
MIGRATIONS="crates/overslash-db/migrations"

# Extract connection parts
DB_HOST=$(echo "$DB_URL" | sed -E 's|.*@([^/]+)/.*|\1|')
DB_USER=$(echo "$DB_URL" | sed -E 's|.*://([^:]+):.*|\1|')
DB_PASS=$(echo "$DB_URL" | sed -E 's|.*://[^:]+:([^@]+)@.*|\1|')
export PGPASSWORD="$DB_PASS"

psql_cmd() {
  psql -h "${DB_HOST%:*}" -p "${DB_HOST#*:}" -U "$DB_USER" -d overslash -tAc "$1" 2>/dev/null
}

psql_no_db() {
  psql -h "${DB_HOST%:*}" -p "${DB_HOST#*:}" -U "$DB_USER" -d postgres -tAc "$1" 2>/dev/null
}

echo "=== Test DB Benchmark ==="
echo "Postgres: $DB_HOST"
echo "Iterations: $ITERATIONS"
echo ""

# --- Benchmark 1: Current approach (create DB + full migrate) ---
echo "--- Approach 1: CREATE DB + sqlx migrate run (current) ---"
migrate_times=()
for i in $(seq 1 "$ITERATIONS"); do
  db_name="bench_migrate_${i}"
  psql_no_db "DROP DATABASE IF EXISTS ${db_name};" || true

  start=$(date +%s%N)
  psql_no_db "CREATE DATABASE ${db_name};"
  migrate_url="${DB_URL/overslash@${DB_HOST}\/overslash/overslash@${DB_HOST}\/${db_name}}"
  DATABASE_URL="$migrate_url" sqlx migrate run --source "$MIGRATIONS" > /dev/null 2>&1
  end=$(date +%s%N)

  elapsed_ms=$(( (end - start) / 1000000 ))
  migrate_times+=("$elapsed_ms")
  printf "  Run %2d: %dms\n" "$i" "$elapsed_ms"

  # Cleanup
  psql_no_db "DROP DATABASE IF EXISTS ${db_name};" || true
done

# --- Create template DB for approach 2 ---
echo ""
echo "--- Creating template database ---"
psql_no_db "DROP DATABASE IF EXISTS bench_template;" || true
psql_no_db "CREATE DATABASE bench_template;"
template_url="${DB_URL/overslash@${DB_HOST}\/overslash/overslash@${DB_HOST}\/bench_template}"
DATABASE_URL="$template_url" sqlx migrate run --source "$MIGRATIONS" > /dev/null 2>&1
echo "  Template created with all migrations applied."

# --- Benchmark 2: Template approach (CREATE DATABASE ... TEMPLATE) ---
echo ""
echo "--- Approach 2: CREATE DATABASE ... TEMPLATE (proposed) ---"
template_times=()
for i in $(seq 1 "$ITERATIONS"); do
  db_name="bench_template_${i}"
  psql_no_db "DROP DATABASE IF EXISTS ${db_name};" || true

  start=$(date +%s%N)
  psql_no_db "CREATE DATABASE ${db_name} TEMPLATE bench_template;"
  end=$(date +%s%N)

  elapsed_ms=$(( (end - start) / 1000000 ))
  template_times+=("$elapsed_ms")
  printf "  Run %2d: %dms\n" "$i" "$elapsed_ms"

  # Cleanup
  psql_no_db "DROP DATABASE IF EXISTS ${db_name};" || true
done

# Cleanup template
psql_no_db "DROP DATABASE IF EXISTS bench_template;" || true

# --- Results ---
echo ""
echo "=== Results ==="

sum_migrate=0
for t in "${migrate_times[@]}"; do sum_migrate=$((sum_migrate + t)); done
avg_migrate=$((sum_migrate / ITERATIONS))

sum_template=0
for t in "${template_times[@]}"; do sum_template=$((sum_template + t)); done
avg_template=$((sum_template / ITERATIONS))

speedup=$(echo "scale=1; $avg_migrate / $avg_template" | bc 2>/dev/null || echo "N/A")

echo "  Migrate approach:  avg ${avg_migrate}ms per DB"
echo "  Template approach: avg ${avg_template}ms per DB"
echo "  Speedup: ${speedup}x"
echo ""
echo "  Projected for 125 tests:"
echo "    Current:  $((avg_migrate * 125 / 1000))s"
echo "    Template: $((avg_template * 125 / 1000))s"
echo "    Saved:    $(( (avg_migrate - avg_template) * 125 / 1000 ))s"
