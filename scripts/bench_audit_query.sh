#!/usr/bin/env bash
# Benchmark: the dashboard's audit-log query under load.
#
# Reproduction for docs/design/audit-log.md § "Index behaviour under load".
# Seeds a throwaway database with 500k synthetic audit rows (400k in the
# queried org, 100k in a second org as noise), then EXPLAIN ANALYZEs the query
# shapes the dashboard actually issues, plus a timed insert loop for the write
# side.
#
# Usage: ./scripts/bench_audit_query.sh [LABEL]
# Requires: psql, sqlx-cli, running Postgres (DATABASE_URL, or the dev default)
#
# The script adapts to the schema it finds: if `audit_log.actor_name` exists it
# benchmarks the materialized-name query (post-migration 110), otherwise the
# joined-name query it replaced. So the same script produces both the "before"
# and "after" columns of the doc's table. For the "before" column, point it at a
# migration set without 110:
#
#   mkdir /tmp/m && cp crates/overslash-db/migrations/* /tmp/m/ && rm /tmp/m/110_*
#   MIGRATIONS=/tmp/m ./scripts/bench_audit_query.sh before
#
# Run both against a table of the same size — index maintenance cost per row
# grows with the table, so numbers taken at different row counts are not
# comparable.

set -euo pipefail

LABEL="${1:-run}"
DB_URL="${DATABASE_URL:-postgres://overslash:overslash@localhost:55432/overslash}"
BENCH_DB="${BENCH_DB:-audit_bench}"
MIGRATIONS="${MIGRATIONS:-crates/overslash-db/migrations}"
ROWS_MAIN="${ROWS_MAIN:-400000}"
ROWS_NOISE="${ROWS_NOISE:-100000}"

DB_HOSTPORT=$(echo "$DB_URL" | sed -E 's|.*@([^/]+)/.*|\1|')
DB_HOST="${DB_HOSTPORT%:*}"
DB_PORT="${DB_HOSTPORT#*:}"
DB_USER=$(echo "$DB_URL" | sed -E 's|.*://([^:]+):.*|\1|')
PGPASSWORD=$(echo "$DB_URL" | sed -E 's|.*://[^:]+:([^@]+)@.*|\1|')
export PGPASSWORD

psql_bench() { psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$BENCH_DB" -X -q -tA "$@"; }
psql_admin() { psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -X -q -tA "$@"; }

echo "=== Audit query benchmark ($LABEL) ==="
echo "Postgres: $DB_HOSTPORT   database: $BENCH_DB"

# --- Fresh database on the real schema -------------------------------------
psql_admin -c "DROP DATABASE IF EXISTS ${BENCH_DB} WITH (FORCE);" >/dev/null
psql_admin -c "CREATE DATABASE ${BENCH_DB};" >/dev/null
echo "--- migrating…"
DATABASE_URL="postgres://${DB_USER}:${PGPASSWORD}@${DB_HOSTPORT}/${BENCH_DB}" \
  sqlx migrate run --source "$MIGRATIONS" >/dev/null

HAS_ACTOR_NAME=$(psql_bench -c "SELECT count(*) FROM information_schema.columns
                                 WHERE table_name='audit_log' AND column_name='actor_name';")
if [ "$HAS_ACTOR_NAME" = "1" ]; then
  echo "--- schema: materialized actor_name (post-110)"
else
  echo "--- schema: joined identity name (pre-110)"
fi

# --- Seed -------------------------------------------------------------------
# Uniform synthetic data: the plan *shapes* are the durable result, the
# millisecond figures are directional. Actions and descriptions come from small
# vocabularies so a "common term" and a "1-in-4" filter are reproducible, and
# ip_address cycles over 250 values to give the sparse-equality case.
echo "--- seeding ${ROWS_MAIN} + ${ROWS_NOISE} rows…"
psql_bench <<SQL >/dev/null
INSERT INTO orgs (id, name, slug) VALUES
  ('11111111-1111-1111-1111-111111111111', 'Bench Main', 'bench-main'),
  ('22222222-2222-2222-2222-222222222222', 'Bench Noise', 'bench-noise');

-- 20 users per org, each owning 4 agents.
INSERT INTO identities (id, org_id, name, kind)
SELECT gen_random_uuid(), o.id, 'user' || g, 'user'
  FROM orgs o, generate_series(1, 20) g WHERE o.slug LIKE 'bench-%';
INSERT INTO identities (id, org_id, name, kind, owner_id)
SELECT gen_random_uuid(), u.org_id, 'agent' || u.name || '_' || g, 'agent', u.id
  FROM identities u, generate_series(1, 4) g WHERE u.kind = 'user';

INSERT INTO audit_log (org_id, identity_id, action, resource_type, detail, description, ip_address, created_at, tags)
SELECT
  '11111111-1111-1111-1111-111111111111',
  (SELECT id FROM identities i WHERE i.org_id = '11111111-1111-1111-1111-111111111111'
    OFFSET (g % 100) LIMIT 1),
  -- One action in 5000 is rare, because a *dense* equality filter rides the
  -- ordered index perfectly well; the composite index exists for the sparse
  -- case, and a benchmark without one would flatter it.
  CASE WHEN g % 5000 = 0 THEN 'rare.action'
       ELSE (ARRAY['action.executed','secret.put','approval.created','connection.created'])[1 + g % 4]
  END,
  (ARRAY['secret','approval','connection','service'])[1 + g % 4],
  '{}'::jsonb,
  'Executed query against warehouse table number ' || (g % 1000),
  '10.' || (g % 250) || '.0.1',
  now() - (g || ' seconds')::interval,
  ARRAY['service:metabase', 'sql:read']
FROM generate_series(1, ${ROWS_MAIN}) g;

INSERT INTO audit_log (org_id, action, detail, description, created_at)
SELECT '22222222-2222-2222-2222-222222222222', 'action.executed', '{}'::jsonb,
       'Noise row ' || g, now() - (g || ' seconds')::interval
FROM generate_series(1, ${ROWS_NOISE}) g;
SQL

if [ "$HAS_ACTOR_NAME" = "1" ]; then
  # The seed writes rows directly, bypassing the application INSERT that fills
  # these; the migration's own backfill is what a real deployment would run.
  psql_bench -c "UPDATE audit_log a SET actor_name = i.name FROM identities i
                  WHERE i.id = a.identity_id AND i.org_id = a.org_id;" >/dev/null
fi
psql_bench -c "VACUUM ANALYZE audit_log;" >/dev/null

# --- Query shapes -----------------------------------------------------------
ORG="'11111111-1111-1111-1111-111111111111'"
SELECT_COLS="a.id, a.org_id, a.identity_id, a.action, a.description, a.created_at"

if [ "$HAS_ACTOR_NAME" = "1" ]; then
  FROM_CLAUSE="FROM audit_log a"
  # Post-110: no join at all, and the free-text clause carries the redundant
  # single-pattern pruning conjunct the trigram index can serve.
  q_pred() { # $1 = array literal of terms, $2 = pruning pattern
    echo "AND NOT EXISTS (SELECT 1 FROM unnest($1::text[]) AS term
                           WHERE NOT COALESCE(a.action ILIKE term
                                           OR a.description ILIKE term
                                           OR a.actor_name ILIKE term, FALSE))
          AND ($2::text IS NULL OR (a.action || ' ' || COALESCE(a.description, '')
                || ' ' || COALESCE(a.actor_name, '')) ILIKE $2)"
  }
  ORDER="ORDER BY a.created_at DESC, a.id DESC"
else
  FROM_CLAUSE="FROM audit_log a
               LEFT JOIN identities i ON i.id = a.identity_id AND i.org_id = a.org_id
               LEFT JOIN identities owner ON owner.id = i.owner_id AND owner.org_id = a.org_id"
  q_pred() {
    echo "AND NOT EXISTS (SELECT 1 FROM unnest($1::text[]) AS term
                           WHERE NOT COALESCE(a.action ILIKE term
                                           OR a.description ILIKE term
                                           OR i.name ILIKE term, FALSE))"
  }
  ORDER="ORDER BY a.created_at DESC"
fi

run() { # $1 = name, $2 = predicate/suffix SQL
  echo ""
  echo "### $1"
  psql_bench -c "EXPLAIN (ANALYZE, BUFFERS, COSTS OFF)
                 SELECT $SELECT_COLS $FROM_CLAUSE
                  WHERE a.org_id = $ORG $2" \
    | grep -E "Execution Time|Planning Time|Seq Scan|Index Scan|Bitmap|Sort|Limit|Nested Loop" | head -12
}

run "no filters, first page"          "$ORDER LIMIT 50"
run "q = one common term"             "$(q_pred "ARRAY['%warehouse%']" "'%warehouse%'") $ORDER LIMIT 50"
run "q = two common terms"            "$(q_pred "ARRAY['%warehouse%','%executed%']" "'%warehouse%'") $ORDER LIMIT 50"
run "action = (1 in 4)"               "AND a.action = 'secret.put' $ORDER LIMIT 50"
run "action = (1 in 5000, sparse)"    "AND a.action = 'rare.action' $ORDER LIMIT 50"
run "ip_address = (1 in 250)"         "AND a.ip_address = '10.42.0.1' $ORDER LIMIT 50"
run "ip_address = (repeat)"           "AND a.ip_address = '10.42.0.1' $ORDER LIMIT 50"
run "q matching nothing"              "$(q_pred "ARRAY['%zzzznotathing%']" "'%zzzznotathing%'") $ORDER LIMIT 50"
run "resource_type = (1 in 4)"        "AND a.resource_type = 'approval' $ORDER LIMIT 50"
run "OFFSET 5000"                     "$ORDER LIMIT 50 OFFSET 5000"

if [ "$HAS_ACTOR_NAME" = "1" ]; then
  # Keyset equivalent of page 101 — the shape that replaces OFFSET 5000.
  CURSOR=$(psql_bench -c "SELECT created_at || '|' || id FROM audit_log
                           WHERE org_id = $ORG ORDER BY created_at DESC, id DESC
                           OFFSET 5000 LIMIT 1;")
  CTS="${CURSOR%%|*}"; CID="${CURSOR##*|}"
  run "keyset at the same depth" \
      "AND a.created_at <= '$CTS'::timestamptz
       AND (a.created_at < '$CTS'::timestamptz OR a.id < '$CID'::uuid) $ORDER LIMIT 50"
fi

# --- Write side -------------------------------------------------------------
# audit_log is the hottest insert path in the system; every index on it is paid
# on every write. Measured against the same schema the reads just used.
echo ""
echo "### insert throughput (10k rows, single session)"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$BENCH_DB" -X -q -c "\timing on" -c "
INSERT INTO audit_log (org_id, identity_id, action, resource_type, detail, description, ip_address, tags)
SELECT $ORG,
       (SELECT id FROM identities i WHERE i.org_id = $ORG OFFSET (g % 100) LIMIT 1),
       'action.executed', 'secret', '{}'::jsonb,
       'Executed query against warehouse table number ' || g,
       '10.1.0.1', ARRAY['service:metabase','sql:read']
FROM generate_series(1, 10000) g;" 2>&1 | grep -i "^Time" || true

echo ""
echo "=== done ($LABEL). Drop with: DROP DATABASE ${BENCH_DB};"
