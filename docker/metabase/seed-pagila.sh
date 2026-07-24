#!/usr/bin/env bash
# Seed the local Metabase stack with the Pagila sample database (Postgres's
# canonical DVD-rental OLTP set: ~20 tables plus views, functions, and a
# partitioned `payment` table — exactly the shapes the D42 SQL policy needs
# to exercise). Then register it as a Metabase database and record its id.
#
# Idempotent: safe to re-run. Run after (or via) bootstrap.sh — it needs the
# stack up and docker/metabase/.env.metabase populated.
#
#   ./docker/metabase/bootstrap.sh && ./docker/metabase/seed-pagila.sh
#
# Downloads the two SQL files from the pinned upstream commit on first run
# (sha256-verified, cached in docker/metabase/pagila/, gitignored — ~3 MB
# that don't belong in the repo).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$HERE/.env.metabase"
CACHE_DIR="$HERE/pagila"

# devrimgunduz/pagila @ 2024-12-01 (PostgreSQL license).
PAGILA_COMMIT="5ba5a57aeb159f75f02aca2432d3c262186d13d3"
SCHEMA_SHA256="8ce358e4c8014087b85296694a0893887bd7a4190e3ce407f2721b86b98e5707"
DATA_SHA256="880580fb2cd4daaa99f290ced264988cdd657b3158be63cd281466f796f6dbf2"

DB_CONTAINER="overslash-metabase-db"

[ -f "$ENV_FILE" ] || { echo "ERROR: $ENV_FILE missing — run bootstrap.sh first" >&2; exit 1; }
MB_URL="$(sed -n 's/^METABASE_URL=//p' "$ENV_FILE" | head -1)"
API_KEY="$(sed -n 's/^METABASE_API_KEY=//p' "$ENV_FILE" | head -1)"
[ -n "$MB_URL" ] && [ -n "$API_KEY" ] || { echo "ERROR: $ENV_FILE incomplete" >&2; exit 1; }

# jq-free JSON field extraction via python3 (same idiom as bootstrap.sh).
jval() { python3 -c 'import sys,json;d=json.load(sys.stdin);print(d'"$1"')' 2>/dev/null; }

CONTAINER_RUNTIME="$(command -v podman || command -v docker)"

# --- fetch + verify the SQL files --------------------------------------------
mkdir -p "$CACHE_DIR"
fetch() {
  local file="$1" want="$2"
  local path="$CACHE_DIR/$file"
  if [ -f "$path" ] && echo "$want  $path" | sha256sum -c --quiet - 2>/dev/null; then
    return 0
  fi
  echo "==> Fetching $file @ ${PAGILA_COMMIT:0:12}"
  curl -sfL -o "$path" \
    "https://raw.githubusercontent.com/devrimgunduz/pagila/$PAGILA_COMMIT/$file"
  echo "$want  $path" | sha256sum -c --quiet - \
    || { echo "ERROR: $file checksum mismatch" >&2; rm -f "$path"; exit 1; }
}
fetch pagila-schema.sql "$SCHEMA_SHA256"
fetch pagila-data.sql "$DATA_SHA256"

# --- create + load the pagila DB on the stack's postgres ---------------------
psql_in() { "$CONTAINER_RUNTIME" exec -i "$DB_CONTAINER" psql -v ON_ERROR_STOP=1 -q -U metabase "$@"; }

# "Loaded" means the data actually landed, not just that the DB exists — a
# previously interrupted load leaves an empty/partial database behind.
pagila_loaded() {
  [ "$(psql_in -d pagila -tAc "SELECT count(*) FROM film" 2>/dev/null || echo 0)" -ge 1000 ]
}

if psql_in -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='pagila'" | grep -q 1 \
  && ! pagila_loaded; then
  echo "==> pagila database exists but is empty/partial — dropping for a clean load"
  # FORCE: Metabase may already hold sync connections to the broken DB.
  psql_in -d postgres -c "DROP DATABASE pagila WITH (FORCE)" >/dev/null
fi

if pagila_loaded; then
  echo "==> pagila database already loaded — skipping"
else
  echo "==> Creating + loading pagila (schema, then ~3 MB of data)"
  psql_in -d postgres -c "CREATE DATABASE pagila"
  # Upstream sets `OWNER TO postgres`; this stack's only role is `metabase`.
  sed 's/OWNER TO postgres/OWNER TO metabase/' "$CACHE_DIR/pagila-schema.sql" \
    | psql_in -d pagila >/dev/null
  psql_in -d pagila < "$CACHE_DIR/pagila-data.sql" >/dev/null
  echo "==> Loaded: $(psql_in -d pagila -tAc "SELECT count(*) FROM film") films"
fi

# --- register it in Metabase and pin the database id -------------------------
AUTH=(-H "x-api-key: $API_KEY")
DB_ID="$(curl -sf "${AUTH[@]}" "$MB_URL/api/database" \
  | python3 -c 'import sys,json
d = json.load(sys.stdin)
rows = d["data"] if isinstance(d, dict) else d
print(next((r["id"] for r in rows if r["name"] == "pagila"), ""))')"

if [ -z "$DB_ID" ]; then
  echo "==> Registering pagila in Metabase"
  DB_ID="$(curl -sf -X POST "${AUTH[@]}" "$MB_URL/api/database" \
    -H 'Content-Type: application/json' \
    -d '{
      "engine": "postgres",
      "name": "pagila",
      "details": {
        "host": "metabase-db", "port": 5432, "dbname": "pagila",
        "user": "metabase", "password": "metabase", "ssl": false
      }
    }' | jval '["id"]')"
fi
[ -n "$DB_ID" ] && [ "$DB_ID" != "None" ] || { echo "ERROR: could not register pagila" >&2; exit 1; }
echo "==> pagila is Metabase database id $DB_ID"

# --- wait for the initial sync so tables are queryable -----------------------
# Explicit trigger: the DB may have been registered before the load finished
# (or re-loaded since), and the periodic scan is hourly.
curl -sf -X POST "${AUTH[@]}" "$MB_URL/api/database/$DB_ID/sync_schema" >/dev/null || true
echo -n "==> Waiting for Metabase to sync the pagila schema "
for i in $(seq 1 30); do
  FIELDS="$(curl -sf "${AUTH[@]}" "$MB_URL/api/database/$DB_ID/metadata" \
    | python3 -c 'import sys,json;print(len(json.load(sys.stdin).get("tables",[])))' 2>/dev/null || echo 0)"
  if [ "${FIELDS:-0}" -ge 15 ]; then echo " ready ($FIELDS tables)"; break; fi
  echo -n "."
  sleep 2
  if [ "$i" -eq 30 ]; then echo; echo "WARN: sync still running; tests may need a moment" >&2; fi
done

# --- record the id for the e2e suite -----------------------------------------
if grep -q '^METABASE_PAGILA_DB_ID=' "$ENV_FILE"; then
  sed -i "s/^METABASE_PAGILA_DB_ID=.*/METABASE_PAGILA_DB_ID=$DB_ID/" "$ENV_FILE"
else
  echo "METABASE_PAGILA_DB_ID=$DB_ID" >> "$ENV_FILE"
fi
echo "==> Wrote METABASE_PAGILA_DB_ID=$DB_ID to $ENV_FILE"
echo "==> Run the gated suite:  make metabase-e2e"
