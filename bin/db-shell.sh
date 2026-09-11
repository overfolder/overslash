#!/usr/bin/env bash
# Open a psql shell against an Overslash Cloud SQL instance via the Auth Proxy.
# No public IP whitelisting, no VPN — `cloud-sql-proxy` authenticates as your
# current `gcloud` identity and tunnels through GCP's control plane.
#
# Wakes the instance first (idempotent activation-policy=ALWAYS patch + poll
# until RUNNABLE) so it works after the night scheduler has paused dev.
#
# Usage:
#   bin/db-shell.sh [env]              # dev (default) | prod
#   bin/db-shell.sh dev -c 'select 1'  # forwarded to psql
#
# Requirements:
#   - cloud-sql-proxy on PATH. It does NOT ship with the gcloud SDK - grab the
#     static binary from https://github.com/GoogleCloudPlatform/cloud-sql-proxy
#   - psql on PATH
#   - gcloud auth with `roles/cloudsql.client` and Secret Manager accessor on
#     the instance. ADC (`gcloud auth application-default login`) is preferred;
#     without it we fall back to the active gcloud identity's bearer token, so
#     this works from a service account, CI, or an agent sandbox too.
#
# Env vars:
#   PORT=<n>      pin the local proxy port (default: random in 55500–55599)
#   READONLY=1    open the session in read-only mode (default off)

set -euo pipefail

ENV_NAME="${1:-dev}"
shift || true

case "$ENV_NAME" in
  prod)      PROJECT=overslash ;;
  dev|stage) PROJECT="overslash-${ENV_NAME}" ;;
  *) echo "Unknown env: $ENV_NAME (use dev|prod)"; exit 1 ;;
esac

REGION="europe-west1"
BASE_PREFIX="overslash-${ENV_NAME}"
SQL_INSTANCE="${BASE_PREFIX}-db"
CONNECTION_NAME="${PROJECT}:${REGION}:${SQL_INSTANCE}"
DB_USER="overslash"
DB_NAME="overslash"
SECRET_NAME="${BASE_PREFIX}-db-password"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[db-shell:${ENV_NAME}]${NC} $1"; }
warn() { echo -e "${YELLOW}[db-shell:${ENV_NAME}]${NC} $1"; }
err()  { echo -e "${RED}[db-shell:${ENV_NAME}]${NC} $1" >&2; exit 1; }

command -v gcloud          >/dev/null || err "gcloud not on PATH"
command -v cloud-sql-proxy >/dev/null || err "cloud-sql-proxy not on PATH (it does not ship with gcloud; see the header)"
command -v psql            >/dev/null || err "psql not on PATH (install postgresql-client)"

# Prod safety
if [ "$ENV_NAME" = "prod" ] && [ "${READONLY:-0}" != "1" ]; then
  warn "Connecting to PRODUCTION read/write. Set READONLY=1 to open a read-only session."
  read -rp "Type 'prod' to continue: " confirm
  [ "$confirm" = "prod" ] || { echo "Aborted."; exit 1; }
fi

# Wake the instance
log "Ensuring Cloud SQL ${SQL_INSTANCE} is RUNNABLE..."
gcloud sql instances patch "$SQL_INSTANCE" \
  --activation-policy=ALWAYS --project="$PROJECT" --quiet >/dev/null 2>&1 || true
for i in $(seq 1 60); do
  state="$(gcloud sql instances describe "$SQL_INSTANCE" \
    --project="$PROJECT" --format='value(state)' 2>/dev/null || echo UNKNOWN)"
  [ "$state" = "RUNNABLE" ] && { log "  state: RUNNABLE"; break; }
  log "  state: $state — waiting..."
  sleep 10
  [ "$i" -eq 60 ] && err "Timed out waiting for SQL"
done

# Pick a port (random unless pinned)
PORT="${PORT:-$(( 55500 + RANDOM % 100 ))}"

# Fetch password from Secret Manager
log "Fetching DB password from Secret Manager..."
DB_PASSWORD="$(gcloud secrets versions access latest --secret="$SECRET_NAME" --project="$PROJECT")"

# The proxy reads ADC by default. A service account activated with plain
# `gcloud auth` has none, which is the usual shape in CI and agent sandboxes --
# so hand it a bearer token for the active identity instead. Static, and the
# proxy does not refresh it: a session outliving the ~1h token drops new
# connections. Fine for a shell, and the alternative (whitelisting the caller's
# egress IP on a shared instance) is strictly worse.
PROXY_AUTH=()
if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
  log "No ADC - authenticating the proxy as $(gcloud config get-value account 2>/dev/null)."
  PROXY_AUTH=(--token "$(gcloud auth print-access-token)")
fi

# Start proxy in background
log "Starting cloud-sql-proxy on 127.0.0.1:${PORT} -> ${CONNECTION_NAME}..."
cloud-sql-proxy ${PROXY_AUTH[@]+"${PROXY_AUTH[@]}"} --port="$PORT" "$CONNECTION_NAME" \
  >/tmp/cloud-sql-proxy.${ENV_NAME}.log 2>&1 &
PROXY_PID=$!
trap 'kill $PROXY_PID 2>/dev/null || true' EXIT INT TERM

# Wait until the proxy is accepting connections (max ~10s)
for i in $(seq 1 20); do
  if (echo > /dev/tcp/127.0.0.1/$PORT) >/dev/null 2>&1; then break; fi
  sleep 0.5
  if [ "$i" -eq 20 ]; then
    err "Proxy didn't come up in time — see /tmp/cloud-sql-proxy.${ENV_NAME}.log"
  fi
done
log "Proxy ready."

# psql. For READONLY=1 we set the GUC via PGOPTIONS so it's applied by the
# server at connection time and persists for the whole interactive session —
# `-c "SET ..."` would run the command and exit immediately, defeating the
# purpose.
PG_EXTRA_OPTIONS=""
if [ "${READONLY:-0}" = "1" ]; then
  PG_EXTRA_OPTIONS="-c default_transaction_read_only=on"
fi

PGPASSWORD="$DB_PASSWORD" PGOPTIONS="$PG_EXTRA_OPTIONS" psql \
  "host=127.0.0.1 port=${PORT} user=${DB_USER} dbname=${DB_NAME} sslmode=disable" \
  "$@"
