#!/usr/bin/env bash
# Capture standalone /approvals/[id] screenshots end-to-end against the
# full podman-compose dev stack (postgres + api + dashboard).
#
# Usage:
#   ./dashboard/scripts/screenshot-approvals.sh            # boots stack, runs, leaves it up
#   KEEP_STACK=0 ./dashboard/scripts/screenshot-approvals.sh   # tear down at end
#
# Requires: podman-compose (or docker compose), curl, jq, node (>=18), npx.
# Playwright is installed on demand into dashboard/node_modules.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

DASH_URL="${DASH_URL:-http://localhost:5173}"
API_URL="${API_URL:-http://localhost:3000}"
COMPOSE_FILE="docker/docker-compose.dev.yml"
COMPOSE="$(command -v podman-compose || command -v docker-compose || echo 'docker compose')"
KEEP_STACK="${KEEP_STACK:-1}"

log() { printf '\033[0;32m[screenshots]\033[0m %s\n' "$*"; }
err() { printf '\033[0;31m[screenshots]\033[0m %s\n' "$*" >&2; }

cleanup() {
  if [[ "$KEEP_STACK" != "1" ]]; then
    log "tearing down stack"
    $COMPOSE -f "$COMPOSE_FILE" down || true
  fi
}
trap cleanup EXIT

# 1. Ensure stack is up. `make dev` builds + runs api with cargo-watch + dashboard.
log "starting stack ($COMPOSE up -d)"
$COMPOSE -f "$COMPOSE_FILE" up -d postgres api dashboard

# 2. Wait for api and dashboard to respond.
wait_for() {
  local url="$1" name="$2" tries=120
  log "waiting for $name at $url"
  while ((tries-- > 0)); do
    if curl -fsS -o /dev/null "$url"; then
      log "$name ready"
      return 0
    fi
    sleep 2
  done
  err "$name did not become ready"
  exit 1
}
wait_for "$API_URL/health" "api"
wait_for "$DASH_URL" "dashboard"

# 3. Get a dev session cookie via the vite-proxied dashboard host so the cookie
#    binds to localhost:5173 (the host Playwright will use).
log "minting dev session cookie"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"; cleanup' EXIT
DEV_TOKEN_JSON="$(curl -sS -c "$COOKIE_JAR" "$DASH_URL/auth/dev/token" || true)"
if ! echo "$DEV_TOKEN_JSON" | jq -e .org_id >/dev/null 2>&1; then
  err "/auth/dev/token did not return a session — set DEV_AUTH=1 in .env and restart the api container ($COMPOSE -f $COMPOSE_FILE up -d --force-recreate api)"
  echo "$DEV_TOKEN_JSON" >&2
  exit 1
fi
ORG_ID="$(echo "$DEV_TOKEN_JSON" | jq -r .org_id)"
IDENTITY_ID="$(echo "$DEV_TOKEN_JSON" | jq -r .identity_id)"
SESSION_COOKIE="$(awk '$6=="oss_session" {print $7}' "$COOKIE_JAR")"
if [[ -z "$SESSION_COOKIE" || "$ORG_ID" == "null" ]]; then
  err "failed to obtain dev session — is dev_auth_enabled=true in the api config?"
  echo "$DEV_TOKEN_JSON" >&2
  exit 1
fi
log "org=$ORG_ID identity=$IDENTITY_ID"

# 4. Insert a pending approval directly via psql so we don't need a configured
#    service or secret. permission_keys[] uses two granular keys so the
#    suggested-tier picker has something to render.
log "inserting fixture approval"
TOKEN="screenshot-$(date +%s)"
APPROVAL_ID="$(
  $COMPOSE -f "$COMPOSE_FILE" exec -T postgres \
    psql -U overslash -d overslash -At -c "
      INSERT INTO approvals (org_id, identity_id, action_summary, action_detail,
                             permission_keys, token, expires_at)
      VALUES ('$ORG_ID', '$IDENTITY_ID',
              'POST https://api.example.com/messages',
              '{\"method\":\"POST\",\"url\":\"https://api.example.com/messages\"}'::jsonb,
              ARRAY['example:messages.send:channel-general',
                    'example:messages.send:channel-random'],
              '$TOKEN',
              now() + interval '1 hour')
      RETURNING id;
    " | tr -d '[:space:]'
)"
log "approval_id=$APPROVAL_ID"

# 5. Install playwright on demand (kept out of package.json devDeps to avoid
#    bloating the production lockfile).
cd "$REPO_ROOT/dashboard"
if [[ ! -d node_modules/playwright ]]; then
  log "installing playwright (one-time)"
  npm install --no-save playwright >/dev/null
  npx playwright install chromium >/dev/null
fi

# 6. Run the playwright screenshot script.
mkdir -p screenshots
SESSION_COOKIE="$SESSION_COOKIE" \
APPROVAL_ID="$APPROVAL_ID" \
DASH_URL="$DASH_URL" \
node scripts/screenshot-approvals.mjs

log "done — screenshots written to dashboard/screenshots/"
ls -1 screenshots
