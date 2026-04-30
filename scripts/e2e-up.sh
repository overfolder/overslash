#!/usr/bin/env bash
# Bring up the full e2e stack: Postgres → overslash-fakes → API → dashboard
# preview, all on dynamic ports written into a per-worktree state dir.
#
# Idempotent within reason: tearing down via `make e2e-down` is recommended
# between runs. Re-runs without teardown will pick a new state dir slot only
# if the prior state file is missing (otherwise it errors out — manual stale
# state needs explicit cleanup).
#
# Outputs:
#   $STATE_DIR/.e2e/fakes.ports.json   — written by overslash-fakes
#   $STATE_DIR/.e2e/api.url            — chosen API listen URL
#   $STATE_DIR/.e2e/dashboard.url      — chosen dashboard preview URL
#   $STATE_DIR/.e2e/dashboard.env      — KEY=VALUE file consumed by playwright.config.ts
#   $STATE_DIR/.e2e/pids               — newline-separated pids for teardown

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# WORKTREE_STATE_DIR resolves to .cline/worktrees/<id>/ when in a worktree
# (so concurrent worktrees don't share state). CI sets it explicitly.
if [ -z "${WORKTREE_STATE_DIR:-}" ]; then
    if [ -f "$REPO_ROOT/.git" ] && grep -q "worktrees/" "$REPO_ROOT/.git" 2>/dev/null; then
        WORKTREE_STATE_DIR="$REPO_ROOT"
    else
        WORKTREE_STATE_DIR="$REPO_ROOT"
    fi
fi
STATE_DIR="$WORKTREE_STATE_DIR/.e2e"
mkdir -p "$STATE_DIR"
: > "$STATE_DIR/pids"

log()  { echo "[e2e-up] $*" >&2; }
fail() { log "error: $*"; exit 1; }

# Find a free TCP port via the kernel, by binding to :0 and reading back the
# resolved port. Avoids the TOCTOU window of `ss | grep`.
free_port() {
    python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

record_pid() { echo "$1" >> "$STATE_DIR/pids"; }

# 1. Postgres. CI passes DATABASE_URL via the workflow's `services:` block;
#    locally we reuse `make local` (worktree-aware) and read .env.local.
if [ -n "${DATABASE_URL:-}" ]; then
    log "using preset DATABASE_URL=$DATABASE_URL"
else
    log "starting Postgres via make local"
    ( cd "$REPO_ROOT" && make local >/dev/null )
    # shellcheck disable=SC1091
    [ -f "$REPO_ROOT/.env.local" ] && set -a && . "$REPO_ROOT/.env.local" && set +a
    [ -n "${DATABASE_URL:-}" ] || fail "DATABASE_URL not set after make local — Postgres bring-up failed"
fi

# Migrations: the API doesn't run them on boot, so apply them once here. In CI
# the Postgres service starts empty; locally `make local` also starts a clean
# instance on the worktree's port, so this is correct in both cases.
if command -v sqlx >/dev/null 2>&1; then
    log "running sqlx migrate"
    ( cd "$REPO_ROOT" && DATABASE_URL="$DATABASE_URL" sqlx migrate run --source crates/overslash-db/migrations >/dev/null ) \
        || fail "sqlx migrate failed"
else
    log "sqlx CLI not found — assuming the DB is already migrated"
fi

# 2. Build the fakes + API binaries up-front so the stack is fast to boot.
log "building binaries"
( cd "$REPO_ROOT" && SQLX_OFFLINE=true cargo build -p overslash-fakes -p overslash-cli --release >/dev/null )

# 3. Start overslash-fakes (OS-assigned ports + state file).
FAKES_STATE_FILE="$STATE_DIR/fakes.ports.json"
rm -f "$FAKES_STATE_FILE"
log "starting overslash-fakes"
"$REPO_ROOT/target/release/overslash-fakes" \
    --state-file "$FAKES_STATE_FILE" \
    > "$STATE_DIR/fakes.log" 2>&1 &
FAKES_PID=$!
record_pid "$FAKES_PID"
# Wait up to 10s for fakes to write the state file.
for _ in $(seq 1 50); do
    if [ -s "$FAKES_STATE_FILE" ]; then break; fi
    sleep 0.2
done
[ -s "$FAKES_STATE_FILE" ] || fail "overslash-fakes did not produce $FAKES_STATE_FILE within 10s"

OAUTH_AS_URL=$(python3 -c "import json,sys; print(json.load(open('$FAKES_STATE_FILE'))['oauth_as'])")
OPENAPI_URL=$(python3   -c "import json,sys; print(json.load(open('$FAKES_STATE_FILE'))['openapi'])")
STRIPE_URL=$(python3    -c "import json,sys; print(json.load(open('$FAKES_STATE_FILE'))['stripe'])")
MCP_URL=$(python3       -c "import json,sys; print(json.load(open('$FAKES_STATE_FILE'))['mcp'])")
log "fakes ready: oauth_as=$OAUTH_AS_URL openapi=$OPENAPI_URL stripe=$STRIPE_URL mcp=$MCP_URL"

# 4. Pick a free port and start the API.
API_PORT=$(free_port)
API_URL="http://127.0.0.1:$API_PORT"

# Build OVERSLASH_SERVICE_BASE_OVERRIDES from the fakes' resolved URLs, keyed by
# the upstream hostnames the shipped service templates use. Add more as needed.
OPENAPI_HOST=$(python3 -c "from urllib.parse import urlparse; import sys; print(urlparse('$OPENAPI_URL').netloc.split(':')[0])")
OVERRIDES="api.github.com=$OPENAPI_URL,api.slack.com=$OPENAPI_URL,api.stripe.com=$STRIPE_URL"
# Hex 32-byte secrets (deterministic — these are local-only).
ENCRYPTION_KEY="ab$(printf 'cd%.0s' $(seq 1 31))"
SIGNING_KEY="ef$(printf '01%.0s' $(seq 1 31))"

log "starting API on $API_URL"
DEV_AUTH=1 \
OVERSLASH_SSRF_ALLOW_PRIVATE=1 \
OVERSLASH_SERVICE_BASE_OVERRIDES="$OVERRIDES" \
DATABASE_URL="$DATABASE_URL" \
SECRETS_ENCRYPTION_KEY="$ENCRYPTION_KEY" \
SIGNING_KEY="$SIGNING_KEY" \
HOST=127.0.0.1 \
PORT="$API_PORT" \
PUBLIC_URL="$API_URL" \
DASHBOARD_URL="/" \
DASHBOARD_ORIGIN="*localhost*" \
SQLX_OFFLINE=true \
"$REPO_ROOT/target/release/overslash" serve \
    > "$STATE_DIR/api.log" 2>&1 &
API_PID=$!
record_pid "$API_PID"

# Wait up to 30s for API health.
for _ in $(seq 1 150); do
    if curl -sf "$API_URL/health" >/dev/null 2>&1; then break; fi
    sleep 0.2
done
curl -sf "$API_URL/health" >/dev/null || fail "API at $API_URL did not become healthy within 30s — see $STATE_DIR/api.log"
echo "$API_URL" > "$STATE_DIR/api.url"

# 5. Build the dashboard once with the chosen API base URL embedded, then run
# `vite preview` on a free port.
DASH_PORT=$(free_port)
DASH_URL="http://127.0.0.1:$DASH_PORT"

log "building dashboard against $API_URL"
( cd "$REPO_ROOT/dashboard" \
    && VITE_API_BASE_URL="$API_URL" \
       npm run build --silent >/dev/null )

log "starting dashboard preview on $DASH_URL"
( cd "$REPO_ROOT/dashboard" \
    && API_URL="$API_URL" \
       npx vite preview --port "$DASH_PORT" --strictPort \
       > "$STATE_DIR/dashboard.log" 2>&1 ) &
DASH_PID=$!
record_pid "$DASH_PID"

for _ in $(seq 1 100); do
    if curl -sf "$DASH_URL" >/dev/null 2>&1; then break; fi
    sleep 0.2
done
curl -sf "$DASH_URL" >/dev/null || fail "dashboard preview did not become reachable within 20s — see $STATE_DIR/dashboard.log"
echo "$DASH_URL" > "$STATE_DIR/dashboard.url"

# 6. Write the unified env file Playwright reads.
cat > "$STATE_DIR/dashboard.env" <<EOF
DASHBOARD_URL=$DASH_URL
API_URL=$API_URL
OAUTH_AS_URL=$OAUTH_AS_URL
OPENAPI_URL=$OPENAPI_URL
STRIPE_URL=$STRIPE_URL
MCP_URL=$MCP_URL
EOF

# Suppress unused-var warnings for the host we computed but don't currently
# write into the env file.
: "$OPENAPI_HOST"

log "stack up — state in $STATE_DIR"
log "  dashboard: $DASH_URL"
log "  api:       $API_URL"
log "  fakes oauth_as: $OAUTH_AS_URL"
