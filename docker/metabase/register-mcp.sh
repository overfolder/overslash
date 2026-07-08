#!/usr/bin/env bash
# Register the Metabase MCP server with Claude Code at USER scope, so it is
# available in the base repo AND every worktree (each worktree is a distinct
# project path, and user scope spans them all) without touching the committed
# .mcp.json. Re-run to rotate the key. Requires docker/metabase/.env.metabase.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$HERE/.env.metabase"
NAME="${MCP_NAME:-metabase}"
READ_ONLY="${METABASE_READ_ONLY_MODE:-true}"   # start read-only; flip to false to allow write SQL

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found. Run ./bootstrap.sh first." >&2
  exit 1
fi
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

if [ -z "${METABASE_URL:-}" ] || [ -z "${METABASE_API_KEY:-}" ]; then
  echo "ERROR: METABASE_URL / METABASE_API_KEY missing from $ENV_FILE" >&2
  exit 1
fi

# Replace any prior registration so the key stays current.
claude mcp remove -s user "$NAME" >/dev/null 2>&1 || true

claude mcp add "$NAME" -s user \
  -e "METABASE_URL=$METABASE_URL" \
  -e "METABASE_API_KEY=$METABASE_API_KEY" \
  -e "METABASE_READ_ONLY_MODE=$READ_ONLY" \
  -- npx -y @jerichosequitin/metabase-mcp

echo
echo "==> Registered MCP server '$NAME' (user scope) -> $METABASE_URL (read_only=$READ_ONLY)"
echo "==> Restart Claude Code (or open a new session) in any worktree to pick it up."
echo "==> Verify with:  claude mcp list"
