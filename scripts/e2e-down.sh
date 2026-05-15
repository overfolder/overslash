#!/usr/bin/env bash
# Tear down the e2e stack started by scripts/e2e-up.sh.
# Reads pids from $WORKTREE_STATE_DIR/.e2e/pids and SIGTERMs them.
# Postgres is left running (use `make worktree-clean` for full teardown).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKTREE_STATE_DIR="${WORKTREE_STATE_DIR:-$REPO_ROOT}"
STATE_DIR="$WORKTREE_STATE_DIR/.e2e"

if [ ! -d "$STATE_DIR" ]; then
    echo "[e2e-down] no state dir at $STATE_DIR — nothing to do" >&2
    exit 0
fi

if [ -f "$STATE_DIR/pids" ]; then
    while read -r pid; do
        [ -z "$pid" ] && continue
        if kill -0 "$pid" 2>/dev/null; then
            echo "[e2e-down] SIGTERM pid $pid" >&2
            kill "$pid" 2>/dev/null || true
        fi
    done < "$STATE_DIR/pids"
    # Give them a moment to shut down gracefully.
    sleep 1
    while read -r pid; do
        [ -z "$pid" ] && continue
        if kill -0 "$pid" 2>/dev/null; then
            echo "[e2e-down] SIGKILL pid $pid (still running)" >&2
            kill -9 "$pid" 2>/dev/null || true
        fi
    done < "$STATE_DIR/pids"
fi

rm -rf "$STATE_DIR"
echo "[e2e-down] state cleaned: $STATE_DIR" >&2
