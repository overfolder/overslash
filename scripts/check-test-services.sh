#!/usr/bin/env bash
# Preflight for `make test` / `make check`: are the backing services the test
# suite needs actually reachable?
#
# Without this, a missing Postgres or Valkey surfaces as hundreds of failed
# tests (oversla-sh's integration tests panic by design when VALKEY_URL is
# unreachable — see crates/oversla-sh/tests/integration.rs), which reads like a
# broken branch rather than a missing container.
#
# Reads DATABASE_URL / VALKEY_URL from the environment, falling back to
# .env.local (worktree ports) then .env, then to the compose defaults — the
# same precedence the test binaries see, since `make` exports .env.local and
# dotenvy never overrides an already-set variable.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Pull a KEY=value out of an env file without executing it.
from_file() {
    local key="$1" file="$2"
    [ -f "$file" ] || return 1
    local line
    line=$(grep -E "^${key}=" "$file" | tail -1) || return 1
    [ -n "$line" ] || return 1
    printf '%s' "${line#*=}"
}

resolve() {
    local key="$1" default="$2" value
    value="${!key:-}"
    [ -n "$value" ] || value=$(from_file "$key" "$REPO_ROOT/.env.local") || true
    [ -n "$value" ] || value=$(from_file "$key" "$REPO_ROOT/.env") || true
    [ -n "$value" ] || value="$default"
    printf '%s' "$value"
}

# host:port out of a URL like scheme://[user[:pass]@]host[:port][/path].
host_port() {
    local url="$1" default_port="$2" hostport
    hostport="${url#*://}"
    hostport="${hostport%%/*}"
    hostport="${hostport##*@}"
    case "$hostport" in
        *:*) printf '%s %s' "${hostport%%:*}" "${hostport##*:}" ;;
        *)   printf '%s %s' "$hostport" "$default_port" ;;
    esac
}

failed=0

probe() {
    local label="$1" url="$2" default_port="$3" hint="$4"
    local host port
    read -r host port <<<"$(host_port "$url" "$default_port")"
    if timeout 3 bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null; then
        return 0
    fi
    echo "  ✗ ${label} unreachable at ${host}:${port} (${url})" >&2
    echo "    ${hint}" >&2
    failed=1
}

DATABASE_URL_VALUE=$(resolve DATABASE_URL "postgres://overslash:overslash@localhost:55432/overslash")
VALKEY_URL_VALUE=$(resolve VALKEY_URL "redis://localhost:6380")

probe "Postgres" "$DATABASE_URL_VALUE" 5432 "run \`make local-db\`, then \`make migrate\`"
probe "Valkey"   "$VALKEY_URL_VALUE"   6379 "run \`make local-db\` (oversla-sh's tests panic without it)"

if [ "$failed" -ne 0 ]; then
    echo "" >&2
    echo "Backing services for the test suite are not up. See the hints above." >&2
    exit 1
fi
