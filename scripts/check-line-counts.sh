#!/usr/bin/env bash
#
# Every .rs file under crates/*/src/ must stay under MAX lines.
#
# Oversized modules are slow to navigate for humans and burn context for
# agents. When this fails, split the file along a functional seam into a
# directory module (see crates/overslash-api/src/routes/actions/ for the
# house pattern) rather than raising the number.
#
# Scope is crates/*/src/ only. Integration tests under crates/*/tests/ are
# deliberately excluded: tests/api.rs is an intentionally consolidated
# single binary, and tests/common/mod.rs is shared fixture code.
set -euo pipefail

MAX="${MAX_RS_LINES:-1000}"

# git ls-files, so build artifacts and untracked scratch files never count.
# xargs may batch and emit several "total" rows — hence the $2 guard.
offenders=$(
    git ls-files \
        | grep -E '^crates/[^/]+/src/.*\.rs$' \
        | xargs -r wc -l \
        | awk -v max="$MAX" '$2 != "total" && $1 > max { printf "%6d  %s\n", $1, $2 }' \
        | sort -rn
)

if [ -n "$offenders" ]; then
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::error::Rust source files exceed ${MAX} lines"
    fi
    echo "ERROR: these files under crates/*/src/ exceed ${MAX} lines:" >&2
    echo "$offenders" >&2
    exit 1
fi
