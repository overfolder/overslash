# shellcheck shell=bash
#
# Shared helpers for the decision-numbering gates: scripts/check-decisions.sh
# (the lint) and scripts/allocate-decision.sh (the merge-time stamper). Both
# must agree on which files may carry a decision number, or the lint will flag
# a reference the allocator never rewrites.
#
# Sourced, not executed. Callers cd to the repo root first.

DECISIONS_FILE="DECISIONS.md"

# The placeholder an author writes instead of guessing a number. Allocated
# repo-wide by scripts/allocate-decision.sh once the PR reaches dev.
DECISION_PLACEHOLDER="D-NEXT"

# A file containing this marker is *about* the numbering scheme rather than a
# consumer of it: the tooling itself, and the docs that teach the convention.
# The placeholder rules skip those files, and the allocator never rewrites
# them — otherwise the first allocation would stamp a real number into the
# sentence explaining what the placeholder is. This file carries the marker,
# which is why the line above survives allocation.
#
#   decision-numbering:vocabulary
#
DECISION_VOCAB_MARKER="decision-numbering:vocabulary"

# Tracked files that may legitimately cite a decision number.
#
# Excluded:
#   - binary assets. PNG bytes match a decision reference by chance: the
#     committed screenshots alone yield three such tokens, two of them well
#     out of range, and each would read as a dangling reference.
#   - CHANGELOG.md. release-please generates it from commit subjects that are
#     already merged and cannot be corrected, so it is neither a lint target
#     nor a rewrite target.
decision_files() {
    git ls-files \
        | grep -vE '\.(png|jpg|jpeg|gif|ico|webp|woff2?|ttf|otf|pdf|zip)$' \
        | grep -vxF 'CHANGELOG.md'
}

# decision_files() minus the vocabulary files described above. This is the set
# the placeholder rules and the allocator operate on. Note that it is NOT used
# for the dangling-reference check: a vocabulary file still cites real
# decisions, and that rule is the broad one worth keeping broad.
decision_consumer_files() {
    local all marked
    all=$(decision_files)
    marked=$(printf '%s\n' "$all" | xargs -r grep -alF "$DECISION_VOCAB_MARKER" 2>/dev/null || true)
    if [ -z "$marked" ]; then
        printf '%s\n' "$all"
        return
    fi
    printf '%s\n' "$all" | grep -vxF -f <(printf '%s\n' "$marked") || true
}

# Every allocated decision number, in file order, one per line.
decision_numbers() {
    sed -n 's/^## D\([0-9][0-9]*\):.*/\1/p' "$DECISIONS_FILE"
}

# The highest allocated number; 0 when the file has no entries.
max_decision() {
    local max
    max=$(decision_numbers | sort -n | tail -1)
    printf '%s\n' "${max:-0}"
}
