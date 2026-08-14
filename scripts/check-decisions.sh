#!/usr/bin/env bash
#
# Decision numbers must be unique, contiguous, and allocated at merge.
#
# DECISIONS.md is append-only, so a number picked while a PR is open goes
# stale every time another decision lands first — and the number is
# denormalized into ~10 files across five languages, so a renumber that
# misses one leaves a reference pointing at an unrelated decision. That reads
# plausibly and never errors. Authors therefore write the placeholder heading
# (see scripts/lib/decisions.sh) and .github/workflows/allocate-decision.yml
# stamps the real number repo-wide once the PR reaches dev.
#
# What this cannot catch: a reference naming a number that *exists* but points
# at the wrong decision. #542 shipped exactly that — its subject said D57, the
# heading it added was D58, and six files still said D57 afterwards. #547 did
# the same in the other direction and #543 caught a stray D61. Fourteen
# citations were wrong when this gate was written, and no lint sees any of
# them, which is why allocation moved to merge time rather than stopping at a
# uniqueness check.
#
# Environment:
#   BASE_REF          diff against this ref to reject newly hardcoded numbers.
#                     Unset (the default) skips that rule.
#   STRICT_ALLOCATED  non-empty: no placeholder may survive. Set on master;
#                     dev tolerates one for the minute before the allocator runs.
#
# decision-numbering:vocabulary
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/lib/decisions.sh
. scripts/lib/decisions.sh

BASE_REF="${BASE_REF:-}"
STRICT_ALLOCATED="${STRICT_ALLOCATED:-}"

fail=0
err() {
    [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error::$1"
    echo "ERROR: $1" >&2
    fail=1
}
detail() { echo "$1" >&2; }

max=$(max_decision)

# 1. No duplicate numbers.
dupes=$(decision_numbers | sort -n | uniq -d)
if [ -n "$dupes" ]; then
    err "duplicate decision numbers in $DECISIONS_FILE"
    for n in $dupes; do
        detail "  D$n  $(grep -n "^## D$n:" "$DECISIONS_FILE" | cut -d: -f1 | tr '\n' ' ')"
    done
fi

# 2. No gaps. A gap means a renumber dropped an entry on the floor.
missing=$(comm -13 <(decision_numbers | sort -u) <(seq 1 "$max" | sort))
if [ -n "$missing" ]; then
    err "gap in decision numbers (highest is D$max)"
    detail "  missing: $(printf 'D%s ' $missing)"
fi

# 3. Every entry keeps the Date / Decision / Rationale shape.
malformed=$(awk '
    /^## (D[0-9]+|D-NEXT):/ {
        if (h != "" && (!d || !dec || !r)) print h
        h = $0; d = 0; dec = 0; r = 0; next
    }
    /^\*\*Date\*\*:/      { d = 1 }
    /^\*\*Decision\*\*:/  { dec = 1 }
    /^\*\*Rationale\*\*:/ { r = 1 }
    END { if (h != "" && (!d || !dec || !r)) print h }
' "$DECISIONS_FILE")
if [ -n "$malformed" ]; then
    err "decision entries missing a **Date**/**Decision**/**Rationale** line"
    detail "$malformed"
fi

# 4. No reference to a decision that does not exist. The only rule that scans
#    every file, so it is deliberately narrow: out-of-range only. Test files
#    legitimately write things like "(B5 + D1 + D2 + D3)" for plan item ids,
#    and those resolve to real decisions by luck — flagging them would be noise.
dangling=$(decision_files \
    | xargs -r grep -aoHnE '\bD[0-9]{1,3}\b' 2>/dev/null \
    | awk -F: -v max="$max" '{ n = substr($NF, 2) + 0; if (n < 1 || n > max) print }' \
    || true)
if [ -n "$dangling" ]; then
    err "reference to a decision that does not exist (highest is D$max)"
    detail "$dangling"
fi

# 5. A placeholder reference without a placeholder heading. This is what makes
#    the allocator workflow's `paths: [DECISIONS.md]` filter sound: a stray
#    reference can never land in a push the allocator does not look at.
placeholder_heading_count=$(grep -c "^## $DECISION_PLACEHOLDER:" "$DECISIONS_FILE" || true)
placeholder_refs=$(decision_consumer_files \
    | xargs -r grep -aHnwF "$DECISION_PLACEHOLDER" 2>/dev/null || true)
if [ -n "$placeholder_refs" ] && [ "$placeholder_heading_count" -eq 0 ]; then
    err "$DECISION_PLACEHOLDER referenced but $DECISIONS_FILE has no '## $DECISION_PLACEHOLDER:' heading"
    detail "$placeholder_refs"
fi

# 6. No anchor link to the placeholder: the slug is derived from the heading,
#    which changes when the number is stamped in.
anchors=$(decision_consumer_files \
    | xargs -r grep -aHniF '#d-next' 2>/dev/null || true)
if [ -n "$anchors" ]; then
    err "anchor link to an unallocated decision (the slug changes at allocation)"
    detail "$anchors"
fi

# 7. New entries must use the placeholder. Retitling an existing entry is fine,
#    so only a heading whose number is absent from the base counts as new.
if [ -n "$BASE_REF" ]; then
    base_file=$(git show "$BASE_REF:$DECISIONS_FILE" 2>/dev/null || true)
    base_nums=$(sed -n 's/^## D\([0-9][0-9]*\):.*/\1/p' <<<"$base_file")

    # An allocation legitimately turns a placeholder into a numbered heading.
    # Recognise it by shape — the base had one and the working tree does not —
    # so `make allocate-decision` followed by a commit is not blocked by the
    # pre-commit hook on the manual-recovery path.
    allocated=""
    if grep -q "^## $DECISION_PLACEHOLDER:" <<<"$base_file" \
       && ! grep -q "^## $DECISION_PLACEHOLDER:" "$DECISIONS_FILE"; then
        allocated=$(( $(sort -n <<<"$base_nums" | tail -1) + 1 ))
    fi
    added=$(git diff "$BASE_REF" -- "$DECISIONS_FILE" \
        | sed -n 's/^+## D\([0-9][0-9]*\):.*/\1/p' || true)
    for n in $added; do
        # Exactly the number the allocator would have assigned, and no other:
        # a hardcoded entry riding along with an allocation still fails.
        [ "$n" = "$allocated" ] && continue
        if ! grep -qxF "$n" <<<"$base_nums"; then
            err "new decision D$n hardcodes a number; write '## $DECISION_PLACEHOLDER:' instead"
            detail "  The number is only valid at merge time. See docs/runbooks/decision-numbering.md."
        fi
    done
fi

# 8. Nothing unallocated may reach master.
if [ -n "$STRICT_ALLOCATED" ]; then
    survivors=$(decision_consumer_files \
        | xargs -r grep -aHnwF "$DECISION_PLACEHOLDER" 2>/dev/null || true)
    if [ -n "$survivors" ]; then
        err "unallocated $DECISION_PLACEHOLDER reached a release branch"
        detail "$survivors"
        detail "  Run 'make allocate-decision' — see docs/runbooks/decision-numbering.md."
    fi
fi

exit "$fail"
