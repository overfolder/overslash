#!/usr/bin/env bash
#
# Stamp the real number onto a decision that was authored as a placeholder.
#
# Authors never pick a number: the value is only correct at merge time, and
# picking it earlier is what produced three renumbers in a single PR (#546) and
# two commit subjects that name the wrong decision forever. This script runs
# from .github/workflows/allocate-decision.yml after a PR lands on dev, and by
# hand via `make allocate-decision` when that workflow cannot push.
#
# Usage: scripts/allocate-decision.sh [--dry-run]
#
# decision-numbering:vocabulary
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/lib/decisions.sh
. scripts/lib/decisions.sh

dry_run=0
case "${1:-}" in
    --dry-run) dry_run=1 ;;
    "") ;;
    *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
esac

headings=$(grep -c "^## $DECISION_PLACEHOLDER:" "$DECISIONS_FILE" || true)

if [ "$headings" -eq 0 ]; then
    echo "No unallocated decision in $DECISIONS_FILE — nothing to do."
    exit 0
fi

# Two placeholders means two PRs landed before this ran. Their references in
# other files are indistinguishable — a comment saying "See D-NEXT." belongs to
# one of them and nothing in the tree says which. Guessing would recreate the
# mispointed-reference bug this whole mechanism exists to prevent.
if [ "$headings" -gt 1 ]; then
    [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error::$headings unallocated decisions in $DECISIONS_FILE"
    {
        echo "ERROR: $DECISIONS_FILE holds $headings '## $DECISION_PLACEHOLDER:' headings."
        echo
        echo "Two decisions landed before either was allocated, so the"
        echo "$DECISION_PLACEHOLDER references in other files are ambiguous — nothing"
        echo "records which decision each one belongs to. Resolve by hand:"
        echo "  1. Number the headings in file order."
        echo "  2. Fix each reference against the PR that introduced it:"
        echo "     git log -S'$DECISION_PLACEHOLDER' --oneline -- <file>"
        echo "See docs/runbooks/decision-numbering.md."
    } >&2
    exit 1
fi

next=$(( $(max_decision) + 1 ))

files=$(decision_consumer_files \
    | xargs -r grep -alwF "$DECISION_PLACEHOLDER" 2>/dev/null || true)

if [ -z "$files" ]; then
    echo "ERROR: '## $DECISION_PLACEHOLDER:' heading present but no file matched." >&2
    exit 1
fi

count=$(printf '%s\n' "$files" | wc -l | tr -d ' ')
hits=$(printf '%s\n' "$files" | xargs -r grep -owF "$DECISION_PLACEHOLDER" | wc -l | tr -d ' ')

if [ "$dry_run" -eq 1 ]; then
    echo "Would allocate D$next — $count files, $hits replacements:"
    printf '%s\n' "$files" | while read -r f; do
        printf '  %4s  %s\n' "$(grep -cwF "$DECISION_PLACEHOLDER" "$f")" "$f"
    done
    exit 0
fi

printf '%s\n' "$files" | xargs -r sed -i "s/\\b$DECISION_PLACEHOLDER\\b/D$next/g"

echo "Allocated D$next across $count files ($hits replacements)."
echo "$next"
