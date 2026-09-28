#!/usr/bin/env bash
#
# Every advisory ignore in deny.toml must carry a `review-by: YYYY-MM-DD` date
# in its reason, no more than 90 days out, and that date must not have passed.
#
# cargo-deny has no expiry field of its own, so without this an ignore written
# for a good reason on day one keeps suppressing the advisory forever, long
# after the reason stopped being true (a fix shipped, we started using RSA
# keys). The policy in docs/compliance/casa/dependency-vulnerability-policy.md
# is what this enforces.
#
# When it fails: re-triage the advisory. If the ignore still holds, update the
# reason and push the date out (≤ 90 days); if a fix exists, take it and
# delete the entry.
#
# osv-scanner.toml needs no such check: its `ignoreUntil` is native, and an
# expired entry simply stops suppressing, so the scan itself fails.
set -euo pipefail

file=${1:-deny.toml}
max_days=90

today=$(date -u +%Y-%m-%d)
today_s=$(date -u -d "$today" +%s)
limit_s=$((today_s + max_days * 86400))

status=0
count=0

# Entries are one `{ id = "...", reason = "..." }` per line; see deny.toml.
while IFS= read -r line; do
    id=$(sed -nE 's/.*id[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' <<<"$line")
    [ -n "$id" ] || continue
    count=$((count + 1))

    review=$(sed -nE 's/.*review-by:[[:space:]]*([0-9]{4}-[0-9]{2}-[0-9]{2}).*/\1/p' <<<"$line")
    if [ -z "$review" ]; then
        echo "::error file=$file::$id has no 'review-by: YYYY-MM-DD' in its reason"
        status=1
        continue
    fi

    review_s=$(date -u -d "$review" +%s 2>/dev/null) || {
        echo "::error file=$file::$id has an unparseable review-by date: $review"
        status=1
        continue
    }

    if [ "$review_s" -lt "$today_s" ]; then
        echo "::error file=$file::$id review-by $review has passed — re-triage it (see docs/compliance/casa/dependency-vulnerability-policy.md)"
        status=1
    elif [ "$review_s" -gt "$limit_s" ]; then
        echo "::error file=$file::$id review-by $review is more than $max_days days out"
        status=1
    else
        echo "ok: $id (review-by $review)"
    fi
done < <(awk '/^[[:space:]]*ignore[[:space:]]*=[[:space:]]*\[/ { in_ignore = 1; next }
              in_ignore && /^[[:space:]]*\]/ { in_ignore = 0 }
              in_ignore && !/^[[:space:]]*#/ { print }' "$file")

echo "$count advisory ignore(s) checked"
exit "$status"
