#!/usr/bin/env bash
#
# The dashboard's /.well-known/security.txt (RFC 9116) must carry the fields
# SECURITY.md relies on, and its `Expires` must be in the future but no more
# than a year out. RFC 9116 §2.5.5: a file past its Expires is stale and
# clients should ignore it, so a forgotten renewal silently drops our
# security contact.
#
# The daily Dependency audit runs this against dev and master, so the renewal
# window below opens a triage issue a month before the file goes stale.
#
# When it fails on the date: push `Expires` out to at most a year from today,
# after checking the Contact and Policy lines are still right.
set -euo pipefail

file=${1:-dashboard/static/.well-known/security.txt}
renew_days=30
max_days=366

status=0
for field in Contact Expires Policy Preferred-Languages; do
    if ! grep -qE "^$field: " "$file"; then
        echo "::error file=$file::missing required field '$field'"
        status=1
    fi
done

if [ "$(grep -cE '^Expires: ' "$file")" -gt 1 ]; then
    echo "::error file=$file::'Expires' must appear exactly once (RFC 9116 §2.5.5)"
    status=1
fi

expires=$(sed -nE 's/^Expires: (.*)$/\1/p' "$file" | head -1)
if [ -n "$expires" ]; then
    now_s=$(date -u +%s)
    if ! expires_s=$(date -u -d "$expires" +%s 2>/dev/null); then
        echo "::error file=$file::unparseable Expires: $expires"
        status=1
    elif [ "$expires_s" -le "$now_s" ]; then
        echo "::error file=$file::Expires $expires has passed; clients now ignore this file"
        status=1
    elif [ "$expires_s" -lt $((now_s + renew_days * 86400)) ]; then
        echo "::error file=$file::Expires $expires is less than $renew_days days away; renew it"
        status=1
    elif [ "$expires_s" -gt $((now_s + max_days * 86400)) ]; then
        echo "::error file=$file::Expires $expires is more than a year out (RFC 9116 recommends less)"
        status=1
    else
        echo "ok: $file expires $expires"
    fi
fi

exit "$status"
