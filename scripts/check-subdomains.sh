#!/usr/bin/env bash
#
# Live DNS must match docs/compliance/casa/subdomain-inventory.md (CASA 6.4.1,
# subdomain takeover). Fails on:
#
#   * a record whose value is not the one the inventory lists (an A record
#     still naming a released GCLB address, a CNAME repointed by hand);
#   * a dangling CNAME or MX — its target is NXDOMAIN;
#   * an unclaimed target — a `tls` row whose HTTPS does not present a valid
#     certificate for its own name, or that Vercel answers DEPLOYMENT_NOT_FOUND.
#     An A/AAAA row is probed at every address it resolves to (AAAA only
#     where the host has an IPv6 route);
#   * a hostname or record the inventory does not list. The zones live at the
#     registrar with no API to list them, so names are discovered three ways:
#     a random label under every parent in the inventory (catches a new
#     wildcard), common labels under each apex, and every name in Certificate
#     Transparency (CertSpotter). A CT name that no longer resolves is fine.
#   * an apex whose registration expires within 14 days (RDAP; a warning from 60).
#
# The daily Dependency audit runs it against dev, so a record changed at the
# registrar without an inventory change opens a triage issue the next morning.
# What to do on each failure: docs/runbooks/subdomain-inventory.md.
#
# Usage: check-subdomains.sh [--offline] [inventory.md]
#   --offline  parse and validate the table only; no network.
#   DNS_RESOLVER (default 1.1.1.1) picks the resolver, so a runner's cache
#   cannot mask a change.
#   SKIP_CT=1 skips Certificate Transparency. CertSpotter's anonymous tier
#   allows a handful of queries an hour — plenty for one daily run, not for
#   running this in a loop locally.
set -euo pipefail

offline=0
if [ "${1:-}" = --offline ]; then
    offline=1
    shift
fi
inventory=${1:-docs/compliance/casa/subdomain-inventory.md}
resolver=${DNS_RESOLVER:-1.1.1.1}
# Warn early; fail only once auto-renew (Namecheap charges within the last
# month) should already have run.
expiry_warn_days=60
expiry_fail_days=14

status=0
fail() {
    echo "::error file=$inventory::$*"
    status=1
}
warn() { echo "::warning file=$inventory::$*"; }

# --- parse ------------------------------------------------------------------

# One tab-separated "name type expect check" line per table row, backticks and
# padding stripped, an empty cell as "-" (`read` collapses adjacent tabs).
# Header and separator rows are dropped.
rows=$(awk -F'|' '
    /<!-- inventory:begin -->/ { on = 1; next }
    /<!-- inventory:end -->/   { on = 0 }
    on && /^\|/ {
        for (i = 2; i <= 5; i++) { gsub(/`/, "", $i); gsub(/^ +| +$/, "", $i); if ($i == "") $i = "-" }
        if ($2 == "Name" || $2 ~ /^-+$/) next
        printf "%s\t%s\t%s\t%s\n", tolower($2), $3, $4, $5
    }' "$inventory")

if [ -z "$rows" ]; then
    fail "no inventory table between the inventory:begin/end markers"
    exit 1
fi

while IFS=$'\t' read -r name type expect check; do
    case $type in
        absent)
            [ "$check" = - ] || fail "$name: an absent row takes check '-', not '$check'"
            continue ;;
        A | AAAA | CNAME) ok_checks="tls dns delegated pending" ;;
        MX | TXT) ok_checks="dns pending" ;;
        *) fail "$name: unknown type '$type'"; continue ;;
    esac
    [ "$expect" != - ] || fail "$name $type: empty Expect"
    case " $ok_checks " in
        *" $check "*) ;;
        *) fail "$name $type: check '$check' is not one of: $ok_checks" ;;
    esac
    [ "$check" != delegated ] || [ "$type" = CNAME ] \
        || fail "$name $type: only a CNAME can be 'delegated'"
done <<<"$rows"

if [ "$offline" = 1 ]; then
    [ "$status" = 0 ] && echo "ok: $(wc -l <<<"$rows") inventory rows parse"
    exit "$status"
fi

# --- helpers ----------------------------------------------------------------

# A query whose answer cannot be trusted — dig timed out, or the resolver said
# SERVFAIL/REFUSED — is recorded here instead of read as "no record", which
# would pass an absent row or hide an unlisted name. Any entry fails the run.
dns_errors=$(mktemp)
trap 'rm -f "$dns_errors"' EXIT

q() {
    local out
    if ! out=$(dig @"$resolver" +noall +comments +answer +tries=3 +time=5 "$@" 2>&1) \
        || ! grep -qE 'status: (NOERROR|NXDOMAIN)' <<<"$out"; then
        echo "$*" >>"$dns_errors"
        return 0
    fi
    printf '%s\n' "$out"
}

# Records of `type` owned by `name` itself — not the CNAME chain dig follows.
rr() {
    q "$2" "$1" | awk -v n="${1%.}." -v t="$2" '
        tolower($1) == tolower(n) && $4 == t {
            $1 = $2 = $3 = $4 = ""; sub(/^ +/, "")
            if (t == "MX") $0 = $NF
            if (t == "TXT") { gsub(/" "/, ""); gsub(/"/, "") }
            print tolower($0)
        }'
}

rcode() {
    q A "$1" | sed -nE 's/.*status: ([A-Z]+).*/\1/p' | head -1
}

# The first record a name owns, as "TYPE value", or nothing. NS covers a
# delegation to someone else's nameservers, the classic takeover; MX and TXT a
# name that carries no address at all.
first_rr() {
    local t v
    for t in CNAME A AAAA NS MX TXT; do
        v=$(rr "$1" "$t" | head -1)
        [ -n "$v" ] && { echo "$t $v"; return 0; }
    done
    return 1
}

label="zz-dnscheck-$(date -u +%s)$RANDOM"
# A wildcard row is probed through one random label under it.
concrete() {
    case $1 in
        '*.'*) echo "$label.${1#\*.}" ;;
        *) echo "$1" ;;
    esac
}

# Is `addr` in a network ARIN registers to Vercel? Warns once per address,
# since a pass here means the prefix list in `matches` is behind.
vercel_seen=" "
vercel_net() {
    local net
    net=$(curl -fsS --max-time 15 --retry 2 "https://rdap.arin.net/registry/ip/$1" 2>/dev/null \
        | jq -r '.name // empty' 2>/dev/null) || return 1
    [[ $net == VERCEL-* ]] || return 1
    case $vercel_seen in *" $1 "*) ;; *)
        vercel_seen+="$1 "
        warn "$1 is Vercel ($net, per ARIN) but not in the known prefixes; add its /24 to matches()" ;;
    esac
}

# Is `value` (a record of `type`) one of the comma-separated `expect`?
matches() {
    local type=$1 expect=$2 value=${3%.} e
    if [ "$expect" = vercel ]; then
        case $type in
            # Vercel's ARIN nets seen so far: the anycast pool (216.150.x,
            # 64.29.17.x, 66.33.60.x) and the two addresses its docs tell you
            # to configure (legacy 76.76.21.21, current 216.198.79.1). Vercel
            # adds /24s over time, so an address outside these is looked up
            # in RDAP: a VERCEL-* net passes with a warning to add it here.
            # The tls check still decides whether the name is ours.
            A) [[ $value =~ ^(216\.150\.|64\.29\.17\.|66\.33\.60\.|216\.198\.79\.|76\.76\.21\.) ]] \
                || vercel_net "$value" ;;
            CNAME) [[ $value =~ \.vercel-dns(-[0-9]+)?\.com$ ]] ;;
            *) false ;;
        esac
        return
    fi
    IFS=, read -ra list <<<"$expect"
    for e in "${list[@]}"; do
        e=$(tr '[:upper:]' '[:lower:]' <<<"${e%.}")
        if [ "$type" = TXT ]; then
            [[ $value == "$e"* ]] && return 0
        elif [ "$value" = "$e" ]; then
            return 0
        fi
    done
    return 1
}

# GitHub's runners have no IPv6 route; an AAAA address is then noted, not
# probed, rather than failed for a connect error that says nothing about it.
ipv6=0
ip -6 route show default 2>/dev/null | grep -q . && ipv6=1

probed_tls=" "
# HTTPS to `host`, pinned to `addr` when given (an A/AAAA row: every address
# is probed, not just the one curl would pick), else via normal resolution.
probe_tls() {
    local name=$1 host=$2 addr=${3:-} out pin=() via=""
    case $probed_tls in *" $host@$addr "*) return ;; esac
    probed_tls+="$host@$addr "
    if [ -n "$addr" ]; then
        if [[ $addr == *:* ]]; then
            if [ "$ipv6" = 0 ]; then
                echo "note: $name $addr not probed (no IPv6 route here)"
                return
            fi
            pin=(--resolve "$host:443:[$addr]")
        else
            pin=(--resolve "$host:443:$addr")
        fi
        via=" via $addr"
    fi
    # curl verifies the certificate against the hostname by default. The
    # HTTP status is irrelevant: a 5xx from a sleeping dev backend still means
    # the name is ours. Not curl's --retry, which retries 5xx and then exits 23
    # because it cannot rewind the headers already written; retry by hand on
    # connect failures and timeouts only.
    local rc attempt
    for attempt in 1 2 3; do
        rc=0
        out=$(curl -sS --max-time 20 "${pin[@]}" -o /dev/null -D - "https://$host/" 2>&1) || rc=$?
        case $rc in 6 | 7 | 28) sleep 2 ;; *) break ;; esac
    done
    case $rc in
        0)
            if grep -qi '^x-vercel-error: *DEPLOYMENT_NOT_FOUND' <<<"$out"; then
                fail "$name: unclaimed target — Vercel has no deployment for $host$via"
            fi ;;
        # TLS handshake / certificate failures (35 handshake, 51/60 verify,
        # 58/59 local cert or cipher): nothing serves our certificate here.
        35 | 51 | 58 | 59 | 60)
            fail "$name: unclaimed target — HTTPS to $host$via has no valid certificate for it ($(grep -m1 '^curl:' <<<"$out"))" ;;
        *) fail "$name: HTTPS to $host$via failed (curl $rc: $(grep -m1 '^curl:' <<<"$out"))" ;;
    esac
}

# --- every inventory row against live DNS -----------------------------------

while IFS=$'\t' read -r name type expect check; do
    host=$(concrete "$name")
    if [ "$type" = absent ]; then
        found=$(first_rr "$host") && fail "$name: listed as absent but resolves ($found)"
        continue
    fi

    answers=$(rr "$host" "$type")
    if [ -z "$answers" ]; then
        # `pending`: listed before the record exists (or after it is gone),
        # so the PR adding or removing a hostname can pass before the
        # registrar change. Present values are still checked below.
        if [ "$check" = pending ]; then
            echo "note: $name $type is pending and not live"
        else
            fail "$name: no $type record (inventory expects $expect)"
        fi
        continue
    fi
    if [ "$type" = TXT ]; then
        # One row per TXT value: some answer must carry this row's prefix.
        found=0
        while IFS= read -r v; do matches TXT "$expect" "$v" && found=1; done <<<"$answers"
        [ "$found" = 1 ] || fail "$name: no TXT record starting '$expect'"
        continue
    fi
    while IFS= read -r v; do
        matches "$type" "$expect" "$v" || fail "$name: $type $v is not in the inventory ($expect)"
        if [ "$type" = CNAME ] || [ "$type" = MX ]; then
            code=$(rcode "${v%.}")
            if [ "$code" != NOERROR ] && [ "$check" != delegated ]; then
                fail "$name: dangling $type — target ${v%.} is ${code:-unreachable}"
            fi
        fi
        if [ "$check" = tls ]; then
            case $type in A | AAAA) probe_tls "$name" "$host" "$v" ;; *) probe_tls "$name" "$host" ;; esac
        fi
    done <<<"$answers"
done <<<"$rows"

# --- nothing live that the inventory does not list ---------------------------

listed=$(awk -F'\t' '$2 != "absent" { print $1 }' <<<"$rows" | sort -u)
listed_pairs=$(awk -F'\t' '$2 != "absent" { print $1 "\t" $2 }' <<<"$rows" | sort -u)

covered_by() {
    local host=$1 n suffix rest
    while IFS= read -r n; do
        [ "$host" = "$n" ] && { echo "$n"; return 0; }
        case $n in
            '*.'*)
                suffix=${n#\*.}
                rest=${host%".$suffix"}
                if [ "$rest" != "$host" ] && [[ $rest != *.* ]]; then
                    echo "$n"
                    return 0
                fi ;;
        esac
    done <<<"$listed"
    return 1
}

# Every record type a listed name answers for must have a row. TXT values are
# checked per row above; a new TXT value on a listed name is caught here.
while IFS= read -r name; do
    host=$(concrete "$name")
    for type in A AAAA CNAME MX TXT; do
        answers=$(rr "$host" "$type")
        [ -n "$answers" ] || continue
        if ! grep -qxF "$name"$'\t'"$type" <<<"$listed_pairs"; then
            fail "$name: unlisted $type record ($(head -1 <<<"$answers"))"
        elif [ "$type" = TXT ]; then
            prefixes=$(awk -F'\t' -v n="$name" '$1 == n && $2 == "TXT" { print $3 }' <<<"$rows")
            while IFS= read -r v; do
                hit=0
                while IFS= read -r p; do matches TXT "$p" "$v" && hit=1; done <<<"$prefixes"
                [ "$hit" = 1 ] || fail "$name: unlisted TXT record '${v:0:60}'"
            done <<<"$answers"
        fi
    done
done <<<"$listed"

apexes=$(awk -F'\t' '$1 !~ /\*/ && split($1, p, ".") == 2 { print $1 }' <<<"$rows" | sort -u)
# Every parent of every row, so a wildcard appearing at any level shows up.
parents=$(awk -F'\t' '{ n = $1; sub(/^\*\./, "", n); while (split(n, p, ".") > 2) { sub(/^[^.]+\./, "", n); print n } }' <<<"$rows" | sort -u)
common="www mail smtp imap pop webmail mx docs doc dev staging stage test qa beta demo blog
admin portal console dashboard status api app cdn assets static auth login sso id help
support shop go link m old new preview sandbox vpn git ci grafana metrics monitor"

candidates=()
for p in $parents $apexes; do candidates+=("$label.$p"); done
for a in $apexes; do for l in $common; do candidates+=("$l.$a"); done; done

for a in $apexes; do
    [ "${SKIP_CT:-}" = 1 ] && break
    ct=() after="" page=0
    while [ "$page" -lt 20 ]; do
        url="https://api.certspotter.com/v1/issuances?domain=$a&include_subdomains=true&expand=dns_names${after:+&after=$after}"
        # --retry-max-time: curl honours Retry-After, and a 429 asks for minutes.
        if ! body=$(curl -fsS --max-time 30 --retry 2 --retry-all-errors --retry-max-time 60 "$url"); then
            warn "Certificate Transparency lookup for $a failed; CT names not checked this run"
            break
        fi
        [ "$(jq length <<<"$body")" -gt 0 ] || break
        mapfile -t -O "${#ct[@]}" ct < <(jq -r '.[].dns_names[]' <<<"$body")
        after=$(jq -r '.[-1].id' <<<"$body")
        page=$((page + 1))
    done
    for n in "${ct[@]}"; do
        n=$(tr '[:upper:]' '[:lower:]' <<<"$n")
        case $n in "$a" | *".$a") ;; *) continue ;; esac
        candidates+=("$(concrete "$n")")
    done
done

checked=" "
for c in "${candidates[@]}"; do
    case $checked in *" $c "*) continue ;; esac
    checked+="$c "
    covered_by "$c" >/dev/null && continue
    found=$(first_rr "$c") && fail "$c resolves but is not in the inventory ($found)"
done

# --- registration expiry -----------------------------------------------------

now_s=$(date -u +%s)
for a in $apexes; do
    if ! exp=$(curl -fsSL --max-time 20 --retry 2 "https://rdap.org/domain/$a" 2>/dev/null \
        | jq -r '[.events[]? | select(.eventAction == "expiration") | .eventDate][0] // empty'); then
        exp=""
    fi
    if [ -z "$exp" ]; then
        echo "note: no RDAP expiry for $a (registry publishes none); check auto-renew at the registrar"
        continue
    fi
    exp_s=$(date -u -d "$exp" +%s)
    if [ "$exp_s" -lt $((now_s + expiry_fail_days * 86400)) ]; then
        fail "$a registration expires $exp — less than $expiry_fail_days days and not renewed; renew it"
    elif [ "$exp_s" -lt $((now_s + expiry_warn_days * 86400)) ]; then
        warn "$a registration expires $exp — under $expiry_warn_days days; confirm auto-renew is on"
    fi
done

if [ -s "$dns_errors" ]; then
    fail "resolver $resolver failed $(wc -l <"$dns_errors") queries — those names are unchecked, so the run cannot pass: $(sort -u "$dns_errors" | head -5 | tr '\n' ';')"
fi

[ "$status" = 0 ] && echo "ok: $(wc -l <<<"$rows") inventory rows match live DNS; ${#candidates[@]} discovered names covered"
exit "$status"
