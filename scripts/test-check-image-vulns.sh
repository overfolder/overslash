#!/usr/bin/env bash
#
# Drives check-image-vulns.sh against a fake `curl`, covering what the live run
# can only show when something goes wrong: a failed call or an unscanned image
# must fail the check, never read as a clean result. Needs no credentials.
set -euo pipefail

script=$(cd "$(dirname "$0")" && pwd)/check-image-vulns.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Answers from $FIXTURES/<key>.json, or `{}` when there is no such file. A
# <key>.fail file makes the call fail the way `curl --fail-with-body` does.
mkdir "$work/bin"
cat >"$work/bin/curl" <<'FAKE'
#!/usr/bin/env bash
url="" filter="" page=""
for arg in "$@"; do
    case "$arg" in
        https://*) url=$arg ;;
        filter=*) filter=$arg ;;
        pageToken=*) page=${arg#pageToken=} ;;
    esac
done
case "$url" in
    */services) key=services ;;
    */jobs) key=jobs ;;
    */tags/*) key=tag ;;
    */occurrences) case "$filter" in *DISCOVERY*) key=discovery ;; *) key=vulns ;; esac ;;
    *) echo "unexpected url: $url" >&2; exit 2 ;;
esac
key+=${page:+-$page}
if [ -e "$FIXTURES/$key.fail" ]; then
    echo '{"error":{"code":403}}'
    exit 22
fi
cat "$FIXTURES/$key.json" 2>/dev/null || echo '{}'
FAKE
chmod +x "$work/bin/curl"

registry=europe-west1-docker.pkg.dev/p/r
in_days() { date -u -d "+$1 days" +%Y-%m-%d; }

vuln() { # severity package [fixed version]
    jq -cn --arg s "$1" --arg p "$2" --arg f "${3:-}" '{
        noteName: "projects/goog-vulnz/notes/CVE-2026-1",
        vulnerability: {effectiveSeverity: $s, packageIssue: [
            {affectedPackage: $p, effectiveSeverity: $s, fixedVersion: {fullName: $f}}]}}'
}

# A clean baseline: one tagged service, one digest-pinned job, scan finished.
reset() {
    export FIXTURES="$work/f"
    rm -rf "$FIXTURES"
    mkdir "$FIXTURES"
    echo "{\"services\":[{\"template\":{\"containers\":[{\"image\":\"$registry/api:abc\"}]}}]}" >"$FIXTURES/services.json"
    echo "{\"jobs\":[{\"template\":{\"template\":{\"containers\":[{\"image\":\"$registry/job@sha256:def\"}]}}}]}" >"$FIXTURES/jobs.json"
    echo '{"version":"projects/p/locations/l/repositories/r/packages/api/versions/sha256:abc"}' >"$FIXTURES/tag.json"
    discovery FINISHED_SUCCESS ACTIVE
    echo '{"ignores":[]}' >"$work/ignores.json"
}
discovery() {
    echo "{\"occurrences\":[{\"discovery\":{\"analysisStatus\":\"$1\",\"continuousAnalysis\":\"$2\"}}]}" >"$FIXTURES/discovery.json"
}
findings() { jq -cs '{occurrences: .}' >"$FIXTURES/vulns.json"; }
ignore() { # package reviewBy [reason]
    jq -n --arg p "$1" --arg d "$2" --arg r "${3-a reason}" \
        '{ignores: [{id: "CVE-2026-1", package: $p, reviewBy: $d, reason: $r}]}' >"$work/ignores.json"
}

failed=0
check() { # name expected-exit expected-output [script args]
    local name=$1 want=$2 pattern=$3 got=0 out
    shift 3
    out=$(GCP_ACCESS_TOKEN=t PATH="$work/bin:$PATH" bash "$script" --ignores "$work/ignores.json" "$@" 2>&1) || got=$?
    if [ "$got" -ne "$want" ] || ! grep -q -- "$pattern" <<<"$out"; then
        echo "FAIL: $name (exit $got, want $want, output must match '$pattern')"
        echo "$out" | sed 's/^/    /'
        failed=1
    else
        echo "ok: $name"
    fi
}
live=(--project p)

reset
check "clean images pass" 0 "2 images, 0 open findings" "${live[@]}"

reset
vuln MEDIUM libfoo | findings
check "medium does not fail" 0 "0 open findings" "${live[@]}"

reset
vuln HIGH libssl3 3.5.1 | findings
check "high fails and names the fix" 1 "HIGH CVE-2026-1 in libssl3 (fix: 3.5.1)" "${live[@]}"

reset
vuln CRITICAL libssl3 | findings
check "critical with no fix fails" 1 "fix: none" "${live[@]}"

reset
vuln HIGH libssl3 | findings
ignore libssl3 "$(in_days 30)"
check "valid ignore suppresses" 0 "2 excepted" "${live[@]}"

reset
vuln HIGH libssl3 | findings
ignore zlib "$(in_days 30)"
check "ignore for another package does not suppress" 1 "HIGH CVE-2026-1 in libssl3" "${live[@]}"

reset
vuln HIGH libssl3 | findings
ignore libssl3 "$(in_days -1)"
check "expired ignore stops suppressing" 1 "HIGH CVE-2026-1 in libssl3" "${live[@]}"

reset
ignore libssl3 "$(in_days 91)"
check "ignore over 90 days out fails" 1 "more than 90 days out" --offline

reset
ignore libssl3 "$(in_days 30)" ""
check "ignore without a reason fails" 1 "has no reason" --offline

reset
ignore libssl3 2026-02-31
check "unparseable reviewBy fails" 1 "unparseable reviewBy" --offline

reset
ignore libssl3 "$(in_days 30)"
check "good ignore passes offline" 0 "ok: 1 ignores" --offline

reset
rm "$FIXTURES/discovery.json"
check "never scanned fails" 1 "never been scanned" "${live[@]}"

reset
discovery FINISHED_UNSUPPORTED ACTIVE
check "unsupported image fails" 1 "scan ended as FINISHED_UNSUPPORTED" "${live[@]}"

reset
discovery FINISHED_SUCCESS INACTIVE
check "stale image fails" 1 "is stale" "${live[@]}"

reset
discovery SCANNING ACTIVE
check "in-progress scan warns only" 0 "still SCANNING" "${live[@]}"

reset
echo "{\"services\":[{\"template\":{\"containers\":[{\"image\":\"gcr.io/x/y:1\"}]}}]}" >"$FIXTURES/services.json"
check "image outside the registry fails" 1 "nothing scans it" "${live[@]}"

reset
echo '{}' >"$FIXTURES/services.json"
echo '{}' >"$FIXTURES/jobs.json"
check "no deployed images fails" 1 "no Cloud Run images" "${live[@]}"

for key in services jobs tag discovery vulns; do
    reset
    touch "$FIXTURES/$key.fail"
    check "failed $key call fails" 1 "failed:" "${live[@]}"
done

reset
vuln MEDIUM libfoo | jq -cs '{occurrences: ., nextPageToken: "p2"}' >"$FIXTURES/vulns.json"
vuln HIGH libssl3 | jq -cs '{occurrences: .}' >"$FIXTURES/vulns-p2.json"
check "finding on a later page fails" 1 "HIGH CVE-2026-1 in libssl3" "${live[@]}"

reset
touch "$FIXTURES/vulns-p2.fail"
echo '{"nextPageToken":"p2"}' >"$FIXTURES/vulns.json"
check "failed later page fails" 1 "failed:" "${live[@]}"

[ "$failed" -eq 0 ] && echo "all passed"
exit "$failed"
