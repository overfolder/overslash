#!/usr/bin/env bash
#
# The images a project is running must carry no HIGH or CRITICAL finding that
# isn't excepted (CASA 6.1.1). Policy:
# docs/compliance/casa/dependency-vulnerability-policy.md. Runbook:
# docs/runbooks/image-scanning.md.
#
#   check-image-vulns.sh --project <id> [--region <r>] [--ignores <file>]
#   check-image-vulns.sh --offline [--ignores <file>]
#
# It reads the images from Cloud Run rather than from the registry. The
# registry also holds rollback images and build cache, which nobody can fix and
# which would bury what is live. A newly added service is covered without
# touching this script. Only the template's image is read, so a service rolled
# back by shifting traffic is checked at its latest revision.
#
# Fails on:
#
#   * a HIGH or CRITICAL finding with no valid entry in the ignores file;
#   * an ignore with no reason, or a reviewBy that is unparseable, past, or more
#     than 90 days out. An expired ignore also stops suppressing its finding;
#   * an image the scanner can't vouch for: outside this project's Artifact
#     Registry, never scanned, unsupported, failed, or stale. Without this a
#     scanner that isn't running reads as a clean result.
#
# PENDING and SCANNING only warn, because a deploy can land just before a run.
#
# Severity is Artifact Analysis's effectiveSeverity: the distro's rating where
# there is one, otherwise the note provider's.
#
# --offline validates the ignores file and calls nothing, for CI.
#
# Auth: GCP_ACCESS_TOKEN, or the active gcloud account.
set -euo pipefail
# Without this, `set -e` stops at $(...), and a failed API call inside one would
# carry on as an empty result.
shopt -s inherit_errexit

project=""
region="europe-west1"
ignores="image-scan-ignores.json"
offline=false
max_days=90

while [ $# -gt 0 ]; do
    case "$1" in
        --project) project=$2; shift 2 ;;
        --region) region=$2; shift 2 ;;
        --ignores) ignores=$2; shift 2 ;;
        --offline) offline=true; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

status=0
fail() {
    echo "::error::$1"
    status=1
}

# --- Ignores ---------------------------------------------------------------

today=$(date -u +%Y-%m-%d)
today_s=$(date -u -d "$today" +%s)
limit_s=$((today_s + max_days * 86400))

jq -e '.ignores | type == "array"' "$ignores" >/dev/null ||
    { echo "::error file=$ignores::expected an object with an \"ignores\" array"; exit 1; }

# The entries that may suppress a finding, as `id<TAB>package` lines.
valid_ignores=""
while IFS= read -r entry; do
    id=$(jq -r '.id // ""' <<<"$entry")
    package=$(jq -r '.package // ""' <<<"$entry")
    reason=$(jq -r '.reason // ""' <<<"$entry")
    review=$(jq -r '.reviewBy // ""' <<<"$entry")
    label="${id:-<no id>} in ${package:-<no package>}"

    if [ -z "$id" ] || [ -z "$package" ]; then
        fail "$ignores: $label: an ignore needs both id and package"
    elif [ -z "$reason" ]; then
        fail "$ignores: $label has no reason"
    elif ! [[ "$review" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] ||
        ! review_s=$(date -u -d "$review" +%s 2>/dev/null); then
        fail "$ignores: $label has an unparseable reviewBy: '$review'"
    elif [ "$review_s" -lt "$today_s" ]; then
        fail "$ignores: $label reviewBy $review has passed, re-triage it"
    elif [ "$review_s" -gt "$limit_s" ]; then
        fail "$ignores: $label reviewBy $review is more than $max_days days out"
    else
        valid_ignores+="$id"$'\t'"$package"$'\n'
    fi
done < <(jq -c '.ignores[]' "$ignores")

if [ "$offline" = true ]; then
    [ "$status" -eq 0 ] && echo "ok: $(jq '.ignores | length' "$ignores") ignores in $ignores"
    exit "$status"
fi

[ -n "$project" ] || { echo "--project is required without --offline" >&2; exit 2; }

# --- Google APIs -----------------------------------------------------------

token=${GCP_ACCESS_TOKEN:-$(gcloud auth print-access-token)}

# GET a URL, following nextPageToken, and print one JSON document per page.
# Extra arguments go to curl. A failed call must abort the run, since a 403 that
# reads as "no findings" is what this script exists to prevent. So always assign
# the result (`x=$(api ...)`) and filter it afterwards: in a pipeline or a <(...)
# the failure is lost.
api() {
    local url=$1 page="" body
    shift
    while :; do
        body=$(curl -sS --fail-with-body --get "$url" \
            -H "Authorization: Bearer $token" \
            ${page:+--data-urlencode "pageToken=$page"} "$@") || {
            echo "::error::GET $url failed: $body" >&2
            exit 1
        }
        printf '%s\n' "$body"
        page=$(jq -r '.nextPageToken // ""' <<<"$body")
        [ -n "$page" ] || break
    done
}

registry="$region-docker.pkg.dev/$project/"

# The image's digest reference. Tags resolve through Artifact Registry, because
# the scanner keys everything on the digest.
resolve() {
    local image=$1 path repo rest package tag version
    case "$image" in
        *@sha256:*) echo "$image"; return ;;
    esac
    path=${image#"$registry"}
    repo=${path%%/*}
    rest=${path#*/}
    package=${rest%:*}
    tag=${rest##*:}
    # A nested package name is one URL segment.
    version=$(api "https://artifactregistry.googleapis.com/v1/projects/$project/locations/$region/repositories/$repo/packages/${package//\//%2F}/tags/$tag")
    version=$(jq -r '.version // ""' <<<"$version")
    [ -n "$version" ] || { echo "::error::no digest for $image" >&2; exit 1; }
    echo "${image%:*}@${version##*/}"
}

services=$(api "https://run.googleapis.com/v2/projects/$project/locations/$region/services")
jobs=$(api "https://run.googleapis.com/v2/projects/$project/locations/$region/jobs")
images=$({
    jq -r '.services[]?.template.containers[]?.image' <<<"$services"
    jq -r '.jobs[]?.template.template.containers[]?.image' <<<"$jobs"
} | sort -u)
[ -n "$images" ] || { echo "::error::no Cloud Run images found in $project ($region)"; exit 1; }

# --- Findings --------------------------------------------------------------

occurrences="https://containeranalysis.googleapis.com/v1/projects/$project/occurrences"
summary=""
checked=0
open_findings=0
suppressed=0

while IFS= read -r image; do
    if [[ "$image" != "$registry"* ]]; then
        fail "$image is outside $registry, so nothing scans it"
        continue
    fi
    ref=$(resolve "$image")
    checked=$((checked + 1))

    # Was it scanned, and is the scan still being kept current?
    discovery=$(api "$occurrences" --data-urlencode "filter=kind=\"DISCOVERY\" AND resourceUrl=\"https://$ref\"")
    discovery=$(jq -cs '[.[].occurrences[]?][0] // empty' <<<"$discovery")
    if [ -z "$discovery" ]; then
        fail "$ref has never been scanned (runbook: images pushed before enablement)"
        continue
    fi
    analysis=$(jq -r '.discovery.analysisStatus // "UNKNOWN"' <<<"$discovery")
    continuous=$(jq -r '.discovery.continuousAnalysis // "UNKNOWN"' <<<"$discovery")
    case "$analysis" in
        FINISHED_SUCCESS | COMPLETE) ;;
        PENDING | SCANNING)
            echo "::warning::$ref scan is still $analysis, findings may be incomplete"
            ;;
        *)
            fail "$ref scan ended as $analysis"
            continue
            ;;
    esac
    if [ "$continuous" = "INACTIVE" ]; then
        fail "$ref is stale: not pulled in 30 days, so new advisories no longer reach it (runbook: stale images)"
    fi

    vulnerabilities=$(api "$occurrences" --data-urlencode "filter=kind=\"VULNERABILITY\" AND resourceUrl=\"https://$ref\"")

    # One line per (CVE, package), HIGH and CRITICAL only.
    while IFS=$'\t' read -r id package severity fixed; do
        [ -n "$id" ] || continue
        if grep -qxF "$id"$'\t'"$package" <<<"$valid_ignores"; then
            suppressed=$((suppressed + 1))
            continue
        fi
        open_findings=$((open_findings + 1))
        fail "$severity $id in $package (fix: ${fixed:-none}) on $ref"
        summary+="| $severity | $id | $package | ${fixed:-none} | \`${ref##*/}\` |"$'\n'
    done < <(jq -r '.occurrences[]?
            | (.noteName | split("/") | last) as $id
            | .vulnerability as $v
            | $v.packageIssue[]?
            | (.effectiveSeverity // $v.effectiveSeverity // $v.severity) as $severity
            | select($severity == "HIGH" or $severity == "CRITICAL")
            | [$id, .affectedPackage, $severity, (.fixedVersion.fullName // "")]
            | @tsv' <<<"$vulnerabilities" | sort -u)
    echo "checked: $ref"
done <<<"$images"

echo "$project: $checked images, $open_findings open findings, $suppressed excepted"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### $project: $checked images, $open_findings open, $suppressed excepted"
        if [ -n "$summary" ]; then
            echo
            echo "| Severity | Advisory | Package | Fixed in | Image |"
            echo "|---|---|---|---|---|"
            printf '%s' "$summary"
        fi
    } >>"$GITHUB_STEP_SUMMARY"
fi

exit "$status"
