#!/usr/bin/env bash
# Stop hook: block agent turn end until current branch's PR satisfies all
# three mergeability gates (CI green, no unresolved review threads, no conflicts).
#
# Input: JSON on stdin, including { "stop_hook_active": bool, ... }
# Behavior:
#   - exit 0  -> allow stop
#   - exit 2  -> block stop, stderr "reason" surfaced to the model
#
# Caps at N=5 block attempts per turn (tracked in a per-session state file)
# to avoid infinite looping. After 5 blocks we surface state and allow stop.

set -uo pipefail

MAX_BLOCKS=5
CI_WAIT_SECONDS=600  # 10 minutes total CI settle wait

# ----- read hook input -----------------------------------------------------
INPUT="$(cat || true)"

jget() {
  # tiny JSON getter using python (always available); falls back to empty.
  python3 -c "import sys,json; d=json.loads(sys.stdin.read() or '{}');
keys='$1'.split('.')
v=d
for k in keys:
    if isinstance(v,dict) and k in v: v=v[k]
    else: v=''; break
print(v if not isinstance(v,(dict,list)) else json.dumps(v))" <<<"$INPUT" 2>/dev/null
}

SESSION_ID="$(jget session_id)"
STOP_HOOK_ACTIVE="$(jget stop_hook_active)"

# ----- counter state -------------------------------------------------------
STATE_DIR="${TMPDIR:-/tmp}/overslash-pr-gate"
mkdir -p "$STATE_DIR" 2>/dev/null || true
COUNTER_FILE="$STATE_DIR/${SESSION_ID:-default}.count"

# Reset counter when this is a fresh stop (not a re-entry from a prior block).
if [[ "$STOP_HOOK_ACTIVE" != "True" && "$STOP_HOOK_ACTIVE" != "true" ]]; then
  echo 0 > "$COUNTER_FILE"
fi

COUNT=0
[[ -f "$COUNTER_FILE" ]] && COUNT="$(cat "$COUNTER_FILE" 2>/dev/null || echo 0)"

# ----- need gh -------------------------------------------------------------
if ! command -v gh >/dev/null 2>&1; then
  exit 0  # no gh: nothing we can gate on
fi

# ----- find PR for current branch -----------------------------------------
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
if [[ -z "$BRANCH" || "$BRANCH" == "HEAD" ]]; then
  exit 0
fi

PR_JSON="$(gh pr view --json number,mergeable,mergeStateStatus,headRefName 2>/dev/null || true)"
if [[ -z "$PR_JSON" ]]; then
  # No PR for this branch -> nothing to gate
  exit 0
fi

PR_NUMBER="$(printf '%s' "$PR_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("number",""))')"
if [[ -z "$PR_NUMBER" ]]; then
  exit 0
fi

# ----- gate 1: CI green (with bounded wait on pending) --------------------
ci_status() {
  # Returns: GREEN | FAILING:<csv> | PENDING:<csv> | ERROR:<msg>
  # Fails CLOSED: any unexpected gh failure becomes ERROR, never GREEN.
  local out rc
  out="$(gh pr checks "$PR_NUMBER" 2>&1)"
  rc=$?
  # gh pr checks exits non-zero when checks are pending/failing, AND when
  # the API call itself fails. Distinguish "real error" from "checks not green":
  #   - rc=0 + parseable rows  -> some mix of pass/pending/fail
  #   - rc!=0 + parseable rows -> pending/failing checks (normal)
  #   - "no required checks" / "no checks reported" message -> GREEN
  #   - rc!=0 + no parseable rows -> genuine API/auth/network error
  if printf '%s' "$out" | grep -qiE 'no required checks|no checks reported'; then
    echo "GREEN"
    return
  fi
  local failing pending total
  # gh pr checks emits TAB-separated columns; check names may contain spaces.
  failing="$(printf '%s\n' "$out" | awk -F'\t' '$2=="fail"    {print $1}' | paste -sd, -)"
  pending="$(printf '%s\n' "$out" | awk -F'\t' '$2=="pending" {print $1}' | paste -sd, -)"
  total="$(printf '%s\n' "$out" | awk -F'\t' 'NF>=2 && ($2=="pass"||$2=="fail"||$2=="pending"||$2=="skipping")' | wc -l)"
  if [[ "$total" -eq 0 ]]; then
    # No recognizable rows: treat as error rather than silently green.
    local first
    first="$(printf '%s' "$out" | head -1 | tr -d '\n')"
    echo "ERROR:gh pr checks rc=$rc: ${first:-no output}"
    return
  fi
  if [[ -n "$failing" ]]; then
    echo "FAILING:$failing"
  elif [[ -n "$pending" ]]; then
    echo "PENDING:$pending"
  else
    echo "GREEN"
  fi
}

CI="$(ci_status)"
if [[ "$CI" == PENDING:* ]]; then
  # Wait up to CI_WAIT_SECONDS for CI to settle. --watch blocks until done.
  timeout "$CI_WAIT_SECONDS" gh pr checks "$PR_NUMBER" --watch >/dev/null 2>&1 || true
  CI="$(ci_status)"
fi

# ----- gate 2: unresolved review conversations ----------------------------
OWNER="$(gh repo view --json owner -q .owner.login 2>/dev/null || true)"
REPO="$(gh repo view --json name  -q .name        2>/dev/null || true)"
UNRESOLVED_ERR=""
UNRESOLVED=0
if [[ -z "$OWNER" || -z "$REPO" ]]; then
  UNRESOLVED_ERR="could not resolve owner/repo via gh"
else
  GQL_OUT="$(gh api graphql -f query='
    query($owner:String!,$repo:String!,$num:Int!) {
      repository(owner:$owner,name:$repo) {
        pullRequest(number:$num) {
          reviewThreads(first:100) { nodes { isResolved } }
        }
      }
    }' \
    -F owner="$OWNER" -F repo="$REPO" -F num="$PR_NUMBER" 2>&1)"
  GQL_RC=$?
  if [[ $GQL_RC -ne 0 ]]; then
    UNRESOLVED_ERR="gh api graphql failed (rc=$GQL_RC)"
  else
    PARSED="$(printf '%s' "$GQL_OUT" | python3 -c '
import sys, json
try:
  d = json.loads(sys.stdin.read())
  if "errors" in d and d["errors"]:
    print("ERR:graphql errors")
  else:
    n = d["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"]
    print(sum(1 for t in n if not t.get("isResolved")))
except Exception as e:
  print(f"ERR:parse {type(e).__name__}")
' 2>/dev/null)"
    if [[ "$PARSED" == ERR:* ]]; then
      UNRESOLVED_ERR="${PARSED#ERR:}"
    elif [[ -z "$PARSED" ]]; then
      UNRESOLVED_ERR="empty graphql response"
    else
      UNRESOLVED="$PARSED"
    fi
  fi
fi

# ----- gate 3: merge conflicts --------------------------------------------
# Re-fetch PR metadata: the initial $PR_JSON can be up to ~10 minutes stale
# if we waited for CI above. A conflict introduced during that wait would
# otherwise be missed (TOCTOU).
PR_JSON_FRESH="$(gh pr view --json number,mergeable,mergeStateStatus 2>/dev/null || true)"
[[ -z "$PR_JSON_FRESH" ]] && PR_JSON_FRESH="$PR_JSON"
MERGE_STATE="$(printf '%s' "$PR_JSON_FRESH" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("mergeStateStatus","")+"|"+str(d.get("mergeable","")))')"
CONFLICTING=0
if printf '%s' "$MERGE_STATE" | grep -qi 'CONFLICTING'; then
  CONFLICTING=1
fi

# ----- assemble failures ---------------------------------------------------
FAILS=()
case "$CI" in
  GREEN) ;;
  FAILING:*) FAILS+=("failing checks (${CI#FAILING:})") ;;
  PENDING:*) FAILS+=("CI still pending after ${CI_WAIT_SECONDS}s (${CI#PENDING:})") ;;
  ERROR:*)   FAILS+=("could not check CI status (${CI#ERROR:})") ;;
  *)         FAILS+=("could not check CI status (unknown ci_status output)") ;;
esac
if [[ -n "$UNRESOLVED_ERR" ]]; then
  # Fail closed: if we can't determine the state of review threads, treat
  # the gate as failing rather than silently letting the PR through.
  FAILS+=("could not check review threads ($UNRESOLVED_ERR)")
elif [[ "$UNRESOLVED" -gt 0 ]]; then
  FAILS+=("$UNRESOLVED unresolved review conversation(s)")
fi
if [[ "$CONFLICTING" -eq 1 ]]; then
  FAILS+=("merge conflict with base")
fi

if [[ ${#FAILS[@]} -eq 0 ]]; then
  echo 0 > "$COUNTER_FILE"
  exit 0
fi

# ----- enforce N=5 cap -----------------------------------------------------
COUNT=$((COUNT + 1))
echo "$COUNT" > "$COUNTER_FILE"

REASON="PR #${PR_NUMBER}: $(IFS='; '; echo "${FAILS[*]}") [block ${COUNT}/${MAX_BLOCKS}]"

if [[ "$COUNT" -gt "$MAX_BLOCKS" ]]; then
  # Surface state but allow stop so a human can take over.
  echo "pr-mergeability-gate: reached ${MAX_BLOCKS} block attempts; allowing stop. ${REASON}" >&2
  echo 0 > "$COUNTER_FILE"
  exit 0
fi

# Block: exit 2 with reason on stderr
echo "${REASON}" >&2
exit 2
