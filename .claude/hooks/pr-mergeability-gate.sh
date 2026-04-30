#!/usr/bin/env bash
# Stop hook: block agent turn end until current branch's PR satisfies all
# three mergeability gates (CI green, no unresolved review threads, no conflicts).
#
# Input: JSON on stdin, including { "stop_hook_active": bool, ... }
# Behavior:
#   - exit 0  -> allow stop
#   - exit 2  -> block stop, stderr "reason" surfaced to the model
#
# During the CI wait we poll every POLL_SECONDS and break out early on:
#   - any required check having gone `fail` (rest of CI still pending)
#   - Seer Code Review having finished while leaving unresolved Seer comments
#
# Caps at N=5 block attempts per turn (tracked in a per-session state file)
# to avoid infinite looping. After 5 blocks we surface state and allow stop.

set -uo pipefail

MAX_BLOCKS=5
CI_WAIT_SECONDS=600  # 10 minutes total CI settle wait
POLL_SECONDS=90      # poll cadence inside the wait window

# Set to 1 when we hit a failure mode the agent cannot fix in-loop (gh/API
# errors, owner/repo resolution, graphql failures). Fatal failures surface
# once and allow stop instead of consuming MAX_BLOCKS retries.
FATAL=0

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

PR_JSON="$(gh pr view --json number,mergeable,mergeStateStatus,headRefName,baseRefName 2>/dev/null || true)"
if [[ -z "$PR_JSON" ]]; then
  # No PR for this branch -> nothing to gate
  exit 0
fi

PR_NUMBER="$(printf '%s' "$PR_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("number",""))')"
if [[ -z "$PR_NUMBER" ]]; then
  exit 0
fi
PR_BASE="$(printf '%s' "$PR_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("baseRefName",""))')"

# Resolve owner/repo once: needed by fetch_review_threads() during the poll
# loop AND by gate 2.
OWNER="$(gh repo view --json owner -q .owner.login 2>/dev/null || true)"
REPO="$(gh repo view --json name  -q .name        2>/dev/null || true)"

# ----- check helpers -------------------------------------------------------
gh_pr_checks_raw() {
  # Echo raw `gh pr checks` output (stdout+stderr). Returns empty on call
  # failure; downstream parsers treat "no parseable rows" as ERROR.
  gh pr checks "$PR_NUMBER" 2>&1 || true
}

ci_status() {
  # $1 = raw `gh pr checks` output.
  # Echoes: GREEN | FAILING:<csv> | PENDING:<csv> | ERROR:<msg>
  # Fails CLOSED: any unrecognized output becomes ERROR, never GREEN.
  local out="$1"
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
    local first
    first="$(printf '%s' "$out" | head -1 | tr -d '\n')"
    echo "ERROR:gh pr checks: ${first:-no output}"
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

seer_check_state() {
  # $1 = raw `gh pr checks` output.
  # Echoes: RUNNING | DONE | MISSING | ERROR:<msg>
  # MISSING means Seer is not configured on this PR (treat as "no signal").
  local row state
  row="$(printf '%s\n' "$1" | awk -F'\t' '$1=="Seer Code Review" {print; exit}')"
  if [[ -z "$row" ]]; then
    echo "MISSING"
    return
  fi
  state="$(printf '%s' "$row" | awk -F'\t' '{print $2}')"
  case "$state" in
    pending)            echo "RUNNING" ;;
    pass|fail|skipping) echo "DONE" ;;
    *)                  echo "ERROR:unknown state '$state'" ;;
  esac
}

fetch_review_threads() {
  # Echoes a JSON blob from the GraphQL response, or "ERR:<reason>" on failure.
  if [[ -z "$OWNER" || -z "$REPO" ]]; then
    echo "ERR:could not resolve owner/repo via gh"
    return
  fi
  local out rc
  out="$(gh api graphql -f query='
    query($owner:String!,$repo:String!,$num:Int!) {
      repository(owner:$owner,name:$repo) {
        pullRequest(number:$num) {
          reviewThreads(first:100) {
            nodes {
              isResolved
              comments(first:1) { nodes { author { login } } }
            }
          }
        }
      }
    }' \
    -F owner="$OWNER" -F repo="$REPO" -F num="$PR_NUMBER" 2>&1)"
  rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "ERR:gh api graphql failed (rc=$rc)"
    return
  fi
  printf '%s' "$out"
}

count_unresolved_seer() {
  # $1 = JSON blob from fetch_review_threads.
  # Echoes integer count of unresolved threads whose first comment author is
  # "sentry" (Seer's GitHub identity). Echoes 0 on any parse trouble — caller
  # decides whether absence is fatal.
  printf '%s' "$1" | python3 -c '
import sys, json
try:
  d = json.loads(sys.stdin.read())
  if "errors" in d and d["errors"]:
    print(0); sys.exit(0)
  nodes = d["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"]
  c = 0
  for t in nodes:
    if t.get("isResolved"): continue
    cs = t.get("comments", {}).get("nodes", [])
    if cs and cs[0].get("author", {}).get("login") == "sentry":
      c += 1
  print(c)
except Exception:
  print(0)
' 2>/dev/null
}

count_unresolved_total() {
  # $1 = JSON blob from fetch_review_threads.
  # Echoes either an integer count of all unresolved threads, or "ERR:<reason>".
  printf '%s' "$1" | python3 -c '
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
' 2>/dev/null
}

# ----- gate 1: CI green (with bounded poll-and-fail-fast wait) ------------
SEER_FAIL_FAST=""    # reason if Seer fail-fast fires
CI_FAIL_FAST=""      # reason if any check has gone `fail` mid-pending
THREADS_JSON=""      # cached threads JSON for gate 2 reuse

raw="$(gh_pr_checks_raw)"
CI="$(ci_status "$raw")"
if [[ "$CI" == PENDING:* ]]; then
  deadline=$(( $(date +%s) + CI_WAIT_SECONDS ))
  while :; do
    raw="$(gh_pr_checks_raw)"
    CI="$(ci_status "$raw")"

    # Fail-fast #1: any required check has gone red. ci_status returns
    # FAILING:* whenever at least one row is `fail`, even if others are still
    # pending — so this short-circuits the wait the moment a failure appears.
    if [[ "$CI" == FAILING:* ]]; then
      CI_FAIL_FAST="failing checks (${CI#FAILING:})"
      break
    fi

    # CI fully settled green/error -> exit loop, normal flow handles it.
    [[ "$CI" != PENDING:* ]] && break

    # Fail-fast #2: Seer's own check is done AND it left unresolved comments.
    seer="$(seer_check_state "$raw")"
    if [[ "$seer" == "DONE" ]]; then
      tj="$(fetch_review_threads)"
      if [[ "$tj" != ERR:* ]]; then
        THREADS_JSON="$tj"
        n_seer="$(count_unresolved_seer "$tj")"
        if [[ "${n_seer:-0}" -gt 0 ]]; then
          SEER_FAIL_FAST="${n_seer} unresolved Seer comment(s); Seer Code Review has finished while other CI is still pending"
          break
        fi
      fi
      # GraphQL hiccup -> skip this tick, retry next loop.
    fi

    now=$(date +%s)
    [[ "$now" -ge "$deadline" ]] && break
    remain=$(( deadline - now ))
    if (( remain < POLL_SECONDS )); then
      sleep "$remain"
    else
      sleep "$POLL_SECONDS"
    fi
  done
fi
if [[ "$CI" == ERROR:* ]]; then
  FATAL=1
fi

# ----- early exit on fail-fast signals from the loop ----------------------
EARLY_REASON=""
[[ -n "$CI_FAIL_FAST" ]] && EARLY_REASON="$CI_FAIL_FAST"
[[ -z "$EARLY_REASON" && -n "$SEER_FAIL_FAST" ]] && EARLY_REASON="$SEER_FAIL_FAST"

if [[ -n "$EARLY_REASON" ]]; then
  REASON="PR #${PR_NUMBER}: ${EARLY_REASON}"
  COUNT=$((COUNT + 1))
  echo "$COUNT" > "$COUNTER_FILE"
  if [[ "$COUNT" -gt "$MAX_BLOCKS" ]]; then
    echo "pr-mergeability-gate: reached ${MAX_BLOCKS} block attempts; allowing stop. ${REASON}" >&2
    echo 0 > "$COUNTER_FILE"
    exit 0
  fi
  echo "${REASON} [block ${COUNT}/${MAX_BLOCKS}]" >&2
  exit 2
fi

# ----- gate 2: unresolved review conversations ----------------------------
UNRESOLVED_ERR=""
UNRESOLVED=0
if [[ -z "$OWNER" || -z "$REPO" ]]; then
  UNRESOLVED_ERR="could not resolve owner/repo via gh"
  FATAL=1
else
  if [[ -z "$THREADS_JSON" ]]; then
    THREADS_JSON="$(fetch_review_threads)"
  fi
  if [[ "$THREADS_JSON" == ERR:* ]]; then
    UNRESOLVED_ERR="${THREADS_JSON#ERR:}"
    FATAL=1
  else
    PARSED="$(count_unresolved_total "$THREADS_JSON")"
    if [[ "$PARSED" == ERR:* ]]; then
      UNRESOLVED_ERR="${PARSED#ERR:}"
      FATAL=1
    elif [[ -z "$PARSED" ]]; then
      UNRESOLVED_ERR="empty graphql response"
      FATAL=1
    else
      UNRESOLVED="$PARSED"
    fi
  fi
fi

# ----- gate 3: merge conflicts --------------------------------------------
# Re-fetch PR metadata: the initial $PR_JSON can be up to ~10 minutes stale
# if we waited for CI above. A conflict introduced during that wait would
# otherwise be missed (TOCTOU).
PR_JSON_FRESH="$(gh pr view --json number,mergeable,mergeStateStatus,baseRefName 2>/dev/null || true)"
PR_REFRESH_OK=1
if [[ -z "$PR_JSON_FRESH" ]]; then
  PR_JSON_FRESH="$PR_JSON"
  PR_REFRESH_OK=0
fi
MERGE_STATE="$(printf '%s' "$PR_JSON_FRESH" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("mergeStateStatus","")+"|"+str(d.get("mergeable","")))')"
# Refresh PR_BASE from the same fresh fetch — the base branch can be changed
# by a user during the CI wait, and the auto-merge decision below must reflect
# the current target, not the value captured at hook entry. If the refresh
# failed, leave PR_BASE empty so the auto-merge step skips (fail closed).
if [[ "$PR_REFRESH_OK" -eq 1 ]]; then
  PR_BASE="$(printf '%s' "$PR_JSON_FRESH" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("baseRefName",""))')"
else
  PR_BASE=""
fi
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

# ----- fail fast on unactionable failures ---------------------------------
# gh/graphql/owner-repo errors can't be fixed by the agent in-loop; surface
# once and allow stop instead of burning MAX_BLOCKS retries.
if [[ "$FATAL" -eq 1 ]]; then
  REASON="PR #${PR_NUMBER}: $(IFS='; '; echo "${FAILS[*]}")"
  echo "pr-mergeability-gate: unactionable failure, surfacing instead of retrying. ${REASON}" >&2
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
