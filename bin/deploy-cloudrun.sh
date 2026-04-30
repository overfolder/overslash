#!/usr/bin/env bash
# Build, push, and deploy an Overslash Cloud Run service or Job from local.
# Mirrors the Cloud Build pipeline, useful when CB is unavailable (incident /
# weekend) or when you want to skip the GitHub-trigger round-trip.
#
# Also pokes Cloud SQL to ALWAYS-on and waits for RUNNABLE before deploying,
# so it works even if the night scheduler has paused the dev instance.
#
# Usage:
#   bin/deploy-cloudrun.sh <svc> [env]
#
# svc: api | metrics-exporter | shortener
# env: dev (default) | prod
#
# Env vars:
#   CONTAINER_RUNTIME=docker|podman   (default: docker)
#   DEPLOY_AUTO_APPROVE=1              skip prod confirmation
#   SHA=<tag>                          override image tag (default: short SHA, +"-dirty" if uncommitted)
#   SKIP_SQL_WAKE=1                    skip the SQL wake/poll (e.g. for shortener)

set -euo pipefail

SVC="${1:-}"
ENV_NAME="${2:-dev}"

usage() {
  echo "Usage: $0 <api|metrics-exporter|shortener> [dev|prod]"
  echo ""
  echo "Examples:"
  echo "  $0 api                       # build & deploy api to dev"
  echo "  $0 metrics-exporter dev      # build & update the exporter Cloud Run Job"
  echo "  $0 api prod                  # prod (asks for confirmation)"
  echo "  CONTAINER_RUNTIME=podman $0 api"
  exit 1
}
[ -z "$SVC" ] && usage

case "$SVC" in
  api)              IMG=overslash-api;              DOCKERFILE=crates/overslash-api/Dockerfile;              IS_JOB=false; SQL_NEEDED=true  ;;
  metrics-exporter) IMG=overslash-metrics-exporter; DOCKERFILE=crates/overslash-metrics-exporter/Dockerfile; IS_JOB=true;  SQL_NEEDED=true  ;;
  shortener)        IMG=oversla-sh;                 DOCKERFILE=crates/oversla-sh/Dockerfile;                 IS_JOB=false; SQL_NEEDED=false ;;
  *) echo "Unknown service: $SVC"; usage ;;
esac

case "$ENV_NAME" in
  prod)      PROJECT=overslash ;;
  dev|stage) PROJECT="overslash-${ENV_NAME}" ;;
  *) echo "Unknown env: $ENV_NAME"; usage ;;
esac

REGION="europe-west1"
RUNTIME="${CONTAINER_RUNTIME:-docker}"
BASE_PREFIX="overslash-${ENV_NAME}"
REPO="${BASE_PREFIX}-registry"
AR_HOST="${REGION}-docker.pkg.dev"
SQL_INSTANCE="${BASE_PREFIX}-db"
CLOUDRUN_NAME="${BASE_PREFIX}-${SVC}"
IMAGE="${AR_HOST}/${PROJECT}/${REPO}/${IMG}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Tag = short SHA, with "-dirty" if working tree differs from HEAD
if [ -z "${SHA:-}" ]; then
  SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
  if ! git -C "$REPO_ROOT" diff --quiet HEAD 2>/dev/null; then
    SHA="${SHA}-dirty"
  fi
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[deploy:${SVC}:${ENV_NAME}]${NC} $1"; }
warn() { echo -e "${YELLOW}[deploy:${SVC}:${ENV_NAME}]${NC} $1"; }
err()  { echo -e "${RED}[deploy:${SVC}:${ENV_NAME}]${NC} $1" >&2; exit 1; }
now()  { date +%s; }

command -v gcloud  >/dev/null || err "gcloud CLI not found"
command -v "$RUNTIME" >/dev/null || err "$RUNTIME not found (set CONTAINER_RUNTIME=docker|podman)"

# Prod confirmation
if [ "$ENV_NAME" = "prod" ] && [ "${DEPLOY_AUTO_APPROVE:-0}" != "1" ]; then
  echo -e "${RED}About to deploy ${BOLD}${SVC}${NC}${RED} (${IMAGE}:${SHA}) to PRODUCTION (${PROJECT})${NC}"
  read -rp "Type 'prod' to confirm: " confirm
  [ "$confirm" = "prod" ] || { echo "Aborted."; exit 1; }
fi

# Wake Cloud SQL — idempotent. Skipped for services that don't talk to SQL.
if [ "$SQL_NEEDED" = "true" ] && [ "${SKIP_SQL_WAKE:-0}" != "1" ]; then
  log "Ensuring Cloud SQL ${SQL_INSTANCE} is RUNNABLE..."
  gcloud sql instances patch "$SQL_INSTANCE" \
    --activation-policy=ALWAYS --project="$PROJECT" --quiet >/dev/null 2>&1 || true
  for i in $(seq 1 60); do
    state="$(gcloud sql instances describe "$SQL_INSTANCE" \
      --project="$PROJECT" --format='value(state)' 2>/dev/null || echo UNKNOWN)"
    if [ "$state" = "RUNNABLE" ]; then
      log "  SQL state: RUNNABLE"
      break
    fi
    log "  SQL state: $state — waiting..."
    sleep 10
    [ "$i" -eq 60 ] && err "Timed out waiting for SQL to become RUNNABLE"
  done
fi

# AR auth
log "Configuring Artifact Registry auth..."
gcloud auth configure-docker "$AR_HOST" --quiet >/dev/null

# Build
T_BUILD_START=$(now)
log "Building image (tag: ${SHA})..."
"$RUNTIME" build \
  -f "$DOCKERFILE" \
  -t "${IMAGE}:${SHA}" \
  -t "${IMAGE}:latest" \
  "$REPO_ROOT"
T_BUILD_END=$(now)

# Push
T_PUSH_START=$(now)
log "Pushing ${IMAGE}:${SHA} and :latest..."
"$RUNTIME" push "${IMAGE}:${SHA}"
"$RUNTIME" push "${IMAGE}:latest"
T_PUSH_END=$(now)

# Deploy
T_DEPLOY_START=$(now)
if [ "$IS_JOB" = "true" ]; then
  log "Updating Cloud Run Job ${CLOUDRUN_NAME}..."
  gcloud run jobs update "$CLOUDRUN_NAME" \
    --image="${IMAGE}:${SHA}" \
    --region="$REGION" \
    --project="$PROJECT" \
    --quiet
else
  log "Deploying to Cloud Run service ${CLOUDRUN_NAME}..."
  gcloud run deploy "$CLOUDRUN_NAME" \
    --image="${IMAGE}:${SHA}" \
    --region="$REGION" \
    --project="$PROJECT" \
    --quiet
fi
T_DEPLOY_END=$(now)

# Summary
T_TOTAL=$(( T_DEPLOY_END - T_BUILD_START ))
echo ""
echo -e "${BOLD}── Summary ─────────────────────────────${NC}"
printf "  Build:  %3ds\n" $(( T_BUILD_END - T_BUILD_START ))
printf "  Push:   %3ds\n" $(( T_PUSH_END - T_PUSH_START ))
printf "  Deploy: %3ds\n" $(( T_DEPLOY_END - T_DEPLOY_START ))
echo -e "  ${BOLD}Total:  ${T_TOTAL}s${NC}"
echo ""
log "Done! ${IMAGE}:${SHA} → ${CLOUDRUN_NAME}"
