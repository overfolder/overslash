#!/usr/bin/env bash
# Create the GCS bucket that holds OpenTofu remote state for the `infra/`
# config. Run once, out-of-band, from a gcloud-authenticated machine with
# `storage.admin` on the project. After this bucket exists, re-run
# `tofu init -migrate-state` inside `infra/` to push local state up.
#
# Idempotent: re-running on an existing bucket is a no-op (each step
# either creates or updates to the desired state).
set -euo pipefail

PROJECT="${PROJECT:-overslash}"
BUCKET="${BUCKET:-overslash-tfstate}"
LOCATION="${LOCATION:-europe-west1}"

if ! command -v gcloud >/dev/null; then
    echo "ERROR: gcloud CLI is required" >&2
    exit 1
fi

echo "Project:  $PROJECT"
echo "Bucket:   gs://$BUCKET"
echo "Location: $LOCATION"
echo

# Create the bucket (uniform bucket-level access; public access blocked).
# `gcloud storage buckets create` is idempotent-ish — on an existing bucket
# it errors, so we branch on existence.
if gcloud storage buckets describe "gs://$BUCKET" --project="$PROJECT" >/dev/null 2>&1; then
    echo "Bucket already exists — skipping create."
else
    echo "Creating bucket..."
    gcloud storage buckets create "gs://$BUCKET" \
        --project="$PROJECT" \
        --location="$LOCATION" \
        --uniform-bucket-level-access \
        --public-access-prevention
fi

echo "Enabling versioning (state recovery depends on this)..."
gcloud storage buckets update "gs://$BUCKET" \
    --project="$PROJECT" \
    --versioning

echo "Adding lifecycle: keep 10 noncurrent versions, delete older..."
TMPFILE=$(mktemp)
cat > "$TMPFILE" <<'JSON'
{
  "rule": [
    {
      "action": {"type": "Delete"},
      "condition": {"numNewerVersions": 10, "isLive": false}
    },
    {
      "action": {"type": "Delete"},
      "condition": {"daysSinceNoncurrentTime": 90, "isLive": false}
    }
  ]
}
JSON
gcloud storage buckets update "gs://$BUCKET" \
    --project="$PROJECT" \
    --lifecycle-file="$TMPFILE"
rm -f "$TMPFILE"

echo
echo "Bucket ready. Next steps:"
echo "  1. cd infra && tofu init -migrate-state"
echo "     (answers 'yes' to copy existing state into GCS)"
echo "  2. Verify state is remote:  gcloud storage ls gs://$BUCKET/infra/"
echo "  3. Commit the providers.tf backend block."
