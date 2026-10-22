# `<project>_cloudbuild` bucket hardening — applying it

`infra/modules/cloud-build-source/main.tf` adopts the bucket Cloud Build auto-created in
each project and hardens it. An `import` block in `infra/main.tf` brings it into state, so
the apply is an import plus an in-place update. It covers both projects:

| Bucket | Project | UBLA | Public access prevention | Lifecycle |
|---|---|---|---|---|
| `overslash_cloudbuild` | `overslash` | `false` → **`true`** | `inherited` → **`enforced`** | none → delete objects older than 30 days |
| `overslash-dev_cloudbuild` | `overslash-dev` | `false` → **`true`** | `inherited` → **`enforced`** | none → delete objects older than 30 days |

Raised by the live scan in [gcp-posture.md](../compliance/casa/gcp-posture.md#storage--production).
Infra is never auto-applied. This page is the human half.

## Why import it instead of moving builds elsewhere

None of our builds use this bucket. All three triggers (`cloud-build`, `cloud-build-shortener`,
`cloud-build-metrics-exporter`) are GitHub-connected and clone from GitHub, so they never
stage source in GCS. Both buckets were created on 2026-04-29 by a one-off manual
`gcloud builds submit` and each holds that single archive. That leaves no trigger config to
point at a managed bucket. Deleting the bucket would only let the next manual submit
recreate it with the same defaults. Owning it keeps the name taken and hardened.

That archive was a working-directory dump, not a git checkout. With no `.gcloudignore`,
gcloud honoured `.gitignore` but not `.git/info/exclude`, so it uploaded
`.claude/settings.local.json` and a Python `.venv/`. The repo now has a `.gcloudignore`, and the
apply below deletes the archive.

## What changes for access

Turning on UBLA drops the legacy ACLs (project owners and editors `OWNER`, project viewers
`READER`) on the bucket and its objects. Access is then IAM-only:

- Owners and editors keep access through their project roles, so a manual
  `gcloud builds submit` still works.
- `roles/viewer` has no `storage.objects.get`, so project viewers can no longer read source
  archives. That is intended.

The triggers are unaffected.

## Pre-flight (each project)

```bash
for p in overslash-dev overslash; do
  gcloud storage buckets describe gs://${p}_cloudbuild \
    --format="yaml(location,storage_class,uniform_bucket_level_access,public_access_prevention)"
  gcloud storage ls -l -r gs://${p}_cloudbuild/
done
# expect location: US and storage_class: STANDARD. If either differs, stop: the module
# would replace the bucket. Change location/storage_class in the module to match first.
```

## Apply: dev first, then prod

```bash
make tofu-init
make tofu-plan ENV=dev
# Expect, and only this under module.cloud_build_source:
#   # module.cloud_build_source.google_storage_bucket.source will be updated in-place
#   # (imported from "overslash-dev_cloudbuild")
#   ~ public_access_prevention    = "inherited" -> "enforced"
#   ~ uniform_bucket_level_access = false -> true
#   + lifecycle_rule { action { type = "Delete" } condition { age = 30 } }
#   Plan: 1 to import, ... 1 to change ...
# A "-/+" or "must be replaced" on this bucket means STOP (see pre-flight).
# If unrelated drift shows up and you don't want it now, target the module:
#   cd infra && tofu workspace select dev && \
#   tofu plan -var-file=env/dev.tfvars -target=module.cloud_build_source -out=dev.tfplan && cd ..
make tofu-apply ENV=dev

make tofu-plan ENV=prod      # same expectations, "imported from "overslash_cloudbuild""
make tofu-apply ENV=prod     # asks you to type `prod`
```

A read-only targeted plan was run on both workspaces before the PR. Each showed exactly
`1 to import, 0 to add, 1 to change, 0 to destroy`.

The `import` block is a no-op once the bucket is in state, so it can stay. A brand-new
project has no `_cloudbuild` bucket until its first manual submit, so drop the block for
that project's first apply.

## Delete the bootstrap archive now

The lifecycle rule deletes it within about a day of the apply. Since it carried a local-only
settings file, delete it straight away:

```bash
for p in overslash-dev overslash; do
  gcloud storage rm "gs://${p}_cloudbuild/source/**"
done
```

Soft delete (7 days, the bucket default) keeps it restorable for another week. After that
it is gone for good.

## Verify and capture evidence

```bash
for p in overslash-dev overslash; do
  gcloud storage buckets describe gs://${p}_cloudbuild \
    --format="yaml(name,uniform_bucket_level_access,public_access_prevention,lifecycle_config)"
  gcloud storage buckets describe gs://${p}_cloudbuild --format="value(acl)"   # expect empty
  gcloud storage ls -r gs://${p}_cloudbuild/                                    # expect no objects
done
```

Paste the output into the evidence pack ([evidence-index.md](../compliance/casa/evidence-index.md),
Scan output). Update the Storage table in [gcp-posture.md](../compliance/casa/gcp-posture.md)
to the measured values and drop "pending apply" from TODO.md §1.6 and the gap-assessment
3.1.1 caveat.

## Rollback

- UBLA can be turned off again for 90 days after it was enabled. Set
  `uniform_bucket_level_access = false` and apply. After 90 days it is permanent.
- Public access prevention and the lifecycle rule are plain in-place edits.
- To stop managing the bucket without touching it, run
  `tofu state rm module.cloud_build_source.google_storage_bucket.source` and remove the
  module and the `import` block.
