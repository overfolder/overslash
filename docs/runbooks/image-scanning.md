# Container image scanning — applying and operating it

Artifact Analysis scans every image in Artifact Registry for OS and language package
vulnerabilities. [`image-scan.yml`](../../.github/workflows/image-scan.yml) reads the results
for the images actually deployed and files a `needs-triage` issue when a HIGH or CRITICAL
finding is open. The policy it implements is
[dependency-vulnerability-policy.md](../compliance/casa/dependency-vulnerability-policy.md)
(CASA 6.1.1).

| Piece | Where |
|---|---|
| `containerscanning` + `containeranalysis` APIs, and `iam`, `iamcredentials`, `sts` for federation | `infra/main.tf` |
| Both repos follow the project setting (`enablement_config = "INHERITED"`) | `infra/modules/artifact-registry/main.tf` |
| `overslash-<env>-imgscan` service account, `github-actions` pool, `image-scan` provider | `infra/modules/image-scanning/main.tf` |
| The check | `scripts/check-image-vulns.sh`, tested by `scripts/test-check-image-vulns.sh` |
| Exceptions | `image-scan-ignores.json` |

Scanning covers the whole project, so the API, shortener and exporter images
(`overslash-<env>-registry`) and the two third-party images, overfwd and the API's
`otel-collector` sidecar (`overslash-<env>-dockerhub`, a remote repository), are all in scope.
Dev has no shortener. The check finds images from Cloud Run, sidecars included, so a new
service needs no change here. An image pulled from anywhere but this project's Artifact
Registry fails the check, because nothing would scan it.

**Status: written, not applied.** Infra is never auto-applied. This page is the human half.

## Cost

Billing starts the moment the API is enabled. Google's list price is **$0.26 per image
scanned**, charged once per digest. Rescans of the same digest are free, as is pushing that
digest to another repo or project. Check the
[pricing page](https://cloud.google.com/artifact-analysis/pricing) before applying: this
figure comes from search excerpts of it, because the page itself wouldn't load for us.

New digests pushed from 2026-10-07 to 2026-11-06:

| | `overslash-dev` | `overslash` | Total |
|---|---|---|---|
| Images (API, exporter, shortener) | 109 | 22 | 131 |
| BuildKit cache manifests (`*/cache`) | 118 | 24 | 142 |

| Case | Per month |
|---|---|
| Images only | about **$34** |
| Cache manifests billed too | about **$71** |

Google's cost guide counts digests pushed, and the cache is exported with
`image-manifest=true`, so it may be billed even though it has nothing to scan. Step 3 below
measures that. Dev pushes about five times as much as prod, and on every push to `dev`, so
dev is about 83% of the bill.

Levers, if the bill matters:

- Move `cache_ref` in the three `cloud-build*` modules to a repository of its own with
  `enablement_config = "DISABLED"`. This removes the cache half, at the cost of one cold build
  per image.
- Set `enablement_config = "DISABLED"` on dev's registry. This saves most of the bill, but dev
  stops being an early warning, and the check must drop its `dev` matrix entry or it fails
  every day on unscanned images.

The check itself is free: a few read calls a day, on GitHub-hosted runners.

## Apply

Run these with an identity that can create Workload Identity pools and set project IAM
(project Owner does). Dev first.

### 1. Plan and apply dev

```bash
make tofu-plan ENV=dev
make tofu-apply ENV=dev
```

Expect, on top of any unrelated drift: 13 to add and 3 to change. That is 5
`google_project_service.image_scanning`, 8 in `module.image_scanning`, an in-place
`vulnerability_scanning_config` on each repo, and the API's Cloud Run service. `iam` and
`iamcredentials` are already on, so those two only enter state.

**Stop if the plan replaces `module.secret_manager.google_project_iam_member.api_secret_accessor`.**
It shouldn't. These APIs have their own resource to avoid exactly that, because replacing the
grant leaves the API without access to secrets for a moment.

**The apply rolls a new API revision.** The `otel-collector` sidecar moves from Docker Hub to
the mirror. It is the same image (the digest of the `0.120.0` tag already running), and the
API container keeps its deployed image, but it is a real deploy and the first pull goes through
the mirror. On prod, apply when you can watch it, and check metrics still arrive afterwards.

That revision also carries an unrelated change, if nothing has applied it first: D141's TCP
startup and liveness probes are committed, but both API services still ran `httpGet` probes on
2026-11-06. They show in the same plan. To keep the two apart, apply D141 on its own first.

**Known risk: the org's domain restriction.** `iam.allowedPolicyMemberDomains` allows only
our customer ID. Google's docs don't say whether it evaluates the `principalSet://` member
that `google_service_account_iam_member.github_impersonation` adds, and the only way to know
is to apply it. If that one resource fails with a message about users not belonging to a
permitted customer, everything else has applied and scanning is on. Then add the
organization principal set to the policy's allowed values in the org repo (it needs
`roles/orgpolicy.policyAdmin` on the org), and re-apply.

### 2. Check it applied

```bash
gcloud services list --enabled --project=overslash-dev \
  --filter='config.name:(containerscanning.googleapis.com containeranalysis.googleapis.com sts.googleapis.com)'

gcloud artifacts repositories list --project=overslash-dev --location=europe-west1 \
  --format='table(name.basename(),mode,vulnerabilityScanningConfig.enablementState,vulnerabilityScanningConfig.enablementConfig)'
```

Both repos should read `SCANNING_ACTIVE` / `INHERITED`. Re-run the plan and confirm it is
clean. Google has returned an empty `enablementConfig` until now, so if the plan keeps
proposing `INHERITED` after the apply, remove the two blocks from the module: the check still
fails on an image a disabled repo stops scanning.

### 3. Get the deployed images scanned

Only new pushes are documented as being scanned, so assume everything already deployed is
unscanned. The check fails on those with *never been scanned*, which is the signal to do this.

The next push to `dev` covers the API image on dev. Then:

```bash
# Scan results for the newest versions of one image
gcloud artifacts docker images list \
  europe-west1-docker.pkg.dev/overslash-dev/overslash-dev-registry/overslash-api \
  --show-occurrences --occurrence-filter='kind="VULNERABILITY"' --include-tags --limit=5

# Was a cache manifest scanned? Empty or FINISHED_UNSUPPORTED both need the bill checked.
gcloud artifacts docker images list \
  europe-west1-docker.pkg.dev/overslash-dev/overslash-dev-registry/overslash-api/cache \
  --show-occurrences --occurrence-filter='kind="DISCOVERY"' --format=json --limit=1
```

After a day of dev pushes, compare the Artifact Analysis SKU in Billing against the image
count, to settle which row of the cost table applies. Update this page with the answer.

The sidecar needs nothing: the apply enables scanning before it rolls the revision, so its
first pull through the mirror is a new image. Other images that won't be rebuilt soon (the
exporter, and overfwd in either project): pull each one, then give it up to 24 hours.

```bash
gcloud auth configure-docker europe-west1-docker.pkg.dev
docker pull <image from `gcloud run services describe` or `gcloud run jobs describe`>
```

Google documents a pull as refreshing a *stale* image. Whether it also triggers the first
scan of an image pushed before enablement is undocumented. If the image still has no
`DISCOVERY` occurrence the next day, rebuild it. Run the image's Cloud Build trigger, which
**also deploys the branch tip**, so on prod do this after a release. overfwd isn't built here:
it needs a new upstream digest in `overfwd_image`.

### 4. Triage the first results

```bash
bash scripts/check-image-vulns.sh --project overslash-dev   # uses your gcloud account
```

Expect findings on the first run, because Debian carries HIGH advisories with no fix yet.
Handle each one under the policy: rebuild if a fix exists, otherwise add a justified entry to
`image-scan-ignores.json` and to the register in the policy.

### 5. Prod

Repeat steps 1 to 4 with `ENV=prod` and `overslash`. Enabling the APIs and the repo setting
does not touch running services.

### 6. Turn on the workflow

GitHub reads schedules, and the *Run workflow* trigger, from the default branch, so
`image-scan.yml` does nothing until the next `dev` → `master` release. Then:

```bash
gh workflow run image-scan.yml --ref master
gh run list --workflow=image-scan.yml --limit=1
```

The matrix hardcodes each project's number and service account. They must match
`tofu output image_scan_workload_identity_provider` and `image_scan_service_account`.

If that run finds anything, it opens the *Container image scan failing (scheduled scan)*
issue with `needs-triage`. Confirm the issue appears. That proves the path end to end, so
leave one finding unexcepted for the first run if you can.

### 7. Capture the evidence

For [evidence-index.md](../compliance/casa/evidence-index.md): the output of step 2 on both
projects, a green scheduled run, and the first triage issue. Then tick the item in
[TODO.md](../../TODO.md), update the measured state in
[gcp-posture.md](../compliance/casa/gcp-posture.md), and add scanning to
[STATUS.md](../../STATUS.md).

## Rollback

Revert the `containerscanning.googleapis.com` line and run:

```bash
gcloud services disable containerscanning.googleapis.com --project=<project>
```

Do both. The resource has `disable_on_destroy = false`, so removing it alone leaves the API on
and billing, and disabling it alone is undone by the next apply. No service depends on
scanning, so this is safe at any time.

## When the check fails

Read the job log. The job summary lists open findings.

| Message | Meaning | Do this |
|---|---|---|
| `HIGH CVE-… in <package> (fix: <version>)` | A deployed image has a fixable finding | Rebuild, below. The SLA runs from this first failure |
| `… (fix: none)` | No fix published yet | Justified entry in `image-scan-ignores.json`, or change the base image |
| `reviewBy … has passed` | An exception ran out | Re-review it, per the policy |
| `has never been scanned` | Pushed before enablement, or the scan never ran | Step 3 |
| `scan ended as FINISHED_UNSUPPORTED` / `FINISHED_FAILED` | The scanner can't read this image | Read `analysisError` on its `DISCOVERY` occurrence. A base image we can't scan is a coverage gap, so change it |
| `is stale` | Not pulled for 30 days, so new advisories stop reaching it | Pull it (step 3). Redeploying also works |
| `outside … so nothing scans it` | A service runs an image from another registry | Move it into Artifact Registry |
| `GET … failed` | Sign-in or permissions | Check the role grants, then the provider's `attribute_condition` |
| `google-github-actions/auth` fails | Federation | Compare the matrix values with `tofu output`. The provider accepts only `image-scan.yml` on `dev` and `master` |

Stale is the one to watch. Google only says "pulled", and doesn't say whether Cloud Run
starting an instance counts. Prod images can go a month between releases, so if `is stale`
turns out to recur, teach the workflow to pull stale images rather than doing it by hand.

### Fixing an image

Findings are mostly in OS packages, which come from `debian:trixie-slim` and the
`apt-get install` layer. Nothing in the repo pins them, so a fresh build picks up the fix once
Debian has published it, as long as BuildKit doesn't reuse the cached layer. That cache is
keyed on the base image digest and the command, so **a rebuild can reuse the vulnerable layer
until Debian refreshes `trixie-slim`**. If a rebuild leaves the finding in place, add
`apt-get upgrade -y` to that image's runtime stage.

| Image | Rebuilds when | To force it |
|---|---|---|
| `overslash-api` | Every push to the deploy branch | Any merge |
| `overslash-metrics-exporter`, `oversla-sh` | Only when their paths change | Run the Cloud Build trigger |
| `overfwd` | Never here | New upstream image, then a new `overfwd_image` digest ([mailbox-gateway.md](mailbox-gateway.md)) |
| `otel-collector` sidecar | Never here | A newer upstream release, then a new `otel_collector_image` digest. Pinned at 0.120.0 today, an old release, so expect findings in it on the first run |

Rust crates are the dependency audit's job. The scanner's Cargo support may report them too,
but `cargo-deny` and OSV remain the gate for `Cargo.lock`.
