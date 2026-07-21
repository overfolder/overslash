# Release runbook

How a release goes from `dev` to binaries on a GitHub release. See
[D19](../../DECISIONS.md) for the rationale.

## Normal flow

1. **Sync the release base** (only needed if `master` holds rebased copies of
   `dev` commits from a previous rebase-merge — check with
   `git cherry origin/dev origin/master`, which must print nothing):

   ```sh
   git checkout dev && git pull
   git merge -s ours origin/master -m "Merge master into dev (sync release base for vX.Y.Z)"
   git push origin dev   # requires ruleset bypass (admin)
   ```

2. **Open the promotion PR** `dev` → `master`, titled `Release vX.Y.Z`, with
   highlights grouped by area (see #345 / #373 for the shape). Merge it once
   CI is green.

3. **release-please takes over.** The push to `master` triggers
   `release-please.yml`, which opens (or updates) a `chore(release): vX.Y.Z`
   PR against `master` bumping `version.txt` / `.release-please-manifest.json`
   and prepending `CHANGELOG.md` from the conventional commits since the last
   tag. Review the changelog, then merge.

4. **Tag + binaries are automatic.** Merging the release PR creates the
   `vX.Y.Z` tag and GitHub release; the tag push triggers `release.yml`,
   which builds the dashboard-embedded binary for 4 targets and attaches
   the archives + `SHA256SUMS.txt` to the release. The binaries report the
   tag version (injected via `OVERSLASH_VERSION` at build time).

5. **Sync back — automatic.** The same tag push triggers `sync-dev.yml`, which
   merges `master` into `dev` so the changelog/version commit doesn't drift.
   It exits early when `dev` already contains `master`, so re-running it is
   always safe (`gh workflow run sync-dev.yml`).

   It fails loudly on a merge conflict or a rejected push. Then do it by hand
   (needs admin, see Requirements):

   ```sh
   git checkout dev && git pull
   git merge --no-ff origin/master -m "chore: sync master into dev (post-release vX.Y.Z)"
   git push origin dev
   ```

   Never rebase `dev` onto `master`: `dev` is the default branch and its ruleset
   forbids non-fast-forward pushes. The merge is also what keeps
   `.release-please-manifest.json` current on `dev`, which is where every
   non-release build reads its `X.Y.Z-dev` version from.

## Requirements

- **`RELEASE_PLEASE_TOKEN` repo secret** — fine-grained PAT scoped to
  `overfolder/overslash` with **Contents: read/write** and
  **Pull requests: read/write**. Without it the workflow falls back to
  `GITHUB_TOKEN`, whose PRs never trigger CI (the master ruleset's required
  checks block the release PR) and whose tags never trigger `release.yml`.
  Rotate before expiry; the workflow fails loudly with 403s when it lapses.
- **The PAT's owner must be a repository admin.** `sync-dev.yml` pushes the
  merge commit straight to `dev`, whose ruleset requires a pull request and
  allows squash merges only; the repository-admin role is the ruleset's bypass
  actor. A sync PR is not an equivalent: a squash merge never makes the release
  commit an ancestor of `dev`, so the drift would return every release.

## Emergency / manual path

A hand-pushed tag still works exactly as before release-please:

```sh
git tag vX.Y.Z <master-sha> && git push origin vX.Y.Z
```

`release.yml` builds the binaries and creates the release with
auto-generated notes. Afterwards, update `.release-please-manifest.json` on
`master` to the new version so release-please's bookkeeping stays correct.

## Validating release.yml without releasing

`workflow_dispatch` on `release.yml` with a version ending in `-test`
(e.g. `v0.0.0-test`) runs the full build matrix but skips publishing —
download artifacts from the run instead.
