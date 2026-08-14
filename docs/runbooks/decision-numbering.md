<!-- decision-numbering:vocabulary -->

# Decision numbering runbook

Decision numbers are allocated **at merge**, not while you write. You author
`## D-NEXT:`; a workflow stamps the real number across the whole repo once the
PR lands on `dev`.

## Why

`DECISIONS.md` is append-only, so `max + 1` is only correct until the next
decision merges. At the current rate that is hours. The number is also
denormalized into roughly ten files per PR — `STATUS.md`, `TODO.md`, `SPEC.md`,
Rust comments, Svelte, migrations, service YAML, Terraform descriptions — so a
renumber is a ten-file rename across five languages, done by hand under rebase
pressure. It has gone wrong twice:

- **#546** renumbered three times (`dev` took D57, then D60, then D61 while the
  branch was open) and still merged with a subject naming D60 for a decision
  that shipped as D62.
- **#542**'s renumber reached `DECISIONS.md` and none of the six other files
  that cited it, so `STATUS.md`, `TODO.md`, three Terraform files and the dev
  compose file pointed at an unrelated decision.
- **#547** was authored as D57 and shipped as D61, leaving its authoring number
  in five files — and one `STATUS.md` bullet credited D62, which belongs to a
  different PR entirely.

None of it is detectable by a lint: every one of those cites a number that
exists. Fourteen citations were wrong when this was written. Removing the guess
is the only fix.

## Authoring a decision

1. Write the entry with the placeholder heading, keeping the usual shape:

   ```markdown
   ## D-NEXT: The thing you decided, stated as a claim

   **Date**: 2026-08-14
   **Decision**: …
   **Rationale**: …
   ```

2. Refer to it as `D-NEXT` everywhere else in the same PR — code comments,
   `STATUS.md`, `TODO.md`, Terraform `description` strings. The allocator
   rewrites every tracked file, so all of them move together.

3. **Leave the number out of the commit subject and PR title.** There isn't one
   yet, and that field is exactly what went stale in #542 and #546 —
   `CHANGELOG.md` is generated from subjects and cannot be corrected afterwards.

Do not write an anchor link to an unallocated decision
(`[D-NEXT](#d-next-…)`): the slug is derived from the heading and changes when
the number is stamped in. Bare `D-NEXT` is the house style anyway.

## What happens on merge

`.github/workflows/allocate-decision.yml` fires on every push to `dev` that
touches `DECISIONS.md`. It reads the current maximum, rewrites every `D-NEXT`
in every tracked file to the next number, and pushes a follow-up commit:

```
chore(docs): allocate D<n> (#<pr>)
```

That commit is the greppable mapping from a decision to the PR that decided it.
(Written with placeholders here on purpose: rule 4 below rejects a doc that
cites a decision number which does not exist yet.)

The job is serialized (`concurrency: allocate-decision`) and checks out `dev`
rather than the triggering SHA, so two decisions merging back to back are
numbered in order rather than racing for the same value.

## When it fails

### The push 403s

The workflow pushes straight to `dev` using `RELEASE_PLEASE_TOKEN`, the same
fine-grained PAT `release-please.yml` and `sync-dev.yml` use. The `dev` ruleset
requires a pull request, and the token works only because its owner is a
repository admin and therefore a bypass actor. If it lapses, the job fails on
the push and the placeholder stays on `dev`.

Nothing is broken in the meantime — `dev` tolerates a placeholder. But
`scripts/check-decisions.sh` runs with `STRICT_ALLOCATED` on `master` and on
any PR into `master`, so the release is blocked until it is resolved:

```sh
git checkout dev && git pull
make allocate-decision
git commit -am "chore(docs): allocate D<n> (#<pr>)"
git push origin dev   # requires ruleset bypass (admin)
```

### Two placeholders on `dev`

`scripts/allocate-decision.sh` refuses rather than guessing when
`DECISIONS.md` holds more than one `## D-NEXT:` heading. It has to: a comment
somewhere saying `See D-NEXT.` belongs to one of the two decisions and nothing
in the tree records which.

Resolve it by hand — number the headings in file order, then attribute each
reference to the PR that introduced it:

```sh
git log -S'D-NEXT' --oneline -- <file>
```

## The lint

`scripts/check-decisions.sh` (`make check-decisions`, the `docs` CI job, and
the pre-commit hook) enforces:

| | Rule |
|---|---|
| 1 | No duplicate `## D<n>` headings |
| 2 | No gaps in the sequence |
| 3 | Every entry keeps its Date / Decision / Rationale lines |
| 4 | No reference to a decision number that does not exist |
| 5 | A `D-NEXT` reference requires a `## D-NEXT:` heading |
| 6 | No anchor link to an unallocated decision |
| 7 | `BASE_REF` set: a new entry may not hardcode a number |
| 8 | `STRICT_ALLOCATED` set: no placeholder may survive |

Rule 4 scans every tracked file, which is why binary assets are excluded —
PNG bytes match a decision reference by chance. `CHANGELOG.md` is excluded
because it is generated from merged commit subjects that cannot be corrected.

Files that *teach* this convention rather than consume it — this runbook, the
scripts, the allocator workflow, `CLAUDE.md`, `docs/agents/domain.md` — carry
the marker `decision-numbering:vocabulary`. Rules 5, 6 and 8 skip them, and the
allocator never rewrites them, so the sentences explaining the placeholder
survive allocation. Rule 4 still applies to them.
