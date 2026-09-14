#!/usr/bin/env python3
"""Report how many lines of *production code* a PR actually changes.

`git diff --shortstat` is a poor proxy for review size here: a branch that
regenerates one `.sqlx/` cache entry, re-dumps `SCHEMA.sql` and edits a design
doc looks bigger than one that rewrites approval bubbling. `.sqlx/` alone is
~46k tracked lines, 11.6% of the repo. This script narrows the count to the
part a reviewer has to reason about:

  * only files under a `src/` directory (every crate, the dashboard and the SDK
    keep their sources there — `.sqlx/`, `crates/overslash-db/migrations/`,
    `docs/`, `infra/`, `services/*.yaml`, `assets/service-icons/`, `Cargo.lock`,
    `package-lock.json` and the generated `SCHEMA.sql` all fall away);
  * only source extensions (`CODE_SUFFIXES`) — no `.json`, `.css`, `.html`;
  * no test files (`tests/` dirs, `*.test.ts`, `*_test.rs`, `testing.rs`, …);
  * and, for Rust, no inline `#[cfg(test)]` modules or `#[test]` functions,
    which is where nearly all of this repo's unit tests live.

The inline-test exclusion is done by stripping those items from *both* sides of
the diff and re-diffing the stripped blobs, so moving a function into a test
module counts as a deletion rather than as untouched code.

Usage:
    scripts/pr-diff-stats.py <base-ref> <head-ref> [--out FILE]

Writes a Markdown report to stdout and, with `--out`, to FILE. Exit status is 0
unless the script itself fails — this is a report, never a gate.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# Extensions we consider "code". Deliberately excludes data/markup that lives
# under src/ (`.json`, `.css`, `.html`) — changing a stylesheet is not the kind
# of churn this number is meant to track.
CODE_SUFFIXES = {".rs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".svelte", ".py", ".go"}

# Path components that mark a whole subtree as tests.
TEST_DIRS = {"tests", "test", "__tests__", "__mocks__"}

# Whole crates that exist only to support tests. They keep their sources under
# `src/` like any other crate and carry no test-ish path component or file
# name, so nothing else in this file would catch them.
TEST_CRATES = {"overslash-fakes", "overslash-mcp-puppet"}

# File names that are test code even though they sit next to production code.
TEST_FILE_RE = re.compile(
    r"""(?x)
    ^(
        test_.*            # test_foo.py
      | .*[._-]test\..*    # foo.test.ts, foo_test.rs
      | .*[._-]spec\..*    # foo.spec.ts
      | testing            # mock harnesses sitting next to production code
      | test_utils
      | test_helpers
      | mocks?
    )\.[^.]+$
    """
)

# Rust attributes that open an item we want to drop wholesale.
TEST_ATTR_RE = re.compile(
    r"""(?x)
    ^\#\[
    (
        cfg\(\s*test\s*\)                 # #[cfg(test)]
      | cfg\(.*\btest\b.*\)               # #[cfg(all(test, feature = "x"))]
      | cfg_attr\(\s*test\s*,             # #[cfg_attr(test, ...)]
      | (\w+::)*test\b                    # #[test], #[tokio::test], #[sqlx::test]
      | rstest
      | should_panic
      | ignore\b
    )
    """
)


# A real Rust char literal: `'x'`, `'\n'`, `'\u{1f600}'`. Anything else that
# starts with a quote is a lifetime.
CHAR_LIT_RE = re.compile(r"'(\\u\{[0-9a-fA-F]+\}|\\.|[^'\\])'")

# `r"..."`, `r#"..."#`, `br#"..."#` — group 1 is the hash run. Plain `b"..."`
# needs no special case: the `b` is an ordinary char and the `"` branch takes it.
RAW_STR_RE = re.compile(r'b?r(#*)"')


def run(*args: str, cwd: Path | None = None) -> str:
    proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if proc.returncode not in (0, 1):  # git diff --no-index exits 1 on differences
        sys.exit(f"command failed ({proc.returncode}): {' '.join(args)}\n{proc.stderr}")
    return proc.stdout


def is_code_path(path: str) -> bool:
    p = Path(path)
    if "src" not in p.parts:
        return False
    if p.suffix not in CODE_SUFFIXES:
        return False
    if TEST_DIRS & set(p.parts):
        return False
    if p.parts[0] == "crates" and len(p.parts) > 1 and p.parts[1] in TEST_CRATES:
        return False
    if TEST_FILE_RE.match(p.name):
        return False
    return True


def strip_noncode(line: str, pending: str) -> tuple[str, str]:
    """Blank out comments and string literals so brace counting is reliable.

    `pending` carries multi-line state across calls: `""` for ordinary code,
    otherwise the token that closes the construct we are inside (`*/` for a
    block comment, `"` for a string, `"##` for a raw string). Raw strings
    matter here — this repo embeds SQL, JSON and prompt text in `r#"..."#`,
    braces and all, and a brace miscount silently truncates a test module.

    Returns the sanitized line and the still-pending closer.
    """
    out: list[str] = []
    i, n = 0, len(line)
    while i < n:
        if pending:
            end = line.find(pending, i)
            if end == -1:
                return "".join(out), pending
            i, pending = end + len(pending), ""
            continue
        ch = line[i]
        if ch == "/" and i + 1 < n:
            if line[i + 1] == "/":
                break
            if line[i + 1] == "*":
                i, pending = i + 2, "*/"
                continue
        if ch in "rb" and not (i and (line[i - 1].isalnum() or line[i - 1] == "_")):
            m = RAW_STR_RE.match(line, i)
            if m:
                closer = '"' + m.group(1)
                end = line.find(closer, m.end())
                if end == -1:
                    return "".join(out), closer
                i = end + len(closer)
                continue
        if ch == "'":
            # `'a` / `'_` are lifetimes, not char literals — only skip when the
            # quote actually closes as a character.
            m = CHAR_LIT_RE.match(line, i)
            i = m.end() if m else i + 1
            continue
        if ch == '"':
            j = i + 1
            while j < n:
                if line[j] == "\\":
                    j += 2
                    continue
                if line[j] == '"':
                    break
                j += 1
            if j >= n:  # Rust strings may span lines
                return "".join(out), '"'
            i = j + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), pending


def strip_rust_tests(text: str) -> str:
    """Drop `#[cfg(test)]` / `#[test]` items from Rust source."""
    lines = text.splitlines()
    kept: list[str] = []
    pending = ""
    skipping = False
    depth = 0
    opened = False

    for raw in lines:
        # `carried` is the state *before* this line. An attribute only opens an
        # item when the line did not start inside a block comment or a
        # multi-line string: a commented-out test module, or a Rust snippet
        # embedded in a prompt or codegen string, contains `#[cfg(test)]` lines
        # that are not items. Treating one as an item swallows production code
        # until the braces happen to balance — often to the end of the file,
        # since braces inside a comment are not counted at all.
        carried = pending
        code, pending = strip_noncode(raw, pending)

        if not skipping and not carried and TEST_ATTR_RE.match(raw.strip()):
            skipping, depth, opened = True, 0, False

        if not skipping:
            kept.append(raw)
            continue

        for ch in code:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
        # The item ends at the closing brace of its block, or at the `;` of a
        # brace-less item (`#[cfg(test)] mod tests;`, `#[cfg(test)] use ...;`).
        if (opened and depth <= 0) or (not opened and ";" in code):
            skipping = False

    return "\n".join(kept) + ("\n" if text.endswith("\n") else "")


def strip_tests(path: str, text: str) -> str:
    return strip_rust_tests(text) if path.endswith(".rs") else text


def blob(ref: str, path: str) -> str | None:
    proc = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        capture_output=True,
        text=True,
        errors="replace",  # a stray non-UTF-8 source file must not fail the job
    )
    return proc.stdout if proc.returncode == 0 else None


def field(fields: list[str], i: int, what: str) -> str:
    """Read one NUL-separated field, or fail with a diagnostic.

    Both `-z` parsers below read fields at a fixed offset from the record
    header. Bare indexing would turn truncated or unexpected git output into an
    `IndexError` traceback; this says which record and which field went missing.
    """
    if i >= len(fields):
        sys.exit(
            f"unexpected git output: wanted {what} at field {i}, "
            f"got {len(fields)} field(s)"
        )
    return fields[i]


def changed_files(base: str, head: str) -> list[tuple[str, str]]:
    """Changed files as `(path in base, path in head)` pairs.

    Rename detection is on, so a moved file keeps both of its names and is
    counted by what actually changed inside it rather than as a whole-file
    add plus a whole-file delete. For pure adds and deletes the two names are
    the same — the missing side simply has no blob.
    """
    raw = run("git", "diff", "--name-status", "-M", "-z", base, head)
    fields = raw.split("\0")
    pairs: list[tuple[str, str]] = []
    i = 0
    while i < len(fields) and fields[i]:
        status = fields[i]
        if status.startswith(("R", "C")):
            src = field(fields, i + 1, f"rename source for {status!r}")
            dst = field(fields, i + 2, f"rename destination for {status!r}")
            pairs.append((src, dst))
            i += 3
        else:
            path = field(fields, i + 1, f"path for {status!r}")
            pairs.append((path, path))
            i += 2
    return pairs


def numstat(
    base: str, head: str, pairs: list[tuple[str, str]]
) -> dict[str, tuple[int, int]]:
    """Added/removed per file, computed on test-stripped copies of each blob."""
    if not pairs:
        return {}
    with tempfile.TemporaryDirectory() as tmp:
        old_root, new_root = Path(tmp) / "old", Path(tmp) / "new"
        # Both sides are laid out under the *head* path so git pairs them up;
        # only the blob each side is read from differs.
        for old_path, new_path in pairs:
            for root, ref, path in (
                (old_root, base, old_path),
                (new_root, head, new_path),
            ):
                target = root / new_path
                target.parent.mkdir(parents=True, exist_ok=True)
                content = blob(ref, path)
                target.write_text(
                    "" if content is None else strip_tests(path, content),
                    encoding="utf-8",
                )
        out = run(
            "git", "diff", "--no-index", "--numstat", "--no-renames", "-z",
            str(old_root), str(new_root),
        )
        # `-z` avoids the `{old => new}` path compression the text format uses,
        # emitting `added\tremoved\t` followed by the two paths as separate
        # NUL-terminated fields.
        fields = out.split("\0")
        stats: dict[str, tuple[int, int]] = {}
        i = 0
        while i < len(fields) and fields[i]:
            added, removed, rest = fields[i].split("\t", 2)
            if rest:
                name, i = rest, i + 1
            else:
                # Two-path form: the header is followed by the old and new
                # paths; only the new one is needed to key the stats.
                name, i = field(fields, i + 2, "new path in numstat record"), i + 3
            if added == "-":  # binary
                continue
            stats[str(Path(name).relative_to(new_root))] = (int(added), int(removed))
    return stats


def group(path: str) -> str:
    parts = Path(path).parts
    # `crates/` is a workspace directory, not a unit of review: grouping by the
    # first component alone would file every Rust change under one `crates` row
    # covering ~228k lines across ten crates. Everything else (`dashboard`,
    # `sdk`) is already its own top-level unit.
    if parts[0] == "crates" and len(parts) > 1:
        return parts[1]
    return parts[0]


def render(stats: dict[str, tuple[int, int]], skipped: int) -> str:
    groups: dict[str, list[int]] = {}
    for path, (added, removed) in stats.items():
        g = groups.setdefault(group(path), [0, 0, 0])
        g[0] += added
        g[1] += removed
        g[2] += 1

    total_added = sum(a for a, _, _ in groups.values())
    total_removed = sum(r for _, r, _ in groups.values())
    total_files = sum(f for _, _, f in groups.values())

    lines = [
        "## Code diff size",
        "",
        f"**+{total_added} / −{total_removed}** across "
        f"**{total_files} file{'s' if total_files != 1 else ''}** "
        f"(net {total_added - total_removed:+d})",
        "",
    ]
    if groups:
        lines += [
            "| Area | Files | Added | Removed | Net |",
            "|------|------:|------:|--------:|----:|",
        ]
        for name in sorted(groups, key=lambda k: -(groups[k][0] + groups[k][1])):
            added, removed, files = groups[name]
            lines.append(
                f"| `{name}` | {files} | +{added} | −{removed} | {added - removed:+d} |"
            )
        lines.append("")
    else:
        lines += ["No production source files changed.", ""]

    lines.append(
        f"<sub>Source files under `src/` only "
        f"({', '.join(sorted(CODE_SUFFIXES))}); test files and inline "
        f"`#[cfg(test)]` modules excluded. {skipped} other changed "
        f"file{'s' if skipped != 1 else ''} not counted.</sub>"
    )
    return "\n".join(lines) + "\n"


# The test module is built to break naive brace tracking two ways, both of
# which are real bugs this script shipped with at some point:
#   * `Ctx<'_>` — read as a char literal, the scan to the next `'` swallows the
#     `{` that opens `fn ctx`, so the fn's closing `}` closes the module early;
#   * a raw string spanning lines with stray `}`s inside — without cross-line
#     state those braces are counted and the module closes early again.
# Either one ends the skip mid-module, leaking test lines into the count.
TEST_MOD = '''\
#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(name: &str) -> Ctx<'_> {
        Ctx { name }
    }

    #[test]
    fn renders() {
        let sql = r#"
            SELECT '{"a": 1}' }}} FROM t
        "#;
        assert_eq!(render(&ctx("x")), "x");
        assert!(!sql.is_empty());
    }
%s}
'''

EXTRA_TEST = '''
    #[test]
    fn renders_trimmed() {
        assert_eq!(render(&ctx(" x ")), "x");
    }
'''

# `#[cfg(test)]` inside a block comment and `#[test]` inside a raw string are
# not items — they are production lines. Opening a skip on either runs until
# the braces happen to balance, which eats the single-line `pub fn` right after
# it; each decoy's edit is only visible if the attribute was correctly ignored.
# The `fn`s are one-liners on purpose: a multi-line body ends the bogus skip on
# its own opening brace and the bug hides itself.
DECOYS = '''
/*
#[cfg(test)]
mod disabled {
    fn was_here() {}
}
*/
pub fn decoy_a() -> u32 { %s }

pub fn snippet() -> &'static str {
    r#"
#[test]
fn generated() {}
"#
}
pub fn decoy_b() -> u32 { %s }
'''

BASE_LIB_RS = (
    "use std::fmt;\n"
    "\n"
    "pub fn render(ctx: &Ctx<'_>) -> String {\n"
    '    format!("{}", ctx.name)\n'
    "}\n"
) + (DECOYS % ("1", "1")) + "\n" + TEST_MOD % ""

HEAD_LIB_RS = (
    "use std::fmt;\n"
    "\n"
    "pub fn render(ctx: &Ctx<'_>) -> String {\n"
    "    let name = ctx.name.trim();\n"
    '    format!("{name}")\n'
    "}\n"
) + (DECOYS % ("2", "2")) + "\n" + TEST_MOD % EXTRA_TEST


def self_test() -> None:
    """Prove the pipeline on a synthetic repo covering every branch.

    The reporting job's own diffs are usually small, and a PR that touches no
    `src/` file exercises only the empty path — so without this the interesting
    code (rename pairing, test stripping, path recovery from `--no-index`) can
    sit broken and green.
    """
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"
        repo.mkdir()
        git = ("git", "-C", str(repo))
        run(*git, "init", "-q", "-b", "main")
        run(*git, "config", "user.email", "self-test@example.com")
        run(*git, "config", "user.name", "self test")

        def write(rel: str, text: str) -> None:
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")

        write("crate/src/lib.rs", BASE_LIB_RS)
        write("crate/src/moved.rs", "pub fn a() {}\npub fn b() {}\npub fn c() {}\n")
        write("crate/tests/it.rs", "#[test]\nfn integration() {}\n")
        write("docs/readme.md", "hello\n")
        write("crate/src/styles.css", "a { color: red }\n")
        # Two workspace members and one test-support crate, to pin the two
        # overslash-specific rules: `crates/` groups per crate, and TEST_CRATES
        # drops a member wholesale even though its layout is ordinary.
        write("crates/overslash-api/src/lib.rs", "pub fn ping() -> u32 { 1 }\n")
        write("crates/overslash-core/src/lib.rs", "pub fn tick() -> u32 { 1 }\n")
        write("crates/overslash-fakes/src/lib.rs", "pub fn fake() -> u32 { 1 }\n")
        run(*git, "add", "-A")
        run(*git, "commit", "-qm", "base")
        base = run(*git, "rev-parse", "HEAD").strip()

        write("crate/src/lib.rs", HEAD_LIB_RS)
        (repo / "crate/src/moved.rs").rename(repo / "crate/src/renamed.rs")
        write("crate/src/renamed.rs", "pub fn a() {}\npub fn b2() {}\npub fn c() {}\n")
        write("crate/tests/it.rs", "#[test]\nfn integration() {}\n#[test]\nfn more() {}\n")
        write("docs/readme.md", "hello\nworld\n")
        write("crate/src/styles.css", "a { color: blue }\n")
        write("web/src/app.ts", "export const x = 1;\n")
        write("crates/overslash-api/src/lib.rs", "pub fn ping() -> u32 { 2 }\n")
        write("crates/overslash-core/src/lib.rs", "pub fn tick() -> u32 { 2 }\n")
        write("crates/overslash-fakes/src/lib.rs", "pub fn fake() -> u32 { 2 }\n")
        run(*git, "add", "-A")
        run(*git, "commit", "-qm", "head")
        head = run(*git, "rev-parse", "HEAD").strip()

        # `run` inherits this process's cwd, so point git at the scratch
        # repo for the pipeline calls too.
        cwd = os.getcwd()
        os.chdir(repo)
        try:
            files = changed_files(base, head)
            code = [pair for pair in files if is_code_path(pair[1])]
            stats = numstat(base, head, code)
        finally:
            os.chdir(cwd)

    expected = {
        # Two production edits: `render` grows a line, `decoy` changes one.
        # The added `#[test] fn renders_trimmed` must not register at all, and
        # neither may the commented-out / string-embedded test decoys hide the
        # `decoy` edit that follows them.
        "crate/src/lib.rs": (4, 3),
        # A rename with one line changed inside — not a whole-file add/delete.
        "crate/src/renamed.rs": (1, 1),
        # A brand-new non-Rust source file.
        "web/src/app.ts": (1, 0),
        # Two workspace members, counted normally. `crates/overslash-fakes` is
        # edited identically and must be absent here.
        "crates/overslash-api/src/lib.rs": (1, 1),
        "crates/overslash-core/src/lib.rs": (1, 1),
    }
    problems = []
    if stats != expected:
        problems.append(f"stats mismatch\n  got:      {stats}\n  expected: {expected}")
    # `crate/tests/it.rs`, `docs/readme.md`, `crate/src/styles.css` and
    # `crates/overslash-fakes/src/lib.rs` changed too; all four must land in
    # the uncounted bucket.
    if len(files) - len(code) != 4:
        problems.append(f"expected 4 uncounted files, got {len(files) - len(code)}")
    report = render(stats, skipped=len(files) - len(code))
    if "**+8 / −6**" not in report:
        problems.append(f"unexpected totals in report:\n{report}")
    if "| `crate` | 2 |" not in report or "| `web` | 1 |" not in report:
        problems.append(f"unexpected grouping in report:\n{report}")
    # Per-crate rows, not one `crates` row for the whole workspace.
    if "| `overslash-api` | 1 |" not in report or "| `overslash-core` | 1 |" not in report:
        problems.append(f"workspace members not grouped per crate:\n{report}")
    if "| `crates` |" in report:
        problems.append(f"workspace collapsed into one `crates` row:\n{report}")

    # Truncated `-z` output must produce a diagnostic, not an IndexError.
    try:
        field(["R100", "only-the-source-path"], 2, "rename destination")
    except SystemExit as exc:
        if "unexpected git output" not in str(exc):
            problems.append(f"unhelpful truncation diagnostic: {exc}")
    except Exception as exc:  # noqa: BLE001 - any other type is the bug
        problems.append(
            f"truncated git output raised {type(exc).__name__}, expected SystemExit"
        )
    else:
        problems.append("truncated git output was accepted silently")

    if problems:
        sys.exit("self-test FAILED:\n" + "\n".join(problems))
    print("self-test passed")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("base", nargs="?", help="base ref (merge-base is computed against it)")
    ap.add_argument("head", nargs="?", help="head ref")
    ap.add_argument("--out", type=Path, help="also write the Markdown report here")
    ap.add_argument(
        "--self-test", action="store_true", help="verify the pipeline and exit"
    )
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return
    if not args.base or not args.head:
        ap.error("base and head are required unless --self-test is given")

    base = run("git", "merge-base", args.base, args.head).strip() or args.base
    files = changed_files(base, args.head)
    code = [pair for pair in files if is_code_path(pair[1])]
    stats = numstat(base, args.head, code)
    report = render(stats, skipped=len(files) - len(code))

    sys.stdout.write(report)
    if args.out:
        args.out.write_text(report, encoding="utf-8")


if __name__ == "__main__":
    main()
