//! Bakes the git commit of the source tree into the binary as
//! `OVERSLASH_GIT_SHA`, read back by `build_info::build_info()`.
//!
//! Two supply routes, in priority order:
//!
//! 1. An `OVERSLASH_GIT_SHA` env var. This is how CI and the container build
//!    inject it — `crates/overslash-api/Dockerfile` turns a `--build-arg` into
//!    this var, because `.dockerignore` keeps `.git` out of the build context.
//! 2. `git rev-parse HEAD`, so a plain `cargo build` on a developer machine
//!    still reports something truthful.
//!
//! Falling back to `unknown` is always acceptable: an unidentifiable build is
//! a cosmetic loss, a failed build is not.

use std::process::Command;

const UNKNOWN: &str = "unknown";

fn main() {
    println!("cargo::rerun-if-env-changed=OVERSLASH_GIT_SHA");
    emit_git_rerun_paths();

    println!("cargo::rustc-env=OVERSLASH_GIT_SHA={}", resolve_sha());
}

/// Tell cargo which files invalidate the baked SHA.
///
/// Emitting *any* `rerun-if-changed` replaces cargo's default "re-run when the
/// package changes", so these paths must be right in both directions: miss one
/// and a local build bakes a stale SHA; name one that does not exist and cargo
/// treats the script as permanently dirty, recompiling `overslash-core` and
/// everything downstream on every single build.
///
/// Hence `git rev-parse --git-path`, which resolves through both the `.git`
/// *file* a worktree has (this repo runs agents in `.cline/worktrees/<id>/`)
/// and the shared common dir. Committing on the current branch rewrites the
/// branch ref, not `HEAD`, so both are needed; on a detached HEAD there is no
/// branch ref and `HEAD` itself moves.
///
/// When git is unavailable — the container build — nothing is emitted, which
/// leaves only `rerun-if-env-changed` above. That is exactly right there: the
/// SHA comes from the env var and there is no repository to watch.
fn emit_git_rerun_paths() {
    let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) else {
        return;
    };
    emit_if_exists(&head);

    // `symbolic-ref` fails on a detached HEAD — then `HEAD` above is the only
    // file that moves, and it is already covered. The loose ref file is also
    // absent once `git gc` packs it, hence `emit_if_exists`: naming a path
    // that is not there is worse than watching one file too few.
    if let Some(branch_ref) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        if let Some(path) = git(&["rev-parse", "--git-path", &branch_ref]) {
            emit_if_exists(&path);
        }
        if let Some(packed) = git(&["rev-parse", "--git-path", "packed-refs"]) {
            emit_if_exists(&packed);
        }
    }
}

fn emit_if_exists(path: &str) {
    if std::path::Path::new(path).exists() {
        println!("cargo::rerun-if-changed={path}");
    }
}

fn resolve_sha() -> String {
    if let Ok(sha) = std::env::var("OVERSLASH_GIT_SHA") {
        let sha = sha.trim().to_string();
        if !sha.is_empty() {
            return sha;
        }
    }

    git(&["rev-parse", "HEAD"]).unwrap_or_else(|| UNKNOWN.to_string())
}

/// Run a git command, returning its trimmed stdout. `None` for any failure —
/// no git binary, not a repository, or an empty result.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!text.is_empty()).then_some(text)
}
