//! Bakes the identity of the build into the binary as `OVERSLASH_GIT_SHA` and
//! `OVERSLASH_VERSION`, read back by `build_info::build_info()`.
//!
//! The commit has two supply routes, in priority order:
//!
//! 1. An `OVERSLASH_GIT_SHA` env var. This is how CI and the container build
//!    inject it — `crates/overslash-api/Dockerfile` turns a `--build-arg` into
//!    this var, because `.dockerignore` keeps `.git` out of the build context.
//! 2. `git rev-parse HEAD`, so a plain `cargo build` on a developer machine
//!    still reports something truthful.
//!
//! The version has two as well:
//!
//! 1. An `OVERSLASH_VERSION` env var — the release tag, set by
//!    `.github/workflows/release.yml`. Re-emitted verbatim.
//! 2. `.release-please-manifest.json` at the workspace root, suffixed `-dev`
//!    (e.g. `0.5.0-dev`). Crate versions stay frozen at `0.1.0` on purpose
//!    (D19: bumping them would churn `Cargo.lock` and break the `--locked`
//!    release build), so without this every non-release build — local, dev
//!    Cloud Run — would report `0.1.0` and say nothing about which release
//!    line it came from.
//!
//! Falling back to `unknown` / `CARGO_PKG_VERSION` is always acceptable: an
//! unidentifiable build is a cosmetic loss, a failed build is not.

use std::process::Command;

const UNKNOWN: &str = "unknown";

/// Workspace-root manifest release-please rewrites on every release, relative
/// to this crate.
const RELEASE_MANIFEST: &str = "../../.release-please-manifest.json";

fn main() {
    println!("cargo::rerun-if-env-changed=OVERSLASH_GIT_SHA");
    println!("cargo::rerun-if-env-changed=OVERSLASH_VERSION");
    emit_git_rerun_paths();
    // Not every build context ships the manifest (the dev container copies an
    // allow-list of files), and naming a path that is not there makes cargo
    // treat this script as permanently dirty.
    emit_if_exists(RELEASE_MANIFEST);

    println!("cargo::rustc-env=OVERSLASH_GIT_SHA={}", resolve_sha());
    // Emitting nothing leaves `option_env!("OVERSLASH_VERSION")` as `None`, so
    // `build_info()` falls back to `CARGO_PKG_VERSION`.
    if let Some(version) = resolve_version() {
        println!("cargo::rustc-env=OVERSLASH_VERSION={version}");
    }
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

/// Release version to bake in, or `None` to leave the crate version in place.
fn resolve_version() -> Option<String> {
    if let Ok(version) = std::env::var("OVERSLASH_VERSION") {
        let version = version.trim();
        if !version.is_empty() {
            return Some(version.to_string());
        }
    }

    let manifest = std::fs::read_to_string(RELEASE_MANIFEST).ok()?;
    Some(format!("{}-dev", manifest_version(&manifest)?))
}

/// Pull the root package's version out of a release-please manifest.
///
/// The file is machine-written with a fixed shape — `{ ".": "0.5.0" }`, one
/// key because `release-please-config.json` declares a single root package —
/// so a quoted-string scan beats a `serde_json` build-dependency here. Every
/// failure path lands on the `CARGO_PKG_VERSION` fallback, so a shape we do
/// not recognise costs a cosmetic stamp, not a build.
fn manifest_version(manifest: &str) -> Option<&str> {
    let after_key = manifest.split_once("\".\"")?.1;
    let after_colon = after_key.split_once(':')?.1;
    let value = after_colon.split_once('"')?.1;
    let (version, _) = value.split_once('"')?;
    (!version.is_empty()).then_some(version)
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
