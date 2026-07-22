//! Which build am I?
//!
//! One resolver for the release version and git commit, so the CLI banner, the
//! MCP `serverInfo`, `/health` and `GET /v1/version` can never disagree about
//! what is running.
//!
//! Both values are baked at compile time by this crate's `build.rs`:
//!
//! - **version** — the release tag when `.github/workflows/release.yml` set
//!   `OVERSLASH_VERSION`, else the `.release-please-manifest.json` version with
//!   a `-dev` suffix (`0.5.0-dev`), else this crate's `CARGO_PKG_VERSION`.
//!   That last fallback is `0.1.0` and always will be: crate versions are
//!   deliberately never bumped (D19), which is exactly why `build.rs` reads the
//!   release manifest.
//! - **commit** — `OVERSLASH_GIT_SHA`, normally emitted by `build.rs`, else
//!   read straight from the environment, else [`UNKNOWN_COMMIT`].
//!
//! Both are read with `option_env!` rather than `env!` on purpose: not every
//! build context has the build script. `docker/docker-compose.dev.yml`
//! bind-mounts each crate's `src/` (plus a short allow-list of compile-time
//! assets) into the dev container, so `build.rs` — which sits at the crate
//! root — is not there, and that container reports `0.1.0` / `unknown`. An
//! `env!` would turn that into a compile error, which is a wildly
//! disproportionate outcome for a cosmetic version stamp.

/// Length of the abbreviated commit shown in UIs. Seven is git's own default
/// for `--short` and stays unambiguous well past this repo's size.
const SHORT_SHA_LEN: usize = 7;

/// Placeholder used when the commit could not be determined at build time.
pub const UNKNOWN_COMMIT: &str = "unknown";

/// Identity of the running binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildInfo {
    /// Release version, e.g. `0.4.2`.
    pub version: &'static str,
    /// Full 40-char git commit, or [`UNKNOWN_COMMIT`].
    pub commit: &'static str,
}

impl BuildInfo {
    /// Abbreviated commit for display. Returns [`UNKNOWN_COMMIT`] unchanged
    /// rather than truncating it to a meaningless `unknow`.
    pub fn commit_short(&self) -> &'static str {
        short_commit(self.commit)
    }
}

/// Version and commit of this binary.
pub fn build_info() -> BuildInfo {
    BuildInfo {
        version: option_env!("OVERSLASH_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
        commit: option_env!("OVERSLASH_GIT_SHA").unwrap_or(UNKNOWN_COMMIT),
    }
}

/// Split out from [`BuildInfo::commit_short`] so it is testable against inputs
/// other than whatever this test binary happened to be built from.
fn short_commit(commit: &str) -> &str {
    if commit == UNKNOWN_COMMIT || commit.len() <= SHORT_SHA_LEN {
        return commit;
    }
    // A SHA is hex, so every byte is a char boundary — but this function is
    // `&str`-typed and nothing stops a future caller passing something else,
    // and a mid-codepoint slice panics (see CLAUDE.md rule 5).
    let mut end = SHORT_SHA_LEN;
    while !commit.is_char_boundary(end) {
        end -= 1;
    }
    &commit[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_commit_abbreviates_a_full_sha() {
        assert_eq!(
            short_commit("28fb03201f4c0d9e8b7a6f5e4d3c2b1a09876543"),
            "28fb032"
        );
    }

    #[test]
    fn short_commit_passes_unknown_through() {
        assert_eq!(short_commit(UNKNOWN_COMMIT), UNKNOWN_COMMIT);
    }

    #[test]
    fn short_commit_leaves_already_short_input_alone() {
        assert_eq!(short_commit("28fb03"), "28fb03");
        assert_eq!(short_commit(""), "");
    }

    /// Truncation must not panic when the cut lands mid-codepoint.
    #[test]
    fn short_commit_respects_char_boundaries() {
        // '€' is 3 bytes and SHORT_SHA_LEN is not a multiple of 3, so the byte
        // cap falls inside a codepoint.
        assert_ne!(SHORT_SHA_LEN % 3, 0, "cap must not fall on a '€' boundary");
        assert_eq!(short_commit(&"€".repeat(10)), "€€");
    }

    /// The build script must always have supplied something.
    #[test]
    fn build_info_is_populated() {
        let info = build_info();
        assert!(!info.version.is_empty());
        assert!(!info.commit.is_empty());
    }
}
