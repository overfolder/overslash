//! The one place the process environment is read.
//!
//! # The rule
//!
//! **An empty or whitespace-only value means unset.** Not "set to nothing" —
//! unset. Every accessor here trims first and then treats `""` exactly as it
//! treats a variable that was never exported.
//!
//! This is not a preference, it is what the deployment substrate does to us.
//! Compose renders `${FOO:-}` as the empty string when `FOO` is unset, so a
//! variable nobody configured arrives at the process *present and empty*. A
//! Secret Manager version can hold an empty payload and Cloud Run will mount
//! it. Shell pipelines that populate secrets leave trailing newlines. A
//! presence check — `env::var(..).is_ok()`, or a bare `.ok()` kept as
//! `Some("")` — reads all of those as "the operator configured this", which is
//! how an unset variable comes to disable a login provider, enable a dev-auth
//! bypass, or advertise credentials that are two empty strings.
//!
//! The convention predates this module: D44 already said a template variable is
//! "never an empty string", and `overslash_core::template_vars` calls `""` the
//! repo-wide unset spelling. What was missing was one implementation, so the
//! ~130 call sites could not drift apart. That is what this crate is.
//!
//! # Flags
//!
//! [`flag`] is the only truthiness rule. `true`/`1`/`yes`/`on` are true,
//! `false`/`0`/`no`/`off` are false, case-insensitively and after trimming.
//! Anything else — including unset and empty — falls back to the caller's
//! declared default, with a warning for the values that are neither.
//!
//! Falling back to the *default* rather than to `false` is deliberate. Security
//! gates declare `false`, so an unreadable value leaves them closed; default-on
//! flags like `MAGIC_LINK_ENABLED` declare `true`, so a typo does not silently
//! turn passwordless login off for a whole deployment. Either way the operator
//! gets a log line naming the variable and the value we could not read.
//!
//! # What this crate deliberately does not do
//!
//! It does not know which variables exist, what they mean, or which are
//! required. That knowledge belongs to each binary's config type — here there
//! are only the reading primitives. Nothing in this crate should ever need to
//! name an Overslash variable.

#![forbid(unsafe_code)]

use std::fmt;
use std::str::FromStr;

/// A required variable that was unset, empty, or whitespace-only.
///
/// Carries the name so the caller can report every missing variable in one
/// message rather than failing on the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingEnv(pub &'static str);

impl fmt::Display for MissingEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is required (unset, or set to an empty value)",
            self.0
        )
    }
}

impl std::error::Error for MissingEnv {}

impl MissingEnv {
    /// The variable's name.
    pub fn name(&self) -> &'static str {
        self.0
    }
}

/// The single read. Everything else in this crate is a shape on top of it.
fn read(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// The variable's value, or `None` when unset or empty.
///
/// The workhorse: anything optional reads through this.
pub fn optional(name: &str) -> Option<String> {
    read(name)
}

/// The variable's value, or [`MissingEnv`] when unset or empty.
pub fn required(name: &'static str) -> Result<String, MissingEnv> {
    read(name).ok_or(MissingEnv(name))
}

/// Whether the variable carries a usable value.
///
/// For callers that only need the question answered — a startup check
/// collecting the names of everything missing, say — without the value.
pub fn is_set(name: &str) -> bool {
    read(name).is_some()
}

/// The variable's value, or `default` when unset or empty.
pub fn or_default(name: &str, default: &str) -> String {
    read(name).unwrap_or_else(|| default.to_string())
}

/// The parsed value, or `None` when unset, empty, or unparseable.
///
/// An unparseable value warns rather than failing the boot, because for every
/// caller of this function the fallback is a sane default and a typo'd tuning
/// knob is not worth refusing to start over. It does warn: falling back in
/// total silence is how `CALL_TIMEOUT_MS=3o000` becomes 30s with nobody the
/// wiser. Where a silent fallback would be *unsafe*, use [`parse_or_die`].
pub fn parse_opt<T>(name: &str) -> Option<T>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    let raw = read(name)?;
    match raw.parse() {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!("{name}: ignoring {raw:?} — {e}");
            None
        }
    }
}

/// The parsed value, `default` when unset or empty, and a **panic** when set
/// to something that does not parse.
///
/// For values where falling back would be worse than not starting: a key id
/// that silently reverts to `1` re-tags fresh ciphertext with the historical
/// key's version byte, and every blob written under the real active key stops
/// decrypting. Surfacing the typo at boot is the cheap failure.
pub fn parse_or_die<T>(name: &str, default: T) -> T
where
    T: FromStr,
    T::Err: fmt::Display,
{
    match read(name) {
        None => default,
        Some(raw) => raw.parse().unwrap_or_else(|e| {
            panic!(
                "{name} must be a valid {}, got {raw:?} ({e})",
                type_name::<T>()
            )
        }),
    }
}

fn type_name<T>() -> &'static str {
    // The full path is noise in an operator-facing panic: `u8`, not
    // `core::primitive::u8`.
    std::any::type_name::<T>()
        .rsplit("::")
        .next()
        .unwrap_or("value")
}

/// Whether the flag is on, defaulting to `false`.
///
/// See the module docs for the truthiness rule. Use this for anything that
/// turns a capability *on*, so that an unreadable value leaves it off.
pub fn flag(name: &str) -> bool {
    flag_or(name, false)
}

/// Whether the flag is on, defaulting to `default` when unset, empty, or
/// unrecognised.
pub fn flag_or(name: &str, default: bool) -> bool {
    let Some(raw) = read(name) else {
        return default;
    };
    match raw.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => true,
        "false" | "0" | "no" | "off" => false,
        _ => {
            tracing::warn!(
                "{name}: {raw:?} is not a recognised boolean — using the default ({default}). \
                 Set one of true/1/yes/on or false/0/no/off."
            );
            default
        }
    }
}

/// A comma-separated list, trimmed, with empty entries dropped.
///
/// Operators write these by hand, so a trailing or doubled comma is a typo to
/// absorb rather than an empty-string entry to hand onward — an allow-list with
/// a `""` in it is one buggy comparison away from matching everything.
pub fn list(name: &str) -> Vec<String> {
    match read(name) {
        None => Vec::new(),
        Some(raw) => raw
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(str::to_string)
            .collect(),
    }
}

/// The invariant behind this crate: every environment read in the config
/// boundary and the security-relevant lazy readers goes through an accessor
/// here, so the empty-means-unset rule and the truthiness rule cannot drift
/// back apart.
///
/// Modelled on `overslash_core::openapi::lint`'s accessor guard, which keeps
/// the extension vocabulary centralised the same way.
///
/// Scoped deliberately rather than applied workspace-wide. These are the
/// modules where a raw read has actually produced a bug — a login provider
/// configured with two empty strings, a dev-auth bypass enabled by
/// `DEV_AUTH=0`. Somewhere like `template_vars`, which *discovers* names by
/// scanning `env::vars()` rather than reading one, cannot use a named accessor
/// at all and is not listed.
#[cfg(test)]
mod guard {
    /// `(label, source)` for each module that must read through this crate.
    ///
    /// `include_str!` paths are relative to this file. Adding a module here is
    /// the cheap half of the job; the expensive half is that a raw read in it
    /// now fails the build.
    const GUARDED: &[(&str, &str)] = &[
        (
            "overslash-api/config/from_env.rs",
            include_str!("../../overslash-api/src/config/from_env.rs"),
        ),
        (
            "overslash-api/config/parse.rs",
            include_str!("../../overslash-api/src/config/parse.rs"),
        ),
        (
            "overslash-api/config/mod.rs",
            include_str!("../../overslash-api/src/config/mod.rs"),
        ),
        (
            "overslash-api/services/client_credentials.rs",
            include_str!("../../overslash-api/src/services/client_credentials.rs"),
        ),
        (
            "overslash-api/services/ssrf_guard.rs",
            include_str!("../../overslash-api/src/services/ssrf_guard.rs"),
        ),
        (
            "overslash-api/routes/oauth_providers.rs",
            include_str!("../../overslash-api/src/routes/oauth_providers.rs"),
        ),
        (
            "overslash-api/routes/org_oauth_credentials.rs",
            include_str!("../../overslash-api/src/routes/org_oauth_credentials.rs"),
        ),
        (
            "overslash-cli/common.rs",
            include_str!("../../overslash-cli/src/common.rs"),
        ),
        (
            "oversla-sh/config.rs",
            include_str!("../../oversla-sh/src/config.rs"),
        ),
        (
            "overslash-metrics-exporter/main.rs",
            include_str!("../../overslash-metrics-exporter/src/main.rs"),
        ),
    ];

    #[test]
    fn no_guarded_module_reads_the_environment_directly() {
        // The *call* is banned, not the variable names: `ssrf_guard` reads
        // through a `const METADATA_OVERRIDE_VAR`, so a ban on string literals
        // would miss it entirely.
        const BANNED: &[&str] = &["env::var(", "env::var_os(", "env::vars("];

        // Only production code is scanned. A test may legitimately reach for
        // the raw API to *set* a variable, which is the thing being tested.
        // `clippy::items_after_test_module` keeps every test module at the end
        // of its file, so truncating at the first `#[cfg(test)]` is exact
        // rather than a heuristic.
        for (name, src) in GUARDED {
            let production = src.split("#[cfg(test)]").next().unwrap_or(src);
            for (n, line) in production.lines().enumerate() {
                for banned in BANNED {
                    assert!(
                        !line.contains(banned),
                        "{name}:{} reads the environment directly; use an \
                         `overslash_env` accessor so an empty value keeps \
                         meaning unset:\n{line}",
                        n + 1,
                    );
                }
            }
        }
    }

    #[test]
    fn the_guard_list_points_at_real_files() {
        // `include_str!` would fail the build on a bad path, so this only has
        // to catch a stale entry that still resolves — an emptied file.
        for (name, src) in GUARDED {
            assert!(!src.trim().is_empty(), "{name} is empty");
        }
    }
}
