//! What a process will agree to start with (CASA 6.2.1, 1.2.1).
//!
//! [`Config::from_env`] reads the environment; this module decides whether
//! the result is fit to serve. Each rule here is an *interlock*: a
//! configuration that is fine on a laptop and a vulnerability on the public
//! internet, told apart by [`DeploymentEnv`].
//!
//! - **`DEV_AUTH`** must be a recognised boolean — a typo stops the boot
//!   instead of silently picking a side — and may not be on in production.
//! - **Weak keys.** `SECRETS_ENCRYPTION_KEY` and `SIGNING_KEY` are refused
//!   when they are placeholders, one repeated byte, too short, or nearly
//!   constant, which is every value `.env.example` and the test fixtures ever
//!   shipped. Refused outside [`DeploymentEnv::Local`]; a warning on it, so an
//!   existing local database keeps decrypting. `SECRETS_ENCRYPTION_KEY_PREVIOUS`
//!   is deliberately exempt: rotating *off* a weak key is the remediation, and
//!   it needs the weak key as the previous one.
//! - **`RUST_LOG`** may not enable `debug` or `trace` in production. That one
//!   clamps to `info` with a warning rather than refusing, because the log
//!   level is not worth an outage (see [`log_filter`]).
//!
//! The production container image sets `OVERSLASH_ENV=prod`, so a
//! deployment gets these interlocks unless it explicitly says otherwise; an
//! unset `OVERSLASH_ENV` is a source checkout on a developer's machine.

use std::fmt;

use overslash_env as env;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

use super::Config;

/// `OVERSLASH_ENV`, parsed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum DeploymentEnv {
    /// Unset, or `local`. A developer's checkout.
    #[default]
    Local,
    /// `dev` / `development` — the shared, internet-facing dev deployment.
    Dev,
    Staging,
    /// `prod` / `production`.
    Prod,
    /// Any other marker, lowercased. Treated as a deployment, not as local.
    Other(String),
}

impl DeploymentEnv {
    pub fn parse(raw: Option<&str>) -> Self {
        let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
            return Self::Local;
        };
        let lower = raw.to_ascii_lowercase();
        match lower.as_str() {
            "local" => Self::Local,
            "dev" | "development" => Self::Dev,
            "staging" => Self::Staging,
            "prod" | "production" => Self::Prod,
            _ => Self::Other(lower),
        }
    }

    pub fn from_env() -> Self {
        Self::parse(env::optional("OVERSLASH_ENV").as_deref())
    }

    pub fn is_prod(&self) -> bool {
        matches!(self, Self::Prod)
    }

    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Local => "local",
            Self::Dev => "dev",
            Self::Staging => "staging",
            Self::Prod => "prod",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for DeploymentEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Minimum key material, in decoded bytes. 256 bits, the AES key size and the
/// HS256 recommendation.
const MIN_KEY_BYTES: usize = 32;

/// Fewer distinct byte values than this is a pattern, not a key. 32 random
/// bytes land on ~30 distinct values; the chance of fewer than 8 is below
/// 10^-20. The e2e harness's `ab cd cd cd …` has two.
const MIN_DISTINCT_BYTES: usize = 8;

/// Substrings that mark a value somebody meant to replace.
const PLACEHOLDER_MARKERS: &[&str] = &[
    "changeme",
    "change-me",
    "change_me",
    "replace-me",
    "replace_me",
    "placeholder",
    "example",
];

/// Why a key was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyWeakness {
    Placeholder,
    RepeatedByte,
    TooShort { bytes: usize },
    LowVariety { distinct: usize },
}

impl fmt::Display for KeyWeakness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Placeholder => f.write_str("is a placeholder value"),
            Self::RepeatedByte => f.write_str("is one byte repeated"),
            Self::TooShort { bytes } => {
                write!(f, "is {bytes} bytes; at least {MIN_KEY_BYTES} are required")
            }
            Self::LowVariety { distinct } => write!(
                f,
                "uses only {distinct} distinct byte values, which is a pattern, not a random key"
            ),
        }
    }
}

/// Judge a key by its configured text (`raw`) and the bytes it decodes to.
pub fn assess_key(raw: &str, bytes: &[u8]) -> Option<KeyWeakness> {
    let lower = raw.to_ascii_lowercase();
    if PLACEHOLDER_MARKERS.iter().any(|m| lower.contains(m)) {
        return Some(KeyWeakness::Placeholder);
    }
    let mut seen = [false; 256];
    for b in bytes {
        seen[*b as usize] = true;
    }
    let distinct = seen.iter().filter(|s| **s).count();
    if distinct <= 1 {
        return Some(KeyWeakness::RepeatedByte);
    }
    if bytes.len() < MIN_KEY_BYTES {
        return Some(KeyWeakness::TooShort { bytes: bytes.len() });
    }
    if distinct < MIN_DISTINCT_BYTES {
        return Some(KeyWeakness::LowVariety { distinct });
    }
    None
}

/// One configuration the process should not run with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootViolation {
    DevAuthNotBoolean {
        raw: String,
    },
    DevAuthInProduction,
    WeakKey {
        var: &'static str,
        weakness: KeyWeakness,
    },
}

impl fmt::Display for BootViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DevAuthNotBoolean { raw } => write!(
                f,
                "DEV_AUTH={raw:?} is not a boolean. Set one of true/1/yes/on or \
                 false/0/no/off, or unset it."
            ),
            Self::DevAuthInProduction => f.write_str(
                "DEV_AUTH is on and OVERSLASH_ENV is prod. The dev-auth bypass mints a \
                 session for anyone who asks; it cannot run in production.",
            ),
            Self::WeakKey { var, weakness } => {
                write!(
                    f,
                    "{var} {weakness}. Generate one with `openssl rand -hex 32`"
                )?;
                if *var == "SECRETS_ENCRYPTION_KEY" {
                    f.write_str(
                        " — and rotate onto it rather than swapping it in: set the old value as \
                         SECRETS_ENCRYPTION_KEY_PREVIOUS, bump SECRETS_ENCRYPTION_KEY_ACTIVE_ID, \
                         then run `overslash admin reencrypt`",
                    )?;
                }
                f.write_str(".")
            }
        }
    }
}

/// The verdict: `errors` stop the boot, `warnings` are logged.
#[derive(Debug, Default)]
pub struct BootReport {
    pub errors: Vec<BootViolation>,
    pub warnings: Vec<BootViolation>,
}

impl Config {
    /// Run every interlock against this config and the raw `DEV_AUTH`.
    pub fn boot_policy(&self) -> BootReport {
        self.boot_policy_with(env::optional("DEV_AUTH").as_deref())
    }

    /// [`Config::boot_policy`] with the one raw value it needs passed in, so
    /// it can be tested without touching the process environment.
    /// `dev_auth_enabled` has already been through the fail-closed
    /// [`env::flag`]; the raw value is what tells a typo from an `off`.
    pub(crate) fn boot_policy_with(&self, dev_auth_raw: Option<&str>) -> BootReport {
        let mut report = BootReport::default();

        if let Some(raw) = dev_auth_raw
            && env::parse_bool(raw).is_none()
        {
            report.errors.push(BootViolation::DevAuthNotBoolean {
                raw: raw.to_string(),
            });
        }
        if self.dev_auth_enabled && self.deployment_env.is_prod() {
            report.errors.push(BootViolation::DevAuthInProduction);
        }

        let mut weak = Vec::new();
        // A malformed encryption key is not judged here: `Config::keyring`
        // refuses it at startup with its own error.
        if let Ok(bytes) = overslash_core::crypto::parse_hex_key(&self.secrets_encryption_key)
            && let Some(weakness) = assess_key(&self.secrets_encryption_key, &bytes)
        {
            weak.push(BootViolation::WeakKey {
                var: "SECRETS_ENCRYPTION_KEY",
                weakness,
            });
        }
        let signing = crate::services::jwt::signing_key_bytes(&self.signing_key);
        if let Some(weakness) = assess_key(&self.signing_key, &signing) {
            weak.push(BootViolation::WeakKey {
                var: "SIGNING_KEY",
                weakness,
            });
        }
        if self.deployment_env.is_local() {
            report.warnings.extend(weak);
        } else {
            report.errors.extend(weak);
        }

        report
    }
}

/// The tracing filter to run with, plus a warning to log once it is up.
///
/// Unset or unparseable `RUST_LOG` means `info`. In production a filter that
/// enables `debug` or `trace` anywhere — including one that cannot say, which
/// `max_level_hint` reports as `None` — is replaced by `info`: debug output
/// carries request bodies, resolver results and upstream error text that
/// production logs are not meant to retain. Clamped rather than refused,
/// because an operator raising verbosity during an incident should get a
/// warning, not a crash loop.
pub fn log_filter(
    rust_log: Option<&str>,
    deployment: &DeploymentEnv,
) -> (EnvFilter, Option<String>) {
    let Some(raw) = rust_log else {
        return (EnvFilter::new("info"), None);
    };
    let Ok(filter) = EnvFilter::try_new(raw) else {
        return (
            EnvFilter::new("info"),
            Some(format!("RUST_LOG={raw:?} does not parse; logging at info")),
        );
    };
    let too_verbose = filter
        .max_level_hint()
        .is_none_or(|level| level > LevelFilter::INFO);
    if deployment.is_prod() && too_verbose {
        return (
            EnvFilter::new("info"),
            Some(format!(
                "RUST_LOG={raw:?} enables debug output, which production does not run \
                 with; logging at info"
            )),
        );
    }
    (filter, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::empty_test_config;

    /// 32 bytes, 32 distinct values — what `openssl rand -hex 32` looks like.
    const STRONG_HEX: &str = "8f3a1c9e5b7d2f4068a1c3e5f7092b4d6e8f0a1b2c3d4e5f60718293a4b5c6d7";

    fn config(env: DeploymentEnv) -> Config {
        let mut cfg = empty_test_config();
        cfg.deployment_env = env;
        cfg.secrets_encryption_key = STRONG_HEX.into();
        cfg.signing_key = STRONG_HEX.chars().rev().collect();
        cfg
    }

    // ── DeploymentEnv ───────────────────────────────────────────────────

    #[test]
    fn deployment_env_parses_every_spelling() {
        assert_eq!(DeploymentEnv::parse(None), DeploymentEnv::Local);
        assert_eq!(DeploymentEnv::parse(Some("  ")), DeploymentEnv::Local);
        assert_eq!(DeploymentEnv::parse(Some("local")), DeploymentEnv::Local);
        assert_eq!(DeploymentEnv::parse(Some("dev")), DeploymentEnv::Dev);
        assert_eq!(
            DeploymentEnv::parse(Some("Development")),
            DeploymentEnv::Dev
        );
        assert_eq!(
            DeploymentEnv::parse(Some("staging")),
            DeploymentEnv::Staging
        );
        assert_eq!(DeploymentEnv::parse(Some("prod")), DeploymentEnv::Prod);
        assert_eq!(
            DeploymentEnv::parse(Some(" PRODUCTION ")),
            DeploymentEnv::Prod
        );
        assert_eq!(
            DeploymentEnv::parse(Some("Canary")),
            DeploymentEnv::Other("canary".into())
        );
    }

    // ── DEV_AUTH ────────────────────────────────────────────────────────

    #[test]
    fn a_healthy_config_passes_in_every_environment() {
        for env in [
            DeploymentEnv::Local,
            DeploymentEnv::Dev,
            DeploymentEnv::Prod,
            DeploymentEnv::Other("canary".into()),
        ] {
            let report = config(env.clone()).boot_policy_with(None);
            assert!(report.errors.is_empty(), "{env}: {:?}", report.errors);
            assert!(report.warnings.is_empty(), "{env}: {:?}", report.warnings);
        }
    }

    #[test]
    fn dev_auth_is_refused_in_production() {
        let mut cfg = config(DeploymentEnv::Prod);
        cfg.dev_auth_enabled = true;
        let report = cfg.boot_policy_with(Some("1"));
        assert_eq!(report.errors, vec![BootViolation::DevAuthInProduction]);
    }

    #[test]
    fn dev_auth_is_allowed_outside_production() {
        for env in [
            DeploymentEnv::Local,
            DeploymentEnv::Dev,
            DeploymentEnv::Staging,
        ] {
            let mut cfg = config(env.clone());
            cfg.dev_auth_enabled = true;
            let report = cfg.boot_policy_with(Some("true"));
            assert!(report.errors.is_empty(), "{env}: {:?}", report.errors);
        }
    }

    #[test]
    fn an_explicit_dev_auth_off_is_fine_in_production() {
        let report = config(DeploymentEnv::Prod).boot_policy_with(Some("0"));
        assert!(report.errors.is_empty(), "{:?}", report.errors);
    }

    #[test]
    fn a_dev_auth_that_is_not_a_boolean_stops_the_boot_everywhere() {
        // `env::flag` already read these as off; the interlock is that the
        // operator finds out, rather than getting the side they did not mean.
        for raw in ["ture", "enabled", "2"] {
            for env in [DeploymentEnv::Local, DeploymentEnv::Prod] {
                let report = config(env.clone()).boot_policy_with(Some(raw));
                assert_eq!(
                    report.errors,
                    vec![BootViolation::DevAuthNotBoolean { raw: raw.into() }],
                    "{env} / {raw:?}"
                );
            }
        }
    }

    // ── weak keys ───────────────────────────────────────────────────────

    #[test]
    fn assess_key_accepts_random_material() {
        let bytes = overslash_core::crypto::parse_hex_key(STRONG_HEX).unwrap();
        assert_eq!(assess_key(STRONG_HEX, &bytes), None);
        // `openssl rand -base64 32`, used raw as a signing key.
        let b64 = "q7Vx0kR3n+Jc2L9mP4sT8wZ1yB6eH5dA0uF3gK7iN2o=";
        assert_eq!(assess_key(b64, b64.as_bytes()), None);
    }

    #[test]
    fn assess_key_refuses_each_weakness() {
        let zeros = [0u8; 32];
        assert_eq!(
            assess_key(&"00".repeat(32), &zeros),
            Some(KeyWeakness::RepeatedByte)
        );

        let short = b"s3cr3t-but-short";
        assert_eq!(
            assess_key("s3cr3t-but-short", short),
            Some(KeyWeakness::TooShort { bytes: 16 })
        );

        // The e2e harness's key: `ab` then `cd` × 31.
        let mut patterned = [0xCDu8; 32];
        patterned[0] = 0xAB;
        assert_eq!(
            assess_key("", &patterned),
            Some(KeyWeakness::LowVariety { distinct: 2 })
        );

        let placeholder = "please-changeme-to-a-real-signing-key-before-deploying";
        assert_eq!(
            assess_key(placeholder, placeholder.as_bytes()),
            Some(KeyWeakness::Placeholder)
        );
    }

    /// The literal values `.env.example` shipped, and the fixture keys the
    /// test suite uses, must all be refused.
    #[test]
    fn the_env_example_and_fixture_keys_are_refused_outside_local() {
        for (enc, sig) in [
            ("0".repeat(64), "1".repeat(64)),
            ("ab".repeat(32), "cd".repeat(32)),
            (
                format!("ab{}", "cd".repeat(31)),
                format!("ef{}", "01".repeat(31)),
            ),
        ] {
            let mut cfg = config(DeploymentEnv::Prod);
            cfg.secrets_encryption_key = enc.clone();
            cfg.signing_key = sig.clone();
            let report = cfg.boot_policy_with(None);
            let vars: Vec<_> = report
                .errors
                .iter()
                .map(|v| match v {
                    BootViolation::WeakKey { var, .. } => *var,
                    other => panic!("unexpected {other:?}"),
                })
                .collect();
            assert_eq!(
                vars,
                ["SECRETS_ENCRYPTION_KEY", "SIGNING_KEY"],
                "{enc} / {sig}"
            );
        }
    }

    #[test]
    fn weak_keys_only_warn_on_a_local_checkout() {
        let mut cfg = config(DeploymentEnv::Local);
        cfg.secrets_encryption_key = "0".repeat(64);
        let report = cfg.boot_policy_with(None);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.warnings.len(), 1);

        // Dev and unknown markers are deployments, not laptops.
        for env in [DeploymentEnv::Dev, DeploymentEnv::Other("canary".into())] {
            let mut cfg = config(env.clone());
            cfg.secrets_encryption_key = "0".repeat(64);
            assert_eq!(cfg.boot_policy_with(None).errors.len(), 1, "{env}");
        }
    }

    #[test]
    fn a_weak_previous_key_is_allowed_so_it_can_be_rotated_away() {
        let mut cfg = config(DeploymentEnv::Prod);
        cfg.secrets_encryption_key_previous = Some("0".repeat(64));
        cfg.secrets_encryption_key_active_id = 2;
        cfg.secrets_encryption_key_previous_id = 1;
        assert!(cfg.boot_policy_with(None).errors.is_empty());
    }

    // ── RUST_LOG ────────────────────────────────────────────────────────

    fn level(rust_log: Option<&str>, env: DeploymentEnv) -> (Option<LevelFilter>, bool) {
        let (filter, warning) = log_filter(rust_log, &env);
        (filter.max_level_hint(), warning.is_some())
    }

    #[test]
    fn rust_log_defaults_to_info() {
        assert_eq!(
            level(None, DeploymentEnv::Prod),
            (Some(LevelFilter::INFO), false)
        );
        assert_eq!(
            level(None, DeploymentEnv::Local),
            (Some(LevelFilter::INFO), false)
        );
    }

    #[test]
    fn production_is_clamped_off_debug() {
        for raw in [
            "debug",
            "trace",
            "overslash=debug,info",
            "info,overslash_api=trace",
        ] {
            assert_eq!(
                level(Some(raw), DeploymentEnv::Prod),
                (Some(LevelFilter::INFO), true),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn production_keeps_a_quieter_filter_as_given() {
        assert_eq!(
            level(Some("warn,hyper=error"), DeploymentEnv::Prod),
            (Some(LevelFilter::WARN), false)
        );
        assert_eq!(
            level(Some("info"), DeploymentEnv::Prod),
            (Some(LevelFilter::INFO), false)
        );
    }

    #[test]
    fn debug_is_left_alone_outside_production() {
        for env in [DeploymentEnv::Local, DeploymentEnv::Dev] {
            assert_eq!(
                level(Some("overslash=debug,info"), env.clone()),
                (Some(LevelFilter::DEBUG), false),
                "{env}"
            );
        }
    }
}
