#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub valkey_url: String,
    /// How to authenticate to Valkey: unset locally, `VALKEY_AUTH=gcp-iam`
    /// against Memorystore, or a static `VALKEY_PASSWORD`.
    pub valkey_auth: overslash_valkey::Auth,
    /// PEM bundle of the Memorystore server CAs; requires a `rediss://` URL.
    pub valkey_ca_cert: Option<String>,
    pub api_key: String,
    pub base_url: String,
    pub min_ttl_secs: u64,
    pub max_ttl_secs: u64,
    /// If set, `GET /` 302s here. If unset, `GET /` is a 404. Lets
    /// oversla.sh send curious visitors to the marketing site without
    /// baking any brand in the code.
    pub root_redirect_url: Option<String>,
    /// Hosts a short link may point at: each entry and its subdomains
    /// (`ALLOWED_REDIRECT_DOMAINS`, comma-separated; default `overslash.com`).
    /// See `crate::target`.
    pub allowed_domains: Vec<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let host = overslash_env::or_default("HOST", "0.0.0.0");
        let port = overslash_env::parse_opt("PORT").unwrap_or(8080);
        let valkey_url = overslash_env::required("VALKEY_URL")?;
        let valkey_auth =
            overslash_valkey::Auth::from_env(&crate::storage::VARS).map_err(anyhow::Error::msg)?;
        let valkey_ca_cert = overslash_env::optional("VALKEY_CA_CERT");
        // `overslash_env` trims, which keeps the stored key symmetric with
        // the presented token (also trimmed in `auth::ApiKey`). Secret Manager
        // values frequently pick up trailing newlines when populated from
        // shell pipelines; untrimmed, a valid key fails the constant-time
        // length check.
        let api_key = overslash_env::required("API_KEY")?;
        let base_url = overslash_env::required("BASE_URL")?
            .trim_end_matches('/')
            .to_string();

        let min_ttl_secs = overslash_env::parse_opt("MIN_TTL_SECS").unwrap_or(60);
        let max_ttl_secs = overslash_env::parse_opt("MAX_TTL_SECS").unwrap_or(604_800); // 7 days

        if min_ttl_secs == 0 || min_ttl_secs > max_ttl_secs {
            anyhow::bail!(
                "invalid TTL bounds: MIN_TTL_SECS={min_ttl_secs} MAX_TTL_SECS={max_ttl_secs}"
            );
        }

        // Defaulted rather than required: infra is applied by hand, so a
        // required var would crash-loop the next image before the tfvars land.
        let mut allowed_domains = Vec::new();
        if let Some(raw) = overslash_env::optional("ALLOWED_REDIRECT_DOMAINS") {
            for entry in raw.split(',') {
                match crate::target::parse_domain(entry) {
                    Ok(Some(d)) => allowed_domains.push(d),
                    Ok(None) => {}
                    Err(e) => anyhow::bail!("invalid ALLOWED_REDIRECT_DOMAINS: {e}"),
                }
            }
        }
        if allowed_domains.is_empty() {
            allowed_domains = crate::target::DEFAULT_ALLOWED_DOMAINS
                .iter()
                .map(|d| d.to_string())
                .collect();
        }

        let root_redirect_url = overslash_env::optional("ROOT_REDIRECT_URL");
        if let Some(root) = &root_redirect_url {
            let ok = url::Url::parse(root)
                .is_ok_and(|u| crate::target::is_allowed(&u, &allowed_domains));
            if !ok {
                anyhow::bail!(
                    "ROOT_REDIRECT_URL must be an https URL on one of ALLOWED_REDIRECT_DOMAINS ({})",
                    allowed_domains.join(", ")
                );
            }
        }

        Ok(Self {
            host,
            port,
            valkey_url,
            valkey_auth,
            valkey_ca_cert,
            api_key,
            base_url,
            min_ttl_secs,
            max_ttl_secs,
            root_redirect_url,
            allowed_domains,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The process environment is global; serialise the cohort that mutates
    /// it so two of these can't race under the parallel runner.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const VARS: &[&str] = &[
        "HOST",
        "PORT",
        "VALKEY_URL",
        "VALKEY_PASSWORD",
        "VALKEY_AUTH",
        "VALKEY_CA_CERT",
        "API_KEY",
        "BASE_URL",
        "MIN_TTL_SECS",
        "MAX_TTL_SECS",
        "ROOT_REDIRECT_URL",
        "ALLOWED_REDIRECT_DOMAINS",
    ];

    /// Clear the slate, apply `overrides`, build a config, then restore and
    /// release the lock before the caller asserts — a panicking assertion
    /// would otherwise poison the mutex for every sibling test.
    fn with_env(overrides: &[(&str, &str)]) -> anyhow::Result<Config> {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: ENV_LOCK serialises every env mutation in this cohort.
        unsafe {
            for k in VARS {
                std::env::remove_var(k);
            }
            std::env::set_var("VALKEY_URL", "redis://localhost:6379");
            std::env::set_var("API_KEY", "secret");
            std::env::set_var("BASE_URL", "https://oversla.sh");
            for (k, v) in overrides {
                std::env::set_var(k, v);
            }
        }
        let out = Config::from_env();
        unsafe {
            for k in VARS {
                std::env::remove_var(k);
            }
        }
        drop(guard);
        out
    }

    #[test]
    fn reads_a_populated_environment() {
        let cfg = with_env(&[
            ("HOST", "127.0.0.1"),
            ("PORT", "9090"),
            ("MIN_TTL_SECS", "30"),
            ("ROOT_REDIRECT_URL", "https://overslash.com"),
        ])
        .expect("builds");
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 9090);
        assert_eq!(cfg.min_ttl_secs, 30);
        assert_eq!(cfg.api_key, "secret");
        assert_eq!(
            cfg.root_redirect_url.as_deref(),
            Some("https://overslash.com")
        );
    }

    #[test]
    fn valkey_auth_selects_memorystore_iam() {
        let cfg = with_env(&[("VALKEY_AUTH", "gcp-iam")]).expect("builds");
        assert_eq!(cfg.valkey_auth, overslash_valkey::Auth::GcpIam);
    }

    #[test]
    fn a_misspelled_valkey_auth_is_rejected_not_ignored() {
        let err = with_env(&[("VALKEY_AUTH", "iam")]).expect_err("must not boot");
        assert!(err.to_string().contains("VALKEY_AUTH"), "{err}");
    }

    #[test]
    fn a_trailing_slash_is_stripped_from_base_url() {
        let cfg = with_env(&[("BASE_URL", "https://oversla.sh/")]).expect("builds");
        assert_eq!(cfg.base_url, "https://oversla.sh");
    }

    #[test]
    fn the_key_is_trimmed_so_a_secret_manager_newline_still_matches() {
        // `auth::ApiKey` trims the presented token; untrimmed storage would
        // fail the constant-time length check against a valid key.
        let cfg = with_env(&[("API_KEY", "  secret\n")]).expect("builds");
        assert_eq!(cfg.api_key, "secret");
    }

    #[test]
    fn an_empty_required_var_is_rejected_like_an_unset_one() {
        // Previously only API_KEY was checked for emptiness: an empty
        // BASE_URL booted fine and produced broken short links.
        for var in ["VALKEY_URL", "API_KEY", "BASE_URL"] {
            let err = with_env(&[(var, "")])
                .expect_err(&format!("{var}=\"\" must be rejected"))
                .to_string();
            assert!(err.contains(var), "error should name {var}, got: {err}");
        }
    }

    #[test]
    fn empty_optional_vars_fall_back_to_their_defaults() {
        let cfg = with_env(&[
            ("HOST", ""),
            ("PORT", ""),
            ("MIN_TTL_SECS", ""),
            ("ROOT_REDIRECT_URL", ""),
        ])
        .expect("builds");
        assert_eq!(cfg.host, "0.0.0.0");
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.min_ttl_secs, 60);
        assert_eq!(
            cfg.root_redirect_url, None,
            "empty must not become Some(\"\")"
        );
    }

    #[test]
    fn allowed_domains_default_to_overslash() {
        for raw in [None, Some(""), Some(" , ")] {
            let overrides: Vec<_> = raw
                .map(|v| ("ALLOWED_REDIRECT_DOMAINS", v))
                .into_iter()
                .collect();
            let cfg = with_env(&overrides).expect("builds");
            assert_eq!(cfg.allowed_domains, ["overslash.com"], "{raw:?}");
        }
    }

    #[test]
    fn allowed_domains_are_parsed_and_normalised() {
        let cfg = with_env(&[("ALLOWED_REDIRECT_DOMAINS", " .Overslash.com , example.org,")])
            .expect("builds");
        assert_eq!(cfg.allowed_domains, ["overslash.com", "example.org"]);
    }

    #[test]
    fn a_malformed_allowed_domain_is_rejected() {
        let err = with_env(&[("ALLOWED_REDIRECT_DOMAINS", "*.overslash.com")])
            .expect_err("must not boot");
        assert!(
            err.to_string().contains("ALLOWED_REDIRECT_DOMAINS"),
            "{err}"
        );
    }

    #[test]
    fn a_root_redirect_outside_the_allowed_domains_is_rejected() {
        let err =
            with_env(&[("ROOT_REDIRECT_URL", "https://example.com")]).expect_err("must not boot");
        assert!(err.to_string().contains("ROOT_REDIRECT_URL"), "{err}");
    }

    #[test]
    fn inverted_ttl_bounds_are_rejected() {
        let err = with_env(&[("MIN_TTL_SECS", "100"), ("MAX_TTL_SECS", "50")])
            .expect_err("inverted bounds must fail");
        assert!(err.to_string().contains("invalid TTL bounds"));
    }
}
