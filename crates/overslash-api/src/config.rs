use std::collections::HashMap;
use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub secrets_encryption_key: String,
    pub signing_key: String,
    pub approval_expiry_secs: u64,
    /// Seconds a pending execution row (`executions.status='pending'`) lives
    /// before the sweeper marks it `expired`. Default 900 (15 minutes).
    pub execution_pending_ttl_secs: u64,
    /// Upper bound on how long the synchronous replay inside
    /// `POST /v1/approvals/{id}/call` may wait for the upstream call.
    /// Beyond this the row is finalised as `failed` with `error='replay_timeout'`.
    pub execution_replay_timeout_secs: u64,
    pub services_dir: String,
    pub google_auth_client_id: Option<String>,
    pub google_auth_client_secret: Option<String>,
    pub github_auth_client_id: Option<String>,
    pub github_auth_client_secret: Option<String>,
    pub public_url: String,
    pub dev_auth_enabled: bool,
    pub max_response_body_bytes: usize,
    pub filter_timeout_ms: u64,
    pub dashboard_url: String,
    pub dashboard_origin: String,
    pub redis_url: Option<String>,
    pub default_rate_limit: u32,
    pub default_rate_window_secs: u32,
    /// When `false`, `POST /v1/orgs` returns 403 and the dashboard hides the
    /// "Create org" CTA. Lets a self-hosted operator lock down org creation
    /// after initial setup. Default `true`.
    pub allow_org_creation: bool,
    /// When set, the subdomain middleware is bypassed and every request is
    /// treated as scoped to the named org slug. Self-hosted operators who
    /// want the old single-org experience set this to their org's slug.
    /// Default unset (multi-org cloud mode).
    pub single_org_mode: Option<String>,
    /// When true, Team org creation is gated behind a Stripe subscription.
    /// Personal orgs (created at signup) remain free. Requires the
    /// STRIPE_* vars to be set. Default false (self-hosted: no billing).
    pub cloud_billing: bool,
    pub stripe_secret_key: Option<String>,
    pub stripe_webhook_secret: Option<String>,
    /// Stripe lookup key for the EUR seat price. Default `overslash_seat_eur`.
    /// Resolved to a literal `price_…` ID at startup when billing is enabled
    /// (see `stripe_eur_price_id`). Lookup keys are stable Stripe Dashboard
    /// handles, so rotating the underlying price doesn't require a redeploy.
    pub stripe_eur_lookup_key: String,
    /// Stripe lookup key for the USD seat price. Default `overslash_seat_usd`.
    pub stripe_usd_lookup_key: String,
    /// Resolved EUR price ID. Populated at startup from the lookup key — this
    /// is what we pass to Checkout Session create. `None` until resolution.
    pub stripe_eur_price_id: Option<String>,
    /// Resolved USD price ID. Populated at startup from the lookup key.
    pub stripe_usd_price_id: Option<String>,
    /// Base URL for the Stripe API. Overridden in tests to point to a mock
    /// server; in production this is always "https://api.stripe.com/v1".
    pub stripe_api_base: String,
    /// Optional apex used to resolve `<slug>.<apex>` subdomains into an org.
    /// e.g. `app.overslash.com`. When unset, subdomain routing is disabled
    /// (helpful for self-hosted single-host deploys). Leave unset in local
    /// dev; tests set this explicitly.
    pub app_host_suffix: Option<String>,
    /// Optional Domain attribute for the session cookie, typically a leading
    /// dot + `app_host_suffix` so cookies are shared across subdomains
    /// (e.g. `.app.overslash.com`). When None, cookies stay origin-scoped,
    /// which is what local dev without TLS needs.
    pub session_cookie_domain: Option<String>,
    /// Test-only host rewrites applied to every upstream URL right before the
    /// HTTP request goes out. Keyed by hostname (`api.github.com`) → base URL
    /// (`http://127.0.0.1:54321`). Loaded from `OVERSLASH_SERVICE_BASE_OVERRIDES`
    /// in the form `host=base_url[,host=base_url...]`. The override is
    /// silently ignored unless the override target is a loopback address or
    /// `OVERSLASH_SSRF_ALLOW_PRIVATE=1` is set, so prod deploys can leave the
    /// var defined harmlessly.
    pub service_base_overrides: HashMap<String, String>,
    /// Base URL for the `oversla.sh` short-link service, e.g.
    /// `https://oversla.sh`. When set together with `oversla_sh_api_key`,
    /// the nested-OAuth `initiate` handler creates a short URL alongside
    /// the proxied URL. When unset, only the proxied URL is returned.
    pub oversla_sh_base_url: Option<String>,
    pub oversla_sh_api_key: Option<String>,
}

fn parse_service_base_overrides(raw: Option<&str>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(s) = raw.filter(|s| !s.trim().is_empty()) else {
        return out;
    };
    for entry in s.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((k, v)) = entry.split_once('=') else {
            continue;
        };
        let host = k.trim();
        let base = v.trim();
        if host.is_empty() || base.is_empty() {
            continue;
        }
        out.insert(host.to_string(), base.to_string());
    }
    out
}

/// Returns true if the override target is loopback or
/// `OVERSLASH_SSRF_ALLOW_PRIVATE` is set to a truthy value. Mirrors the SSRF
/// guard so production deploys can leave `OVERSLASH_SERVICE_BASE_OVERRIDES`
/// set harmlessly: a public override target is silently dropped.
fn ssrf_allowed_for(base_url: &str) -> bool {
    if let Ok(v) = env::var("OVERSLASH_SSRF_ALLOW_PRIVATE") {
        // Accept the same truthy spellings as `CLOUD_BILLING` etc. above so a
        // stray `OVERSLASH_SSRF_ALLOW_PRIVATE=0` doesn't accidentally enable
        // the bypass.
        if matches!(v.as_str(), "true" | "1" | "yes") {
            return true;
        }
    }
    let Ok(parsed) = url::Url::parse(base_url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    false
}

/// Build the default `public_url` from the bind host/port. We map
/// wildcard binds (`0.0.0.0`, `::`) to `localhost` because the public URL
/// is meant to be reachable from a browser — `http://0.0.0.0:8080` is not
/// a valid origin to advertise. Raw IPv6 literals (e.g. `::1`,
/// `2001:db8::1`) are wrapped in brackets per RFC 3986 so the resulting
/// URL parses cleanly. Set `PUBLIC_URL` explicitly for production
/// deployments behind a reverse proxy.
pub fn default_public_url(host: &str, port: u16) -> String {
    let display: std::borrow::Cow<'_, str> = match host {
        "0.0.0.0" | "::" | "[::]" => "localhost".into(),
        h if h.starts_with('[') => h.into(),
        // An unbracketed colon means an IPv6 literal — bracket it so
        // `host:port` doesn't collide with the address's own colons.
        h if h.contains(':') => format!("[{h}]").into(),
        h => h.into(),
    };
    format!("http://{display}:{port}")
}

impl Config {
    /// Load config from environment variables.
    pub fn from_env() -> Self {
        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
        let port = env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3000);
        let public_url = env::var("PUBLIC_URL").unwrap_or_else(|_| default_public_url(&host, port));
        Self {
            host,
            port,
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL is required"),
            secrets_encryption_key: env::var("SECRETS_ENCRYPTION_KEY")
                .expect("SECRETS_ENCRYPTION_KEY is required"),
            signing_key: env::var("SIGNING_KEY").expect("SIGNING_KEY is required"),
            approval_expiry_secs: env::var("APPROVAL_EXPIRY_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1800),
            execution_pending_ttl_secs: env::var("EXECUTION_PENDING_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(900),
            execution_replay_timeout_secs: env::var("EXECUTION_REPLAY_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            services_dir: env::var("SERVICES_DIR").unwrap_or_else(|_| "services".into()),
            google_auth_client_id: env::var("GOOGLE_AUTH_CLIENT_ID").ok(),
            google_auth_client_secret: env::var("GOOGLE_AUTH_CLIENT_SECRET").ok(),
            github_auth_client_id: env::var("GITHUB_AUTH_CLIENT_ID").ok(),
            github_auth_client_secret: env::var("GITHUB_AUTH_CLIENT_SECRET").ok(),
            public_url,
            dev_auth_enabled: env::var("DEV_AUTH").is_ok(),
            max_response_body_bytes: env::var("MAX_RESPONSE_BODY_BYTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5_242_880), // 5 MB
            filter_timeout_ms: env::var("FILTER_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2000),
            dashboard_url: env::var("DASHBOARD_URL").unwrap_or_else(|_| "/".into()),
            // "*localhost*" matches any http://localhost:<port> / http://127.0.0.1:<port>
            // origin so that worktrees with dynamic dashboard ports work out of the box.
            // In production set this to a comma-separated list of explicit origins.
            dashboard_origin: env::var("DASHBOARD_ORIGIN").unwrap_or_else(|_| "*localhost*".into()),
            redis_url: env::var("REDIS_URL").ok(),
            default_rate_limit: env::var("DEFAULT_RATE_LIMIT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1000),
            default_rate_window_secs: env::var("DEFAULT_RATE_WINDOW_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
            allow_org_creation: env::var("ALLOW_ORG_CREATION")
                .ok()
                .map(|v| !matches!(v.as_str(), "false" | "0" | "no" | ""))
                .unwrap_or(true),
            single_org_mode: env::var("SINGLE_ORG_MODE").ok().filter(|s| !s.is_empty()),
            app_host_suffix: env::var("APP_HOST_SUFFIX").ok().filter(|s| !s.is_empty()),
            session_cookie_domain: env::var("SESSION_COOKIE_DOMAIN")
                .ok()
                .filter(|s| !s.is_empty()),
            cloud_billing: env::var("CLOUD_BILLING")
                .ok()
                .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
                .unwrap_or(false),
            stripe_secret_key: env::var("STRIPE_SECRET_KEY").ok().filter(|s| !s.is_empty()),
            stripe_webhook_secret: env::var("STRIPE_WEBHOOK_SECRET")
                .ok()
                .filter(|s| !s.is_empty()),
            stripe_eur_lookup_key: env::var("STRIPE_EUR_LOOKUP_KEY")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "overslash_seat_eur".into()),
            stripe_usd_lookup_key: env::var("STRIPE_USD_LOOKUP_KEY")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "overslash_seat_usd".into()),
            // Populated at startup by `resolve_stripe_prices` when billing
            // is enabled — left None here so a misconfigured deploy fails
            // fast at startup instead of at first checkout.
            stripe_eur_price_id: None,
            stripe_usd_price_id: None,
            stripe_api_base: env::var("STRIPE_API_BASE")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "https://api.stripe.com/v1".into()),
            service_base_overrides: parse_service_base_overrides(
                env::var("OVERSLASH_SERVICE_BASE_OVERRIDES").ok().as_deref(),
            ),
            oversla_sh_base_url: env::var("OVERSLA_SH_BASE_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            oversla_sh_api_key: env::var("OVERSLA_SH_API_KEY")
                .ok()
                .filter(|s| !s.is_empty()),
        }
    }

    /// Check for required env vars and return list of missing ones.
    pub fn validate_env() -> Vec<&'static str> {
        let always_required = ["DATABASE_URL", "SECRETS_ENCRYPTION_KEY", "SIGNING_KEY"];
        let cloud_billing_enabled = env::var("CLOUD_BILLING")
            .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);
        // Lookup keys default to overslash_seat_{eur,usd} so they're not
        // listed here. Operators only need to set the secrets.
        let billing_required: &[&str] = if cloud_billing_enabled {
            &["STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"]
        } else {
            &[]
        };
        always_required
            .iter()
            .chain(billing_required.iter())
            .filter(|k| env::var(k).map(|v| v.is_empty()).unwrap_or(true))
            .copied()
            .collect()
    }

    /// Build a URL for a dashboard deep-link path (e.g., `/approvals/<id>`,
    /// `/oauth/consent?request_id=...`, `/secrets/provide/<id>?token=...`).
    ///
    /// `dashboard_url` is the canonical dashboard host. When it's already
    /// absolute (`http://` or `https://`) it's used directly; when relative
    /// (the default `/` in local/single-process deployments), `public_url`
    /// is prepended so the resulting URL is reachable from outside the
    /// host process. The dashboard URL must be suitable to paste into an
    /// agent's conversation and have the owner click it.
    pub fn dashboard_url_for(&self, path: &str) -> String {
        let dash = self.dashboard_url.trim_end_matches('/');
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        if dash.starts_with("http://") || dash.starts_with("https://") {
            format!("{dash}{path}")
        } else {
            format!("{}{dash}{path}", self.public_url.trim_end_matches('/'))
        }
    }

    /// Apply host-based base URL overrides to an upstream URL.
    ///
    /// If the URL's host matches an entry in `service_base_overrides`, the
    /// `scheme://host[:port]` portion is replaced with the override base
    /// (preserving path + query). When no override matches, returns the URL
    /// unchanged.
    ///
    /// The override is silently skipped if the override target is not loopback
    /// and `OVERSLASH_SSRF_ALLOW_PRIVATE` isn't set — the SSRF guard is
    /// honored regardless. Errors in URL parsing fall through unchanged.
    pub fn apply_base_overrides(&self, url_str: &str) -> String {
        if self.service_base_overrides.is_empty() {
            return url_str.to_string();
        }
        let Ok(parsed) = url::Url::parse(url_str) else {
            return url_str.to_string();
        };
        let Some(host) = parsed.host_str() else {
            return url_str.to_string();
        };
        let Some(override_base) = self.service_base_overrides.get(host) else {
            return url_str.to_string();
        };
        if !ssrf_allowed_for(override_base) {
            return url_str.to_string();
        }
        // Splice override base + path + query.
        let mut out = override_base.trim_end_matches('/').to_string();
        out.push_str(parsed.path());
        if let Some(q) = parsed.query() {
            out.push('?');
            out.push_str(q);
        }
        out
    }

    /// Returns env-var-based auth credentials for a given provider key, if configured.
    /// Env vars take precedence over DB-stored IdP configs.
    pub fn env_auth_credentials(&self, provider_key: &str) -> Option<(String, String)> {
        match provider_key {
            "google" => self
                .google_auth_client_id
                .as_ref()
                .zip(self.google_auth_client_secret.as_ref())
                .map(|(a, b)| (a.clone(), b.clone())),
            "github" => self
                .github_auth_client_id
                .as_ref()
                .zip(self.github_auth_client_secret.as_ref())
                .map(|(a, b)| (a.clone(), b.clone())),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests in this module mutate `OVERSLASH_SSRF_ALLOW_PRIVATE`; the env
    /// is process-global so any two of them racing would produce nondeter-
    /// ministic results under cargo's default parallel runner. Serialise
    /// across the whole env-touching cohort with a single mutex.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn default_public_url_maps_wildcard_hosts_to_localhost() {
        assert_eq!(default_public_url("0.0.0.0", 8080), "http://localhost:8080");
        assert_eq!(default_public_url("::", 3000), "http://localhost:3000");
        assert_eq!(default_public_url("[::]", 7676), "http://localhost:7676");
    }

    #[test]
    fn default_public_url_passes_through_explicit_hosts() {
        assert_eq!(
            default_public_url("127.0.0.1", 7676),
            "http://127.0.0.1:7676"
        );
        assert_eq!(
            default_public_url("api.example.com", 8080),
            "http://api.example.com:8080"
        );
    }

    #[test]
    fn default_public_url_brackets_raw_ipv6_literals() {
        // RFC 3986 requires IPv6 in URLs to be bracketed so the host's
        // colons can be told apart from the host:port colon.
        assert_eq!(default_public_url("::1", 8080), "http://[::1]:8080");
        assert_eq!(
            default_public_url("2001:db8::1", 8080),
            "http://[2001:db8::1]:8080"
        );
    }

    #[test]
    fn default_public_url_does_not_double_bracket_already_bracketed_ipv6() {
        assert_eq!(default_public_url("[::1]", 8080), "http://[::1]:8080");
        assert_eq!(
            default_public_url("[2001:db8::1]", 8080),
            "http://[2001:db8::1]:8080"
        );
    }

    #[test]
    fn parse_service_base_overrides_handles_multiple_entries() {
        let map = parse_service_base_overrides(Some(
            "api.github.com=http://127.0.0.1:9101,slack.com=http://127.0.0.1:9102",
        ));
        assert_eq!(
            map.get("api.github.com"),
            Some(&"http://127.0.0.1:9101".to_string())
        );
        assert_eq!(
            map.get("slack.com"),
            Some(&"http://127.0.0.1:9102".to_string())
        );
    }

    #[test]
    fn parse_service_base_overrides_skips_malformed_entries() {
        let map = parse_service_base_overrides(Some(
            "api.github.com=http://127.0.0.1:9101,bad-no-equals,=http://x,foo=",
        ));
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("api.github.com"));
    }

    #[test]
    fn apply_base_overrides_swaps_host_keeping_path_and_query() {
        let mut cfg = empty_test_config();
        cfg.service_base_overrides
            .insert("api.github.com".into(), "http://127.0.0.1:9101".into());
        assert_eq!(
            cfg.apply_base_overrides("https://api.github.com/repos/x/y?per_page=5"),
            "http://127.0.0.1:9101/repos/x/y?per_page=5"
        );
    }

    #[test]
    fn apply_base_overrides_unchanged_when_host_not_listed() {
        let mut cfg = empty_test_config();
        cfg.service_base_overrides
            .insert("api.github.com".into(), "http://127.0.0.1:9101".into());
        assert_eq!(
            cfg.apply_base_overrides("https://api.slack.com/x"),
            "https://api.slack.com/x"
        );
    }

    #[test]
    fn apply_base_overrides_drops_non_loopback_target_without_ssrf_bypass() {
        // Without OVERSLASH_SSRF_ALLOW_PRIVATE, a non-loopback override is
        // silently ignored — guards prod deploys against accidentally-set vars.
        let _guard = ENV_LOCK.lock().unwrap();
        let mut cfg = empty_test_config();
        cfg.service_base_overrides.insert(
            "api.github.com".into(),
            "https://attacker.example.com".into(),
        );
        // SAFETY: ENV_LOCK serialises env-touching tests in this module so
        // the bypass var stays in a known state across `apply_base_overrides`,
        // which reads the env at call time.
        unsafe {
            env::remove_var("OVERSLASH_SSRF_ALLOW_PRIVATE");
        }
        assert_eq!(
            cfg.apply_base_overrides("https://api.github.com/x"),
            "https://api.github.com/x"
        );
    }

    #[test]
    fn apply_base_overrides_mixed_matrix_keeps_loopback_drops_disallowed() {
        // E2E real-stack scenario: a single override map combines both kinds
        // of entries — the loopback fake target the e2e harness sets up and
        // an extra entry that purposely points at a disallowed host. Without
        // the SSRF bypass, the loopback entry must apply (override hits the
        // fake) while the disallowed entry must be silently dropped (request
        // would fall through to the original upstream — proving the gate
        // rejected the override). The non-overridden host passes through
        // unchanged regardless of the matrix.
        let _guard = ENV_LOCK.lock().unwrap();
        let mut cfg = empty_test_config();
        cfg.service_base_overrides
            .insert("api.github.com".into(), "http://127.0.0.1:9101".into());
        cfg.service_base_overrides.insert(
            "api.attacker.test".into(),
            "https://attacker.example.com".into(),
        );
        // SAFETY: see sibling test — env is read at call time.
        unsafe {
            env::remove_var("OVERSLASH_SSRF_ALLOW_PRIVATE");
        }
        // Allowed: loopback target, override applies.
        assert_eq!(
            cfg.apply_base_overrides("https://api.github.com/repos/x/y?per_page=5"),
            "http://127.0.0.1:9101/repos/x/y?per_page=5"
        );
        // Rejected: non-loopback target, override silently dropped.
        assert_eq!(
            cfg.apply_base_overrides("https://api.attacker.test/foo"),
            "https://api.attacker.test/foo"
        );
        // Untouched: host has no override entry at all.
        assert_eq!(
            cfg.apply_base_overrides("https://api.slack.com/x"),
            "https://api.slack.com/x"
        );
    }

    #[test]
    fn apply_base_overrides_keeps_non_loopback_target_with_ssrf_bypass() {
        // Inverse of the rejection case: when OVERSLASH_SSRF_ALLOW_PRIVATE=1
        // (the e2e profile turns this on so loopback fakes are reachable)
        // the gate's loopback-only check is bypassed and *every* override
        // entry applies — including non-loopback ones. The bypass is the
        // single audited escape hatch for tests; the production binary never
        // sets it.
        let _guard = ENV_LOCK.lock().unwrap();
        let mut cfg = empty_test_config();
        cfg.service_base_overrides.insert(
            "api.attacker.test".into(),
            "https://attacker.example.com".into(),
        );
        // SAFETY: env is read at call time.
        unsafe {
            env::set_var("OVERSLASH_SSRF_ALLOW_PRIVATE", "1");
        }
        let resolved = cfg.apply_base_overrides("https://api.attacker.test/foo");
        // Restore env state for sibling tests that expect the bypass off.
        unsafe {
            env::remove_var("OVERSLASH_SSRF_ALLOW_PRIVATE");
        }
        assert_eq!(resolved, "https://attacker.example.com/foo");
    }

    fn empty_test_config() -> Config {
        Config {
            host: "127.0.0.1".into(),
            port: 0,
            database_url: String::new(),
            secrets_encryption_key: "ab".repeat(32),
            signing_key: "cd".repeat(32),
            approval_expiry_secs: 1800,
            execution_pending_ttl_secs: 900,
            execution_replay_timeout_secs: 30,
            services_dir: "services".into(),
            google_auth_client_id: None,
            google_auth_client_secret: None,
            github_auth_client_id: None,
            github_auth_client_secret: None,
            public_url: "http://localhost:0".into(),
            dev_auth_enabled: false,
            max_response_body_bytes: 0,
            filter_timeout_ms: 0,
            dashboard_url: "/".into(),
            dashboard_origin: "*".into(),
            redis_url: None,
            default_rate_limit: 0,
            default_rate_window_secs: 0,
            allow_org_creation: true,
            single_org_mode: None,
            cloud_billing: false,
            stripe_secret_key: None,
            stripe_webhook_secret: None,
            stripe_eur_lookup_key: "x".into(),
            stripe_usd_lookup_key: "x".into(),
            stripe_eur_price_id: None,
            stripe_usd_price_id: None,
            stripe_api_base: "https://api.stripe.com/v1".into(),
            app_host_suffix: None,
            session_cookie_domain: None,
            service_base_overrides: HashMap::new(),
            oversla_sh_base_url: None,
            oversla_sh_api_key: None,
        }
    }
}
