//! `Config::from_env` and `Config::validate_env` — the boot-time read of
//! the process environment. Split out of `mod.rs` for size; Rust allows
//! multiple inherent `impl` blocks for the same type across modules of a
//! crate, so this is the same `Config` API as before.

use super::parse::*;
use super::*;
use overslash_env as env;

/// A required variable, or a panic naming it.
///
/// [`Config::validate_env`] is the operator-facing check and runs first — it
/// reports *every* missing variable at once and exits cleanly. Reaching this
/// panic means a caller built a `Config` without validating, which is a
/// programming error rather than a misconfiguration.
fn require(name: &'static str) -> String {
    env::required(name).unwrap_or_else(|e| panic!("{e}"))
}

impl Config {
    /// Load config from environment variables.
    pub fn from_env() -> Self {
        let host = env::or_default("HOST", "127.0.0.1");
        let port = env::parse_opt("PORT").unwrap_or(3000);
        let public_url =
            env::optional("PUBLIC_URL").unwrap_or_else(|| default_public_url(&host, port));
        Self {
            host,
            port,
            database_url: require("DATABASE_URL"),
            db_max_connections: env::parse_opt("DB_MAX_CONNECTIONS").unwrap_or(25),
            db_min_connections: env::parse_opt("DB_MIN_CONNECTIONS").unwrap_or(2),
            db_acquire_timeout_secs: env::parse_opt("DB_ACQUIRE_TIMEOUT_SECS").unwrap_or(10),
            db_background_max_connections: env::parse_opt("DB_BACKGROUND_MAX_CONNECTIONS")
                .unwrap_or(6),
            events_stream_max_connection_secs: env::parse_opt("EVENTS_STREAM_MAX_CONNECTION_SECS")
                .unwrap_or(30),
            secrets_encryption_key: require("SECRETS_ENCRYPTION_KEY"),
            secrets_encryption_key_previous: env::optional("SECRETS_ENCRYPTION_KEY_PREVIOUS"),
            // `_ACTIVE_ID` must be bumped on every rotation — it's the
            // version byte stamped onto new ciphertext. `_PREVIOUS_ID`
            // defaults to `_ACTIVE_ID - 1` so the common "set _PREVIOUS
            // and _ACTIVE_ID=2, forget _PREVIOUS_ID" case lands on the
            // legal (2, 1) shape. `Keyring::dual` enforces
            // `active_id > previous_id` so any misconfiguration is
            // rejected at startup (not silently in the rotation loop).
            secrets_encryption_key_active_id: secrets_encryption_key_active_id_from_env(),
            secrets_encryption_key_previous_id: secrets_encryption_key_previous_id_from_env(
                secrets_encryption_key_active_id_from_env(),
            ),
            signing_key: require("SIGNING_KEY"),
            approval_expiry_secs: env::parse_opt("APPROVAL_EXPIRY_SECS").unwrap_or(1800),
            execution_pending_ttl_secs: env::parse_opt("EXECUTION_PENDING_TTL_SECS").unwrap_or(900),
            execution_replay_timeout_secs: env::parse_opt("EXECUTION_REPLAY_TIMEOUT_SECS")
                .unwrap_or(30),
            sweep_grace_secs: env::parse_opt("SWEEP_GRACE_SECS")
                .filter(|n| *n > 0)
                .unwrap_or(60),
            call_timeout_ms: env::parse_opt("CALL_TIMEOUT_MS")
                .filter(|n| *n > 0)
                .unwrap_or(30_000),
            // Just under the 120s Cloud Run cuts at, so we return our own 504
            // with an audit row rather than letting the proxy drop the
            // connection anonymously. (The HTTPS LB sets no timeout of its
            // own — serverless-NEG backends reject `timeout_sec`.)
            call_timeout_max_ms: env::parse_opt("CALL_TIMEOUT_MAX_MS")
                .filter(|n| *n > 0)
                .unwrap_or(110_000),
            call_stream_idle_timeout_ms: env::parse_opt("CALL_STREAM_IDLE_TIMEOUT_MS")
                .filter(|n| *n > 0)
                .unwrap_or(30_000),
            async_execution: crate::config::AsyncExecutionConfig {
                enabled: env::flag("ASYNC_EXECUTION_ENABLED"),
                call_timeout_max_ms: env::parse_opt("ASYNC_CALL_TIMEOUT_MAX_MS")
                    .filter(|n| *n > 0)
                    .unwrap_or(900_000),
                worker_concurrency: env::parse_opt("ASYNC_WORKER_CONCURRENCY")
                    .filter(|n| *n > 0)
                    .unwrap_or(2),
                lease_ttl_secs: env::parse_opt("ASYNC_LEASE_TTL_SECS")
                    .filter(|n| *n > 0)
                    .unwrap_or(60),
                max_attempts: env::parse_opt("ASYNC_MAX_ATTEMPTS")
                    .filter(|n| *n > 0)
                    .unwrap_or(1),
                hybrid_handoff_ms: env::parse_opt("HYBRID_HANDOFF_MS")
                    .filter(|n| *n > 0)
                    .unwrap_or(5_000),
                hybrid_handoff_max_ms: env::parse_opt("HYBRID_HANDOFF_MAX_MS")
                    .filter(|n| *n > 0)
                    .unwrap_or(30_000),
                hybrid_max_inflight: env::parse_opt("HYBRID_MAX_INFLIGHT")
                    .filter(|n| *n > 0)
                    .unwrap_or(32),
            },
            services_dir: env::or_default("SERVICES_DIR", "services"),
            google_auth_client_id: env::optional("GOOGLE_AUTH_CLIENT_ID"),
            google_auth_client_secret: env::optional("GOOGLE_AUTH_CLIENT_SECRET"),
            github_auth_client_id: env::optional("GITHUB_AUTH_CLIENT_ID"),
            github_auth_client_secret: env::optional("GITHUB_AUTH_CLIENT_SECRET"),
            public_url,
            dev_auth_enabled: env::flag("DEV_AUTH"),
            live_map_enabled: env::flag("OVERSLASH_LIVE_MAP"),
            // Default-on; only an explicit falsey value disables it.
            magic_link_enabled: env::flag_or("MAGIC_LINK_ENABLED", true),
            max_response_body_bytes: env::parse_opt("MAX_RESPONSE_BODY_BYTES").unwrap_or(5_242_880), // 5 MB
            audit_response_body_max_bytes: env::parse_opt("AUDIT_RESPONSE_BODY_MAX_BYTES")
                .unwrap_or(65_536), // 64 KB
            filter_timeout_ms: env::parse_opt("FILTER_TIMEOUT_MS").unwrap_or(2000),
            download_token_ttl_secs: env::parse_opt("DOWNLOAD_TOKEN_TTL_SECS")
                .filter(|n| *n > 0)
                .unwrap_or(900), // 15 min
            upload_token_ttl_secs: env::parse_opt("UPLOAD_TOKEN_TTL_SECS")
                .filter(|n| *n > 0)
                .unwrap_or(900), // 15 min
            // Matches the reference container's own default. Set it lower to
            // bound what a redemption can push; raising it past what the
            // upstream accepts only moves the rejection later, to a 413 from
            // the upstream after the bytes have already crossed the wire.
            upload_max_bytes: env::parse_opt("UPLOAD_MAX_BYTES")
                .filter(|n| *n > 0)
                .unwrap_or(100 * 1024 * 1024), // 100 MiB
            // No `.filter(|n| *n > 0)` here, unlike the TTL above: 0 is a
            // meaningful value — it turns result storage off — whereas a
            // zero-second token lifetime is only ever a misconfiguration.
            call_result_max_bytes: env::parse_opt("CALL_RESULT_MAX_BYTES").unwrap_or(1024 * 1024), // 1 MB
            dashboard_url: env::or_default("DASHBOARD_URL", "/"),
            // "*localhost*" matches any http://localhost:<port> / http://127.0.0.1:<port>
            // origin so that worktrees with dynamic dashboard ports work out of the box.
            // In production set this to a comma-separated list of explicit origins.
            dashboard_origin: env::or_default("DASHBOARD_ORIGIN", "*localhost*"),
            mcp_extra_origins: env::or_default("MCP_EXTRA_ORIGINS", ""),
            redis_url: env::optional("REDIS_URL"),
            // No `.filter(|n| *n > 0)` on the TTLs: `0` is a real value that
            // turns the cache off, not a typo to fall back from.
            resolve_cache_ttl_secs: env::parse_opt("RESOLVE_CACHE_TTL_SECS").unwrap_or(300), // 5 min
            resolve_cache_negative_ttl_secs: env::parse_opt("RESOLVE_CACHE_NEGATIVE_TTL_SECS")
                .unwrap_or(30),
            resolve_cache_scope_ttl_max_secs: env::parse_opt("RESOLVE_CACHE_SCOPE_TTL_MAX_SECS")
                .unwrap_or(300), // 5 min
            resolve_cache_timeout_ms: env::parse_opt("RESOLVE_CACHE_TIMEOUT_MS")
                .filter(|n| *n > 0)
                .unwrap_or(100),
            resolve_cache_max_entries: env::parse_opt("RESOLVE_CACHE_MAX_ENTRIES")
                .filter(|n| *n > 0)
                .unwrap_or(10_000),
            resolve_cache_namespace: env::optional("RESOLVE_CACHE_NAMESPACE"),
            default_rate_limit: env::parse_opt("DEFAULT_RATE_LIMIT").unwrap_or(1000),
            default_rate_window_secs: env::parse_opt("DEFAULT_RATE_WINDOW_SECS").unwrap_or(60),
            allow_org_creation: env::flag_or("ALLOW_ORG_CREATION", true),
            trial_default_duration_days: env::parse_opt("TRIAL_DEFAULT_DURATION_DAYS")
                .filter(|d| *d > 0)
                .unwrap_or(30),
            single_org_mode: env::optional("SINGLE_ORG_MODE"),
            app_host_suffix: env::optional("APP_HOST_SUFFIX"),
            api_host_suffix: env::optional("API_HOST_SUFFIX"),
            session_cookie_domain: env::optional("SESSION_COOKIE_DOMAIN"),
            cloud_billing: env::flag("CLOUD_BILLING"),
            stripe_secret_key: env::optional("STRIPE_SECRET_KEY"),
            stripe_webhook_secret: env::optional("STRIPE_WEBHOOK_SECRET"),
            stripe_eur_lookup_key: env::optional("STRIPE_EUR_LOOKUP_KEY")
                .unwrap_or_else(|| "overslash_seat_eur".into()),
            stripe_usd_lookup_key: env::optional("STRIPE_USD_LOOKUP_KEY")
                .unwrap_or_else(|| "overslash_seat_usd".into()),
            // Populated at startup by `resolve_stripe_prices` when billing
            // is enabled — left None here so a misconfigured deploy fails
            // fast at startup instead of at first checkout.
            stripe_eur_price_id: None,
            stripe_usd_price_id: None,
            stripe_api_base: env::optional("STRIPE_API_BASE")
                .unwrap_or_else(|| "https://api.stripe.com/v1".into()),
            service_base_overrides: parse_service_base_overrides(
                env::optional("OVERSLASH_SERVICE_BASE_OVERRIDES").as_deref(),
            ),
            platform_credential: parse_platform_credential(
                env::optional("OVERSLASH_PLATFORM_GATEWAY_SECRET_NAME").as_deref(),
                env::optional("OVERSLASH_PLATFORM_GATEWAY_HOST").as_deref(),
                env::optional("OVERSLASH_PLATFORM_GATEWAY_KEY").as_deref(),
            ),
            oversla_sh_base_url: env::optional("OVERSLA_SH_BASE_URL"),
            oversla_sh_api_key: env::optional("OVERSLA_SH_API_KEY"),
            email_provider: env::optional("EMAIL_PROVIDER"),
            email_from: env::optional("EMAIL_FROM"),
            email_reply_to: env::optional("EMAIL_REPLY_TO"),
            email_api_key: env::optional("EMAIL_API_KEY"),
            preview_origin_allowlist: parse_preview_origin_allowlist(
                env::optional("PREVIEW_ORIGIN_ALLOWLIST").as_deref(),
            ),
            overslash_env: env::optional("OVERSLASH_ENV"),
            connection_return_url_allowed_hosts: parse_connection_return_url_allowed_hosts(
                env::optional("OVERSLASH_CONNECTION_RETURN_URL_HOSTS").as_deref(),
            ),
        }
    }

    /// Check for required env vars and return the list of missing ones.
    ///
    /// "Missing" means unset **or** empty — `overslash_env` treats the two
    /// alike, which matters because the substrate hands us empty strings for
    /// variables nobody set: `${FOO:-}` in a compose file, an empty Secret
    /// Manager payload. Sharing that definition with [`Config::from_env`] is
    /// the point of routing both through the same accessors; when the two
    /// disagreed about what "set" meant, a variable could pass validation and
    /// then read as absent (or the reverse) a few lines later.
    pub fn validate_env() -> Vec<&'static str> {
        let always_required = ["DATABASE_URL", "SECRETS_ENCRYPTION_KEY", "SIGNING_KEY"];
        let cloud_billing_enabled = env::flag("CLOUD_BILLING");
        // Lookup keys default to overslash_seat_{eur,usd} so they're not
        // listed here. Operators only need to set the secrets.
        let billing_required: &[&str] = if cloud_billing_enabled {
            &["STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"]
        } else {
            &[]
        };
        // EMAIL_API_KEY and EMAIL_FROM are required iff EMAIL_PROVIDER is
        // set. Mirrors the cloud_billing pattern above: a misconfigured
        // sender would otherwise silently drop receipts / welcome mail.
        let email_enabled = env::is_set("EMAIL_PROVIDER");
        let email_required: &[&str] = if email_enabled {
            &["EMAIL_API_KEY", "EMAIL_FROM"]
        } else {
            &[]
        };
        always_required
            .iter()
            .chain(billing_required.iter())
            .chain(email_required.iter())
            .filter(|k| !env::is_set(k))
            .copied()
            .collect()
    }
}
