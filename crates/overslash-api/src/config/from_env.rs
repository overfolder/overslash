//! `Config::from_env` and `Config::validate_env` — the boot-time read of
//! the process environment. Split out of `mod.rs` for size; Rust allows
//! multiple inherent `impl` blocks for the same type across modules of a
//! crate, so this is the same `Config` API as before.

use super::parse::*;
use super::*;
use std::env;

impl Config {
    /// Load config from environment variables.
    pub fn from_env() -> Self {
        let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port = env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3000);
        let public_url = env::var("PUBLIC_URL").unwrap_or_else(|_| default_public_url(&host, port));
        Self {
            host,
            port,
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL is required"),
            db_max_connections: env::var("DB_MAX_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(25),
            db_min_connections: env::var("DB_MIN_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2),
            db_acquire_timeout_secs: env::var("DB_ACQUIRE_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            db_background_max_connections: env::var("DB_BACKGROUND_MAX_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(6),
            events_stream_max_connection_secs: env::var("EVENTS_STREAM_MAX_CONNECTION_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            secrets_encryption_key: env::var("SECRETS_ENCRYPTION_KEY")
                .expect("SECRETS_ENCRYPTION_KEY is required"),
            secrets_encryption_key_previous: env::var("SECRETS_ENCRYPTION_KEY_PREVIOUS")
                .ok()
                .filter(|s| !s.is_empty()),
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
            // Default-on; only an explicit falsey value disables it.
            magic_link_enabled: env::var("MAGIC_LINK_ENABLED")
                .map(|v| !matches!(v.trim().to_lowercase().as_str(), "false" | "0" | "no"))
                .unwrap_or(true),
            max_response_body_bytes: env::var("MAX_RESPONSE_BODY_BYTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5_242_880), // 5 MB
            audit_response_body_max_bytes: env::var("AUDIT_RESPONSE_BODY_MAX_BYTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(65_536), // 64 KB
            filter_timeout_ms: env::var("FILTER_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2000),
            download_token_ttl_secs: env::var("DOWNLOAD_TOKEN_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .filter(|n| *n > 0)
                .unwrap_or(900), // 15 min
            dashboard_url: env::var("DASHBOARD_URL").unwrap_or_else(|_| "/".into()),
            // "*localhost*" matches any http://localhost:<port> / http://127.0.0.1:<port>
            // origin so that worktrees with dynamic dashboard ports work out of the box.
            // In production set this to a comma-separated list of explicit origins.
            dashboard_origin: env::var("DASHBOARD_ORIGIN").unwrap_or_else(|_| "*localhost*".into()),
            mcp_extra_origins: env::var("MCP_EXTRA_ORIGINS").unwrap_or_default(),
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
            trial_default_duration_days: env::var("TRIAL_DEFAULT_DURATION_DAYS")
                .ok()
                .and_then(|s| s.parse().ok())
                .filter(|d| *d > 0)
                .unwrap_or(30),
            single_org_mode: env::var("SINGLE_ORG_MODE").ok().filter(|s| !s.is_empty()),
            app_host_suffix: env::var("APP_HOST_SUFFIX").ok().filter(|s| !s.is_empty()),
            api_host_suffix: env::var("API_HOST_SUFFIX").ok().filter(|s| !s.is_empty()),
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
            platform_credential: parse_platform_credential(
                env::var("OVERSLASH_PLATFORM_GATEWAY_SECRET_NAME")
                    .ok()
                    .as_deref(),
                env::var("OVERSLASH_PLATFORM_GATEWAY_HOST").ok().as_deref(),
                env::var("OVERSLASH_PLATFORM_GATEWAY_KEY").ok().as_deref(),
            ),
            oversla_sh_base_url: env::var("OVERSLA_SH_BASE_URL")
                .ok()
                .filter(|s| !s.is_empty()),
            oversla_sh_api_key: env::var("OVERSLA_SH_API_KEY")
                .ok()
                .filter(|s| !s.is_empty()),
            email_provider: env::var("EMAIL_PROVIDER").ok().filter(|s| !s.is_empty()),
            email_from: env::var("EMAIL_FROM").ok().filter(|s| !s.is_empty()),
            email_reply_to: env::var("EMAIL_REPLY_TO").ok().filter(|s| !s.is_empty()),
            email_api_key: env::var("EMAIL_API_KEY").ok().filter(|s| !s.is_empty()),
            preview_origin_allowlist: parse_preview_origin_allowlist(
                env::var("PREVIEW_ORIGIN_ALLOWLIST").ok().as_deref(),
            ),
            overslash_env: env::var("OVERSLASH_ENV").ok().filter(|s| !s.is_empty()),
            connection_return_url_allowed_hosts: parse_connection_return_url_allowed_hosts(
                env::var("OVERSLASH_CONNECTION_RETURN_URL_HOSTS")
                    .ok()
                    .as_deref(),
            ),
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
        // EMAIL_API_KEY and EMAIL_FROM are required iff EMAIL_PROVIDER is
        // set. Mirrors the cloud_billing pattern above: a misconfigured
        // sender would otherwise silently drop receipts / welcome mail.
        let email_enabled = env::var("EMAIL_PROVIDER")
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let email_required: &[&str] = if email_enabled {
            &["EMAIL_API_KEY", "EMAIL_FROM"]
        } else {
            &[]
        };
        always_required
            .iter()
            .chain(billing_required.iter())
            .chain(email_required.iter())
            .filter(|k| env::var(k).map(|v| v.is_empty()).unwrap_or(true))
            .copied()
            .collect()
    }
}
