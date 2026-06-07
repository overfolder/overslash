use std::collections::HashMap;
use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    /// 64-char hex master key used to encrypt every secret value, OAuth
    /// token, BYOC client_id/secret, and IdP credential. Wrapped at runtime
    /// in a [`overslash_core::crypto::Keyring`] together with
    /// `secrets_encryption_key_previous` so the operator can rotate the
    /// master key with zero downtime — see `docs/runbooks/` (forthcoming).
    pub secrets_encryption_key: String,
    /// Optional second master key, decrypt-only. Set during a rotation to
    /// the *prior* key so existing blobs stay readable while the
    /// re-encrypt loop rewrites every row under the new active key. Unset
    /// at rest.
    pub secrets_encryption_key_previous: Option<String>,
    /// Key id (1..=255) tagged onto every blob written with
    /// `secrets_encryption_key`. Default 1. **Must be bumped on every
    /// rotation** so old blobs (still tagged with the previous id)
    /// decrypt via the `_previous` slot and so the re-encrypt loop's
    /// fast-path skip stays sound.
    pub secrets_encryption_key_active_id: u8,
    /// Key id (1..=255) of the previous master key. Must be **strictly
    /// less than** `secrets_encryption_key_active_id`. Defaults to
    /// `active_id - 1` so the typical `(active=2, previous=1)` rotation
    /// shape works without setting it explicitly. Ignored unless
    /// `secrets_encryption_key_previous` is set.
    pub secrets_encryption_key_previous_id: u8,
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
    /// Truncation cap for upstream response bodies persisted on
    /// `action.executed` audit rows (when the org's
    /// `audit_response_body_mode` enables capture). Bytes of the
    /// already-decoded body string, not the wire size.
    pub audit_response_body_max_bytes: usize,
    pub filter_timeout_ms: u64,
    pub dashboard_url: String,
    pub dashboard_origin: String,
    /// Additional CORS origins allowed *only* on MCP transport
    /// (`/mcp`) and the OAuth metadata / DCR / token endpoints
    /// (`/.well-known/oauth-*`, `/oauth/*`). Comma-separated.
    /// Used to let a locally-run MCP Inspector at e.g.
    /// `http://localhost:6274` complete the OAuth handshake against a
    /// deployed API without widening CORS on the rest of the surface
    /// (`/v1/*` etc.). Default empty.
    pub mcp_extra_origins: String,
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
    /// e.g. `app.overslash.com`. The dashboard surface — browsers run on
    /// `<slug>.app.overslash.com`. When unset, subdomain routing is disabled
    /// for this surface. Leave unset in local dev; tests set this explicitly.
    pub app_host_suffix: Option<String>,
    /// Optional apex for the programmatic surface (MCP, OAuth AS metadata,
    /// REST). e.g. `api.overslash.com`. Both suffixes are accepted by the
    /// subdomain middleware; `.well-known` issuers built on a corp subdomain
    /// prefer this one because programmatic clients hit Cloud Run directly.
    pub api_host_suffix: Option<String>,
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
    /// Transactional-email provider key. `Some("resend")` selects the Resend
    /// implementation; any other value (or `None`) falls back to the no-op
    /// mailer so local/dev/test boots don't require credentials.
    pub email_provider: Option<String>,
    /// `From` address used for all outbound transactional mail
    /// (e.g. `no-reply@overslash.com`). Must be a domain Resend is
    /// authorised to send for. Required when `email_provider` is set.
    pub email_from: Option<String>,
    /// Optional `Reply-To` address. When `None`, the provider applies its
    /// default (usually `From`).
    pub email_reply_to: Option<String>,
    /// Raw provider API key (Resend `re_…` token). Stored as an env var
    /// alongside `stripe_secret_key` and `oversla_sh_api_key` — Cloud Run
    /// surfaces Secret Manager values this way.
    pub email_api_key: Option<String>,
    /// Vercel preview-deployment OAuth handoff allowlist. When set on a
    /// `OVERSLASH_ENV=dev` deployment, the API will accept a `preview_origin`
    /// query param on `/auth/login/<provider>`, embed an opaque preview-id
    /// in the OAuth state, and after callback bounce the user to
    /// `<preview_origin>/auth/handoff?code=...` so the preview can adopt the
    /// session via a host-only cookie set on the proxied response. The
    /// allowlist is fail-closed: an invalid regex disables the feature; a
    /// non-dev `OVERSLASH_ENV` disables it; an empty value disables it. The
    /// production deployment must never set this.
    pub preview_origin_allowlist: Option<regex::Regex>,
    /// Deployment environment marker (`dev`, `staging`, `prod`, …). Used as
    /// a defense-in-depth gate alongside `preview_origin_allowlist`: the
    /// preview-handoff feature is off unless this is exactly `dev`.
    pub overslash_env: Option<String>,
    /// Hosts the OAuth callback is willing to 302 to when the create-flow
    /// caller supplied a `return_url`. Operator-owned allow-list — without
    /// it, an attacker who can fabricate a state could fish OAuth completion
    /// state through an arbitrary URL. Comma-separated host list from
    /// `OVERSLASH_CONNECTION_RETURN_URL_HOSTS` (e.g.
    /// `cloud.overfolder.com,localhost`); matched exact + lowercase. An
    /// empty list disables the redirect feature entirely (callback falls
    /// back to the historical JSON response).
    pub connection_return_url_allowed_hosts: Vec<String>,
}

/// Parse the `PREVIEW_ORIGIN_ALLOWLIST` env var into a compiled regex.
/// Fail-closed: any error (empty string, invalid regex syntax) returns
/// None and the preview-handoff feature stays off. We also log the
/// failure so an operator who fat-fingers the regex notices instead of
/// silently disabling the feature.
///
/// Wraps the user pattern in `^(?:<pat>)$` so `is_match` does a
/// full-string match. Without this, an unanchored config like
/// `overslash\.vercel\.app` would let `overslash.vercel.app.attacker.com`
/// pass — the partial-match default would be a session-theft footgun.
/// Wrapping is idempotent for already-anchored patterns: `^foo$` becomes
/// `^(?:^foo$)$`, which the regex engine collapses to the same
/// language as `^foo$`.
fn parse_preview_origin_allowlist(raw: Option<&str>) -> Option<regex::Regex> {
    let pattern = raw.map(str::trim).filter(|s| !s.is_empty())?;
    let anchored = format!("^(?:{pattern})$");
    match regex::Regex::new(&anchored) {
        Ok(re) => Some(re),
        Err(e) => {
            tracing::warn!(
                pattern = pattern,
                error = %e,
                "PREVIEW_ORIGIN_ALLOWLIST regex did not compile; preview handoff disabled",
            );
            None
        }
    }
}

fn parse_connection_return_url_allowed_hosts(raw: Option<&str>) -> Vec<String> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Vec::new();
    };
    s.split(',')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect()
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
/// Parse `SECRETS_ENCRYPTION_KEY_ACTIVE_ID` from the env. Defaults to `1`
/// when unset. **Panics** if set to a value that doesn't parse as a `u8`
/// (e.g. `256`, `0x02`, `two`) — silently folding such typos back to the
/// default `1` would re-tag fresh writes with the historical key id while
/// the active slot holds new key bytes, so old blobs (tagged id=1, old
/// key) would stop decrypting at runtime. Better to surface the typo at
/// boot, in the same `from_env` panic-on-misconfig path the required env
/// vars use.
fn secrets_encryption_key_active_id_from_env() -> u8 {
    match env::var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID") {
        Err(_) => 1,
        Ok(s) if s.is_empty() => 1,
        Ok(s) => s.parse::<u8>().unwrap_or_else(|_| {
            panic!("SECRETS_ENCRYPTION_KEY_ACTIVE_ID must be a u8 (1..=255), got {s:?}")
        }),
    }
}

/// Parse `SECRETS_ENCRYPTION_KEY_PREVIOUS_ID` from the env. Defaults to
/// `active_id - 1` (the only legal rotation shape) when unset. Same
/// fail-fast posture as the active-id helper.
fn secrets_encryption_key_previous_id_from_env(active_id: u8) -> u8 {
    match env::var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID") {
        Err(_) => active_id.saturating_sub(1),
        Ok(s) if s.is_empty() => active_id.saturating_sub(1),
        Ok(s) => s.parse::<u8>().unwrap_or_else(|_| {
            panic!("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID must be a u8 (1..=255), got {s:?}")
        }),
    }
}

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
    /// Build the [`Keyring`](overslash_core::crypto::Keyring) used by every
    /// encrypt/decrypt call. Returns a single-key keyring at rest and a
    /// dual-key (active + previous) one during a rotation.
    ///
    /// Cheap enough to call per-request: `parse_hex_key` runs over a fixed
    /// 64-char hex string, matching the per-call cost of the
    /// `parse_hex_key(&state.config.secrets_encryption_key)` pattern that
    /// every encrypt/decrypt site used before the keyring was wired up.
    pub fn keyring(
        &self,
    ) -> Result<overslash_core::crypto::Keyring, overslash_core::crypto::CryptoError> {
        overslash_core::crypto::Keyring::from_hex(
            &self.secrets_encryption_key,
            self.secrets_encryption_key_active_id,
            self.secrets_encryption_key_previous.as_deref(),
            self.secrets_encryption_key_previous_id,
        )
    }

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

    /// Whether the Vercel preview-deployment OAuth handoff is enabled. Both
    /// gates must be on: `OVERSLASH_ENV=dev` (deployment marker) and a
    /// well-formed `PREVIEW_ORIGIN_ALLOWLIST` regex. Either missing → off.
    /// Defense in depth: even if a non-dev deployment accidentally ships
    /// the allowlist, the env mismatch keeps the endpoint 404 and the
    /// callback rejects 4-segment state params.
    pub fn is_preview_handoff_enabled(&self) -> bool {
        self.overslash_env.as_deref() == Some("dev") && self.preview_origin_allowlist.is_some()
    }

    /// Test the candidate origin against the allowlist regex. Returns false
    /// when the feature is disabled or the candidate doesn't match.
    pub fn preview_origin_allowed(&self, candidate: &str) -> bool {
        if !self.is_preview_handoff_enabled() {
            return false;
        }
        match self.preview_origin_allowlist.as_ref() {
            Some(re) => re.is_match(candidate),
            None => false,
        }
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

    // ── connection_return_url_allowed_hosts ─────────────────────────────
    //
    // The OAuth callback uses this list as its fail-closed gate on whether
    // to honour a flow row's `return_url` (see
    // `routes/connections.rs::resolve_redirect_target`). An empty list
    // *disables* the redirect feature entirely. Parsing has to be
    // forgiving (operators set comma-separated env vars by hand) but never
    // silently widen the host set.

    #[test]
    fn parse_connection_return_url_hosts_handles_multiple_entries() {
        let hosts = parse_connection_return_url_allowed_hosts(Some(
            "cloud.overfolder.com,cloud-dev.overfolder.com,localhost",
        ));
        assert_eq!(
            hosts,
            vec![
                "cloud.overfolder.com".to_string(),
                "cloud-dev.overfolder.com".to_string(),
                "localhost".to_string(),
            ]
        );
    }

    #[test]
    fn parse_connection_return_url_hosts_lowercases_and_trims() {
        // The callback's allow-list check lowercases the URL's host_str()
        // before comparing — entries must come out of the parser in the
        // same shape or a `Cloud.Overfolder.COM` allow-list entry would
        // silently never match a `cloud.overfolder.com` host.
        let hosts =
            parse_connection_return_url_allowed_hosts(Some("  Cloud.Overfolder.COM ,  Localhost "));
        assert_eq!(
            hosts,
            vec!["cloud.overfolder.com".to_string(), "localhost".to_string()]
        );
    }

    #[test]
    fn parse_connection_return_url_hosts_empty_disables_feature() {
        // Empty / unset / whitespace-only all mean "the operator did not
        // opt in" and the callback path stays on the historical JSON
        // response. Important that none of these silently parse as a list
        // with an empty-string entry that could be matched by a bug.
        assert!(parse_connection_return_url_allowed_hosts(None).is_empty());
        assert!(parse_connection_return_url_allowed_hosts(Some("")).is_empty());
        assert!(parse_connection_return_url_allowed_hosts(Some("   ")).is_empty());
        assert!(parse_connection_return_url_allowed_hosts(Some(",,,")).is_empty());
    }

    #[test]
    fn parse_connection_return_url_hosts_skips_blank_entries() {
        // Operators occasionally leave a trailing comma or double-comma
        // in env-var syntax. Drop the empties; keep the rest.
        let hosts =
            parse_connection_return_url_allowed_hosts(Some(",cloud.overfolder.com, ,localhost,"));
        assert_eq!(
            hosts,
            vec!["cloud.overfolder.com".to_string(), "localhost".to_string()]
        );
    }

    #[test]
    fn from_env_loads_connection_return_url_hosts() {
        // The full `from_env` boot path. Exercises that the env-var name
        // is wired correctly and that the parser feeds Config without
        // mangling. We can't call `Config::from_env()` itself (it expects
        // DATABASE_URL / SECRETS_ENCRYPTION_KEY / SIGNING_KEY to be set
        // and panics otherwise), so the assertion mirrors the read-line
        // in `from_env`.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var(
                "OVERSLASH_CONNECTION_RETURN_URL_HOSTS",
                "cloud.overfolder.com,localhost",
            );
        }
        let hosts = parse_connection_return_url_allowed_hosts(
            std::env::var("OVERSLASH_CONNECTION_RETURN_URL_HOSTS")
                .ok()
                .as_deref(),
        );
        unsafe {
            std::env::remove_var("OVERSLASH_CONNECTION_RETURN_URL_HOSTS");
        }
        assert_eq!(
            hosts,
            vec!["cloud.overfolder.com".to_string(), "localhost".to_string()]
        );
    }

    #[test]
    fn from_env_unset_connection_return_url_hosts_disables_feature() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::remove_var("OVERSLASH_CONNECTION_RETURN_URL_HOSTS");
        }
        let hosts = parse_connection_return_url_allowed_hosts(
            std::env::var("OVERSLASH_CONNECTION_RETURN_URL_HOSTS")
                .ok()
                .as_deref(),
        );
        assert!(hosts.is_empty());
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

    /// Resolve overrides under a stable env state and release the lock
    /// before any assertion runs — a panic inside `assert_eq!` would
    /// otherwise poison `ENV_LOCK` and convert sibling-test failures into
    /// `PoisonError`s, hiding the real cause.
    fn with_env_locked<R>(set_bypass: bool, f: impl FnOnce() -> R) -> R {
        // Tolerate a prior poisoning so a single failing test doesn't
        // cascade into "all env-touching tests fail" — `into_inner()`
        // hands back the wrapped guard regardless of poisoning state.
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: ENV_LOCK serialises env mutations across this cohort,
        // and `apply_base_overrides` reads the env at call time.
        unsafe {
            if set_bypass {
                env::set_var("OVERSLASH_SSRF_ALLOW_PRIVATE", "1");
            } else {
                env::remove_var("OVERSLASH_SSRF_ALLOW_PRIVATE");
            }
        }
        let out = f();
        // Always reset to the unset state so subsequent acquirers don't
        // observe leaked bypass enablement.
        unsafe {
            env::remove_var("OVERSLASH_SSRF_ALLOW_PRIVATE");
        }
        drop(guard);
        out
    }

    #[test]
    fn apply_base_overrides_drops_non_loopback_target_without_ssrf_bypass() {
        // Without OVERSLASH_SSRF_ALLOW_PRIVATE, a non-loopback override is
        // silently ignored — guards prod deploys against accidentally-set vars.
        let mut cfg = empty_test_config();
        cfg.service_base_overrides.insert(
            "api.github.com".into(),
            "https://attacker.example.com".into(),
        );
        let resolved = with_env_locked(false, || {
            cfg.apply_base_overrides("https://api.github.com/x")
        });
        assert_eq!(resolved, "https://api.github.com/x");
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
        let mut cfg = empty_test_config();
        cfg.service_base_overrides
            .insert("api.github.com".into(), "http://127.0.0.1:9101".into());
        cfg.service_base_overrides.insert(
            "api.attacker.test".into(),
            "https://attacker.example.com".into(),
        );
        let (allowed, rejected, untouched) = with_env_locked(false, || {
            (
                cfg.apply_base_overrides("https://api.github.com/repos/x/y?per_page=5"),
                cfg.apply_base_overrides("https://api.attacker.test/foo"),
                cfg.apply_base_overrides("https://api.slack.com/x"),
            )
        });
        assert_eq!(allowed, "http://127.0.0.1:9101/repos/x/y?per_page=5");
        assert_eq!(rejected, "https://api.attacker.test/foo");
        assert_eq!(untouched, "https://api.slack.com/x");
    }

    #[test]
    fn apply_base_overrides_keeps_non_loopback_target_with_ssrf_bypass() {
        // Inverse of the rejection case: when OVERSLASH_SSRF_ALLOW_PRIVATE=1
        // (the e2e profile turns this on so loopback fakes are reachable)
        // the gate's loopback-only check is bypassed and *every* override
        // entry applies — including non-loopback ones. The bypass is the
        // single audited escape hatch for tests; the production binary never
        // sets it.
        let mut cfg = empty_test_config();
        cfg.service_base_overrides.insert(
            "api.attacker.test".into(),
            "https://attacker.example.com".into(),
        );
        let resolved = with_env_locked(true, || {
            cfg.apply_base_overrides("https://api.attacker.test/foo")
        });
        assert_eq!(resolved, "https://attacker.example.com/foo");
    }

    #[test]
    fn parse_preview_origin_allowlist_disabled_when_empty_or_invalid() {
        assert!(parse_preview_origin_allowlist(None).is_none());
        assert!(parse_preview_origin_allowlist(Some("")).is_none());
        assert!(parse_preview_origin_allowlist(Some("   ")).is_none());
        // Unbalanced group — regex compile fails, fall back to disabled.
        assert!(parse_preview_origin_allowlist(Some("(unbalanced")).is_none());
    }

    #[test]
    fn parse_preview_origin_allowlist_compiles_valid_pattern() {
        let re =
            parse_preview_origin_allowlist(Some(r"^https://overslash-[a-z0-9-]+\.vercel\.app$"))
                .expect("compiles");
        assert!(re.is_match("https://overslash-feat-x.vercel.app"));
        assert!(!re.is_match("https://attacker.example.com"));
    }

    #[test]
    fn parse_preview_origin_allowlist_full_string_matches_even_unanchored_input() {
        // An operator who forgets to anchor their regex must not create a
        // session-theft hole. Substring matches like "...vercel.app..."
        // could otherwise pass.
        let re = parse_preview_origin_allowlist(Some(r"https://allowed\.preview\.test"))
            .expect("compiles");
        assert!(re.is_match("https://allowed.preview.test"));
        assert!(
            !re.is_match("https://allowed.preview.test.attacker.com"),
            "unanchored pattern must not be exploitable via suffix injection"
        );
        assert!(
            !re.is_match("https://prefix.allowed.preview.test"),
            "unanchored pattern must not be exploitable via prefix injection"
        );
    }

    #[test]
    fn parse_preview_origin_allowlist_anchoring_is_idempotent() {
        // Already-anchored input must keep working — the wrapper is
        // `^(?:<pat>)$`, so `^foo$` becomes `^(?:^foo$)$` which is the
        // same language as `^foo$`.
        let re = parse_preview_origin_allowlist(Some(r"^foo$")).expect("compiles");
        assert!(re.is_match("foo"));
        assert!(!re.is_match("foofoo"));
        assert!(!re.is_match("xfoo"));
    }

    #[test]
    fn parse_preview_origin_allowlist_alternation_anchors_each_branch() {
        // `foo|bar` becomes `^(?:foo|bar)$` — both branches must be
        // full-string-matched, not just the first.
        let re = parse_preview_origin_allowlist(Some("foo|bar")).expect("compiles");
        assert!(re.is_match("foo"));
        assert!(re.is_match("bar"));
        assert!(!re.is_match("foobar"));
        assert!(!re.is_match("xfoo"));
        assert!(!re.is_match("barx"));
    }

    #[test]
    fn preview_handoff_gate_requires_dev_env_and_allowlist() {
        let mut cfg = empty_test_config();
        // Both off → disabled.
        assert!(!cfg.is_preview_handoff_enabled());
        // Allowlist alone → still disabled (defense in depth).
        cfg.preview_origin_allowlist = Some(regex::Regex::new("^https://x$").unwrap());
        assert!(!cfg.is_preview_handoff_enabled());
        // Wrong env value → disabled.
        cfg.overslash_env = Some("staging".into());
        assert!(!cfg.is_preview_handoff_enabled());
        // Both on → enabled.
        cfg.overslash_env = Some("dev".into());
        assert!(cfg.is_preview_handoff_enabled());
        // Drop allowlist → disabled again.
        cfg.preview_origin_allowlist = None;
        assert!(!cfg.is_preview_handoff_enabled());
    }

    #[test]
    fn preview_origin_allowed_returns_false_when_disabled() {
        let mut cfg = empty_test_config();
        cfg.preview_origin_allowlist = Some(regex::Regex::new("^https://ok$").unwrap());
        // overslash_env not set → feature off → never allowed even when match.
        assert!(!cfg.preview_origin_allowed("https://ok"));
    }

    // ── Config::keyring() accessor ───────────────────────────────────────

    #[test]
    fn keyring_builds_single_key_when_previous_unset() {
        let cfg = empty_test_config();
        let kr = cfg.keyring().expect("single-key keyring builds");
        assert_eq!(kr.active_id(), 1);
        assert_eq!(kr.previous_id(), None);
    }

    #[test]
    fn keyring_builds_dual_when_previous_set() {
        let mut cfg = empty_test_config();
        cfg.secrets_encryption_key = "cd".repeat(32);
        cfg.secrets_encryption_key_previous = Some("ab".repeat(32));
        cfg.secrets_encryption_key_active_id = 2;
        cfg.secrets_encryption_key_previous_id = 1;
        let kr = cfg.keyring().expect("dual-key keyring builds");
        assert_eq!(kr.active_id(), 2);
        assert_eq!(kr.previous_id(), Some(1));
    }

    #[test]
    fn keyring_rejects_inverted_ids() {
        // active_id < previous_id → Keyring::dual rejects, surfacing the
        // misconfig at boot rather than silently mis-tagging blobs.
        let mut cfg = empty_test_config();
        cfg.secrets_encryption_key_previous = Some("cd".repeat(32));
        cfg.secrets_encryption_key_active_id = 1;
        cfg.secrets_encryption_key_previous_id = 2;
        assert!(cfg.keyring().is_err());
    }

    #[test]
    fn keyring_rejects_invalid_hex() {
        let mut cfg = empty_test_config();
        cfg.secrets_encryption_key = "not-hex".into();
        assert!(cfg.keyring().is_err());
    }

    #[test]
    fn keyring_treats_empty_previous_as_unset() {
        let mut cfg = empty_test_config();
        cfg.secrets_encryption_key_previous = Some(String::new());
        let kr = cfg.keyring().expect("empty previous folds to single-key");
        assert_eq!(kr.previous_id(), None);
    }

    // ── env-var helpers ──────────────────────────────────────────────────

    #[test]
    fn previous_id_defaults_to_active_minus_one() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID");
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID");
        }
        assert_eq!(secrets_encryption_key_active_id_from_env(), 1);
        assert_eq!(
            secrets_encryption_key_previous_id_from_env(secrets_encryption_key_active_id_from_env()),
            0,
            "previous_id defaults to active_id - 1 (0 when active is 1)"
        );
    }

    #[test]
    fn active_id_reads_env_when_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID", "7");
        }
        assert_eq!(secrets_encryption_key_active_id_from_env(), 7);
        unsafe {
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID");
        }
    }

    #[test]
    fn previous_id_reads_env_when_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID", "5");
        }
        assert_eq!(secrets_encryption_key_previous_id_from_env(8), 5);
        unsafe {
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID");
        }
    }

    #[test]
    fn active_id_panics_on_unparseable_value() {
        // Silent fallback to 1 would be unsafe: typo'd `_ACTIVE_ID=256`
        // would re-tag new writes with the historical id while the
        // active slot holds new key bytes, breaking decryption of every
        // old blob. The helper must surface the typo.
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID", "256");
        }
        let panicked = std::panic::catch_unwind(secrets_encryption_key_active_id_from_env).is_err();
        unsafe {
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID");
        }
        assert!(panicked, "out-of-range u8 must panic at startup");
    }

    #[test]
    fn active_id_panics_on_non_numeric_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID", "not-a-number");
        }
        let panicked = std::panic::catch_unwind(secrets_encryption_key_active_id_from_env).is_err();
        unsafe {
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID");
        }
        assert!(panicked, "non-numeric value must panic at startup");
    }

    #[test]
    fn previous_id_panics_on_unparseable_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID", "not-a-number");
        }
        let panicked =
            std::panic::catch_unwind(|| secrets_encryption_key_previous_id_from_env(2)).is_err();
        unsafe {
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID");
        }
        assert!(panicked, "non-numeric previous_id must panic at startup");
    }

    #[test]
    fn empty_env_falls_back_to_default() {
        // Empty string is treated as "unset" — Cloud Run secret mounts
        // sometimes materialise unset vars as empty strings.
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID", "");
            std::env::set_var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID", "");
        }
        assert_eq!(secrets_encryption_key_active_id_from_env(), 1);
        assert_eq!(secrets_encryption_key_previous_id_from_env(3), 2);
        unsafe {
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID");
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID");
        }
    }

    fn empty_test_config() -> Config {
        Config {
            host: "127.0.0.1".into(),
            port: 0,
            database_url: String::new(),
            secrets_encryption_key: "ab".repeat(32),
            secrets_encryption_key_previous: None,
            secrets_encryption_key_active_id: 1,
            secrets_encryption_key_previous_id: 0,
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
            audit_response_body_max_bytes: 0,
            filter_timeout_ms: 0,
            dashboard_url: "/".into(),
            dashboard_origin: "*".into(),
            mcp_extra_origins: String::new(),
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
            api_host_suffix: None,
            session_cookie_domain: None,
            service_base_overrides: HashMap::new(),
            oversla_sh_base_url: None,
            oversla_sh_api_key: None,
            email_provider: None,
            email_from: None,
            email_reply_to: None,
            email_api_key: None,
            preview_origin_allowlist: None,
            overslash_env: None,
            connection_return_url_allowed_hosts: Vec::new(),
        }
    }
}
