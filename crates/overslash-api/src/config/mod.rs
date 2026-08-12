//! Runtime configuration for the API process.
//!
//! This module owns the [`Config`] struct, [`PlatformCredential`] and the
//! accessor/derivation half of `impl Config`. The env-var parsing helpers
//! live in the private `parse` submodule; `Config::from_env` /
//! `Config::validate_env` live in the private `from_env` submodule.

use std::collections::HashMap;

mod from_env;
mod parse;

pub use parse::default_public_url;

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    /// Max connections in the *request-handler* pool. Shared by every HTTP
    /// handler. Default 25. `DB_MAX_CONNECTIONS`. The prior code used sqlx's
    /// bare default of 10, which — shared with ~7 background loops on the same
    /// pool — starved under burst and fired the 30s acquire timeout (dropped
    /// `connection.*` webhooks on overslash-dev). Cloud Run maxScale 3 × 25 =
    /// 75, comfortably under the Postgres app ceiling (~97).
    pub db_max_connections: u32,
    /// Min idle connections kept warm in the request-handler pool. Default 2.
    /// `DB_MIN_CONNECTIONS`.
    pub db_min_connections: u32,
    /// Seconds to wait for a free connection before erroring. Default 10.
    /// `DB_ACQUIRE_TIMEOUT_SECS`. Lower than sqlx's 30s default so a starved
    /// pool surfaces fast instead of blocking a handler for half a minute.
    pub db_acquire_timeout_secs: u64,
    /// Max connections in the dedicated *background-jobs* pool (expiry sweeps,
    /// webhook retry/digest, embedding backfill). Default 6. `DB_BACKGROUND_MAX_CONNECTIONS`.
    /// Isolating the loops onto their own small pool means a webhook/expiry
    /// burst can never starve request handling — the root cause of the
    /// overslash-dev pool-exhaustion incident.
    ///
    /// One connection is held permanently by the event-stream `LISTEN` task,
    /// which is why the default is 6 rather than the 5 the loops alone needed.
    pub db_background_max_connections: u32,
    /// How long a single `GET /v1/events/stream` connection lives before the
    /// server closes it. Default 30s per SPEC.md §10: a short, fixed ceiling
    /// keeps idle connections cheap, survives proxies that cap request
    /// duration, and forces clients to exercise `Last-Event-ID` resume
    /// continuously rather than discovering it broken during an outage.
    /// Tests set it low to keep runtimes sane. `EVENTS_STREAM_MAX_CONNECTION_SECS`.
    pub events_stream_max_connection_secs: u64,
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
    /// Floor for the outer wall-clock guard on the synchronous replay inside
    /// `POST /v1/approvals/{id}/call`. Beyond the wall the row is finalised as
    /// `failed` with `error='replay_timeout'`.
    ///
    /// Since D56 this is no longer the timeout a caller feels — that is
    /// resolved per call by [`crate::services::call_timeout`]. This is the
    /// crash-recovery backstop that also covers the DB work, filtering, and
    /// finalisation *after* the upstream returns, so it must never sit below
    /// the largest per-call timeout the resolver can hand out. Read it through
    /// [`Config::replay_wall_clock`], never directly.
    pub execution_replay_timeout_secs: u64,
    /// Default upstream timeout, in milliseconds, for an action call that
    /// names no timeout of its own and whose template and org say nothing.
    /// The bottom rung of the D56 cascade.
    pub call_timeout_ms: u64,
    /// Hard ceiling on any resolved per-call timeout — the synchronous budget.
    ///
    /// Sized to sit just under the deployment's own request cap (Cloud Run cuts
    /// at 120s; the HTTPS LB sets no timeout, because serverless-NEG backends
    /// reject `timeout_sec`), so a call fails with our 504 and a
    /// real audit row rather than an opaque proxy timeout. It is a *config*
    /// knob rather than a constant precisely because a self-hosted deploy
    /// behind no such proxy has no reason to inherit our 120s.
    pub call_timeout_max_ms: u64,
    /// Per-chunk idle timeout for streamed response bodies.
    ///
    /// Streaming deliberately does not take the resolved call timeout as a
    /// total deadline — that would mean "your 900MB export fails at exactly
    /// 90s", which is the opposite of what streaming is for. The resolved
    /// timeout bounds time-to-first-byte; this bounds the gap between chunks,
    /// so a stalled transfer still dies while a slow-but-live one does not.
    pub call_stream_idle_timeout_ms: u64,
    /// Async execution. See [`AsyncExecutionConfig`].
    pub async_execution: AsyncExecutionConfig,
    pub services_dir: String,
    pub google_auth_client_id: Option<String>,
    pub google_auth_client_secret: Option<String>,
    pub github_auth_client_id: Option<String>,
    pub github_auth_client_secret: Option<String>,
    pub public_url: String,
    pub dev_auth_enabled: bool,
    /// Live Map (`/map` in the dashboard) and the per-call `action.*` events
    /// that feed it. Off unless `OVERSLASH_LIVE_MAP` is set, because emission
    /// costs one durable `events` row per action call — the hottest path in
    /// the system. Reported on `GET /v1/version` so the dashboard knows
    /// whether to offer the view at all.
    pub live_map_enabled: bool,
    /// Passwordless email magic-link login. Default-on: it needs no external
    /// IdP credentials, so it's the working login on a fresh self-hosted
    /// deploy. Set `MAGIC_LINK_ENABLED=false` to disable (e.g. an org that
    /// mandates SSO). Surfaced on the root login page and gates both
    /// `/auth/magic-link/*` endpoints.
    pub magic_link_enabled: bool,
    pub max_response_body_bytes: usize,
    /// Truncation cap for upstream response bodies persisted on
    /// `action.executed` audit rows (when the org's
    /// `audit_response_body_mode` enables capture). Bytes of the
    /// already-decoded body string, not the wire size.
    pub audit_response_body_max_bytes: usize,
    pub filter_timeout_ms: u64,
    /// Lifetime of a deferred-download capability token (`deliver: "url"`).
    ///
    /// The token travels in an action result — which for an agent means it
    /// lands in a context window and possibly a transcript — so the window in
    /// which a leaked URL is useful is exactly this. Kept short by default;
    /// long enough that an agent can hand the URL to a shell and let a large
    /// file finish transferring, including a retry or two.
    pub download_token_ttl_secs: i64,
    /// Ceiling on the plaintext size of a stored call result.
    ///
    /// A truncated compact render stores the full `ActionResult` so the same
    /// bytes can be delivered again without re-running upstream. That store is
    /// bounded well under `max_response_body_bytes`: 5 MB per cropped call is
    /// heavy write amplification for a "let me look again" cache, and a payload
    /// that large wants `deliver: "url"` up front anyway. Over the cap nothing
    /// is stored and the caller is told why — a *partial* stored copy would be
    /// worse than none, since the agent would fetch it and believe it complete.
    ///
    /// `0` disables result storage entirely.
    pub call_result_max_bytes: usize,
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
    /// Default length (in days) of a trial, used both by the instance-admin
    /// "start trial" endpoint when no explicit duration is given and by the
    /// self-serve Stripe trial (`subscription_data[trial_period_days]`).
    /// Default 30 (~1 month).
    pub trial_default_duration_days: u32,
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
    /// Credential this deployment supplies on an org's behalf, for a service
    /// it hosts itself. `None` on a deployment that hosts no such service —
    /// every self-host, and any env where the three vars aren't all set.
    ///
    /// See [`PlatformCredential`] for why it is one entry and not a map.
    pub platform_credential: Option<PlatformCredential>,
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

/// A credential the *platform* holds on every org's behalf, for a service the
/// platform itself hosts — today only the shared overfwd Mailbox Gateway
/// (`services/email.yaml`, D39).
///
/// It sits one rung below the org vault in the credential cascade: an org that
/// stores the named secret, or binds it per instance, still wins. And it is
/// pinned to a single `host`, because the whole point of the shared gateway is
/// that a *different* org can point its instances at its own deployment — that
/// deployment must never receive our key.
///
/// Deliberately one entry rather than a map keyed by secret name: there is
/// exactly one platform-hosted upstream, and a map would invite filling
/// third-party credentials from platform env, which is what
/// `OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS` (OAuth clients, tier 4)
/// already exists to gate loudly. Generalise when a second one appears.
#[derive(Debug, Clone)]
pub struct PlatformCredential {
    /// Vault secret name this fills — `overfwd_gateway_key`. Matched against a
    /// credential slot's `default_secret_name`.
    pub secret_name: String,
    /// The only host the value may be sent to, lowercased.
    pub host: String,
    /// The credential itself. Cloud Run surfaces the Secret Manager value as
    /// an env var, same as `stripe_secret_key` and friends.
    pub value: String,
}

/// Async (non-blocking) action execution — see DECISIONS D62.
///
/// Nested rather than five flat `Config` fields on purpose. Every `Config`
/// field has to be repeated in the test builder and in ~14 test fixtures that
/// list fields explicitly, so five flat knobs would be ~75 mechanical edits and
/// every future async knob another 15. One nested field costs one line each.
#[derive(Clone, Debug)]
pub struct AsyncExecutionConfig {
    /// `ASYNC_EXECUTION_ENABLED`. Off means `execution: "async"` is rejected at
    /// the boundary and no worker or signal handler is spawned, so a
    /// flag-off deployment behaves exactly as it did before this feature.
    pub enabled: bool,
    /// `ASYNC_CALL_TIMEOUT_MAX_MS`. The deployment ceiling for an async call,
    /// passed to the same `call_timeout::resolve` the sync path uses.
    ///
    /// Much larger than `call_timeout_max_ms` because that number exists to sit
    /// under a proxy's request cap, and no proxy is counting an async call. The
    /// binding constraints instead are instance lifetime (Cloud Run may recycle
    /// at any time) and retry economics (`max_attempts` defaults to 1, so a lost
    /// job is a failed job).
    pub call_timeout_max_ms: u64,
    /// `ASYNC_WORKER_CONCURRENCY`. Jobs one replica runs at once.
    ///
    /// Default 2 is a *connection* budget, not a throughput guess: the request
    /// pool (25) plus the background pool (6) is 31 per instance, and with
    /// `max_instances = 3` that is 93 against a Postgres ceiling around 97.
    /// Raising this requires raising `DB_BACKGROUND_MAX_CONNECTIONS` by the
    /// same amount, and 3 x (DB_MAX_CONNECTIONS + DB_BACKGROUND_MAX_CONNECTIONS)
    /// must stay under that ceiling.
    pub worker_concurrency: usize,
    /// `ASYNC_LEASE_TTL_SECS`. How long a claim stays valid without a
    /// heartbeat. Independent of job duration — the heartbeat is what keeps a
    /// long job alive — so this only needs to tolerate a GC pause or a slow
    /// database, not a slow upstream.
    pub lease_ttl_secs: u64,
    /// `ASYNC_MAX_ATTEMPTS`. Attempts before a row that keeps losing its lease
    /// is failed outright.
    ///
    /// Defaults to **1**: an action call is not idempotent and there is no
    /// idempotency-key concept, so a POST that already reached the upstream
    /// must not be replayed because a worker died. Operators who know their
    /// actions are safe to retry raise it.
    pub max_attempts: i32,
}

impl Default for AsyncExecutionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            call_timeout_max_ms: 900_000,
            worker_concurrency: 2,
            lease_ttl_secs: 60,
            max_attempts: 1,
        }
    }
}

/// Slack added to [`Config::call_timeout_max_ms`] to get the replay wall.
///
/// Covers what the replay future does *after* the upstream answers — secret
/// decryption, jq filtering, finalising the execution row — so the wall never
/// fires on a call that merely used its full, legitimate budget.
const REPLAY_WALL_SLACK_MS: u64 = 5_000;

impl Config {
    /// Outer wall-clock guard for `POST /v1/approvals/{id}/call`.
    ///
    /// Derived rather than configured, so a per-call timeout can never be
    /// silently shadowed by the wall and an operator never has to bump two env
    /// vars in lockstep. Always at least the largest timeout the D56 resolver
    /// can return, plus slack for the post-call work.
    pub fn replay_wall_clock(&self) -> std::time::Duration {
        let floor_ms = self.call_timeout_max_ms + REPLAY_WALL_SLACK_MS;
        std::time::Duration::from_millis((self.execution_replay_timeout_secs * 1_000).max(floor_ms))
    }

    /// Grace before the sweeper reclaims an `executing` execution row as
    /// orphaned. One minute past the wall: if the wall had been going to fire,
    /// it already would have, so anything still `executing` lost its process.
    pub fn orphan_execution_grace_secs(&self) -> i64 {
        self.replay_wall_clock().as_secs() as i64 + 60
    }

    /// How often a worker renews its lease. Derived as a third of the TTL, so
    /// a job gets three chances to renew before it is presumed dead — and so
    /// the two can never be configured into contradiction.
    ///
    /// This interval also bounds cancel latency: the heartbeat's
    /// `RETURNING cancel_requested` *is* the cancel poll, deliberately, so
    /// "I still own this row" and "I should stop" are one atomic observation.
    pub fn async_heartbeat_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs((self.async_execution.lease_ttl_secs / 3).max(1))
    }

    /// Outer wall-clock guard for one async job. Mirrors [`Self::replay_wall_clock`]:
    /// the largest budget the resolver can hand out, plus slack for the work
    /// after the upstream answers.
    pub fn async_wall_clock(&self) -> std::time::Duration {
        std::time::Duration::from_millis(
            self.async_execution.call_timeout_max_ms + REPLAY_WALL_SLACK_MS,
        )
    }

    /// Grace before the sweeper fails an async row that is still `executing`
    /// past its wall. One minute past, on the same reasoning as
    /// [`Self::orphan_execution_grace_secs`].
    pub fn async_orphan_grace_secs(&self) -> i64 {
        self.async_wall_clock().as_secs() as i64 + 60
    }

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
    /// The platform-held value for vault secret `secret_name`, if this
    /// deployment has one *and* `url` lands on the host it is pinned to.
    ///
    /// Both conditions matter. The name check keeps the value bound to the one
    /// credential slot it belongs to; the host check keeps it off any other
    /// upstream, so an org that points its `email` instances at a self-hosted
    /// overfwd — or at an attacker's — receives nothing.
    ///
    /// `url` is the full outgoing request URL. Anything that doesn't parse, or
    /// carries no host, resolves to `None`: a URL we can't reason about is not
    /// one we hand a credential to.
    pub fn platform_credential_for(&self, secret_name: &str, url: &str) -> Option<&str> {
        let cred = self.platform_credential.as_ref()?;
        if cred.secret_name != secret_name {
            return None;
        }
        let host = url::Url::parse(url).ok()?.host_str()?.to_ascii_lowercase();
        (host == cred.host).then_some(cred.value.as_str())
    }

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
        if !parse::ssrf_allowed_for(override_base) {
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
    /// These are a fallback for IdP login: `resolve_auth_credentials` prefers a
    /// dedicated IdP config and then org-level OAuth App Credentials, using these
    /// env vars only when no org/dedicated credentials are configured.
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
    use super::parse::parse_platform_credential;
    use super::*;
    use std::env;
    use std::sync::Mutex;

    /// Tests in this module mutate `OVERSLASH_SSRF_ALLOW_PRIVATE`; the env
    /// is process-global so any two of them racing would produce nondeter-
    /// ministic results under cargo's default parallel runner. Serialise
    /// across the whole env-touching cohort with a single mutex.
    pub(super) static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn platform_config() -> Config {
        let mut cfg = empty_test_config();
        cfg.platform_credential = Some(PlatformCredential {
            secret_name: "overfwd_gateway_key".into(),
            host: "mailbox.overslash.com".into(),
            value: "platform-key".into(),
        });
        cfg
    }

    #[test]
    fn platform_credential_matches_on_name_and_host() {
        let cfg = platform_config();
        assert_eq!(
            cfg.platform_credential_for(
                "overfwd_gateway_key",
                "https://mailbox.overslash.com/email/search"
            ),
            Some("platform-key")
        );
        // Case and port are not part of the identity of a host.
        assert_eq!(
            cfg.platform_credential_for(
                "overfwd_gateway_key",
                "https://MAILBOX.Overslash.com:443/email/search"
            ),
            Some("platform-key")
        );
    }

    #[test]
    fn platform_credential_withheld_from_any_other_host_or_slot() {
        let cfg = platform_config();
        // A self-hosted gateway — the containment property. `instance.url` is
        // tenant-controlled, so this is the case that must never leak.
        assert_eq!(
            cfg.platform_credential_for(
                "overfwd_gateway_key",
                "https://overfwd.some-tenant.example/email/search"
            ),
            None
        );
        // A lookalike host must not match on suffix.
        assert_eq!(
            cfg.platform_credential_for(
                "overfwd_gateway_key",
                "https://evil-mailbox.overslash.com.attacker.test/email/search"
            ),
            None
        );
        // Right host, different credential slot.
        assert_eq!(
            cfg.platform_credential_for("stripe_key", "https://mailbox.overslash.com/x"),
            None
        );
        // A URL we cannot parse is not one we hand a credential to.
        assert_eq!(
            cfg.platform_credential_for("overfwd_gateway_key", "not a url"),
            None
        );
    }

    #[test]
    fn platform_credential_absent_without_all_three_vars() {
        assert!(
            empty_test_config()
                .platform_credential_for("overfwd_gateway_key", "https://mailbox.overslash.com/x")
                .is_none()
        );
        // A partial config must not half-activate the rung.
        assert!(parse_platform_credential(Some("overfwd_gateway_key"), Some("h"), None).is_none());
        assert!(parse_platform_credential(Some("overfwd_gateway_key"), None, Some("k")).is_none());
        assert!(parse_platform_credential(None, Some("h"), Some("k")).is_none());
        assert!(parse_platform_credential(Some("n"), Some("  "), Some("k")).is_none());
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

    fn empty_test_config() -> Config {
        Config {
            async_execution: Default::default(),
            call_stream_idle_timeout_ms: 30_000,
            call_timeout_max_ms: 110_000,
            call_timeout_ms: 30_000,
            host: "127.0.0.1".into(),
            port: 0,
            database_url: String::new(),
            db_max_connections: 5,
            db_min_connections: 1,
            db_acquire_timeout_secs: 10,
            db_background_max_connections: 2,
            events_stream_max_connection_secs: 30,
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
            live_map_enabled: false,
            magic_link_enabled: true,
            max_response_body_bytes: 0,
            audit_response_body_max_bytes: 0,
            filter_timeout_ms: 0,
            download_token_ttl_secs: 900,
            call_result_max_bytes: 1024 * 1024,
            dashboard_url: "/".into(),
            dashboard_origin: "*".into(),
            mcp_extra_origins: String::new(),
            redis_url: None,
            default_rate_limit: 0,
            default_rate_window_secs: 0,
            allow_org_creation: true,
            trial_default_duration_days: 30,
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
            platform_credential: None,
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
