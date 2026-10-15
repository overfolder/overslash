//! Memorystore IAM auth: `AUTH default <access token>`.
//!
//! Memorystore checks the token only when a connection authenticates. A token
//! lives an hour; an authenticated connection stays usable for 12 hours. So
//! each connection needs a token that is current *when it connects*, and a
//! long-lived connection needs a fresh `AUTH` before its 12 hours run out.
//!
//! `redis` covers both through [`StreamingCredentialsProvider`]: it takes the
//! first item of a fresh stream on every (re)connect, and keeps a second
//! stream per connection whose later items re-`AUTH` it in place. So each
//! stream yields a token now, then another every [`REAUTH_EVERY`].
//!
//! Tokens come from the metadata server (the Cloud Run service account's
//! identity), cached until [`REFRESH_MARGIN`] before they expire. The metadata
//! server caches too, and hands out its cached token with the time it has
//! left — that remaining lifetime is what the expiry is computed from, so the
//! two caches cannot stack into handing out a token that is about to lapse.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{Stream, stream};
use redis::{BasicAuth, ErrorKind, RedisError, RedisResult, StreamingCredentialsProvider};
use serde::Deserialize;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// Memorystore accepts no other user for IAM auth.
const USERNAME: &str = "default";
/// Fetch a new token once the cached one has less than this left.
const REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);
/// Re-`AUTH` open connections this often: well inside both the token's hour
/// and the connection's 12-hour window.
const REAUTH_EVERY: Duration = Duration::from_secs(30 * 60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const TOKEN_PATH: &str = "/computeMetadata/v1/instance/service-accounts/default/token";

/// Credentials for the runtime's own service account. Cheap to clone; clones
/// share one token cache.
#[derive(Clone)]
pub struct GcpIamCredentials {
    inner: Arc<Inner>,
}

struct Inner {
    token_url: String,
    reauth_every: Duration,
    http: reqwest::Client,
    cached: Mutex<Option<Cached>>,
}

#[derive(Clone)]
struct Cached {
    token: String,
    refresh_at: Instant,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

impl GcpIamCredentials {
    /// The metadata server, or `GCE_METADATA_HOST` when set (the variable
    /// Google's own client libraries honour, for emulators and tests).
    pub fn from_env() -> Self {
        let host = overslash_env::or_default("GCE_METADATA_HOST", "metadata.google.internal");
        Self::with_base_url(&format!("http://{host}"))
    }

    pub fn with_base_url(base_url: &str) -> Self {
        Self::new(base_url, REAUTH_EVERY)
    }

    fn new(base_url: &str, reauth_every: Duration) -> Self {
        // The metadata server is link-local; never route it through a proxy.
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(FETCH_TIMEOUT)
            .build()
            .expect("static reqwest config");
        Self {
            inner: Arc::new(Inner {
                token_url: format!("{}{TOKEN_PATH}", base_url.trim_end_matches('/')),
                reauth_every,
                http,
                cached: Mutex::new(None),
            }),
        }
    }

    /// A token with at least [`REFRESH_MARGIN`] left.
    pub async fn token(&self) -> RedisResult<String> {
        let mut cached = self.inner.cached.lock().await;
        if let Some(c) = cached.as_ref()
            && Instant::now() < c.refresh_at
        {
            return Ok(c.token.clone());
        }
        let fresh = self.inner.fetch().await?;
        let token = fresh.token.clone();
        *cached = Some(fresh);
        Ok(token)
    }
}

impl Inner {
    async fn fetch(&self) -> RedisResult<Cached> {
        let fail = |detail: String| {
            RedisError::from((
                ErrorKind::AuthenticationFailed,
                "could not get a Memorystore IAM token from the metadata server",
                detail,
            ))
        };
        let resp = self
            .http
            .get(&self.token_url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| fail(e.to_string()))?;
        let body: TokenResponse = resp.json().await.map_err(|e| fail(e.to_string()))?;
        let lifetime = Duration::from_secs(body.expires_in);
        tracing::debug!(
            expires_in = body.expires_in,
            "fetched Memorystore IAM token"
        );
        Ok(Cached {
            token: body.access_token,
            refresh_at: Instant::now() + lifetime.saturating_sub(REFRESH_MARGIN),
        })
    }
}

impl StreamingCredentialsProvider for GcpIamCredentials {
    fn subscribe(&self) -> Pin<Box<dyn Stream<Item = RedisResult<BasicAuth>> + Send + 'static>> {
        let this = self.clone();
        Box::pin(stream::unfold(true, move |first| {
            let this = this.clone();
            async move {
                if !first {
                    tokio::time::sleep(this.inner.reauth_every).await;
                }
                let item = this
                    .token()
                    .await
                    .map(|token| BasicAuth::new(USERNAME.to_owned(), token));
                if let Err(e) = &item {
                    tracing::warn!("Memorystore IAM token refresh failed: {e}");
                }
                Some((item, false))
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures_util::StreamExt;

    use axum::{Json, Router, http::HeaderMap, http::StatusCode, routing::get};

    /// A metadata server that hands out `token-<n>` with the given lifetime,
    /// and refuses requests without the `Metadata-Flavor` header like the real one.
    async fn fake_metadata(expires_in: u64) -> (String, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let app = Router::new().route(
            TOKEN_PATH,
            get(move |headers: HeaderMap| {
                let counter = counter.clone();
                async move {
                    if headers.get("Metadata-Flavor").map(|v| v.as_bytes()) != Some(b"Google") {
                        return Err(StatusCode::FORBIDDEN);
                    }
                    let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    Ok(Json(serde_json::json!({
                        "access_token": format!("token-{n}"),
                        "expires_in": expires_in,
                        "token_type": "Bearer",
                    })))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), calls)
    }

    #[tokio::test]
    async fn token_is_cached_until_close_to_expiry() {
        let (url, calls) = fake_metadata(3600).await;
        let creds = GcpIamCredentials::with_base_url(&url);
        assert_eq!(creds.token().await.unwrap(), "token-1");
        assert_eq!(creds.clone().token().await.unwrap(), "token-1");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_token_inside_the_refresh_margin_is_not_reused() {
        // 60s left is already inside the 5-minute margin.
        let (url, calls) = fake_metadata(60).await;
        let creds = GcpIamCredentials::with_base_url(&url);
        assert_eq!(creds.token().await.unwrap(), "token-1");
        assert_eq!(creds.token().await.unwrap(), "token-2");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn stream_yields_default_user_immediately() {
        let (url, _) = fake_metadata(3600).await;
        let creds = GcpIamCredentials::with_base_url(&url);
        let auth = creds.subscribe().next().await.unwrap().unwrap();
        assert_eq!(auth.username(), "default");
        assert_eq!(auth.password(), "token-1");
    }

    #[tokio::test]
    async fn stream_keeps_yielding_a_current_token() {
        // Every token is inside the refresh margin, so each re-AUTH fetches.
        let (url, calls) = fake_metadata(60).await;
        let creds = GcpIamCredentials::new(&url, Duration::from_millis(10));
        let mut s = creds.subscribe();
        assert_eq!(s.next().await.unwrap().unwrap().password(), "token-1");
        assert_eq!(s.next().await.unwrap().unwrap().password(), "token-2");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// The whole path against a real Valkey: redis-rs takes the provider's
    /// token and sends `AUTH default <token>`. Gated, because it needs a Valkey
    /// whose `default` password is the fake server's first token:
    /// `valkey-server --requirepass token-1`, then
    /// `VALKEY_IAM_TEST_URL=redis://127.0.0.1:<port>`.
    #[tokio::test]
    async fn connects_with_the_metadata_token_as_default_user() {
        let Some(url) = overslash_env::optional("VALKEY_IAM_TEST_URL") else {
            eprintln!("skipping: VALKEY_IAM_TEST_URL not set");
            return;
        };
        let (metadata, _) = fake_metadata(3600).await;
        let client = redis::Client::open(url.as_str()).unwrap();
        let config = redis::aio::ConnectionManagerConfig::new()
            .set_credentials_provider(GcpIamCredentials::with_base_url(&metadata));
        let mut conn = client
            .get_connection_manager_with_config(config)
            .await
            .expect("connect");
        let who: String = redis::cmd("ACL")
            .arg("WHOAMI")
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(who, "default");

        // A second server's token is "token-1" too, so prove a wrong one fails.
        let (metadata, calls) = fake_metadata(3600).await;
        calls.store(1, Ordering::SeqCst); // next token handed out is "token-2"
        let config = redis::aio::ConnectionManagerConfig::new()
            .set_credentials_provider(GcpIamCredentials::with_base_url(&metadata));
        assert!(
            client
                .get_connection_manager_with_config(config)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn an_unreachable_metadata_server_is_an_auth_error() {
        let creds = GcpIamCredentials::with_base_url("http://127.0.0.1:9");
        let err = creds.token().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AuthenticationFailed);
    }
}
