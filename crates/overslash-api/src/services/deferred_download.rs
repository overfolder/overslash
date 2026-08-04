//! Deferred downloads: hand the caller a capability URL instead of bytes.
//!
//! # Why this exists
//!
//! Overslash had exactly one way to return a file: `prefer_stream: true` on
//! `POST /v1/actions/call`. That is a REST-DTO field, and the MCP dispatch fork
//! in `routes/actions/call.rs` returns long before the streaming fork is
//! reached — so an agent talking over MCP could not request it, and the
//! buffered path it *did* reach ran the body through `String::from_utf8_lossy`
//! and then cropped strings at 200 chars in compact mode. Binary was not merely
//! awkward over MCP; it was unreachable.
//!
//! It should stay unreachable. An agent that wants a 40 MB video does not want
//! it in a context window — it wants it on disk. So the result carries a URL
//! (a couple hundred bytes, safe to put in front of a model) and the bytes move
//! out of band, fetched by whatever tool actually writes files.
//!
//! # What a token is and is not
//!
//! It is *not* a second authorization system. The action call that mints a
//! token is fully permission-checked, gated, and audited before the token
//! exists. Deferring only moves *byte delivery*, never the decision. The token
//! is the bearer proof that the decision already happened — the presigned-URL
//! model, and for the same reason: the process that fetches (curl in a sandbox,
//! a browser) holds none of the caller's credentials and cannot be given them.
//!
//! Two consequences shape the code below:
//!
//! * **Credentials are re-resolved at fetch time, never stored.** The row keeps
//!   an [`ActionRequest`], which is credential-*free* by construction — it names
//!   secrets ([`SecretRef`]) rather than carrying them, and `AuthHeader`
//!   deliberately doesn't implement `Serialize` so a live token cannot be
//!   persisted even by accident. Re-resolving means a rotated secret is picked
//!   up and a deleted one fails closed.
//! * **The identity is re-checked at fetch time**, so revoking access
//!   invalidates outstanding tokens without having to hunt them down.

use std::collections::HashMap;

use axum::response::Response;
use overslash_core::secret_injection::inject_secrets;
use overslash_core::types::{ActionRequest, InjectAs, SecretRef};
use overslash_db::repos::download_token::{self, NewDownloadToken};
use overslash_db::scopes::OrgScope;
use rand::RngExt as _;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{AppState, error::AppError, services::http_caller};

/// Upstream response headers forwarded verbatim to the fetching client.
///
/// The same six the inline `prefer_stream` path allows. Everything else is
/// dropped: an upstream `Set-Cookie` or `WWW-Authenticate` has no business
/// reaching a caller that never spoke to that host, and forwarding
/// `Transfer-Encoding` would contradict the framing axum applies itself.
const FORWARDED_HEADERS: [&str; 6] = [
    "content-type",
    "content-length",
    "content-disposition",
    "etag",
    "last-modified",
    "cache-control",
];

/// What the caller gets back in place of the bytes.
#[derive(Debug, serde::Serialize)]
pub struct Descriptor {
    /// Absolute, fetchable URL. Carries the raw token in its path.
    pub download_url: String,
    /// RFC 3339. After this the URL 404s.
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

/// Everything a mint needs. A struct rather than a nine-argument function:
/// three of those arguments are adjacent `Option<&str>`s that would swap
/// silently.
pub struct Mint<'a> {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub service_instance_id: Option<Uuid>,
    pub service_key: Option<&'a str>,
    pub action_key: Option<&'a str>,
    /// The request to replay at fetch time. Must be credential-free — name
    /// secrets via `secrets`, never bake a resolved value into `headers`.
    /// Callers whose `headers` come from user input must run
    /// [`reject_inline_credentials`] first; the other construction paths
    /// satisfy this structurally.
    pub request: ActionRequest,
    pub mime: Option<String>,
    pub size_bytes: Option<i64>,
    pub filename: Option<String>,
}

/// Mint a capability token and return the descriptor to hand the caller.
pub async fn mint(
    state: &AppState,
    ext: &axum::http::Extensions,
    m: Mint<'_>,
) -> Result<Descriptor, AppError> {
    // 32 random bytes → URL-safe token; only its SHA-256 is stored. Same
    // construction as magic-link tokens.
    let mut buf = [0u8; 32];
    rand::rng().fill(&mut buf);
    let raw_token = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, buf);
    let token_hash = Sha256::digest(raw_token.as_bytes()).to_vec();

    let request = serde_json::to_value(&m.request)
        .map_err(|e| AppError::Internal(format!("download request not serializable: {e}")))?;

    let row = download_token::create(
        state.db(ext),
        NewDownloadToken {
            token_hash: &token_hash,
            org_id: m.org_id,
            identity_id: m.identity_id,
            service_instance_id: m.service_instance_id,
            service_key: m.service_key,
            action_key: m.action_key,
            request,
            // Reserved for credential shapes an `ActionRequest` can't name on
            // its own (a live OAuth connection). Bearer/none — every shape
            // supported today — travel as `SecretRef`s inside `request`.
            credential_ref: serde_json::json!({}),
            mime: m.mime.as_deref(),
            size_bytes: m.size_bytes,
            filename: m.filename.as_deref(),
            ttl_secs: state.config.download_token_ttl_secs,
        },
    )
    .await?;

    let base = state.config.public_url.trim_end_matches('/');
    Ok(Descriptor {
        download_url: format!("{base}/v1/downloads/{raw_token}"),
        expires_at: row
            .expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        mime: row.mime,
        size_bytes: row.size_bytes,
        filename: row.filename,
    })
}

/// Hash a raw token for lookup. Kept here so the mint and redeem sides can
/// never disagree about the construction.
pub fn hash_token(raw: &str) -> Vec<u8> {
    Sha256::digest(raw.as_bytes()).to_vec()
}

/// Header names that carry a credential rather than describing the request.
///
/// Not exhaustive, and can't be — an upstream is free to read a secret out of
/// any header it likes. It covers the standard ones plus the `*-api-key` /
/// `*-token` family that account for essentially every API in the wild.
const CREDENTIAL_HEADERS: [&str; 7] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
];

/// Reject a request that carries a credential in a caller-supplied header.
///
/// Every other path here keeps its promise structurally: an `ActionRequest` is
/// credential-free because it *names* secrets rather than carrying them, and
/// `AuthHeader` has no `Serialize` so a live OAuth token cannot be persisted
/// even by accident. Raw HTTP (Mode A) is the one shape that can break it —
/// `resolve_request` copies the caller's `headers` map through verbatim, so a
/// caller writing `"headers": {"Authorization": "Bearer …"}` would land a
/// plaintext credential in the token row, at rest, outside the vault, for the
/// token's lifetime.
///
/// Rejecting rather than stripping: stripping would mint a token whose replay
/// silently 401s later, which is a worse failure than a 400 now. `secrets` is
/// the mechanism for this and it already works on the deferred path.
pub fn reject_inline_credentials(request: &ActionRequest) -> Result<(), AppError> {
    for name in request.headers.keys() {
        let lower = name.trim().to_ascii_lowercase();
        if CREDENTIAL_HEADERS.contains(&lower.as_str()) {
            return Err(AppError::BadRequest(format!(
                "deliver: \"url\" cannot carry the credential header `{name}` inline — it would \
                 be persisted with the download token. Name the secret via `secrets` instead, \
                 and it is resolved from the vault at fetch time."
            )));
        }
    }
    Ok(())
}

/// Build the `ActionRequest` for fetching a URL behind a vault-backed bearer.
///
/// This is what makes an MCP-runtime download reuse the HTTP credential
/// machinery unchanged: the media route wants `Authorization: Bearer <secret>`,
/// and that is precisely the raw-HTTP (Mode A) `SecretRef` shape — an unbound
/// ref whose `name` *is* the vault secret name, with the prefix carried
/// literally. No new resolution path, no second place for credential handling
/// to drift.
pub fn bearer_request(url: String, secret_name: Option<&str>) -> ActionRequest {
    ActionRequest {
        method: "GET".into(),
        url,
        headers: HashMap::new(),
        body: None,
        secrets: secret_name
            .map(|name| SecretRef {
                name: name.to_string(),
                inject_as: InjectAs::Header,
                header_name: Some("Authorization".into()),
                query_param: None,
                prefix: Some("Bearer ".into()),
                template: None,
                bindings: Default::default(),
                config: Default::default(),
                // Legacy field, accepted and ignored; never set on new refs.
                encode: None,
            })
            .into_iter()
            .collect(),
    }
}

/// Re-resolve credentials for a stored request and open the upstream stream.
///
/// The mirror image of the mint: whatever the row named, resolve it *now*
/// against the current vault, inject, and dial. A secret rotated since mint
/// works; a secret deleted since mint fails closed with `CredentialMissing`.
pub async fn open_upstream(
    state: &AppState,
    scope: &OrgScope,
    service_key: Option<&str>,
    request: &ActionRequest,
) -> Result<reqwest::Response, AppError> {
    let secret_values = crate::services::action_caller::resolve_credential_values(
        state,
        scope,
        service_key,
        request,
    )
    .await?;
    let (resolved_url, resolved_headers) =
        inject_secrets(request, &secret_values).map_err(|e| AppError::BadRequest(e.to_string()))?;
    let resolved_url = state.config.apply_base_overrides(&resolved_url);

    http_caller::call_streaming(
        &state.http_client,
        &request.method,
        &resolved_url,
        &resolved_headers,
        request.body.as_deref(),
    )
    .await
    .map_err(|e| AppError::BadGateway(format!("download upstream request failed: {e}")))
}

/// Pipe an upstream response straight through to the caller: raw bytes, the
/// upstream status, and the [`FORWARDED_HEADERS`] allowlist.
///
/// Nothing is buffered, so `max_response_body_bytes` never applies — which is
/// the point. A 40 MB video is exactly the case the 5 MB buffered cap exists to
/// prevent from reaching a context window, and exactly the case this path is
/// for.
pub fn stream_through(upstream: reqwest::Response) -> Response {
    let status = upstream.status().as_u16();
    let headers = upstream.headers().clone();
    let body = axum::body::Body::from_stream(upstream.bytes_stream());

    let mut builder = Response::builder().status(status);
    for (name, value) in headers.iter() {
        if FORWARDED_HEADERS.contains(&name.as_str()) {
            builder = builder.header(name, value);
        }
    }
    builder
        .body(body)
        .expect("status + allowlisted headers always build a valid response")
}
