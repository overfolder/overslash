//! Proxy uploads: minting a capability to push bytes, and metering them on the
//! way through.
//!
//! The inbound half of the byte path. [`deferred_download`] hands a caller a
//! URL to *fetch* from; this hands a caller a URL to *push* to, and the
//! redemption streams those bytes into the service with the credential
//! re-resolved from the vault at that moment. Same trust model, opposite
//! direction: the process holding the token is deliberately not the caller and
//! holds none of the caller's credentials.
//!
//! # The organizing invariant
//!
//! **Everything the reviewer approved is fixed at mint time; the anonymous
//! redemption leg contributes only bytes.** The filename, the target route, the
//! ceiling and the declared content all come off the token, never off the
//! request that redeems it. That is what makes the approval mean something: a
//! redeemer who could choose the filename could get a reviewer's yes to
//! `notes.txt` and push `payroll.xlsx`.
//!
//! # What verification can and cannot do
//!
//! A declared size is *prevented* from being exceeded — the meter cuts the
//! transfer mid-stream, so the upstream never sees the overage. A declared
//! hash can only be *detected*, because a hash is not known until the last
//! byte, which is after the upstream already has them. On a mismatch the
//! redemption fails and the upstream's reference is never handed back, so
//! nothing downstream can name those bytes; the bytes themselves may linger
//! upstream as an unreferenced orphan. Saying this plainly matters more than
//! the check reading as airtight, because an operator who believes a mismatch
//! is impossible will not think about the orphan.
//!
//! [`deferred_download`]: crate::services::deferred_download

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use overslash_core::types::{ActionResult, DownloadAuth, McpAuth, UploadSpec};
use overslash_db::repos::upload_token::{self, NewUploadToken};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{AppState, error::AppError, services::deferred_download};

/// What the caller gets back in place of a place to put bytes.
#[derive(Debug, serde::Serialize)]
pub struct UploadDescriptor {
    /// Absolute URL to push to. Carries the raw token in its path.
    pub upload_url: String,
    /// The verb the URL accepts.
    pub method: &'static str,
    /// RFC 3339. After this the URL 404s.
    pub expires_at: String,
    /// Hard ceiling for this push, already clamped to the deployment limit.
    pub max_bytes: u64,
    /// A ready-to-run invocation. Present because the whole point of this
    /// shape is that the bytes never enter an agent's context — so the useful
    /// thing to hand back is the command that moves them without doing so.
    pub hint: String,
}

// ---------------------------------------------------------------------------
// Minting
// ---------------------------------------------------------------------------

/// Everything a mint reads. A struct rather than an eleven-argument function,
/// for the reason the download side gives: adjacent `Option<&str>`s swap
/// silently at a call site with no type error to catch it.
pub(crate) struct Mint<'a> {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub service_instance_id: Option<Uuid>,
    pub service_key: Option<&'a str>,
    pub action_key: Option<&'a str>,
    /// The resolved MCP server URL. The byte route resolves against this
    /// origin and no other.
    pub mcp_url: &'a str,
    pub mcp_auth: &'a McpAuth,
    pub spec: &'a UploadSpec,
    /// The call's arguments, which is where the caller states what it intends
    /// to push.
    pub arguments: &'a serde_json::Value,
}

/// Mint a capability for pushing bytes, instead of dispatching a tool call.
///
/// Called only once a dispatch site has found an upload block, which is why it
/// takes `spec` rather than an `Option` — the two sites branch, this mints.
///
/// There are two such sites and missing either is silent: an ungated call goes
/// through the inline executor, while a *gated* one — the first call any
/// permission-checked agent makes — is replayed from a stored payload after
/// approval. An interception present only on the inline path would work
/// perfectly until the moment an approval was involved.
pub(crate) async fn intercept_mint(
    state: &AppState,
    ext: &axum::http::Extensions,
    m: Mint<'_>,
) -> Result<ActionResult, AppError> {
    let started = std::time::Instant::now();
    let spec = m.spec;

    let url = deferred_download::resolve_same_origin(m.mcp_url, &spec.path)?;

    // Same credential rules as a deferred download, deliberately reusing its
    // vocabulary: an OAuth bearer is minted live from the caller's connection
    // and is not persistable, so a redemption could not re-present it.
    let secret_name = match (m.mcp_auth, spec.auth) {
        (_, DownloadAuth::None) => None,
        (McpAuth::Bearer { secret_name }, DownloadAuth::Inherit) => secret_name.as_deref(),
        (McpAuth::None, DownloadAuth::Inherit) => None,
        (McpAuth::OAuth { .. }, DownloadAuth::Inherit) => {
            return Err(AppError::BadRequest(
                "uploads are not supported for OAuth-authenticated MCP services yet; \
                 the deferred push cannot re-mint an OAuth bearer"
                    .into(),
            ));
        }
    };

    let declared = Declared::read(m.arguments)?;
    // A template may lower the deployment ceiling, never raise it. Both are
    // real limits — the deployment's bounds what this process will move, the
    // template's bounds what the upstream will accept.
    let max_bytes = spec
        .max_bytes
        .unwrap_or(state.config.upload_max_bytes)
        .min(state.config.upload_max_bytes);
    if let Some(size) = declared.size_bytes
        && size as u64 > max_bytes
    {
        return Err(AppError::BadRequest(format!(
            "declared size_bytes ({size}) exceeds the {max_bytes}-byte limit for this upload"
        )));
    }

    let request = deferred_download::bearer_request(spec.method.as_str(), url, secret_name);
    deferred_download::reject_inline_credentials(&request)?;

    let (raw_token, token_hash) = deferred_download::new_token();

    let row = upload_token::create(
        state.db(ext),
        NewUploadToken {
            token_hash: &token_hash,
            org_id: m.org_id,
            identity_id: m.identity_id,
            service_instance_id: m.service_instance_id,
            service_key: m.service_key,
            action_key: m.action_key,
            request: serde_json::to_value(&request)
                .map_err(|e| AppError::Internal(format!("upload request not serializable: {e}")))?,
            credential_ref: json!({}),
            declared_sha256: declared.sha256.as_deref(),
            declared_size_bytes: declared.size_bytes,
            declared_mime: declared.mime.as_deref(),
            declared_filename: declared.filename.as_deref(),
            max_bytes: max_bytes as i64,
            filename_param: spec.filename_param.as_deref(),
            // Carried on the row because redemption cannot resolve it: it
            // holds a token, not an action key. Same constraint that puts
            // `pagination` on an approval's replay payload.
            result_spec: spec
                .result
                .as_ref()
                .and_then(|r| serde_json::to_value(r).ok()),
            ttl_secs: state.config.upload_token_ttl_secs,
        },
    )
    .await
    .map_err(|e| AppError::Internal(format!("could not mint upload token: {e}")))?;

    let base = state.config.public_url.trim_end_matches('/');
    let upload_url = format!("{base}/v1/uploads/{raw_token}");
    let expires_at = row
        .expires_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    let content_type = declared
        .mime
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let descriptor = UploadDescriptor {
        method: spec.method.as_str(),
        hint: format!(
            "curl -sSf -X {} --data-binary @FILE -H 'Content-Type: {}' '{}'",
            spec.method.as_str(),
            content_type,
            upload_url
        ),
        upload_url,
        expires_at,
        max_bytes,
    };

    Ok(ActionResult {
        status_code: 200,
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        body: serde_json::to_string(&descriptor).unwrap_or_default(),
        duration_ms: started.elapsed().as_millis() as u64,
        filtered_body: None,
    })
}

/// What the caller said it was about to push.
///
/// Every field is optional, and the asymmetry in how they are treated is the
/// point: absent means "unverified", while present means "enforced". A caller
/// that declares nothing gets an approval reading "some bytes, to be chosen
/// later", which is a weaker thing to approve and should look like one.
struct Declared {
    sha256: Option<String>,
    size_bytes: Option<i64>,
    mime: Option<String>,
    filename: Option<String>,
}

impl Declared {
    fn read(arguments: &serde_json::Value) -> Result<Self, AppError> {
        let get = |k: &str| {
            arguments
                .get(k)
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        // Normalized to lowercase so a caller writing an uppercase digest is
        // not told its own file's hash mismatched.
        let sha256 = get("sha256").map(|s| s.to_ascii_lowercase());
        if let Some(h) = &sha256
            && (h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(AppError::BadRequest(
                "sha256 must be 64 hexadecimal characters".into(),
            ));
        }
        let size_bytes = match arguments.get("size_bytes") {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => match v.as_i64().filter(|n| *n > 0) {
                Some(n) => Some(n),
                None => {
                    return Err(AppError::BadRequest(
                        "size_bytes must be a positive integer".into(),
                    ));
                }
            },
        };
        Ok(Declared {
            sha256,
            size_bytes,
            mime: get("mime"),
            filename: get("filename"),
        })
    }
}

// ---------------------------------------------------------------------------
// Metering
// ---------------------------------------------------------------------------

/// What a redemption is allowed to accept, all of it fixed at mint time.
pub struct Limit {
    /// Hard ceiling for this token, already clamped to the deployment's.
    pub max_bytes: u64,
    /// Declared at mint. When set the transfer must be *exactly* this long:
    /// over is cut mid-stream, under is caught at end of stream.
    pub declared_bytes: Option<u64>,
    /// Per-chunk stall budget. Bounds liveness without bounding duration, so a
    /// slow but progressing transfer is not punished for being large.
    pub idle: Duration,
}

/// What a completed pass over the body measured.
#[derive(Debug, Clone, Copy)]
pub struct Measured {
    pub bytes: u64,
    pub sha256: [u8; 32],
}

impl Measured {
    /// Lowercase hex, the spelling every upstream states its digests in.
    pub fn hex(&self) -> String {
        self.sha256.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }
}

#[derive(Default)]
struct Tally {
    bytes: u64,
    hasher: Sha256,
    finished: bool,
    exceeded: bool,
}

/// Handle onto a live meter.
pub struct MeterHandle(Arc<Mutex<Tally>>);

impl MeterHandle {
    /// Whether the transfer was cut for going past its ceiling.
    ///
    /// Read from the meter rather than matched against the transport error's
    /// text: the abort reaches the caller as a generic reqwest failure with our
    /// message buried an unknown number of `source()` hops down, and a status
    /// code that depends on string matching is one dependency-bump away from
    /// silently becoming a 502.
    pub fn exceeded(&self) -> bool {
        self.0.lock().map(|t| t.exceeded).unwrap_or(false)
    }

    /// What the body measured, or `None` if it was never read to completion.
    ///
    /// The `None` case is not a formality: an upstream can answer before
    /// consuming the request body (an early error, a 100-continue it declines),
    /// and the tally at that moment describes a prefix. Callers must treat
    /// `None` as "unverified" and fail closed — reporting a verification that
    /// did not happen is worse than not verifying, because it is believed.
    pub fn finish(&self) -> Option<Measured> {
        let t = self.0.lock().ok()?;
        if !t.finished {
            return None;
        }
        Some(Measured {
            bytes: t.bytes,
            sha256: t.hasher.clone().finalize().into(),
        })
    }
}

/// Why a metered body stopped short.
///
/// Named rather than folded into one `io::Error` because the two cases get
/// different statuses — over-limit is the caller's fault (413), a stall is
/// nobody's (504) — and by the time the error surfaces the transfer is gone.
const ERR_TOO_LARGE: &str = "upload exceeds the byte limit for this token";
const ERR_STALLED: &str = "upload stalled";

/// Wrap a request body so it can be handed to reqwest without buffering:
/// count it, hash it, and cut the transfer the moment it exceeds what was
/// declared.
///
/// Cutting mid-stream is what makes the size limit *preventive* rather than
/// merely detective. Yielding an error aborts reqwest's request body and tears
/// the connection, so a content-addressed upstream that reads to completion
/// before committing never stores the overage.
///
/// Deliberately the same `unfold` shape as
/// [`crate::services::http_caller::idle_guarded_stream`], so the inbound and
/// outbound guards read alike.
pub fn metered_body(body: axum::body::Body, limit: Limit) -> (reqwest::Body, MeterHandle) {
    let tally = Arc::new(Mutex::new(Tally::default()));
    let shared = tally.clone();
    // The tighter of the two bounds. A declared size is exact, so anything
    // past it is already a mismatch and there is no reason to keep paying for
    // bytes that cannot be accepted.
    let ceiling = limit
        .declared_bytes
        .map_or(limit.max_bytes, |d| d.min(limit.max_bytes));

    let stream =
        futures_util::stream::unfold(Some(Box::pin(body.into_data_stream())), move |state| {
            let shared = shared.clone();
            async move {
                let mut inner = state?;
                match tokio::time::timeout(limit.idle, inner.next()).await {
                    Ok(Some(Ok(chunk))) => {
                        // The guard is never held across an await, so this
                        // future stays `Send`.
                        {
                            let mut t = match shared.lock() {
                                Ok(t) => t,
                                Err(_) => {
                                    return Some((
                                        Err(std::io::Error::other("upload meter poisoned")),
                                        None,
                                    ));
                                }
                            };
                            t.bytes += chunk.len() as u64;
                            if t.bytes > ceiling {
                                t.exceeded = true;
                                return Some((
                                    Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        ERR_TOO_LARGE,
                                    )),
                                    None,
                                ));
                            }
                            t.hasher.update(&chunk);
                        }
                        Some((Ok(chunk), Some(inner)))
                    }
                    Ok(Some(Err(e))) => Some((Err(std::io::Error::other(e)), None)),
                    Ok(None) => {
                        if let Ok(mut t) = shared.lock() {
                            t.finished = true;
                        }
                        None
                    }
                    Err(_elapsed) => Some((
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            ERR_STALLED,
                        )),
                        None,
                    )),
                }
            }
        });

    (reqwest::Body::wrap_stream(stream), MeterHandle(tally))
}

/// Record what an upload stored, so a later approval referencing these bytes
/// can describe them.
///
/// Best-effort and deliberately not fatal: the push succeeded, and failing the
/// redemption because a descriptive row could not be written would trade a
/// working upload for a prettier approval.
pub(crate) async fn record_uploaded(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    service_instance_id: Option<Uuid>,
    service_key: Option<&str>,
    d: &UploadedDescriptor,
) {
    if let Err(e) = overslash_db::repos::media_descriptor::record(
        pool,
        overslash_db::repos::media_descriptor::NewMediaDescriptor {
            org_id,
            service_instance_id,
            service_key,
            media_path: &d.media_path,
            sha256: d.sha256.as_deref(),
            mime: d.mime.as_deref(),
            size_bytes: d.size_bytes,
            filename: d.filename.as_deref(),
            source: overslash_db::repos::media_descriptor::MediaSource::Upload,
        },
    )
    .await
    {
        tracing::warn!(error = %e, "upload: media descriptor not recorded");
    }
}

/// What the upstream said it stored, read through the template's `result` jq.
#[derive(Debug, Default, Clone)]
pub struct UploadedDescriptor {
    pub media_path: String,
    pub sha256: Option<String>,
    pub mime: Option<String>,
    pub size_bytes: Option<i64>,
    pub filename: Option<String>,
}
