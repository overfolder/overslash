//! `POST|PUT /v1/uploads/{token}` — redeem an upload capability.
//!
//! Mounted **outside** the auth and rate-limit layers, like
//! [`super::downloads`]: the pushing process is deliberately not the caller. It
//! is `curl` in a sandbox, or a browser — something that holds none of the
//! caller's credentials and cannot be handed any. The token in the URL is the
//! sole authority, which is why it is 256 bits of randomness, stored only as a
//! hash, short-lived, and good for exactly one successful push.
//!
//! The authorization decision was made and audited when the action call minted
//! the token; see [`crate::services::proxy_upload`]. What happens here is the
//! second half: re-resolve the upstream credential from the vault as it stands
//! right now, stream the body through it, and record what came back.
//!
//! # Nothing the redeemer sends decides anything
//!
//! The filename, the target route, the byte ceiling and the declared content
//! all come off the token. The redeemer contributes bytes and, at most, a
//! `Content-Type` hint. That is not defensive tidiness: a redeemer who could
//! choose the filename could get a reviewer's approval for `notes.txt` and push
//! `payroll.xlsx` under it.
//!
//! Failure modes are deliberately indistinguishable. Unknown token, expired
//! token, already-consumed token and deleted identity all return the same bare
//! `404`.

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use overslash_core::types::{ActionRequest, DisclosureField, UploadResultSpec};
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::upload_token::{self, UploadTokenRow};
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    extractors::{ClientIp, ReqExt},
    services::{deferred_download, proxy_upload},
};

/// Per-IP ceiling on redemption attempts.
///
/// Far tighter than the download side's 120/60, and the asymmetry is the point:
/// a download token is multi-use precisely so a large transfer can resume, so
/// its ceiling has to accommodate a legitimate retry storm. An upload token is
/// good for one successful push and cannot be resumed, so repeated attempts
/// against one IP are not a transfer pattern.
const UPLOAD_IP_MAX: u32 = 10;
const UPLOAD_IP_WINDOW_SECS: u32 = 60;

/// Cap on the upstream's *response*. It is a small JSON descriptor; anything
/// approaching this is a misconfigured target rather than a large answer.
const MAX_UPSTREAM_RESPONSE_BYTES: usize = 64 * 1024;

/// Headers copied from the inbound request to the upstream. Exactly one, and
/// the shortness is deliberate.
///
/// On the response side the gateway relays an upstream it authenticated to. On
/// this side it relays an *anonymous* client into a host holding the org's
/// credential, so the default is to forward nothing. `content-length` is
/// dropped because the body is re-framed as it streams; `authorization` because
/// the redeemer's credential, if it has one, has no business on a connection
/// where ours is the one that belongs.
const FORWARDED_UPLOAD_HEADERS: [&str; 1] = ["content-type"];

/// Content types that mean "I did not state one". A byte route that sniffs its
/// input treats these as a gap, so passing them through would replace a sniff
/// with a wrong answer — the difference between a photo sent as a photo and a
/// photo sent as a document.
const GENERIC_CONTENT_TYPES: [&str; 3] = [
    "application/octet-stream",
    "application/x-www-form-urlencoded",
    "binary/octet-stream",
];

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/uploads/{token}", post(redeem).put(redeem))
}

/// `body` must stay last: it is the only `FromRequest` extractor in the list,
/// and every `FromRequestParts` one has to precede it.
///
/// Taking `axum::body::Body` rather than `Bytes` is also what keeps the body
/// unbuffered — the limited-body machinery lives inside the extractors that
/// collect, and this one does not collect.
async fn redeem(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    client_ip: ClientIp,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    // Anonymous, so the global rate-limit middleware (which keys on the API-key
    // prefix) skips it entirely. Throttle here on the shared store, the same
    // way the download and magic-link endpoints do.
    let ip = client_ip.0.as_deref().unwrap_or("unknown");
    let rl = state
        .rate_limiter(&ext)
        .check_and_increment(
            &format!("up:redeem:ip:{ip}"),
            UPLOAD_IP_MAX,
            UPLOAD_IP_WINDOW_SECS,
        )
        .await;
    if !rl.allowed {
        let retry_after = rl
            .reset_at
            .saturating_sub(crate::services::rate_limit::now_unix());
        return crate::error::AppError::RateLimited {
            limit: rl.limit,
            reset_at: rl.reset_at,
            retry_after,
        }
        .into_response();
    }

    let not_found = || (StatusCode::NOT_FOUND, "unknown or expired token").into_response();

    // `claim` matches on hash, unexpired and unconsumed in one statement, so
    // from here an expired token, an unknown one and one whose single push
    // already happened are the same answer.
    let row =
        match upload_token::claim(state.db(&ext), &deferred_download::hash_token(&token)).await {
            Ok(Some(r)) => r,
            Ok(None) => return not_found(),
            Err(e) => {
                tracing::error!(error = %e, "upload: token lookup failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "upload failed").into_response();
            }
        };

    let scope = OrgScope::new(row.org_id, state.db_pool(&ext));

    // The permission decision was made and audited at mint time; this catches
    // the identity being deleted in between, so outstanding tokens die with
    // their principal rather than outliving it.
    match scope.get_identity(row.identity_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "upload: identity lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "upload failed").into_response();
        }
    }

    match push(&state, &ext, &scope, &row, headers, body).await {
        Ok(outcome) => {
            log_upload(&scope, &row, ip, &outcome).await;
            outcome.into_response()
        }
        Err(outcome) => {
            log_upload(&scope, &row, ip, &outcome).await;
            outcome.into_response()
        }
    }
}

/// What a redemption did, so the audit row and the response describe the same
/// thing rather than being derived twice.
enum Pushed {
    /// The upstream accepted the bytes and named what it stored.
    Accepted {
        status: u16,
        descriptor: proxy_upload::UploadedDescriptor,
        measured_bytes: u64,
        measured_sha256: String,
    },
    /// The bytes were pushed but do not match what was approved. The upstream's
    /// reference is deliberately *not* carried here — see [`Pushed::refused`].
    Mismatch {
        detail: String,
        measured_bytes: u64,
        measured_sha256: Option<String>,
    },
    /// The transfer never completed: too large, stalled, or the upstream
    /// refused it.
    Failed { status: StatusCode, detail: String },
    /// The upstream answered, but not with success.
    Upstream { status: u16, detail: String },
}

impl Pushed {
    /// A mismatch answers 422 and, crucially, without the stored reference.
    ///
    /// The hash is only known once the last byte has gone, so the bytes are
    /// already upstream — the check detects, it cannot prevent. Withholding the
    /// reference is what makes the detection worth having: nothing downstream
    /// can name bytes it was never told the name of, so no send can act on
    /// them. They linger upstream as an unreferenced orphan, which is a fact
    /// worth stating rather than papering over.
    fn refused(detail: String, measured_bytes: u64, measured_sha256: Option<String>) -> Self {
        Pushed::Mismatch {
            detail,
            measured_bytes,
            measured_sha256,
        }
    }
}

impl IntoResponse for Pushed {
    fn into_response(self) -> Response {
        match self {
            Pushed::Accepted {
                status, descriptor, ..
            } => {
                let body = serde_json::json!({
                    "media_path": descriptor.media_path,
                    "sha256": descriptor.sha256,
                    "mime": descriptor.mime,
                    "size": descriptor.size_bytes,
                    "filename": descriptor.filename,
                });
                (
                    StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
                    axum::Json(body),
                )
                    .into_response()
            }
            Pushed::Mismatch { detail, .. } => {
                (StatusCode::UNPROCESSABLE_ENTITY, detail).into_response()
            }
            Pushed::Failed { status, detail } => (status, detail).into_response(),
            Pushed::Upstream { status, detail } => (
                StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                detail,
            )
                .into_response(),
        }
    }
}

/// Stream the body upstream and reconcile what came back against what was
/// approved.
///
/// `Err` carries a [`Pushed`] too: both arms audit, and splitting the type
/// would mean two shapes to keep in step for no gain.
async fn push(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    row: &UploadTokenRow,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Result<Pushed, Pushed> {
    let request: ActionRequest = serde_json::from_value(row.request.clone()).map_err(|e| {
        // Only reachable if a row was written by an incompatible build.
        tracing::error!(token_id = %row.id, error = %e, "upload: stored request unreadable");
        Pushed::Failed {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            detail: "upload failed".into(),
        }
    })?;

    let max_bytes = row.max_bytes.max(0) as u64;
    // A stated length over the cap is refused before a byte moves. The
    // mid-stream meter is still the real enforcement — a chunked body states
    // no length, and a caller is free to state one that is untrue.
    if let Some(len) = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        && len > max_bytes
    {
        return Err(Pushed::Failed {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            detail: format!("upload of {len} bytes exceeds the {max_bytes}-byte limit"),
        });
    }

    let resolved =
        deferred_download::resolve_for_replay(state, scope, row.service_key.as_deref(), &request)
            .await
            .map_err(|e| Pushed::Failed {
                status: StatusCode::BAD_GATEWAY,
                detail: format!("upload credential resolution failed: {e}"),
            })?;

    let mut out_headers = resolved.headers.clone();
    for name in FORWARDED_UPLOAD_HEADERS {
        if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) {
            let v = value.trim();
            let generic = GENERIC_CONTENT_TYPES.iter().any(|g| {
                v.split(';')
                    .next()
                    .unwrap_or(v)
                    .trim()
                    .eq_ignore_ascii_case(g)
            });
            if !v.is_empty() && !generic {
                out_headers.insert(name.to_string(), v.to_string());
            }
        }
    }
    // Fall back to what the caller declared at mint time. Still nothing if it
    // declared nothing — a byte route that sniffs would rather be told nothing
    // than told something untrue.
    if !out_headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("content-type"))
        && let Some(mime) = row.declared_mime.as_deref()
    {
        out_headers.insert("content-type".to_string(), mime.to_string());
    }

    let url = with_filename(
        &resolved.url,
        row.filename_param.as_deref(),
        row.declared_filename.as_deref(),
    );

    let (metered, meter) = proxy_upload::metered_body(
        body,
        proxy_upload::Limit {
            max_bytes,
            declared_bytes: row.declared_size_bytes.map(|n| n.max(0) as u64),
            idle: std::time::Duration::from_millis(state.config.call_stream_idle_timeout_ms),
        },
    );

    let response = crate::services::http_caller::call_streaming_upload(
        &state.http_client,
        &request.method,
        &url,
        &out_headers,
        metered,
    )
    .await
    .map_err(|e| {
        // The transfer aborted, and only the meter knows why: the abort reaches
        // us as a generic reqwest failure, so ask the meter rather than reading
        // the error's text. Over the ceiling is the caller's problem (413);
        // anything else is the upstream's (502).
        let status = if meter.exceeded() {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_GATEWAY
        };
        Pushed::Failed {
            status,
            detail: format!("upload failed: {e}"),
        }
    })?;

    let status = response.status().as_u16();
    let upstream_body = read_capped(response).await.map_err(|e| Pushed::Failed {
        status: StatusCode::BAD_GATEWAY,
        detail: format!("upload response unreadable: {e}"),
    })?;

    if !(200..300).contains(&status) {
        return Err(Pushed::Upstream {
            status,
            detail: truncate(&upstream_body, 512),
        });
    }

    // `None` means the body was never read to completion — the upstream
    // answered before consuming it. Fail closed: reporting a verification that
    // did not happen is worse than not verifying, because it is believed.
    let Some(measured) = meter.finish() else {
        return Err(Pushed::refused(
            "upload could not be verified: the upstream answered before the body was \
             fully sent, so the gateway never measured what it stored"
                .into(),
            0,
            None,
        ));
    };
    let measured_hex = measured.hex();

    if let Some(declared) = row.declared_size_bytes
        && measured.bytes != declared.max(0) as u64
    {
        return Err(Pushed::refused(
            format!(
                "upload size mismatch: declared {declared} bytes, received {}",
                measured.bytes
            ),
            measured.bytes,
            Some(measured_hex),
        ));
    }
    if let Some(declared) = row.declared_sha256.as_deref()
        && !declared.eq_ignore_ascii_case(&measured_hex)
    {
        return Err(Pushed::refused(
            format!("upload content mismatch: declared sha256 {declared}, received {measured_hex}"),
            measured.bytes,
            Some(measured_hex),
        ));
    }

    let spec = upload_result_spec(row);
    let mut descriptor = read_descriptor(
        &upstream_body,
        spec.as_ref(),
        std::time::Duration::from_millis(state.config.filter_timeout_ms),
    )
    .await
    .map_err(|detail| Pushed::Upstream {
        status: StatusCode::BAD_GATEWAY.as_u16(),
        detail,
    })?;

    // Cross-check the upstream's own digest against ours. A disagreement means
    // one of the two is describing different bytes, and guessing which would be
    // exactly the wrong instinct: record neither as authoritative, refuse.
    if let Some(upstream_hash) = descriptor.sha256.as_deref()
        && !upstream_hash.eq_ignore_ascii_case(&measured_hex)
    {
        return Err(Pushed::refused(
            format!(
                "upstream stored a different object than was sent: it reports sha256 \
                 {upstream_hash}, the gateway measured {measured_hex}"
            ),
            measured.bytes,
            Some(measured_hex),
        ));
    }

    // Fill the gaps the upstream left from what was declared, never overwrite
    // what it stated: it is the authority on what it stored.
    if descriptor.sha256.is_none() {
        descriptor.sha256 = Some(measured_hex.clone());
    }
    if descriptor.size_bytes.is_none() {
        descriptor.size_bytes = Some(measured.bytes as i64);
    }
    if descriptor.filename.is_none() {
        descriptor.filename = row.declared_filename.clone();
    }
    if descriptor.mime.is_none() {
        descriptor.mime = row.declared_mime.clone();
    }

    // Best-effort, and deliberately not fatal on either. The push succeeded;
    // failing it because a bookkeeping row would not write would trade a
    // working upload for a tidier ledger.
    if upload_token::complete(
        state.db(ext),
        row.id,
        overslash_db::repos::upload_token::StoredDescriptor {
            media_path: &descriptor.media_path,
            sha256: descriptor.sha256.as_deref(),
            size_bytes: descriptor.size_bytes,
            mime: descriptor.mime.as_deref(),
            filename: descriptor.filename.as_deref(),
        },
    )
    .await
    .is_err()
    {
        tracing::warn!(token_id = %row.id, "upload: completion not recorded");
    }
    proxy_upload::record_uploaded(
        state.db(ext),
        row.org_id,
        row.service_instance_id,
        row.service_key.as_deref(),
        &descriptor,
    )
    .await;

    Ok(Pushed::Accepted {
        status,
        descriptor,
        measured_bytes: measured.bytes,
        measured_sha256: measured_hex,
    })
}

/// The `result` jq block, recovered from the token's own row.
///
/// Returns `None` when the template declared none, in which case the response
/// is read as the conventional flat descriptor. Kept as a function so the
/// "where does the spec come from at redemption time" question has one answer.
fn upload_result_spec(row: &UploadTokenRow) -> Option<UploadResultSpec> {
    let raw = row.result_spec.as_ref()?;
    match serde_json::from_value(raw.clone()) {
        Ok(spec) => Some(spec),
        Err(e) => {
            // Only reachable if a row was written by an incompatible build.
            // Falling back to the flat reader beats failing a push whose bytes
            // already landed.
            tracing::warn!(token_id = %row.id, error = %e, "upload: stored result spec unreadable");
            None
        }
    }
}

/// Read the upstream's descriptor out of its response body.
///
/// With a `result` block, through jq — reusing the disclosure runner rather
/// than a second jq harness, exactly as the download mint does, so the timeout,
/// the input ceiling and the `spawn_blocking` are not re-implemented. Without
/// one, through the conventional flat keys, so a target that already answers
/// `{media_path, sha256, mime, size, filename}` needs no declaration at all.
async fn read_descriptor(
    body: &str,
    spec: Option<&UploadResultSpec>,
    filter_timeout: std::time::Duration,
) -> Result<proxy_upload::UploadedDescriptor, String> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| format!("upload target did not answer with JSON: {e}"))?;

    let Some(spec) = spec else {
        let get = |k: &str| {
            value
                .get(k)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        };
        let media_path = get("media_path")
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| "upload target returned no media_path".to_string())?;
        return Ok(proxy_upload::UploadedDescriptor {
            media_path,
            sha256: get("sha256"),
            mime: get("mime"),
            size_bytes: value.get("size").and_then(serde_json::Value::as_i64),
            filename: get("filename"),
        });
    };

    let mut fields = vec![DisclosureField {
        label: "media_path".into(),
        filter: spec.media_path.clone(),
        max_chars: None,
        primary: false,
    }];
    for (label, filter) in [
        ("sha256", spec.sha256.as_ref()),
        ("mime", spec.mime.as_ref()),
        ("size", spec.size.as_ref()),
        ("filename", spec.filename.as_ref()),
    ] {
        if let Some(f) = filter {
            fields.push(DisclosureField {
                label: label.into(),
                filter: f.clone(),
                max_chars: None,
                primary: false,
            });
        }
    }
    let disclosed = crate::services::disclosure::run_disclosures(&fields, &value, filter_timeout)
        .await
        .map_err(|e| format!("upload result filters failed: {e}"))?;
    // Joined on label because the runner drops zero-yield filters, so positions
    // shift. Same reason the download mint joins on label.
    let pick = |label: &str| -> Option<String> {
        disclosed
            .iter()
            .find(|d| d.label == label)
            .and_then(|d| d.value.clone())
            .filter(|s| !s.trim().is_empty())
    };
    let media_path = pick("media_path")
        .ok_or_else(|| "upload target returned no value for the declared media_path".to_string())?;
    Ok(proxy_upload::UploadedDescriptor {
        media_path,
        sha256: pick("sha256"),
        mime: pick("mime"),
        size_bytes: pick("size").and_then(|s| s.trim().parse::<i64>().ok()),
        filename: pick("filename"),
    })
}

/// Append the token's declared filename under the parameter name the template
/// said the byte route takes it in.
///
/// Both halves come off the token, and both have to be present: a route that
/// declares no `filename_param` takes none, so appending a guessed `filename=`
/// would put an unrecognized parameter on someone else's API. Percent-encoded
/// via `query_pairs_mut` rather than formatted in, because the value is
/// caller-supplied and a filename containing `&` would otherwise become a
/// second parameter.
fn with_filename(url: &str, param: Option<&str>, filename: Option<&str>) -> String {
    let (Some(param), Some(name)) = (
        param.map(str::trim).filter(|s| !s.is_empty()),
        filename.map(str::trim).filter(|s| !s.is_empty()),
    ) else {
        return url.to_string();
    };
    match url::Url::parse(url) {
        Ok(mut u) => {
            u.query_pairs_mut().append_pair(param, name);
            u.to_string()
        }
        // Unreachable — the URL was validated at mint. Sending the file
        // unnamed beats failing a push that would otherwise work.
        Err(_) => url.to_string(),
    }
}

/// Read a bounded response body. The answer is a small JSON descriptor;
/// anything near the cap is a misconfigured target rather than a big answer.
async fn read_capped(response: reqwest::Response) -> Result<String, String> {
    use futures_util::StreamExt as _;
    let mut collected: Vec<u8> = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        collected.extend_from_slice(&chunk);
        if collected.len() > MAX_UPSTREAM_RESPONSE_BYTES {
            return Err(format!(
                "upload target answered with more than {MAX_UPSTREAM_RESPONSE_BYTES} bytes"
            ));
        }
    }
    Ok(String::from_utf8_lossy(&collected).into_owned())
}

/// Crop to `max` bytes without splitting a codepoint.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    s[..s.floor_char_boundary(max)].to_string()
}

/// Audit the redemption. Sibling of `action.downloaded`: like that row the body
/// is never buffered so it cannot be captured, and like it the row exists so a
/// deferred push is not a hole in the trail between "agent was allowed to
/// upload" and "bytes entered the service".
///
/// Declared *and* measured are both recorded, because a divergence between them
/// is the whole signal — the row is the only place it survives.
async fn log_upload(scope: &OrgScope, row: &UploadTokenRow, ip: &str, outcome: &Pushed) {
    let (status, is_error, detail, bytes, sha) = match outcome {
        Pushed::Accepted {
            status,
            measured_bytes,
            measured_sha256,
            ..
        } => (
            Some(*status),
            false,
            None,
            Some(*measured_bytes),
            Some(measured_sha256.clone()),
        ),
        Pushed::Mismatch {
            detail,
            measured_bytes,
            measured_sha256,
        } => (
            Some(422),
            true,
            Some(detail.clone()),
            Some(*measured_bytes),
            measured_sha256.clone(),
        ),
        Pushed::Failed { status, detail } => (
            Some(status.as_u16()),
            true,
            Some(detail.clone()),
            None,
            None,
        ),
        Pushed::Upstream { status, detail } => {
            (Some(*status), true, Some(detail.clone()), None, None)
        }
    };
    let stored_path = match outcome {
        Pushed::Accepted { descriptor, .. } => Some(descriptor.media_path.clone()),
        _ => None,
    };
    let _ = scope
        .clone()
        .log_audit(AuditEntry {
            org_id: row.org_id,
            identity_id: Some(row.identity_id),
            action: "action.uploaded",
            resource_type: row.service_key.as_deref(),
            resource_id: None,
            detail: serde_json::json!({
                "runtime": "upload",
                "service": row.service_key,
                "action": row.action_key,
                "status_code": status,
                "is_error": is_error,
                "error": detail,
                "declared_sha256": row.declared_sha256,
                "declared_size_bytes": row.declared_size_bytes,
                "declared_filename": row.declared_filename,
                "declared_mime": row.declared_mime,
                "measured_sha256": sha,
                "measured_size_bytes": bytes,
                "stored_media_path": stored_path,
                "request": { "skipped": "streamed" },
            }),
            description: Some("Upload capability redeemed"),
            ip_address: Some(ip),
        })
        .await;
}

#[cfg(test)]
mod with_filename_tests {
    use super::with_filename;

    const URL: &str = "https://wa.example.com/media";

    #[test]
    fn uses_the_parameter_name_the_template_declared() {
        let out = with_filename(URL, Some("name"), Some("clip.mp4"));
        assert_eq!(out, "https://wa.example.com/media?name=clip.mp4");
    }

    /// A route that takes no filename parameter must not be handed a guessed
    /// one — the declaration is what says the parameter exists at all.
    #[test]
    fn appends_nothing_when_the_template_declares_no_parameter() {
        assert_eq!(with_filename(URL, None, Some("clip.mp4")), URL);
    }

    #[test]
    fn appends_nothing_when_no_filename_was_declared() {
        assert_eq!(with_filename(URL, Some("filename"), None), URL);
    }

    /// The value is caller-supplied, so it is encoded rather than formatted in:
    /// an `&` would otherwise start a second parameter on the byte route.
    #[test]
    fn a_filename_cannot_smuggle_a_second_parameter() {
        let out = with_filename(URL, Some("filename"), Some("a&evil=1.txt"));
        assert_eq!(
            out,
            "https://wa.example.com/media?filename=a%26evil%3D1.txt"
        );
    }
}
