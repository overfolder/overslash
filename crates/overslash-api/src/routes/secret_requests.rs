//! Standalone "Provide Secret" flow.
//!
//! Three endpoints:
//! - `POST /v1/secrets/requests` (authenticated): mint a request + signed URL.
//! - `GET  /public/secrets/provide/{req_id}?token=...`: render-time metadata.
//! - `POST /public/secrets/provide/{req_id}`: submit value, encrypt, store.
//!
//! Public endpoints take no auth extractor — security comes from the JWT in
//! the URL plus a server-side `secret_requests` row that enforces single-use
//! and binds the token to a specific secret slot on a specific identity.
//!
//! See `SPEC.md` §5 / §11 and `docs/design/INDEX.md`.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use overslash_db::repos::{audit::AuditEntry, secret_request};
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{ClientIp, WriteAcl},
    services::jwt::{self, SECRET_REQUEST_KIND, SecretRequestClaims},
    services::session::extract_session,
};
use overslash_core::crypto;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/secrets/requests", post(create_secret_request))
        .route(
            "/public/secrets/provide/{req_id}",
            get(get_provide).post(submit_provide),
        )
}

// ─── 1. Mint (authenticated) ──────────────────────────────────────────

#[derive(Deserialize)]
struct CreateSecretRequestBody {
    secret_name: String,
    /// Identity that the secret belongs to / will be `created_by` for. Defaults
    /// to the caller's own identity if omitted.
    identity_id: Option<Uuid>,
    reason: Option<String>,
    /// Time-to-live for the URL, in seconds. Capped at 24h, defaults to 1h.
    ttl_seconds: Option<u64>,
}

#[derive(Serialize)]
struct CreateSecretRequestResponse {
    id: String,
    token: String,
    url: String,
    expires_at: String,
}

const DEFAULT_TTL: u64 = 3600;
const MAX_TTL: u64 = 86_400;

async fn create_secret_request(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Json(req): Json<CreateSecretRequestBody>,
) -> Result<Json<CreateSecretRequestResponse>> {
    if req.secret_name.trim().is_empty() {
        return Err(AppError::BadRequest("secret_name is required".into()));
    }

    let caller_identity = acl
        .identity_id
        .ok_or_else(|| AppError::Unauthorized("identity required".into()))?;
    let target_identity = req.identity_id.unwrap_or(caller_identity);

    // Verify the target identity belongs to the same org so a caller cannot
    // mint a request scoped to another tenant.
    let scope = OrgScope::new(acl.org_id, state.db.clone());
    let _target = scope
        .get_identity(target_identity)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    let ttl = req.ttl_seconds.unwrap_or(DEFAULT_TTL).clamp(60, MAX_TTL) as i64;
    let now = time::OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::seconds(ttl);

    let req_id = format!("req_{}", Uuid::new_v4().simple());

    // Capture the org's User-Signed-Mode policy at *mint* time so flipping
    // the toggle later never retroactively breaks in-flight URLs. Default to
    // allowing unsigned if the org has no explicit setting (backwards
    // compat: existing orgs keep their current open behavior).
    let allow_unsigned =
        overslash_db::repos::org::get_allow_unsigned_secret_provide(&state.db, acl.org_id)
            .await?
            .unwrap_or(true);
    let require_user_session = !allow_unsigned;

    // Mint the JWT first so we can hash it before persisting.
    let signing_key = signing_key_bytes(&state);
    let claims = SecretRequestClaims {
        req: req_id.clone(),
        org: acl.org_id,
        iat: now.unix_timestamp(),
        exp: expires_at.unix_timestamp(),
        kind: SECRET_REQUEST_KIND.into(),
    };
    let token = jwt::mint_secret_request(&signing_key, &claims)
        .map_err(|e| AppError::Internal(format!("jwt mint: {e}")))?;
    let token_hash = sha256(&token);

    secret_request::create(
        &state.db,
        &req_id,
        acl.org_id,
        target_identity,
        req.secret_name.trim(),
        caller_identity,
        req.reason.as_deref(),
        &token_hash,
        expires_at,
        require_user_session,
    )
    .await?;

    // Approval/consent URL pattern mirrors enrollment.rs::initiate_enrollment.
    let dash = state.config.dashboard_url.trim_end_matches('/');
    let url = if dash.starts_with("http://") || dash.starts_with("https://") {
        format!("{dash}/secrets/provide/{req_id}?token={token}")
    } else {
        format!(
            "{}{dash}/secrets/provide/{req_id}?token={token}",
            state.config.public_url.trim_end_matches('/')
        )
    };

    let _ = OrgScope::new(acl.org_id, state.db.clone())
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: Some(caller_identity),
            action: "secret_request.created",
            resource_type: Some("secret_request"),
            resource_id: None,
            detail: serde_json::json!({
                "id": &req_id,
                "secret_name": &req.secret_name,
                "target_identity_id": target_identity,
                "require_user_session": require_user_session,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(CreateSecretRequestResponse {
        id: req_id,
        token,
        url,
        expires_at: expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| expires_at.to_string()),
    }))
}

// ─── 2. Public GET (page metadata) ────────────────────────────────────

#[derive(Deserialize)]
struct TokenQuery {
    token: String,
}

#[derive(Serialize)]
struct ProvideMetadata {
    id: String,
    secret_name: String,
    identity_label: String,
    requested_by_label: String,
    reason: Option<String>,
    expires_at: String,
    created_at: String,
    /// True iff the request was minted while the org had
    /// `allow_unsigned_secret_provide = false`. When set, the page must
    /// refuse to submit unless a same-org session is also present.
    require_user_session: bool,
    /// Populated iff the visitor carried a valid `oss_session` cookie for
    /// the same org as this request. Lets the page render a "Signed in as
    /// …" banner so the visitor knows their identity will be captured on
    /// the audit trail. Cross-tenant sessions are silently ignored.
    viewer: Option<ViewerInfo>,
}

#[derive(Serialize)]
struct ViewerInfo {
    identity_id: Uuid,
    email: String,
}

async fn get_provide(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(req_id): Path<String>,
    Query(q): Query<TokenQuery>,
) -> Result<Json<ProvideMetadata>> {
    let row = load_and_validate(&state, &req_id, &q.token).await?;

    let scope = OrgScope::new(row.org_id, state.db.clone());
    let identity_label = scope
        .get_identity(row.identity_id)
        .await?
        .map(|i| i.name)
        .unwrap_or_else(|| row.identity_id.to_string());
    let requested_by_label = scope
        .get_identity(row.requested_by)
        .await?
        .map(|i| i.name)
        .unwrap_or_else(|| row.requested_by.to_string());

    // Opportunistic session binding: if the visitor happens to already be
    // signed in to the same org, surface that so the page can show a banner.
    // Cross-tenant sessions are discarded — never echo identity from another
    // tenant on a public page.
    let viewer = extract_session(&state, &headers)
        .filter(|s| s.org == row.org_id)
        .map(|s| ViewerInfo {
            identity_id: s.sub,
            email: s.email,
        });

    Ok(Json(ProvideMetadata {
        id: row.id,
        secret_name: row.secret_name,
        identity_label,
        requested_by_label,
        reason: row.reason,
        expires_at: row
            .expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| row.expires_at.to_string()),
        created_at: row
            .created_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| row.created_at.to_string()),
        require_user_session: row.require_user_session,
        viewer,
    }))
}

// ─── 3. Public POST (submit value) ────────────────────────────────────

#[derive(Deserialize)]
struct SubmitBody {
    token: String,
    value: String,
}

#[derive(Serialize)]
struct SubmitResponse {
    ok: bool,
    name: String,
    version: i32,
}

async fn submit_provide(
    State(state): State<AppState>,
    headers: HeaderMap,
    ip: ClientIp,
    Path(req_id): Path<String>,
    Json(body): Json<SubmitBody>,
) -> Result<Json<SubmitResponse>> {
    if body.value.is_empty() {
        return Err(AppError::BadRequest("value is required".into()));
    }
    let row = load_and_validate(&state, &req_id, &body.token).await?;

    // Resolve any same-org session cookie the visitor happens to carry.
    // Cross-tenant sessions are discarded (treated as anonymous). We do NOT
    // trust a session alone — the URL JWT is always the capability gate. The
    // session is purely an identity attestation layered on top.
    let session = extract_session(&state, &headers).filter(|s| s.org == row.org_id);

    // Policy gate: if the row was minted under User-Signed-Mode-required,
    // a same-org session is mandatory. This is the only path by which the
    // public endpoint rejects an otherwise-valid JWT.
    if row.require_user_session && session.is_none() {
        return Err(AppError::Unauthorized("user_session_required".into()));
    }

    let provisioned_by_user_id = session.as_ref().map(|s| s.sub);

    // Single-use guard *before* writing to the vault. If a parallel request
    // already fulfilled this row, abort. Done *after* the policy check so a
    // rejected submission does not burn the request.
    if !secret_request::mark_fulfilled(&state.db, &req_id).await? {
        return Err(AppError::Gone("already_fulfilled".into()));
    }

    // Mirrors routes/secrets.rs::put_secret encryption + storage path.
    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let encrypted = crypto::encrypt(&enc_key, body.value.as_bytes())?;

    let scope = OrgScope::new(row.org_id, state.db.clone());
    let (stored, _ver) = scope
        .put_secret(
            &row.secret_name,
            &encrypted,
            Some(row.identity_id),
            provisioned_by_user_id,
        )
        .await?;

    // When a session is present, attribute the audit entry to the human who
    // pasted the value. Otherwise fall back to the target identity (the one
    // that owns the secret slot) to keep the audit row anchored to *some*
    // identity for compliance queries.
    let audit_identity = provisioned_by_user_id.or(Some(row.identity_id));
    let _ = scope
        .log_audit(AuditEntry {
            org_id: row.org_id,
            identity_id: audit_identity,
            action: "secret_request.fulfilled",
            resource_type: Some("secret_request"),
            resource_id: None,
            detail: serde_json::json!({
                "id": &row.id,
                "name": &stored.name,
                "version": stored.current_version,
                "provisioned_by_user_id": provisioned_by_user_id,
                "user_signed": provisioned_by_user_id.is_some(),
                "require_user_session": row.require_user_session,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(SubmitResponse {
        ok: true,
        name: stored.name,
        version: stored.current_version,
    }))
}

// ─── helpers ──────────────────────────────────────────────────────────

/// Validate the JWT, look up the row, and check expiry / fulfillment / token
/// hash. Returns the row on success. All failures map to neutral, stable
/// codes — never echo internal detail to the public client.
async fn load_and_validate(
    state: &AppState,
    req_id: &str,
    token: &str,
) -> Result<overslash_db::repos::secret_request::SecretRequestRow> {
    let signing_key = signing_key_bytes(state);
    let claims = jwt::verify_secret_request(&signing_key, token)
        .map_err(|_| AppError::BadRequest("invalid_token".into()))?;
    if claims.req != req_id {
        return Err(AppError::BadRequest("invalid_token".into()));
    }

    let row = secret_request::get(&state.db, req_id)
        .await?
        .ok_or_else(|| AppError::NotFound("not_found".into()))?;

    if row.org_id != claims.org {
        return Err(AppError::BadRequest("invalid_token".into()));
    }
    // Constant-time-ish hash compare. token_hash is short and not secret-bearing,
    // but use a length-then-eq check anyway.
    let provided_hash = sha256(token);
    if provided_hash != row.token_hash {
        return Err(AppError::BadRequest("invalid_token".into()));
    }
    if row.expires_at < time::OffsetDateTime::now_utc() {
        return Err(AppError::Gone("expired".into()));
    }
    if row.fulfilled_at.is_some() {
        return Err(AppError::Gone("already_fulfilled".into()));
    }
    Ok(row)
}

fn signing_key_bytes(state: &AppState) -> Vec<u8> {
    hex::decode(&state.config.signing_key)
        .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec())
}

fn sha256(s: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().to_vec()
}
