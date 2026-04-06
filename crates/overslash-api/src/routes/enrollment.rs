use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use overslash_db::repos::{
    api_key,
    audit::{self, AuditEntry},
    enrollment_token, identity, pending_enrollment,
};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp},
    services::jwt,
};

pub fn router() -> Router<AppState> {
    Router::new()
        // Flow 1: Enrollment token CRUD
        .route("/v1/enrollment-tokens", post(create_enrollment_token))
        .route("/v1/enrollment-tokens", get(list_enrollment_tokens))
        .route(
            "/v1/enrollment-tokens/{id}",
            delete(revoke_enrollment_token),
        )
        // Flow 1: Agent consumes token
        .route("/v1/enroll", post(enroll_with_token))
        // Flow 2: Agent-initiated
        .route("/v1/enroll/initiate", post(initiate_enrollment))
        .route("/v1/enroll/status", get(poll_enrollment))
        // Flow 2: User approves (browser-facing)
        .route(
            "/enroll/approve/{approval_token}",
            get(get_enrollment_approval),
        )
        .route("/enroll/approve/{approval_token}", post(resolve_enrollment))
}

// ─── Flow 1: Enrollment Token CRUD ─────────────────────────────────────

#[derive(Deserialize)]
struct CreateEnrollmentTokenRequest {
    identity_id: Uuid,
    #[serde(default = "default_token_expiry")]
    expires_in_secs: u64,
}

fn default_token_expiry() -> u64 {
    900 // 15 minutes
}

#[derive(Serialize)]
struct EnrollmentTokenResponse {
    id: Uuid,
    token: String,
    token_prefix: String,
    identity_id: Uuid,
    expires_at: String,
}

async fn create_enrollment_token(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Json(req): Json<CreateEnrollmentTokenRequest>,
) -> Result<Json<EnrollmentTokenResponse>> {
    let auth = acl;
    // Verify identity exists and belongs to this org
    let ident = identity::get_by_id(&state.db, req.identity_id).await?;
    let ident = crate::ownership::require_org_owned(ident, auth.org_id, "identity")?;
    if ident.kind != "agent" && ident.kind != "sub_agent" {
        return Err(AppError::BadRequest(
            "enrollment tokens can only be created for agent or sub_agent identities".into(),
        ));
    }

    let (raw_token, hash, prefix) = generate_prefixed_token("ose_")?;

    let expires_at =
        time::OffsetDateTime::now_utc() + time::Duration::seconds(req.expires_in_secs as i64);

    let row = enrollment_token::create(
        &state.db,
        auth.org_id,
        req.identity_id,
        &hash,
        &prefix,
        expires_at,
        auth.identity_id,
    )
    .await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "enrollment_token.created",
            resource_type: Some("enrollment_token"),
            resource_id: Some(row.id),
            detail: json!({ "identity_id": req.identity_id, "token_prefix": &prefix }),
            description: None,
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(EnrollmentTokenResponse {
        id: row.id,
        token: raw_token,
        token_prefix: prefix,
        identity_id: req.identity_id,
        expires_at: row.expires_at.to_string(),
    }))
}

async fn list_enrollment_tokens(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
) -> Result<Json<Vec<serde_json::Value>>> {
    let auth = acl;
    let rows = enrollment_token::list_by_org(&state.db, auth.org_id).await?;
    let items: Vec<_> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "identity_id": r.identity_id,
                "token_prefix": r.token_prefix,
                "expires_at": r.expires_at.to_string(),
                "created_at": r.created_at.to_string(),
            })
        })
        .collect();
    Ok(Json(items))
}

async fn revoke_enrollment_token(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let auth = acl;
    let revoked = enrollment_token::revoke(&state.db, id, auth.org_id).await?;
    if !revoked {
        return Err(AppError::NotFound("token not found or already used".into()));
    }

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "enrollment_token.revoked",
            resource_type: Some("enrollment_token"),
            resource_id: Some(id),
            detail: json!({}),
            description: None,
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

// ─── Flow 1: Agent Enrolls with Token ──────────────────────────────────

#[derive(Deserialize)]
struct EnrollRequest {
    token: String,
}

async fn enroll_with_token(
    State(state): State<AppState>,
    ip: ClientIp,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<serde_json::Value>> {
    if !req.token.starts_with("ose_") || req.token.len() < 12 || !req.token.is_ascii() {
        return Err(AppError::Unauthorized("invalid token format".into()));
    }

    let prefix = &req.token[..12];
    let token_row = enrollment_token::find_by_prefix(&state.db, prefix)
        .await?
        .ok_or_else(|| AppError::Unauthorized("invalid or consumed enrollment token".into()))?;

    // Check expiry
    if token_row.expires_at < time::OffsetDateTime::now_utc() {
        return Err(AppError::Unauthorized("enrollment token expired".into()));
    }

    // Verify hash
    verify_argon2_hash(&req.token, &token_row.token_hash)?;

    // Mark as used (atomic — if another request races, one will fail)
    let used = enrollment_token::mark_used(&state.db, token_row.id).await?;
    if !used {
        return Err(AppError::Conflict(
            "enrollment token already consumed".into(),
        ));
    }

    // Generate API key for the identity
    let (raw_key, key_hash, key_prefix) = generate_prefixed_token("osk_")?;
    let _key_row = api_key::create(
        &state.db,
        token_row.org_id,
        Some(token_row.identity_id),
        "enrollment",
        &key_hash,
        &key_prefix,
        &[],
    )
    .await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: token_row.org_id,
            identity_id: Some(token_row.identity_id),
            action: "enrollment.completed",
            resource_type: Some("identity"),
            resource_id: Some(token_row.identity_id),
            detail: json!({ "method": "token", "token_prefix": prefix }),
            description: None,
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(json!({
        "api_key": raw_key,
        "identity_id": token_row.identity_id,
        "org_id": token_row.org_id,
    })))
}

// ─── Flow 2: Agent-Initiated Enrollment ────────────────────────────────

#[derive(Deserialize)]
struct InitiateRequest {
    name: String,
    platform: Option<String>,
    #[serde(default)]
    metadata: serde_json::Value,
}

async fn initiate_enrollment(
    State(state): State<AppState>,
    ip: ClientIp,
    Json(req): Json<InitiateRequest>,
) -> Result<Json<serde_json::Value>> {
    // Generate poll token (agent uses to check status)
    let (raw_poll_token, poll_hash, poll_prefix) = generate_prefixed_token("osp_")?;

    // Generate approval token (HMAC-signed UUID for the browser URL)
    let approval_token = generate_approval_token(&state.config.signing_key)?;

    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::hours(1);

    let row = pending_enrollment::create(
        &state.db,
        &req.name,
        req.platform.as_deref(),
        req.metadata,
        &approval_token,
        &poll_hash,
        &poll_prefix,
        expires_at,
        ip.0.as_deref(),
    )
    .await?;

    // Approval URL points to the dashboard consent page, not the backend API.
    // dashboard_url defaults to "/" so prefer public_url when it's relative.
    let dash = state.config.dashboard_url.trim_end_matches('/');
    let approval_url = if dash.starts_with("http://") || dash.starts_with("https://") {
        format!("{dash}/enroll/consent/{approval_token}")
    } else {
        format!(
            "{}{dash}/enroll/consent/{approval_token}",
            state.config.public_url.trim_end_matches('/')
        )
    };

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: Uuid::nil(),
            identity_id: None,
            action: "enrollment.initiated",
            resource_type: Some("pending_enrollment"),
            resource_id: Some(row.id),
            detail: json!({ "name": &req.name, "platform": &req.platform }),
            description: None,
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(json!({
        "enrollment_id": row.id,
        "approval_url": approval_url,
        "poll_token": raw_poll_token,
        "expires_at": row.expires_at.to_string(),
    })))
}

#[derive(Deserialize)]
struct PollQuery {
    poll_token: String,
}

async fn poll_enrollment(
    State(state): State<AppState>,
    Query(q): Query<PollQuery>,
) -> Result<Json<serde_json::Value>> {
    if !q.poll_token.starts_with("osp_") || q.poll_token.len() < 12 || !q.poll_token.is_ascii() {
        return Err(AppError::NotFound("not found".into()));
    }

    let prefix = &q.poll_token[..12];
    let row = pending_enrollment::find_by_poll_prefix(&state.db, prefix)
        .await?
        .ok_or_else(|| AppError::NotFound("enrollment not found".into()))?;

    // Verify poll token hash
    verify_argon2_hash(&q.poll_token, &row.poll_token_hash)?;

    // Check if expired and still pending
    if row.status == "pending" && row.expires_at < time::OffsetDateTime::now_utc() {
        // Expire it now
        let _ = pending_enrollment::expire_stale(&state.db).await;
        return Ok(Json(json!({ "status": "expired" })));
    }

    let mut resp = json!({ "status": row.status });
    if row.status == "approved" {
        if let Some(ref encrypted) = row.api_key_hash {
            // api_key_hash stores the encrypted raw key (not the argon2 hash)
            let raw_key = decrypt_for_poll(encrypted, &state.config.secrets_encryption_key)?;
            resp["api_key"] = json!(raw_key);
        }
        resp["identity_id"] = json!(row.identity_id);
        resp["org_id"] = json!(row.org_id);
    }

    Ok(Json(resp))
}

// ─── Flow 2: User Approves (browser-facing) ────────────────────────────

async fn get_enrollment_approval(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(approval_token): Path<String>,
) -> Result<Response> {
    let row = pending_enrollment::find_by_approval_token(&state.db, &approval_token)
        .await?
        .ok_or_else(|| AppError::NotFound("enrollment not found".into()))?;

    // Check expiration before status: a row may have already been marked
    // 'expired' by the cleanup job, and an unmarked-but-time-expired row
    // should also surface as 410 GONE rather than the generic resolved body.
    if row.status == "expired" || row.expires_at < time::OffsetDateTime::now_utc() {
        return Ok((
            StatusCode::GONE,
            Json(json!({ "status": "expired", "message": "enrollment has expired" })),
        )
            .into_response());
    }

    if row.status != "pending" {
        return Ok((
            StatusCode::OK,
            Json(json!({ "status": row.status, "message": "enrollment already resolved" })),
        )
            .into_response());
    }

    // Check for session — if no session, tell the client to authenticate
    let session = extract_session(&state, &headers);
    let Some(session) = session else {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "authentication required",
                "login_url": format!("{}/auth/google/login", state.config.public_url),
                "message": "Please log in to approve this enrollment",
            })),
        )
            .into_response());
    };

    // Bind the enrollment to this viewer's org on first authenticated view.
    // After this, only sessions in the same org can see/resolve it; everyone
    // else gets a 404. This prevents a leaked approval URL from being
    // claimed by a user in an unintended org.
    let row = pending_enrollment::claim_for_org(&state.db, row.id, session.org)
        .await?
        .ok_or_else(|| AppError::NotFound("enrollment not found".into()))?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "enrollment_id": row.id,
            "suggested_name": row.suggested_name,
            "platform": row.platform,
            "metadata": row.metadata,
            "status": row.status,
            "expires_at": row
                .expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| row.expires_at.to_string()),
            "created_at": row
                .created_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| row.created_at.to_string()),
            "requester_ip": row.requester_ip,
        })),
    )
        .into_response())
}

#[derive(Deserialize)]
struct ResolveEnrollmentRequest {
    decision: String, // "approve" or "deny"
    agent_name: Option<String>,
    parent_id: Option<Uuid>,
}

async fn resolve_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    ip: ClientIp,
    Path(approval_token): Path<String>,
    Json(req): Json<ResolveEnrollmentRequest>,
) -> Result<Json<serde_json::Value>> {
    // Require user session
    let session = extract_session(&state, &headers)
        .ok_or_else(|| AppError::Unauthorized("authentication required".into()))?;

    let row = pending_enrollment::find_by_approval_token(&state.db, &approval_token)
        .await?
        .ok_or_else(|| AppError::NotFound("enrollment not found".into()))?;

    if row.status != "pending" {
        return Err(AppError::Conflict("enrollment already resolved".into()));
    }

    if row.expires_at < time::OffsetDateTime::now_utc() {
        return Err(AppError::Conflict("enrollment has expired".into()));
    }

    // Atomically claim the enrollment for this caller's org. This succeeds if
    // the enrollment is unclaimed OR already claimed by the same org. A POST
    // from a different org (whether or not GET was called first) gets 404.
    let row = pending_enrollment::claim_for_org(&state.db, row.id, session.org)
        .await?
        .ok_or_else(|| AppError::NotFound("enrollment not found".into()))?;

    match req.decision.as_str() {
        "approve" => {
            let agent_name = req.agent_name.as_deref().unwrap_or(&row.suggested_name);

            // Resolve parent: caller-supplied parent_id (must belong to org) or default to approver
            let parent = if let Some(pid) = req.parent_id {
                let p = identity::get_by_id(&state.db, pid).await?;
                let p = crate::ownership::require_org_owned(p, session.org, "identity")?;
                if p.kind != "user" && p.kind != "agent" && p.kind != "sub_agent" {
                    return Err(AppError::BadRequest(
                        "parent must be a user, agent, or sub_agent".into(),
                    ));
                }
                p
            } else {
                identity::get_by_id(&state.db, session.sub)
                    .await?
                    .ok_or_else(|| {
                        AppError::BadRequest("approving user identity no longer exists".into())
                    })?
            };

            // Owner inherits the parent's ownership chain: if the parent is a user,
            // the user IS the owner; otherwise the new agent shares the parent's owner_id.
            let owner_id = if parent.kind == "user" {
                parent.id
            } else {
                parent.owner_id.ok_or_else(|| {
                    AppError::BadRequest(
                        "cannot enroll under an identity with no owner chain".into(),
                    )
                })?
            };

            // Create agent identity under the chosen parent
            let new_identity = identity::create_with_parent(
                &state.db,
                session.org,
                agent_name,
                "agent",
                None,
                parent.id,
                parent.depth + 1,
                owner_id,
            )
            .await?;

            // Generate API key for the new identity
            let (raw_key, key_hash, key_prefix) = generate_prefixed_token("osk_")?;
            let _key_row = api_key::create(
                &state.db,
                session.org,
                Some(new_identity.id),
                "enrollment",
                &key_hash,
                &key_prefix,
                &[],
            )
            .await?;

            // Update pending enrollment with approval details
            // Store the raw key temporarily so the agent can retrieve it via poll
            // We store the hash in the row, but we need a way to return the raw key.
            // Solution: store the raw key encrypted in metadata temporarily.
            let encrypted_key = encrypt_for_poll(&raw_key, &state.config.secrets_encryption_key)?;

            let approved = pending_enrollment::approve(
                &state.db,
                row.id,
                session.org,
                new_identity.id,
                &encrypted_key,
                &key_prefix,
                session.sub,
                agent_name,
            )
            .await?;

            if approved.is_none() {
                // Race condition: another request already approved/denied this enrollment.
                // Clean up the orphaned identity and key we just created.
                let _ = identity::delete(&state.db, new_identity.id).await;
                return Err(AppError::Conflict(
                    "enrollment already resolved by another request".into(),
                ));
            }

            let _ = audit::log(
                &state.db,
                &AuditEntry {
                    org_id: session.org,
                    identity_id: Some(session.sub),
                    action: "enrollment.approved",
                    resource_type: Some("pending_enrollment"),
                    resource_id: Some(row.id),
                    detail: json!({
                        "agent_name": agent_name,
                        "agent_identity_id": new_identity.id,
                    }),
                    description: None,
                    ip_address: ip.0.as_deref(),
                },
            )
            .await;

            Ok(Json(json!({
                "status": "approved",
                "identity_id": new_identity.id,
                "org_id": session.org,
            })))
        }
        "deny" => {
            let _ = pending_enrollment::deny(&state.db, row.id).await?;

            let _ = audit::log(
                &state.db,
                &AuditEntry {
                    org_id: session.org,
                    identity_id: Some(session.sub),
                    action: "enrollment.denied",
                    resource_type: Some("pending_enrollment"),
                    resource_id: Some(row.id),
                    detail: json!({ "suggested_name": &row.suggested_name }),
                    description: None,
                    ip_address: ip.0.as_deref(),
                },
            )
            .await;

            Ok(Json(json!({ "status": "denied" })))
        }
        other => Err(AppError::BadRequest(format!("invalid decision: {other}"))),
    }
}

// ─── Helpers ───────────────────────────────────────────────────────────

fn generate_prefixed_token(
    prefix: &str,
) -> std::result::Result<(String, String, String), AppError> {
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let encoded = hex::encode(bytes);
    let raw = format!("{prefix}{encoded}");
    let key_prefix = raw[..12].to_string();

    let salt =
        argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let hash =
        argon2::PasswordHasher::hash_password(&argon2::Argon2::default(), raw.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(format!("hash error: {e}")))?
            .to_string();

    Ok((raw, hash, key_prefix))
}

fn verify_argon2_hash(raw: &str, stored_hash: &str) -> std::result::Result<(), AppError> {
    let parsed = argon2::PasswordHash::new(stored_hash)
        .map_err(|_| AppError::Internal("invalid stored hash".into()))?;
    argon2::PasswordVerifier::verify_password(&argon2::Argon2::default(), raw.as_bytes(), &parsed)
        .map_err(|_| AppError::Unauthorized("invalid token".into()))?;
    Ok(())
}

fn generate_approval_token(signing_key: &str) -> std::result::Result<String, AppError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let id = Uuid::new_v4();
    let key_bytes = hex::decode(signing_key).unwrap_or_else(|_| signing_key.as_bytes().to_vec());
    let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes)
        .map_err(|e| AppError::Internal(format!("hmac error: {e}")))?;
    mac.update(id.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    Ok(format!("{}-{}", id, &sig[..16]))
}

fn extract_session(state: &AppState, headers: &HeaderMap) -> Option<jwt::Claims> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    let token = cookie_header
        .split(';')
        .find_map(|pair| pair.trim().strip_prefix("oss_session="))?;
    let signing_key = hex::decode(&state.config.signing_key)
        .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());
    jwt::verify(&signing_key, token).ok()
}

/// Encrypt the raw API key so it can be stored in the pending_enrollments row
/// and decrypted when the agent polls. Uses the existing encryption key.
fn encrypt_for_poll(
    raw_key: &str,
    encryption_key_hex: &str,
) -> std::result::Result<String, AppError> {
    let key = overslash_core::crypto::parse_hex_key(encryption_key_hex)
        .map_err(|e| AppError::Internal(format!("key parse error: {e}")))?;
    let encrypted = overslash_core::crypto::encrypt(&key, raw_key.as_bytes())
        .map_err(|e| AppError::Internal(format!("encrypt error: {e}")))?;
    Ok(hex::encode(encrypted))
}

fn decrypt_for_poll(
    encrypted_hex: &str,
    encryption_key_hex: &str,
) -> std::result::Result<String, AppError> {
    let key = overslash_core::crypto::parse_hex_key(encryption_key_hex)
        .map_err(|e| AppError::Internal(format!("key parse error: {e}")))?;
    let encrypted = hex::decode(encrypted_hex)
        .map_err(|e| AppError::Internal(format!("hex decode error: {e}")))?;
    let decrypted = overslash_core::crypto::decrypt(&key, &encrypted)
        .map_err(|e| AppError::Internal(format!("decrypt error: {e}")))?;
    String::from_utf8(decrypted).map_err(|e| AppError::Internal(format!("utf8 error: {e}")))
}
