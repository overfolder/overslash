//! Platform kernels for the secret-request handshake.
//!
//! The agent calls `overslash.request_secret` over MCP; this kernel mints a
//! signed, single-use URL the user can open to paste the value. The secret
//! value never traverses the agent — only the URL does. Mirrors the REST
//! endpoint at `routes/secret_requests.rs::create_secret_request`; both call
//! the same primitives (JWT mint, `secret_request::create`, audit log) so
//! the handshake is identical regardless of surface.
//!
//! Permission split (mirroring `manage_services_own / _share` from
//! `routes/groups.rs`): targeting the caller's own identity, or a descendant
//! of the caller, satisfies `request_secrets_own` (the YAML anchor on the
//! action). Targeting any other identity additionally requires admin-level
//! overslash access — i.e. `request_secrets_share`, which is dashboard-only
//! and never auto-grantable to agents.

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use overslash_core::permissions::AccessLevel;
use overslash_db::repos::{audit::AuditEntry, secret_request};
use overslash_db::scopes::OrgScope;

use super::jwt::{self, SECRET_REQUEST_KIND, SecretRequestClaims};
use super::permission_chain;
use super::platform_caller::PlatformCallContext;
use super::url_shortener;
use crate::error::AppError;
use crate::routes::util::fmt_time;

/// Default TTL for the signed provide URL. Kept short so a request the user
/// never opens drops off the table within the hour. Use the REST endpoint
/// (`POST /v1/secrets/requests`) when an override is needed.
const DEFAULT_TTL_SECS: i64 = 3600;

#[derive(Debug, Default, Deserialize)]
pub struct RequestSecretInput {
    pub secret_name: String,
    /// Identity that the secret will be persisted under. Defaults to the
    /// caller's own identity when omitted.
    #[serde(default)]
    pub identity_id: Option<Uuid>,
    /// Free-form rationale shown on the provide page so the human knows
    /// what they're being asked to paste.
    #[serde(default)]
    pub purpose: Option<String>,
}

pub async fn kernel_request_secret(
    ctx: PlatformCallContext,
    input: RequestSecretInput,
) -> Result<Value, AppError> {
    if input.secret_name.trim().is_empty() {
        return Err(AppError::BadRequest("secret_name is required".into()));
    }

    // Org-level API keys (no identity binding) cannot mint a request — the
    // row's `identity_id` and `requested_by` are NOT NULL, and there's no
    // sensible default that wouldn't drop us straight into the share path
    // without an admin gate.
    let caller_identity = ctx
        .identity_id
        .ok_or_else(|| AppError::BadRequest("identity required to request a secret".into()))?;
    let target = input.identity_id.unwrap_or(caller_identity);
    let scope = OrgScope::new(ctx.org_id, ctx.db.clone());
    let _target_row = scope
        .get_identity(target)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    // _own / _share split. The YAML anchor `request_secrets_own` already
    // gated the call at the action layer. Anything beyond self-or-descendant
    // additionally requires admin-level overslash access (i.e. the holder
    // of `request_secrets_share`). Mirrors the pattern in
    // routes/groups.rs:333-342.
    if target != caller_identity
        && !permission_chain::is_self_or_ancestor(&scope, caller_identity, target).await?
        && ctx.access_level < AccessLevel::Admin
    {
        return Err(AppError::Forbidden(
            "request_secrets_share required to mint a request for another identity".into(),
        ));
    }

    let now = time::OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::seconds(DEFAULT_TTL_SECS);

    let req_id = format!("req_{}", Uuid::new_v4().simple());

    // Capture the org's User-Signed-Mode policy at mint time so flipping the
    // toggle later never retroactively breaks in-flight URLs.
    let allow_unsigned =
        overslash_db::repos::org::get_allow_unsigned_secret_provide(&ctx.db, ctx.org_id)
            .await?
            .unwrap_or(true);
    let require_user_session = !allow_unsigned;

    let signing_key = jwt::signing_key_bytes(&ctx.config.signing_key);
    let claims = SecretRequestClaims {
        req: req_id.clone(),
        org: ctx.org_id,
        iat: now.unix_timestamp(),
        exp: expires_at.unix_timestamp(),
        kind: SECRET_REQUEST_KIND.into(),
    };
    let token = jwt::mint_secret_request(&signing_key, &claims)
        .map_err(|e| AppError::Internal(format!("jwt mint: {e}")))?;
    let token_hash = sha256(&token);

    secret_request::create(
        &ctx.db,
        &req_id,
        ctx.org_id,
        target,
        input.secret_name.trim(),
        caller_identity,
        input.purpose.as_deref(),
        &token_hash,
        expires_at,
        require_user_session,
    )
    .await?;

    let url = ctx
        .config
        .dashboard_url_for(&format!("/secrets/provide/{req_id}?token={token}"));
    let short_url = url_shortener::mint_short_url(
        &ctx.http_client,
        ctx.config.oversla_sh_base_url.as_deref(),
        ctx.config.oversla_sh_api_key.as_deref(),
        &url,
        expires_at,
    )
    .await;

    let _ = scope
        .log_audit(AuditEntry {
            org_id: ctx.org_id,
            identity_id: Some(caller_identity),
            action: "secret_request.created",
            resource_type: Some("secret_request"),
            resource_id: None,
            detail: serde_json::json!({
                "id": &req_id,
                "secret_name": input.secret_name.trim(),
                "target_identity_id": target,
                "require_user_session": require_user_session,
                "via": "mcp",
            }),
            description: None,
            ip_address: None,
        })
        .await;

    Ok(serde_json::json!({
        "request_id": req_id,
        "provide_url": url,
        "short_url": short_url,
        "expires_at": fmt_time(expires_at),
    }))
}

fn sha256(s: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().to_vec()
}
