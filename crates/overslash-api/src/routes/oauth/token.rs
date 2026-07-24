//! Token endpoint (RFC 6749 §4.1.3 + §6) and revocation (RFC 7009).

use super::*;

// ---------------------------------------------------------------------------
// Token endpoint (RFC 6749 §4.1.3 + §6)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct TokenRequest {
    grant_type: String,
    // authorization_code grant
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    // refresh_token grant
    refresh_token: Option<String>,
}

pub(super) async fn token(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    Form(req): Form<TokenRequest>,
) -> Response {
    let flow = match req.grant_type.as_str() {
        "authorization_code" => "token",
        "refresh_token" => "refresh",
        _ => "unknown_grant",
    };
    let response = match req.grant_type.as_str() {
        "authorization_code" => exchange_authorization_code(&state, &ext, req).await,
        "refresh_token" => exchange_refresh_token(&state, &ext, req).await,
        other => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            format!("unsupported grant_type: {other}"),
        ),
    };
    let status = if response.status().is_success() {
        "success"
    } else {
        "failure"
    };
    overslash_metrics::oauth::record_event("overslash", flow, status);
    response
}

async fn exchange_authorization_code(
    state: &AppState,
    ext: &axum::http::Extensions,
    req: TokenRequest,
) -> Response {
    let code = match req.code {
        Some(c) => c,
        None => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "code required");
        }
    };
    let redirect_uri = match req.redirect_uri {
        Some(r) => r,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "redirect_uri required",
            );
        }
    };
    let client_id = match req.client_id {
        Some(c) => c,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id required",
            );
        }
    };
    let verifier = match req.code_verifier {
        Some(v) => v,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "code_verifier required",
            );
        }
    };

    let record = match state.auth_code_store(ext).take(&code) {
        Some(r) => r,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "authorization code not found or expired",
            );
        }
    };
    if record.client_id != client_id
        || record.redirect_uri != redirect_uri
        || oauth_as::pkce_s256(&verifier) != record.code_challenge
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code did not match the expected client/redirect/verifier",
        );
    }

    issue_tokens(
        state,
        ext,
        &record.client_id,
        record.identity_id,
        record.org_id,
        &record.email,
    )
    .await
}

async fn exchange_refresh_token(
    state: &AppState,
    ext: &axum::http::Extensions,
    req: TokenRequest,
) -> Response {
    let raw = match req.refresh_token {
        Some(t) => t,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "refresh_token required",
            );
        }
    };
    let hash = oauth_as::hash_refresh_token(&raw);
    let row = match mcp_refresh_token::get_by_hash(state.db(ext), &hash).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "unknown refresh_token",
            );
        }
        Err(e) => {
            tracing::error!("refresh lookup failed: {e}");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to look up refresh token",
            );
        }
    };

    // Replay detection: a revoked token being presented is evidence that the
    // previously-legitimate client was compromised. Revoke the entire chain
    // so both the attacker and the original client lose access.
    if row.revoked_at.is_some() {
        if let Err(e) = mcp_refresh_token::revoke_chain_from(state.db(ext), row.id).await {
            tracing::error!("revoke chain failed: {e}");
        }
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token revoked",
        );
    }
    if row.expires_at < OffsetDateTime::now_utc() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token expired",
        );
    }

    // We need the identity's email to mint the access JWT — fetch it.
    let identity =
        match overslash_db::repos::identity::get_by_id(state.db(ext), row.org_id, row.identity_id)
            .await
        {
            Ok(Some(i)) => i,
            Ok(None) => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "identity no longer exists",
                );
            }
            Err(e) => {
                tracing::error!("identity lookup failed: {e}");
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "failed to look up identity",
                );
            }
        };

    // Mint new tokens and atomically rotate (revoke old + insert new).
    let (raw_new, new_hash) = oauth_as::generate_refresh_token();
    let expires_at =
        OffsetDateTime::now_utc() + Duration::seconds(oauth_as::REFRESH_TOKEN_TTL_SECS);

    if let Err(e) = mcp_refresh_token::rotate(
        state.db(ext),
        row.id,
        &mcp_refresh_token::CreateMcpRefreshToken {
            client_id: &row.client_id,
            identity_id: row.identity_id,
            org_id: row.org_id,
            hash: &new_hash,
            expires_at,
        },
    )
    .await
    {
        tracing::error!("refresh rotate failed: {e}");
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "failed to rotate refresh token",
        );
    }
    let _ = oauth_mcp_client::mark_seen(state.db(ext), &row.client_id).await;

    let email = identity.email.as_deref().unwrap_or("");
    let access = match mint_access_token(state, row.identity_id, row.org_id, email, &row.client_id)
    {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    token_response(&access, &raw_new)
}

async fn issue_tokens(
    state: &AppState,
    ext: &axum::http::Extensions,
    client_id: &str,
    identity_id: Uuid,
    org_id: Uuid,
    email: &str,
) -> Response {
    let (raw, hash) = oauth_as::generate_refresh_token();
    let expires_at =
        OffsetDateTime::now_utc() + Duration::seconds(oauth_as::REFRESH_TOKEN_TTL_SECS);
    if let Err(e) = mcp_refresh_token::create(
        state.db(ext),
        &mcp_refresh_token::CreateMcpRefreshToken {
            client_id,
            identity_id,
            org_id,
            hash: &hash,
            expires_at,
        },
    )
    .await
    {
        tracing::error!("refresh insert failed: {e}");
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "failed to persist refresh token",
        );
    }
    let _ = oauth_mcp_client::mark_seen(state.db(ext), client_id).await;
    let access = match mint_access_token(state, identity_id, org_id, email, client_id) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    token_response(&access, &raw)
}

#[allow(clippy::result_large_err)]
fn mint_access_token(
    state: &AppState,
    identity_id: Uuid,
    org_id: Uuid,
    email: &str,
    mcp_client_id: &str,
) -> Result<String, Response> {
    let signing_key = hex::decode(&state.config.signing_key)
        .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());
    jwt::mint_mcp(
        &signing_key,
        identity_id,
        org_id,
        email.to_string(),
        oauth_as::ACCESS_TOKEN_TTL_SECS,
        Some(mcp_client_id.to_string()),
    )
    .map_err(|e| {
        tracing::error!("jwt mint failed: {e}");
        oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "failed to mint access token",
        )
    })
}

fn token_response(access: &str, refresh: &str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": oauth_as::ACCESS_TOKEN_TTL_SECS,
            "refresh_token": refresh,
            "scope": "mcp",
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Revoke (RFC 7009)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct RevokeRequest {
    token: String,
    token_type_hint: Option<String>,
}

pub(super) async fn revoke(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    Form(req): Form<RevokeRequest>,
) -> Response {
    // RFC 7009: always return 200 on success, even for unknown tokens.
    // `token_type_hint` is advisory — we ignore it because refresh tokens
    // are the only form we persist; access tokens are stateless JWTs and
    // can't be revoked individually (they expire in 1h).
    let _ = req.token_type_hint;

    let hash = oauth_as::hash_refresh_token(&req.token);
    match mcp_refresh_token::get_by_hash(state.db(&ext), &hash).await {
        Ok(Some(row)) => {
            if let Err(e) = mcp_refresh_token::revoke_by_id(state.db(&ext), row.id).await {
                // Log-but-don't-fail: RFC 7009 wants a 200 for success paths
                // so the client doesn't retry into a DB stampede, but an
                // operator needs a signal when the revoke silently misses.
                tracing::error!(
                    token_id = %row.id,
                    error = %e,
                    "refresh token revoke failed at /oauth/revoke"
                );
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "refresh token lookup failed at /oauth/revoke");
        }
    }
    StatusCode::OK.into_response()
}
