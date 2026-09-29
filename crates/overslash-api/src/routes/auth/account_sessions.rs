//! `/v1/account/sessions` — the caller's own dashboard sessions (CASA 2.2.2).
//!
//! Per human, not per org: a session follows its browser across orgs, so the
//! list spans every org the caller belongs to. Session-cookie only — an agent
//! key has no sessions and must not end its owner's.

use super::*;

use overslash_db::repos::user_session;

#[derive(serde::Serialize)]
struct SessionView {
    id: Uuid,
    org_id: Uuid,
    org_name: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    last_seen_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: time::OffsetDateTime,
    user_agent: Option<String>,
    ip_address: Option<String>,
    /// The session this request came in on.
    current: bool,
}

/// The caller's human and live session, or 401: every endpoint here acts on
/// "my sessions", which only a stateful session can name.
fn caller(session: &crate::extractors::SessionAuth) -> Result<(Uuid, Uuid), AppError> {
    match (session.user_id, session.session_id) {
        (Some(user_id), Some(session_id)) => Ok((user_id, session_id)),
        _ => Err(AppError::Unauthorized(
            "this session cannot manage sessions; sign in again".into(),
        )),
    }
}

/// GET /v1/account/sessions — live sessions, most recently active first.
pub(super) async fn list_sessions(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    session: crate::extractors::SessionAuth,
) -> Result<impl IntoResponse, AppError> {
    let (user_id, current) = caller(&session)?;
    let rows = user_session::list_live_for_user(state.db(&ext), user_id).await?;
    let sessions: Vec<SessionView> = rows
        .into_iter()
        .map(|r| SessionView {
            current: r.id == current,
            id: r.id,
            org_id: r.org_id,
            org_name: r.org_name,
            created_at: r.created_at,
            last_seen_at: r.last_seen_at,
            expires_at: r.expires_at,
            user_agent: r.user_agent,
            ip_address: r.ip_address,
        })
        .collect();
    Ok(axum::Json(json!({ "sessions": sessions })))
}

/// DELETE /v1/account/sessions/{id} — end one of the caller's sessions. Ending
/// the current one is a sign-out, so the response clears the cookie too.
pub(super) async fn revoke_session(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    session: crate::extractors::SessionAuth,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let (user_id, current) = caller(&session)?;
    let reason = if id == current {
        user_sessions::reason::LOGOUT
    } else {
        user_sessions::reason::TERMINATED
    };
    // Scoped to the caller's own sessions: someone else's id is a 404, not a
    // probe that tells them it exists.
    if !user_sessions::revoke_one(&state, &ext, id, Some(user_id), reason).await? {
        return Err(AppError::NotFound("session not found".into()));
    }
    audit(&state, &ext, &session, &ip, id, 1, "Signed out one session").await;

    let mut headers = HeaderMap::new();
    if id == current {
        // Same clears as logout: the configured name, plus the host-only
        // `__Host-` fallback (preview handoff) when a Domain is configured.
        let mut clears = vec![cookies::clear_for(&state, cookies::SESSION, "/")];
        if state.config.session_cookie_domain.is_some() {
            clears.push(cookies::clear(cookies::SESSION, None, "/"));
        }
        cookies::append_all(&mut headers, clears);
    }
    Ok((headers, axum::Json(json!({ "revoked": 1 }))))
}

/// POST /v1/account/sessions/revoke-others — end every session but this one.
pub(super) async fn revoke_other_sessions(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    session: crate::extractors::SessionAuth,
    ip: ClientIp,
) -> Result<impl IntoResponse, AppError> {
    let (user_id, current) = caller(&session)?;
    let n = user_sessions::revoke_all_for_user(
        &state,
        &ext,
        user_id,
        Some(current),
        user_sessions::reason::TERMINATED_BY_OTHER,
    )
    .await?;
    audit(
        &state,
        &ext,
        &session,
        &ip,
        current,
        n,
        "Signed out all other sessions",
    )
    .await;
    Ok(axum::Json(json!({ "revoked": n })))
}

async fn audit(
    state: &AppState,
    ext: &axum::http::Extensions,
    session: &crate::extractors::SessionAuth,
    ip: &ClientIp,
    resource_id: Uuid,
    revoked: usize,
    description: &str,
) {
    let scope = OrgScope::new(session.org_id, state.db_pool(ext));
    if let Err(e) = scope
        .log_audit(AuditEntry {
            org_id: session.org_id,
            identity_id: Some(session.identity_id),
            action: "session.revoked",
            resource_type: Some("session"),
            resource_id: Some(resource_id),
            detail: json!({ "revoked": revoked, "by_session": session.session_id }),
            description: Some(description),
            ip_address: ip.0.as_deref(),
        })
        .await
    {
        tracing::warn!(error = %e, "session revoke audit log failed");
    }
}
