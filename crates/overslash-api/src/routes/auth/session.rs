//! Session, multi-org account, and email-preference endpoints.

use super::*;

pub(super) async fn logout(State(state): State<AppState>) -> impl IntoResponse {
    // Clear on the same Domain the session was set with so browsers actually
    // drop the cookie (missing-Domain clear won't match a Domain-scoped
    // cookie and the session persists visually).
    let mut clear = String::from("oss_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    if let Some(domain) = state.config.session_cookie_domain.as_deref() {
        clear.push_str(&format!("; Domain={domain}"));
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, clear.parse().unwrap());
    (headers, axum::Json(json!({ "status": "logged_out" })))
}

// ---------------------------------------------------------------------------
// Session endpoints (unchanged)
// ---------------------------------------------------------------------------

pub(super) async fn me(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let token = extract_cookie(&headers, "oss_session")
        .ok_or_else(|| AppError::Unauthorized("not authenticated".into()))?;

    let jwt_secret = signing_key_bytes(&state.config.signing_key);
    let claims = jwt::verify(&jwt_secret, &token, jwt::AUD_SESSION)
        .map_err(|_| AppError::Unauthorized("invalid or expired session".into()))?;

    // Resolve the user's ACL level from group grants. Construct an OrgScope
    // inline from the verified JWT claims so the ceiling lookup is bounded
    // by the caller's org at the SQL boundary.
    let scope = overslash_db::OrgScope::new(claims.org, state.db_pool(&ext));
    let ceiling = scope.get_ceiling_for_user(claims.sub).await?;
    let acl_level = ceiling
        .grants
        .iter()
        .filter(|g| g.template_key == "overslash")
        .filter_map(|g| overslash_core::permissions::AccessLevel::parse(&g.access_level))
        .max()
        .map(|l| l.to_string());

    Ok(axum::Json(json!({
        "identity_id": claims.sub,
        "org_id": claims.org,
        "email": claims.email,
        "acl_level": acl_level,
    })))
}

pub(super) async fn me_identity(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    session: crate::extractors::SessionAuth,
) -> Result<impl IntoResponse, AppError> {
    // Was: manual cookie + jwt::verify without the RequestOrgContext cross-
    // check, so a session scoped to the caller's personal org still
    // answered `/auth/me/identity` when the request came in on a corp
    // subdomain — leaking personal-org profile data across trust domains.
    // `SessionAuth` enforces `jwt.org == subdomain.org` via
    // `check_subdomain_matches_jwt`.
    let scope = OrgScope::new(session.org_id, state.db_pool(&ext));
    // A cryptographically-valid, unexpired session cookie can still point at an
    // identity that no longer exists — e.g. the dev user after the Postgres
    // volume is reset, or any identity deleted out from under a live session.
    // `SessionAuth` only verifies the JWT, so the staleness surfaces here.
    // Return 401 (not 404): the session is no longer valid, and 401 is what the
    // dashboard treats as "redirect to /login".
    let ident = scope
        .get_identity(session.identity_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("session identity no longer exists".into()))?;
    let is_org_admin = scope.is_identity_in_admins(ident.id).await?;

    let org_row = org::get_by_id(state.db(&ext), ident.org_id).await?;
    let picture = ident
        .metadata
        .get("picture")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Multi-org surface: memberships + personal-org pointer live on the
    // `users` row. Legacy tokens (no `user_id` claim) fall back to the
    // identity's FK. Fetch the user once and reuse for instance-admin too.
    let user_id = session.user_id.or(ident.user_id);
    let (memberships, personal_org_id, is_instance_admin) = if let Some(uid) = user_id {
        let user = user_repo::get_by_id(state.db(&ext), uid).await?;
        (
            list_membership_summaries(&state, &ext, uid).await?,
            user.as_ref().and_then(|u| u.personal_org_id),
            user.as_ref().map(|u| u.is_instance_admin).unwrap_or(false),
        )
    } else {
        (Vec::new(), None, false)
    };

    let email = ident.email.clone().unwrap_or_default();

    // Trial summary for the org-wide banner. Reaches every member (this
    // endpoint is the universal auth check), unlike the admin-only
    // subscription endpoint. `null` for non-trial orgs. Enforcement is
    // banner-only (DECISIONS D25) — this is purely informational.
    let now = time::OffsetDateTime::now_utc();
    let trial = org_row.as_ref().and_then(|o| {
        use crate::services::billing_tier::{TrialStatus, derive_trial_status};
        match derive_trial_status(&o.plan, o.trial_ends_at, now) {
            TrialStatus::Active { ends_at } => {
                let days_remaining =
                    ((ends_at - now).whole_seconds() as f64 / 86_400.0).ceil() as i64;
                Some(json!({
                    "status": "active",
                    "ends_at": ends_at.unix_timestamp(),
                    "days_remaining": days_remaining.max(0),
                }))
            }
            TrialStatus::Expired { ends_at } => Some(json!({
                "status": "expired",
                "ends_at": ends_at.unix_timestamp(),
                "days_remaining": 0,
            })),
            TrialStatus::None => None,
        }
    });

    // Pending invitations from *other* orgs. Embedded here rather than fetched
    // separately because this endpoint is the shell's universal auth call —
    // the sidebar gets the list on the same round trip as `memberships`, and
    // `invalidateAll()` after accept/decline refreshes both at once.
    let invitations =
        crate::routes::account_invitations::list_pending_invitations(&state, &ext, &session)
            .await?;

    Ok(axum::Json(json!({
        "identity_id": ident.id,
        "org_id": ident.org_id,
        "org_name": org_row.as_ref().map(|o| o.name.clone()),
        "org_slug": org_row.as_ref().map(|o| o.slug.clone()),
        "email": email,
        "name": ident.name,
        "kind": ident.kind,
        "external_id": ident.external_id,
        "is_org_admin": is_org_admin,
        "is_instance_admin": is_instance_admin,
        "picture": picture,
        "user_id": user_id,
        "personal_org_id": personal_org_id,
        "memberships": memberships,
        "invitations": invitations,
        "trial": trial,
    })))
}

/// Shape returned by `/auth/me/identity.memberships[]` and `/v1/account/memberships`.
#[derive(Debug, serde::Serialize)]
struct MembershipSummary {
    org_id: Uuid,
    slug: String,
    name: String,
    role: String,
    is_personal: bool,
}

async fn list_membership_summaries(
    state: &AppState,
    ext: &axum::http::Extensions,
    user_id: Uuid,
) -> Result<Vec<MembershipSummary>, AppError> {
    let memberships = membership::list_for_user(state.db(ext), user_id).await?;
    let mut out = Vec::with_capacity(memberships.len());
    for m in memberships {
        let Some(o) = org::get_by_id(state.db(ext), m.org_id).await? else {
            continue; // Org was deleted; stale membership — CASCADE will sweep it.
        };
        out.push(MembershipSummary {
            org_id: o.id,
            slug: o.slug,
            name: o.name,
            role: m.role,
            is_personal: o.is_personal,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Multi-org account routes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct SwitchOrgRequest {
    org_id: Uuid,
}

/// POST /auth/switch-org — mint a new session JWT scoped to `org_id` after
/// verifying the caller has a membership there. Returns `{ redirect_to }`
/// so the dashboard can hard-reload onto the target subdomain (or the root
/// apex for personal orgs). Uses `SessionAuth` so the cross-subdomain guard
/// runs — switch-org must be called from the caller's *current* subdomain
/// (or root), not from the target.
pub(super) async fn switch_org(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    session: crate::extractors::SessionAuth,
    axum::Json(req): axum::Json<SwitchOrgRequest>,
) -> Result<impl IntoResponse, AppError> {
    let jwt_secret = signing_key_bytes(&state.config.signing_key);

    let current_scope = OrgScope::new(session.org_id, state.db_pool(&ext));
    let current_ident = current_scope
        .get_identity(session.identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("current identity not found".into()))?;
    let user_id = match session.user_id {
        Some(uid) => uid,
        None => current_ident.user_id.ok_or_else(|| {
            AppError::Unauthorized("session has no resolvable user; sign in again".into())
        })?,
    };

    // Membership guard.
    let target_membership = membership::find(state.db(&ext), user_id, req.org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("not a member of that org".into()))?;
    let target_org = org::get_by_id(state.db(&ext), req.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;

    // Resolve the target identity — there is at most one user-kind identity
    // per (org_id, user_id) (enforced by the partial UNIQUE in migration 040).
    let target_identity =
        overslash_db::repos::identity::find_by_org_and_user(state.db(&ext), req.org_id, user_id)
            .await?
            .ok_or_else(|| {
                AppError::Internal(
                    "membership exists but no user identity in target org (invariant violation)"
                        .into(),
                )
            })?;
    let target_identity_id = target_identity.id;

    // Prefer the target identity's email so the new JWT reflects how the
    // target org sees this human; fall back to the current identity's email
    // for users who had no email on the target side.
    let claim_email = target_identity
        .email
        .clone()
        .or(current_ident.email.clone())
        .unwrap_or_default();

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let new_claims = jwt::Claims {
        sub: target_identity_id,
        org: req.org_id,
        email: claim_email,
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 7 * 24 * 3600,
        user_id: Some(user_id),
        mcp_client_id: None,
    };
    let new_token = jwt::mint(&jwt_secret, &new_claims)
        .map_err(|e| AppError::Internal(format!("jwt mint failed: {e}")))?;

    let redirect_to = build_org_redirect(&state, &target_org);

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::SET_COOKIE, session_cookie(&state, &new_token)?);
    Ok((
        resp_headers,
        axum::Json(json!({
            "org_id": target_org.id,
            "slug": target_org.slug,
            "is_personal": target_org.is_personal,
            "role": target_membership.role,
            "redirect_to": redirect_to,
        })),
    ))
}

/// GET /v1/account/memberships — list the caller's memberships, same shape
/// as `/auth/me/identity.memberships[]` but reachable as a discrete endpoint
/// so the dashboard can refresh the switcher without re-loading identity.
pub(super) async fn list_account_memberships(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    session: crate::extractors::SessionAuth,
) -> Result<impl IntoResponse, AppError> {
    let user_id = resolve_session_user_id(&state, &ext, &session).await?;
    let summaries = list_membership_summaries(&state, &ext, user_id).await?;
    Ok(axum::Json(json!({ "memberships": summaries })))
}

/// DELETE /v1/account/memberships/{org_id} — drop the caller's own
/// membership. Refuses to drop a personal-org membership (that'd orphan
/// the account) or the last admin of a non-personal org.
///
/// The "last admin" check and the delete run in a single transaction. A
/// naive two-step lock (caller's row, then all admin rows) can deadlock
/// when two admins drop concurrently — each acquires their own row lock
/// first, then blocks waiting for the other's. We avoid that by issuing
/// a single `SELECT ... FOR UPDATE ORDER BY user_id`, which locks every
/// admin row of the org in a deterministic order. Both concurrent txs
/// contend for the same ordered lock set; the second waits for the
/// first to commit and then reads the post-delete world.
pub(super) async fn drop_account_membership(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    session: crate::extractors::SessionAuth,
    ip: crate::extractors::ClientIp,
    Path(org_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user_id = resolve_session_user_id(&state, &ext, &session).await?;

    let org_row = org::get_by_id(state.db(&ext), org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;

    if org_row.is_personal {
        return Err(AppError::BadRequest(
            "cannot drop membership of your own personal org".into(),
        ));
    }

    let mut tx = state.db(&ext).begin().await?;

    // Lock every admin row of the org in user_id order. This includes the
    // caller's row if (and only if) they are an admin — which is the only
    // case where we care about the count guard. Deterministic order across
    // concurrent txs rules out deadlock; both serialize on the same lock
    // set instead of each grabbing a different row first.
    #[allow(clippy::disallowed_methods)]
    let admin_user_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM user_org_memberships
         WHERE org_id = $1 AND role = 'admin'
         ORDER BY user_id FOR UPDATE",
    )
    .bind(org_id)
    .fetch_all(&mut *tx)
    .await?;

    let caller_is_admin = admin_user_ids.contains(&user_id);

    // Separately lock the caller's row so a NOT-FOUND ("already left")
    // check and the subsequent DELETE can proceed even when the caller
    // is a regular member (not in admin_user_ids).
    #[allow(clippy::disallowed_methods)]
    let existing_role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM user_org_memberships
         WHERE user_id = $1 AND org_id = $2 FOR UPDATE",
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await?;
    existing_role.ok_or_else(|| AppError::NotFound("no such membership".into()))?;

    if caller_is_admin {
        let admin_count = admin_user_ids.len();
        if admin_count <= 1 {
            return Err(AppError::BadRequest(
                "cannot drop the last admin of a non-personal org".into(),
            ));
        }
    }

    #[allow(clippy::disallowed_methods)]
    sqlx::query("DELETE FROM user_org_memberships WHERE user_id = $1 AND org_id = $2")
        .bind(user_id)
        .bind(org_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    // Audit the departure after the commit — the membership drop is the
    // authoritative side-effect, and a failing audit insert shouldn't
    // resurrect it. `was_original_creator` flags founder departures (a
    // notable state change worth pulling out of the broader membership
    // event stream).
    let was_original_creator = org_row.creator_user_id == Some(user_id);
    let scope = OrgScope::new(org_id, state.db_pool(&ext));
    let _ = scope
        .log_audit(AuditEntry {
            org_id,
            identity_id: Some(session.identity_id),
            action: "membership.removed",
            resource_type: Some("membership"),
            // The user who left — so audit filtering by resource_id surfaces
            // this departure (org_id would bury it under the org itself).
            resource_id: Some(user_id),
            detail: json!({
                "user_id": user_id,
                "was_original_creator": was_original_creator,
                "was_admin": caller_is_admin,
            }),
            description: Some(if was_original_creator {
                "Original creator left the org"
            } else {
                "Member left the org"
            }),
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(axum::Json(json!({ "status": "dropped", "org_id": org_id })))
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
pub(super) struct EmailPreferences {
    /// `true` = subscribed to non-transactional welcome / product email
    /// (default for new users); `false` = unsubscribed via `/account` toggle
    /// or one-click link. Billing receipts and other transactional email
    /// ignore this flag by policy. Optional on PUT so the client can update
    /// `webhook_digest_emails` in isolation; always present on GET.
    #[serde(skip_serializing_if = "Option::is_none")]
    welcome_emails: Option<bool>,
    /// `true` = subscribed to the daily webhook DLQ digest (default);
    /// `false` = opted out via one-click link or this toggle. Independent
    /// from `welcome_emails` — silencing one does not silence the other.
    /// Optional on PUT for the same reason as `welcome_emails`.
    #[serde(skip_serializing_if = "Option::is_none")]
    webhook_digest_emails: Option<bool>,
}

fn prefs_from_user(user: &overslash_db::repos::user::UserRow) -> EmailPreferences {
    EmailPreferences {
        welcome_emails: Some(user.welcome_emails_unsubscribed_at.is_none()),
        webhook_digest_emails: Some(user.webhook_digest_unsubscribed_at.is_none()),
    }
}

/// GET /v1/account/email-preferences — return the caller's non-transactional
/// email preferences. Per-user (not per-identity), so the same value is
/// returned regardless of which org subdomain the session is currently in.
pub(super) async fn get_email_preferences(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    session: crate::extractors::SessionAuth,
) -> Result<axum::Json<EmailPreferences>, AppError> {
    let user_id = resolve_session_user_id(&state, &ext, &session).await?;
    let user = overslash_db::repos::user::get_by_id(state.db(&ext), user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("user not found".into()))?;
    Ok(axum::Json(prefs_from_user(&user)))
}

/// PUT /v1/account/email-preferences — update the caller's non-transactional
/// email preferences. Per-category and idempotent: only fields present in
/// the body are applied; unchanged fields neither hit the DB nor write an
/// audit row, so UIs that re-submit on every toggle flip-flop don't spam
/// the audit log with non-events.
pub(super) async fn put_email_preferences(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    session: crate::extractors::SessionAuth,
    axum::Json(prefs): axum::Json<EmailPreferences>,
) -> Result<axum::Json<EmailPreferences>, AppError> {
    let user_id = resolve_session_user_id(&state, &ext, &session).await?;
    let mut current = overslash_db::repos::user::get_by_id(state.db(&ext), user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("user not found".into()))?;

    let scope = OrgScope::new(session.org_id, state.db_pool(&ext));

    if let Some(want) = prefs.welcome_emails {
        let was = current.welcome_emails_unsubscribed_at.is_none();
        if was != want {
            let unsubscribed_at = (!want).then(time::OffsetDateTime::now_utc);
            current = overslash_db::repos::user::set_welcome_unsubscribed(
                state.db(&ext),
                user_id,
                unsubscribed_at,
            )
            .await?
            .ok_or_else(|| AppError::NotFound("user not found".into()))?;
            let action = if want {
                "email.resubscribed"
            } else {
                "email.unsubscribed"
            };
            if let Err(e) = scope
                .log_audit(overslash_db::repos::audit::AuditEntry {
                    org_id: session.org_id,
                    identity_id: Some(session.identity_id),
                    action,
                    resource_type: Some("user"),
                    resource_id: Some(user_id),
                    detail: json!({ "purpose": "welcome", "via": "account_toggle" }),
                    description: Some(if want {
                        "Welcome / product emails re-enabled from /account"
                    } else {
                        "Welcome / product emails unsubscribed from /account"
                    }),
                    ip_address: None,
                })
                .await
            {
                tracing::warn!(%user_id, error = %e, "email-preferences audit log failed (welcome)");
            }
        }
    }

    if let Some(want) = prefs.webhook_digest_emails {
        let was = current.webhook_digest_unsubscribed_at.is_none();
        if was != want {
            let unsubscribed_at = (!want).then(time::OffsetDateTime::now_utc);
            current = overslash_db::repos::user::set_webhook_digest_unsubscribed(
                state.db(&ext),
                user_id,
                unsubscribed_at,
            )
            .await?
            .ok_or_else(|| AppError::NotFound("user not found".into()))?;
            let action = if want {
                "email.resubscribed"
            } else {
                "email.unsubscribed"
            };
            if let Err(e) = scope
                .log_audit(overslash_db::repos::audit::AuditEntry {
                    org_id: session.org_id,
                    identity_id: Some(session.identity_id),
                    action,
                    resource_type: Some("user"),
                    resource_id: Some(user_id),
                    detail: json!({ "purpose": "webhook_digest", "via": "account_toggle" }),
                    description: Some(if want {
                        "Webhook DLQ digest re-enabled from /account"
                    } else {
                        "Webhook DLQ digest unsubscribed from /account"
                    }),
                    ip_address: None,
                })
                .await
            {
                tracing::warn!(%user_id, error = %e, "email-preferences audit log failed (webhook_digest)");
            }
        }
    }

    Ok(axum::Json(prefs_from_user(&current)))
}

/// Resolve the human behind a `SessionAuth`. Prefers the JWT's `user_id`
/// claim (hot path); falls back to the identity's FK for legacy tokens.
async fn resolve_session_user_id(
    state: &AppState,
    ext: &axum::http::Extensions,
    session: &crate::extractors::SessionAuth,
) -> Result<Uuid, AppError> {
    if let Some(uid) = session.user_id {
        return Ok(uid);
    }
    let scope = OrgScope::new(session.org_id, state.db_pool(ext));
    let ident = scope
        .get_identity(session.identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    ident.user_id.ok_or_else(|| {
        AppError::Unauthorized("session has no resolvable user; sign in again".into())
    })
}
