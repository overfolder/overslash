//! Session, multi-org account, and email-preference endpoints.

use super::*;

pub(super) async fn logout(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    // End the server-side session first: clearing the cookie only asks this
    // browser to forget it, revoking the row makes every copy worthless.
    if let Some(jti) = user_sessions::current_jti(&state, &headers) {
        user_sessions::revoke_one(&state, &ext, jti, None, user_sessions::reason::LOGOUT).await?;
    }
    // Clear on the same Domain the session was set with so browsers actually
    // drop the cookie (missing-Domain clear won't match a Domain-scoped
    // cookie and the session persists visually). Also clear the host-only
    // preview-handoff variant and any pre-prefix `oss_session` left over.
    let mut clears = vec![cookies::clear_for(&state, cookies::SESSION, "/")];
    if state.config.session_cookie_domain.is_some() {
        clears.push(cookies::clear(cookies::SESSION, None, "/"));
    }
    clears.extend(cookies::legacy_session_clears_for(&state));
    let mut resp_headers = HeaderMap::new();
    cookies::append_all(&mut resp_headers, clears);
    Ok((resp_headers, axum::Json(json!({ "status": "logged_out" }))))
}

// ---------------------------------------------------------------------------
// Session endpoints (unchanged)
// ---------------------------------------------------------------------------

pub(super) async fn me(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let token = cookies::read_session(&headers, &state)
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
    headers: HeaderMap,
    axum::Json(req): axum::Json<SwitchOrgRequest>,
) -> Result<impl IntoResponse, AppError> {
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

    let (cookie, redirect_to) = rescope_session_to(
        &state,
        &ext,
        &headers,
        user_id,
        &target_org,
        current_ident.email.clone(),
    )
    .await?;

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::SET_COOKIE, cookie);
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

/// Re-point the caller's session at `target_org` (where `user_id` must hold
/// a membership) and return the new session cookie plus the URL the
/// dashboard should hard-reload to. Shared by switch-org and by leaving the
/// org the session is currently scoped to.
async fn rescope_session_to(
    state: &AppState,
    ext: &axum::http::Extensions,
    headers: &HeaderMap,
    user_id: Uuid,
    target_org: &org::OrgRow,
    fallback_email: Option<String>,
) -> Result<(header::HeaderValue, String), AppError> {
    // Resolve the target identity — there is at most one user-kind identity
    // per (org_id, user_id) (enforced by the partial UNIQUE in migration 040).
    let target_identity =
        overslash_db::repos::identity::find_by_org_and_user(state.db(ext), target_org.id, user_id)
            .await?
            .ok_or_else(|| {
                AppError::Internal(
                    "membership exists but no user identity in target org (invariant violation)"
                        .into(),
                )
            })?;

    // Prefer the target identity's email so the new JWT reflects how the
    // target org sees this human; fall back to the current identity's email
    // for users who had no email on the target side.
    let claim_email = target_identity
        .email
        .clone()
        .or(fallback_email)
        .unwrap_or_default();

    // Same session, re-pointed at the target org — not a new sign-in. (When
    // the current session row is already revoked, `rescope` starts a fresh
    // one instead.)
    let new_token = user_sessions::rescope(
        state,
        ext,
        headers,
        user_sessions::Subject {
            identity_id: target_identity.id,
            org_id: target_org.id,
            user_id: Some(user_id),
            email: claim_email,
        },
    )
    .await?;

    Ok((
        session_cookie(state, &new_token)?,
        build_org_redirect(state, target_org),
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

/// DELETE /v1/account/memberships/{org_id} — leave an org. Refuses to drop
/// a personal-org membership (that'd orphan the account) or the last admin
/// of a non-personal org.
///
/// Leaving is the self-service twin of an admin removing the member
/// (`DELETE /v1/identities/{id}`) and runs the very same removal: the
/// caller's sessions in the org are revoked, their identity subtree is
/// archived (revoking API keys, expiring approvals), the membership row is
/// dropped and the archived identity is detached so a later re-invite gets a
/// clean slot. Merely deleting the membership row would leave a live
/// identity — still an admin, still holding working keys — behind.
///
/// When the caller is leaving the org their session is scoped to, the
/// session is re-pointed at their personal org and the response carries the
/// new cookie plus `redirect_to`; without a personal org to land on, leaving
/// the current org signs them out.
pub(super) async fn drop_account_membership(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    session: crate::extractors::SessionAuth,
    headers: HeaderMap,
    ip: crate::extractors::ClientIp,
    Path(org_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    use overslash_db::repos::identity::RemoveUserOutcome;

    let user_id = resolve_session_user_id(&state, &ext, &session).await?;

    let org_row = org::get_by_id(state.db(&ext), org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;

    if org_row.is_personal {
        return Err(AppError::BadRequest(
            "cannot drop membership of your own personal org".into(),
        ));
    }

    // A membership without its user identity is an invariant violation, but
    // either half missing reads as "already left" to the caller.
    if membership::find(state.db(&ext), user_id, org_id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound("no such membership".into()));
    }
    let identity =
        overslash_db::repos::identity::find_by_org_and_user(state.db(&ext), org_id, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("no such membership".into()))?;

    // The removal locks every admin row of the org in user_id order before
    // the last-admin guard, so two admins leaving concurrently serialise
    // instead of deadlocking or both getting out.
    let scope = OrgScope::new(org_id, state.db_pool(&ext));
    let (archived_count, was_admin, revoked_sessions) =
        match scope.remove_user_from_org(identity.id).await? {
            RemoveUserOutcome::Removed {
                archived_count,
                was_admin,
                revoked_sessions,
                ..
            } => (archived_count, was_admin, revoked_sessions),
            RemoveUserOutcome::LastAdmin => {
                return Err(AppError::BadRequest(
                    "cannot drop the last admin of a non-personal org".into(),
                ));
            }
            RemoveUserOutcome::NotFound | RemoveUserOutcome::NotApplicable => {
                return Err(AppError::NotFound("no such membership".into()));
            }
        };
    user_sessions::forget_identities(&state, &ext, org_id, &[identity.id]).await;

    // Audit the departure after the commit — the removal is the
    // authoritative side-effect, and a failing audit insert shouldn't
    // resurrect it. `was_original_creator` flags founder departures (a
    // notable state change worth pulling out of the broader membership
    // event stream).
    let was_original_creator = org_row.creator_user_id == Some(user_id);
    let _ = scope
        .log_audit(AuditEntry {
            org_id,
            identity_id: Some(identity.id),
            action: "membership.removed",
            resource_type: Some("membership"),
            // The user who left — so audit filtering by resource_id surfaces
            // this departure (org_id would bury it under the org itself).
            resource_id: Some(user_id),
            detail: json!({
                "user_id": user_id,
                "identity_id": identity.id,
                "was_original_creator": was_original_creator,
                "was_admin": was_admin,
                "archived_count": archived_count,
                "revoked_sessions": revoked_sessions,
            }),
            description: Some(if was_original_creator {
                "Original creator left the org"
            } else {
                "Member left the org"
            }),
            ip_address: ip.0.as_deref(),
        })
        .await;

    let mut resp_headers = HeaderMap::new();
    let mut body = json!({ "status": "dropped", "org_id": org_id });

    // The removal just revoked the session this request rode in on if it was
    // scoped to the org being left. Land the caller on their personal org
    // rather than signing them out everywhere. Best effort: the leave has
    // already committed, so a failure here (e.g. a personal org missing the
    // user's identity) must not turn it into an error — the caller is
    // signed out instead, the same as having no personal org.
    if session.org_id == org_id {
        match land_on_personal_org(&state, &ext, &headers, user_id, identity.email.clone()).await {
            Ok(Some((cookie, redirect_to))) => {
                resp_headers.insert(header::SET_COOKIE, cookie);
                body["redirect_to"] = json!(redirect_to);
            }
            Ok(None) => {}
            Err(e) => tracing::error!(
                %user_id, %org_id, error = %e,
                "left the current org but could not rescope the session to the personal org; \
                 signing out instead"
            ),
        }
    }

    Ok((resp_headers, axum::Json(body)))
}

/// Re-point the caller's session at their personal org, if they have one.
/// `Ok(None)` when there is no personal org to land on.
async fn land_on_personal_org(
    state: &AppState,
    ext: &axum::http::Extensions,
    headers: &HeaderMap,
    user_id: Uuid,
    fallback_email: Option<String>,
) -> Result<Option<(header::HeaderValue, String)>, AppError> {
    let Some(personal_org_id) = user_repo::get_by_id(state.db(ext), user_id)
        .await?
        .and_then(|u| u.personal_org_id)
    else {
        return Ok(None);
    };
    let Some(personal) = org::get_by_id(state.db(ext), personal_org_id).await? else {
        return Ok(None);
    };
    rescope_session_to(state, ext, headers, user_id, &personal, fallback_email)
        .await
        .map(Some)
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
