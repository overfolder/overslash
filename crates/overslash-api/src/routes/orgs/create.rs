//! Org creation (`POST /v1/orgs`, `POST /v1/orgs/free-unlimited`), the
//! live slug-availability check, and the shared new-org provisioning
//! tail used by both this module and the Stripe billing route.

use super::slug::*;
use super::*;

#[derive(Deserialize)]
pub(super) struct CreateOrgRequest {
    name: String,
    slug: String,
}

/// POST /v1/orgs — create an org. Behavior depends on who's calling:
///
/// * **Multi-org session present** (Overslash-backed user, `user_id` claim
///   set) → attach the caller as a regular `admin` member + an admin
///   identity in the new org. This is the canonical cloud path — see
///   `docs/design/multi_org_auth.md` §Org Creation. The creator's
///   Overslash-backed login continues to work against the new org
///   indefinitely; the org may choose to configure its own IdP later, at
///   which point other humans join through that IdP while the creator
///   retains their root-login access via this membership.
/// * **No session** → create the org without any human attached. Legacy
///   bootstrap entrypoint used by provisioning scripts and the test harness
///   (the first org on a fresh deployment). Subsequent members join
///   through the org's IdP configured afterwards.
///
/// Gated in both cases by `ALLOW_ORG_CREATION` so self-hosted operators can
/// lock the surface after initial setup.
pub(super) async fn create_org(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ip: ClientIp,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateOrgRequest>,
) -> Result<axum::response::Response> {
    if !state.config.allow_org_creation {
        return Err(AppError::Forbidden("org_creation_disabled".into()));
    }

    // In cloud billing mode, all org creation through this HTTP route is
    // blocked: Team orgs go through Stripe Checkout, personal orgs are
    // auto-provisioned during the auth signup flow (which calls the DB
    // layer directly, not this route). There is intentionally no escape
    // hatch here — letting the request flag personal would let attackers
    // bypass billing.
    if state.config.cloud_billing {
        return Err(AppError::Forbidden("team_org_requires_subscription".into()));
    }

    let name = req.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("name is required".into()));
    }
    if let Err(reject) = validate_slug_format(&req.slug) {
        return Err(AppError::BadRequest(reject.code().into()));
    }

    let org =
        match overslash_db::repos::org::create(state.db(&ext), name, &req.slug, "standard").await {
            Ok(row) => row,
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Err(AppError::Conflict("slug_taken".into()));
            }
            Err(e) => return Err(e.into()),
        };

    // New corp orgs opt in to Overslash-managed sign-in by default
    // (migration 066). Existing orgs stay opted out — the migration left
    // the column at `false` for them so live tenants don't see behavior
    // changes. Login still requires an `org_invites` row, so this is safe.
    let org = flip_managed_signin_on_new_org(&state, &ext, org).await?;

    // Optional session: if the caller presents a valid `oss_session` with a
    // multi-org `user_id` claim, attach the bootstrap admin. Otherwise the
    // org is created anonymously (legacy + test-harness path).
    let session_user_id = extract_optional_session_user(&state, &headers);
    let audit_detail = serde_json::json!({
        "name": &org.name,
        "slug": &org.slug,
        "bootstrap_user_id": session_user_id.map(|u| u.to_string()),
    });

    finalize_new_org(&state, &ext, org, session_user_id, audit_detail, ip).await
}

/// Shared tail for org-creation handlers: provisions contents (with
/// compensating rollback), emits the `org.created` audit row, builds the
/// `OrgResponse` with `redirect_to`, and re-mints the session cookie when
/// `bootstrap_user_id` is set so the dashboard redirect lands inside an
/// authenticated session on the new subdomain.
///
/// The follow-up writes inside `provision_new_org_contents` (identity
/// create, admin flag, `bootstrap_org`, membership row) each run in their
/// own sqlx transaction — sqlx doesn't nest, so a single outer tx isn't
/// available without refactoring `bootstrap_org`. The compensating rollback
/// (DELETE FROM orgs) cascades to identities / memberships / groups /
/// service_instances / group_grants on failure.
async fn finalize_new_org(
    state: &AppState,
    ext: &axum::http::Extensions,
    org: overslash_db::repos::org::OrgRow,
    bootstrap_user_id: Option<Uuid>,
    audit_detail: serde_json::Value,
    ip: ClientIp,
) -> Result<axum::response::Response> {
    let bootstrap_identity_id =
        match provision_new_org_contents(state, ext, org.id, bootstrap_user_id).await {
            Ok(id) => id,
            Err(e) => {
                // Best-effort cleanup. If this also fails we leave a dangling
                // org row, but that's strictly better than the half-bootstrapped
                // state; admins can sweep manually.
                if let Err(cleanup_err) = sqlx::query!("DELETE FROM orgs WHERE id = $1", org.id)
                    .execute(state.db(ext))
                    .await
                {
                    tracing::error!(
                        org_id = %org.id,
                        bootstrap_error = %e,
                        cleanup_error = %cleanup_err,
                        "create_org rollback failed; manual cleanup required"
                    );
                }
                return Err(e);
            }
        };

    let bootstrap_scope = overslash_db::OrgScope::new(org.id, state.db_pool(ext));
    let _ = bootstrap_scope
        .log_audit(AuditEntry {
            org_id: org.id,
            identity_id: bootstrap_identity_id,
            action: "org.created",
            resource_type: Some("org"),
            resource_id: Some(org.id),
            detail: audit_detail,
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    // Separate event for the admin grant — distinct from `org.created` so
    // the audit log shows *who* got admin (not just that the org exists).
    // Skipped when there's no signed-in creator (legacy/test-harness path
    // where the org comes up without a bootstrap admin).
    if let (Some(identity_id), Some(user_id)) = (bootstrap_identity_id, bootstrap_user_id) {
        let _ = bootstrap_scope
            .log_audit(AuditEntry {
                org_id: org.id,
                identity_id: Some(identity_id),
                action: "org.creator_admin_added",
                resource_type: Some("org"),
                resource_id: Some(org.id),
                detail: serde_json::json!({
                    "user_id": user_id,
                    "role": membership::ROLE_ADMIN,
                }),
                description: Some("Creator granted admin role on new org"),
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    let redirect_to = redirect_for_org(state, &org);
    let mut resp: OrgResponse = org.into();
    resp.redirect_to = Some(redirect_to);

    // Re-mint the session cookie scoped to the new org when the caller came
    // in with a multi-org session. Without this, the client redirects to
    // the new subdomain and the old JWT's `org` claim trips the
    // subdomain↔JWT guard (`org_mismatch` 401), forcing an extra switch-org
    // round-trip. Anonymous creators keep no session.
    let mut response_headers = HeaderMap::new();
    if let (Some(user_id), Some(identity_id)) = (bootstrap_user_id, bootstrap_identity_id) {
        let jwt_secret = signing_key_bytes(&state.config.signing_key);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = jwt::Claims {
            sub: identity_id,
            org: resp.id,
            email: user_repo::get_by_id(state.db(ext), user_id)
                .await?
                .and_then(|u| u.email)
                .unwrap_or_default(),
            aud: jwt::AUD_SESSION.into(),
            iat: now,
            exp: now + 7 * 24 * 3600,
            user_id: Some(user_id),
            mcp_client_id: None,
        };
        let token = jwt::mint(&jwt_secret, &claims)
            .map_err(|e| AppError::Internal(format!("jwt mint failed: {e}")))?;
        response_headers.insert(header::SET_COOKIE, session_cookie(state, &token)?);
    }

    Ok((response_headers, Json(resp)).into_response())
}

/// POST /v1/orgs/free-unlimited — instance-admin-only direct create that
/// bypasses Stripe entirely. The new org comes up with `plan='free_unlimited'`,
/// which makes the existing rate-limit bypass and synthetic subscription
/// endpoint kick in for free. No `org_subscriptions` row is written.
///
/// Mounted regardless of `cloud_billing` so instance admins keep working
/// in self-hosted deploys (where the toggle still moves the new org to
/// the courtesy tier).
pub(super) async fn create_free_unlimited_org(
    admin: InstanceAdminAuth,
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ip: ClientIp,
    Json(req): Json<CreateOrgRequest>,
) -> Result<axum::response::Response> {
    if !state.config.allow_org_creation {
        return Err(AppError::Forbidden("org_creation_disabled".into()));
    }
    let name = req.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("name is required".into()));
    }
    if let Err(reject) = validate_slug_format(&req.slug) {
        return Err(AppError::BadRequest(reject.code().into()));
    }

    let org =
        match overslash_db::repos::org::create(state.db(&ext), name, &req.slug, "free_unlimited")
            .await
        {
            Ok(row) => row,
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Err(AppError::Conflict("slug_taken".into()));
            }
            Err(e) => return Err(e.into()),
        };

    let org = flip_managed_signin_on_new_org(&state, &ext, org).await?;

    let audit_detail = serde_json::json!({
        "name": &org.name,
        "slug": &org.slug,
        "free_unlimited": true,
        "created_by_instance_admin": admin.user_id.to_string(),
    });

    finalize_new_org(&state, &ext, org, Some(admin.user_id), audit_detail, ip).await
}

/// Flip `allow_overslash_managed_signin` to `true` for a freshly-created
/// corp org. Personal orgs (single-user, no IdP login) skip this — they
/// stay at the migration default (`false`). Returns the row with the new
/// flag value so callers don't have to re-read.
async fn flip_managed_signin_on_new_org(
    state: &AppState,
    ext: &axum::http::Extensions,
    mut org: overslash_db::repos::org::OrgRow,
) -> Result<overslash_db::repos::org::OrgRow> {
    if org.is_personal {
        return Ok(org);
    }
    overslash_db::repos::org::set_allow_overslash_managed_signin(state.db(ext), org.id, true)
        .await?;
    org.allow_overslash_managed_signin = true;
    Ok(org)
}

#[derive(Deserialize)]
pub(super) struct CheckSlugQuery {
    slug: String,
}

#[derive(Serialize)]
pub(super) struct CheckSlugResponse {
    available: bool,
    reason: Option<&'static str>,
}

/// GET /v1/orgs/check-slug?slug=xxx — live-validate a slug for the create-org
/// form. Unauthenticated: slugs are effectively public (subdomain probing
/// reveals the same info) and the dashboard needs this before a session
/// exists for first-time cloud signups.
pub(super) async fn check_slug(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    Query(q): Query<CheckSlugQuery>,
) -> Json<CheckSlugResponse> {
    if let Err(reject) = validate_slug_format(&q.slug) {
        return Json(CheckSlugResponse {
            available: false,
            reason: Some(reject.code()),
        });
    }
    match overslash_db::repos::org::get_by_slug(state.db(&ext), &q.slug).await {
        Ok(Some(_)) => Json(CheckSlugResponse {
            available: false,
            reason: Some("slug_taken"),
        }),
        Ok(None) => Json(CheckSlugResponse {
            available: true,
            reason: None,
        }),
        Err(_) => Json(CheckSlugResponse {
            available: false,
            reason: Some("lookup_failed"),
        }),
    }
}

/// Best-effort session lookup. Returns Some(user_id) only when the cookie
/// verifies AND carries a `user_id` claim — legacy tokens and unauthed
/// callers fall through to None and the handler creates the org without a
/// bootstrap admin.
fn extract_optional_session_user(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Option<Uuid> {
    let cookie = headers.get("cookie").and_then(|v| v.to_str().ok())?;
    let token = cookie
        .split(';')
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix("oss_session="))?;
    let signing_key = hex::decode(&state.config.signing_key)
        .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());
    let claims =
        crate::services::jwt::verify(&signing_key, token, crate::services::jwt::AUD_SESSION)
            .ok()?;
    claims.user_id
}

pub(crate) async fn provision_new_org_contents(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
    session_user_id: Option<Uuid>,
) -> Result<Option<Uuid>> {
    match session_user_id {
        Some(user_id) => {
            let user = user_repo::get_by_id(state.db(ext), user_id)
                .await?
                .ok_or_else(|| AppError::Unauthorized("session user no longer exists".into()))?;
            let display_name = user
                .display_name
                .clone()
                .unwrap_or_else(|| user.email.clone().unwrap_or_else(|| "admin".into()));
            let creator_identity = identity::create_with_email(
                state.db(ext),
                org_id,
                &display_name,
                "user",
                None,
                user.email.as_deref(),
                serde_json::json!({ "bootstrap": true }),
            )
            .await?;
            identity::set_is_org_admin(state.db(ext), org_id, creator_identity.id, true).await?;
            identity::set_user_id(state.db(ext), org_id, creator_identity.id, Some(user_id))
                .await?;

            overslash_db::repos::org_bootstrap::bootstrap_org(
                state.db(ext),
                org_id,
                Some(creator_identity.id),
            )
            .await?;
            membership::create(state.db(ext), user_id, org_id, membership::ROLE_ADMIN).await?;

            // Durable record of the founder. Read by `drop_account_membership`
            // to flag the `was_original_creator` bit on `membership.removed`
            // audit events. Idempotent (only sets when NULL) so retry paths
            // can't rewrite history.
            overslash_db::repos::org::set_creator_user_id(state.db(ext), org_id, user_id).await?;

            Ok(Some(creator_identity.id))
        }
        None => {
            overslash_db::repos::org_bootstrap::bootstrap_org(state.db(ext), org_id, None).await?;
            Ok(None)
        }
    }
}

pub(crate) fn redirect_for_org(state: &AppState, org: &overslash_db::repos::org::OrgRow) -> String {
    let scheme = if state.config.public_url.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    if let Some(apex) = state.config.app_host_suffix.as_deref() {
        format!("{scheme}://{}.{apex}/", org.slug)
    } else {
        state.config.dashboard_url_for("/")
    }
}
