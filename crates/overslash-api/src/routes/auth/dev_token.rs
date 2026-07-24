//! `GET /auth/dev/token` — deterministic dev-profile sign-in.

use super::*;

// ---------------------------------------------------------------------------
// Dev token (unchanged)
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub(super) struct DevTokenQuery {
    next: Option<String>,
    /// `admin` (default), `member`, or `readonly`. Each maps to a deterministic
    /// dev identity inside Dev Org so e2e fixtures can sign in as different
    /// roles. Unknown values fall back to `admin` for forward compatibility.
    profile: Option<String>,
    /// Optional org slug. Absent → the shared `dev-org` (unchanged legacy
    /// behaviour, which every existing screenshot script and spec relies on).
    /// Present → sign into *that* org, creating it on demand, so an e2e spec
    /// can run against a private org nobody else is mutating.
    ///
    /// Identity resolution is by email and `find_user_identity_by_email` is a
    /// global lookup (`idx_identities_email` is not unique), so a per-org org
    /// needs per-org profile emails — otherwise the second org's login would
    /// resolve the first org's identity and silently cross the tenant
    /// boundary. `DevProfile::email_for` derives them from the slug.
    org: Option<String>,
}

/// Where a dev login lands. `Shared` is the legacy `dev-org`; `Scoped` is a
/// per-run org requested via `?org=`.
enum DevOrg {
    Shared,
    Scoped(String),
}

impl DevOrg {
    fn parse(slug: Option<&str>) -> Result<Self, AppError> {
        let Some(slug) = slug else {
            return Ok(Self::Shared);
        };
        let slug = slug.trim();
        // Mirrors the public slug rules in `routes/orgs.rs` so a slug accepted
        // here can't produce an org the real API would have rejected.
        let valid = (2..=63).contains(&slug.len())
            && slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !slug.starts_with('-')
            && !slug.ends_with('-');
        if !valid {
            return Err(AppError::BadRequest(format!(
                "invalid dev org slug {slug:?}: 2-63 chars of [a-z0-9-], no leading/trailing hyphen"
            )));
        }
        if slug == "dev-org" {
            // Would collide with the shared org while using scoped emails,
            // leaving two identity sets fighting over one org.
            return Err(AppError::BadRequest(
                "dev org slug 'dev-org' is reserved — omit ?org= to use the shared org".into(),
            ));
        }
        Ok(Self::Scoped(slug.to_string()))
    }

    fn slug(&self) -> &str {
        match self {
            Self::Shared => "dev-org",
            Self::Scoped(s) => s,
        }
    }

    fn display_name(&self) -> String {
        match self {
            Self::Shared => "Dev Org".to_string(),
            Self::Scoped(s) => format!("Dev Org ({s})"),
        }
    }
}

#[derive(Clone, Copy)]
enum DevProfile {
    Admin,
    Member,
    Readonly,
}

impl DevProfile {
    fn parse(s: Option<&str>) -> Self {
        match s.unwrap_or("admin") {
            "member" => Self::Member,
            "readonly" => Self::Readonly,
            _ => Self::Admin,
        }
    }
    fn email(self) -> &'static str {
        match self {
            Self::Admin => "dev@overslash.local",
            Self::Member => "member@overslash.local",
            Self::Readonly => "readonly@overslash.local",
        }
    }

    /// The profile's email *within a given dev org*. The shared org keeps the
    /// historical addresses verbatim — existing fixtures assert on them — while
    /// a scoped org gets a slug-tagged local part so the global email lookup
    /// can never resolve across orgs.
    fn email_for(self, org: &DevOrg) -> String {
        match org {
            DevOrg::Shared => self.email().to_string(),
            DevOrg::Scoped(slug) => {
                let local = match self {
                    Self::Admin => "dev",
                    Self::Member => "member",
                    Self::Readonly => "readonly",
                };
                format!("{local}+{slug}@overslash.local")
            }
        }
    }
    fn display_name(self) -> &'static str {
        match self {
            Self::Admin => "Dev User",
            Self::Member => "Dev Member",
            Self::Readonly => "Dev Readonly",
        }
    }
    fn external_id(self) -> &'static str {
        match self {
            Self::Admin => "dev-local",
            Self::Member => "dev-local-member",
            Self::Readonly => "dev-local-readonly",
        }
    }
}

pub(super) async fn dev_token(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    Query(query): Query<DevTokenQuery>,
) -> Result<Response, AppError> {
    if !state.config.dev_auth_enabled {
        return Err(AppError::NotFound("not found".into()));
    }

    let profile = DevProfile::parse(query.profile.as_deref());
    let dev_org = DevOrg::parse(query.org.as_deref())?;
    let admin_email = DevProfile::Admin.email_for(&dev_org);
    let org_slug = dev_org.slug();
    let system = SystemScope::new_internal(state.db_pool(&ext));

    // Step 1: ensure the dev org exists. Look up the admin identity to find the
    // org or create one. We always run org_bootstrap (idempotent) so
    // Everyone/Admins groups + the overslash service instance exist.
    let admin_org_id = match system.find_user_identity_by_email(&admin_email).await? {
        Some(existing) => existing.org_id,
        None => {
            match org::create(
                state.db(&ext),
                &dev_org.display_name(),
                org_slug,
                "standard",
            )
            .await
            {
                Ok(new_org) => new_org.id,
                Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
                    org::get_by_slug(state.db(&ext), org_slug)
                        .await?
                        .ok_or_else(|| AppError::Internal(format!("dev race: {org_slug} missing")))?
                        .id
                }
                Err(e) => return Err(e.into()),
            }
        }
    };
    overslash_db::repos::org_bootstrap::bootstrap_org(state.db(&ext), admin_org_id, None).await?;
    // Match the public `POST /v1/orgs` corp-org default — dev orgs ship
    // with the Overslash-managed sign-in flag on so e2e flows and dashboard
    // screenshots exercise the same shape as production cloud orgs.
    let _ = overslash_db::repos::org::set_allow_overslash_managed_signin(
        state.db(&ext),
        admin_org_id,
        true,
    )
    .await;

    // Step 2: resolve (or lazily create) the requested profile's identity
    // inside Dev Org. Every profile gets the same provisioning the
    // production OIDC callback applies — `users` row, `user_id` on the
    // identity, Everyone + Myself groups, membership row — so `/account`,
    // the org switcher, group ceilings, and is_admin all behave. Admin
    // additionally joins the Admins group via `bootstrap_org(.., Some(id))`.
    let profile_email = profile.email_for(&dev_org);
    let profile_email = profile_email.as_str();
    let identity_id =
        if let Some(existing) = system.find_user_identity_by_email(profile_email).await? {
            // Re-assert admin group membership on every admin login. Without
            // this, an admin removed from the Admins group manually (or by a
            // test that toggled it off) silently loses admin powers on the
            // next sign-in. bootstrap_org is idempotent, so this is cheap.
            if matches!(profile, DevProfile::Admin) {
                overslash_db::repos::org_bootstrap::bootstrap_org(
                    state.db(&ext),
                    admin_org_id,
                    Some(existing.id),
                )
                .await?;
            }
            existing.id
        } else {
            let scope = OrgScope::new(admin_org_id, state.db_pool(&ext));
            let new_identity = scope
                .create_identity_with_email(
                    profile.display_name(),
                    "user",
                    Some(profile.external_id()),
                    Some(profile_email),
                    json!({"dev": true, "profile": match profile {
                        DevProfile::Admin => "admin",
                        DevProfile::Member => "member",
                        DevProfile::Readonly => "readonly",
                    }}),
                )
                .await?;

            let user = user_repo::create_org_only(
                state.db(&ext),
                Some(profile_email),
                Some(profile.display_name()),
            )
            .await?;
            overslash_db::repos::identity::set_user_id(
                state.db(&ext),
                admin_org_id,
                new_identity.id,
                Some(user.id),
            )
            .await?;

            let role = if matches!(profile, DevProfile::Admin) {
                // Admins join the Admins group AND get an admin membership row,
                // matching what POST /v1/orgs and the org-creator IdP path do.
                overslash_db::repos::org_bootstrap::bootstrap_org(
                    state.db(&ext),
                    admin_org_id,
                    Some(new_identity.id),
                )
                .await?;
                membership::ROLE_ADMIN
            } else {
                overslash_db::repos::org_bootstrap::bootstrap_user_in_org(
                    state.db(&ext),
                    admin_org_id,
                    new_identity.id,
                )
                .await?;
                membership::ROLE_MEMBER
            };

            match membership::create(state.db(&ext), user.id, admin_org_id, role).await {
                Ok(_) => {}
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {}
                Err(e) => return Err(e.into()),
            }

            new_identity.id
        };
    let org_id = admin_org_id;
    let dev_email = profile_email;

    // Dev login was single-org pre-multi-org. Post-040 we still back every
    // `kind='user'` identity with a `users` row; resolve it here so the dev
    // session participates in the multi-org surface (`/account`, switcher,
    // `POST /v1/orgs` bootstrap admin).
    let dev_user_id = overslash_db::repos::identity::get_by_id(state.db(&ext), org_id, identity_id)
        .await?
        .and_then(|row| row.user_id);
    if dev_user_id.is_none() {
        tracing::warn!(
            "dev identity {identity_id} has no user_id; /account and switch-org will be limited"
        );
    }

    let jwt_secret = signing_key_bytes(&state.config.signing_key);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: dev_email.into(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 7 * 24 * 3600,
        user_id: dev_user_id,
        mcp_client_id: None,
    };
    let token = jwt::mint(&jwt_secret, &claims)
        .map_err(|e| AppError::Internal(format!("jwt mint failed: {e}")))?;

    let session_cookie = session_cookie(&state, &token)?;

    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, session_cookie);

    // When `?next=` is set (e.g. by /oauth/authorize bouncing through dev
    // login), redirect instead of returning JSON so the OAuth flow resumes.
    if let Some(next) = query.next.as_deref().and_then(sanitize_next) {
        return Ok((headers, Redirect::to(&next)).into_response());
    }

    Ok((
        headers,
        axum::Json(json!({
            "status": "authenticated",
            "org_id": org_id,
            "identity_id": identity_id,
            "email": dev_email,
            "token": token,
        })),
    )
        .into_response())
}
