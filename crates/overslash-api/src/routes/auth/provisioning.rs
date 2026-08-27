//! User provisioning across root (personal-org) and org-subdomain logins.

use super::*;

/// Find or provision a user across two distinct trust domains. See
/// `docs/design/multi_org_auth.md` §Authentication Flows.
///
/// - `org_slug = None` — **root login**: the caller hit `app.overslash.com`
///   and signed in via an Overslash-level IdP (env-var-configured Google /
///   GitHub). Lookup keys `(users.overslash_idp_provider, subject)`. If
///   missing, provision an Overslash-backed `users` row + personal org +
///   admin membership + identity.
/// - `org_slug = Some(slug)` — **org-subdomain login**: the caller hit
///   `<slug>.app.overslash.com` and signed in via that org's IdP (or, if
///   the org has opted into `allow_overslash_managed_signin`, via the
///   Overslash-managed env-var OAuth app). Lookup keys
///   `(identities.org_id, external_id)`. If missing, admission is gated by
///   the org-level flag — independent of which IdP authenticated:
///   * `allow_overslash_managed_signin = true`: a pending `org_invites(email)`
///     row is required regardless of IdP; the invite's role is honored.
///     Reject with `not_invited` on miss.
///   * Flag off (legacy): gate on the per-org
///     `org_idp_configs.allowed_email_domains`. Reject with
///     `not_permitted_by_org_idp` on miss.
///
/// In either case we return `(org_id, identity_id, user_id, email)`, which
/// callers shape into session claims.
pub(super) async fn find_or_provision_user(
    state: &AppState,
    ext: &axum::http::Extensions,
    userinfo: &NormalizedUserInfo,
    org_slug: Option<&str>,
) -> Result<(Uuid, Uuid, Uuid, String), AppError> {
    match org_slug {
        None => provision_root(state, ext, userinfo).await,
        Some(slug) => provision_org_subdomain(state, ext, userinfo, slug).await,
    }
}

async fn provision_root(
    state: &AppState,
    ext: &axum::http::Extensions,
    userinfo: &NormalizedUserInfo,
) -> Result<(Uuid, Uuid, Uuid, String), AppError> {
    let display_name = userinfo.name.as_deref().unwrap_or(&userinfo.email);

    // Hot path: existing Overslash-backed user → refresh profile and return.
    if let Some(user) = user_repo::find_by_overslash_idp(
        state.db(ext),
        &userinfo.provider_key,
        &userinfo.external_id,
    )
    .await?
    {
        let _ = user_repo::refresh_profile(
            state.db(ext),
            user.id,
            Some(&userinfo.email),
            Some(display_name),
        )
        .await;
        let personal_org_id = user.personal_org_id.ok_or_else(|| {
            AppError::Internal(
                "Overslash-backed user has no personal_org_id; backfill incomplete".into(),
            )
        })?;
        let identity = overslash_db::repos::identity::find_by_org_and_user(
            state.db(ext),
            personal_org_id,
            user.id,
        )
        .await?
        .ok_or_else(|| AppError::Internal("personal org exists but has no user identity".into()))?;
        // Keep the identity's displayed email/name roughly current too.
        let scope = OrgScope::new(personal_org_id, state.db_pool(ext));
        let metadata = userinfo_metadata(userinfo);
        let _ = scope
            .update_identity_profile(identity.id, display_name, metadata)
            .await;
        return Ok((
            personal_org_id,
            identity.id,
            user.id,
            userinfo.email.clone(),
        ));
    }

    // First-time root login → provision personal org + Overslash-backed user.
    let slug = generate_personal_slug();
    let org = {
        let mut attempts = 0u32;
        loop {
            let candidate = if attempts == 0 {
                slug.clone()
            } else {
                generate_personal_slug()
            };
            match org::create(state.db(ext), display_name, &candidate, "standard").await {
                Ok(mut row) => {
                    // Flip is_personal=true. The column was added in 040 with
                    // DEFAULT false; personal orgs are marked explicitly so the
                    // subdomain middleware refuses to route them.
                    sqlx::query!("UPDATE orgs SET is_personal = true WHERE id = $1", row.id)
                        .execute(state.db(ext))
                        .await?;
                    row.is_personal = true;
                    break row;
                }
                Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() && attempts < 5 => {
                    attempts += 1;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    };

    // Everything from here on — user creation, identity, bootstrap,
    // membership — runs inside `provision_root_contents`. Any error
    // (other than the unique-violation race, which returns Ok(winner) after
    // manually cleaning up the org) bubbles up here, and we compensate by
    // deleting the personal-org shell to avoid leaking an empty row.
    match provision_root_contents(state, ext, userinfo, &org, display_name).await {
        Ok(tuple) => Ok(tuple),
        Err(e) => {
            if let Err(cleanup_err) = sqlx::query!("DELETE FROM orgs WHERE id = $1", org.id)
                .execute(state.db(ext))
                .await
            {
                tracing::error!(
                    org_id = %org.id,
                    error = %e,
                    cleanup_error = %cleanup_err,
                    "provision_root rollback failed; orphan personal org left in DB"
                );
            }
            Err(e)
        }
    }
}

async fn provision_root_contents(
    state: &AppState,
    ext: &axum::http::Extensions,
    userinfo: &NormalizedUserInfo,
    org: &overslash_db::repos::org::OrgRow,
    display_name: &str,
) -> Result<(Uuid, Uuid, Uuid, String), AppError> {
    // Concurrent-first-login race: another request for the same
    // (provider, subject) may have already created the users row + personal
    // org + identity + membership. We detect the race via the partial
    // UNIQUE on `users.(overslash_idp_provider, overslash_idp_subject)` and
    // fall through to the winner's state. In that case we delete *our* org
    // ourselves (the caller's outer cleanup won't run because we're
    // returning Ok) and return the winner's (org, identity, user_id).
    let new_user = match user_repo::create_overslash_backed(
        state.db(ext),
        Some(&userinfo.email),
        Some(display_name),
        &userinfo.provider_key,
        &userinfo.external_id,
    )
    .await
    {
        Ok(u) => u,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            let _ = sqlx::query!("DELETE FROM orgs WHERE id = $1", org.id)
                .execute(state.db(ext))
                .await;
            let winner = user_repo::find_by_overslash_idp(
                state.db(ext),
                &userinfo.provider_key,
                &userinfo.external_id,
            )
            .await?
            .ok_or_else(|| {
                AppError::Internal(
                    "race: user row vanished between unique-violation and re-read".into(),
                )
            })?;
            // personal_org_id is set by the winner after user insert, so it
            // may be NULL if we read the row before the winner's transaction
            // commits. Retry with exponential backoff (50ms → ~1.5s total).
            let personal_org_id = {
                let mut maybe = winner.personal_org_id;
                let mut attempts = 0u32;
                while maybe.is_none() && attempts < 5 {
                    tokio::time::sleep(std::time::Duration::from_millis(50 * 2u64.pow(attempts)))
                        .await;
                    attempts += 1;
                    if let Ok(Some(refreshed)) = user_repo::find_by_overslash_idp(
                        state.db(ext),
                        &userinfo.provider_key,
                        &userinfo.external_id,
                    )
                    .await
                    {
                        maybe = refreshed.personal_org_id;
                    }
                }
                maybe.ok_or_else(|| {
                    AppError::Internal(
                        "race: winner's users row still has no personal_org_id after retries"
                            .into(),
                    )
                })?
            };
            let identity = overslash_db::repos::identity::find_by_org_and_user(
                state.db(ext),
                personal_org_id,
                winner.id,
            )
            .await?
            .ok_or_else(|| {
                AppError::Internal("race: winner has no identity in their personal org yet".into())
            })?;
            let _ = user_repo::refresh_profile(
                state.db(ext),
                winner.id,
                Some(&userinfo.email),
                Some(display_name),
            )
            .await;
            return Ok((
                personal_org_id,
                identity.id,
                winner.id,
                userinfo.email.clone(),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    user_repo::set_personal_org(state.db(ext), new_user.id, org.id).await?;

    let metadata = userinfo_metadata(userinfo);
    let scope = OrgScope::new(org.id, state.db_pool(ext));
    let identity_row = scope
        .create_identity_with_email(
            display_name,
            "user",
            Some(&userinfo.external_id),
            Some(&userinfo.email),
            metadata,
        )
        .await?;
    overslash_db::repos::identity::set_user_id(
        state.db(ext),
        org.id,
        identity_row.id,
        Some(new_user.id),
    )
    .await?;

    overslash_db::repos::org_bootstrap::bootstrap_org(state.db(ext), org.id, Some(identity_row.id))
        .await?;

    membership::create(state.db(ext), new_user.id, org.id, membership::ROLE_ADMIN).await?;

    // Best-effort welcome email. Failures are logged and swallowed inside
    // the service — a transient mailer hiccup must never block first-login.
    let dashboard_url = build_org_redirect(state, org);
    crate::services::welcome_email::send_if_due(state, new_user.id, org.id, dashboard_url).await;

    Ok((org.id, identity_row.id, new_user.id, userinfo.email.clone()))
}

async fn provision_org_subdomain(
    state: &AppState,
    ext: &axum::http::Extensions,
    userinfo: &NormalizedUserInfo,
    slug: &str,
) -> Result<(Uuid, Uuid, Uuid, String), AppError> {
    let target_org = org::get_by_slug(state.db(ext), slug)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("org not found: {slug}")))?;
    if target_org.is_personal {
        return Err(AppError::BadRequest(
            "personal orgs do not accept IdP logins".into(),
        ));
    }

    // Existing org-identity? refresh + return.
    let scope = OrgScope::new(target_org.id, state.db_pool(ext));
    if let Some(existing) = overslash_db::repos::identity::find_user_by_external_id_in_org(
        state.db(ext),
        target_org.id,
        &userinfo.external_id,
    )
    .await?
    {
        let display_name = userinfo.name.as_deref().unwrap_or(&userinfo.email);
        let metadata = userinfo_metadata(userinfo);
        let _ = scope
            .update_identity_profile(existing.id, display_name, metadata)
            .await;
        let user_id = existing.user_id.ok_or_else(|| {
            AppError::Internal(
                "org-identity missing user_id; migration 040 backfill incomplete".into(),
            )
        })?;
        let _ = user_repo::refresh_profile(
            state.db(ext),
            user_id,
            Some(&userinfo.email),
            Some(display_name),
        )
        .await;
        return Ok((target_org.id, existing.id, user_id, userinfo.email.clone()));
    }

    let display_name = userinfo.name.as_deref().unwrap_or(&userinfo.email);

    // The Overslash-backed account behind this subject, if any. Resolved once
    // and threaded through the three branches below — adopt-by-user needs it
    // as a lookup key, and the other two would otherwise re-query it.
    let overslash_user = user_repo::find_by_overslash_idp(
        state.db(ext),
        &userinfo.provider_key,
        &userinfo.external_id,
    )
    .await?;

    // Adopt-by-user, BEFORE adopt-by-email. The subject missed, but this human
    // may already be an actor in this org under a *different* address: the
    // founder identity minted by `POST /v1/orgs` carries `external_id = NULL`
    // and the account email as of signup, so a later org-subdomain login whose
    // IdP reports a different address misses both the subject and the email
    // key, and both missing used to mean "mint a new actor". #487's
    // adopt-by-email converges the two only when the address still matches —
    // see the duplicate actors migration 115 cleans up.
    //
    // Ordering matters. If adopt-by-email ran first it could land on a pending
    // invite for the new address and link THAT row to a user who already owns
    // an identity here, which is the same fork by another route — and now a
    // violation of `identities_org_user_unique`. Checking the account first
    // makes the existing actor win, which is right: they have the agents, the
    // grants and the audit trail, and the redundant invite row is the thing
    // worth orphaning. Membership is already established, so this returns
    // ahead of the admission gate — an existing member whose email changed
    // must not be re-admitted (or rejected with `not_invited`).
    if let Some(user) = &overslash_user
        && let Some(existing) = overslash_db::repos::identity::find_by_org_and_user(
            state.db(ext),
            target_org.id,
            user.id,
        )
        .await?
    {
        let metadata = userinfo_metadata(userinfo);
        // Claim the subject on first adoption only — same rule as the
        // adopt-by-email branch below: `external_id` records who originally
        // claimed this identity and must not flip-flop between IdPs.
        if existing.external_id.is_none() {
            overslash_db::repos::identity::set_external_id(
                state.db(ext),
                target_org.id,
                existing.id,
                &userinfo.external_id,
            )
            .await?;
        }
        let _ = scope
            .update_identity_profile(existing.id, display_name, metadata)
            .await;
        let _ = user_repo::refresh_profile(
            state.db(ext),
            user.id,
            Some(&userinfo.email),
            Some(display_name),
        )
        .await;
        return Ok((target_org.id, existing.id, user.id, userinfo.email.clone()));
    }

    // Adopt-by-email. A user identity with this email but a *different* (or
    // no) IdP subject is the pre-created member — minted by an invite, by
    // name-based impersonation, or by a prior sign-in through another IdP.
    // It IS the admission decision, and adopting it (rather than forking a
    // second identity) is what makes a pre-created member and their first
    // real sign-in converge on one identity — with its agents, connections,
    // and audit history. `require_invite_admission` keeps its meaning: the
    // pre-created identity is the invite.
    if let Some(existing) = scope
        .find_user_identity_by_email_in_org(&userinfo.email)
        .await?
    {
        let metadata = userinfo_metadata(userinfo);

        // Resolve the users row: reuse the identity's existing link (an
        // already-signed-in member switching IdPs), else an Overslash-IdP
        // match, else a fresh org-only user for a never-signed-in invite.
        let user_id = match existing.user_id {
            Some(uid) => {
                let _ = user_repo::refresh_profile(
                    state.db(ext),
                    uid,
                    Some(&userinfo.email),
                    Some(display_name),
                )
                .await;
                uid
            }
            // The adopt-by-user branch above already proved this account has
            // no identity in this org, so linking it here can't collide with
            // `identities_org_user_unique`.
            None => match &overslash_user {
                Some(u) => {
                    let _ = user_repo::refresh_profile(
                        state.db(ext),
                        u.id,
                        Some(&userinfo.email),
                        Some(display_name),
                    )
                    .await;
                    u.id
                }
                None => {
                    user_repo::create_org_only(
                        state.db(ext),
                        Some(&userinfo.email),
                        Some(display_name),
                    )
                    .await?
                    .id
                }
            },
        };

        // Link the identity to this IdP subject — but ONLY the first time.
        // `external_id` records the subject that originally claimed this
        // identity; it must not flip-flop as a member alternates between
        // IdPs. Rewriting it on every alternate-IdP login would make the
        // `(org_id, external_id)` fast-path miss half the time and, worse,
        // make `connect_gate`'s cross-org subject match depend on whichever
        // IdP happened to be used last. A second IdP is still admitted — by
        // email, right here — it just doesn't rewrite the column.
        // `(org_id, external_id)` is unique, and we only reach this branch
        // after the subject lookup missed, so the first write can't collide.
        if existing.external_id.is_none() {
            overslash_db::repos::identity::set_external_id(
                state.db(ext),
                target_org.id,
                existing.id,
                &userinfo.external_id,
            )
            .await?;
        }
        let _ = scope
            .update_identity_profile(existing.id, display_name, metadata)
            .await;

        // A never-signed-in invite still needs its user link + membership +
        // groups. An already-linked member skips all of this (idempotent
        // anyway, but we avoid a redundant membership insert). The work is
        // shared with the in-app accept path — see `services::invite_adoption`.
        if existing.user_id.is_none() {
            crate::services::invite_adoption::adopt_pending_identity(
                state,
                ext,
                &target_org,
                &existing,
                user_id,
                &userinfo.email,
                crate::services::invite_adoption::AdoptionVia::Sso {
                    provider: &userinfo.provider_key,
                },
            )
            .await?;
        }

        return Ok((target_org.id, existing.id, user_id, userinfo.email.clone()));
    }

    // First-time sign-in for this (org, IdP-subject). Two admission paths:
    //
    // 1. Overslash-managed sign-in (migration 066): when the org has opted
    //    in via `allow_overslash_managed_signin`, the IdP authenticates but
    //    cannot admit by itself. Migration 092 splits admission into two
    //    sub-modes, keyed on `require_invite_admission`:
    //      a. `require_invite_admission = true` (default) — membership
    //         requires a pending `org_invites(email)` row. The invite's
    //         `role` is honored when creating the membership. Reject
    //         `not_invited`.
    //      b. `require_invite_admission = false` — admit any email whose
    //         domain is on the org-wide `managed_signin_allowed_domains`
    //         allowlist. An EMPTY allowlist here is a misconfiguration, not
    //         "admit everyone": reject `domain_admission_not_configured`.
    //         A domain not on a non-empty list rejects `domain_not_allowed`.
    //         New members join as `member` (no invite → no role override).
    //
    // 2. Legacy path: gate on the per-org `org_idp_configs.allowed_email_domains`.
    //    Empty list = "trust the IdP entirely" (the admin already constrained
    //    who can authenticate by provisioning the IdP's client_id / tenant).
    //    A non-empty list is a whitelist. The IdP config itself must exist —
    //    absence means this org hasn't enabled this provider, so we reject
    //    with `not_permitted_by_org_idp`.
    //
    // SINGLE_ORG_MODE exception (applies to BOTH paths): self-hosted
    // operators typically use the env-var Overslash-level IdPs
    // (`GOOGLE_AUTH_CLIENT_ID`, etc.). In that mode the operator IS the org
    // admin — the env creds they provisioned ARE the trust boundary, so
    // every per-org gate is bypassed. Without this branch on the
    // invite-gated path, a fresh self-hosted deployment defaults the org's
    // `allow_overslash_managed_signin` flag to `true`, leaving the operator
    // locked out (no invite exists yet and they can't sign in to create
    // one).
    let single_org_bypass = state
        .config
        .single_org_mode
        .as_deref()
        .map(|pinned| pinned == slug)
        .unwrap_or(false);
    // We only reach here when NO user identity with this email exists in the
    // org — the adopt-by-email branch above returns early for every
    // pre-created or already-signed-in member. So the existing-member and
    // pending-invite cases are handled there; this block is purely the
    // *fresh admission* gate for a brand-new email.
    if single_org_bypass {
        // Self-hosted operator: the env-var IdP they provisioned IS the trust
        // boundary, so admission is unconditional.
    } else if target_org.allow_overslash_managed_signin {
        if target_org.require_invite_admission {
            // Invite-required: no pre-created identity for this email means
            // no invite. (An invite is now a `kind='user'` identity with this
            // email — see migration 103 and `routes/org_invites.rs`.)
            return Err(AppError::Forbidden("not_invited".into()));
        } else {
            // Domain-allowlist admission. The allowlist is trusted only when
            // non-empty; an empty list with require-invite off means the
            // admin opened admission without naming any domain — reject
            // rather than admit the whole internet. Domain match splits the
            // verified email on `@` (case-insensitive); it does NOT consult
            // Google's `hd`/hosted-domain claim, so a user with a personal
            // `@reveni.io` alias would match. See TECH_DEBT.
            let email_domain = userinfo
                .email
                .rsplit('@')
                .next()
                .unwrap_or("")
                .to_lowercase();
            if target_org.managed_signin_allowed_domains.is_empty() {
                return Err(AppError::Forbidden(
                    "domain_admission_not_configured".into(),
                ));
            }
            if !target_org
                .managed_signin_allowed_domains
                .iter()
                .any(|d| d.eq_ignore_ascii_case(&email_domain))
            {
                return Err(AppError::Forbidden("domain_not_allowed".into()));
            }
        }
    } else {
        let email_domain = userinfo
            .email
            .rsplit('@')
            .next()
            .unwrap_or("")
            .to_lowercase();
        let idp_config = overslash_db::repos::org_idp_config::get_by_org_and_provider(
            state.db(ext),
            target_org.id,
            &userinfo.provider_key,
        )
        .await?
        .ok_or_else(|| AppError::Forbidden("not_permitted_by_org_idp".into()))?;
        if !idp_config.allowed_email_domains.is_empty()
            && !idp_config
                .allowed_email_domains
                .iter()
                .any(|d| d.eq_ignore_ascii_case(&email_domain))
        {
            return Err(AppError::Forbidden("not_permitted_by_org_idp".into()));
        }
    }

    let metadata = userinfo_metadata(userinfo);

    // Fresh admission for a brand-new email. Attach to an existing
    // Overslash-backed user when the `(provider, subject)` already matches
    // (SINGLE_ORG_MODE: the env-var IdP is both the Overslash IdP and the org
    // IdP), otherwise mint a fresh org-only user. Adopt-by-user already
    // established that such an account holds no identity in this org, so the
    // fresh row below is this human's first actor here.
    let user_id = match &overslash_user {
        Some(u) => {
            let _ = user_repo::refresh_profile(
                state.db(ext),
                u.id,
                Some(&userinfo.email),
                Some(display_name),
            )
            .await;
            u.id
        }
        None => {
            user_repo::create_org_only(state.db(ext), Some(&userinfo.email), Some(display_name))
                .await?
                .id
        }
    };

    let identity_row = scope
        .create_identity_with_email(
            display_name,
            "user",
            Some(&userinfo.external_id),
            Some(&userinfo.email),
            metadata,
        )
        .await?;
    overslash_db::repos::identity::set_user_id(
        state.db(ext),
        target_org.id,
        identity_row.id,
        Some(user_id),
    )
    .await?;
    overslash_db::repos::org_bootstrap::bootstrap_user_in_org(
        state.db(ext),
        target_org.id,
        identity_row.id,
    )
    .await?;

    // A freshly domain-/IdP-admitted email is always a plain member. Admins
    // are conferred elsewhere — the org creator (`POST /v1/orgs`), an admin
    // invite (a pre-created identity carrying `is_org_admin`, adopted by the
    // branch above), or an explicit promote on the Members page — never by a
    // first-time domain-allowlist sign-in.
    //
    // `membership::create` swallows the unique violation so a
    // SINGLE_ORG_MODE reuse-user path (where `POST /v1/orgs` already left a
    // `(user_id, org_id)` row) doesn't fail on repeat login.
    match membership::create(
        state.db(ext),
        user_id,
        target_org.id,
        membership::ROLE_MEMBER,
    )
    .await
    {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {}
        Err(e) => return Err(e.into()),
    };

    // Best-effort welcome email for JIT-provisioned corp-org users. Service
    // gates on `welcome_email_sent_at IS NULL`, so returning users
    // (SINGLE_ORG_MODE Overslash-backed reuse) are naturally no-ops.
    let dashboard_url = build_org_redirect(state, &target_org);
    crate::services::welcome_email::send_if_due(state, user_id, target_org.id, dashboard_url).await;

    Ok((
        target_org.id,
        identity_row.id,
        user_id,
        userinfo.email.clone(),
    ))
}

fn userinfo_metadata(userinfo: &NormalizedUserInfo) -> serde_json::Value {
    json!({
        "provider": userinfo.provider_key,
        "external_id": userinfo.external_id,
        "name": userinfo.name,
        "picture": userinfo.picture,
    })
}

fn generate_personal_slug() -> String {
    // Personal orgs never surface publicly (the subdomain middleware refuses
    // to route them), so the slug just needs to be unique across orgs.
    // `rand::random::<u64>()` gives 64 bits of entropy — collision vanishingly
    // unlikely even across millions of orgs.
    let suffix = rand::random::<u64>();
    format!("personal-{suffix:016x}")
}
