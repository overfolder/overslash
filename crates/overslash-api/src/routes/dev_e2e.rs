//! Dev-only e2e seeding and teardown endpoints.
//!
//! Gated behind `DEV_AUTH=1` (same gate as `/auth/dev/token`). The e2e harness
//! (`scripts/e2e-up.sh`) calls `POST /auth/dev/seed-e2e-idps` after the API
//! becomes healthy to register the Auth0/Okta-shaped fakes from
//! `crates/overslash-fakes` as real `oauth_providers` rows and attach them to
//! per-org `org_idp_configs`. This is the only path through which the test
//! harness can wire the multi-IdP per-org flow without operator intervention.
//!
//! `DELETE /auth/dev/orgs/{slug}` is the teardown counterpart to
//! `/auth/dev/token?org=<slug>`: a spec mints a private org, drives the UI
//! against it, then drops it here (D34).
//!
//! Both endpoints are idempotent: re-running the seed (e.g. after `e2e-down` /
//! `e2e-up` cycles) updates existing rows in place, and deleting an org that is
//! already gone is a no-op rather than a 404.

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{delete, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AppState, error::AppError, extractors::ReqExt};
use overslash_core::crypto;
use overslash_db::repos::{oauth_provider, org, org_idp_config};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/dev/seed-e2e-idps", post(seed_e2e_idps))
        .route("/auth/dev/orgs/{slug}", delete(delete_dev_org))
}

/// Drop a dev org and everything hanging off it.
///
/// This is the teardown half of `/auth/dev/token?org=<slug>`: a spec mints a
/// private org, drives the UI against it, then deletes it here so a long-lived
/// local Postgres doesn't accumulate a run's worth of agents, secrets,
/// services and approvals (which is what happens today — see the scenarios
/// README's `${name}-${Date.now()}` workaround).
///
/// `DELETE FROM orgs` is the whole implementation because the schema already
/// cascades: every one of the org-scoped tables declares
/// `REFERENCES orgs(id) ON DELETE CASCADE`. The single non-cascading FK is
/// `users.personal_org_id`, which is `ON DELETE SET NULL` — so the profile's
/// `users` row survives as an orphan. That is harmless here (dev profile
/// emails are per-org, so a recreated org mints fresh ones) and deliberately
/// not "fixed" by deleting users, which would reach outside the org boundary.
///
/// Refuses to touch `dev-org`: that one is shared by every existing screenshot
/// script and spec, and deleting it mid-suite would be a very confusing
/// failure somewhere else entirely.
async fn delete_dev_org(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    Path(slug): Path<String>,
) -> Result<Json<DeleteOrgResponse>, AppError> {
    if !state.config.dev_auth_enabled {
        return Err(AppError::NotFound("not found".into()));
    }
    if slug == "dev-org" {
        return Err(AppError::BadRequest(
            "refusing to delete the shared 'dev-org'".into(),
        ));
    }

    let Some(org_row) = org::get_by_slug(state.db(&ext), &slug).await? else {
        // Idempotent: a spec's teardown must not fail because a previous
        // teardown already ran, or because the spec died before creating it.
        return Ok(Json(DeleteOrgResponse {
            slug,
            deleted: false,
        }));
    };

    sqlx::query!("DELETE FROM orgs WHERE id = $1", org_row.id)
        .execute(state.db(&ext))
        .await
        .map_err(|e| AppError::Internal(format!("delete dev org {slug}: {e}")))?;

    Ok(Json(DeleteOrgResponse {
        slug,
        deleted: true,
    }))
}

#[derive(Serialize)]
struct DeleteOrgResponse {
    slug: String,
    /// `false` when the org was already gone — teardown is idempotent.
    deleted: bool,
}

#[derive(Deserialize)]
pub struct SeedRequest {
    pub providers: Vec<SeedProvider>,
    pub orgs: Vec<SeedOrg>,
}

#[derive(Deserialize)]
pub struct SeedProvider {
    /// Provider key — used as the URL path segment in `/auth/login/{key}`.
    pub key: String,
    pub display_name: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub issuer_url: String,
}

#[derive(Deserialize)]
pub struct SeedOrg {
    pub slug: String,
    pub name: String,
    /// Provider key from `providers[]` to attach to this org.
    pub provider_key: String,
    /// Plaintext client_id / client_secret. The seed encrypts them with
    /// `SECRETS_ENCRYPTION_KEY` before persisting.
    pub client_id: String,
    pub client_secret: String,
    pub allowed_email_domains: Vec<String>,
}

#[derive(Serialize)]
struct SeedResponse {
    providers: Vec<SeededProvider>,
    orgs: Vec<SeededOrg>,
}

#[derive(Serialize)]
struct SeededProvider {
    key: String,
    issuer_url: String,
}

#[derive(Serialize)]
struct SeededOrg {
    slug: String,
    org_id: Uuid,
    provider_key: String,
    idp_config_id: Uuid,
}

async fn seed_e2e_idps(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    Json(req): Json<SeedRequest>,
) -> Result<Json<SeedResponse>, AppError> {
    if !state.config.dev_auth_enabled {
        return Err(AppError::NotFound("not found".into()));
    }

    let enc_key = state
        .config
        .keyring()
        .map_err(|e| AppError::Internal(format!("invalid encryption key: {e}")))?;

    // 1. Register / refresh providers. `create_custom` is upsert via
    //    `ON CONFLICT (key) DO UPDATE`, so re-runs land on the new fake URLs
    //    if the harness restarted on different ports.
    let mut seeded_providers = Vec::with_capacity(req.providers.len());
    for p in &req.providers {
        oauth_provider::create_custom(
            state.db(&ext),
            &p.key,
            &p.display_name,
            &p.authorization_endpoint,
            &p.token_endpoint,
            None,
            Some(&p.userinfo_endpoint),
            Some(&p.issuer_url),
            None,
            true,
            true,
            "client_secret_post",
        )
        .await
        .map_err(|e| AppError::Internal(format!("upsert provider {}: {e}", p.key)))?;
        seeded_providers.push(SeededProvider {
            key: p.key.clone(),
            issuer_url: p.issuer_url.clone(),
        });
    }

    // 2. Ensure orgs exist + are bootstrapped, then attach the IdP config.
    let mut seeded_orgs = Vec::with_capacity(req.orgs.len());
    for o in &req.orgs {
        let org_row = match org::get_by_slug(state.db(&ext), &o.slug).await? {
            Some(existing) => existing,
            None => match org::create(state.db(&ext), &o.name, &o.slug, "standard").await {
                Ok(new_org) => new_org,
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                    org::get_by_slug(state.db(&ext), &o.slug)
                        .await?
                        .ok_or_else(|| {
                            AppError::Internal(format!(
                                "seed race: {} missing after unique violation",
                                o.slug
                            ))
                        })?
                }
                Err(e) => return Err(e.into()),
            },
        };

        overslash_db::repos::org_bootstrap::bootstrap_org(state.db(&ext), org_row.id, None).await?;

        let enc_id = crypto::encrypt(&enc_key, o.client_id.as_bytes())
            .map_err(|e| AppError::Internal(format!("encrypt client_id: {e}")))?;
        let enc_secret = crypto::encrypt(&enc_key, o.client_secret.as_bytes())
            .map_err(|e| AppError::Internal(format!("encrypt client_secret: {e}")))?;

        // Idempotency: if the config already exists, update creds + domains
        // in place rather than failing on the (org_id, provider_key) unique
        // constraint.
        let existing =
            org_idp_config::get_by_org_and_provider(state.db(&ext), org_row.id, &o.provider_key)
                .await?;
        let scope = overslash_db::OrgScope::new(org_row.id, state.db_pool(&ext));
        let cfg_id = if let Some(cfg) = existing {
            scope
                .update_org_idp_config(
                    cfg.id,
                    org_idp_config::CredentialsUpdate::SetDedicated {
                        encrypted_client_id: &enc_id,
                        encrypted_client_secret: &enc_secret,
                    },
                    Some(true),
                    Some(o.allowed_email_domains.as_slice()),
                )
                .await?;
            cfg.id
        } else {
            let row = scope
                .create_org_idp_config(
                    &o.provider_key,
                    Some(enc_id.as_slice()),
                    Some(enc_secret.as_slice()),
                    true,
                    o.allowed_email_domains.as_slice(),
                )
                .await
                .map_err(|e| {
                    AppError::Internal(format!("create org_idp_config for {}: {e}", o.slug))
                })?;
            row.id
        };

        seeded_orgs.push(SeededOrg {
            slug: o.slug.clone(),
            org_id: org_row.id,
            provider_key: o.provider_key.clone(),
            idp_config_id: cfg_id,
        });
    }

    Ok(Json(SeedResponse {
        providers: seeded_providers,
        orgs: seeded_orgs,
    }))
}
