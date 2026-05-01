//! Dev-only e2e seeding endpoints.
//!
//! Gated behind `DEV_AUTH=1` (same gate as `/auth/dev/token`). The e2e harness
//! (`scripts/e2e-up.sh`) calls `POST /auth/dev/seed-e2e-idps` after the API
//! becomes healthy to register the Auth0/Okta-shaped fakes from
//! `crates/overslash-fakes` as real `oauth_providers` rows and attach them to
//! per-org `org_idp_configs`. This is the only path through which the test
//! harness can wire the multi-IdP per-org flow without operator intervention.
//!
//! The endpoint is idempotent: re-running the seed (e.g. after `e2e-down` /
//! `e2e-up` cycles) updates existing rows in place.

use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AppState, error::AppError};
use overslash_core::crypto;
use overslash_db::repos::{oauth_provider, org, org_idp_config};

pub fn router() -> Router<AppState> {
    Router::new().route("/auth/dev/seed-e2e-idps", post(seed_e2e_idps))
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
    Json(req): Json<SeedRequest>,
) -> Result<Json<SeedResponse>, AppError> {
    if !state.config.dev_auth_enabled {
        return Err(AppError::NotFound("not found".into()));
    }

    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)
        .map_err(|e| AppError::Internal(format!("invalid encryption key: {e}")))?;

    // 1. Register / refresh providers. `create_custom` is upsert via
    //    `ON CONFLICT (key) DO UPDATE`, so re-runs land on the new fake URLs
    //    if the harness restarted on different ports.
    let mut seeded_providers = Vec::with_capacity(req.providers.len());
    for p in &req.providers {
        oauth_provider::create_custom(
            &state.db,
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
        let org_row = match org::get_by_slug(&state.db, &o.slug).await? {
            Some(existing) => existing,
            None => match org::create(&state.db, &o.name, &o.slug, "standard").await {
                Ok(new_org) => new_org,
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                    org::get_by_slug(&state.db, &o.slug).await?.ok_or_else(|| {
                        AppError::Internal(format!(
                            "seed race: {} missing after unique violation",
                            o.slug
                        ))
                    })?
                }
                Err(e) => return Err(e.into()),
            },
        };

        overslash_db::repos::org_bootstrap::bootstrap_org(&state.db, org_row.id, None).await?;

        let enc_id = crypto::encrypt(&enc_key, o.client_id.as_bytes())
            .map_err(|e| AppError::Internal(format!("encrypt client_id: {e}")))?;
        let enc_secret = crypto::encrypt(&enc_key, o.client_secret.as_bytes())
            .map_err(|e| AppError::Internal(format!("encrypt client_secret: {e}")))?;

        // Idempotency: if the config already exists, update creds + domains
        // in place rather than failing on the (org_id, provider_key) unique
        // constraint.
        let existing =
            org_idp_config::get_by_org_and_provider(&state.db, org_row.id, &o.provider_key).await?;
        let scope = overslash_db::OrgScope::new(org_row.id, state.db.clone());
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
