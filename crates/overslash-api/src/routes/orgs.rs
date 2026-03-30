use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AuthContext, ClientIp},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs", post(create_org))
        .route("/v1/orgs/current", get(get_current_org))
}

#[derive(Deserialize)]
struct CreateOrgRequest {
    name: String,
    slug: String,
}

#[derive(Serialize)]
struct OrgResponse {
    id: Uuid,
    name: String,
    slug: String,
}

async fn create_org(
    State(state): State<AppState>,
    ip: ClientIp,
    Json(req): Json<CreateOrgRequest>,
) -> Result<Json<OrgResponse>> {
    let org = overslash_db::repos::org::create(&state.db, &req.name, &req.slug).await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: org.id,
            identity_id: None,
            action: "org.created",
            resource_type: Some("org"),
            resource_id: Some(org.id),
            detail: serde_json::json!({ "name": &org.name, "slug": &org.slug }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(OrgResponse {
        id: org.id,
        name: org.name,
        slug: org.slug,
    }))
}

async fn get_current_org(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<OrgResponse>> {
    let org = overslash_db::repos::org::get_by_id(&state.db, auth.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;
    Ok(Json(OrgResponse {
        id: org.id,
        name: org.name,
        slug: org.slug,
    }))
}
