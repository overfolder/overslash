use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};

use crate::{AppState, error::Result, extractors::ClientIp};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/orgs", post(create_org))
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

    // Bootstrap system assets: overslash service, Everyone + Admins groups, grants
    overslash_db::repos::org_bootstrap::bootstrap_org(&state.db, org.id, None).await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: org.id,
            identity_id: None,
            action: "org.created",
            resource_type: Some("org"),
            resource_id: Some(org.id),
            detail: serde_json::json!({ "name": &org.name, "slug": &org.slug }),
            description: None,
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
