use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AppState, error::Result};

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
    Json(req): Json<CreateOrgRequest>,
) -> Result<Json<OrgResponse>> {
    let org = overslash_db::repos::org::create(&state.db, &req.name, &req.slug).await?;
    Ok(Json(OrgResponse {
        id: org.id,
        name: org.name,
        slug: org.slug,
    }))
}
