use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AppState, error::Result, extractors::AuthContext};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/identities", post(create_identity).get(list_identities))
}

#[derive(Deserialize)]
struct CreateIdentityRequest {
    name: String,
    kind: String,
    external_id: Option<String>,
}

#[derive(Serialize)]
struct IdentityResponse {
    id: Uuid,
    org_id: Uuid,
    name: String,
    kind: String,
    external_id: Option<String>,
}

async fn create_identity(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<CreateIdentityRequest>,
) -> Result<Json<IdentityResponse>> {
    let row = overslash_db::repos::identity::create(
        &state.db,
        auth.org_id,
        &req.name,
        &req.kind,
        req.external_id.as_deref(),
    )
    .await?;
    Ok(Json(IdentityResponse {
        id: row.id,
        org_id: row.org_id,
        name: row.name,
        kind: row.kind,
        external_id: row.external_id,
    }))
}

async fn list_identities(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<IdentityResponse>>> {
    let rows = overslash_db::repos::identity::list_by_org(&state.db, auth.org_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| IdentityResponse {
                id: r.id,
                org_id: r.org_id,
                name: r.name,
                kind: r.kind,
                external_id: r.external_id,
            })
            .collect(),
    ))
}
