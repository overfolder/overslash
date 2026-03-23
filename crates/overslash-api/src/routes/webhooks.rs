use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{delete, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AppState, error::Result, extractors::AuthContext};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/webhooks", post(create_webhook).get(list_webhooks))
        .route("/v1/webhooks/{id}", delete(delete_webhook))
}

#[derive(Deserialize)]
struct CreateWebhookRequest {
    url: String,
    events: Vec<String>,
}

#[derive(Serialize)]
struct WebhookResponse {
    id: Uuid,
    url: String,
    events: Vec<String>,
    active: bool,
}

async fn create_webhook(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<CreateWebhookRequest>,
) -> Result<Json<WebhookResponse>> {
    // Generate a signing secret for this subscription
    use rand::RngCore;
    let mut secret_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut secret_bytes);
    let secret = hex::encode(secret_bytes);

    let row = overslash_db::repos::webhook::create_subscription(
        &state.db,
        auth.org_id,
        &req.url,
        &req.events,
        &secret,
    )
    .await?;

    Ok(Json(WebhookResponse {
        id: row.id,
        url: row.url,
        events: row.events,
        active: row.active,
    }))
}

async fn list_webhooks(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<WebhookResponse>>> {
    let rows = overslash_db::repos::webhook::list_by_org(&state.db, auth.org_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| WebhookResponse {
                id: r.id,
                url: r.url,
                events: r.events,
                active: r.active,
            })
            .collect(),
    ))
}

async fn delete_webhook(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let deleted = overslash_db::repos::webhook::delete_subscription(&state.db, id).await?;
    Ok(Json(serde_json::json!({ "deleted": deleted })))
}
