use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{delete, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};

use crate::{
    AppState,
    error::Result,
    extractors::{AdminAcl, AuthContext, ClientIp},
};

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
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Json(req): Json<CreateWebhookRequest>,
) -> Result<Json<WebhookResponse>> {
    let auth = acl;
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

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "webhook.created",
            resource_type: Some("webhook"),
            resource_id: Some(row.id),
            detail: serde_json::json!({ "url": &row.url, "events": &row.events }),
            description: None,
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

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
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    let deleted =
        overslash_db::repos::webhook::delete_subscription(&state.db, id, auth.org_id).await?;

    if deleted {
        let _ = overslash_db::repos::audit::log(
            &state.db,
            &overslash_db::repos::audit::AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "webhook.deleted",
                resource_type: Some("webhook"),
                resource_id: Some(id),
                detail: serde_json::json!({}),
                description: None,
                ip_address: ip.0.as_deref(),
            },
        )
        .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}
