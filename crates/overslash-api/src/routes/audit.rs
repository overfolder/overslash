use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{AppState, error::Result, extractors::AuthContext};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/audit", get(query_audit))
}

#[derive(Serialize)]
struct AuditEntry {
    id: Uuid,
    identity_id: Option<Uuid>,
    action: String,
    resource_type: Option<String>,
    resource_id: Option<Uuid>,
    detail: serde_json::Value,
    created_at: OffsetDateTime,
}

#[derive(serde::Deserialize)]
struct AuditQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    50
}

async fn query_audit(
    State(state): State<AppState>,
    auth: AuthContext,
    axum::extract::Query(params): axum::extract::Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>> {
    let rows = overslash_db::repos::audit::query_by_org(
        &state.db,
        auth.org_id,
        params.limit,
        params.offset,
    )
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| AuditEntry {
                id: r.id,
                identity_id: r.identity_id,
                action: r.action,
                resource_type: r.resource_type,
                resource_id: r.resource_id,
                detail: r.detail,
                created_at: r.created_at,
            })
            .collect(),
    ))
}
