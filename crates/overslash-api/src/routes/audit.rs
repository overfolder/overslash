use axum::{Json, Router, extract::State, routing::get};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::repos::audit;

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
    ip_address: Option<String>,
    created_at: OffsetDateTime,
}

#[derive(serde::Deserialize)]
struct AuditQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
    action: Option<String>,
    resource_type: Option<String>,
    identity_id: Option<Uuid>,
    #[serde(default, deserialize_with = "deserialize_optional_datetime")]
    since: Option<OffsetDateTime>,
    #[serde(default, deserialize_with = "deserialize_optional_datetime")]
    until: Option<OffsetDateTime>,
}

fn default_limit() -> i64 {
    50
}

fn deserialize_optional_datetime<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<OffsetDateTime>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = <Option<String>>::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(s) => {
            let dt = OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339)
                .map_err(serde::de::Error::custom)?;
            Ok(Some(dt))
        }
    }
}

async fn query_audit(
    State(state): State<AppState>,
    auth: AuthContext,
    axum::extract::Query(params): axum::extract::Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>> {
    let filter = audit::AuditFilter {
        org_id: auth.org_id,
        action: params.action,
        resource_type: params.resource_type,
        identity_id: params.identity_id,
        since: params.since,
        until: params.until,
        limit: params.limit,
        offset: params.offset,
    };

    let rows = audit::query_filtered(&state.db, &filter).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| AuditEntry {
                id: r.id,
                identity_id: r.identity_id,
                action: r.action,
                resource_type: r.resource_type,
                resource_id: r.resource_id,
                detail: r.detail,
                ip_address: r.ip_address,
                created_at: r.created_at,
            })
            .collect(),
    ))
}
