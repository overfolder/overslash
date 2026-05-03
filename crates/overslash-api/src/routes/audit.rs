use std::collections::HashMap;

use axum::{Json, Router, routing::get};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditFilter;

use crate::{AppState, error::Result};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/audit", get(query_audit))
}

#[derive(Serialize)]
struct AuditEntry {
    id: Uuid,
    identity_id: Option<Uuid>,
    identity_name: Option<String>,
    /// SPIFFE-style hierarchical path of the actor identity, e.g.
    /// `spiffe://acme/user/alice/agent/henry`. Null when the chain could not
    /// be resolved (deleted identity, unknown org).
    identity_path: Option<String>,
    /// Identity ids for each `(kind, name)` unit in `identity_path`, in the
    /// same order. Excludes the org slug. Empty when `identity_path` is null.
    identity_path_ids: Vec<Uuid>,
    action: String,
    description: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<Uuid>,
    detail: serde_json::Value,
    ip_address: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    /// Set when the request was made via `X-Overslash-As` impersonation.
    impersonated_by_identity_id: Option<Uuid>,
    impersonated_by_name: Option<String>,
    /// SPIFFE-style path for the impersonator, when present. Same shape as
    /// `identity_path`.
    impersonated_by_path: Option<String>,
    impersonated_by_path_ids: Vec<Uuid>,
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
    /// Free-text substring (case-insensitive) over action, description and
    /// identity name. Drives the audit log search bar.
    q: Option<String>,
    /// Exact match on `audit_log.id`. Powers the `?event=<uuid>` deep-link
    /// — the dashboard fires this query to verify a deep-linked event exists
    /// and to render an anchor row when it falls outside the active filters.
    event_id: Option<Uuid>,
    /// Match a UUID across all relevant places: the row id, actor id,
    /// resource id, and the JSONB `detail` keys `execution_id` and
    /// `replayed_from_approval`. Powers the `uuid =` search bar key.
    uuid: Option<Uuid>,
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
    scope: OrgScope,
    axum::extract::Query(params): axum::extract::Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>> {
    let filter = AuditFilter {
        org_id: scope.org_id(),
        action: params.action,
        resource_type: params.resource_type,
        identity_id: params.identity_id,
        since: params.since,
        until: params.until,
        q: params.q.filter(|s| !s.is_empty()),
        event_id: params.event_id,
        uuid: params.uuid,
        limit: params.limit,
        offset: params.offset,
    };

    let rows = scope.query_audit_log(filter).await?;

    // Batch-resolve identity names for both actor and impersonator in one shot.
    let all_ids: Vec<Uuid> = rows
        .iter()
        .flat_map(|r| [r.identity_id, r.impersonated_by_identity_id])
        .flatten()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let name_map: HashMap<Uuid, String> = if all_ids.is_empty() {
        HashMap::new()
    } else {
        scope
            .get_identity_names_by_ids(&all_ids)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("failed to resolve identity names for audit response: {e}");
                Vec::new()
            })
            .into_iter()
            .collect()
    };

    // Resolve the SPIFFE path for each unique identity referenced on the page.
    // The page size is bounded (default 50) so per-id lookups are cheap; we
    // deduplicate to avoid repeating work when many rows share an actor.
    let mut path_map: HashMap<Uuid, (String, Vec<Uuid>)> = HashMap::new();
    for id in &all_ids {
        match crate::services::identity_path::build_for_identity(&scope, *id).await {
            Ok(Some(p)) => {
                path_map.insert(*id, p);
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("failed to build identity_path for audit identity {id}: {e}");
            }
        }
    }

    Ok(Json(
        rows.into_iter()
            .map(|r| {
                let identity_name = r.identity_id.and_then(|id| name_map.get(&id).cloned());
                let (identity_path, identity_path_ids) = r
                    .identity_id
                    .and_then(|id| path_map.get(&id).cloned())
                    .map(|(p, ids)| (Some(p), ids))
                    .unwrap_or((None, Vec::new()));
                let impersonated_by_name = r
                    .impersonated_by_identity_id
                    .and_then(|id| name_map.get(&id).cloned());
                let (impersonated_by_path, impersonated_by_path_ids) = r
                    .impersonated_by_identity_id
                    .and_then(|id| path_map.get(&id).cloned())
                    .map(|(p, ids)| (Some(p), ids))
                    .unwrap_or((None, Vec::new()));
                // Fall back to detail.description for pre-migration entries
                let description = r.description.or_else(|| {
                    r.detail
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                });
                AuditEntry {
                    id: r.id,
                    identity_id: r.identity_id,
                    identity_name,
                    identity_path,
                    identity_path_ids,
                    action: r.action,
                    description,
                    resource_type: r.resource_type,
                    resource_id: r.resource_id,
                    detail: r.detail,
                    ip_address: r.ip_address,
                    created_at: r.created_at,
                    impersonated_by_identity_id: r.impersonated_by_identity_id,
                    impersonated_by_name,
                    impersonated_by_path,
                    impersonated_by_path_ids,
                }
            })
            .collect(),
    ))
}
