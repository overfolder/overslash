//! `GET /v1/oauth/flows/{flow_id}`: how a connect flow ended.
//!
//! The dashboard opens a flow's gated URL in a popup and has to learn when the
//! user finished. Watching the connections list for a new id or a moved
//! `updated_at` cannot tell a reconnect from a background token refresh; the
//! flow row can, because the callback stamps the connection it produced
//! (`oauth_connection_flow::mark_finished`).

use super::*;

#[derive(Serialize)]
pub(super) struct FlowStatus {
    /// `pending` until the callback runs, then `completed` or `failed`;
    /// `expired` for a flow nobody finished in time.
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<String>,
}

/// Readable by whoever started the flow and by the user it connects for —
/// the same pair that can already see the resulting connection. Anyone else,
/// including another org, gets a 404.
pub(super) async fn get_flow_status(
    scope: UserScope,
    Path(flow_id): Path<String>,
) -> Result<Json<FlowStatus>> {
    let not_found = || AppError::NotFound("flow not found".into());
    let flow = oauth_connection_flow::completion(scope.org().db(), &flow_id)
        .await?
        .ok_or_else(not_found)?;
    let caller = scope.user_id();
    if flow.org_id != scope.org_id()
        || (flow.actor_identity_id != caller && flow.identity_id != caller)
    {
        return Err(not_found());
    }
    let status = if flow.completed_at.is_some() {
        "completed"
    } else if flow.failed_at.is_some() {
        "failed"
    } else if flow.expires_at < OffsetDateTime::now_utc() {
        "expired"
    } else {
        "pending"
    };
    Ok(Json(FlowStatus {
        status,
        connection_id: flow.connection_id,
        failure: flow.failure,
    }))
}
