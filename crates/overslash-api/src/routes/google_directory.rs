//! The org's Google Workspace Directory connection, and the "Sync now" queue.
//!
//! There is no per-org credential. The instance has one service account
//! (`Config::google_directory`); an org's Workspace admin grants its client ID
//! domain-wide delegation in admin.google.com, then connects by signing in with
//! Google (`POST /connect`, finished in `routes::auth::google_directory_connect`).
//!
//! Admin-only throughout: connecting makes Google authoritative over the
//! directory memberships of every human in the Workspace's domain.

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::google_directory_config::{
    GoogleDirectoryConfigRow, GoogleDirectorySettings,
};

use super::util::fmt_time;
use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp, ReqExt},
    services::google_directory,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/google-directory",
            get(get_config).put(put_config).delete(delete_config),
        )
        .route("/v1/google-directory/connect", post(connect))
        .route("/v1/google-directory/sync", post(request_sync))
}

/// What a Workspace admin must add in admin.google.com, and whether this
/// instance can sync at all. Returned whether or not the org has connected,
/// because it is the first thing the setup screen shows.
#[derive(Serialize)]
struct InstanceResponse {
    /// An operator configured a service account for this instance.
    available: bool,
    /// Admin console → Security → API controls → Domain-wide delegation →
    /// "Client ID". Numeric; not a secret.
    client_id: Option<String>,
    /// The service account the client ID belongs to. For recognising it in
    /// Google Cloud, not for pasting anywhere.
    service_account_email: Option<String>,
    /// The exact "OAuth scopes" value to paste.
    scope: &'static str,
}

#[derive(Serialize)]
struct ConfigResponse {
    /// The Workspace's primary domain, as Google reported it at connect.
    domain: String,
    /// The Workspace admin the instance service account acts as — whoever
    /// signed in to connect.
    admin_subject: String,
    connected_at: String,
    enabled: bool,
    sync_interval_hours: i32,
    next_sync_at: String,
    /// A manual run is waiting for a worker. At most one can be.
    queued: bool,
    /// A worker holds the lease right now.
    running: bool,
    last_sync_started_at: Option<String>,
    last_sync_finished_at: Option<String>,
    last_sync_status: Option<String>,
    last_sync_error: Option<String>,
    last_sync_stats: Option<serde_json::Value>,
}

impl From<GoogleDirectoryConfigRow> for ConfigResponse {
    fn from(row: GoogleDirectoryConfigRow) -> Self {
        let running = row.is_running(time::OffsetDateTime::now_utc());
        Self {
            domain: row.domain,
            admin_subject: row.admin_subject,
            connected_at: fmt_time(row.connected_at),
            enabled: row.enabled,
            sync_interval_hours: row.sync_interval_hours,
            next_sync_at: fmt_time(row.next_sync_at),
            queued: row.sync_requested_at.is_some(),
            running,
            last_sync_started_at: row.last_sync_started_at.map(fmt_time),
            last_sync_finished_at: row.last_sync_finished_at.map(fmt_time),
            last_sync_status: row.last_sync_status,
            last_sync_error: row.last_sync_error,
            last_sync_stats: row.last_sync_stats,
        }
    }
}

#[derive(Serialize)]
struct GetResponse {
    instance: InstanceResponse,
    /// `null` until the org connects a Workspace.
    config: Option<ConfigResponse>,
}

fn instance(state: &AppState) -> InstanceResponse {
    let sa = state.config.google_directory.service_account.as_ref();
    InstanceResponse {
        available: sa.is_some(),
        client_id: sa.map(|k| k.client_id.clone()),
        service_account_email: sa.map(|k| k.client_email.clone()),
        scope: google_directory::SCOPE,
    }
}

async fn get_config(
    State(state): State<AppState>,
    AdminAcl(_): AdminAcl,
    scope: OrgScope,
) -> Result<Json<GetResponse>> {
    Ok(Json(GetResponse {
        instance: instance(&state),
        config: scope.get_google_directory_config().await?.map(Into::into),
    }))
}

/// Start "Sign in with Google". Returns the URL the browser should open; the
/// callback lands back on `/org/google-directory` with the outcome.
async fn connect(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(auth): AdminAcl,
    scope: OrgScope,
) -> Result<Json<serde_json::Value>> {
    // The callback binds to the browser session of whoever starts this, so it
    // has to be a signed-in human, not an API key.
    let identity_id = auth.identity_id.ok_or_else(|| {
        AppError::Forbidden("connecting Google Workspace needs a signed-in admin".into())
    })?;
    let auth_url =
        crate::routes::auth::google_directory_connect::start(&state, &ext, &scope, identity_id)
            .await?;
    Ok(Json(json!({ "auth_url": auth_url })))
}

#[derive(Deserialize)]
struct PutRequest {
    enabled: Option<bool>,
    sync_interval_hours: Option<i32>,
}

/// Change the schedule or pause. Which Workspace is connected is not editable
/// here — that only ever comes from a Google sign-in.
async fn put_config(
    AdminAcl(auth): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<PutRequest>,
) -> Result<Json<ConfigResponse>> {
    if let Some(h) = req.sync_interval_hours
        && !(1..=168).contains(&h)
    {
        return Err(AppError::BadRequest(
            "sync_interval_hours must be between 1 and 168".into(),
        ));
    }
    let row = scope
        .update_google_directory_config(GoogleDirectorySettings {
            enabled: req.enabled,
            sync_interval_hours: req.sync_interval_hours,
        })
        .await?
        .ok_or_else(|| AppError::NotFound("Google Workspace is not connected".into()))?;
    audit(
        &scope,
        &auth,
        &ip,
        "google_directory.updated",
        json!({ "enabled": row.enabled, "sync_interval_hours": row.sync_interval_hours }),
    )
    .await;
    Ok(Json(row.into()))
}

/// Disconnect: every Google-derived membership and mapping goes with it.
async fn delete_config(
    AdminAcl(auth): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
) -> Result<Json<serde_json::Value>> {
    let deleted = scope.delete_google_directory_config().await?;
    if deleted {
        audit(
            &scope,
            &auth,
            &ip,
            "google_directory.disconnected",
            json!({}),
        )
        .await;
    }
    Ok(Json(json!({ "deleted": deleted })))
}

/// Queue one manual run. A second request while one is queued changes
/// nothing and says so; a request during a run queues the one follow-up.
async fn request_sync(
    AdminAcl(auth): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let config = scope
        .get_google_directory_config()
        .await?
        .ok_or_else(|| AppError::NotFound("Google Workspace is not connected".into()))?;
    if !config.enabled {
        return Err(AppError::Conflict(
            "Google Directory sync is disabled; enable it first".into(),
        ));
    }
    if !scope.request_google_directory_sync().await? {
        // Nothing was queued: either a run already is, or the config was
        // paused (or removed) since the check above. Say which.
        match scope.get_google_directory_config().await? {
            Some(c) if c.enabled => {}
            Some(_) => {
                return Err(AppError::Conflict(
                    "Google Directory sync is disabled; enable it first".into(),
                ));
            }
            None => {
                return Err(AppError::NotFound(
                    "Google Workspace is not connected".into(),
                ));
            }
        }
        return Ok((
            StatusCode::OK,
            Json(json!({ "queued": false, "already_queued": true })),
        ));
    }
    audit(
        &scope,
        &auth,
        &ip,
        "google_directory.sync_requested",
        json!({}),
    )
    .await;
    Ok((StatusCode::ACCEPTED, Json(json!({ "queued": true }))))
}

async fn audit(
    scope: &OrgScope,
    auth: &crate::extractors::OrgAcl,
    ip: &ClientIp,
    action: &str,
    detail: serde_json::Value,
) {
    let _ = scope
        .log_audit(AuditEntry {
            org_id: scope.org_id(),
            identity_id: auth.identity_id,
            action,
            resource_type: Some("google_directory"),
            resource_id: None,
            detail,
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;
}
