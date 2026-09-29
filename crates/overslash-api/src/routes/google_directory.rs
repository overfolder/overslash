//! The org's Google Workspace Directory credential, and the "Sync now" queue.
//!
//! Admin-only throughout: the credential reads the org's whole group
//! directory, and turning it on makes Google authoritative over the directory
//! memberships of every human in the configured domains.

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use overslash_core::crypto;
use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::google_directory_config::{
    GoogleDirectoryConfigRow, GoogleDirectoryCredential, GoogleDirectorySettings,
};

use super::util::fmt_time;
use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp},
    services::{
        directory_sync::{self, email_domain},
        google_directory::{self, DirectoryClient, ServiceAccountKey},
    },
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/google-directory",
            get(get_config).put(put_config).delete(delete_config),
        )
        .route("/v1/google-directory/sync", post(request_sync))
}

#[derive(Deserialize)]
struct PutRequest {
    /// The service account's JSON key, verbatim. Required on create; on update
    /// it replaces the stored key.
    service_account_json: Option<String>,
    /// The Workspace admin the service account impersonates. Required on create.
    admin_subject: Option<String>,
    customer_id: Option<String>,
    /// Email domains whose users this source reconciles. Defaults on create to
    /// the admin's own domain.
    domains: Option<Vec<String>>,
    enabled: Option<bool>,
    sync_interval_hours: Option<i32>,
}

#[derive(Serialize)]
struct ConfigResponse {
    service_account_email: String,
    service_account_key_id: String,
    admin_subject: String,
    customer_id: String,
    domains: Vec<String>,
    enabled: bool,
    sync_interval_hours: i32,
    next_sync_at: String,
    /// A manual run is waiting for a worker.
    queued: bool,
    /// A worker holds the lease right now.
    running: bool,
    last_sync_started_at: Option<String>,
    last_sync_finished_at: Option<String>,
    last_sync_status: Option<String>,
    last_sync_error: Option<String>,
    last_sync_stats: Option<serde_json::Value>,
    /// What an admin pastes into Google's domain-wide delegation screen.
    scope: &'static str,
    created_at: String,
    updated_at: String,
}

impl From<GoogleDirectoryConfigRow> for ConfigResponse {
    fn from(row: GoogleDirectoryConfigRow) -> Self {
        let running = row.is_running(time::OffsetDateTime::now_utc());
        Self {
            service_account_email: row.service_account_email,
            service_account_key_id: row.service_account_key_id,
            admin_subject: row.admin_subject,
            customer_id: row.customer_id,
            domains: row.domains,
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
            scope: google_directory::SCOPE,
            created_at: fmt_time(row.created_at),
            updated_at: fmt_time(row.updated_at),
        }
    }
}

async fn get_config(AdminAcl(_): AdminAcl, scope: OrgScope) -> Result<Json<ConfigResponse>> {
    let row = scope
        .get_google_directory_config()
        .await?
        .ok_or_else(|| AppError::NotFound("Google Directory sync is not configured".into()))?;
    Ok(Json(row.into()))
}

/// Parse `domains` into lower-cased bare domains, rejecting anything that is
/// not one — an `@` or a space here would never match an email and would
/// silently leave every user unsynced.
fn parse_domains(domains: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::with_capacity(domains.len());
    for d in domains {
        let d = d.trim().trim_start_matches('@').to_lowercase();
        if d.is_empty() {
            continue;
        }
        if d.contains('@') || d.contains(char::is_whitespace) || !d.contains('.') {
            return Err(AppError::BadRequest(format!(
                "'{d}' is not an email domain"
            )));
        }
        if !out.contains(&d) {
            out.push(d);
        }
    }
    if out.is_empty() {
        return Err(AppError::BadRequest(
            "at least one domain is required".into(),
        ));
    }
    Ok(out)
}

fn parse_subject(subject: &str) -> Result<String> {
    let subject = subject.trim().to_lowercase();
    if email_domain(&subject).is_none() || subject.starts_with('@') {
        return Err(AppError::BadRequest(
            "admin_subject must be the email of a Workspace admin".into(),
        ));
    }
    Ok(subject)
}

fn parse_interval(hours: i32) -> Result<i32> {
    if !(1..=168).contains(&hours) {
        return Err(AppError::BadRequest(
            "sync_interval_hours must be between 1 and 168".into(),
        ));
    }
    Ok(hours)
}

/// Prove the credential works — a token, and one page of groups — so a config
/// is never saved half-working. Google's own reason goes back to the admin.
async fn probe(
    state: &AppState,
    key: &ServiceAccountKey,
    subject: &str,
    customer: &str,
) -> Result<()> {
    let client = DirectoryClient::connect(state, key, subject)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    client
        .probe(customer)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))
}

async fn put_config(
    State(state): State<AppState>,
    AdminAcl(auth): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<PutRequest>,
) -> Result<(StatusCode, Json<ConfigResponse>)> {
    let existing = scope.get_google_directory_config().await?;

    let new_key = req
        .service_account_json
        .as_deref()
        .map(ServiceAccountKey::parse)
        .transpose()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    let subject = req
        .admin_subject
        .as_deref()
        .map(parse_subject)
        .transpose()?;
    let customer = req
        .customer_id
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_string);
    let domains = req.domains.as_deref().map(parse_domains).transpose()?;
    let interval = req.sync_interval_hours.map(parse_interval).transpose()?;

    let keyring = state.config.keyring()?;

    let Some(existing) = existing else {
        // Create.
        let key = new_key
            .ok_or_else(|| AppError::BadRequest("service_account_json is required".into()))?;
        let subject =
            subject.ok_or_else(|| AppError::BadRequest("admin_subject is required".into()))?;
        let customer = customer.unwrap_or_else(|| "my_customer".into());
        let domains = match domains {
            Some(d) => d,
            None => vec![email_domain(&subject).expect("parse_subject checked the domain")],
        };
        probe(&state, &key, &subject, &customer).await?;

        let encrypted = crypto::encrypt(
            &keyring,
            req.service_account_json
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        )?;
        let row = scope
            .create_google_directory_config(
                GoogleDirectoryCredential {
                    encrypted_service_account_key: &encrypted,
                    service_account_email: &key.client_email,
                    service_account_key_id: &key.private_key_id,
                },
                &subject,
                &customer,
                &domains,
                req.enabled.unwrap_or(true),
                interval.unwrap_or(8),
            )
            .await
            .map_err(|e| match &e {
                // Two first-time saves raced past the probe; the loser gets
                // told rather than a 500.
                sqlx::Error::Database(db) if db.is_unique_violation() => AppError::Conflict(
                    "Google Directory sync was configured concurrently; reload and edit it".into(),
                ),
                _ => AppError::Database(e),
            })?;
        audit(
            &scope,
            &auth,
            &ip,
            "google_directory.configured",
            json!({
                "service_account_email": key.client_email,
                "admin_subject": subject,
                "domains": domains,
            }),
        )
        .await;
        return Ok((StatusCode::CREATED, Json(row.into())));
    };

    // Update. Re-probe whenever what the probe proves could have changed.
    if new_key.is_some() || subject.is_some() || customer.is_some() {
        let key = match &new_key {
            Some(k) => k.clone(),
            None => directory_sync::stored_key(&state, &existing)
                .map_err(|e| AppError::Internal(e.to_string()))?,
        };
        probe(
            &state,
            &key,
            subject.as_deref().unwrap_or(&existing.admin_subject),
            customer.as_deref().unwrap_or(&existing.customer_id),
        )
        .await?;
    }
    let encrypted = req
        .service_account_json
        .as_deref()
        .map(|j| crypto::encrypt(&keyring, j.as_bytes()))
        .transpose()?;
    let credential = match (&new_key, &encrypted) {
        (Some(k), Some(e)) => Some(GoogleDirectoryCredential {
            encrypted_service_account_key: e,
            service_account_email: &k.client_email,
            service_account_key_id: &k.private_key_id,
        }),
        _ => None,
    };
    let row = scope
        .update_google_directory_config(
            credential,
            GoogleDirectorySettings {
                admin_subject: subject.as_deref(),
                customer_id: customer.as_deref(),
                domains: domains.as_deref(),
                enabled: req.enabled,
                sync_interval_hours: interval,
            },
        )
        .await?
        .ok_or_else(|| AppError::NotFound("Google Directory sync is not configured".into()))?;
    audit(
        &scope,
        &auth,
        &ip,
        "google_directory.updated",
        json!({
            "key_replaced": new_key.is_some(),
            "admin_subject": row.admin_subject,
            "domains": row.domains,
            "enabled": row.enabled,
            "sync_interval_hours": row.sync_interval_hours,
        }),
    )
    .await;
    Ok((StatusCode::OK, Json(row.into())))
}

/// Delete the credential and revoke everything it reported — directory
/// groups, memberships and the mappings drawn onto them.
async fn delete_config(
    AdminAcl(auth): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
) -> Result<Json<serde_json::Value>> {
    let deleted = scope.delete_google_directory_config().await?;
    if deleted {
        audit(&scope, &auth, &ip, "google_directory.deleted", json!({})).await;
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
        .ok_or_else(|| AppError::NotFound("Google Directory sync is not configured".into()))?;
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
                    "Google Directory sync is not configured".into(),
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
