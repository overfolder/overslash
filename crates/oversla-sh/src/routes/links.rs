use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;

use crate::{
    AppState,
    auth::ApiKey,
    error::{AppError, Result},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(root))
        .route("/api/links", post(create))
        .route("/{slug}", get(redirect))
}

#[derive(Deserialize)]
pub struct CreateLinkRequest {
    pub url: String,
    pub ttl_seconds: u64,
}

#[derive(Serialize)]
pub struct CreateLinkResponse {
    pub slug: String,
    pub short_url: String,
    pub expires_at: String,
}

async fn create(
    State(state): State<AppState>,
    _auth: ApiKey,
    Json(req): Json<CreateLinkRequest>,
) -> Result<(StatusCode, Json<CreateLinkResponse>)> {
    // Validate TTL bounds.
    if req.ttl_seconds < state.min_ttl_secs || req.ttl_seconds > state.max_ttl_secs {
        return Err(AppError::TtlOutOfRange {
            min: state.min_ttl_secs,
            max: state.max_ttl_secs,
            got: req.ttl_seconds,
        });
    }

    // Validate URL: must parse and must be http/https. Don't log the value —
    // approval URLs carry tokens.
    let parsed =
        Url::parse(&req.url).map_err(|e| AppError::BadRequest(format!("invalid url: {e}")))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(AppError::BadRequest(format!(
                "unsupported scheme: {other} (only http/https)"
            )));
        }
    }

    let slug = state.storage.put(&req.url, req.ttl_seconds).await?;
    tracing::info!(slug = %slug, ttl = req.ttl_seconds, "created short link");

    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(req.ttl_seconds as i64);
    let expires_at = expires_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    let short_url = format!("{}/{}", state.base_url, slug);
    Ok((
        StatusCode::CREATED,
        Json(CreateLinkResponse {
            slug,
            short_url,
            expires_at,
        }),
    ))
}

/// Root handler. 302s to `ROOT_REDIRECT_URL` if configured, otherwise 404.
/// Gives a bare `oversla.sh` visit a useful destination (marketing site,
/// product page, etc.) without coupling the shortener to any brand.
async fn root(State(state): State<AppState>) -> Result<Response> {
    match state.root_redirect_url.as_deref() {
        Some(target) => Ok((
            StatusCode::FOUND,
            [(header::LOCATION, target.to_string())],
            [(header::CACHE_CONTROL, "no-store, max-age=0")],
        )
            .into_response()),
        None => Err(AppError::NotFound),
    }
}

async fn redirect(State(state): State<AppState>, Path(slug): Path<String>) -> Result<Response> {
    match state.storage.get(&slug).await? {
        Some(target) => Ok((
            StatusCode::FOUND,
            [(header::LOCATION, target)],
            // Cache-Control: prevent intermediaries from caching a short link
            // whose TTL can be as low as MIN_TTL_SECS.
            [(header::CACHE_CONTROL, "no-store, max-age=0")],
        )
            .into_response()),
        None => Err(AppError::NotFound),
    }
}
