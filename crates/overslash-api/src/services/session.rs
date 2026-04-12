//! Shared helpers for reading the dashboard's `oss_session` cookie off a
//! raw [`HeaderMap`].
//!
//! Several public (unauthenticated) endpoints — the enrollment-consent
//! flow and the standalone "Provide Secret" flow — want to *opportunistically*
//! know if a visitor happens to be signed in, without using a full extractor
//! like [`crate::extractors::SessionAuth`] (which rejects the request when no
//! session is present). This module is that escape hatch.

use axum::http::{HeaderMap, header};

use crate::AppState;
use crate::services::jwt;

/// Decode the `oss_session` cookie if present and valid. Returns `None` on
/// any failure (missing cookie, malformed header, bad signature, expired
/// token). The caller decides what to do with the absence — typically
/// treat it as "anonymous visitor" rather than an error.
///
/// This deliberately mirrors the same signing-key decoding fallback used
/// elsewhere (hex → raw bytes on parse failure) so callers get identical
/// behavior across routes.
pub fn extract_session(state: &AppState, headers: &HeaderMap) -> Option<jwt::Claims> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    let token = cookie_header
        .split(';')
        .find_map(|pair| pair.trim().strip_prefix("oss_session="))?;
    let signing_key = hex::decode(&state.config.signing_key)
        .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());
    jwt::verify(&signing_key, token).ok()
}
