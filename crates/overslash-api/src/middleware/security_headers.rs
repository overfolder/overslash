//! Baseline security headers on every API response (CASA 4.x / 6.x).
//!
//! One middleware, mounted outermost in `create_app` (and in the test
//! harness), so every route — including 404s, CORS preflights and the MCP
//! transport — carries the same baseline. Every header is set **only when
//! the handler did not set it**, which is the override seam:
//!
//! - `Cache-Control` defaults to `no-store`: the API answers with secrets,
//!   tokens, session material and org data, and nothing it serves is meant
//!   for a shared cache. Handlers that *want* caching (`/icons/*`) set their
//!   own, and the streamed / deferred-download paths forward the upstream's
//!   `Cache-Control` verbatim, which is kept.
//! - `Content-Security-Policy` depends on what the response is. JSON, SSE
//!   and plain text get `default-src 'none'` — nothing in them should ever
//!   load or run. The few HTML pages the API renders itself (unsubscribe,
//!   connect-authorize interstitials, the upstream-OAuth landing pages) get
//!   [`HTML_CSP`], which lets their inline styles render but runs no script.
//!   A page that needs one inline script builds its response with
//!   [`html_with_inline_script`], which allows exactly that script by hash.
//!
//! Nothing here reads or rewrites a body, so streaming responses (SSE,
//! `/mcp`, `prefer_stream`, downloads) pass through untouched.

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::Next,
    response::{Html, IntoResponse, Response},
};
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// One year. Every `api.*` host (and every `<slug>.api.*` below it) is
/// served by the HTTPS load balancer or a Cloud Run domain mapping, and
/// port 80 only ever redirects, so `includeSubDomains` pins nothing that
/// still needs plain http. Browsers ignore the header over plain http, so
/// local dev on `http://localhost` is unaffected.
pub const HSTS: &str = "max-age=31536000; includeSubDomains";

/// Default for every non-HTML response.
pub const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";

/// Default for the HTML pages the API renders. Inline `style` attributes and
/// `<style>` blocks are allowed so they render; scripts are not.
/// `form-action` is deliberately absent: the connect-authorize confirm form
/// POSTs to us and we answer with a redirect to the OAuth provider, and
/// browsers apply `form-action` to that redirect's target too.
pub const HTML_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; \
                            base-uri 'none'; frame-ancestors 'none'";

/// Features no API response has any use for.
pub const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), camera=(), \
     display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), \
     magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), \
     publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), \
     xr-spatial-tracking=()";

pub async fn security_headers(req: Request<Body>, next: Next) -> Response {
    let mut res = next.run(req).await;
    apply(res.headers_mut());
    res
}

fn apply(headers: &mut HeaderMap) {
    let is_html = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            ct.trim_start()
                .get(..9)
                .is_some_and(|p| p.eq_ignore_ascii_case("text/html"))
        });
    let csp = if is_html { HTML_CSP } else { API_CSP };

    for (name, value) in [
        (header::STRICT_TRANSPORT_SECURITY, HSTS),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            header::HeaderName::from_static("permissions-policy"),
            PERMISSIONS_POLICY,
        ),
        (header::CONTENT_SECURITY_POLICY, csp),
        (header::CACHE_CONTROL, "no-store"),
    ] {
        headers
            .entry(name)
            .or_insert(HeaderValue::from_static(value));
    }
}

/// An HTML page whose `body` embeds `<script>{script}</script>` verbatim.
/// The CSP is [`HTML_CSP`] plus that one script's hash and same-origin
/// `fetch`, so nothing else — an injected tag, an `on*=` attribute — runs.
pub fn html_with_inline_script(status: StatusCode, body: String, script: &str) -> Response {
    debug_assert!(
        body.contains(&format!("<script>{script}</script>")),
        "the page must embed the hashed script byte-for-byte"
    );
    let mut res = (status, Html(body)).into_response();
    let csp = format!(
        "{HTML_CSP}; script-src '{}'; connect-src 'self'",
        script_hash(script)
    );
    res.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&csp).expect("CSP is ASCII"),
    );
    res
}

/// CSP source expression for an inline script: `sha256-<base64>`.
fn script_hash(script: &str) -> String {
    let digest = Sha256::digest(script.as_bytes());
    format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_set_headers_win() {
        let mut h = HeaderMap::new();
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=60"),
        );
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        apply(&mut h);
        assert_eq!(h[header::CACHE_CONTROL], "public, max-age=60");
        assert_eq!(h[header::CONTENT_SECURITY_POLICY], HTML_CSP);
        assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
    }

    #[test]
    fn json_gets_the_locked_down_csp() {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        apply(&mut h);
        assert_eq!(h[header::CONTENT_SECURITY_POLICY], API_CSP);
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
    }

    #[test]
    fn script_hash_matches_a_known_vector() {
        // `echo -n "alert(1)" | openssl dgst -sha256 -binary | base64`
        assert_eq!(
            script_hash("alert(1)"),
            "sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI="
        );
    }
}
