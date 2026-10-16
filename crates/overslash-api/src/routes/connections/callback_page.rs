//! Browser-facing pages for `GET /v1/oauth/callback`.
//!
//! The callback is a top-level browser navigation from the provider's consent
//! screen. Without an allow-listed `return_url` there is nowhere to send the
//! user, so a browser gets a self-contained "you're connected, close this tab"
//! page (or a friendly failure page) instead of the JSON body programmatic
//! callers still receive. Plain inline CSS, no scripts and no external assets,
//! so it renders under [`HTML_CSP`](crate::middleware::security_headers::HTML_CSP)
//! whether or not the host also serves the dashboard.

use axum::{
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
};

use crate::routes::connect_gate::html_escape;

/// Whether the caller is a browser that would rather see a page than JSON.
/// Browsers send `Accept: text/html,...` on every top-level navigation;
/// HTTP clients send `*/*` or nothing, and keep getting JSON.
pub(super) fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.to_ascii_lowercase().contains("text/html"))
}

/// The reason a flow ended without a connection, as shown on the error page.
pub(super) enum Failure<'a> {
    /// The `state` parameter is missing or names no flow (expired, consumed,
    /// or never issued).
    UnknownLink,
    /// The provider redirected back with `error=` (or no `code`). Carries the
    /// sanitized RFC 6749 code from `provider_error_code`.
    Provider(&'a str),
    /// The flow failed on our side of the callback; carries the coarse
    /// allow-listed token from `redirect_reason_token`.
    Exchange(&'a str),
}

pub(super) fn success_page(
    provider: &str,
    account_email: Option<&str>,
    bind_failed: bool,
    dashboard_url: &str,
) -> Response {
    let provider = html_escape(provider);
    let account = account_email
        .map(|e| {
            format!(
                "<p class=\"account\">Signed in as <strong>{}</strong></p>",
                html_escape(e)
            )
        })
        .unwrap_or_default();
    let bind_note = if bind_failed {
        "<p class=\"note\">The account is connected, but it couldn't be attached to the \
         service automatically. Finish setup from the Overslash dashboard.</p>"
    } else {
        ""
    };
    let body = format!(
        "<div class=\"icon ok\" aria-hidden=\"true\">{CHECK_SVG}</div>\
         <h1>Connected to {provider}</h1>\
         {account}\
         <p>You can close this tab and return to your agent or the Overslash dashboard.</p>\
         {bind_note}\
         <a class=\"link\" href=\"{dash}\">Open Overslash</a>",
        dash = html_escape(dashboard_url),
    );
    page(StatusCode::OK, &format!("Connected to {provider}"), &body)
}

pub(super) fn error_page(
    status: StatusCode,
    failure: Failure<'_>,
    provider: Option<&str>,
) -> Response {
    let provider = provider.map(html_escape);
    let named = provider.as_deref().unwrap_or("the provider");
    let (title, detail, code) = match failure {
        Failure::UnknownLink => (
            "This link has expired".to_string(),
            "It was already used, or it is too old. Start the connection again from your \
             agent or the Overslash dashboard."
                .to_string(),
            "invalid_state",
        ),
        Failure::Provider("access_denied") => (
            "Access was not granted".to_string(),
            format!(
                "Nothing was connected because access was declined on {named}'s consent screen."
            ),
            "access_denied",
        ),
        Failure::Provider(code) => (
            match &provider {
                Some(p) => format!("{p} didn't complete the sign-in"),
                None => "The sign-in didn't complete".to_string(),
            },
            format!(
                "{} returned an error, so nothing was connected.",
                capitalize(named)
            ),
            code,
        ),
        Failure::Exchange("gone") => (
            "This link has expired".to_string(),
            "Start the connection again from your agent or the Overslash dashboard.".to_string(),
            "gone",
        ),
        Failure::Exchange(code @ ("bad_request" | "upstream_error")) => (
            match &provider {
                Some(p) => format!("Couldn't connect {p}"),
                None => "Couldn't connect".to_string(),
            },
            format!(
                "{} didn't accept the sign-in. Please try connecting again.",
                capitalize(named)
            ),
            code,
        ),
        Failure::Exchange(code) => (
            "Something went wrong".to_string(),
            "The connection couldn't be completed. Please try connecting again.".to_string(),
            code,
        ),
    };
    let body = format!(
        "<div class=\"icon err\" aria-hidden=\"true\">{CROSS_SVG}</div>\
         <h1>{title}</h1>\
         <p>{detail}</p>\
         <p class=\"note\">You can close this tab.</p>\
         <p class=\"code\">Error code: <code>{code}</code></p>",
        code = html_escape(code),
    );
    page(status, &title, &body)
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

const CHECK_SVG: &str = "<svg viewBox=\"0 0 24 24\" width=\"28\" height=\"28\" fill=\"none\" \
     stroke=\"currentColor\" stroke-width=\"2.5\" stroke-linecap=\"round\" \
     stroke-linejoin=\"round\"><path d=\"M5 12.5l4.5 4.5L19 7.5\"/></svg>";

const CROSS_SVG: &str = "<svg viewBox=\"0 0 24 24\" width=\"26\" height=\"26\" fill=\"none\" \
     stroke=\"currentColor\" stroke-width=\"2.5\" stroke-linecap=\"round\"><path \
     d=\"M7 7l10 10M17 7L7 17\"/></svg>";

/// Palette mirrors `dashboard/src/lib/styles/design-tokens.css`.
const STYLE: &str = r#"
:root { --bg:#fafafa; --surface:#fff; --border:#e8e8ee; --heading:#17191c; --text:#383a42;
  --muted:#737580; --primary:#6359d9; --ok:#21b86b; --ok-bg:rgba(33,184,107,.14);
  --err:#e63836; --err-bg:rgba(230,56,54,.12); }
@media (prefers-color-scheme: dark) {
  :root { --bg:#111213; --surface:#1a1b1e; --border:#2a2b2f; --heading:#f0f1f2; --text:#d4d5d9;
    --muted:#8b8d92; --primary:#8a82f0; --ok-bg:rgba(33,184,107,.19); --err-bg:rgba(230,56,54,.19); }
}
* { box-sizing: border-box; }
html, body { margin: 0; min-height: 100%; }
body { display: flex; align-items: center; justify-content: center; min-height: 100vh;
  padding: 24px 16px; background: var(--bg); color: var(--text);
  font: 15px/1.5 Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
main { width: 100%; max-width: 420px; padding: 36px 32px 28px; text-align: center;
  background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
  box-shadow: 0 4px 24px rgba(0,0,0,.06); }
.icon { width: 56px; height: 56px; margin: 0 auto 18px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center; }
.icon.ok { background: var(--ok-bg); color: var(--ok); }
.icon.err { background: var(--err-bg); color: var(--err); }
h1 { margin: 0 0 8px; font-size: 20px; line-height: 1.3; color: var(--heading); }
p { margin: 0 0 12px; }
.account { color: var(--muted); font-size: 14px; overflow-wrap: anywhere; }
.account strong { color: var(--text); font-weight: 600; }
.note { color: var(--muted); font-size: 13px; }
.code { color: var(--muted); font-size: 12px; margin-top: 16px; }
code { font-family: 'Roboto Mono', ui-monospace, SFMono-Regular, Menlo, monospace; }
.link { display: inline-block; margin-top: 8px; color: var(--primary); font-size: 14px;
  font-weight: 500; text-decoration: none; }
.link:hover { text-decoration: underline; }
.brand { margin-top: 20px; color: var(--muted); font-size: 12px; letter-spacing: .02em; }
"#;

/// `title` and `body` are already escaped by the callers above.
fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
         <meta name=\"color-scheme\" content=\"light dark\">\n\
         <title>{title} — Overslash</title>\n<style>{STYLE}</style>\n</head>\n\
         <body><main>{body}<div class=\"brand\">Overslash</div></main></body>\n</html>\n"
    );
    (status, Html(html)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    async fn body_of(res: Response) -> String {
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn negotiates_on_accept() {
        let mut h = HeaderMap::new();
        assert!(!wants_html(&h));
        h.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        assert!(!wants_html(&h));
        h.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        assert!(!wants_html(&h));
        h.insert(
            header::ACCEPT,
            HeaderValue::from_static("text/html,application/xhtml+xml,*/*;q=0.8"),
        );
        assert!(wants_html(&h));
    }

    #[tokio::test]
    async fn success_page_escapes_interpolated_values() {
        let res = success_page(
            "<b>Git</b>",
            Some("\"><script>alert(1)</script>"),
            false,
            "https://app.example/\"x",
        );
        assert_eq!(res.status(), StatusCode::OK);
        let body = body_of(res).await;
        assert!(!body.contains("<script>"));
        assert!(!body.contains("<b>Git</b>"));
        assert!(body.contains("&lt;b&gt;Git&lt;/b&gt;"));
        assert!(body.contains("close this tab"));
    }

    #[tokio::test]
    async fn error_page_keeps_status_and_names_the_code() {
        let res = error_page(
            StatusCode::BAD_REQUEST,
            Failure::Provider("access_denied"),
            Some("GitHub"),
        );
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = body_of(res).await;
        assert!(body.contains("Access was not granted"));
        assert!(body.contains("GitHub's consent screen"));
        assert!(body.contains("<code>access_denied</code>"));
    }
}
