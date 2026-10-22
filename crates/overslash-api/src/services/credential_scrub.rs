//! Strip injected credentials out of what an upstream sends back.
//!
//! Upstreams echo requests in their errors — `"invalid api key sk-…"`, a
//! 400 that repeats the query string carrying `?api_key=`, a debug endpoint
//! that reflects `Authorization`. A buffered response body reaches both the
//! calling agent and, when the org captures bodies (D18), the audit log, so
//! an echoed credential would leave the vault through either. The values we
//! injected are known exactly at send time, so this matches them literally
//! (plus the encodings an echo is likely to use) rather than guessing at
//! what looks like a secret.
//!
//! Streamed bodies never pass through here: they are not buffered, which is
//! also why they are never captured for audit.
//!
//! See D127 in DECISIONS.md.

use std::collections::HashMap;

use base64::Engine as _;
use overslash_core::types::{ActionResult, AuthHeader};
use serde_json::Value;

/// What a redacted credential reads as.
pub const REDACTED: &str = "[REDACTED]";

/// Needles shorter than this are dropped: replacing a 4-character value
/// would shred unrelated text, and nothing that short is a real credential.
const MIN_NEEDLE_LEN: usize = 8;

/// The literal values one call injected, ready to be removed from its reply.
#[derive(Debug, Default)]
pub struct CredentialScrubber {
    /// Longest first, so a value is replaced before any needle it contains.
    needles: Vec<String>,
}

impl CredentialScrubber {
    /// From the HTTP path's injection inputs: the finished value of every
    /// vault credential (`resolve_credential_values`) and the live OAuth
    /// header merged at send time.
    pub fn injected(values: &HashMap<String, String>, auth_header: Option<&AuthHeader>) -> Self {
        Self::from_values(
            values
                .values()
                .map(String::as_str)
                .chain(auth_header.map(|h| h.value.as_str())),
        )
    }

    /// From the MCP path's outgoing headers, every one of which is a
    /// credential (`mcp_caller::build_client` sets nothing else).
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> Self {
        Self::from_values(headers.values().filter_map(|v| v.to_str().ok()))
    }

    fn from_values<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
        let mut needles = Vec::new();
        for v in values {
            push_variants(&mut needles, v);
        }
        // An empty needle would match between every character.
        needles.retain(|n| !n.is_empty());
        needles.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        needles.dedup();
        Self { needles }
    }

    pub fn is_empty(&self) -> bool {
        self.needles.is_empty()
    }

    /// `s` with every injected value replaced, or `None` if none occurred.
    pub fn scrub_str(&self, s: &str) -> Option<String> {
        let mut out: Option<String> = None;
        for n in &self.needles {
            let cur = out.as_deref().unwrap_or(s);
            if cur.contains(n.as_str()) {
                out = Some(cur.replace(n.as_str(), REDACTED));
            }
        }
        out
    }

    /// Scrub a buffered upstream response — body and header values — in
    /// place, before any filter, render or audit capture reads it.
    pub fn scrub_result(&self, mut result: ActionResult) -> ActionResult {
        if self.is_empty() {
            return result;
        }
        let mut hit = false;
        if let Some(body) = self.scrub_str(&result.body) {
            result.body = body;
            hit = true;
        }
        for v in result.headers.values_mut() {
            if let Some(scrubbed) = self.scrub_str(v) {
                *v = scrubbed;
                hit = true;
            }
        }
        if hit {
            tracing::warn!(
                status = result.status_code,
                "upstream response echoed an injected credential; redacted"
            );
        }
        result
    }

    /// Scrub every string inside a JSON value. Used where the reply is
    /// already parsed, so a replacement can never break its structure.
    pub fn scrub_json(&self, v: &mut Value) -> bool {
        if self.is_empty() {
            return false;
        }
        match v {
            Value::String(s) => match self.scrub_str(s) {
                Some(scrubbed) => {
                    *s = scrubbed;
                    true
                }
                None => false,
            },
            Value::Array(items) => items
                .iter_mut()
                .fold(false, |hit, item| self.scrub_json(item) | hit),
            Value::Object(map) => map
                .values_mut()
                .fold(false, |hit, item| self.scrub_json(item) | hit),
            _ => false,
        }
    }
}

/// The value as injected, plus the forms an upstream is likely to echo it
/// in: without its auth scheme (`Bearer x` → `x`), the decoded password of a
/// `Basic` credential, URL-encoded (query-string echoes) and JSON-escaped
/// (an echo inside a JSON error body).
fn push_variants(out: &mut Vec<String>, value: &str) {
    let value = value.trim();
    let mut forms = vec![value.to_string()];
    if let Some((scheme, rest)) = value.split_once(' ') {
        let rest = rest.trim();
        forms.push(rest.to_string());
        if scheme.eq_ignore_ascii_case("basic")
            && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(rest)
            && let Ok(decoded) = String::from_utf8(bytes)
            && let Some((_user, pass)) = decoded.split_once(':')
        {
            forms.push(pass.to_string());
        }
    }
    // The floor applies to the credential itself, not to an encoding of it
    // that merely came out longer (`ab cd` → `ab%20cd`).
    for f in forms.into_iter().filter(|f| f.len() >= MIN_NEEDLE_LEN) {
        let url = urlencoding::encode(&f).into_owned();
        let json = serde_json::to_string(&f).unwrap_or_default();
        let json = json
            .strip_prefix('"')
            .and_then(|j| j.strip_suffix('"'))
            .unwrap_or_default()
            .to_string();
        out.push(url);
        out.push(json);
        out.push(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scrubber(values: &[&str]) -> CredentialScrubber {
        CredentialScrubber::from_values(values.iter().copied())
    }

    #[test]
    fn redacts_plain_value() {
        let s = scrubber(&["sk_live_abcdef123456"]);
        assert_eq!(
            s.scrub_str(r#"{"error":"invalid key sk_live_abcdef123456"}"#)
                .as_deref(),
            Some(r#"{"error":"invalid key [REDACTED]"}"#)
        );
    }

    #[test]
    fn untouched_body_returns_none() {
        assert!(
            scrubber(&["sk_live_abcdef123456"])
                .scrub_str("all good")
                .is_none()
        );
    }

    #[test]
    fn redacts_token_without_its_scheme() {
        let s = scrubber(&["Bearer ya29.tokenvalue"]);
        assert_eq!(
            s.scrub_str("bad token: ya29.tokenvalue").as_deref(),
            Some("bad token: [REDACTED]")
        );
    }

    #[test]
    fn redacts_basic_password_and_encoded_form() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("alice:hunter2hunter2");
        let s = scrubber(&[&format!("Basic {encoded}")]);
        let body = format!("auth {encoded} failed for password hunter2hunter2");
        assert_eq!(
            s.scrub_str(&body).as_deref(),
            Some("auth [REDACTED] failed for password [REDACTED]")
        );
    }

    #[test]
    fn redacts_url_encoded_echo() {
        let s = scrubber(&["key+with/slash=="]);
        assert_eq!(
            s.scrub_str("GET /v1?api_key=key%2Bwith%2Fslash%3D%3D rejected")
                .as_deref(),
            Some("GET /v1?api_key=[REDACTED] rejected")
        );
    }

    #[test]
    fn redacts_json_escaped_echo() {
        let s = scrubber(&[r#"pa"ss\word12"#]);
        let body = serde_json::json!({ "echo": r#"pa"ss\word12"# }).to_string();
        assert_eq!(
            s.scrub_str(&body).as_deref(),
            Some(r#"{"echo":"[REDACTED]"}"#)
        );
    }

    #[test]
    fn short_values_are_ignored() {
        let s = scrubber(&["abc", "Token x"]);
        assert!(s.is_empty());
        assert!(s.scrub_str("abc x").is_none());
    }

    #[test]
    fn scrub_result_covers_body_and_headers() {
        let s = scrubber(&["secret-token-123"]);
        let result = ActionResult {
            status_code: 400,
            headers: HashMap::from([("x-echo".into(), "secret-token-123".into())]),
            body: "token secret-token-123 rejected".into(),
            duration_ms: 1,
            filtered_body: None,
            wire_bytes: None,
            body_failed: false,
        };
        let out = s.scrub_result(result);
        assert_eq!(out.body, "token [REDACTED] rejected");
        assert_eq!(out.headers["x-echo"], REDACTED);
    }

    #[test]
    fn scrub_json_walks_nested_strings() {
        let s = scrubber(&["secret-token-123"]);
        let mut v = serde_json::json!({
            "content": [{ "type": "text", "text": "echo secret-token-123" }],
            "n": 1,
        });
        assert!(s.scrub_json(&mut v));
        assert_eq!(v["content"][0]["text"], "echo [REDACTED]");
        assert_eq!(v["n"], 1);
    }
}
