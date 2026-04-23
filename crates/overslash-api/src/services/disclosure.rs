//! Approval + audit detail-disclosure runner.
//!
//! Takes a [`ServiceAction`]'s declared disclosure fields (parsed from
//! `x-overslash-disclose`) and runs each jq filter against a structured
//! projection of the resolved request (built via
//! [`overslash_core::disclosure::build_jq_input`]). Returns one
//! [`DisclosedField`] per declared entry — failures are isolated per-filter
//! so one bad expression never poisons the rest of the summary.
//!
//! All filters for a given action run in a single `spawn_blocking` task:
//! each individual invocation is a microsecond-scale jq compile+eval, and
//! batching amortizes the tokio thread hop. The whole batch is wrapped in a
//! wall-clock timeout scaled by filter count.
//!
//! Validation of each `filter` expression happens at template-register time
//! via [`crate::services::response_filter::validate_syntax`] — runtime
//! errors here only surface if a filter's input shape at execute time
//! triggers a type mismatch (e.g. `.body.raw` when body is null).
//!
//! See SPEC §N "Detail disclosure" for the wire contract.

use std::time::Duration;

use overslash_core::types::DisclosureField;
use serde::Serialize;

use super::response_filter::{JqErr, cap_message, run_jq_blocking};

/// Hard ceiling on the stringified length of a single disclosed value,
/// applied on top of the per-field `max_chars` clamp. Stops a rogue filter
/// like `.body | tostring * 1000000` from blowing past the per-field limit.
const MAX_VALUE_CHARS: usize = 10 * 1024;

/// One disclosed field on the wire. Errors are carried per-field so the
/// review UI can render "Subject — (extract failed: …)" inline rather than
/// refusing to show the other fields.
#[derive(Debug, Clone, Serialize)]
pub struct DisclosedField {
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// Error raised when the whole disclosure batch fails (timeout, projection
/// too big). Individual filter errors don't bubble up to this level — they
/// land on the `error` field of the corresponding [`DisclosedField`].
#[derive(Debug, thiserror::Error)]
pub enum DisclosureError {
    #[error("disclosure batch exceeded {0}ms")]
    Timeout(u128),
    #[error("disclosure projection exceeds {0} bytes")]
    InputTooLarge(usize),
    #[error("disclosure task panicked")]
    Panicked,
}

/// Safety ceiling on the size of the projected request JSON fed to jq. The
/// 100KB `action_detail` cap on approvals is the product limit; this cap
/// is one order of magnitude higher so it only fires on runaway inputs.
const MAX_INPUT_BYTES: usize = 1024 * 1024;

/// Run every filter in `fields` against `input`, returning one
/// [`DisclosedField`] per entry in declaration order. Empty `fields` →
/// empty vec (cheap fast-path).
///
/// `per_filter_timeout` matches the per-response-filter timeout; the whole
/// batch is clamped to `min(5 × per_filter, per_filter × fields.len())`.
pub async fn run_disclosures(
    fields: &[DisclosureField],
    input: &serde_json::Value,
    per_filter_timeout: Duration,
) -> Result<Vec<DisclosedField>, DisclosureError> {
    if fields.is_empty() {
        return Ok(Vec::new());
    }

    let input_str = serde_json::to_string(input).unwrap_or_else(|_| "null".to_string());
    if input_str.len() > MAX_INPUT_BYTES {
        return Err(DisclosureError::InputTooLarge(MAX_INPUT_BYTES));
    }

    let owned: Vec<DisclosureField> = fields.to_vec();
    let join = tokio::task::spawn_blocking(move || {
        owned
            .into_iter()
            .map(|f| run_one(&f, &input_str))
            .collect::<Vec<_>>()
    });

    let batch_timeout = per_filter_timeout.saturating_mul(u32::min(fields.len() as u32, 5).max(1));
    match tokio::time::timeout(batch_timeout, join).await {
        Ok(Ok(results)) => Ok(results),
        Ok(Err(_)) => Err(DisclosureError::Panicked),
        Err(_) => Err(DisclosureError::Timeout(batch_timeout.as_millis())),
    }
}

fn run_one(field: &DisclosureField, input_str: &str) -> DisclosedField {
    match run_jq_blocking(&field.filter, input_str) {
        Ok((values, _bytes)) => {
            if values.is_empty() {
                DisclosedField {
                    label: field.label.clone(),
                    value: None,
                    error: Some("filter produced no values".into()),
                    truncated: false,
                }
            } else {
                // Disclosure filters should yield exactly one value; take the
                // first and flag `truncated` if more were emitted.
                let emitted_more = values.len() > 1;
                let first = values.into_iter().next().expect("checked non-empty");
                let rendered = stringify_value(&first);
                let (clamped, clamp_truncated) = clamp(&rendered, field.max_chars);
                DisclosedField {
                    label: field.label.clone(),
                    value: Some(clamped),
                    error: None,
                    truncated: clamp_truncated || emitted_more,
                }
            }
        }
        Err(JqErr::BodyNotJson(msg)) | Err(JqErr::RuntimeError(msg)) => DisclosedField {
            label: field.label.clone(),
            value: None,
            error: Some(cap_message(msg)),
            truncated: false,
        },
        Err(JqErr::OutputOverflow(n)) => DisclosedField {
            label: field.label.clone(),
            value: None,
            error: Some(format!("filter produced more than {n} values")),
            truncated: true,
        },
    }
}

fn stringify_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn clamp(s: &str, max_chars: Option<usize>) -> (String, bool) {
    let cap = max_chars
        .map(|n| n.min(MAX_VALUE_CHARS))
        .unwrap_or(MAX_VALUE_CHARS);
    if s.chars().count() <= cap {
        (s.to_string(), false)
    } else {
        let truncated: String = s.chars().take(cap).collect();
        (truncated, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn f(label: &str, filter: &str) -> DisclosureField {
        DisclosureField {
            label: label.into(),
            filter: filter.into(),
            max_chars: None,
        }
    }

    #[tokio::test]
    async fn plain_body_field_extraction() {
        let input = json!({
            "method": "POST",
            "url": "https://slack.com/api/chat.postMessage",
            "params": {},
            "body": {"channel": "#general", "text": "hello"}
        });
        let out = run_disclosures(
            &[f("Channel", ".body.channel"), f("Text", ".body.text")],
            &input,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(out[0].label, "Channel");
        assert_eq!(out[0].value.as_deref(), Some("#general"));
        assert!(out[0].error.is_none());
        assert_eq!(out[1].value.as_deref(), Some("hello"));
    }

    #[tokio::test]
    async fn gmail_base64url_rfc2822_roundtrip() {
        // Gmail's API takes base64url (no `+`/`/`, no `=` padding). The jq
        // engine's `@base64d` only understands standard base64, so templates
        // must normalize before decoding — these filters exercise exactly
        // that pipeline.
        let raw_mime = "To: alice@example.com\r\nSubject: Invoice Q2\r\n\r\nHello Alice,\r\n\r\nInvoice attached.";
        let encoded = base64_url_encode(raw_mime);
        let input = json!({
            "method": "POST",
            "url": "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            "params": {"userId": "me"},
            "body": {"raw": encoded}
        });
        // Shared prelude: base64url → base64 with padding, then decode.
        let prelude = r#".body.raw | gsub("-"; "+") | gsub("_"; "/") | (if (length % 4 == 2) then . + "==" elif (length % 4 == 3) then . + "=" else . end) | @base64d"#;
        let to = f(
            "To",
            &format!(r#"{prelude} | capture("(?im)^To:\\s*(?<v>[^\\r\\n]+)").v"#),
        );
        let subject = f(
            "Subject",
            &format!(r#"{prelude} | capture("(?im)^Subject:\\s*(?<v>[^\\r\\n]+)").v"#),
        );
        let body = DisclosureField {
            label: "Body".into(),
            filter: format!(r#"{prelude} | split("\r\n\r\n")[1:] | join("\r\n\r\n")"#),
            max_chars: Some(200),
        };
        let out = run_disclosures(&[to, subject, body], &input, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(out[0].error, None, "To filter errored: {:?}", out[0]);
        assert_eq!(out[0].value.as_deref(), Some("alice@example.com"));
        assert_eq!(out[1].value.as_deref(), Some("Invoice Q2"));
        assert!(out[2].value.as_ref().unwrap().contains("Hello Alice"));
    }

    #[tokio::test]
    async fn missing_field_errors_on_that_field_only() {
        let input = json!({
            "method": "POST",
            "url": "https://x",
            "params": {},
            "body": {"channel": "#general"}
        });
        // `.body.channel.nonexistent` tries to key-index a string and errors
        // at runtime (not a silent null-propagation like `.body.text`). This
        // exercises the per-field error isolation: Channel must still render.
        let out = run_disclosures(
            &[
                f("Channel", ".body.channel"),
                f("Bad", ".body.channel.nonexistent"),
            ],
            &input,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(out[0].value.as_deref(), Some("#general"));
        assert!(out[0].error.is_none());
        assert!(
            out[1].error.is_some(),
            "expected runtime error on bad indexing"
        );
    }

    #[tokio::test]
    async fn max_chars_clamps_long_string() {
        let input = json!({"body": {"text": "a".repeat(1000)}});
        let field = DisclosureField {
            label: "Text".into(),
            filter: ".body.text".into(),
            max_chars: Some(50),
        };
        let out = run_disclosures(&[field], &input, Duration::from_secs(2))
            .await
            .unwrap();
        assert!(out[0].truncated);
        assert_eq!(out[0].value.as_ref().unwrap().chars().count(), 50);
    }

    // Local base64-url encoder to avoid pulling `base64` into the API crate
    // just for a test fixture.
    fn base64_url_encode(s: &str) -> String {
        const ALPHA: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let bytes = s.as_bytes();
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0];
            let b1 = chunk.get(1).copied().unwrap_or(0);
            let b2 = chunk.get(2).copied().unwrap_or(0);
            out.push(ALPHA[(b0 >> 2) as usize] as char);
            out.push(ALPHA[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);
            if chunk.len() > 1 {
                out.push(ALPHA[((b1 & 0x0f) << 2 | b2 >> 6) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(ALPHA[(b2 & 0x3f) as usize] as char);
            }
        }
        out
    }
}
