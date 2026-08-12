//! Approval + audit detail-disclosure runner.
//!
//! Takes a [`ServiceAction`]'s declared disclosure fields (parsed from
//! `x-overslash-disclose`) and runs each jq filter against a structured
//! projection of the resolved request (built via
//! [`overslash_core::disclosure::build_jq_input`]). Returns one
//! [`DisclosedField`] per declared entry that yields a value — failures are
//! isolated per-filter so one bad expression never poisons the rest of the
//! summary. A filter that yields *zero* values (the canonical
//! `.foo // empty` idiom for an optional field) is "nothing to disclose" and
//! is omitted entirely rather than surfaced as an error.
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
//! ## Errors must never quote the input
//!
//! jq's runtime errors embed their operands, and the projection these filters
//! read is deliberately **un-redacted** — the Gmail template redacts
//! `body.raw` and discloses To/Subject/Body extracted *from* `body.raw`, so
//! extraction has to see the original. That makes a jaq message here a carrier
//! for exactly what `x-overslash-redact` exists to withhold, and it lands
//! somewhere durable: `approvals.disclosed_fields`, `audit_log.detail.disclosed`,
//! and the inline `pending_approval` envelope the calling agent reads.
//!
//! So every failure collapses to [`classify`], whose `&'static str` return type
//! is the guarantee. Nothing in this module lets a jaq message reach a
//! `DisclosedField`. Keep it that way — this is the same rule
//! [`crate::services::credential_template`] enforces over credentials, and
//! [`crate::services::response_filter`] is the deliberate exception (its
//! operand is the upstream body, which the caller already has on
//! `result.body`). See DECISIONS.md D65.
//!
//! See SPEC §N "Detail disclosure" for the wire contract.

use std::time::Duration;

use overslash_core::types::DisclosureField;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::response_filter::{JqErr, run_jq_blocking};

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
    /// Mirrors the template's `disclose[].primary` flag: the review UI renders
    /// primary fields as prominent "hero" values instead of table rows.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub primary: bool,
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

/// Absolute wall-clock ceiling for a whole disclosure batch, regardless of
/// `n_filters × per_filter_timeout`. Defends against pathological templates
/// declaring hundreds of filters without capping legitimate templates with
/// 8–10 fields (which would otherwise trip a low multiplier silently).
const MAX_BATCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Run every filter in `fields` against `input`, returning one
/// [`DisclosedField`] per entry that yields a value, in declaration order.
/// Filters yielding zero values are omitted (see [`run_one`]). Empty `fields`
/// → empty vec (cheap fast-path).
///
/// The batch wall-clock budget is `per_filter_timeout × fields.len()`,
/// clamped at `MAX_BATCH_TIMEOUT`. Scaling linearly avoids the silent
/// degradation where legitimate 6-field templates would lose the summary
/// because their expected budget was capped below `n × per_filter`.
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
            .filter_map(|f| run_one(&f, &input_str))
            .collect::<Vec<_>>()
    });

    let scaled = per_filter_timeout.saturating_mul(fields.len() as u32);
    let batch_timeout = scaled.min(MAX_BATCH_TIMEOUT);
    match tokio::time::timeout(batch_timeout, join).await {
        Ok(Ok(results)) => Ok(results),
        Ok(Err(_)) => Err(DisclosureError::Panicked),
        Err(_) => Err(DisclosureError::Timeout(batch_timeout.as_millis())),
    }
}

/// Evaluate one filter. Returns `None` when the filter yields zero values so
/// the field is omitted from the summary: a filter producing no output is the
/// author's "nothing to disclose" signal (typically `.foo // empty` for an
/// optional field), not an error worth showing the reviewer. A filter that
/// *errors* (type mismatch, overflow) still yields `Some` with `error` set so
/// the failure surfaces inline.
fn run_one(field: &DisclosureField, input_str: &str) -> Option<DisclosedField> {
    match run_jq_blocking(&field.filter, input_str) {
        Ok((values, _bytes)) => {
            if values.is_empty() {
                None
            } else {
                // Disclosure filters should yield exactly one value; take the
                // first and flag `truncated` if more were emitted.
                let emitted_more = values.len() > 1;
                let first = values.into_iter().next().expect("checked non-empty");
                let rendered = stringify_value(&first);
                let (clamped, clamp_truncated) = clamp(&rendered, field.max_chars);
                Some(DisclosedField {
                    label: field.label.clone(),
                    value: Some(clamped),
                    error: None,
                    truncated: clamp_truncated || emitted_more,
                    primary: field.primary,
                })
            }
        }
        Err(JqErr::RuntimeError(msg)) => {
            let class = classify(&msg);
            // The operator-facing half: enough to find the broken template
            // without carrying the operand. Mirrors the `expr_sha256` the
            // audit `filter` block already logs in place of filter output.
            tracing::warn!(
                label = %field.label,
                filter_sha256 = %hex::encode(Sha256::digest(field.filter.as_bytes())),
                class,
                "disclose filter failed",
            );
            Some(DisclosedField {
                label: field.label.clone(),
                value: None,
                error: Some(class.to_string()),
                truncated: false,
                primary: field.primary,
            })
        }
        // Unreachable in practice — we serialize the projection ourselves a
        // few lines up. Kept distinct so a future regression reads as itself
        // rather than as a template's bad filter.
        Err(JqErr::BodyNotJson(_)) => Some(DisclosedField {
            label: field.label.clone(),
            value: None,
            error: Some("projection is not JSON".to_string()),
            truncated: false,
            primary: field.primary,
        }),
        Err(JqErr::OutputOverflow(n)) => Some(DisclosedField {
            label: field.label.clone(),
            value: None,
            error: Some(format!("filter produced more than {n} values")),
            truncated: true,
            primary: field.primary,
        }),
    }
}

/// The only thing we may say about a jaq failure — see the module docs.
///
/// Returns `&'static str`, never a slice of `msg`: the classification is a
/// whitelist of jaq's own fixed prefixes, which in `jaq_core::Error` always
/// precede the first operand (`Error::index` builds
/// `["cannot index ", Val(l), " with ", Val(r)]`, and `math`/`typ` are the
/// same shape). Nothing operand-derived can ride out. A filter can try to
/// imitate a prefix by raising `error("cannot index …")`, but jaq renders a
/// raised string with its JSON quotes, so it never matches — and the return
/// type means a match would only ever buy a wrong hint anyway.
///
/// The class survives because it is genuinely the useful half: "your dot-path
/// indexed something that is not an object" is what shortens the round trip
/// for a template author who can no longer read the message.
fn classify(msg: &str) -> &'static str {
    if msg.starts_with("cannot index ") {
        "filter runtime error (cannot index)"
    } else if msg.starts_with("cannot calculate ") {
        "filter runtime error (cannot calculate)"
    } else if msg.starts_with("cannot use ") {
        "filter runtime error (cannot use)"
    } else {
        "filter runtime error"
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
            primary: false,
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
            primary: false,
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
        assert_eq!(
            out[1].error.as_deref(),
            Some("filter runtime error (cannot index)"),
            "expected the fixed classification on bad indexing"
        );
    }

    #[tokio::test]
    async fn empty_yielding_filter_is_omitted_not_errored() {
        // `.arguments.reply_to_id // empty` is the canonical idiom for an
        // optional field: when the argument is absent the filter yields zero
        // values. That field must be dropped from the summary entirely — not
        // rendered as "extract failed" — while sibling fields still resolve.
        let input = json!({
            "runtime": "mcp",
            "tool": "send_message",
            "arguments": {"recipient": "34619683806@s.whatsapp.net", "text": "hi"}
        });
        let out = run_disclosures(
            &[
                f("Recipient", ".arguments.recipient"),
                f("Message", ".arguments.text"),
                f("Reply to", ".arguments.reply_to_id // empty"),
            ],
            &input,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(out.len(), 2, "absent optional field should be omitted");
        assert_eq!(out[0].label, "Recipient");
        assert_eq!(out[1].label, "Message");
        assert!(out.iter().all(|f| f.error.is_none()));
    }

    /// `.resolved.x // .arguments.x` is the MCP shape's fallback idiom — the
    /// same one HTTP filters spell `.resolved.fileId // .params.fileId`. It
    /// must prefer the resolved display string and degrade to the literal
    /// argument when the resolver could not answer.
    #[tokio::test]
    async fn resolved_value_is_preferred_over_the_raw_argument() {
        let filter = f("Recipient", ".resolved.recipient // .arguments.recipient");
        let arguments = json!({"recipient": "239135323373760@lid", "text": "hi"});

        let resolved = json!({
            "runtime": "mcp",
            "tool": "send_message",
            "arguments": arguments,
            "resolved": {"recipient": "Sonia Pérez (+34600111222)"},
        });
        let out = run_disclosures(
            std::slice::from_ref(&filter),
            &resolved,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(out[0].value.as_deref(), Some("Sonia Pérez (+34600111222)"));

        // Resolution failed: `resolved` is present but empty.
        let unresolved = json!({
            "runtime": "mcp",
            "tool": "send_message",
            "arguments": arguments,
            "resolved": {},
        });
        let out = run_disclosures(&[filter], &unresolved, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(out[0].value.as_deref(), Some("239135323373760@lid"));
        assert!(out[0].error.is_none());
    }

    #[tokio::test]
    async fn empty_yielding_filter_renders_when_present() {
        // When the optional argument *is* supplied, the same filter yields the
        // value and the field appears as normal.
        let input = json!({
            "runtime": "mcp",
            "tool": "send_message",
            "arguments": {"recipient": "x@s.whatsapp.net", "text": "hi", "reply_to_id": "ABC123"}
        });
        let out = run_disclosures(
            &[f("Reply to", ".arguments.reply_to_id // empty")],
            &input,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].value.as_deref(), Some("ABC123"));
    }

    #[tokio::test]
    async fn max_chars_clamps_long_string() {
        let input = json!({"body": {"text": "a".repeat(1000)}});
        let field = DisclosureField {
            label: "Text".into(),
            filter: ".body.text".into(),
            max_chars: Some(50),
            primary: false,
        };
        let out = run_disclosures(&[field], &input, Duration::from_secs(2))
            .await
            .unwrap();
        assert!(out[0].truncated);
        assert_eq!(out[0].value.as_ref().unwrap().chars().count(), 50);
    }

    #[tokio::test]
    async fn primary_flag_flows_through_to_disclosed_field() {
        // A `disclose[]` entry marked `primary` carries that flag onto the wire
        // `DisclosedField` so the review UI can render it as a hero, while
        // unmarked siblings stay `primary: false`.
        let input = json!({
            "runtime": "mcp",
            "tool": "send_message",
            "arguments": {"recipient": "x@s.whatsapp.net", "text": "hi"}
        });
        let mut message = f("Message", ".arguments.text");
        message.primary = true;
        let out = run_disclosures(
            &[f("Recipient", ".arguments.recipient"), message],
            &input,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(out[0].label, "Recipient");
        assert!(!out[0].primary, "unmarked field must stay primary: false");
        assert_eq!(out[1].label, "Message");
        assert!(out[1].primary, "marked field must carry primary: true");
    }

    /// The property that matters most, and the reason this module exists in
    /// its current shape: disclosure reads the *un-redacted* projection, and a
    /// jaq error quotes the value it choked on. None of that may escape.
    #[tokio::test]
    async fn error_never_quotes_the_redacted_operand() {
        // `.body.api_key.last4` is what an author writes for a provider that
        // returns the key as an object. Against the plain string a caller
        // actually sent, it is a type error.
        let input = json!({
            "method": "POST",
            "url": "https://x",
            "params": {},
            "body": {"api_key": "sk_SENSITIVE_123", "channel": "#general"}
        });
        let out = run_disclosures(
            &[
                f("Channel", ".body.channel"),
                f("Key tail", ".body.api_key.last4"),
            ],
            &input,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        // Per-field isolation is unchanged: the sibling still resolves.
        assert_eq!(out[0].value.as_deref(), Some("#general"));
        assert_eq!(
            out[1].error.as_deref(),
            Some("filter runtime error (cannot index)")
        );
        assert!(out[1].value.is_none(), "a failed filter carries no value");

        // Prove the hazard is real, so this test can't be "simplified" away:
        // the engine itself would happily have named the redacted value.
        let raw = run_jq_blocking(".body.api_key.last4", &input.to_string())
            .expect_err("the filter errors");
        let msg = match raw {
            JqErr::RuntimeError(m) => m,
            _ => panic!("expected a runtime error"),
        };
        assert!(
            msg.contains("sk_SENSITIVE_123"),
            "jaq stopped quoting operands — re-check whether this guard is \
             still needed before deleting it; got: {msg}"
        );
    }

    /// A jaq error names the *enclosing* value, not the path that was
    /// addressed — so one arithmetic slip on `.body` dumps every redacted
    /// field at once, past the per-field `max_chars` clamp.
    #[tokio::test]
    async fn error_never_dumps_the_enclosing_object() {
        let input = json!({
            "method": "POST",
            "url": "https://x",
            "params": {},
            "body": {"api_key": "sk_SENSITIVE_123", "card_number": "4111111111111111"}
        });
        let field = DisclosureField {
            label: "Total".into(),
            filter: ".body + 1".into(),
            max_chars: Some(4),
            primary: false,
        };
        let out = run_disclosures(&[field], &input, Duration::from_secs(2))
            .await
            .unwrap();
        let err = out[0].error.as_deref().expect("the filter errors");
        assert_eq!(err, "filter runtime error (cannot calculate)");
        assert!(!err.contains("sk_SENSITIVE_123"), "leaked the key: {err}");
        assert!(!err.contains("4111"), "leaked the card number: {err}");
    }

    /// `classify` matches on jaq's own fixed prefixes, so the obvious attack is
    /// a filter that *raises* a message imitating one. Two things stop it, and
    /// the test pins both: a raised string is rendered by jaq with its JSON
    /// quotes, so it cannot reach the whitelist at all and falls to the generic
    /// class; and the `&'static str` return type means even a match would only
    /// buy a wrong label, never a byte of the operand.
    #[tokio::test]
    async fn a_raised_message_cannot_imitate_a_classification() {
        let input = json!({"body": {}});
        let out = run_disclosures(
            &[f("Spoof", r#"error("cannot index \"sk_LEAK\" with 1")"#)],
            &input,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let err = out[0].error.as_deref().expect("the filter errors");
        assert!(!err.contains("sk_LEAK"), "leaked through classify: {err}");
        assert_eq!(err, "filter runtime error");
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
