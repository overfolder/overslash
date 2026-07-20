//! Send-time rendering of credential templates.
//!
//! A [`CredentialTemplate`] builds one header or query-parameter value from
//! the secrets a scheme reads — `"Basic " + (.mailbox_user + ":" +
//! .mailbox_pass | @base64)` and the like. Which secrets it reads was settled
//! at template-compile time (`overslash_core::credential_template`); this
//! module only evaluates, and only ever holds plaintext for the length of one
//! call.
//!
//! ## Errors must never quote the input
//!
//! jq's runtime errors embed their operands, and the operands here are
//! credentials. [`run_jq_blocking`] formats them with `format!("{e}")`, so
//! that text can carry a password. Nothing in this module lets a jaq error
//! message reach the caller: every failure collapses to a fixed string naming
//! the scheme. Keep it that way.

use std::collections::BTreeMap;
use std::time::Duration;

use overslash_core::types::CredentialTemplate;

use crate::error::AppError;

use super::response_filter::{JqErr, run_jq_blocking};

/// Wall-clock ceiling for one credential render. A credential expression is a
/// concat and an encode; anything slower is a runaway, not slow work. Far
/// tighter than a response filter's budget because this runs on every call.
const RENDER_TIMEOUT: Duration = Duration::from_millis(250);

/// Build a credential value. `values` maps slot key → plaintext secret and
/// must hold exactly the slots the expression reads.
///
/// The result is one string, placed into the request verbatim by
/// `inject_secrets`.
pub async fn render(
    template: &CredentialTemplate,
    scheme: &str,
    values: &BTreeMap<String, String>,
) -> Result<String, AppError> {
    let CredentialTemplate::Jq { expr } = template;

    // Deliberately lossy: every arm collapses to the same caller-visible
    // message. `failed` is the ONLY thing we may say about a jq error whose
    // operands are secrets — see the module docs.
    let failed = || {
        AppError::Internal(format!(
            "credential template for scheme '{scheme}' failed to build a value"
        ))
    };

    // Refuse to build a credential from a slot we have no value for.
    //
    // This is not belt-and-braces: in jq, `"user" + null` is `"user"`, so a
    // missing password would quietly yield `Basic base64("user:")` — a
    // truncated credential that authenticates as nobody and looks, from every
    // downstream vantage point, like a wrong password. Resolution already
    // refuses to emit a half-bound scheme; this stops a template whose stored
    // slot list has drifted from its expression (parts-based CRUD rebuilds a
    // definition without one) from reaching the wire.
    let read =
        overslash_core::credential_template::referenced_slots(template).map_err(|_| failed())?;
    if read.iter().any(|slot| !values.contains_key(slot)) {
        return Err(failed());
    }

    // Hand jq only the slots the expression named, so a template that somehow
    // reached us reading more than it declared still cannot see them.
    let input = serde_json::Value::Object(
        values
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect(),
    )
    .to_string();

    let expr = expr.clone();
    let join = tokio::task::spawn_blocking(move || run_jq_blocking(&expr, &input));

    // Every failure mode — jq error, panic, timeout — collapses to `failed()`.
    let values = match tokio::time::timeout(RENDER_TIMEOUT, join).await {
        Ok(Ok(Ok((values, _bytes)))) => values,
        Ok(Ok(Err(JqErr::OutputOverflow(_) | JqErr::RuntimeError(_) | JqErr::BodyNotJson(_)))) => {
            return Err(failed());
        }
        Ok(Err(_panicked)) => return Err(failed()),
        Err(_timed_out) => return Err(failed()),
    };

    // Exactly one string: a credential is a single header value. Several
    // outputs (`.a, .b`) or a non-string (`.a | length`) is a template bug,
    // and guessing which one to send would be worse than failing.
    match values.as_slice() {
        [serde_json::Value::String(s)] => Ok(s.clone()),
        _ => Err(failed()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jq(expr: &str) -> CredentialTemplate {
        CredentialTemplate::Jq {
            expr: expr.to_string(),
        }
    }

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn joins_two_secrets_into_basic_auth() {
        // The services/email.yaml header, end to end. Same expected string the
        // single-`user:pass`-secret path used to produce, which is what makes
        // this a pure change of where the colon comes from.
        let out = render(
            &jq(r#""Basic " + (.mailbox_user + ":" + .mailbox_pass | @base64)"#),
            "mailbox",
            &values(&[
                ("mailbox_user", "user@example.com"),
                ("mailbox_pass", "app-password"),
            ]),
        )
        .await
        .unwrap();
        assert_eq!(out, "Basic dXNlckBleGFtcGxlLmNvbTphcHAtcGFzc3dvcmQ=");
    }

    #[tokio::test]
    async fn bearer_prefix() {
        let out = render(
            &jq(r#""Bearer " + .token"#),
            "token",
            &values(&[("token", "abc123")]),
        )
        .await
        .unwrap();
        assert_eq!(out, "Bearer abc123");
    }

    #[tokio::test]
    async fn string_interpolation_form() {
        let out = render(
            &jq(r#""\(.user):\(.pass)" | @base64"#),
            "cred",
            &values(&[("user", "u"), ("pass", "p")]),
        )
        .await
        .unwrap();
        assert_eq!(out, "dTpw");
    }

    /// The nastiest failure mode this module has to prevent. In jq
    /// `"user" + null` is `"user"`, so without the presence check a missing
    /// password renders `Basic base64("user:")` — a truncated credential that
    /// is indistinguishable downstream from a wrong password.
    #[tokio::test]
    async fn missing_slot_fails_instead_of_truncating() {
        let err = render(
            &jq(r#""Basic " + (.user + ":" + .pass | @base64)"#),
            "cred",
            &values(&[("user", "u")]),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("scheme 'cred'"));

        // Prove the hazard is real, so this test can't be "simplified" away:
        // jq itself would happily have produced the truncated value.
        let truncated = render(
            &jq(r#""Basic " + (.user + ":" + .pass | @base64)"#),
            "cred",
            &values(&[("user", "u"), ("pass", "")]),
        )
        .await
        .unwrap();
        assert_eq!(truncated, "Basic dTo=", "base64(\"u:\")");
    }

    #[tokio::test]
    async fn several_outputs_fail() {
        let err = render(&jq(".a, .b"), "cred", &values(&[("a", "1"), ("b", "2")]))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("failed to build a value"));
    }

    #[tokio::test]
    async fn non_string_output_fails() {
        let err = render(&jq(".a | length"), "cred", &values(&[("a", "abc")]))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("failed to build a value"));
    }

    /// The property that matters most: a jq runtime error names the operands,
    /// and here the operands are credentials. None of that may escape.
    #[tokio::test]
    async fn errors_never_leak_the_secret() {
        // `.pass` is absent, so this is `"str" + null` — the kind of type
        // error whose jaq message quotes the other operand.
        let err = render(
            &jq(r#".user + ":" + .pass"#),
            "mailbox",
            &values(&[("user", "hunter2-the-password")]),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(!err.contains("hunter2"), "leaked the secret: {err}");
        assert!(
            err.ends_with("credential template for scheme 'mailbox' failed to build a value"),
            "got: {err}"
        );
    }
}
