//! Send-time rendering of credential templates.
//!
//! A [`CredentialTemplate`] builds one header or query-parameter value from
//! the inputs a scheme reads — `"Basic " + (.mailbox_user + ":" +
//! .mailbox_pass | @base64)` and the like, where the username is a non-secret
//! per-instance value and the password is a vault secret. Which inputs it
//! reads, and which of them are secret, was settled at template-compile time
//! (`overslash_core::credential_template`); this module only evaluates, and
//! only ever holds plaintext for the length of one call.
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

/// Build a credential value from the expression's two kinds of input:
/// `values` (slot key → plaintext secret, decrypted for this call) and `config`
/// (non-secret per-instance values, resolved from the service instance).
/// Between them they must hold every key the expression reads.
///
/// The two arrive separately because they come from different stores and get
/// different treatment everywhere else — a secret is decrypted per call and
/// never persisted, a config value is stored on the `SecretRef` in the clear.
/// jq sees one object: at this point the distinction has done its job.
///
/// The result is one string, placed into the request verbatim by
/// `inject_secrets`.
pub async fn render(
    template: &CredentialTemplate,
    scheme: &str,
    values: &BTreeMap<String, String>,
    config: &BTreeMap<String, String>,
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

    // Refuse to build a credential from an input we have no value for —
    // secret or config, the hazard is identical.
    //
    // This is not belt-and-braces: in jq, `"user" + null` is `"user"`, so a
    // missing password would quietly yield `Basic base64("user:")` — a
    // truncated credential that authenticates as nobody and looks, from every
    // downstream vantage point, like a wrong password. A missing *username* is
    // the same bug with the halves swapped. Resolution already refuses to emit
    // a half-bound scheme; this stops a template whose stored input list has
    // drifted from its expression (parts-based CRUD rebuilds a definition
    // without one) from reaching the wire.
    let read =
        overslash_core::credential_template::referenced_inputs(template).map_err(|_| failed())?;
    if read
        .iter()
        .any(|key| !values.contains_key(key) && !config.contains_key(key))
    {
        return Err(failed());
    }

    // Hand jq only the inputs the expression named, so a template that somehow
    // reached us reading more than it declared still cannot see them. A slot
    // wins a name collision — extraction rejects one, so this can only be
    // drifted stored data, and resolving it toward the vault is the reading
    // that cannot turn a secret into a public value.
    let input = serde_json::Value::Object(
        config
            .iter()
            .chain(values.iter())
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

    /// Most cases here compose secrets only; spell that out once.
    fn no_config() -> BTreeMap<String, String> {
        BTreeMap::new()
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
            &no_config(),
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
            &no_config(),
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
            &no_config(),
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
            &no_config(),
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
            &no_config(),
        )
        .await
        .unwrap();
        assert_eq!(truncated, "Basic dTo=", "base64(\"u:\")");
    }

    /// The `services/email.yaml` shape after the username stopped being a
    /// secret: same bytes on the wire, one fewer vault entry.
    #[tokio::test]
    async fn joins_a_config_value_with_a_secret() {
        let out = render(
            &jq(r#""Basic " + (.mailbox_user + ":" + .mailbox_pass | @base64)"#),
            "mailbox",
            &values(&[("mailbox_pass", "app-password")]),
            &values(&[("mailbox_user", "user@example.com")]),
        )
        .await
        .unwrap();
        assert_eq!(
            out, "Basic dXNlckBleGFtcGxlLmNvbTphcHAtcGFzc3dvcmQ=",
            "identical to the all-secrets rendering above"
        );
    }

    /// Truncation cuts both ways: a missing *username* builds
    /// `Basic base64(":pass")`, which is just as wrong and just as invisible
    /// downstream as a missing password.
    #[tokio::test]
    async fn missing_config_value_fails_instead_of_truncating() {
        let expr = jq(r#""Basic " + (.mailbox_user + ":" + .mailbox_pass | @base64)"#);
        let err = render(
            &expr,
            "mailbox",
            &values(&[("mailbox_pass", "p")]),
            &no_config(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("scheme 'mailbox'"));

        // The hazard, made real: jq would have sent this.
        let truncated = render(
            &expr,
            "mailbox",
            &values(&[("mailbox_pass", "p")]),
            &values(&[("mailbox_user", "")]),
        )
        .await
        .unwrap();
        assert_eq!(truncated, "Basic OnA=", "base64(\":p\")");
    }

    /// A config value is public, but it shares a jq expression with a secret
    /// and jq errors quote every operand. The lossy-error invariant has to hold
    /// for the mixed case too.
    #[tokio::test]
    async fn mixed_render_errors_still_leak_nothing() {
        let err = render(
            &jq(".mailbox_user + .mailbox_pass + .missing"),
            "mailbox",
            &values(&[("mailbox_pass", "hunter2-the-password")]),
            &values(&[("mailbox_user", "user@example.com")]),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(!err.contains("hunter2"), "leaked the secret: {err}");
        assert!(
            !err.contains("user@example.com"),
            "quoted an operand: {err}"
        );
    }

    #[tokio::test]
    async fn several_outputs_fail() {
        let err = render(
            &jq(".a, .b"),
            "cred",
            &values(&[("a", "1"), ("b", "2")]),
            &no_config(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("failed to build a value"));
    }

    #[tokio::test]
    async fn non_string_output_fails() {
        let err = render(
            &jq(".a | length"),
            "cred",
            &values(&[("a", "abc")]),
            &no_config(),
        )
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
            &no_config(),
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
