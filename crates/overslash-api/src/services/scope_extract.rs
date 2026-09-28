//! Evaluating the `extract` jq on an action's `scope_param` entries.
//!
//! The half of scope resolution that cannot live in `overslash-core`: jq
//! *evaluation* is here, and key derivation stays there
//! (`permissions::scope_values` explains the split). This runs the pending
//! programs a [`ScopePlan`] handed over and fills the outcomes back in, so
//! `PermissionKey::from_service_action` still receives a pure value.
//!
//! Two properties hold throughout, and both matter more than usual because the
//! output is an authorization decision rather than a rendering:
//!
//! - **No operand ever escapes.** Every failure collapses to a fieldless
//!   [`ScopeExtractError`], so jaq's messages — which interleave static text
//!   with the values themselves — cannot reach a log line, an approval row or
//!   a response. Same guarantee `disclosure` gets, for the same reason (D65).
//! - **Every guard fails the entry rather than truncating it.** Keeping the
//!   first 64 of 200 recipients, or skipping the one output that came back as
//!   an object, would drop values out of the authorization set silently —
//!   which is the exact bug the extractor exists to fix, reintroduced one level
//!   down.

use std::time::Duration;

use overslash_core::permissions::{MAX_SCOPE_VALUES, ScopeExtractError, ScopePlan};

use super::response_filter::{JqErr, classify_runtime_error, run_jq_blocking};

/// Run every pending extractor in `plan`, filling each outcome back in.
///
/// `timeout` is the per-entry wall-clock budget — the same one the response
/// filter and the SQL classifier use, because this is the same evaluator on the
/// same request path.
pub async fn evaluate(plan: &mut ScopePlan, timeout: Duration) {
    let pending: Vec<(usize, String, String)> = plan
        .pending()
        .into_iter()
        .map(|(i, expr, input)| (i, expr.to_string(), input.to_string()))
        .collect();

    for (idx, expr, input) in pending {
        let outcome = run_one(expr, input, timeout).await;
        plan.fill(idx, outcome);
    }
}

async fn run_one(
    expr: String,
    input: String,
    timeout: Duration,
) -> Result<Vec<String>, ScopeExtractError> {
    let handle = tokio::task::spawn_blocking(move || run_jq_blocking(&expr, &input));
    let raw = match tokio::time::timeout(timeout, handle).await {
        Err(_) => return Err(ScopeExtractError::Timeout),
        // A panic in the evaluator is not a reason to widen a permission key.
        Ok(Err(_)) => return Err(ScopeExtractError::Runtime("panicked")),
        Ok(Ok(r)) => r,
    };
    let (values, _) = raw.map_err(|e| match e {
        JqErr::OutputOverflow(_) => ScopeExtractError::Overflow,
        // The input is this param's own value, already a `serde_json::Value`,
        // so it is JSON by construction — this arm is unreachable in practice
        // and classified rather than special-cased.
        JqErr::BodyNotJson(_) => ScopeExtractError::Runtime("input not json"),
        JqErr::RuntimeError(msg) => ScopeExtractError::Runtime(classify_runtime_error(&msg)),
    })?;

    if values.len() > MAX_SCOPE_VALUES {
        return Err(ScopeExtractError::TooManyValues);
    }

    let mut out = Vec::with_capacity(values.len());
    for v in values {
        let text = match v {
            serde_json::Value::String(s) => s,
            serde_json::Value::Number(n) => n.to_string(),
            // Not "skip this one": a scope value we cannot render is a
            // recipient we cannot gate on, and silently dropping it is worse
            // than refusing the whole extraction.
            _ => return Err(ScopeExtractError::NonScalarOutput),
        };
        if text.trim().is_empty() {
            return Err(ScopeExtractError::EmptyValue);
        }
        out.push(text);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use overslash_core::permissions::{ScopeEntry, ScopeValues};
    use overslash_core::types::{ScopeParamRef, ScopeParams};
    use serde_json::json;

    use super::*;

    const BUDGET: Duration = Duration::from_secs(2);

    fn scope(expr: &str) -> ScopeParams {
        [ScopeParamRef {
            param: "toRecipients".into(),
            label: "recipient".into(),
            extract: Some(expr.into()),
        }]
        .into_iter()
        .collect()
    }

    async fn run(expr: &str, value: serde_json::Value) -> ScopeValues {
        let params: HashMap<String, serde_json::Value> =
            HashMap::from([("toRecipients".to_string(), value)]);
        let mut plan = ScopePlan::build(&scope(expr), &params);
        evaluate(&mut plan, BUDGET).await;
        plan.finish().expect("every pending entry was filled")
    }

    #[tokio::test]
    async fn it_extracts_one_value_per_recipient() {
        // The case the whole mechanism exists for: Outlook's recipients are
        // objects, so a bare scope_param would mint a key whose value is a
        // JSON literal.
        let values = run(
            ".[] | .emailAddress.address",
            json!([
                { "emailAddress": { "address": "a@x.com", "name": "A" } },
                { "emailAddress": { "address": "b@y.com" } }
            ]),
        )
        .await;
        assert_eq!(
            values.entries()[0].1,
            ScopeEntry::Ready(vec!["a@x.com".into(), "b@y.com".into()])
        );
    }

    #[tokio::test]
    async fn a_number_renders_rather_than_failing() {
        let values = run(".[] | .id", json!([{ "id": 42 }])).await;
        assert_eq!(values.entries()[0].1, ScopeEntry::Ready(vec!["42".into()]));
    }

    #[tokio::test]
    async fn an_empty_result_is_not_a_failure() {
        // An empty recipient list is "nothing to gate on", the same reading an
        // omitted optional param gets — not "we could not tell".
        let values = run(".[] | .emailAddress.address", json!([])).await;
        assert!(!values.has_failures());
        assert_eq!(values.entries()[0].1, ScopeEntry::Ready(Vec::new()));
    }

    #[tokio::test]
    async fn a_runtime_error_fails_closed_with_no_operand() {
        let values = run(".[] | .emailAddress.address", json!("not-a-list")).await;
        let failures = values.failures();
        assert_eq!(failures.len(), 1);
        let tag = failures[0].2.tag();
        assert!(
            !tag.contains("not-a-list"),
            "the operand must never ride out on the class: {tag}"
        );
    }

    #[tokio::test]
    async fn a_non_scalar_output_fails_the_whole_entry() {
        // Skipping just the bad output would drop a recipient out of the gate.
        let values = run(
            ".[] | .emailAddress",
            json!([{ "emailAddress": { "address": "a@x.com" } }]),
        )
        .await;
        assert_eq!(values.failures()[0].2, ScopeExtractError::NonScalarOutput);
    }

    #[tokio::test]
    async fn an_empty_string_output_fails_the_entry() {
        let values = run(".[] | .address", json!([{ "address": "   " }])).await;
        assert_eq!(values.failures()[0].2, ScopeExtractError::EmptyValue);
    }

    #[tokio::test]
    async fn too_many_values_fails_rather_than_truncating() {
        let many: Vec<serde_json::Value> = (0..MAX_SCOPE_VALUES + 1)
            .map(|i| json!({ "address": format!("a{i}@x.com") }))
            .collect();
        let values = run(".[] | .address", serde_json::Value::Array(many)).await;
        assert_eq!(values.failures()[0].2, ScopeExtractError::TooManyValues);
    }

    #[tokio::test]
    async fn exactly_the_cap_still_resolves() {
        let many: Vec<serde_json::Value> = (0..MAX_SCOPE_VALUES)
            .map(|i| json!({ "address": format!("a{i}@x.com") }))
            .collect();
        let values = run(".[] | .address", serde_json::Value::Array(many)).await;
        assert!(!values.has_failures());
    }
}
