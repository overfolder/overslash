//! `x-overslash-success`: judging a below-400 HTTP body as success or failure.
//!
//! Some upstreams report failure in-band. Slack answers almost every error
//! with `200 {"ok": false, "error": "channel_not_found"}`. Judged by status
//! alone, that is a success, so audit records it as one, `is_error` is false,
//! and a paged walk keeps going. An action that declares a predicate gets the
//! body judged instead. The status stays untouched, and the verdict goes on
//! [`ActionResult::body_failed`].
//!
//! The verdict is deliberately lopsided. A body that *answered* the predicate
//! with anything but `true`, or made it error at runtime, is a failure: the
//! author said what success looks like, and this body is not it. A body that is
//! not JSON, or a predicate that times out or panics, says nothing about the
//! upstream, so the call keeps the status-only verdict it would have had before
//! the key existed.

use std::time::Duration;

use overslash_core::types::ActionResult;

use super::response_filter::{JqErr, run_jq_blocking};

/// Judge `result` against `predicate` and record the verdict on it.
///
/// A no-op when there is no predicate, when the status already says failure,
/// or when the body is empty.
pub async fn judge(result: &mut ActionResult, predicate: Option<&str>, timeout: Duration) {
    let Some(predicate) = predicate else {
        return;
    };
    if result.status_code >= 400 || result.body.trim().is_empty() {
        return;
    }
    let expr = predicate.to_string();
    let body = result.body.clone();
    let join = tokio::task::spawn_blocking(move || verdict(&expr, &body));
    match tokio::time::timeout(timeout, join).await {
        Ok(Ok(Some(failed))) => result.body_failed = failed,
        Ok(Ok(None)) => {}
        Ok(Err(_)) => tracing::warn!("success predicate panicked; judging by status"),
        Err(_) => tracing::warn!(
            timeout_ms = timeout.as_millis() as u64,
            "success predicate timed out; judging by status"
        ),
    }
}

/// `Some(true)` when the body failed the predicate, `Some(false)` when it
/// passed, `None` when the body is not JSON and there is nothing to judge.
fn verdict(predicate: &str, body: &str) -> Option<bool> {
    match run_jq_blocking(predicate, body) {
        // Every value must be `true`, and there must be at least one. `empty`
        // is no statement of success.
        Ok((values, _)) => Some(values.is_empty() || values.iter().any(|v| *v != true)),
        Err(JqErr::BodyNotJson(_)) => None,
        Err(JqErr::RuntimeError(_) | JqErr::OutputOverflow(_)) => Some(true),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const SLACK: &str = ".ok == true";

    fn result(status: u16, body: &str) -> ActionResult {
        ActionResult {
            status_code: status,
            headers: HashMap::new(),
            body: body.into(),
            duration_ms: 0,
            filtered_body: None,
            wire_bytes: None,
            body_failed: false,
        }
    }

    async fn judged(status: u16, body: &str, predicate: Option<&str>) -> ActionResult {
        let mut r = result(status, body);
        judge(&mut r, predicate, Duration::from_secs(1)).await;
        r
    }

    #[tokio::test]
    async fn an_in_band_failure_is_an_upstream_error_with_its_status_intact() {
        let r = judged(
            200,
            r#"{"ok":false,"error":"channel_not_found"}"#,
            Some(SLACK),
        )
        .await;
        assert!(r.body_failed);
        assert!(r.is_upstream_error());
        assert_eq!(r.status_code, 200);
    }

    #[tokio::test]
    async fn a_passing_body_stays_a_success() {
        let r = judged(200, r#"{"ok":true,"channels":[]}"#, Some(SLACK)).await;
        assert!(!r.body_failed);
        assert!(!r.is_upstream_error());
    }

    #[tokio::test]
    async fn no_predicate_means_status_only() {
        let r = judged(200, r#"{"ok":false}"#, None).await;
        assert!(!r.is_upstream_error());
    }

    #[tokio::test]
    async fn a_body_that_is_not_json_has_nothing_to_judge() {
        let r = judged(200, "<html>ok</html>", Some(SLACK)).await;
        assert!(!r.body_failed);
    }

    #[tokio::test]
    async fn an_error_status_is_not_re_judged() {
        let r = judged(500, r#"{"ok":true}"#, Some(SLACK)).await;
        assert!(!r.body_failed);
        assert!(r.is_upstream_error());
    }

    #[tokio::test]
    async fn a_truthy_value_that_is_not_true_fails() {
        // `.ok` on a body where `ok` is a string: truthy to jq, not `true`.
        let r = judged(200, r#"{"ok":"yes"}"#, Some(".ok")).await;
        assert!(r.body_failed);
    }

    #[tokio::test]
    async fn empty_output_or_a_runtime_error_fails() {
        assert!(
            judged(200, r#"{"ok":true}"#, Some("empty"))
                .await
                .body_failed
        );
        assert!(judged(200, "[1]", Some(".ok.x")).await.body_failed);
    }

    #[test]
    fn the_unserialized_flag_is_elided_on_the_wire() {
        let wire = serde_json::to_value(result(200, "{}")).unwrap();
        assert!(wire.get("body_failed").is_none());
    }
}
