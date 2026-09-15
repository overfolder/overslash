//! The credential probe: a service instance's template-declared test action,
//! resolved and run.
//!
//! `POST /v1/services/{id}/test` exists so no caller has to know *what* the
//! probe is. The template names it (`x-overslash-test`), this module looks it
//! up, and the answer comes back as a verdict — worked, did not work, still
//! needs authenticating — rather than as a call result the caller must
//! interpret.
//!
//! Deliberately **not** a bypass. The probe goes through `call_action_impl`
//! like any other call, so the permission chain and the Layer-2 approval gate
//! both apply. In practice that is invisible for the case this was built for:
//! a freshly-created instance carries a Myself auto-grant with
//! `auto_approve_level = 'read'` and the probe is forced to `risk: read` by
//! template validation, so the owner's own probe auto-approves. A caller
//! without that reach gets an honest `pending_approval` instead of a silently
//! elevated call.
//!
//! The response carries no upstream body. "Do these credentials work" is the
//! whole question, and echoing an arbitrary response through a button that
//! anyone with instance access can press would make a disclosure surface out
//! of a diagnostic.

use axum::extract::State;
use axum::response::Response;
use serde::Serialize;
use serde_json::Value;

use overslash_core::types::ServiceDefinition;
use overslash_db::repos::service_instance::ServiceInstanceRow;
use overslash_db::scopes::OrgScope;

use super::dto::CallRequest;
use crate::AppState;
use crate::error::AppError;
use crate::extractors::{AuthContext, CallerTransport, ClientIp, ReqExt};

/// How much of an upstream error message to keep on the verdict, in bytes.
/// `truncate` snaps down to a char boundary, so the rendered string can be
/// shorter — never longer.
const ERROR_BYTES: usize = 300;

/// Cap on the envelope this reads back.
///
/// `to_bytes` *errors* past this rather than truncating, and an unreadable
/// body classifies as `failed` — so the cap can turn a healthy probe into a
/// reported failure, which is why it is far above anything a probe should
/// produce. The verbose render is uncapped (see `verbose` in [`run`]), so
/// this is the only bound on it: a read action returning more than a megabyte
/// is not a liveness check, and reporting that as "no verdict" is the honest
/// outcome.
const MAX_BODY_BYTES: usize = 1 << 20;

/// A template's declared credential probe, as clients see it.
///
/// Present on `TemplateDetail` and on every service-instance view so the
/// dashboard knows whether to render a Test button at all — the alternative
/// is fetching the whole template just to find out.
#[derive(Serialize, Debug, Clone)]
pub struct TestActionRef {
    /// Action key to call. Also what the verdict echoes back.
    pub action: String,
    /// The action's one-line `summary`, for the button's tooltip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

/// Describe a template's probe, if it declares one.
pub fn describe(def: &ServiceDefinition) -> Option<TestActionRef> {
    def.test_action().map(|(key, action)| TestActionRef {
        action: key.to_string(),
        summary: action.summary.clone(),
    })
}

/// The verdict.
#[derive(Serialize, Debug)]
pub struct ServiceTestResponse {
    /// - `ok` — the probe ran and the upstream accepted it.
    /// - `failed` — the probe ran and the upstream rejected it. `http_status`
    ///   and `error` say how.
    /// - `pending_approval` — the caller's permission chain requires a human.
    /// - `denied` — a permission rule refuses the call outright. `error`
    ///   carries the reason.
    /// - `needs_authentication` — there is no usable credential yet.
    /// - `not_supported` — the template declares no probe.
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Upstream HTTP status, when the call reached an upstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// Wall time for the whole probe, gateway included.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// The call's `action_description` — the same one-line summary the
    /// approval screen renders.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Truncated upstream error text. Never the response body of a call that
    /// succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
}

impl ServiceTestResponse {
    fn bare(status: &'static str) -> Self {
        Self {
            status,
            action: None,
            http_status: None,
            latency_ms: None,
            summary: None,
            error: None,
            approval_url: None,
            auth_url: None,
        }
    }
}

/// Run `instance`'s probe as `auth`, and classify the outcome.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    state: AppState,
    ext: axum::http::Extensions,
    auth: AuthContext,
    scope: OrgScope,
    ip: ClientIp,
    transport: CallerTransport,
    instance: &ServiceInstanceRow,
    def: &ServiceDefinition,
) -> Result<ServiceTestResponse, AppError> {
    let Some((action_key, action)) = def.test_action() else {
        return Ok(ServiceTestResponse::bare("not_supported"));
    };
    let params = action
        .test
        .as_ref()
        .map(|t| t.params.clone().into_iter().collect())
        .unwrap_or_default();

    let req = CallRequest {
        // Addressed by id, not by name: an org admin probing an instance
        // owned by someone else would miss it on the caller-shadowed name
        // lookup. `service` is still set because the metrics label and the
        // error envelopes read it.
        service: Some(instance.name.clone()),
        service_id: Some(instance.id),
        action: Some(action_key.to_string()),
        params,
        // Verbose, counter-intuitively, because the body is discarded.
        // Compact-and-truncated is the one combination `render_stored`
        // persists: past the 8 KiB compact budget it writes a `call_results`
        // row and mints a download URL. This drops the whole envelope, so
        // every probe of a chatty read action would leave behind a row and a
        // stored object nothing can ever reach. Verbose renders larger and
        // stores nothing, which is the cheaper trade when the render is read
        // for four fields and thrown away.
        verbose: Some(true),
        ..CallRequest::default()
    };

    let started = std::time::Instant::now();
    let outcome = super::call::call_action_impl(
        State(state),
        ReqExt(ext),
        auth,
        scope,
        ip,
        transport,
        axum::Json(req),
    )
    .await;
    let latency_ms = started.elapsed().as_millis() as u64;

    let response = match outcome {
        Ok(resp) => resp,
        // Two classes of error are themselves verdicts rather than failures
        // to produce one:
        //
        // - The gateway's auth errors. "There is no usable credential" is
        //   exactly what a probe is for.
        // - Failing to reach the upstream at all, whether that is a connect
        //   error (`Request`) or the budget running out (`UpstreamTimeout`).
        //   Answering 502/504 here would tell the operator the *gateway* is
        //   broken; what actually happened is that this service could not be
        //   reached, which is the question they asked. The two arrive as
        //   different variants because `http_caller::map_reqwest_timeout`
        //   folds every timeout into `CallError::Timeout` before it can
        //   become a `Request` — so matching only on `Request` would let a
        //   hung upstream escape as a 504.
        //
        // Everything else — a 400 from a malformed template, a 500 —
        // propagates, because the caller needs the real status to act on it.
        Err(AppError::Request(e)) => {
            return Ok(transport_verdict(
                action_key,
                latency_ms,
                transport_reason(&e),
            ));
        }
        Err(AppError::UpstreamTimeout { timeout_ms, .. }) => {
            return Ok(transport_verdict(
                action_key,
                latency_ms,
                format!("the service did not respond within {timeout_ms} ms"),
            ));
        }
        // The secret-bag twin of `needs_authentication`: a slot is bound to a
        // vault name that holds no value. `wrap_auth_error_as_ok` does not
        // cover it (it is a 400, not a 401), but "there is no usable
        // credential" is the same verdict, and a probe answering 400 would
        // read as a broken request rather than as the answer it asked for.
        Err(AppError::CredentialMissing { secret_name, .. }) => {
            let mut out = ServiceTestResponse::bare("needs_authentication");
            out.action = Some(action_key.to_string());
            out.latency_ms = Some(latency_ms);
            out.error = Some(truncate(
                &format!("no value stored for secret `{secret_name}`"),
                ERROR_BYTES,
            ));
            return Ok(out);
        }
        Err(err) => match super::wrap_auth_error_as_ok(&err) {
            Some(resp) => resp,
            None => return Err(err),
        },
    };

    let body = read_json_body(response).await;
    Ok(classify(action_key, latency_ms, &body))
}

/// Drain the handler's response into JSON. A body that will not parse yields
/// `Null`, which [`classify`] reports as `failed` with no detail rather than
/// as success — the safe direction for a diagnostic.
async fn read_json_body(response: Response) -> Value {
    let bytes = match axum::body::to_bytes(response.into_body(), MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            // Logged rather than swallowed: the verdict this produces
            // ("returned no verdict") is the least diagnosable one there is,
            // so the operator debugging it needs a trail.
            tracing::warn!(error = %e, "probe response body was unreadable");
            return Value::Null;
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "probe response body was not JSON");
            Value::Null
        }
    }
}

/// Turn a `CallResponse`-shaped envelope into a verdict.
///
/// Reads the envelope shallowly rather than deserializing `CallResponse`:
/// that type is `Serialize`-only (its `result` is already a rendered
/// `Value`), and the four fields wanted here are a stable part of the
/// contract this crate owns.
fn classify(action_key: &str, latency_ms: u64, body: &Value) -> ServiceTestResponse {
    let mut out = ServiceTestResponse::bare("failed");
    out.action = Some(action_key.to_string());
    out.latency_ms = Some(latency_ms);
    out.summary = body
        .get("action_description")
        .and_then(Value::as_str)
        .map(str::to_string);

    match body.get("status").and_then(Value::as_str) {
        Some("called") => {
            let result = body.get("result");
            // `status_code` in both render shapes: the verbose one is a
            // serialized `ActionResult` (whose field is `status_code`) and the
            // compact one inserts the same key explicitly.
            out.http_status = result
                .and_then(|r| r.get("status_code"))
                .and_then(Value::as_u64)
                .map(|n| n as u16);
            let is_error = body
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if is_error {
                out.error = Some(upstream_error(result, out.http_status));
            } else {
                out.status = "ok";
            }
        }
        Some("pending_approval") => {
            out.status = "pending_approval";
            out.approval_url = body
                .get("approval_url")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        Some("needs_authentication") | Some("reauth_required") => {
            out.status = "needs_authentication";
            out.auth_url = body
                .get("auth_url")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        // A Layer-2 refusal. It arrives as `Ok(403 + body)` rather than an
        // `Err`, so it reaches here rather than the propagation arm above —
        // and it is a genuine verdict anyway: the probe did not run, and the
        // reason is the thing the operator needs.
        //
        // Not integration-tested, because it is currently unreachable
        // *through this endpoint* and contorting a test into reaching it would
        // assert the contortion rather than the behaviour. Two rules combine:
        // `permission_gate` skips Layer 2 entirely for `kind == "user"`
        // ("users are gated by groups only — they are their own approvers"),
        // and `require_owner_or_admin` admits only the owner user or an admin.
        // The arm stays because `CallResponse::Denied` is a real variant of the
        // shared call path: leaving it in the catch-all below would turn a
        // gating change into a silent "the gateway returned no verdict".
        Some("denied") => {
            out.status = "denied";
            out.error = body
                .get("reason")
                .and_then(Value::as_str)
                .map(|r| truncate(r, ERROR_BYTES));
        }
        // `accepted` (a deferred call) and anything unrecognised: the probe
        // produced no verdict. Say so rather than guessing at one.
        _ => {
            out.error = Some("the gateway returned no verdict for this call".into());
        }
    }
    out
}

/// A verdict for a call that never got an answer out of the upstream.
fn transport_verdict(action_key: &str, latency_ms: u64, reason: String) -> ServiceTestResponse {
    let mut out = ServiceTestResponse::bare("failed");
    out.action = Some(action_key.to_string());
    out.latency_ms = Some(latency_ms);
    out.error = Some(truncate(&reason, ERROR_BYTES));
    out
}

/// Why the request never reached the upstream, in words an operator can act
/// on. `reqwest`'s own `Display` leads with the URL, which on this path is
/// the gateway's own composed target and reads like an internal detail.
///
/// No timeout branch: a timeout never arrives as `AppError::Request` —
/// `map_reqwest_timeout` has already turned it into `CallError::Timeout`, and
/// `AppError::UpstreamTimeout` is handled by its own arm above with the budget
/// it actually blew.
fn transport_reason(e: &reqwest::Error) -> String {
    if e.is_connect() {
        "could not connect to the service".into()
    } else {
        format!("could not reach the service: {e}")
    }
}

/// A short, human-facing rendering of an upstream failure.
fn upstream_error(result: Option<&Value>, http_status: Option<u16>) -> String {
    let body = result.and_then(|r| r.get("body"));
    let text = match body {
        Some(Value::String(s)) => s.clone(),
        Some(other) if !other.is_null() => other.to_string(),
        _ => String::new(),
    };
    if text.trim().is_empty() {
        return match http_status {
            Some(code) => format!("upstream returned HTTP {code}"),
            None => "upstream rejected the call".into(),
        };
    }
    truncate(text.trim(), ERROR_BYTES)
}

/// Truncate on a char boundary. Upstream error text is exactly the string
/// that carries non-ASCII, and `&s[..n]` panics mid-codepoint (CLAUDE.md
/// rule 5).
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let end = s.floor_char_boundary(max);
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A `called` envelope. `status_code` is the key both render shapes use —
    /// feeding `status` here instead would exercise nothing, since the
    /// envelope never carries one.
    fn called(is_error: bool, status_code: u64, body: Value) -> Value {
        json!({
            "status": "called",
            "is_error": is_error,
            "action_description": "List domains",
            "result": {"status_code": status_code, "body": body},
        })
    }

    #[test]
    fn a_clean_call_is_ok() {
        let v = classify(
            "list_domains",
            214,
            &called(false, 200, json!({"data": []})),
        );
        assert_eq!(v.status, "ok");
        assert_eq!(v.http_status, Some(200));
        assert_eq!(v.latency_ms, Some(214));
        assert_eq!(v.summary.as_deref(), Some("List domains"));
        assert!(v.error.is_none(), "a clean probe carries no error text");
    }

    /// The case the whole feature exists for: the key was pasted wrong.
    #[test]
    fn an_upstream_rejection_is_failed_with_its_message() {
        let v = classify(
            "list_domains",
            80,
            &called(true, 401, json!("{\"message\":\"API key is invalid\"}")),
        );
        assert_eq!(v.status, "failed");
        assert_eq!(v.http_status, Some(401));
        assert!(v.error.unwrap().contains("API key is invalid"));
    }

    #[test]
    fn an_empty_error_body_falls_back_to_the_status() {
        let v = classify("list_domains", 80, &called(true, 503, json!("")));
        assert_eq!(v.error.as_deref(), Some("upstream returned HTTP 503"));
    }

    /// The verbose shape serializes an `ActionResult`, whose status field is
    /// spelled the same way. Both must read.
    #[test]
    fn the_verbose_shape_reads_the_same_status_field() {
        let v = classify(
            "list_domains",
            5,
            &json!({"status": "called", "is_error": false,
                    "result": {"status_code": 204, "headers": {}, "body": "", "duration_ms": 3}}),
        );
        assert_eq!(v.status, "ok");
        assert_eq!(v.http_status, Some(204));
    }

    #[test]
    fn an_approval_is_not_a_failure() {
        let v = classify(
            "list_domains",
            12,
            &json!({"status": "pending_approval", "approval_url": "https://x.test/a/1"}),
        );
        assert_eq!(v.status, "pending_approval");
        assert_eq!(v.approval_url.as_deref(), Some("https://x.test/a/1"));
    }

    #[test]
    fn a_missing_credential_is_needs_authentication() {
        let v = classify(
            "list_domains",
            5,
            &json!({"status": "needs_authentication", "auth_url": "https://x.test/c/1"}),
        );
        assert_eq!(v.status, "needs_authentication");
        assert_eq!(v.auth_url.as_deref(), Some("https://x.test/c/1"));
    }

    /// A Layer-2 refusal comes back as `Ok(403 + body)`, not an `Err`, so it
    /// lands in `classify` rather than propagating — and the reason is the
    /// part the operator needs, so it must survive the classification.
    #[test]
    fn a_denial_keeps_its_reason() {
        let v = classify(
            "list_domains",
            7,
            &json!({"status": "denied", "reason": "deny rule on resend:*:*"}),
        );
        assert_eq!(v.status, "denied");
        assert_eq!(v.error.as_deref(), Some("deny rule on resend:*:*"));
    }

    /// An unparseable body must not read as success.
    #[test]
    fn a_shapeless_body_is_failed() {
        let v = classify("list_domains", 5, &Value::Null);
        assert_eq!(v.status, "failed");
        assert!(v.error.is_some());
    }

    #[test]
    fn a_transport_failure_is_a_verdict_not_a_gateway_error() {
        let v = transport_verdict(
            "list_domains",
            31,
            "could not connect to the service".into(),
        );
        assert_eq!(v.status, "failed");
        assert_eq!(v.action.as_deref(), Some("list_domains"));
        assert_eq!(v.latency_ms, Some(31));
        assert_eq!(v.error.as_deref(), Some("could not connect to the service"));
    }

    #[test]
    fn truncation_lands_on_a_char_boundary() {
        // Every char is 3 bytes, so a byte cap of 10 falls mid-codepoint.
        let s = "日本語日本語";
        let out = truncate(s, 10);
        assert!(out.ends_with('…'));
        assert_eq!(out.chars().count(), 4, "3 kept chars plus the ellipsis");
    }
}
