use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A secret reference for injection into an HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRef {
    pub name: String,
    pub inject_as: InjectAs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_param: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Optional transform applied to the decrypted value **before** the
    /// `prefix` is prepended. `Some(Base64)` turns a raw `user:pass` secret
    /// into `Basic <base64(user:pass)>` when paired with `prefix: "Basic "`.
    /// `None` (the default) injects the value verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encode: Option<SecretEncoding>,
}

/// How to transform a decrypted secret value before injection.
///
/// Extensible on purpose — today only `base64` (for HTTP `Basic` auth over a
/// `user:pass` secret) is defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretEncoding {
    Base64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InjectAs {
    Header,
    Query,
}

/// A raw HTTP action request (Mode A).
///
/// Credential-free by construction: live OAuth tokens are carried alongside
/// in [`ResolvedActionRequest::auth_header`], never in `headers`, so this
/// struct stays safe to persist (`approvals.replay_payload`) and to project
/// into approval/audit surfaces. Vault secrets ride as [`SecretRef`]s —
/// references only — and are resolved at send time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default)]
    pub secrets: Vec<SecretRef>,
}

/// A live credential header resolved at auth time (e.g.
/// `Authorization: Bearer <oauth token>`).
///
/// Deliberately does NOT derive `Serialize`/`Deserialize`: tokens must be
/// structurally impossible to persist or return on any API surface
/// (approvals, audit, replay payloads). The value is merged into the
/// outgoing header map only at send time.
#[derive(Debug, Clone)]
pub struct AuthHeader {
    pub name: String,
    pub value: String,
}

/// A fully resolved request: the serializable, credential-free
/// [`ActionRequest`] plus the live auth header (when the service resolved
/// OAuth). Not serializable as a whole — persistence paths must take
/// `.request`, execution paths consume both.
#[derive(Debug, Clone)]
pub struct ResolvedActionRequest {
    pub request: ActionRequest,
    pub auth_header: Option<AuthHeader>,
}

/// Result of executing an HTTP action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub duration_ms: u64,
    /// Output of the optional server-side response filter (e.g. jq) when one
    /// was attached to the request. `None` means no filter was requested.
    /// The original `body` is preserved either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filtered_body: Option<FilteredBody>,
}

/// Result of evaluating a server-side filter against the upstream response body.
///
/// `values` is always a `Vec` even for filters that emit a single result, since
/// jq is a streaming language (`.items[]` may yield N values). For the common
/// single-output case, callers read `values[0]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FilteredBody {
    Ok {
        lang: String,
        values: Vec<serde_json::Value>,
        original_bytes: usize,
        filtered_bytes: usize,
    },
    Error {
        lang: String,
        kind: FilterErrorKind,
        message: String,
        original_bytes: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterErrorKind {
    /// Upstream body wasn't valid JSON.
    BodyNotJson,
    /// Filter evaluated but errored at runtime (type mismatch, etc.).
    RuntimeError,
    /// Filter exceeded the wall-clock timeout.
    Timeout,
    /// Filter produced more values than the configured cap.
    OutputOverflow,
}
