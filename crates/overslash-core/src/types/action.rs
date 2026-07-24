use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use super::CredentialTemplate;

/// A credential to inject into an HTTP request, as *references* only.
///
/// One `SecretRef` fills one header or query parameter. Its value is either a
/// single vault secret injected verbatim, or — with a `template` — several
/// composed at send time. Either way this struct holds secret *names*: it is
/// persisted on approval replay payloads, so a plaintext value must never
/// reach it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretRef {
    /// Identity of the credential slot this fills — the securityScheme key.
    /// Also the lookup key for the finished value at injection time.
    pub name: String,
    pub inject_as: InjectAs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_param: Option<String>,
    /// Literal prepended to the value at injection — `"Bearer "` and friends.
    ///
    /// The raw-HTTP (Mode A) surface only: a caller naming a secret inline has
    /// no service template to carry a [`CredentialTemplate`], and `prefix` is
    /// part of that documented request shape. A `SecretRef` compiled from a
    /// service template expresses any prefix in its `template` instead and
    /// leaves this `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// How to build the value from several secrets, when it isn't just one
    /// secret injected verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<CredentialTemplate>,
    /// Secret slot key → vault secret name. Holds exactly the slots the
    /// template names (or the one implicit slot when there is no template),
    /// so the send path decrypts nothing it does not need.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bindings: BTreeMap<String, String>,
    /// Non-secret config key → resolved value, for the config vars the template
    /// reads. Resolved from the service instance when the ref is built.
    ///
    /// Unlike `bindings`, which names secrets and resolves them at send time,
    /// this holds the values themselves — so they are **persisted verbatim into
    /// approval payloads**. That is sound only because a config var is
    /// non-secret by declaration (`components.x-overslash-config`); never put a
    /// vaulted value here. It also means a long-pending approval replays with
    /// the value captured when the call was issued, exactly like an
    /// instance-config param pin already baked into the stored args.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, String>,

    /// Accepted and ignored. Predecessor of `template` on template-compiled
    /// refs; kept only so `ActionRequest`s persisted on approvals from before
    /// the migration still deserialise while that queue drains. Mode A never
    /// set it. See TECH_DEBT.md.
    #[serde(default, skip_serializing)]
    pub encode: Option<serde_json::Value>,
}

impl SecretRef {
    /// Every vault secret this credential needs, deduped. The seam the
    /// send-time fetch loop iterates — never the template's full slot set.
    ///
    /// With no bindings, `name` IS the vault secret name: that is the raw-HTTP
    /// (Mode A) shape, where a caller names a secret inline
    /// (`secrets: [{name, inject_as, header_name}]`) with no template behind
    /// it, and also how `ActionRequest`s persisted before credential slots
    /// read back.
    pub fn vault_names(&self) -> Vec<&str> {
        if self.bindings.is_empty() {
            return vec![self.name.as_str()];
        }
        let mut names: Vec<&str> = Vec::with_capacity(self.bindings.len());
        for n in self.bindings.values() {
            if !names.contains(&n.as_str()) {
                names.push(n.as_str());
            }
        }
        names
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InjectAs {
    #[default]
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
