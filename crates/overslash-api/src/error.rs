use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use overslash_core::openapi::validate_input::ArgError;
use serde_json::json;

/// API-layer mirror of `ArgError`. Owning the wire shape here keeps the
/// core crate free of serde contracts that the API renders.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArgErrorDto {
    Missing {
        field: String,
    },
    Unknown {
        field: String,
        suggestion: Option<String>,
        expected: Vec<String>,
    },
}

impl From<ArgError> for ArgErrorDto {
    fn from(e: ArgError) -> Self {
        match e {
            ArgError::Missing { field } => Self::Missing { field },
            ArgError::Unknown {
                field,
                suggestion,
                expected,
            } => Self::Unknown {
                field,
                suggestion,
                expected,
            },
        }
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("bad gateway: {0}")]
    BadGateway(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("gone: {0}")]
    Gone(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("request error: {0}")]
    Request(#[from] reqwest::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] overslash_core::crypto::CryptoError),

    #[error("rate limit exceeded")]
    RateLimited {
        limit: u32,
        reset_at: u64,
        retry_after: u64,
    },

    #[error("response too large")]
    ResponseTooLarge {
        content_length: Option<u64>,
        content_type: Option<String>,
        limit_bytes: usize,
    },

    #[error("filter syntax error: {0}")]
    FilterSyntax(String),

    #[error("invalid action args")]
    InvalidActionArgs {
        /// All required argument names for the action, sorted.
        required: Vec<String>,
        /// All declared argument names for the action, sorted.
        allowed: Vec<String>,
        /// Per-error details (missing fields, unknown fields).
        errors: Vec<ArgErrorDto>,
        /// One-line human summary — same string `format_errors` produces.
        detail: String,
    },

    #[error("identity archived: {reason}")]
    IdentityArchived {
        identity_id: uuid::Uuid,
        reason: String,
        restorable_until: time::OffsetDateTime,
    },

    #[error("template validation failed")]
    TemplateValidationFailed {
        report: overslash_core::template_validation::ValidationReport,
    },

    #[error("{message}")]
    ServiceResolution {
        status: StatusCode,
        message: String,
        matched_template: Option<String>,
        available_instances: Vec<String>,
        hint: Option<String>,
    },

    /// The service the agent called has no live credentials yet (no
    /// connection bound, no inline secret on an auth-bearing template). The
    /// agent should hand `auth_url` to the user — clicking it walks the
    /// gated `/connect-authorize` flow and lands on the provider consent
    /// page. Returned as 401 with a structured body (`error: needs_authentication`)
    /// so the MCP layer can branch on the typed error rather than parsing
    /// a free-form string.
    ///
    /// `short` is a best-effort `oversla.sh/<slug>` redirect to `auth_url`
    /// — present only when the shortener is configured; friendlier for
    /// chat delivery where the long base62 flow id gets mangled by line
    /// wrapping. The raw upstream provider authorize URL is never surfaced.
    ///
    /// **Headless orgs** (white-label, no Overslash dashboard session): no
    /// user-facing URL is minted (`auth_url`/`short` omitted, no flow row).
    /// `headless: true` plus `provider`/`required_scopes` tell the integration
    /// to run its own OAuth dance and re-import.
    #[error("needs_authentication: {service:?}")]
    NeedsAuthentication {
        service: Option<String>,
        service_instance_id: Option<uuid::Uuid>,
        connection_id: Option<uuid::Uuid>,
        /// `None` only for headless orgs (no gated URL minted).
        auth_url: Option<String>,
        short: Option<String>,
        provider: Option<String>,
        required_scopes: Vec<String>,
        account_email: Option<String>,
        headless: bool,
    },

    /// An existing connection's access token can no longer be refreshed
    /// (revoked, expired Google testing-client refresh). Returned as 401.
    /// Two shapes by *org kind* — orthogonal to how the connection refreshes:
    ///
    /// - **Orchestrated org** (`headless = false`): `auth_url` is a freshly-minted
    ///   gated link that, on consent, updates the *same* connection in place via
    ///   the upgrade-flow callback — without that we'd orphan the broken row and
    ///   any service bound to its id.
    /// - **Headless org** (`headless = true`): a white-label org whose end users
    ///   have no Overslash session. Overslash mints no reconnect link and no
    ///   flow row, so `auth_url`/`short` are omitted; the integration re-runs its
    ///   own dance and re-imports. `provider`/`required_scopes`/`account_email`
    ///   carry the identity it must re-authorize.
    ///
    /// `short` is the chat-friendly shortened form of `auth_url`. The raw
    /// upstream provider authorize URL is never surfaced.
    #[error("reauth_required: {connection_id}")]
    ReauthRequired {
        connection_id: uuid::Uuid,
        provider: String,
        auth_url: Option<String>,
        short: Option<String>,
        reason: String,
        required_scopes: Vec<String>,
        account_email: Option<String>,
        headless: bool,
    },

    /// An OAuth connection exists but lacks one or more scopes the action
    /// declares as required. `upgrade_url` is the raw REST endpoint white-label
    /// callers can POST to; `auth_url` is the chat-deliverable gated
    /// `/connect-authorize` link that runs incremental-scope OAuth against the
    /// existing connection (preferred for agents). Returned as 403.
    ///
    /// **Headless orgs** (`headless = true`): both `auth_url`/`short` *and*
    /// `upgrade_url` are omitted — the upgrade path would mint a gated flow the
    /// org's users can't open. The integration re-imports with the wider scopes;
    /// `provider`/`account_email` name the connection's identity.
    ///
    /// `short` follows the same semantics as on [`Self::NeedsAuthentication`].
    /// `upgrade_url` (REST endpoint) is Overslash-owned; the raw upstream
    /// provider authorize URL is never surfaced.
    #[error("missing_scopes: {connection_id}")]
    MissingScopes {
        connection_id: uuid::Uuid,
        /// The full set the action requires (so the caller sees the target, not
        /// just the delta).
        required: Vec<String>,
        /// The subset not currently granted (the delta to obtain).
        missing: Vec<String>,
        /// `None` only for headless orgs (no gated upgrade flow minted).
        upgrade_url: Option<String>,
        auth_url: Option<String>,
        short: Option<String>,
        provider: Option<String>,
        account_email: Option<String>,
        headless: bool,
    },

    /// The action's template declared a required secret (an inline API key,
    /// HMAC secret, etc.) and no value is present for the calling identity.
    /// Distinct from `needs_authentication`, which is OAuth-shaped: this is
    /// the secret-bag analogue. `hint_url` (when present) points at the
    /// dashboard surface where a human can supply the value. Returned as 400.
    #[error("credential_missing: secret {secret_name} on service {service:?}")]
    CredentialMissing {
        service: Option<String>,
        secret_name: String,
        hint_url: Option<String>,
    },

    /// The caller is asking to act on an identity outside their reachable
    /// chain (e.g. a sub-agent trying to read a sibling's secrets). Distinct
    /// from `Forbidden` (which carries explicit-deny semantics): an explicit
    /// deny means "you have a path but a rule says no"; not-in-your-chain
    /// means "there is no path at all". Returned as 403.
    ///
    /// Wire shape is shipped now so slice 5 (cross-identity access control)
    /// can flip its emit sites without changing the agent-facing contract.
    #[error("not_in_your_chain: {action}")]
    NotInYourChain {
        identity_id: uuid::Uuid,
        action: String,
        reason: String,
    },
}

impl AppError {
    /// Status code this error will eventually be rendered with.
    /// Mirrors `into_response` without consuming the error — used by
    /// metrics wrappers to classify outcomes before propagation.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_)
            | Self::IdentityArchived { .. }
            | Self::MissingScopes { .. }
            | Self::NotInYourChain { .. } => StatusCode::FORBIDDEN,
            Self::BadRequest(_)
            | Self::FilterSyntax(_)
            | Self::InvalidActionArgs { .. }
            | Self::CredentialMissing { .. } => StatusCode::BAD_REQUEST,
            Self::BadGateway(_) | Self::Request(_) | Self::ResponseTooLarge { .. } => {
                StatusCode::BAD_GATEWAY
            }
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Gone(_) => StatusCode::GONE,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::TemplateValidationFailed { .. } => StatusCode::BAD_REQUEST,
            Self::ServiceResolution { status, .. } => *status,
            Self::NeedsAuthentication { .. } | Self::ReauthRequired { .. } => {
                StatusCode::UNAUTHORIZED
            }
            Self::Internal(_) | Self::Database(_) | Self::Json(_) | Self::Crypto(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let sc = self.status_code();
        if sc.as_u16() >= 400 {
            tracing::debug!(error = %self, status = sc.as_u16(), "api error");
        }
        let (status, message) = match &self {
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::BadGateway(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            Self::FilterSyntax(msg) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "filter_syntax_error",
                        "detail": msg,
                    })),
                )
                    .into_response();
            }
            Self::InvalidActionArgs {
                required,
                allowed,
                errors,
                detail,
            } => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_action_args",
                        "detail": detail,
                        "required": required,
                        "allowed": allowed,
                        "errors": errors,
                    })),
                )
                    .into_response();
            }
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            Self::Gone(msg) => (StatusCode::GONE, msg.clone()),
            Self::Internal(msg) => {
                tracing::error!("Internal error: {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
            Self::Database(e) => {
                tracing::error!("Database error: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "database error".into())
            }
            Self::Request(e) => {
                tracing::error!("Request error: {e}");
                (StatusCode::BAD_GATEWAY, "external service error".into())
            }
            Self::Json(e) => {
                tracing::error!("JSON error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "serialization error".into(),
                )
            }
            Self::Crypto(e) => {
                tracing::error!("Crypto error: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "encryption error".into())
            }
            Self::RateLimited {
                limit,
                reset_at,
                retry_after,
            } => {
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                        "error": "rate limit exceeded",
                        "retry_after": retry_after,
                    })),
                )
                    .into_response();
                let headers = response.headers_mut();
                headers.insert("Retry-After", retry_after.to_string().parse().unwrap());
                headers.insert("X-RateLimit-Limit", limit.to_string().parse().unwrap());
                headers.insert("X-RateLimit-Remaining", "0".parse().unwrap());
                headers.insert("X-RateLimit-Reset", reset_at.to_string().parse().unwrap());
                return response;
            }
            Self::ResponseTooLarge {
                content_length,
                content_type,
                limit_bytes,
            } => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "error": "response_too_large",
                        "content_length": content_length,
                        "content_type": content_type,
                        "limit_bytes": limit_bytes,
                        "hint": "retry with prefer_stream: true to stream large responses"
                    })),
                )
                    .into_response();
            }
            Self::IdentityArchived {
                identity_id,
                reason,
                restorable_until,
            } => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "identity_archived",
                        "identity_id": identity_id,
                        "reason": reason,
                        "restorable_until": restorable_until
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default(),
                        "hint": format!(
                            "POST /v1/identities/{identity_id}/restore to recover within the retention window"
                        ),
                    })),
                )
                    .into_response();
            }
            Self::TemplateValidationFailed { report } => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "validation_failed",
                        "report": report,
                    })),
                )
                    .into_response();
            }
            Self::ServiceResolution {
                status,
                message,
                matched_template,
                available_instances,
                hint,
            } => {
                let mut body = json!({ "error": message });
                if let Some(t) = matched_template {
                    body["matched_template"] = json!(t);
                }
                body["available_instances"] = json!(available_instances);
                if let Some(h) = hint {
                    body["hint"] = json!(h);
                }
                return (*status, Json(body)).into_response();
            }
            Self::NeedsAuthentication {
                service,
                service_instance_id,
                connection_id,
                auth_url,
                short,
                provider,
                required_scopes,
                account_email,
                headless,
            } => {
                let mut body = json!({
                    "error": "needs_authentication",
                });
                if let Some(s) = service {
                    body["service"] = json!(s);
                }
                if let Some(id) = service_instance_id {
                    body["service_instance_id"] = json!(id);
                }
                if let Some(id) = connection_id {
                    body["connection_id"] = json!(id);
                }
                if *headless {
                    // White-label org: no gated URL. The integration runs its
                    // own dance and re-imports, keyed by provider/scopes/email.
                    body["headless"] = json!(true);
                    if let Some(p) = provider {
                        body["provider"] = json!(p);
                    }
                    body["required_scopes"] = json!(required_scopes);
                    if let Some(e) = account_email {
                        body["account_email"] = json!(e);
                    }
                } else {
                    // `auth_url` is always present for non-headless orgs.
                    body["auth_url"] = json!(auth_url);
                    if let Some(s) = short {
                        body["short"] = json!(s);
                    }
                }
                return (StatusCode::UNAUTHORIZED, Json(body)).into_response();
            }
            Self::ReauthRequired {
                connection_id,
                provider,
                auth_url,
                short,
                reason,
                required_scopes,
                account_email,
                headless,
            } => {
                let mut body = json!({
                    "error": "reauth_required",
                    "connection_id": connection_id,
                    "provider": provider,
                    "reason": reason,
                });
                if *headless {
                    // White-label org: no Overslash reconnect link, no flow row.
                    // The integration refreshes against its own client and
                    // re-imports, keyed by provider/scopes/email.
                    body["headless"] = json!(true);
                    body["required_scopes"] = json!(required_scopes);
                    if let Some(e) = account_email {
                        body["account_email"] = json!(e);
                    }
                } else {
                    // `auth_url` is the chat-deliverable gated link (`short` its
                    // shortened form).
                    if let Some(url) = auth_url {
                        body["auth_url"] = json!(url);
                    }
                    if let Some(s) = short {
                        body["short"] = json!(s);
                    }
                }
                return (StatusCode::UNAUTHORIZED, Json(body)).into_response();
            }
            Self::MissingScopes {
                connection_id,
                required,
                missing,
                upgrade_url,
                auth_url,
                short,
                provider,
                account_email,
                headless,
            } => {
                let mut body = json!({
                    "error": "missing_scopes",
                    "required": required,
                    "missing": missing,
                    "connection_id": connection_id,
                });
                if *headless {
                    // White-label org: omit both the gated `auth_url` and the
                    // `upgrade_url` (it would mint a gated flow too). The
                    // integration re-imports with the wider scopes.
                    body["headless"] = json!(true);
                    if let Some(p) = provider {
                        body["provider"] = json!(p);
                    }
                    if let Some(e) = account_email {
                        body["account_email"] = json!(e);
                    }
                } else {
                    if let Some(url) = upgrade_url {
                        body["upgrade_url"] = json!(url);
                    }
                    if let Some(url) = auth_url {
                        body["auth_url"] = json!(url);
                    }
                    if let Some(s) = short {
                        body["short"] = json!(s);
                    }
                }
                return (StatusCode::FORBIDDEN, Json(body)).into_response();
            }
            Self::CredentialMissing {
                service,
                secret_name,
                hint_url,
            } => {
                let mut body = json!({
                    "error": "credential_missing",
                    "secret_name": secret_name,
                });
                if let Some(s) = service {
                    body["service"] = json!(s);
                }
                if let Some(url) = hint_url {
                    body["hint_url"] = json!(url);
                }
                return (StatusCode::BAD_REQUEST, Json(body)).into_response();
            }
            Self::NotInYourChain {
                identity_id,
                action,
                reason,
            } => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "not_in_your_chain",
                        "identity_id": identity_id,
                        "action": action,
                        "reason": reason,
                    })),
                )
                    .into_response();
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    //! Unit coverage for the three SPEC §5 envelope shapes added in this
    //! slice. Integration tests in `tests/mcp_typed_errors.rs` already
    //! exercise the `needs_authentication` and `reauth_required` paths
    //! end-to-end; these unit tests pin the wire shape (body keys, status
    //! codes, optional-field elision) for the variants without dedicated
    //! integration coverage so a regression in `into_response` would still
    //! be caught.

    use super::*;
    use axum::body::to_bytes;
    use uuid::Uuid;

    async fn body_json(resp: axum::response::Response) -> (StatusCode, serde_json::Value) {
        let (parts, body) = resp.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (parts.status, value)
    }

    #[tokio::test]
    async fn missing_scopes_renders_typed_envelope() {
        let conn_id = Uuid::new_v4();
        let err = AppError::MissingScopes {
            connection_id: conn_id,
            required: vec!["calendar.readonly".into(), "calendar.events".into()],
            missing: vec!["calendar.readonly".into(), "calendar.events".into()],
            upgrade_url: Some("https://api.example/v1/connections/x/upgrade_scopes".into()),
            auth_url: Some("https://api.example/connect-authorize?id=abc".into()),
            short: Some("https://oversla.sh/abc".into()),
            provider: Some("google".into()),
            account_email: None,
            headless: false,
        };
        let (status, body) = body_json(err.into_response()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "missing_scopes");
        assert!(
            body.get("headless").is_none(),
            "headless must be absent on a non-headless envelope: {body}"
        );
        assert_eq!(
            body["required"],
            json!(["calendar.readonly", "calendar.events"])
        );
        assert_eq!(body["connection_id"].as_str().unwrap(), conn_id.to_string());
        assert_eq!(
            body["missing"],
            json!(["calendar.readonly", "calendar.events"])
        );
        assert_eq!(
            body["upgrade_url"],
            "https://api.example/v1/connections/x/upgrade_scopes"
        );
        assert_eq!(
            body["auth_url"],
            "https://api.example/connect-authorize?id=abc"
        );
        assert_eq!(body["short"], "https://oversla.sh/abc");
        assert!(
            body.get("raw").is_none(),
            "raw must never be present on the envelope: {body}"
        );
    }

    #[tokio::test]
    async fn missing_scopes_omits_auth_url_when_mint_failed() {
        // Mint failure path: `auth_url: None` → key absent (not null), so
        // white-label callers can rely on `.upgrade_url` always being present
        // and `.auth_url` only when it's actually a usable URL. Same elision
        // contract applies to the optional `short` field.
        let err = AppError::MissingScopes {
            connection_id: Uuid::new_v4(),
            required: vec!["s".into()],
            missing: vec!["s".into()],
            upgrade_url: Some("https://api.example/upg".into()),
            auth_url: None,
            short: None,
            provider: Some("google".into()),
            account_email: None,
            headless: false,
        };
        let (_, body) = body_json(err.into_response()).await;
        assert!(
            body.get("auth_url").is_none(),
            "auth_url must be elided when None: {body}"
        );
        assert!(
            body.get("short").is_none(),
            "short must be elided when None: {body}"
        );
        assert!(
            body.get("raw").is_none(),
            "raw must be elided when None: {body}"
        );
    }

    #[tokio::test]
    async fn credential_missing_renders_typed_envelope() {
        let err = AppError::CredentialMissing {
            service: Some("resend".into()),
            secret_name: "RESEND_API_KEY".into(),
            hint_url: Some("https://dashboard.example/secrets?name=RESEND_API_KEY".into()),
        };
        let (status, body) = body_json(err.into_response()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "credential_missing");
        assert_eq!(body["secret_name"], "RESEND_API_KEY");
        assert_eq!(body["service"], "resend");
        assert_eq!(
            body["hint_url"],
            "https://dashboard.example/secrets?name=RESEND_API_KEY"
        );
    }

    #[tokio::test]
    async fn credential_missing_elides_optional_fields() {
        // Both `service` and `hint_url` are optional. Their absence must
        // collapse to omitted keys (not nulls) so consumers branching on
        // `body.service` aren't tripped by an explicit JSON null.
        let err = AppError::CredentialMissing {
            service: None,
            secret_name: "X".into(),
            hint_url: None,
        };
        let (_, body) = body_json(err.into_response()).await;
        assert_eq!(body["error"], "credential_missing");
        assert_eq!(body["secret_name"], "X");
        assert!(body.get("service").is_none());
        assert!(body.get("hint_url").is_none());
    }

    #[tokio::test]
    async fn not_in_your_chain_renders_typed_envelope() {
        let identity = Uuid::new_v4();
        let err = AppError::NotInYourChain {
            identity_id: identity,
            action: "github:list_repos:*".into(),
            reason: "identity is not an ancestor or descendant of caller".into(),
        };
        let (status, body) = body_json(err.into_response()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "not_in_your_chain");
        assert_eq!(body["identity_id"].as_str().unwrap(), identity.to_string());
        assert_eq!(body["action"], "github:list_repos:*");
        assert_eq!(
            body["reason"],
            "identity is not an ancestor or descendant of caller"
        );
    }

    #[test]
    fn new_variants_status_codes_match_renderers() {
        // Cheap pin: keep status_code() in sync with into_response()'s status.
        // A drift here would silently violate the contract documented in
        // docs/design/agent-self-management.md §5.
        assert_eq!(
            AppError::MissingScopes {
                connection_id: Uuid::new_v4(),
                required: vec![],
                missing: vec![],
                upgrade_url: None,
                auth_url: None,
                short: None,
                provider: None,
                account_email: None,
                headless: false,
            }
            .status_code(),
            StatusCode::FORBIDDEN,
        );
        assert_eq!(
            AppError::CredentialMissing {
                service: None,
                secret_name: String::new(),
                hint_url: None,
            }
            .status_code(),
            StatusCode::BAD_REQUEST,
        );
        assert_eq!(
            AppError::NotInYourChain {
                identity_id: Uuid::new_v4(),
                action: String::new(),
                reason: String::new(),
            }
            .status_code(),
            StatusCode::FORBIDDEN,
        );
    }
}
