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

/// Build a `response_too_large` in each of the three states its hint
/// distinguishes.
fn too_large(offer_prefer_stream: bool, minted: bool) -> AppError {
    AppError::ResponseTooLarge {
        content_length: Some(31_457_280),
        content_type: Some("application/json".into()),
        limit_bytes: 5_242_880,
        offer_prefer_stream,
        download_url: minted.then(|| "https://api.example/v1/downloads/tok".to_string()),
        expires_at: minted.then(|| "2026-08-11T12:15:00Z".to_string()),
    }
}

/// The one rule behind all three hint forms: never name a recovery the
/// caller cannot use. Unit-tested here because the wording is a pure
/// function of the variant — reaching all three end-to-end would need an
/// OAuth service just to make a mint refuse.
#[tokio::test]
async fn response_too_large_names_only_reachable_recoveries() {
    // 1. Minted — the retry is already done, so neither flag is named.
    let (status, body) = body_json(too_large(true, true).into_response()).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"], "response_too_large");
    assert_eq!(body["download_url"], "https://api.example/v1/downloads/tok");
    assert_eq!(body["expires_at"], "2026-08-11T12:15:00Z");
    let hint = body["hint"].as_str().unwrap();
    assert!(hint.contains("download_url"), "{hint}");
    assert!(
        !hint.contains("deliver") && !hint.contains("prefer_stream"),
        "a minted URL supersedes both flags — naming either is the wasted \
         round trip this hint exists to prevent: {hint}"
    );

    // 2. Not minted, REST — both flags, `deliver` leading.
    let (_, body) = body_json(too_large(true, false).into_response()).await;
    assert!(body["download_url"].is_null());
    let hint = body["hint"].as_str().unwrap();
    let deliver_at = hint.find("deliver").expect("names deliver");
    let stream_at = hint.find("prefer_stream").expect("names prefer_stream");
    assert!(deliver_at < stream_at, "deliver should lead: {hint}");

    // 3. Not minted, MCP — `deliver` only. `prefer_stream` is absent from
    //    the tool schemas, so naming it sends the agent down a dead end.
    let (_, body) = body_json(too_large(false, false).into_response()).await;
    let hint = body["hint"].as_str().unwrap();
    assert!(hint.contains("deliver"), "{hint}");
    assert!(!hint.contains("prefer_stream"), "{hint}");
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

/// The secret-backed `needs_authentication` shape: no consent link, but a
/// named field list and a dashboard deep-link in its place.
#[tokio::test]
async fn needs_authentication_secret_shape_renders_hint_and_missing() {
    let instance = Uuid::new_v4();
    let err = AppError::NeedsAuthentication {
        service: Some("email".into()),
        service_instance_id: Some(instance),
        connection_id: None,
        auth_url: None,
        short: None,
        provider: None,
        required_scopes: Vec::new(),
        account_email: None,
        headless: false,
        missing_credentials: vec!["mailbox_user".into(), "mailbox_pass".into()],
        hint_url: Some(format!(
            "https://dash.example/services/{instance}?tab=credentials"
        )),
    };
    let (status, body) = body_json(err.into_response()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "needs_authentication");
    assert_eq!(body["service"], "email");
    assert_eq!(
        body["missing_credentials"],
        json!(["mailbox_user", "mailbox_pass"])
    );
    assert_eq!(
        body["hint_url"],
        json!(format!(
            "https://dash.example/services/{instance}?tab=credentials"
        ))
    );
    // Absent, not null — consumers branch on key presence.
    assert!(body.get("auth_url").is_none(), "{body}");
    assert!(body.get("provider").is_none(), "{body}");
}

/// A headless org has no dashboard to be pointed at, but still needs to
/// know which fields to collect — so the list ships and the link does not.
#[tokio::test]
async fn needs_authentication_headless_keeps_missing_without_hint() {
    let err = AppError::NeedsAuthentication {
        service: Some("email".into()),
        service_instance_id: None,
        connection_id: None,
        auth_url: None,
        short: None,
        provider: None,
        required_scopes: Vec::new(),
        account_email: None,
        headless: true,
        missing_credentials: vec!["mailbox_pass".into()],
        hint_url: None,
    };
    let (_status, body) = body_json(err.into_response()).await;
    assert_eq!(body["headless"], json!(true));
    assert_eq!(body["missing_credentials"], json!(["mailbox_pass"]));
    assert!(body.get("hint_url").is_none(), "{body}");
}

/// The OAuth shape is unchanged: neither new key appears when empty, so
/// existing consumers see exactly the body they saw before.
#[tokio::test]
async fn needs_authentication_oauth_shape_elides_new_fields() {
    let err = AppError::NeedsAuthentication {
        service: Some("x".into()),
        service_instance_id: None,
        connection_id: None,
        auth_url: Some("https://api.example/connect-authorize?id=abc".into()),
        short: None,
        provider: Some("x".into()),
        required_scopes: vec!["tweet.read".into()],
        account_email: None,
        headless: false,
        missing_credentials: Vec::new(),
        hint_url: None,
    };
    let (_status, body) = body_json(err.into_response()).await;
    assert_eq!(
        body["auth_url"],
        "https://api.example/connect-authorize?id=abc"
    );
    assert!(body.get("missing_credentials").is_none(), "{body}");
    assert!(body.get("hint_url").is_none(), "{body}");
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
