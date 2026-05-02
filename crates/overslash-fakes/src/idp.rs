//! Auth0- and Okta-flavored OIDC IdP fakes.
//!
//! Each variant runs on its own port and serves a discovery doc + the OAuth
//! 2.1 + OIDC userinfo endpoint surface that Overslash's
//! `/auth/login/{provider_key}` flow drives. The variants differ in:
//!
//! - **issuer / discovery layout** — Auth0 publishes the discovery doc at the
//!   root of the tenant (`/.well-known/openid-configuration`); Okta publishes
//!   it under `/oauth2/{authorizationServerId}/.well-known/...`. The fakes
//!   mirror those URL shapes so a real OIDC discovery client would happily
//!   resolve them.
//! - **userinfo claim shape** — Auth0 puts custom group/role data behind a
//!   namespace claim (`https://overslash.test/groups`, `.../roles`) because
//!   Auth0 strips non-standard top-level claims; Okta returns `groups` /
//!   `roles` directly at the top level.
//! - **token shape & subject** — each variant carries its own deterministic
//!   subject + email so a per-org seed can match users by `(provider, sub)`.
//!
//! These fakes do **not** mint signed JWTs (no JWKS publication) — Overslash's
//! login flow relies on the OAuth 2 `access_token` + the `userinfo_endpoint`,
//! never on parsing an `id_token`. If/when id_token verification lands the
//! fakes will need a JWKS endpoint and a signed payload.

use axum::{
    Form, Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::sync::Arc;

use crate::{Handle, authorize_redirect_with_mock_code, bind, serve};

/// Which IdP product the fake should impersonate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdpVariant {
    Auth0,
    Okta,
}

impl IdpVariant {
    /// Path prefix used in the fake's URLs. Distinct prefixes let a single
    /// host serve both variants if needed (the binary spawns one per port to
    /// keep ports → variants 1:1, but the prefix is still semantically
    /// meaningful — it's what an upstream tenant URL would look like).
    pub fn path_prefix(self) -> &'static str {
        match self {
            IdpVariant::Auth0 => "/auth0",
            IdpVariant::Okta => "/okta/oauth2/default",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            IdpVariant::Auth0 => "Auth0",
            IdpVariant::Okta => "Okta",
        }
    }
}

/// Per-variant userinfo profile. The fake returns the same profile to every
/// request so seeded e2e tests can assert deterministically. A real IdP would
/// vary this per-user; the fake's "user" is whoever holds the access token.
#[derive(Clone, Debug)]
pub struct IdpProfile {
    pub sub: String,
    pub email: String,
    pub name: String,
    pub picture: Option<String>,
    /// Group memberships the IdP claims for the user. Auth0 puts these behind
    /// a namespace claim; Okta puts them at the top level. Group → role
    /// mapping is the consumer's job (Overslash currently does not act on
    /// these claims; the e2e tests assert what's surfaced via the session).
    pub groups: Vec<String>,
    /// Application roles. Same namespacing rules as `groups`.
    pub roles: Vec<String>,
}

impl IdpProfile {
    pub fn auth0_default() -> Self {
        Self {
            sub: "auth0|e2e-admin".into(),
            email: "alice@orga.example".into(),
            name: "Alice (Auth0)".into(),
            picture: Some("https://example.com/auth0/alice.png".into()),
            groups: vec!["org-a-admins".into(), "everyone".into()],
            roles: vec!["org-admin".into()],
        }
    }

    pub fn okta_default() -> Self {
        Self {
            sub: "00uOKTA-e2e-member".into(),
            email: "bob@orgb.example".into(),
            name: "Bob (Okta)".into(),
            picture: Some("https://example.com/okta/bob.png".into()),
            groups: vec!["org-b-members".into(), "everyone".into()],
            roles: vec!["org-member".into()],
        }
    }
}

#[derive(Clone)]
struct AppState {
    variant: IdpVariant,
    profile: Arc<IdpProfile>,
    /// Custom-claim namespace used by the Auth0 variant. Held on the state
    /// so the discovery handler and userinfo handler stay consistent.
    namespace: String,
}

pub async fn start_variant(variant: IdpVariant, profile: IdpProfile, bind_addr: &str) -> Handle {
    let (listener, addr, url) = bind(bind_addr).await.expect("bind idp variant");
    let app = router(variant, profile);
    serve(listener, addr, url, app)
}

pub fn router(variant: IdpVariant, profile: IdpProfile) -> Router {
    let state = AppState {
        variant,
        profile: Arc::new(profile),
        namespace: "https://overslash.test".to_string(),
    };
    let prefix = variant.path_prefix();
    Router::new()
        .route(
            &format!("{prefix}/.well-known/openid-configuration"),
            get(discovery),
        )
        // Auth0 historically uses /authorize + /oauth/token; Okta uses
        // /v1/authorize + /v1/token. We accept both shapes under the variant's
        // prefix so a hand-written client gets the same surface either way —
        // the discovery doc is what tells callers which to use.
        .route(
            &format!("{prefix}/authorize"),
            get(authorize_redirect_with_mock_code),
        )
        .route(&format!("{prefix}/oauth/token"), post(token))
        .route(
            &format!("{prefix}/v1/authorize"),
            get(authorize_redirect_with_mock_code),
        )
        .route(&format!("{prefix}/v1/token"), post(token))
        .route(&format!("{prefix}/userinfo"), get(userinfo))
        .route(&format!("{prefix}/v1/userinfo"), get(userinfo))
        .with_state(state)
}

async fn discovery(headers: HeaderMap, State(state): State<AppState>) -> Json<Value> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let base = format!("http://{host}{}", state.variant.path_prefix());
    let (auth_path, token_path, userinfo_path) = match state.variant {
        IdpVariant::Auth0 => ("/authorize", "/oauth/token", "/userinfo"),
        IdpVariant::Okta => ("/v1/authorize", "/v1/token", "/v1/userinfo"),
    };
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}{auth_path}"),
        "token_endpoint": format!("{base}{token_path}"),
        "userinfo_endpoint": format!("{base}{userinfo_path}"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "scopes_supported": ["openid", "email", "profile", "offline_access", "groups"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
        ],
        "claims_supported": claims_supported(&state),
        "x-overslash-idp-variant": state.variant.display_name(),
    }))
}

fn claims_supported(state: &AppState) -> Vec<String> {
    let mut base = vec![
        "sub".to_string(),
        "email".to_string(),
        "name".to_string(),
        "picture".to_string(),
    ];
    match state.variant {
        IdpVariant::Auth0 => {
            base.push(format!("{}/groups", state.namespace));
            base.push(format!("{}/roles", state.namespace));
        }
        IdpVariant::Okta => {
            base.push("groups".into());
            base.push("roles".into());
            base.push("preferred_username".into());
        }
    }
    base
}

async fn token(Form(params): Form<Vec<(String, String)>>) -> Json<Value> {
    let grant_type = params
        .iter()
        .find(|(k, _)| k == "grant_type")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    match grant_type {
        "authorization_code" => Json(json!({
            "access_token": "mock_access_idp_variant",
            "refresh_token": "mock_refresh_idp_variant",
            "expires_in": 3600,
            "token_type": "Bearer",
        })),
        "refresh_token" => Json(json!({
            "access_token": "mock_refreshed_access_token",
            "refresh_token": "mock_refreshed_refresh_token",
            "expires_in": 3600,
            "token_type": "Bearer",
        })),
        _ => Json(json!({"error": "unsupported_grant_type"})),
    }
}

async fn userinfo(State(state): State<AppState>) -> Json<Value> {
    let p = &*state.profile;
    let mut body = json!({
        "sub": p.sub,
        "email": p.email,
        "email_verified": true,
        "name": p.name,
    });
    if let Some(pic) = &p.picture {
        body["picture"] = json!(pic);
    }
    match state.variant {
        IdpVariant::Auth0 => {
            // Auth0 strips unrecognized top-level claims unless the tenant
            // adds an Action that emits them under a namespaced URI. Mirror
            // that convention so e2e expectations match real-world payloads.
            body[format!("{}/groups", state.namespace)] = json!(p.groups);
            body[format!("{}/roles", state.namespace)] = json!(p.roles);
        }
        IdpVariant::Okta => {
            body["preferred_username"] = json!(p.email);
            body["groups"] = json!(p.groups);
            body["roles"] = json!(p.roles);
        }
    }
    Json(body)
}

/// Combined handle returned by the binary that pairs the [`Handle`] with the
/// per-variant URL prefixes the harness needs to record.
pub struct VariantHandle {
    pub variant: IdpVariant,
    pub handle: Handle,
    /// Tenant root URL — the value an org admin would paste into the IdP
    /// configuration form (issuer-equivalent).
    pub issuer_url: String,
    /// Discovery doc URL.
    pub discovery_url: String,
}

/// Convenience: bind + serve for the binary entry point.
pub async fn boot(variant: IdpVariant, profile: IdpProfile, bind_host: &str) -> VariantHandle {
    let bind_addr = format!("{bind_host}:0");
    let handle = start_variant(variant, profile, &bind_addr).await;
    let prefix = variant.path_prefix();
    let issuer_url = format!("{}{prefix}", handle.url);
    let discovery_url = format!("{issuer_url}/.well-known/openid-configuration");
    VariantHandle {
        variant,
        handle,
        issuer_url,
        discovery_url,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn auth0_discovery_matches_expected_shape() {
        let h = boot(IdpVariant::Auth0, IdpProfile::auth0_default(), "127.0.0.1").await;
        let resp: Value = reqwest::get(&h.discovery_url)
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp["issuer"], h.issuer_url);
        assert!(
            resp["authorization_endpoint"]
                .as_str()
                .unwrap()
                .ends_with("/auth0/authorize")
        );
        assert!(
            resp["token_endpoint"]
                .as_str()
                .unwrap()
                .ends_with("/auth0/oauth/token")
        );
        assert!(
            resp["userinfo_endpoint"]
                .as_str()
                .unwrap()
                .ends_with("/auth0/userinfo")
        );
        let claims: Vec<String> = serde_json::from_value(resp["claims_supported"].clone()).unwrap();
        assert!(
            claims.iter().any(|c| c == "https://overslash.test/groups"),
            "auth0 must expose groups behind its namespace, got {claims:?}"
        );
    }

    #[tokio::test]
    async fn okta_userinfo_returns_top_level_groups() {
        let h = boot(IdpVariant::Okta, IdpProfile::okta_default(), "127.0.0.1").await;
        let userinfo_url = format!("{}/v1/userinfo", h.issuer_url);
        let resp: Value = reqwest::Client::new()
            .get(&userinfo_url)
            .bearer_auth("anything")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp["sub"], "00uOKTA-e2e-member");
        assert_eq!(resp["email"], "bob@orgb.example");
        let groups: Vec<String> = serde_json::from_value(resp["groups"].clone()).unwrap();
        assert!(groups.contains(&"org-b-members".to_string()));
    }

    #[tokio::test]
    async fn auth0_userinfo_namespaces_groups_and_roles() {
        let h = boot(IdpVariant::Auth0, IdpProfile::auth0_default(), "127.0.0.1").await;
        let userinfo_url = format!("{}/userinfo", h.issuer_url);
        let resp: Value = reqwest::Client::new()
            .get(&userinfo_url)
            .bearer_auth("anything")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(
            resp.get("groups").is_none(),
            "auth0 must not put groups at the top level"
        );
        let ns_groups = resp["https://overslash.test/groups"].clone();
        let groups: Vec<String> = serde_json::from_value(ns_groups).unwrap();
        assert!(groups.contains(&"org-a-admins".to_string()));
    }
}
