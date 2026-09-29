//! Google Workspace Admin SDK Directory API fake.
//!
//! Serves the three surfaces Overslash's Google Directory sync drives, at the
//! same paths Google does so the API's `service_base_overrides` host swap is
//! all a test needs:
//!
//! - `POST /token` — the JWT-bearer grant. The assertion's RS256 signature is
//!   verified against [`TEST_PUBLIC_KEY_PEM`], and its `aud` and `scope` are
//!   checked, so a regression in how Overslash signs is a test failure rather
//!   than a silent pass.
//! - `GET /admin/directory/v1/groups?customer=…` and `?userKey=…`
//! - `GET /admin/directory/v1/groups/{id}/members`
//!
//! Listings are served [`PAGE_SIZE`] items at a time whatever `maxResults`
//! asks for, so every test exercises pagination. Knobs on [`GoogleDirectoryState`]
//! inject a token rejection, a failure on one page of one group's members, or
//! a delay on `userKey` lookups.
//!
//! When booted by the `overslash-fakes` binary for e2e, the directory starts
//! empty and `POST /__admin/groups` replaces it, so a scenario can name the
//! humans its own run created.

use std::sync::{Arc, Mutex};

use axum::{
    Form, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Handle, bind, serve};

/// Throwaway RSA key generated for tests. It signs nothing outside them.
pub const TEST_PRIVATE_KEY_PEM: &str = include_str!("../fixtures/google_sa_test_key.pem");
pub const TEST_PUBLIC_KEY_PEM: &str = include_str!("../fixtures/google_sa_test_key.pub.pem");

pub const TOKEN_AUD: &str = "https://oauth2.googleapis.com/token";
pub const SCOPE: &str = "https://www.googleapis.com/auth/admin.directory.group.readonly";
pub const PAGE_SIZE: usize = 2;

/// A service-account key JSON the fake will accept.
pub fn service_account_json(client_email: &str) -> String {
    json!({
        "type": "service_account",
        "project_id": "overslash-test",
        "private_key_id": "test-key-1",
        "private_key": TEST_PRIVATE_KEY_PEM,
        "client_email": client_email,
        "client_id": "109876543210",
        "token_uri": TOKEN_AUD,
    })
    .to_string()
}

#[derive(Clone, Debug)]
pub struct FakeMember {
    pub email: String,
    /// `USER`, `GROUP` or `CUSTOMER`.
    pub kind: String,
    /// `ACTIVE` or `SUSPENDED`.
    pub status: String,
}

impl FakeMember {
    pub fn user(email: &str) -> Self {
        Self {
            email: email.into(),
            kind: "USER".into(),
            status: "ACTIVE".into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FakeGroup {
    pub id: String,
    pub email: String,
    pub name: String,
    pub members: Vec<FakeMember>,
}

impl FakeGroup {
    pub fn new(id: &str, name: &str, members: &[&str]) -> Self {
        Self {
            id: id.into(),
            email: format!("{id}@groups.test"),
            name: name.into(),
            members: members.iter().map(|m| FakeMember::user(m)).collect(),
        }
    }
}

#[derive(Default)]
pub struct GoogleDirectoryState {
    pub groups: Vec<FakeGroup>,
    /// When set, `/token` answers 401 with this OAuth error code.
    pub token_error: Option<String>,
    /// `(group_id, zero-based page)` whose members listing answers 500.
    pub fail_members_page: Option<(String, usize)>,
    /// Delay before answering a `userKey` lookup.
    pub user_groups_delay: Option<std::time::Duration>,
    /// Every `sub` a successful token request impersonated.
    pub subjects: Vec<String>,
    pub token_requests: usize,
    pub user_group_requests: usize,
}

#[derive(Clone)]
pub struct GoogleDirectoryHandle {
    pub url: String,
    pub state: Arc<Mutex<GoogleDirectoryState>>,
}

impl GoogleDirectoryHandle {
    pub fn set_groups(&self, groups: Vec<FakeGroup>) {
        self.state.lock().unwrap().groups = groups;
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut GoogleDirectoryState) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }
}

pub async fn start(bind_addr: &str) -> (Handle, GoogleDirectoryHandle) {
    let state = Arc::new(Mutex::new(GoogleDirectoryState::default()));
    let (listener, addr, url) = bind(bind_addr).await.expect("bind google directory fake");
    let handle = serve(listener, addr, url.clone(), router(state.clone()));
    (handle, GoogleDirectoryHandle { url, state })
}

pub fn router(state: Arc<Mutex<GoogleDirectoryState>>) -> Router {
    Router::new()
        .route("/token", post(token))
        .route("/admin/directory/v1/groups", get(list_groups))
        .route("/admin/directory/v1/groups/{id}/members", get(list_members))
        .route("/__admin/groups", post(admin_set_groups))
        .with_state(state)
}

#[derive(Deserialize)]
struct AdminGroup {
    id: String,
    name: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    members: Vec<String>,
}

/// Replace the whole directory. E2E-only control surface.
async fn admin_set_groups(State(state): Shared, Json(groups): Json<Vec<AdminGroup>>) -> StatusCode {
    let groups = groups
        .into_iter()
        .map(|g| FakeGroup {
            email: g.email.unwrap_or_else(|| format!("{}@groups.test", g.id)),
            members: g.members.iter().map(|m| FakeMember::user(m)).collect(),
            id: g.id,
            name: g.name,
        })
        .collect();
    state.lock().unwrap().groups = groups;
    StatusCode::NO_CONTENT
}

type Shared = State<Arc<Mutex<GoogleDirectoryState>>>;

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    assertion: String,
}

#[derive(Deserialize)]
struct Assertion {
    sub: String,
    scope: String,
}

async fn token(State(state): Shared, Form(form): Form<TokenForm>) -> Response {
    if form.grant_type != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
        return oauth_error("unsupported_grant_type");
    }
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[TOKEN_AUD]);
    validation.set_required_spec_claims(&["exp", "iat", "aud", "iss", "sub"]);
    let key = jsonwebtoken::DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM.as_bytes())
        .expect("test public key");
    let Ok(data) = jsonwebtoken::decode::<Assertion>(&form.assertion, &key, &validation) else {
        return oauth_error("invalid_grant");
    };
    if data.claims.scope != SCOPE {
        return oauth_error("invalid_scope");
    }
    let mut s = state.lock().unwrap();
    s.token_requests += 1;
    if let Some(code) = s.token_error.clone() {
        return oauth_error(&code);
    }
    s.subjects.push(data.claims.sub);
    Json(json!({
        "access_token": "fake-directory-token",
        "token_type": "Bearer",
        "expires_in": 3600,
    }))
    .into_response()
}

fn oauth_error(code: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": code }))).into_response()
}

fn authorized(headers: &HeaderMap) -> bool {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "Bearer fake-directory-token")
}

fn api_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({ "error": { "code": status.as_u16(), "message": message } })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct ListQuery {
    customer: Option<String>,
    #[serde(rename = "userKey")]
    user_key: Option<String>,
    #[serde(rename = "pageToken")]
    page_token: Option<String>,
}

/// Slice one page out of `items`; the page token is the next offset.
fn page<T: Clone>(items: &[T], token: Option<&str>) -> (Vec<T>, Option<String>, usize) {
    let start: usize = token.and_then(|t| t.parse().ok()).unwrap_or(0);
    let end = (start + PAGE_SIZE).min(items.len());
    let next = (end < items.len()).then(|| end.to_string());
    (items[start.min(end)..end].to_vec(), next, start / PAGE_SIZE)
}

fn group_json(g: &FakeGroup) -> Value {
    json!({ "id": g.id, "email": g.email, "name": g.name })
}

async fn list_groups(
    State(state): Shared,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Response {
    if !authorized(&headers) {
        return api_error(StatusCode::UNAUTHORIZED, "Login Required");
    }
    let (groups, delay) = {
        let mut s = state.lock().unwrap();
        match (&q.customer, &q.user_key) {
            (Some(_), None) => (s.groups.clone(), None),
            (None, Some(user)) => {
                s.user_group_requests += 1;
                let user = user.to_lowercase();
                let groups = s
                    .groups
                    .iter()
                    .filter(|g| {
                        g.members.iter().any(|m| {
                            m.kind == "USER"
                                && m.status == "ACTIVE"
                                && m.email.to_lowercase() == user
                        })
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                (groups, s.user_groups_delay)
            }
            _ => return api_error(StatusCode::BAD_REQUEST, "customer or userKey required"),
        }
    };
    if let Some(d) = delay {
        tokio::time::sleep(d).await;
    }
    let (items, next, _) = page(&groups, q.page_token.as_deref());
    let mut body = json!({ "kind": "admin#directory#groups" });
    if !items.is_empty() {
        body["groups"] = items.iter().map(group_json).collect();
    }
    if let Some(n) = next {
        body["nextPageToken"] = json!(n);
    }
    Json(body).into_response()
}

async fn list_members(
    State(state): Shared,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<ListQuery>,
) -> Response {
    if !authorized(&headers) {
        return api_error(StatusCode::UNAUTHORIZED, "Login Required");
    }
    let s = state.lock().unwrap();
    let Some(group) = s.groups.iter().find(|g| g.id == id) else {
        return api_error(StatusCode::NOT_FOUND, "Resource Not Found: groupKey");
    };
    let (items, next, page_no) = page(&group.members, q.page_token.as_deref());
    if s.fail_members_page.as_ref() == Some(&(id.clone(), page_no)) {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "Backend Error");
    }
    let mut body = json!({ "kind": "admin#directory#members" });
    if !items.is_empty() {
        body["members"] = items
            .iter()
            .map(|m| json!({ "email": m.email, "type": m.kind, "status": m.status, "role": "MEMBER" }))
            .collect();
    }
    if let Some(n) = next {
        body["nextPageToken"] = json!(n);
    }
    Json(body).into_response()
}
