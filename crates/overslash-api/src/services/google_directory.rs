//! Google Workspace Admin SDK Directory API client, authenticated as a service
//! account with domain-wide delegation.
//!
//! Read-only and narrow on purpose: one scope
//! (`admin.directory.group.readonly`), three listings, direct membership only.
//! Nested groups are skipped rather than expanded so the per-user pull at
//! sign-in and the full sweep report the same thing — expansion in one path
//! but not the other would make membership flap between them — and so a
//! directory group stays one hop from a ceiling, as D107 has it.

use serde::Deserialize;
use time::OffsetDateTime;

use crate::AppState;

/// Where the signed assertion is exchanged. Fixed, never taken from the
/// uploaded key: a key JSON whose `token_uri` pointed elsewhere would
/// otherwise hand a signed, replayable assertion for this org's Workspace to
/// whatever host its author chose.
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const DIRECTORY_BASE: &str = "https://admin.googleapis.com/admin/directory/v1";
pub const SCOPE: &str = "https://www.googleapis.com/auth/admin.directory.group.readonly";

const PAGE_SIZE: u32 = 200;
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// A runaway `nextPageToken` loop must end. 500 pages × 200 = 100k groups, or
/// 100k members of one group — far beyond any org this is built for.
const MAX_PAGES: usize = 500;

#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    #[error("not a service account key: {0}")]
    InvalidKey(String),
    /// Google refused the assertion. The message is Google's own
    /// `error_description` where it gave one, which for the common failure —
    /// delegation not granted — is the most useful thing an admin can read.
    #[error("Google refused the service account ({code}): {message}")]
    TokenRejected { code: String, message: String },
    #[error("Google Directory API returned {status} for {what}: {message}")]
    Api {
        status: u16,
        what: &'static str,
        message: String,
    },
    #[error("could not reach Google: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("Google returned an unreadable response: {0}")]
    Decode(String),
    #[error("too many pages listing {0}")]
    TooManyPages(&'static str),
}

/// The fields of a service-account JSON key this client uses, parsed at the
/// boundary. `token_uri` is deliberately not among them — see [`TOKEN_URL`].
#[derive(Clone)]
pub struct ServiceAccountKey {
    pub client_email: String,
    /// The OAuth client ID a Workspace admin enters in admin.google.com →
    /// Domain-wide delegation. Numeric, not secret — the dashboard shows it.
    pub client_id: String,
    pub private_key_id: String,
    private_key: String,
}

impl std::fmt::Debug for ServiceAccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccountKey")
            .field("client_email", &self.client_email)
            .field("client_id", &self.client_id)
            .field("private_key_id", &self.private_key_id)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct RawKey {
    #[serde(rename = "type")]
    kind: Option<String>,
    client_email: Option<String>,
    client_id: Option<String>,
    private_key_id: Option<String>,
    private_key: Option<String>,
}

impl ServiceAccountKey {
    pub fn parse(json: &str) -> Result<Self, DirectoryError> {
        let raw: RawKey = serde_json::from_str(json)
            .map_err(|e| DirectoryError::InvalidKey(format!("not valid JSON ({e})")))?;
        if raw.kind.as_deref() != Some("service_account") {
            return Err(DirectoryError::InvalidKey(
                "expected \"type\": \"service_account\"".into(),
            ));
        }
        let field = |v: Option<String>, name: &str| {
            v.filter(|s| !s.trim().is_empty())
                .ok_or_else(|| DirectoryError::InvalidKey(format!("missing {name}")))
        };
        let key = Self {
            client_email: field(raw.client_email, "client_email")?,
            client_id: field(raw.client_id, "client_id")?,
            private_key_id: field(raw.private_key_id, "private_key_id")?,
            private_key: field(raw.private_key, "private_key")?,
        };
        // Fail at save time, not at the first sweep.
        jsonwebtoken::EncodingKey::from_rsa_pem(key.private_key.as_bytes()).map_err(|e| {
            DirectoryError::InvalidKey(format!("private_key is not an RSA PEM ({e})"))
        })?;
        Ok(key)
    }
}

#[derive(serde::Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

fn build_assertion(
    key: &ServiceAccountKey,
    subject: &str,
    now: OffsetDateTime,
) -> Result<String, DirectoryError> {
    let iat = now.unix_timestamp();
    let claims = AssertionClaims {
        iss: &key.client_email,
        sub: subject,
        scope: SCOPE,
        aud: TOKEN_URL,
        iat,
        exp: iat + 3600,
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(key.private_key_id.clone());
    let enc = jsonwebtoken::EncodingKey::from_rsa_pem(key.private_key.as_bytes())
        .map_err(|e| DirectoryError::InvalidKey(e.to_string()))?;
    jsonwebtoken::encode(&header, &claims, &enc)
        .map_err(|e| DirectoryError::InvalidKey(e.to_string()))
}

/// A group as the Directory API lists it.
#[derive(Debug, Clone, Deserialize)]
pub struct DirectoryGroup {
    /// Stable across renames and email changes — the `external_id`.
    pub id: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub name: String,
}

impl DirectoryGroup {
    pub fn label(&self) -> &str {
        if self.name.trim().is_empty() {
            &self.email
        } else {
            &self.name
        }
    }
}

#[derive(Deserialize)]
struct GroupsPage {
    #[serde(default)]
    groups: Vec<DirectoryGroup>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct Member {
    #[serde(default)]
    email: String,
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    status: String,
}

#[derive(Deserialize)]
struct MembersPage {
    #[serde(default)]
    members: Vec<Member>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

/// An authenticated Directory API session for one org.
pub struct DirectoryClient<'a> {
    state: &'a AppState,
    access_token: String,
}

impl<'a> DirectoryClient<'a> {
    /// Exchange a signed assertion for an access token impersonating `subject`.
    pub async fn connect(
        state: &'a AppState,
        key: &ServiceAccountKey,
        subject: &str,
    ) -> Result<Self, DirectoryError> {
        let assertion = build_assertion(key, subject, OffsetDateTime::now_utc())?;
        let resp = state
            .http_client
            .post(state.config.apply_base_overrides(TOKEN_URL))
            .timeout(REQUEST_TIMEOUT)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await?;
        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| DirectoryError::Decode(e.to_string()))?;
        if !status.is_success() {
            let code = body["error"].as_str().unwrap_or("error").to_string();
            let message = body["error_description"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| token_hint(&code).to_string());
            return Err(DirectoryError::TokenRejected { code, message });
        }
        let access_token = body["access_token"]
            .as_str()
            .ok_or_else(|| DirectoryError::Decode("token response has no access_token".into()))?
            .to_string();
        Ok(Self {
            state,
            access_token,
        })
    }

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        query: &[(&str, &str)],
        what: &'static str,
    ) -> Result<T, DirectoryError> {
        let mut url = url::Url::parse(url).map_err(|e| DirectoryError::Decode(e.to_string()))?;
        url.query_pairs_mut().extend_pairs(query);
        let resp = self
            .state
            .http_client
            .get(self.state.config.apply_base_overrides(url.as_str()))
            .timeout(REQUEST_TIMEOUT)
            .bearer_auth(&self.access_token)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let message = body["error"]["message"]
                .as_str()
                .unwrap_or("no detail")
                .to_string();
            return Err(DirectoryError::Api {
                status: status.as_u16(),
                what,
                message,
            });
        }
        resp.json()
            .await
            .map_err(|e| DirectoryError::Decode(e.to_string()))
    }

    async fn list_groups_where(
        &self,
        key: &str,
        value: &str,
        what: &'static str,
        limit: Option<u32>,
    ) -> Result<Vec<DirectoryGroup>, DirectoryError> {
        let url = format!("{DIRECTORY_BASE}/groups");
        let page_size = limit.unwrap_or(PAGE_SIZE).to_string();
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut q = vec![(key, value), ("maxResults", page_size.as_str())];
            if let Some(t) = token.as_deref() {
                q.push(("pageToken", t));
            }
            let page: GroupsPage = self.get(&url, &q, what).await?;
            out.extend(page.groups);
            match page.next_page_token {
                Some(t) if limit.is_none() && !t.is_empty() => token = Some(t),
                _ => return Ok(out),
            }
        }
        Err(DirectoryError::TooManyPages(what))
    }

    /// Every group in the Workspace account.
    pub async fn list_groups(&self, customer: &str) -> Result<Vec<DirectoryGroup>, DirectoryError> {
        self.list_groups_where("customer", customer, "groups", None)
            .await
    }

    /// One page of one group — proves the credential and the delegation work
    /// without walking the whole directory.
    pub async fn probe(&self, customer: &str) -> Result<(), DirectoryError> {
        self.list_groups_where("customer", customer, "groups", Some(1))
            .await
            .map(|_| ())
    }

    /// The groups `email` is a direct member of.
    pub async fn list_user_groups(
        &self,
        email: &str,
    ) -> Result<Vec<DirectoryGroup>, DirectoryError> {
        self.list_groups_where("userKey", email, "user groups", None)
            .await
    }

    /// Lower-cased emails of the active users directly in `group_id`.
    pub async fn list_member_emails(&self, group_id: &str) -> Result<Vec<String>, DirectoryError> {
        let url = format!(
            "{DIRECTORY_BASE}/groups/{}/members",
            urlencoding::encode(group_id)
        );
        let page_size = PAGE_SIZE.to_string();
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut q = vec![("maxResults", page_size.as_str())];
            if let Some(t) = token.as_deref() {
                q.push(("pageToken", t));
            }
            let page: MembersPage = self.get(&url, &q, "group members").await?;
            out.extend(
                page.members
                    .into_iter()
                    // Nested groups and customer-wide members are not humans
                    // this org can hold; suspended users are not members.
                    .filter(|m| m.kind == "USER" && m.status == "ACTIVE" && !m.email.is_empty())
                    .map(|m| m.email.to_lowercase()),
            );
            match page.next_page_token {
                Some(t) if !t.is_empty() => token = Some(t),
                _ => return Ok(out),
            }
        }
        Err(DirectoryError::TooManyPages("group members"))
    }
}

/// What an admin should check when Google gave a code but no description.
fn token_hint(code: &str) -> &'static str {
    match code {
        "unauthorized_client" => {
            "domain-wide delegation is not granted for this service account's client ID \
             and the admin.directory.group.readonly scope"
        }
        "invalid_grant" => {
            "the admin email is not a Workspace user this service account may impersonate, \
             or the key was revoked"
        }
        _ => "no detail",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Throwaway 2048-bit key generated for these tests only. Never used anywhere.
    const TEST_PEM: &str = overslash_fakes::google_directory::TEST_PRIVATE_KEY_PEM;

    fn key_json(extra: serde_json::Value) -> String {
        let mut v = serde_json::json!({
            "type": "service_account",
            "client_email": "sync@acme.iam.gserviceaccount.com",
            "client_id": "1234",
            "private_key_id": "kid-1",
            "private_key": TEST_PEM,
            "token_uri": "https://evil.example/token",
        });
        if let (Some(o), serde_json::Value::Object(e)) = (v.as_object_mut(), extra) {
            o.extend(e);
        }
        v.to_string()
    }

    #[test]
    fn parses_a_service_account_key() {
        let k = ServiceAccountKey::parse(&key_json(serde_json::json!({}))).unwrap();
        assert_eq!(k.client_email, "sync@acme.iam.gserviceaccount.com");
        assert_eq!(k.private_key_id, "kid-1");
    }

    #[test]
    fn rejects_a_non_service_account_key() {
        let err =
            ServiceAccountKey::parse(&key_json(serde_json::json!({"type": "authorized_user"})))
                .unwrap_err();
        assert!(matches!(err, DirectoryError::InvalidKey(_)));
    }

    #[test]
    fn rejects_a_key_that_is_not_rsa_pem() {
        let err = ServiceAccountKey::parse(&key_json(serde_json::json!({"private_key": "nope"})))
            .unwrap_err();
        assert!(matches!(err, DirectoryError::InvalidKey(_)));
    }

    #[test]
    fn debug_never_prints_the_private_key() {
        let k = ServiceAccountKey::parse(&key_json(serde_json::json!({}))).unwrap();
        assert!(!format!("{k:?}").contains("PRIVATE KEY"));
    }

    /// The assertion's audience is the fixed Google endpoint whatever the
    /// uploaded key's `token_uri` says.
    #[test]
    fn the_assertion_ignores_token_uri() {
        let k = ServiceAccountKey::parse(&key_json(serde_json::json!({}))).unwrap();
        let jwt = build_assertion(&k, "admin@acme.com", OffsetDateTime::now_utc()).unwrap();
        let payload = jwt.split('.').nth(1).unwrap();
        use base64::Engine;
        let claims: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claims["aud"], TOKEN_URL);
        assert_eq!(claims["sub"], "admin@acme.com");
        assert_eq!(claims["iss"], "sync@acme.iam.gserviceaccount.com");
        assert_eq!(claims["scope"], SCOPE);
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            3600
        );
    }
}
