//! Qualified secret paths: which vault namespace a secret binding points at.
//!
//! Secrets are namespaced per user (the ceiling user of the identity that
//! wrote them) or org-wide. A binding — a service instance's `credentials`
//! value, its legacy `secret_name`, a `SecretRef` binding — names a secret by
//! a path so the namespace travels with the name. Grammar:
//!
//! * `org/<name>` — the org-wide vault (admin-written)
//! * `<user>/<name>` — a user's vault. Stored canonically with the user's
//!   identity uuid; on input `<user>` may also be a handle (name or email)
//!   that the API layer resolves when it is unambiguous.
//! * `user:<user>/<name>` — explicit user form, the escape hatch for a user
//!   whose handle is literally `org`.
//! * `<name>` (no `/`) — bare; its namespace comes from context.
//!
//! New secret names may not contain `/` or start with `user:`
//! ([`is_reserved_name`]), so a name is never mistaken for a path.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

const ORG_HANDLE: &str = "org";
const USER_PREFIX: &str = "user:";

/// Which vault a secret lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(
    tag = "scope",
    content = "owner_identity_id",
    rename_all = "snake_case"
)]
pub enum SecretNamespace {
    /// A user's vault, keyed by the user identity id.
    User(Uuid),
    /// The org-wide vault (`secrets.owner_identity_id IS NULL`).
    Org,
}

impl SecretNamespace {
    /// The `secrets.owner_identity_id` value for this namespace.
    pub fn owner(self) -> Option<Uuid> {
        match self {
            Self::User(id) => Some(id),
            Self::Org => None,
        }
    }

    /// Inverse of [`Self::owner`].
    pub fn from_owner(owner: Option<Uuid>) -> Self {
        owner.map_or(Self::Org, Self::User)
    }

    pub fn path(self, name: impl Into<String>) -> SecretPath {
        SecretPath {
            ns: self,
            name: name.into(),
        }
    }
}

/// A secret name qualified by its namespace.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecretPath {
    pub ns: SecretNamespace,
    pub name: String,
}

/// Result of parsing a stored or submitted binding value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedBinding {
    /// Fully resolved: `org/<name>` or `<uuid>/<name>`.
    Qualified(SecretPath),
    /// `<handle>/<name>` where the handle is not a uuid: a user name or
    /// email that only the API layer (with an org's identities) can resolve.
    Handle { user: String, name: String },
    /// An unqualified name. Its namespace comes from context (the writer's
    /// default namespace, or the requester's for pre-migration payloads).
    Bare(String),
}

impl SecretPath {
    pub fn parse(s: &str) -> ParsedBinding {
        let (explicit_user, rest) = match s.strip_prefix(USER_PREFIX) {
            Some(rest) => (true, rest),
            None => (false, s),
        };
        let Some((user, name)) = rest.split_once('/') else {
            return ParsedBinding::Bare(s.to_string());
        };
        if user.is_empty() || name.is_empty() {
            return ParsedBinding::Bare(s.to_string());
        }
        if !explicit_user && user == ORG_HANDLE {
            return ParsedBinding::Qualified(SecretNamespace::Org.path(name));
        }
        if user.len() == 36
            && let Ok(id) = Uuid::parse_str(user)
        {
            return ParsedBinding::Qualified(SecretNamespace::User(id).path(name));
        }
        ParsedBinding::Handle {
            user: user.to_string(),
            name: name.to_string(),
        }
    }

    pub fn to_canonical(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for SecretPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ns {
            SecretNamespace::User(id) => write!(f, "{id}/{}", self.name),
            SecretNamespace::Org => write!(f, "{ORG_HANDLE}/{}", self.name),
        }
    }
}

/// True for names that would read as a path. Rejected at every secret-write
/// boundary so a name can never be mistaken for one.
pub fn is_reserved_name(name: &str) -> bool {
    name.contains('/') || name.starts_with(USER_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_user_and_org() {
        let id = Uuid::new_v4();
        for p in [
            SecretNamespace::User(id).path("shortcut_api_token"),
            SecretNamespace::Org.path("overfwd_gateway_key"),
            // Legacy names may still contain `/`; the first one splits.
            SecretNamespace::User(id).path("a/b:c"),
        ] {
            assert_eq!(
                SecretPath::parse(&p.to_canonical()),
                ParsedBinding::Qualified(p)
            );
        }
        assert_eq!(
            SecretPath::parse("org/x"),
            ParsedBinding::Qualified(SecretNamespace::Org.path("x"))
        );
        assert_eq!(
            SecretPath::parse(&format!("user:{id}/x")),
            ParsedBinding::Qualified(SecretNamespace::User(id).path("x"))
        );
    }

    #[test]
    fn handles_need_resolution() {
        assert_eq!(
            SecretPath::parse("angel/shortcut_api_token"),
            ParsedBinding::Handle {
                user: "angel".into(),
                name: "shortcut_api_token".into()
            }
        );
        // `user:org/…` addresses a user whose handle is literally `org`.
        assert_eq!(
            SecretPath::parse("user:org/x"),
            ParsedBinding::Handle {
                user: "org".into(),
                name: "x".into()
            }
        );
        assert_eq!(
            SecretPath::parse("user:angel@reveni.com/x"),
            ParsedBinding::Handle {
                user: "angel@reveni.com".into(),
                name: "x".into()
            }
        );
    }

    #[test]
    fn bare_and_malformed_stay_bare() {
        for s in [
            "shortcut_api_token",
            "org/",
            "/x",
            "",
            "user:",
            "user:/x",
            "org:x",
        ] {
            assert_eq!(
                SecretPath::parse(s),
                ParsedBinding::Bare(s.to_string()),
                "{s}"
            );
        }
    }

    #[test]
    fn reserved_names() {
        assert!(is_reserved_name("a/b"));
        assert!(is_reserved_name("user:x"));
        assert!(!is_reserved_name("username"));
        assert!(!is_reserved_name("org_key"));
        assert!(!is_reserved_name("OAUTH_GOOGLE_CLIENT_ID"));
    }
}
