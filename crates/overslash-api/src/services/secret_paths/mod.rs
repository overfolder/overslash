//! Who may bind — and who may use — which vault namespace.
//!
//! Secrets live in a user's vault or the org vault ([`SecretNamespace`]), and
//! every binding names one by path ([`SecretPath`]). This module is the one
//! place the namespace rules live:
//!
//! * **Write rule** ([`BindingWriter`]): a binding a request *changes* may only
//!   point into the writer's own vault — the instance owner's for a user-level
//!   instance, the caller's own for an org-level one — or, for org admins, the
//!   org vault. Bindings a request leaves unchanged are kept verbatim, which is
//!   how a shared org service keeps mounting the admin's secret after another
//!   admin edits it.
//! * **Read rule** ([`readable_instance_binding`]): a user-level instance only
//!   ever resolves its owner's vault and the org vault, whatever is stored. An
//!   org-level instance resolves the stored path — the write rule vouched for
//!   it.
//! * **Mode A** ([`canonicalize_explicit_refs`]): a caller naming secrets
//!   inline reaches only its own user's vault. Never the org vault: Mode A
//!   dials any host, and org credentials reach a request only through a
//!   template that pins one.
//!
//! On input a user may be named by handle (`angel/x`, `angel@acme.com/x`):
//! [`parse_input`] resolves it against the org's users when exactly one
//! matches.

use overslash_core::types::{
    ParsedBinding, SecretNamespace, SecretPath, SecretRef, is_reserved_name,
};
use overslash_db::OrgScope;
use uuid::Uuid;

use crate::error::AppError;

/// The read rule. `None` when a user-level instance's binding points outside
/// its owner's vault (or is otherwise unusable) — the caller reports the slot
/// as unbound rather than resolving someone else's secret.
pub fn readable_instance_binding(instance_owner: Option<Uuid>, stored: &str) -> Option<SecretPath> {
    let path = match SecretPath::parse(stored) {
        ParsedBinding::Qualified(p) => p,
        // Only a row written by a pre-namespace binary mid-deploy is bare.
        // It meant "the name in the org-unique vault"; the safe reading is
        // the instance's own namespace.
        ParsedBinding::Bare(name) if !name.is_empty() => {
            SecretNamespace::from_owner(instance_owner).path(name)
        }
        // Handles are resolved at write time and never stored.
        ParsedBinding::Bare(_) | ParsedBinding::Handle { .. } => return None,
    };
    match (instance_owner, path.ns) {
        (None, _) | (_, SecretNamespace::Org) => Some(path),
        (Some(owner), SecretNamespace::User(u)) if u == owner => Some(path),
        (Some(_), SecretNamespace::User(_)) => None,
    }
}

/// A stored binding as the API shows it: relative to the instance's *home
/// vault* — the one a bare name means when written back. That is the owner's
/// vault on a user-level instance and the viewer's own (`viewer`, the reading
/// caller's ceiling user) on an org-level one, exactly as [`BindingWriter`]
/// qualifies bare names. So a path into the home vault reads as the plain
/// name, and echoing a response into an update is always a no-op. The org
/// vault and every other vault stay full paths.
pub fn relative_to_instance(
    instance_owner: Option<Uuid>,
    viewer: Option<Uuid>,
    stored: &str,
) -> String {
    match (instance_owner.or(viewer), SecretPath::parse(stored)) {
        // Only when the name reads back as bare: a legacy name holding `/`
        // (`org/x`, `a/b`) shown alone would come back as another vault or a
        // handle, so it keeps its full path.
        (Some(home), ParsedBinding::Qualified(p))
            if p.ns == SecretNamespace::User(home)
                && SecretPath::parse(&p.name) == ParsedBinding::Bare(p.name.clone()) =>
        {
            p.name
        }
        _ => stored.to_string(),
    }
}

/// Where an org-source slot's `default_secret_name` is looked up, in order:
/// a user-level instance prefers its owner's own copy, then the org-wide
/// one; an org-level instance reads the org vault only.
pub fn org_default_candidates(instance_owner: Option<Uuid>, default: &str) -> Vec<SecretPath> {
    let mut out = Vec::with_capacity(2);
    if let Some(owner) = instance_owner {
        out.push(SecretNamespace::User(owner).path(default));
    }
    out.push(SecretNamespace::Org.path(default));
    out
}

/// Parse a user-submitted secret reference: a canonical path, `org/<name>`,
/// `<handle>/<name>`, or a bare name (qualified with `default`).
///
/// A handle matches a user identity's email, email local part, or name
/// (case-insensitive). Zero matches is a 400, several a 400 that asks for the
/// unambiguous form — never a guess.
pub async fn parse_input(
    scope: &OrgScope,
    raw: &str,
    default: SecretNamespace,
) -> Result<SecretPath, AppError> {
    let raw = raw.trim();
    match SecretPath::parse(raw) {
        ParsedBinding::Qualified(p) => Ok(p),
        ParsedBinding::Bare(name) => {
            if name.is_empty() {
                return Err(AppError::BadRequest("secret name must not be empty".into()));
            }
            Ok(default.path(name))
        }
        ParsedBinding::Handle { user, name } => {
            let id = resolve_user_handle(scope, &user).await?;
            Ok(SecretNamespace::User(id).path(name))
        }
    }
}

async fn resolve_user_handle(scope: &OrgScope, handle: &str) -> Result<Uuid, AppError> {
    let h = handle.to_lowercase();
    let matches: Vec<Uuid> = scope
        .list_identities()
        .await?
        .into_iter()
        .filter(|i| i.kind == "user" && i.archived_at.is_none())
        .filter(|i| {
            let email = i.email.as_deref().unwrap_or("").to_lowercase();
            let local = email.rsplit_once('@').map_or("", |(l, _)| l);
            i.name.to_lowercase() == h || (!email.is_empty() && (email == h || local == h))
        })
        .map(|i| i.id)
        .collect();
    match matches.as_slice() {
        [id] => Ok(*id),
        [] => Err(AppError::BadRequest(format!(
            "no user `{handle}` in this org; write the secret as `<user id>/<name>`"
        ))),
        _ => Err(AppError::BadRequest(format!(
            "`{handle}` matches several users; write the secret as `<user id>/<name>`"
        ))),
    }
}

/// Reject a name that would read as a path. Every secret-write boundary
/// (`PUT /v1/secrets`, secret requests) calls this.
pub fn validate_new_secret_name(name: &str) -> Result<(), AppError> {
    if is_reserved_name(name) {
        return Err(AppError::BadRequest(format!(
            "secret name `{name}` may not contain `/` or start with `user:`"
        )));
    }
    Ok(())
}

/// The write rule, for one create/update of a service instance.
pub struct BindingWriter {
    /// The caller's own vault (its ceiling user).
    pub caller_user: Uuid,
    pub caller_is_admin: bool,
    /// The instance's owner; `None` for an org-level instance.
    pub instance_owner: Option<Uuid>,
}

impl BindingWriter {
    /// The one user vault this writer may bind into.
    fn writable_user(&self) -> Uuid {
        self.instance_owner.unwrap_or(self.caller_user)
    }

    /// The vault a bare name written by this writer lands in.
    pub fn home(&self) -> SecretNamespace {
        SecretNamespace::User(self.writable_user())
    }

    /// Canonicalize one binding value. `stored` is the slot's current value:
    /// an unchanged binding is returned verbatim, whatever vault it points at.
    pub async fn canonicalize(
        &self,
        scope: &OrgScope,
        incoming: &str,
        stored: Option<&str>,
        slot_is_org_source: bool,
    ) -> Result<String, AppError> {
        if stored == Some(incoming) {
            return Ok(incoming.to_string());
        }
        let path = parse_input(scope, incoming, self.home()).await?;
        self.authorize(path, stored, slot_is_org_source)
    }

    /// The write rule's decision for an already-resolved path — pure, so it
    /// can be checked exhaustively. Returns the canonical value to store.
    pub fn authorize(
        &self,
        path: SecretPath,
        stored: Option<&str>,
        slot_is_org_source: bool,
    ) -> Result<String, AppError> {
        let canonical = path.to_canonical();
        // Resubmitting the display / handle form of the stored binding is no
        // change either.
        if stored == Some(canonical.as_str()) {
            return Ok(canonical);
        }
        match path.ns {
            SecretNamespace::User(u) if u == self.writable_user() => {}
            SecretNamespace::Org
                if self.caller_is_admin
                    && (self.instance_owner.is_none() || slot_is_org_source) => {}
            SecretNamespace::Org => {
                return Err(AppError::Forbidden(if self.caller_is_admin {
                    "org-vault secrets bind only to org-source credential slots on a \
                     user-level service"
                        .into()
                } else {
                    "only org admins may bind org-vault secrets".into()
                }));
            }
            SecretNamespace::User(_) => {
                return Err(AppError::Forbidden(
                    "can only bind secrets from this service owner's own vault".into(),
                ));
            }
        }
        Ok(canonical)
    }
}

/// The inline-secret rule for one resolved path — pure, so it can be checked
/// exhaustively: only the caller's own vault.
pub fn authorize_inline(
    own: SecretNamespace,
    path: SecretPath,
    raw: &str,
) -> Result<String, AppError> {
    if path.ns != own {
        return Err(AppError::Forbidden(format!(
            "secret `{raw}` is outside your own vault; inline secrets can only \
             name your own secrets"
        )));
    }
    Ok(path.to_canonical())
}

/// Mode A / explicit `secrets` on a call: qualify every reference into the
/// caller's own vault and refuse anything else. After this, every
/// `SecretRef` carries explicit bindings holding canonical paths, so the
/// send path never sees a bare caller-supplied name.
pub async fn canonicalize_explicit_refs(
    scope: &OrgScope,
    caller_user: Uuid,
    refs: &[SecretRef],
) -> Result<Vec<SecretRef>, AppError> {
    let own = SecretNamespace::User(caller_user);
    let mut out = Vec::with_capacity(refs.len());
    for r in refs {
        let mut r = r.clone();
        if r.bindings.is_empty() {
            // One implicit slot whose secret is `name` itself.
            r.bindings.insert(r.name.clone(), r.name.clone());
        }
        for value in r.bindings.values_mut() {
            let path = parse_input(scope, value, own).await?;
            *value = authorize_inline(own, path, value)?;
        }
        out.push(r);
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
