//! Refusing to mint a link that would overwrite a credential.
//!
//! Split out of [`super`] because it is a self-contained question — "is this
//! vault name already spoken for, and what should the caller be told?" — that
//! the mint paths ask and nothing else does.
//!
//! The distinction the whole module turns on: reusing a secret *name* is a
//! feature. Binding two service instances to one credential is ordinary, and
//! `credentials: {slot: name}` is how it is done. What is never deliberate is
//! minting a link that **writes** to a name somebody already filled, because
//! the person who opens it is shown a name, not a history. So the check sits
//! on the write path and leaves the bind path alone.

use overslash_db::scopes::OrgScope;

use crate::error::{AppError, SecretNameConflict};

/// Check a set of `(credential_key, secret_name)` pairs against the vault.
///
/// Returns one [`SecretNameConflict`] per name that already exists, in the
/// order asked. An empty result means every name is free.
///
/// Why this is not a uniqueness constraint: a secret name is *deliberately*
/// reusable. Binding two instances to one credential is a feature — the
/// dashboard's `SecretNamePicker` exists to do exactly that, and
/// `credentials: {key: name}` is how an agent does it. What is never
/// deliberate is minting a link that *writes* to a name somebody already
/// filled, because the person who opens it is told only "paste a value for
/// `holded_api_key`" and has no way to know whose value they are replacing.
/// So the check belongs at mint time, on the write path, and not on the bind
/// path at all.
pub async fn conflicting_secret_names(
    scope: &OrgScope,
    candidates: &[(Option<String>, String)],
) -> Result<Vec<SecretNameConflict>, AppError> {
    let mut out = Vec::new();
    for (credential_key, secret_name) in candidates {
        // `get_secret_by_name` filters `deleted_at IS NULL`, so a soft-deleted
        // slot does not conflict. That is the right call and not an oversight:
        // the name is free from the operator's point of view, and the upsert
        // resurrects the row rather than colliding with it. The old versions
        // stay behind it either way.
        if let Some(existing) = scope.get_secret_by_name(secret_name).await? {
            out.push(SecretNameConflict {
                credential_key: credential_key.clone(),
                secret_name: secret_name.clone(),
                current_version: existing.current_version,
            });
        }
    }
    Ok(out)
}

/// The 409 for a set of conflicts, with a `hint` written for `create_service`.
///
/// Names the *bind* escape first. It is the one that is usually meant — two
/// instances of one template sharing an API key is ordinary — and unlike
/// `force` it destroys nothing.
pub fn conflict_error_for_create(conflicts: Vec<SecretNameConflict>) -> AppError {
    let bind = conflicts
        .iter()
        .filter_map(|c| {
            c.credential_key
                .as_ref()
                .map(|k| format!("{k:?}: {:?}", c.secret_name))
        })
        .collect::<Vec<_>>()
        .join(", ");
    let hint = if bind.is_empty() {
        "pass `force: true` to store a new version over the existing secret \
         (the current version stays restorable)"
            .to_string()
    } else {
        format!(
            "to share the existing credential, bind it instead: \
             `credentials: {{{bind}}}` — no setup link is needed and nothing \
             is overwritten. To replace its value with the one your user \
             pastes, pass `force: true`; the current version stays restorable."
        )
    };
    AppError::SecretNameConflict { conflicts, hint }
}

/// The 409 for the two bare-request surfaces (`request_secret`, `POST
/// /v1/secrets/requests`), neither of which takes a credentials map.
///
/// `service_id` is the instance the request was bound to, when it was bound to
/// one. It changes the advice rather than just decorating it: a bound request
/// *does* have a bind escape, but it is `update_service` — naming
/// `credentials: {…}` here would describe a field the caller's own request
/// body does not have, which is the dead-end shape D77 removed from the
/// service-resolution messages.
pub fn conflict_error_for_request(
    conflicts: Vec<SecretNameConflict>,
    service_id: Option<uuid::Uuid>,
) -> AppError {
    let bind = conflicts
        .iter()
        .filter_map(|c| {
            c.credential_key
                .as_ref()
                .map(|k| format!("{k:?}: {:?}", c.secret_name))
        })
        .collect::<Vec<_>>()
        .join(", ");
    let hint = match (service_id, bind.is_empty()) {
        (Some(id), false) => format!(
            "to bind the existing secret to this slot, no request is needed — \
             `update_service` on instance {id} with `credentials: {{{bind}}}` \
             overwrites nothing. Otherwise choose a `secret_name` that is not \
             in use, or pass `force: true` to store a new version over the \
             existing secret (the current version stays restorable)."
        ),
        _ => "choose a `secret_name` that is not in use, or pass `force: true` \
              to store a new version over the existing secret (the current \
              version stays restorable)"
            .to_string(),
    };
    AppError::SecretNameConflict { conflicts, hint }
}
