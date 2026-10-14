//! Resolve an [`IdentityRef`] — a UUID or a user email taken from a path
//! segment or query arg — to an identity id in the caller's org.
//!
//! A UUID passes through untouched: the handler already does its own
//! org-scoped lookup and 404, and keeping that path byte-identical means no
//! existing caller changes behaviour. An email is looked up among this org's
//! *live* users (the same lookup `X-Overslash-As` uses), so it can never name
//! an identity in another tenant. Archived users are not matched — restoring
//! one takes its UUID, as it would via impersonation.

use overslash_core::identity_path::IdentityRef;
use overslash_db::OrgScope;
use uuid::Uuid;

use crate::error::AppError;

pub async fn resolve(scope: &OrgScope, r: &IdentityRef) -> Result<Uuid, AppError> {
    match r {
        IdentityRef::Id(id) => Ok(*id),
        IdentityRef::Email(email) => scope
            .find_user_identity_by_email_in_org(email)
            .await?
            .map(|row| row.id)
            // Same text as an unknown UUID, so the two forms are
            // indistinguishable to a caller probing for members.
            .ok_or_else(|| AppError::NotFound("identity not found".into())),
    }
}

/// [`resolve`] for an optional query arg.
pub async fn resolve_opt(
    scope: &OrgScope,
    r: Option<&IdentityRef>,
) -> Result<Option<Uuid>, AppError> {
    match r {
        Some(r) => resolve(scope, r).await.map(Some),
        None => Ok(None),
    }
}
