//! Build SPIFFE-style identity paths from the database.
//!
//! Wraps the pure `overslash_core::identity_path` builder with the queries
//! needed to resolve an `identity_id` into its ancestor chain + org slug.

use overslash_core::identity_path::build_spiffe_path;
use overslash_db::OrgScope;
use overslash_db::repos::org;
use uuid::Uuid;

/// Resolve `identity_id` into a SPIFFE-style path
/// `spiffe://<org_slug>/<kind>/<name>/...` (root first, leaf last).
///
/// Returns `None` if the identity does not exist within the caller's org.
/// Falls back to the literal `unknown` org slug if the org row has gone
/// missing (should not happen but we don't want to fail an approval render
/// over it).
pub async fn build_for_identity(
    scope: &OrgScope,
    identity_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    let chain = scope.get_identity_ancestor_chain(identity_id).await?;
    if chain.is_empty() {
        return Ok(None);
    }

    let org_slug = match org::get_by_id(scope.db(), chain[0].org_id).await? {
        Some(o) => o.slug,
        None => "unknown".to_string(),
    };

    let segments: Vec<(&str, &str)> = chain
        .iter()
        .map(|i| (i.kind.as_str(), i.name.as_str()))
        .collect();

    Ok(Some(build_spiffe_path(&org_slug, &segments)))
}
