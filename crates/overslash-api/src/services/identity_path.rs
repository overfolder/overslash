//! Build SPIFFE-style identity paths from the database.
//!
//! Wraps the pure `overslash_core::identity_path` builder with the queries
//! needed to resolve an `identity_id` into its ancestor chain + org slug.

use overslash_core::identity_path::build_spiffe_path;
use overslash_db::OrgScope;
use overslash_db::repos::org;
use uuid::Uuid;

/// Resolve `identity_id` into a SPIFFE-style path
/// `spiffe://<org_slug>/user/<email>/agent/<name>/...` (root first, leaf last) plus the
/// id of each `(kind, name)` unit in the same order. The id list excludes the
/// org slug, so its length matches the number of unit segments in the path.
///
/// Returns `None` if the identity does not exist within the caller's org.
/// Falls back to the literal `unknown` org slug if the org row has gone
/// missing (should not happen but we don't want to fail an approval render
/// over it).
pub async fn build_for_identity(
    scope: &OrgScope,
    identity_id: Uuid,
) -> Result<Option<(String, Vec<Uuid>)>, sqlx::Error> {
    let chain = scope.get_identity_ancestor_chain(identity_id).await?;
    if chain.is_empty() {
        return Ok(None);
    }

    let org_slug = match org::get_by_id(scope.db(), chain[0].org_id).await? {
        Some(o) => o.slug,
        None => "unknown".to_string(),
    };

    // User units are named by email, never by display name: `identities.name`
    // is the IdP's `name` claim — not unique, editable, and free to contain
    // `/`, which would corrupt the path. The email is the IdP-verified handle
    // (the same one `X-Overslash-As` accepts as a target root). A user row
    // without an email falls back to its UUID. Agents keep their name — it is
    // what the owner chose and what impersonation paths address them by.
    let labels: Vec<String> = chain
        .iter()
        .map(|i| match (i.kind.as_str(), i.email.as_deref()) {
            ("user", Some(email)) if !email.trim().is_empty() => email.to_string(),
            ("user", _) => i.id.to_string(),
            _ => i.name.clone(),
        })
        .collect();
    let segments: Vec<(&str, &str)> = chain
        .iter()
        .zip(&labels)
        .map(|(i, label)| (i.kind.as_str(), label.as_str()))
        .collect();
    let ids: Vec<Uuid> = chain.iter().map(|i| i.id).collect();

    Ok(Some((build_spiffe_path(&org_slug, &segments), ids)))
}
