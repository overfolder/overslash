//! Mirroring an IdP's group claim into directory groups at sign-in.
//!
//! The whole feature is one idea: **a directory group is a membership source,
//! not a ceiling.** What arrives here is the org's own IdP saying which humans
//! belong together. It is recorded, and it confers access only where an admin
//! has separately mapped it onto an Overslash group. Discovering a group is
//! never the same act as granting it anything.
//!
//! Three rules constrain what this module is allowed to believe. Each is
//! enforced here rather than at the call site so the login path cannot drift
//! away from them:
//!
//! 1. **Only an org's own IdP may speak about that org.** Sync runs only off an
//!    enabled `org_idp_configs` row (D12 — each IdP is its own trust domain). A
//!    `groups` claim arriving on Overslash-managed sign-in comes from the
//!    operator's shared Google/GitHub OAuth app and says nothing about this org.
//! 2. **An absent claim is not an empty claim.** See [`extract_claim`].
//! 3. **Humans only.** Agents inherit their owner-user's ceiling and never hold
//!    group membership of their own.

use uuid::Uuid;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::org_idp_config;
use overslash_db::scopes::OrgScope;

use crate::{AppState, error::Result};

/// The `directory_groups.source` this module writes. Google Admin SDK and
/// SCIM will write the same tables under their own values.
pub const SOURCE_OIDC_CLAIM: &str = "oidc_claim";

/// What one sign-in changed, for logging and tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Directory groups this human newly belongs to.
    pub added: Vec<Uuid>,
    /// Directory groups this human no longer belongs to.
    pub removed: Vec<Uuid>,
    /// False when the IdP said nothing about groups and nothing was touched.
    pub ran: bool,
}

/// Pull group membership for one identity out of an IdP's claims.
///
/// Never fails a login: every error path returns `Ok(SyncOutcome::default())`
/// or propagates only genuine database faults, and the caller logs rather than
/// aborts. Being unable to refresh group membership is a degraded sign-in, not
/// a failed one — and the alternative, locking users out of the dashboard
/// because their IdP changed a claim shape, is far worse than a stale ceiling.
pub async fn sync_identity_groups(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
    claims: &serde_json::Map<String, serde_json::Value>,
) -> Result<SyncOutcome> {
    // Rule 1. A dedicated `org_idp_configs` row always wins over managed
    // sign-in in `org_signin::resolve_org_signin_credentials`, so an enabled
    // row for this provider *is* the IdP this login came through. No row, a
    // disabled row, or sync switched off → this login says nothing about
    // groups.
    let Some(config) =
        org_idp_config::get_by_org_and_provider(state.db(ext), org_id, provider_key).await?
    else {
        return Ok(SyncOutcome::default());
    };
    if !config.enabled || !config.group_sync_enabled {
        return Ok(SyncOutcome::default());
    }

    // Rule 2.
    let Some(external_ids) = extract_claim(claims, &config.group_claim) else {
        return Ok(SyncOutcome::default());
    };

    let scope = OrgScope::new(org_id, state.db_pool(ext));

    // Record what the directory says exists before asserting who is in it —
    // the membership rows are FK'd to these.
    let mut directory_group_ids = Vec::with_capacity(external_ids.len());
    for external_id in &external_ids {
        let row = scope
            .upsert_directory_group(
                Some(config.id),
                SOURCE_OIDC_CLAIM,
                external_id,
                // A bare claim carries no separate label. Kept as its own
                // column because Entra sends object GUIDs here, and a later
                // Admin SDK sync can fill in the human name without
                // invalidating the membership rows keyed on the id.
                external_id,
            )
            .await?;
        directory_group_ids.push(row.id);
    }

    let (added, removed) = scope
        .replace_directory_memberships(
            identity_id,
            Some(config.id),
            SOURCE_OIDC_CLAIM,
            &directory_group_ids,
        )
        .await?;

    // Only a real delta is worth an audit row. Every sign-in re-asserts the
    // same claim, so logging unconditionally would bury the membership changes
    // an auditor is actually looking for under one row per login per user.
    if !added.is_empty() || !removed.is_empty() {
        let _ = scope
            .log_audit(AuditEntry {
                org_id,
                identity_id: Some(identity_id),
                action: "identity.directory_groups_synced",
                resource_type: Some("identity"),
                resource_id: Some(identity_id),
                detail: serde_json::json!({
                    "provider_key": provider_key,
                    "idp_config_id": config.id,
                    "group_claim": config.group_claim,
                    "added": added,
                    "removed": removed,
                }),
                description: None,
                // No ClientIp here: this runs inside the OAuth callback, where
                // the peer is the browser following a redirect rather than an
                // API caller, and the sign-in itself is already audited.
                ip_address: None,
            })
            .await;
    }

    Ok(SyncOutcome {
        added,
        removed,
        ran: true,
    })
}

/// Read the configured claim, distinguishing "the IdP said nothing" from "the
/// IdP said none".
///
/// `None` — the key is absent, or present but not a shape we understand. The
/// caller changes nothing.
/// `Some(vec![])` — the key is present and empty. The human is in no directory
/// group and their derived membership is revoked.
///
/// The distinction is the whole safety story for authoritative sync. Collapsing
/// the two would mean that an admin renaming a claim in Okta, or an IdP
/// dropping the claim from a release policy, silently strips every user's
/// directory-derived access at their next login — an org-wide outage caused by
/// a config change nobody connected to Overslash.
///
/// Accepted shapes: an array of strings (the norm), and a single bare string
/// (some IdPs collapse a one-element list). Non-string array elements are
/// skipped rather than voiding the claim, so one malformed entry in an
/// otherwise good list does not revoke everything.
fn extract_claim(
    claims: &serde_json::Map<String, serde_json::Value>,
    claim_name: &str,
) -> Option<Vec<String>> {
    let value = claims.get(claim_name)?;

    let mut out: Vec<String> = match value {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect(),
        serde_json::Value::String(s) if !s.trim().is_empty() => vec![s.trim().to_string()],
        // An explicit JSON null reads as "no data", not "no groups": it is what
        // an IdP emits for an unpopulated claim, and treating it as a revoke
        // would trip the outage above.
        serde_json::Value::Null => return None,
        // An empty string is the one-element collapse of an empty list.
        serde_json::Value::String(_) => vec![],
        // A number, bool or object is not a group list. Refusing to guess is
        // safer than inventing membership from a shape we do not understand.
        _ => return None,
    };

    // The same group twice would violate the membership primary key.
    out.sort();
    out.dedup();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::extract_claim;

    fn claims(json: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        match json {
            serde_json::Value::Object(m) => m,
            _ => unreachable!(),
        }
    }

    /// The rule the whole authoritative-sync story rests on. If these two ever
    /// collapse, a claim disappearing from an IdP release policy becomes an
    /// org-wide revocation.
    #[test]
    fn an_absent_claim_is_not_an_empty_one() {
        let absent = claims(serde_json::json!({ "email": "a@b.c" }));
        assert_eq!(extract_claim(&absent, "groups"), None);

        let empty = claims(serde_json::json!({ "groups": [] }));
        assert_eq!(extract_claim(&empty, "groups"), Some(vec![]));
    }

    #[test]
    fn a_null_claim_reads_as_no_data() {
        let c = claims(serde_json::json!({ "groups": serde_json::Value::Null }));
        assert_eq!(extract_claim(&c, "groups"), None);
    }

    #[test]
    fn a_bare_string_is_a_one_element_list() {
        let c = claims(serde_json::json!({ "groups": "engineering" }));
        assert_eq!(
            extract_claim(&c, "groups"),
            Some(vec!["engineering".into()])
        );
    }

    #[test]
    fn duplicates_collapse_and_blanks_drop() {
        let c = claims(serde_json::json!({ "groups": ["eng", "eng", "  ", "ops"] }));
        assert_eq!(
            extract_claim(&c, "groups"),
            Some(vec!["eng".to_string(), "ops".to_string()])
        );
    }

    /// One bad element must not void an otherwise good list — that would be a
    /// silent revocation.
    #[test]
    fn a_non_string_element_is_skipped_not_fatal() {
        let c = claims(serde_json::json!({ "groups": ["eng", 7, null, "ops"] }));
        assert_eq!(
            extract_claim(&c, "groups"),
            Some(vec!["eng".to_string(), "ops".to_string()])
        );
    }

    #[test]
    fn a_shape_we_do_not_understand_changes_nothing() {
        let c = claims(serde_json::json!({ "groups": { "a": 1 } }));
        assert_eq!(extract_claim(&c, "groups"), None);
    }

    /// Auth0 namespaces its custom claims; the claim name is a plain key lookup
    /// so a URL works without special handling.
    #[test]
    fn a_namespaced_claim_name_is_just_a_key() {
        let c = claims(serde_json::json!({ "https://acme.com/groups": ["eng"] }));
        assert_eq!(
            extract_claim(&c, "https://acme.com/groups"),
            Some(vec!["eng".to_string()])
        );
    }
}
